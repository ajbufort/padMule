//! Secure identification: RSA public-key exchange + challenge signing that lets
//! a peer prove it owns the userhash its credits are tracked under, so a stolen
//! userhash cannot steal the credits. See
//! docs/raw/wave5-crypto-research-2026-07-14.md section C (eMule 0.50a wire
//! authority; aMule byte-identical).
//!
//! Crypto: RSA-384, RSASSA-PKCS1-v1.5 over SHA-1 (Crypto++
//! `RSASSA_PKCS1v15_SHA`). The public key on the wire is its PKCS#1
//! `RSAPublicKey` DER (n, e), ~58 bytes (<= 80); the signature is a fixed 48
//! bytes (the 384-bit modulus size). `cryptkey.dat` is the base64 of the private
//! key's **PKCS#8** `PrivateKeyInfo` DER - verified against a real amuled file,
//! whose Crypto++ `InvertibleRSAFunction::DEREncode` emits the PKCS#8 wrapper
//! (AlgorithmIdentifier + rsaEncryption OID around the inner PKCS#1 key), NOT
//! raw PKCS#1 as one might assume. Getting this wrong makes us unable to load an
//! aMule identity.
//!
//! This module implements SecureIdent **v1** (the default, MISCOPTIONS1 bit 16).
//! v2 appends a challenge-IP + kind to the signed bytes; deferred until needed.
//!
//! # The one thing that is easy to get wrong
//!
//! You sign the OTHER peer's public key concatenated with the challenge THEY
//! sent you - never your own key. The verifier reconstructs the message from ITS
//! OWN public key plus the challenge IT issued, and checks the signature with
//! your public key. The two constructions are mirror images; `sign_v1` and
//! `verify_v1` encode exactly that asymmetry.

use base64::Engine;
use mule_proto::{IoError, Packet, Reader, Writer, PROT_EMULE};
use rand::rngs::OsRng;
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::{Pkcs1v15Sign, RsaPrivateKey, RsaPublicKey};
use sha1::{Digest, Sha1};

/// Opcodes, all under `OP_EMULEPROT` (0xC5).
pub const OP_SIGNATURE: u8 = 0x86;
pub const OP_PUBLICKEY: u8 = 0x85;
pub const OP_SECIDENTSTATE: u8 = 0x87;

/// SecIdentState values.
pub const IS_SIGNATURENEEDED: u8 = 1;
pub const IS_KEYANDSIGNEEDED: u8 = 2;

/// RSA modulus size in bits (and so the signature is 48 bytes).
pub const RSA_KEY_BITS: usize = 384;
/// The public key blob never exceeds this on the wire / in clients.met.
pub const MAX_PUBKEY_SIZE: usize = 80;
/// A v1 signature is exactly the modulus size.
pub const SIGNATURE_LEN: usize = 48;

/// Our RSA identity: the private key plus its cached public-key DER (the bytes
/// we put on the wire).
pub struct Identity {
    key: RsaPrivateKey,
    pub_der: Vec<u8>,
}

impl Identity {
    /// Generate a fresh RSA-384 identity.
    pub fn generate() -> Self {
        let key = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS)
            .expect("RSA-384 keygen cannot fail with a real RNG");
        Self::from_key(key)
    }

    fn from_key(key: RsaPrivateKey) -> Self {
        let pub_der = RsaPublicKey::from(&key)
            .to_pkcs1_der()
            .expect("PKCS#1 public DER encoding cannot fail")
            .as_bytes()
            .to_vec();
        debug_assert!(pub_der.len() <= MAX_PUBKEY_SIZE);
        Identity { key, pub_der }
    }

    /// Load an identity from the contents of `cryptkey.dat` (base64 of the
    /// private key's PKCS#8 DER - aMule's exact format, Crypto++-compatible).
    pub fn from_cryptkey_dat(bytes: &[u8]) -> Result<Self, IoError> {
        let text: Vec<u8> = bytes
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        let der = base64::engine::general_purpose::STANDARD
            .decode(&text)
            .map_err(|_| IoError::Decompress)?;
        let key = RsaPrivateKey::from_pkcs8_der(&der).map_err(|_| IoError::Decompress)?;
        Ok(Self::from_key(key))
    }

    /// Serialize this identity to `cryptkey.dat` form (base64 of PKCS#8 DER).
    pub fn to_cryptkey_dat(&self) -> Vec<u8> {
        let der = self
            .key
            .to_pkcs8_der()
            .expect("PKCS#8 private DER encoding cannot fail");
        base64::engine::general_purpose::STANDARD
            .encode(der.as_bytes())
            .into_bytes()
    }

    /// The public key DER to advertise (OP_PUBLICKEY payload).
    pub fn public_key_der(&self) -> &[u8] {
        &self.pub_der
    }

    /// Sign a SecureIdent v1 challenge. The signed message is
    /// `peer_public_key_der || challenge (u32 LE)`; it is SHA-1'd then
    /// PKCS#1-v1.5 signed. `challenge` is the value the PEER sent us in its
    /// OP_SECIDENTSTATE. Returns exactly 48 bytes.
    pub fn sign_v1(&self, peer_public_key_der: &[u8], challenge: u32) -> Vec<u8> {
        let msg = signed_message(peer_public_key_der, challenge);
        let hash = Sha1::digest(&msg);
        self.key
            .sign(Pkcs1v15Sign::new::<Sha1>(), &hash)
            .expect("PKCS#1 signing cannot fail")
    }
}

/// The exact bytes covered by a v1 signature: the target's public key DER
/// followed by the 4-byte little-endian challenge.
fn signed_message(public_key_der: &[u8], challenge: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(public_key_der.len() + 4);
    m.extend_from_slice(public_key_der);
    m.extend_from_slice(&challenge.to_le_bytes());
    m
}

/// Verify a peer's SecureIdent v1 signature.
///
/// The peer signed `our_public_key_der || challenge_we_issued`; we recompute
/// that message and check `sig` against the peer's public key. `peer_public_key_der`
/// is the key the peer sent us in OP_PUBLICKEY; `challenge_we_issued` is the
/// random value we put in the OP_SECIDENTSTATE we sent it.
pub fn verify_v1(
    peer_public_key_der: &[u8],
    our_public_key_der: &[u8],
    challenge_we_issued: u32,
    sig: &[u8],
) -> bool {
    let peer_pub = match RsaPublicKey::from_pkcs1_der(peer_public_key_der) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let msg = signed_message(our_public_key_der, challenge_we_issued);
    let hash = Sha1::digest(&msg);
    peer_pub
        .verify(Pkcs1v15Sign::new::<Sha1>(), &hash, sig)
        .is_ok()
}

// -------------------------------------------------------------- packet codecs

/// OP_PUBLICKEY: `<len u8><DER public key>`.
pub fn build_public_key(pub_der: &[u8]) -> Packet {
    let mut w = Writer::new();
    w.write_u8(pub_der.len() as u8);
    w.write_bytes(pub_der);
    Packet::new(PROT_EMULE, OP_PUBLICKEY, w.into_inner())
}

/// Parse OP_PUBLICKEY -> the DER public key bytes. Enforces the length prefix
/// and the 80-byte cap (aMule rejects anything larger).
pub fn parse_public_key(payload: &[u8]) -> Result<Vec<u8>, IoError> {
    let mut r = Reader::new(payload);
    let len = r.read_u8()? as usize;
    if len == 0 || len > MAX_PUBKEY_SIZE {
        return Err(IoError::BadTag(len as u8));
    }
    r.read_bytes(len)
}

/// OP_SECIDENTSTATE: `<state u8><challenge u32 LE>`. `state` is
/// [`IS_SIGNATURENEEDED`] or [`IS_KEYANDSIGNEEDED`]; `challenge` is a fresh
/// non-zero random value the receiver must sign back.
pub fn build_sec_ident_state(state: u8, challenge: u32) -> Packet {
    let mut w = Writer::new();
    w.write_u8(state);
    w.write_u32(challenge);
    Packet::new(PROT_EMULE, OP_SECIDENTSTATE, w.into_inner())
}

/// Parse OP_SECIDENTSTATE -> (state, challenge).
pub fn parse_sec_ident_state(payload: &[u8]) -> Result<(u8, u32), IoError> {
    let mut r = Reader::new(payload);
    let state = r.read_u8()?;
    let challenge = r.read_u32()?;
    Ok((state, challenge))
}

/// OP_SIGNATURE (v1): `<len u8><signature>`. v2 appends a challenge-IP-kind byte
/// which this v1 builder does not emit.
pub fn build_signature(sig: &[u8]) -> Packet {
    let mut w = Writer::new();
    w.write_u8(sig.len() as u8);
    w.write_bytes(sig);
    Packet::new(PROT_EMULE, OP_SIGNATURE, w.into_inner())
}

/// Parse OP_SIGNATURE -> the signature bytes (v1; ignores any trailing
/// challenge-IP-kind byte).
pub fn parse_signature(payload: &[u8]) -> Result<Vec<u8>, IoError> {
    let mut r = Reader::new(payload);
    let len = r.read_u8()? as usize;
    r.read_bytes(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_has_a_sane_public_key() {
        let id = Identity::generate();
        // PKCS#1 RSAPublicKey DER for a 384-bit key is ~58-60 bytes, under 80.
        assert!(id.public_key_der().len() <= MAX_PUBKEY_SIZE);
        assert!(id.public_key_der().len() >= 50);
    }

    #[test]
    fn cryptkey_dat_round_trips_and_yields_the_same_public_key() {
        let id = Identity::generate();
        let dat = id.to_cryptkey_dat();
        // It is base64 text.
        assert!(dat.iter().all(|b| b.is_ascii()));
        let loaded = Identity::from_cryptkey_dat(&dat).unwrap();
        assert_eq!(loaded.public_key_der(), id.public_key_der());
    }

    #[test]
    fn from_cryptkey_dat_tolerates_trailing_whitespace() {
        let id = Identity::generate();
        let mut dat = id.to_cryptkey_dat();
        dat.extend_from_slice(b"\n\r\n");
        let loaded = Identity::from_cryptkey_dat(&dat).unwrap();
        assert_eq!(loaded.public_key_der(), id.public_key_der());
    }

    #[test]
    fn a_v1_signature_verifies_with_the_mirror_construction() {
        // Alice proves her identity to Bob.
        let alice = Identity::generate();
        let bob = Identity::generate();

        // Bob challenges Alice: Bob sends its own pubkey (in OP_PUBLICKEY) and a
        // challenge (in OP_SECIDENTSTATE). Alice signs BOB's pubkey + challenge.
        let challenge = 0xDEAD_BEEFu32;
        let sig = alice.sign_v1(bob.public_key_der(), challenge);
        assert_eq!(sig.len(), SIGNATURE_LEN);

        // Bob verifies with Alice's pubkey against ITS OWN pubkey + the challenge
        // it issued.
        assert!(verify_v1(
            alice.public_key_der(),
            bob.public_key_der(),
            challenge,
            &sig
        ));
    }

    #[test]
    fn verification_fails_on_a_tampered_challenge() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let sig = alice.sign_v1(bob.public_key_der(), 1000);
        assert!(!verify_v1(
            alice.public_key_der(),
            bob.public_key_der(),
            1001, // different challenge
            &sig
        ));
    }

    #[test]
    fn verification_fails_when_signing_the_wrong_key() {
        // A classic mistake: signing OUR OWN key instead of the peer's. It must
        // not verify.
        let alice = Identity::generate();
        let bob = Identity::generate();
        let challenge = 42;
        let wrong = alice.sign_v1(alice.public_key_der(), challenge); // signed own key
        assert!(!verify_v1(
            alice.public_key_der(),
            bob.public_key_der(),
            challenge,
            &wrong
        ));
    }

    #[test]
    fn an_impostor_with_a_different_key_cannot_forge_a_signature() {
        let alice = Identity::generate();
        let bob = Identity::generate();
        let impostor = Identity::generate();
        let challenge = 7;
        // Impostor signs the right message but with the wrong key.
        let sig = impostor.sign_v1(bob.public_key_der(), challenge);
        // Verifying against ALICE's advertised pubkey fails.
        assert!(!verify_v1(
            alice.public_key_der(),
            bob.public_key_der(),
            challenge,
            &sig
        ));
    }

    #[test]
    fn packet_codecs_round_trip() {
        let id = Identity::generate();
        let pk = build_public_key(id.public_key_der());
        assert_eq!(pk.opcode, OP_PUBLICKEY);
        assert_eq!(parse_public_key(&pk.payload).unwrap(), id.public_key_der());

        let st = build_sec_ident_state(IS_KEYANDSIGNEEDED, 0x1234_5678);
        assert_eq!(st.opcode, OP_SECIDENTSTATE);
        assert_eq!(
            parse_sec_ident_state(&st.payload).unwrap(),
            (IS_KEYANDSIGNEEDED, 0x1234_5678)
        );

        let sig_bytes = vec![0xAB; SIGNATURE_LEN];
        let sg = build_signature(&sig_bytes);
        assert_eq!(sg.opcode, OP_SIGNATURE);
        assert_eq!(parse_signature(&sg.payload).unwrap(), sig_bytes);
    }

    #[test]
    fn parse_public_key_rejects_oversize_and_empty() {
        assert!(parse_public_key(&[0]).is_err()); // len 0
        let mut too_big = vec![81u8];
        too_big.extend_from_slice(&[0u8; 81]);
        assert!(parse_public_key(&too_big).is_err()); // len 81 > 80
    }

    #[test]
    fn a_full_v1_exchange_over_the_packet_codecs() {
        // Drive the whole thing through the wire codecs, both directions, the way
        // the engine will: each side challenges the other.
        let alice = Identity::generate();
        let bob = Identity::generate();

        // Alice -> Bob: OP_PUBLICKEY(alice) then Bob challenges.
        let alice_pk = parse_public_key(&build_public_key(alice.public_key_der()).payload).unwrap();
        let (_state, bob_challenge) =
            parse_sec_ident_state(&build_sec_ident_state(IS_KEYANDSIGNEEDED, 55).payload).unwrap();
        // Alice signs Bob's key + Bob's challenge, sends OP_SIGNATURE.
        let sig = parse_signature(
            &build_signature(&alice.sign_v1(bob.public_key_der(), bob_challenge)).payload,
        )
        .unwrap();
        // Bob verifies.
        assert!(verify_v1(
            &alice_pk,
            bob.public_key_der(),
            bob_challenge,
            &sig
        ));
    }
}
