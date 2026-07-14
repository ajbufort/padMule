//! eMule/aMule protocol obfuscation primitives: the RC4 key derivation and the
//! TCP handshake byte layout. See docs/raw/wave5-crypto-research-2026-07-14.md
//! section A (EncryptedStreamSocket, eMule 0.50a is the wire authority; aMule is
//! byte-identical).
//!
//! Obfuscation is NOT encryption in any meaningful sense (RC4 keyed off a value
//! any peer already knows - the target's userhash). Its only purpose is to make
//! the traffic not look like eD2k to a naive DPI filter. padMule implements it
//! solely for interoperability: real aMule/eMule request it by default.

use crate::rc4::Rc4;
use md5::{Digest, Md5};

/// The 4-byte sync value proving the RC4 key was derived correctly (LE on wire).
pub const MAGICVALUE_SYNC: u32 = 0x835E_6FC4;
/// Keys the requester -> responder stream direction.
pub const MAGICVALUE_REQUESTER: u8 = 34;
/// Keys the responder -> requester stream direction.
pub const MAGICVALUE_SERVER: u8 = 203;
/// TCP obfuscation discards this many keystream bytes right after keying.
pub const TCP_RC4_DISCARD: usize = 1024;
/// The only obfuscation method eMule defines; both method bytes are 0.
pub const ENM_OBFUSCATION: u8 = 0x00;

/// The three plaintext eD2k protocol markers. A receiver treats a connection
/// whose first byte is one of these as UNOBFUSCATED; anything else starts the
/// obfuscation handshake. (This is also why the initiator's leading "semi-random"
/// marker byte must avoid these three values.)
pub const PLAINTEXT_MARKERS: [u8; 3] = [0xE3, 0xD4, 0xC5];

/// True if `b` is a plaintext eD2k protocol byte (so NOT an obfuscated stream).
pub fn is_plaintext_marker(b: u8) -> bool {
    PLAINTEXT_MARKERS.contains(&b)
}

/// Derive an obfuscation RC4 cipher for a client-to-client stream.
///
/// The key is `MD5(user_hash[16] || magic || random_key[4 LE])`, then RC4 with
/// the first [`TCP_RC4_DISCARD`] keystream bytes dropped. `magic` selects the
/// direction: [`MAGICVALUE_REQUESTER`] keys requester->responder,
/// [`MAGICVALUE_SERVER`] keys responder->requester.
///
/// `user_hash` is whichever hash both ends agree identifies this key: the
/// initiator uses the TARGET peer's hash; the responder uses its OWN hash (which
/// is the initiator's target). `random_key` is the 4 raw little-endian bytes the
/// initiator sent in the clear.
pub fn tcp_cipher(user_hash: &[u8; 16], magic: u8, random_key: u32) -> Rc4 {
    let mut h = Md5::new();
    h.update(user_hash);
    h.update([magic]);
    h.update(random_key.to_le_bytes());
    let digest = h.finalize();
    Rc4::new_discard(&digest, TCP_RC4_DISCARD)
}

/// Pick a "semi-random" marker byte for the start of an obfuscated handshake:
/// any value that is not a plaintext eD2k marker, so the receiver knows to
/// obfuscate. `rand_byte` supplies randomness; on the vanishingly rare collision
/// it is nudged to a safe value (upstream retries, then falls back to 0x01).
pub fn semi_random_marker(rand_byte: u8) -> u8 {
    if is_plaintext_marker(rand_byte) {
        0x01
    } else {
        rand_byte
    }
}

/// The two RC4 ciphers for one end of an obfuscated client-to-client stream.
pub struct StreamCiphers {
    /// Encrypts bytes we send.
    pub send: Rc4,
    /// Decrypts bytes we receive.
    pub recv: Rc4,
}

impl StreamCiphers {
    /// Ciphers for the INITIATOR (the side that opened the connection). It keys
    /// its send stream with [`MAGICVALUE_REQUESTER`] and its recv stream with
    /// [`MAGICVALUE_SERVER`], both against the TARGET peer's `user_hash`.
    pub fn initiator(target_hash: &[u8; 16], random_key: u32) -> Self {
        StreamCiphers {
            send: tcp_cipher(target_hash, MAGICVALUE_REQUESTER, random_key),
            recv: tcp_cipher(target_hash, MAGICVALUE_SERVER, random_key),
        }
    }

    /// Ciphers for the RESPONDER (the side that accepted the connection). Roles
    /// swap: it keys recv with [`MAGICVALUE_REQUESTER`] and send with
    /// [`MAGICVALUE_SERVER`], both against its OWN `user_hash` (the initiator's
    /// target).
    pub fn responder(own_hash: &[u8; 16], random_key: u32) -> Self {
        StreamCiphers {
            recv: tcp_cipher(own_hash, MAGICVALUE_REQUESTER, random_key),
            send: tcp_cipher(own_hash, MAGICVALUE_SERVER, random_key),
        }
    }
}

/// Build the INITIATOR's obfuscation handshake bytes (client-to-client).
///
/// Layout (see spec A.2): the first 5 bytes are plaintext, the rest is RC4'd
/// with the initiator's SEND cipher:
/// ```text
/// [0]      semi-random marker           plaintext (not an eD2k marker byte)
/// [1..4]   random_key (u32 LE)          plaintext
/// [5..8]   MAGICVALUE_SYNC (u32 LE)     RC4(send)
/// [9]      methods supported = 0        RC4(send)
/// [10]     method preferred = 0         RC4(send)
/// [11]     padding length               RC4(send)
/// [12..]   padding                      RC4(send)
/// ```
/// `marker` should come from [`semi_random_marker`]; `padding` is the caller's
/// random bytes (0..=254 of them). Returns the wire bytes and consumes/advances
/// the provided send cipher so the caller keeps using it for the stream.
pub fn build_initiator_handshake(
    send: &mut Rc4,
    marker: u8,
    random_key: u32,
    padding: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + padding.len());
    out.push(marker);
    out.extend_from_slice(&random_key.to_le_bytes());

    // The encrypted portion.
    let mut enc = Vec::with_capacity(7 + padding.len());
    enc.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
    enc.push(ENM_OBFUSCATION); // methods supported
    enc.push(ENM_OBFUSCATION); // method preferred
    enc.push(padding.len() as u8);
    enc.extend_from_slice(padding);
    send.apply(&mut enc);

    out.extend_from_slice(&enc);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: [u8; 16] = [
        0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88,
    ];

    #[test]
    fn key_derivation_is_md5_of_hash_magic_randomkey() {
        // Independently recompute the expected key and compare keystreams.
        let random_key = 0x1122_3344u32;
        let mut h = Md5::new();
        h.update(TARGET);
        h.update([MAGICVALUE_REQUESTER]);
        h.update(random_key.to_le_bytes());
        let expected_key = h.finalize();
        let mut expected = Rc4::new_discard(&expected_key, TCP_RC4_DISCARD);

        let mut got = tcp_cipher(&TARGET, MAGICVALUE_REQUESTER, random_key);
        assert_eq!(got.keystream(32), expected.keystream(32));
    }

    #[test]
    fn the_two_directions_use_different_keys() {
        let rk = 0xDEAD_BEEFu32;
        let mut req = tcp_cipher(&TARGET, MAGICVALUE_REQUESTER, rk);
        let mut srv = tcp_cipher(&TARGET, MAGICVALUE_SERVER, rk);
        assert_ne!(req.keystream(16), srv.keystream(16));
    }

    #[test]
    fn initiator_and_responder_agree_on_each_direction() {
        // The whole point: the initiator's SEND cipher must match the responder's
        // RECV cipher (and vice versa), or nothing decrypts. Same target hash,
        // same random key, roles swapped.
        let rk = 0x0A0B_0C0Du32;
        let mut init = StreamCiphers::initiator(&TARGET, rk);
        let mut resp = StreamCiphers::responder(&TARGET, rk);

        // initiator send == responder recv
        assert_eq!(init.send.keystream(32), resp.recv.keystream(32));
        // responder send == initiator recv
        assert_eq!(resp.send.keystream(32), init.recv.keystream(32));
    }

    #[test]
    fn a_full_message_round_trips_through_the_paired_ciphers() {
        let rk = 0x5555_6666u32;
        let mut init = StreamCiphers::initiator(&TARGET, rk);
        let mut resp = StreamCiphers::responder(&TARGET, rk);

        let msg = b"OP_HELLO would go here, obfuscated".to_vec();
        let mut wire = msg.clone();
        init.send.apply(&mut wire); // initiator encrypts
        assert_ne!(wire, msg);
        resp.recv.apply(&mut wire); // responder decrypts
        assert_eq!(wire, msg);
    }

    #[test]
    fn semi_random_marker_never_collides_with_a_plaintext_byte() {
        for b in 0u8..=255 {
            assert!(!is_plaintext_marker(semi_random_marker(b)));
        }
        // A safe random byte is returned unchanged.
        assert_eq!(semi_random_marker(0x42), 0x42);
        // A colliding byte is replaced.
        assert_eq!(semi_random_marker(0xE3), 0x01);
    }

    #[test]
    fn initiator_handshake_has_the_right_layout_and_decrypts() {
        let rk = 0x1020_3040u32;
        let mut init = StreamCiphers::initiator(&TARGET, rk);
        let marker = semi_random_marker(0x77);
        let padding = [0x9Au8, 0xBC, 0xDE];
        let hs = build_initiator_handshake(&mut init.send, marker, rk, &padding);

        // Plaintext prefix.
        assert_eq!(hs[0], marker);
        assert_eq!(&hs[1..5], &rk.to_le_bytes());
        assert_eq!(hs.len(), 12 + padding.len());

        // The responder derives its recv cipher from the plaintext random key and
        // decrypts the encrypted portion back to SYNC + methods + padlen + pad.
        let mut resp = StreamCiphers::responder(&TARGET, rk);
        let mut enc = hs[5..].to_vec();
        resp.recv.apply(&mut enc);
        assert_eq!(&enc[0..4], &MAGICVALUE_SYNC.to_le_bytes());
        assert_eq!(enc[4], ENM_OBFUSCATION);
        assert_eq!(enc[5], ENM_OBFUSCATION);
        assert_eq!(enc[6] as usize, padding.len());
        assert_eq!(&enc[7..], &padding);
    }
}
