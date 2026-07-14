//! Interop test: load a REAL aMule 3.0.1 `cryptkey.dat` (Crypto++-written) with
//! padMule's secure-ident parser. This is the differential check that our RSA
//! key encoding matches Crypto++ - the whole reason to store PKCS#8 rather than
//! raw PKCS#1. The fixture was produced by an actual amuled run
//! (see docs/wiki/build-progress.md, Wave 5c).

use mule_engine::secure_ident::{verify_v1, Identity};

const AMULE_CRYPTKEY: &[u8] = include_bytes!("fixtures/amule-cryptkey.dat");

#[test]
fn loads_a_real_amule_cryptkey_dat_and_the_key_works() {
    // If our DER format did not match Crypto++'s, this parse would fail.
    let id = Identity::from_cryptkey_dat(AMULE_CRYPTKEY)
        .expect("padMule must be able to load a real aMule cryptkey.dat");

    // The derived public key is a valid PKCS#1 RSAPublicKey within the wire cap.
    let pk = id.public_key_der();
    assert!(!pk.is_empty() && pk.len() <= 80);

    // And it is a working key: a challenge signed with the loaded aMule identity
    // verifies against its own advertised public key (self-consistency proving
    // sign + verify + the loaded key all agree).
    let peer = Identity::generate();
    let challenge = 0x0BAD_F00Du32;
    let sig = id.sign_v1(peer.public_key_der(), challenge);
    assert!(verify_v1(pk, peer.public_key_der(), challenge, &sig));
}

#[test]
fn re_encoding_the_loaded_key_round_trips() {
    let id = Identity::from_cryptkey_dat(AMULE_CRYPTKEY).unwrap();
    // Write it back out and reload - same public key, proving our PKCS#8 encoder
    // and decoder are inverses over a Crypto++-originated key.
    let dat = id.to_cryptkey_dat();
    let reloaded = Identity::from_cryptkey_dat(&dat).unwrap();
    assert_eq!(reloaded.public_key_der(), id.public_key_der());
}
