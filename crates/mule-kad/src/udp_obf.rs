//! Kad UDP obfuscation - eMule's `CEncryptedDatagramSocket`. See
//! docs/raw/wave6-kad-research-2026-07-14.md section E.
//!
//! Every Kad datagram is wrapped in an RC4 layer. The first three bytes are
//! plaintext (a marker plus a 2-byte random key seed); from byte [3] on is one
//! contiguous RC4 keystream over a 4-byte sync sentinel, a pad-length, the two
//! 32-bit verify keys, and the Kad frame itself:
//!
//! ```text
//! [0]      bySemiRandomNotProtocolMarker   plaintext (low 2 bits = Kad markers)
//! [1..2]   nRandomKeyPart u16 LE           plaintext
//! [3..6]   0x395F2EC1 sync sentinel        RC4
//! [7]      byPadLen (0 for Kad)            RC4
//! [8..]    <pad>                           RC4
//! [..]     nReceiverVerifyKey u32 LE       RC4
//! [..]     nSenderVerifyKey   u32 LE       RC4
//! [..]     Kad frame (0xE4/0xE5 ...)       RC4
//! ```
//!
//! RC4 uses the FULL 16-byte MD5 digest as its key with NO keystream discard
//! (unlike TCP's 1024). Two Kad key derivations:
//!   - NodeID key (requests): MD5(target KadID wire bytes || randomKeyPart).
//!   - ReceiverKey (responses): MD5(verifyKey u32 LE || randomKeyPart).

use md5::{Digest, Md5};
use mule_proto::{Kad128, Rc4};

/// Kad sync sentinel `MAGICVALUE_UDP_SYNC_CLIENT`; on the wire the LE bytes are
/// `C1 2E 5F 39`.
pub const MAGICVALUE_UDP_SYNC_CLIENT: u32 = 0x395F_2EC1;

/// Datagrams this short cannot be obfuscated (header alone is 8+ bytes); passed
/// through as plaintext (eMule `DecryptReceivedClient`).
const MIN_OBFUSCATED_LEN: usize = 8;

/// Protocol header bytes that mark a PLAINTEXT datagram; a marker byte equal to
/// any of these is treated as unobfuscated by the receiver, so the sender never
/// emits one. This is exactly eMule/aMule's UDP set (`EncryptedDatagramSocket`
/// send switch and `DecryptReceivedClient` passthrough): OP_EMULEPROT 0xC5,
/// OP_PACKEDPROT 0xD4, OP_KADEMLIAHEADER 0xE4, OP_KADEMLIAPACKEDPROT 0xE5,
/// OP_UDPRESERVEDPROT1 0xA3, OP_UDPRESERVEDPROT2 0xB2. It is NOT the TCP set:
/// 0xE3/0xF4/0xF5 are not excluded here (a real peer may send 0xF4 as a Kad
/// marker), and 0xA3/0xB2 must be (a 0xB2 marker is otherwise a valid
/// ReceiverKey marker a peer would treat as plaintext and drop).
fn is_protocol_byte(b: u8) -> bool {
    matches!(b, 0xC5 | 0xD4 | 0xE4 | 0xE5 | 0xA3 | 0xB2)
}

/// The plaintext marker byte: low 2 bits carry the Kad key hint (0b00 = NodeID
/// key, 0b10 = ReceiverKey), upper 6 bits are `rand`, nudged (preserving the low
/// bits) off any real protocol byte.
fn make_marker(rand: u8, receiver_key: bool) -> u8 {
    let low = if receiver_key { 0b10 } else { 0b00 };
    let mut m = (rand & 0xFC) | low;
    while is_protocol_byte(m) {
        m = m.wrapping_add(4); // +4 keeps the low 2 bits fixed
    }
    m
}

/// RC4 key for a REQUEST: MD5 of the target node's 16 wire-form ID bytes
/// followed by the 2-byte random key seed (eMule `achKeyData[18]`).
fn nodeid_key(target_wire: &[u8; 16], random_key_part: u16) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(target_wire);
    h.update(random_key_part.to_le_bytes());
    h.finalize().into()
}

/// RC4 key for a RESPONSE: MD5 of the verify-key u32 (LE) followed by the
/// random key seed (eMule `achKeyData[6]`).
fn receiver_key(verify_key: u32, random_key_part: u16) -> [u8; 16] {
    let mut h = Md5::new();
    h.update(verify_key.to_le_bytes());
    h.update(random_key_part.to_le_bytes());
    h.finalize().into()
}

/// Anti-spoof key we issue for a peer at `ip`: `MD5((kad_udp_key<<32)|ip)` folded
/// to a nonzero u32 (eMule `CPreferences::GetUDPVerifyKey`). A peer that echoes
/// this back proves it received a packet we actually sent to its IP.
pub fn udp_verify_key(kad_udp_key: u32, ip: u32) -> u32 {
    // Low 32 bits of the u64 are the IP, high 32 the key; LE bytes are therefore
    // ip[4] then kad_udp_key[4], matching eMule's `&ui64` memcpy.
    let ui64 = ((kad_udp_key as u64) << 32) | ip as u64;
    let d = Md5::digest(ui64.to_le_bytes());
    let folded = u32::from_le_bytes([d[0], d[1], d[2], d[3]])
        ^ u32::from_le_bytes([d[4], d[5], d[6], d[7]])
        ^ u32::from_le_bytes([d[8], d[9], d[10], d[11]])
        ^ u32::from_le_bytes([d[12], d[13], d[14], d[15]]);
    (folded % 0xFFFF_FFFE) + 1
}

/// Assemble one obfuscated datagram given the already-derived RC4 `key`.
fn assemble(
    key: &[u8; 16],
    marker: u8,
    random_key_part: u16,
    receiver_vk: u32,
    sender_vk: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 13 + payload.len());
    out.push(marker); // [0] plaintext
    out.extend_from_slice(&random_key_part.to_le_bytes()); // [1..2] plaintext

    // The RC4 region: sentinel | padLen(0) | receiverVK | senderVK | payload.
    // padLen is 0 for Kad so no pad bytes follow.
    let mut region = Vec::with_capacity(13 + payload.len());
    region.extend_from_slice(&MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes());
    region.push(0); // byPadLen
    region.extend_from_slice(&receiver_vk.to_le_bytes());
    region.extend_from_slice(&sender_vk.to_le_bytes());
    region.extend_from_slice(payload);

    Rc4::new(key).apply(&mut region); // NO discard for UDP
    out.extend_from_slice(&region);
    out
}

/// Obfuscate a Kad REQUEST (NodeID-keyed on the destination's `target_id`).
/// `receiver_vk` is the verify key the peer previously handed us (0 if none);
/// `sender_vk` is [`udp_verify_key`] for the destination IP (we want it echoed).
pub fn kad_obfuscate_request(
    payload: &[u8],
    target_id: &Kad128,
    random_key_part: u16,
    receiver_vk: u32,
    sender_vk: u32,
    marker_rand: u8,
) -> Vec<u8> {
    let key = nodeid_key(&target_id.to_wire(), random_key_part);
    let marker = make_marker(marker_rand, false);
    assemble(
        &key,
        marker,
        random_key_part,
        receiver_vk,
        sender_vk,
        payload,
    )
}

/// Obfuscate a Kad RESPONSE (ReceiverKey-keyed on `receiver_vk`, the verify key
/// the peer told us to echo - which is also written into the packet's
/// receiver-key field).
pub fn kad_obfuscate_response(
    payload: &[u8],
    random_key_part: u16,
    receiver_vk: u32,
    sender_vk: u32,
    marker_rand: u8,
) -> Vec<u8> {
    let key = receiver_key(receiver_vk, random_key_part);
    let marker = make_marker(marker_rand, true);
    assemble(
        &key,
        marker,
        random_key_part,
        receiver_vk,
        sender_vk,
        payload,
    )
}

/// A successfully deobfuscated Kad datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadDecrypted {
    /// The plaintext Kad frame (starts 0xE4/0xE5); feed to `unpack_kad`.
    pub payload: Vec<u8>,
    /// `nReceiverVerifyKey` from the packet: the key we issued that the sender
    /// echoed. Compare against `udp_verify_key(our_key, sender_ip)` for
    /// `bValidReceiverKey` (IP-verification).
    pub receiver_vk: u32,
    /// `nSenderVerifyKey` from the packet: the key the sender wants US to echo
    /// on our next packet to it.
    pub sender_vk: u32,
    /// True if the ReceiverKey path matched (a response to a request we sent);
    /// false if the NodeID path matched (a request addressed to our node).
    pub used_receiver_key: bool,
}

/// Try one candidate RC4 key against a datagram; `Some` only if the sync
/// sentinel decrypts correctly and the header is well-formed.
fn try_decrypt(datagram: &[u8], key: &[u8; 16], used_receiver_key: bool) -> Option<KadDecrypted> {
    // The whole region from [3] is one contiguous keystream.
    let mut region = datagram[3..].to_vec();
    Rc4::new(key).apply(&mut region);
    if region.len() < 4 {
        return None;
    }
    let sentinel = u32::from_le_bytes([region[0], region[1], region[2], region[3]]);
    if sentinel != MAGICVALUE_UDP_SYNC_CLIENT {
        return None;
    }
    // sentinel(4) | padLen(1) | pad(padLen) | receiverVK(4) | senderVK(4) | payload
    // padLen is NOT masked on the Kad client path (unlike the ed2k server path).
    let pad_len = region[4] as usize;
    let off = 5 + pad_len;
    // eMule rejects (as junk, without learning the keys) a packet with no room
    // for both verify keys AND at least one payload byte: `if (result <= 8)`.
    if region.len() <= off + 8 {
        return None;
    }
    let receiver_vk = u32::from_le_bytes([
        region[off],
        region[off + 1],
        region[off + 2],
        region[off + 3],
    ]);
    let sender_vk = u32::from_le_bytes([
        region[off + 4],
        region[off + 5],
        region[off + 6],
        region[off + 7],
    ]);
    let payload = region[off + 8..].to_vec();
    Some(KadDecrypted {
        payload,
        receiver_vk,
        sender_vk,
        used_receiver_key,
    })
}

/// Deobfuscate an incoming Kad datagram. Returns `None` for a plaintext datagram
/// (marker is a real protocol byte, or too short) or one that matches neither
/// Kad key. Tries the NodeID key (our own `our_id`) and the ReceiverKey
/// (`udp_verify_key(our_udp_key, sender_ip)`), ordered by the marker hint.
pub fn kad_deobfuscate(
    datagram: &[u8],
    our_id: &Kad128,
    our_udp_key: u32,
    sender_ip: u32,
) -> Option<KadDecrypted> {
    if datagram.len() <= MIN_OBFUSCATED_LEN || is_protocol_byte(datagram[0]) {
        return None;
    }
    let random_key_part = u16::from_le_bytes([datagram[1], datagram[2]]);
    let nodeid = nodeid_key(&our_id.to_wire(), random_key_part);
    let recvkey = receiver_key(udp_verify_key(our_udp_key, sender_ip), random_key_part);

    // Marker low 2 bits hint which key to try first (never trusted, just ordered).
    let prefer_receiver = (datagram[0] & 3) == 2;
    let order: [(bool, &[u8; 16]); 2] = if prefer_receiver {
        [(true, &recvkey), (false, &nodeid)]
    } else {
        [(false, &nodeid), (true, &recvkey)]
    };
    for (is_recv, key) in order {
        if let Some(d) = try_decrypt(datagram, key, is_recv) {
            return Some(d);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kid(seed: u8) -> Kad128 {
        Kad128::from_hash(&[seed; 16])
    }

    #[test]
    fn request_round_trips_via_nodeid_key() {
        // A node with id `server` receives a request addressed to it: it decrypts
        // with its OWN id as the NodeID key.
        let server = kid(0x11);
        let payload = vec![0xE4, 0x01]; // BOOTSTRAP_REQ frame
        let dg = kad_obfuscate_request(&payload, &server, 0xBEEF, 0, 0x1234_5678, 0x40);
        let d = kad_deobfuscate(
            &dg,
            &server,
            /*our_udp_key*/ 999,
            /*sender_ip*/ 0x0A00_0001,
        )
        .expect("server decrypts a request keyed on its own id");
        assert_eq!(d.payload, payload);
        assert!(!d.used_receiver_key);
        assert_eq!(d.sender_vk, 0x1234_5678);
        assert_eq!(d.receiver_vk, 0);
    }

    #[test]
    fn response_round_trips_via_receiver_key() {
        // We sent a request to a peer; it replies ReceiverKey-encrypted with the
        // verify key WE issued for its IP. We decrypt with the same value.
        let our_key = 0xA1B2_C3D4u32;
        let peer_ip = 0x0102_0304u32;
        let vk = udp_verify_key(our_key, peer_ip); // the key we issued them
        let payload = vec![0xE4, 0x09, 0xAA, 0xBB];
        let dg = kad_obfuscate_response(&payload, 0x1357, vk, 0xCAFE_F00D, 0x80);
        let d = kad_deobfuscate(&dg, &kid(0x22), our_key, peer_ip)
            .expect("we decrypt a response via the receiver key we issued");
        assert_eq!(d.payload, payload);
        assert!(d.used_receiver_key);
        assert_eq!(d.receiver_vk, vk);
        assert_eq!(d.sender_vk, 0xCAFE_F00D);
    }

    #[test]
    fn sentinel_is_c1_2e_5f_39_on_the_wire() {
        assert_eq!(
            MAGICVALUE_UDP_SYNC_CLIENT.to_le_bytes(),
            [0xC1, 0x2E, 0x5F, 0x39]
        );
    }

    #[test]
    fn marker_low_bits_encode_the_key_class_and_avoid_protocol_bytes() {
        for r in 0u16..=255 {
            let r = r as u8;
            let nid = make_marker(r, false);
            let rk = make_marker(r, true);
            assert_eq!(nid & 3, 0b00, "NodeID marker low bits");
            assert_eq!(rk & 3, 0b10, "ReceiverKey marker low bits");
            assert!(!is_protocol_byte(nid) && !is_protocol_byte(rk));
        }
    }

    #[test]
    fn protocol_byte_set_matches_amule_exactly() {
        // aMule's UDP set: 0xC5 0xD4 0xE4 0xE5 0xA3 0xB2.
        for b in [0xC5, 0xD4, 0xE4, 0xE5, 0xA3, 0xB2] {
            assert!(is_protocol_byte(b), "0x{b:02X} must be a protocol byte");
        }
        // These are TCP-only / ed2kv2 markers a real peer MAY use as a Kad marker;
        // treating them as plaintext would drop valid packets.
        for b in [0xE3, 0xF4, 0xF5] {
            assert!(!is_protocol_byte(b), "0x{b:02X} must NOT be excluded");
        }
        // A ReceiverKey marker (low bits 0b10) must never collide with 0xB2.
        assert_ne!(make_marker(0xB0, true), 0xB2);
    }

    #[test]
    fn plaintext_and_short_datagrams_pass_through_as_none() {
        // A real protocol byte at [0] -> not obfuscated.
        let plain = vec![0xE4, 0x01, 0x00, 0, 0, 0, 0, 0, 0, 0];
        assert!(kad_deobfuscate(&plain, &kid(1), 0, 0).is_none());
        // Too short.
        assert!(kad_deobfuscate(&[0x40, 1, 2, 3], &kid(1), 0, 0).is_none());
    }

    #[test]
    fn wrong_key_does_not_falsely_decrypt() {
        let payload = vec![0xE4, 0x21, 1, 2, 3];
        let dg = kad_obfuscate_request(&payload, &kid(0x11), 0x1111, 0, 0, 0x10);
        // A different node id -> neither key matches the sentinel.
        assert!(kad_deobfuscate(&dg, &kid(0x99), 12345, 0x0808_0808).is_none());
    }

    #[test]
    fn udp_verify_key_is_never_zero_and_depends_on_ip_and_key() {
        assert_ne!(udp_verify_key(0, 0), 0);
        assert_ne!(udp_verify_key(0xDEAD_BEEF, 0x0102_0304), 0);
        assert_ne!(
            udp_verify_key(0xDEAD_BEEF, 0x0102_0304),
            udp_verify_key(0xDEAD_BEEF, 0x0102_0305),
            "different IP -> different key"
        );
        assert_ne!(
            udp_verify_key(0xDEAD_BEEF, 0x0102_0304),
            udp_verify_key(0xDEAD_BEEE, 0x0102_0304),
            "different install key -> different key"
        );
        // Deterministic.
        assert_eq!(
            udp_verify_key(0x1234_5678, 0x5566_7788),
            udp_verify_key(0x1234_5678, 0x5566_7788)
        );
    }
}
