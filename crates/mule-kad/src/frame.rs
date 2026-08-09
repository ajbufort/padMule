//! Kad UDP framing: the plaintext packet that rides inside the obfuscation
//! layer. See docs/raw/wave6-kad-research-2026-07-14.md section B.
//!
//! Wire form after obfuscation is stripped:
//!
//! ```text
//! [0] = 0xE4 (OP_KADEMLIAHEADER)   |  [1] = opcode  |  [2..] = payload
//! ```
//!
//! If the PAYLOAD exceeds 200 bytes (opcode and header excluded) it is
//! zlib-packed: the header becomes 0xE5 (OP_KADEMLIAPACKEDPROT) and ONLY the
//! payload after the opcode is compressed (the opcode byte is copied
//! verbatim). Send path: eMule `CKademliaUDPListener::SendPacket`
//! (KademliaUDPListener.cpp:2043-2092; see [`KAD_PACK_THRESHOLD`] for the
//! overloads and a known 2-byte divergence); receive path
//! `ClientUDPSocket.cpp:103` (case OP_KADEMLIAPACKEDPROT).

use mule_proto::{compress, decompress, IoError, Packet, PROT_KAD, PROT_KAD_PACKED};

/// padMule packs a Kad datagram only when the PAYLOAD (the bytes after the
/// 0xE4/opcode header) exceeds this; below it the frame is always sent plain.
///
/// The authorities, as actually read:
/// - eMule 0.50a `CKademliaUDPListener::SendPacket` has a CSafeMemFile
///   overload testing `pPacket->size > 200` (KademliaUDPListener.cpp:2084),
///   where `size` is the memfile length - payload only, header and opcode
///   excluded (`Packet::Packet(CMemFile*, ...)`, packets.cpp:107-112). Most
///   Kad sends go this way, and padMule matches it exactly.
/// - eMule 0.50a also has a raw-byte-array overload whose buffer INCLUDES the
///   2-byte header and which tests `uLenData > 200` on that whole length
///   (KademliaUDPListener.cpp:2043-2055), i.e. it packs from payload >= 199.
///   `SendMyDetails` (:151-157) and `SendPublishSourcePacket` (:230-233) use
///   it, so eMule packs ITS hello/publish-source sends two bytes sooner.
/// - aMule master has one CMemFile overload testing
///   `packet->GetPacketSize() > 200` (src/kademlia/net/
///   KademliaUDPListener.cpp:1849), and `GetPacketSize()` returns the payload
///   `size` (src/Packet.h:70) - payload-only for every send.
///
/// KNOWN, DELIBERATE DIVERGENCE: padMule applies the payload-only rule to all
/// sends, so a 199- or 200-byte payload that eMule's raw-array paths would
/// pack goes out plain here. Interop-safe by construction - every receiver
/// handles 0xE4 and 0xE5 alike (eMule ClientUDPSocket.cpp:103), packing is a
/// size optimization, not a protocol requirement.
pub const KAD_PACK_THRESHOLD: usize = 200;

/// Build a plaintext Kad frame `0xE4|opcode|payload`, zlib-packing to
/// `0xE5|opcode|compressed` when the payload exceeds [`KAD_PACK_THRESHOLD`] and
/// compression actually shrinks it (matching eMule `Packet::PackPacket`, which
/// reverts to the raw form when `size <= newsize`, packets.cpp:199-206).
pub fn pack_kad(opcode: u8, payload: Vec<u8>) -> Vec<u8> {
    let p = Packet::new(PROT_KAD, opcode, payload);
    // Only attempt compression above the threshold; `compress` keeps the
    // uncompressed form when it does not help, so the wire output matches eMule.
    let p = if p.payload.len() > KAD_PACK_THRESHOLD {
        compress(&p)
    } else {
        p
    };
    let mut out = Vec::with_capacity(2 + p.payload.len());
    out.push(p.protocol);
    out.push(p.opcode);
    out.extend_from_slice(&p.payload);
    out
}

/// Parse a plaintext Kad frame into `(opcode, payload)`, decompressing a
/// 0xE5-packed frame. The datagram must start with 0xE4 or 0xE5 and hold at
/// least the 2-byte header.
pub fn unpack_kad(frame: &[u8]) -> Result<(u8, Vec<u8>), IoError> {
    if frame.len() < 2 {
        return Err(IoError::UnexpectedEof);
    }
    let protocol = frame[0];
    let opcode = frame[1];
    let body = frame[2..].to_vec();
    match protocol {
        PROT_KAD => Ok((opcode, body)),
        PROT_KAD_PACKED => {
            let packed = Packet::new(PROT_KAD_PACKED, opcode, body);
            // Bound inflation like aMule: packetLen * 10 + 300
            // (ClientUDPSocket.cpp:109), NOT the 2MB TCP packet cap - a hostile
            // ~1.4KB datagram must not balloon to megabytes.
            let un = decompress(&packed, frame.len() * 10 + 300)?;
            Ok((opcode, un.payload))
        }
        _ => Err(IoError::BadHeader(protocol)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_frame_is_plain_and_round_trips() {
        let payload = vec![1, 2, 3, 4];
        let frame = pack_kad(0x21, payload.clone());
        assert_eq!(frame[0], PROT_KAD);
        assert_eq!(frame[1], 0x21);
        assert_eq!(&frame[2..], &payload[..]);
        assert_eq!(unpack_kad(&frame).unwrap(), (0x21, payload));
    }

    #[test]
    fn unpack_rejects_a_zlib_bomb_beyond_the_amule_inflation_bound() {
        // aMule bounds Kad UDP decompression to packetLen * 10 + 300
        // (ClientUDPSocket.cpp:109); a ~150KB-of-zeros payload packs to a tiny
        // datagram whose inflation blows that bound and must be REJECTED, not
        // ballooned to MAX_PACKET_SIZE.
        let frame = pack_kad(0x2B, vec![0u8; 150_000]);
        assert_eq!(frame[0], PROT_KAD_PACKED, "sanity: the bomb packed");
        assert!(frame.len() < 2_000, "sanity: it compressed massively");
        assert!(unpack_kad(&frame).is_err());
    }

    #[test]
    fn unpack_accepts_a_packed_frame_within_the_inflation_bound() {
        // A legitimately compressible payload whose inflation stays under
        // packetLen * 10 + 300 still unpacks fine.
        let payload = vec![0u8; 250];
        let frame = pack_kad(0x2B, payload.clone());
        assert_eq!(frame[0], PROT_KAD_PACKED);
        assert_eq!(unpack_kad(&frame).unwrap(), (0x2B, payload));
    }

    #[test]
    fn empty_payload_frame() {
        // BOOTSTRAP_REQ: opcode with a zero-length payload.
        let frame = pack_kad(0x01, Vec::new());
        assert_eq!(frame, vec![PROT_KAD, 0x01]);
        assert_eq!(unpack_kad(&frame).unwrap(), (0x01, Vec::new()));
    }

    #[test]
    fn large_compressible_frame_packs_and_round_trips() {
        // > 200 bytes and highly compressible -> 0xE5, opcode preserved.
        let payload = vec![0xABu8; 500];
        let frame = pack_kad(0x29, payload.clone());
        assert_eq!(frame[0], PROT_KAD_PACKED, "large frame must pack");
        assert_eq!(frame[1], 0x29, "opcode byte is never compressed");
        assert!(frame.len() < 2 + payload.len(), "packing must shrink it");
        assert_eq!(unpack_kad(&frame).unwrap(), (0x29, payload));
    }

    #[test]
    fn large_incompressible_frame_stays_plain() {
        // Over the threshold but random -> compression does not help, sent plain.
        let payload: Vec<u8> = (0..400u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
            .collect();
        let frame = pack_kad(0x29, payload.clone());
        assert_eq!(frame[0], PROT_KAD, "incompressible frame is not packed");
        assert_eq!(unpack_kad(&frame).unwrap(), (0x29, payload));
    }

    #[test]
    fn threshold_is_payload_length_not_frame_length() {
        // The payload-only rule padMule follows: aMule tests
        // `GetPacketSize() > 200` (KademliaUDPListener.cpp:1849), the payload
        // alone (Packet.h:70), and eMule's CSafeMemFile overload agrees - see
        // KAD_PACK_THRESHOLD for eMule's raw-array paths, which count the
        // 2-byte header (a recorded, interop-safe divergence). So a 200-byte
        // payload - even a highly compressible one - is sent PLAIN (200 is
        // not > 200); 201 packs.
        let plain = pack_kad(0x11, vec![0u8; 200]);
        assert_eq!(plain[0], PROT_KAD, "payload == 200 must not pack");
        assert_eq!(plain.len(), 202); // 2 header + 200 payload

        let packed = pack_kad(0x11, vec![0u8; 201]);
        assert_eq!(packed[0], PROT_KAD_PACKED, "payload == 201 must pack");
    }

    #[test]
    fn rejects_short_and_foreign_frames() {
        assert!(unpack_kad(&[0xE4]).is_err());
        assert!(unpack_kad(&[]).is_err());
        assert!(unpack_kad(&[0xE3, 0x01, 0x02]).is_err());
    }
}
