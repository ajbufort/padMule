//! Kad UDP framing: the plaintext packet that rides inside the obfuscation
//! layer. See docs/raw/wave6-kad-research-2026-07-14.md section B.
//!
//! Wire form after obfuscation is stripped:
//!
//! ```text
//! [0] = 0xE4 (OP_KADEMLIAHEADER)   |  [1] = opcode  |  [2..] = payload
//! ```
//!
//! If the whole frame would exceed 200 bytes it is zlib-packed: the header
//! becomes 0xE5 (OP_KADEMLIAPACKEDPROT) and ONLY the payload after the opcode
//! is compressed (the opcode byte is copied verbatim). eMule
//! `KademliaUDPListener.cpp:2050-2090`; receive path `ClientUDPSocket.cpp:103`.

use mule_proto::{
    compress, decompress, IoError, Packet, MAX_PACKET_SIZE, PROT_KAD, PROT_KAD_PACKED,
};

/// eMule/aMule packs a Kad datagram only when the PAYLOAD (the bytes after the
/// 0xE4/opcode header) exceeds this. `CKademliaUDPListener::SendPacket` tests
/// `packet->GetPacketSize() > 200`, and `GetPacketSize()` is the CMemFile payload
/// length - the opcode and header byte are NOT counted (`Packet.cpp:96-98`,
/// `KademliaUDPListener.cpp:1610`). Below it the frame is always sent plain.
pub const KAD_PACK_THRESHOLD: usize = 200;

/// Build a plaintext Kad frame `0xE4|opcode|payload`, zlib-packing to
/// `0xE5|opcode|compressed` when the payload exceeds [`KAD_PACK_THRESHOLD`] and
/// compression actually shrinks it (matching eMule `CPacket::PackPacket`, which
/// reverts to the raw form when `size <= newsize`).
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
            let un = decompress(&packed, MAX_PACKET_SIZE)?;
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
        // aMule tests `GetPacketSize() > 200` where GetPacketSize is the payload
        // alone (opcode/header excluded). So a 200-byte payload - even a highly
        // compressible one - is sent PLAIN (200 is not > 200); 201 packs.
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
