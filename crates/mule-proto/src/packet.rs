//! eD2k/eMule TCP packet framing and zlib packing. See docs/raw reference
//! sections 1-4 (EMSocket.cpp, Packet.cpp:80-307, Protocols.h).
//!
//! Wire frame: `[protocol u8][packetlength u32 LE][opcode u8][payload]`, where
//! `packetlength = 1 + payload.len()` (it includes the opcode byte). Total wire
//! size is `6 + payload.len()`. A zlib-packed packet compresses ONLY the
//! payload and swaps the protocol byte to a packed variant.
//!
//! `read_packet` is a STREAMING parser: it returns `Ok(None)` when the buffer
//! holds only part of a frame, so a socket read loop can call it as bytes
//! arrive. aMule does not emit multi-fragment "split" packets; a single packet
//! may be arbitrarily large up to `MAX_PACKET_SIZE`.

use crate::io::IoError;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::io::{Read, Write};

/// Base eDonkey protocol byte.
pub const PROT_EDONKEY: u8 = 0xE3;
/// eMule extended protocol byte.
pub const PROT_EMULE: u8 = 0xC5;
/// zlib-packed packet (payload decompresses to an eMule-extended packet).
pub const PROT_PACKED: u8 = 0xD4;
/// Kad (TCP-style header) protocol byte.
pub const PROT_KAD: u8 = 0xE4;
/// zlib-packed Kad packet.
pub const PROT_KAD_PACKED: u8 = 0xE5;
/// aMule experimental ED2Kv2 header.
pub const PROT_ED2KV2: u8 = 0xF4;
/// zlib-packed ED2Kv2 packet.
pub const PROT_ED2KV2_PACKED: u8 = 0xF5;

/// Maximum payload size accepted for a single packet (EMSocket MAX_PACKET_SIZE).
pub const MAX_PACKET_SIZE: usize = 2_000_000;

const HEADER_SIZE: usize = 6;

/// One framed eD2k/eMule packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub protocol: u8,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

impl Packet {
    pub fn new(protocol: u8, opcode: u8, payload: Vec<u8>) -> Self {
        Packet {
            protocol,
            opcode,
            payload,
        }
    }
}

fn is_known_protocol(p: u8) -> bool {
    matches!(
        p,
        PROT_EDONKEY
            | PROT_EMULE
            | PROT_PACKED
            | PROT_KAD
            | PROT_KAD_PACKED
            | PROT_ED2KV2
            | PROT_ED2KV2_PACKED
    )
}

/// Serialize `p` to its wire bytes.
pub fn write_packet(p: &Packet) -> Vec<u8> {
    let packetlength = (1 + p.payload.len()) as u32;
    let mut out = Vec::with_capacity(HEADER_SIZE + p.payload.len());
    out.push(p.protocol);
    out.extend_from_slice(&packetlength.to_le_bytes());
    out.push(p.opcode);
    out.extend_from_slice(&p.payload);
    out
}

/// Try to parse one packet from the front of `buf`.
///
/// Returns `Ok(Some((packet, consumed)))` when a full frame is available (the
/// caller should drop `consumed` bytes from the buffer), `Ok(None)` when more
/// bytes are needed, or `Err` for a malformed header (unknown protocol byte or
/// oversized payload).
pub fn read_packet(buf: &[u8]) -> Result<Option<(Packet, usize)>, IoError> {
    if buf.len() < HEADER_SIZE {
        return Ok(None);
    }
    let protocol = buf[0];
    if !is_known_protocol(protocol) {
        return Err(IoError::BadHeader(protocol));
    }
    let packetlength = u32::from_le_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if packetlength < 1 {
        return Err(IoError::BadHeader(protocol));
    }
    let payload_size = (packetlength - 1) as usize;
    if payload_size > MAX_PACKET_SIZE {
        return Err(IoError::TooBig);
    }
    let total = HEADER_SIZE + payload_size;
    if buf.len() < total {
        return Ok(None);
    }
    let opcode = buf[5];
    let payload = buf[HEADER_SIZE..total].to_vec();
    Ok(Some((
        Packet {
            protocol,
            opcode,
            payload,
        },
        total,
    )))
}

fn packed_protocol_for(protocol: u8) -> u8 {
    match protocol {
        PROT_KAD => PROT_KAD_PACKED,
        PROT_ED2KV2 => PROT_ED2KV2_PACKED,
        _ => PROT_PACKED,
    }
}

/// zlib-compress `p`'s payload. If the compressed payload is smaller, return a
/// new packet with the packed protocol byte; otherwise return `p` unchanged
/// (matching aMule, which keeps the uncompressed form when it does not shrink).
pub fn compress(p: &Packet) -> Packet {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
    if enc.write_all(&p.payload).is_err() {
        return p.clone();
    }
    match enc.finish() {
        Ok(compressed) if compressed.len() < p.payload.len() => Packet {
            protocol: packed_protocol_for(p.protocol),
            opcode: p.opcode,
            payload: compressed,
        },
        _ => p.clone(),
    }
}

/// zlib-decompress a packed packet (`0xD4`/`0xF5` -> `0xC5`, `0xE5` -> `0xE4`),
/// bounding the output to `max_size` bytes. Errors if `p` is not a packed
/// packet, the output would exceed `max_size`, or the zlib stream is invalid.
pub fn decompress(p: &Packet, max_size: usize) -> Result<Packet, IoError> {
    let protocol = match p.protocol {
        PROT_PACKED | PROT_ED2KV2_PACKED => PROT_EMULE,
        PROT_KAD_PACKED => PROT_KAD,
        other => return Err(IoError::BadHeader(other)),
    };
    let mut dec = ZlibDecoder::new(&p.payload[..]).take(max_size as u64 + 1);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).map_err(|_| IoError::Decompress)?;
    if out.len() > max_size {
        return Err(IoError::TooBig);
    }
    Ok(Packet {
        protocol,
        opcode: p.opcode,
        payload: out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_packet_golden() {
        let p = Packet::new(PROT_EDONKEY, 0x01, vec![0xAA, 0xBB]);
        // [E3][len=3 LE][opcode 01][AA BB]
        assert_eq!(
            write_packet(&p),
            vec![0xE3, 0x03, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB]
        );
    }

    #[test]
    fn read_full_single_packet() {
        let bytes = [0xE3u8, 0x03, 0x00, 0x00, 0x00, 0x01, 0xAA, 0xBB];
        let (p, consumed) = read_packet(&bytes).unwrap().unwrap();
        assert_eq!(p, Packet::new(PROT_EDONKEY, 0x01, vec![0xAA, 0xBB]));
        assert_eq!(consumed, 8);
    }

    #[test]
    fn read_returns_none_when_incomplete() {
        // Fewer than 6 header bytes.
        assert_eq!(read_packet(&[0xE3, 0x03, 0x00]).unwrap(), None);
        // Full header but payload not all here (needs 2 payload bytes, has 1).
        assert_eq!(
            read_packet(&[0xE3, 0x03, 0x00, 0x00, 0x00, 0x01, 0xAA]).unwrap(),
            None
        );
    }

    #[test]
    fn read_two_concatenated_packets() {
        let mut stream = write_packet(&Packet::new(PROT_EDONKEY, 0x01, vec![0xAA]));
        stream.extend(write_packet(&Packet::new(
            PROT_EMULE,
            0x60,
            vec![0x11, 0x22],
        )));
        let (p1, c1) = read_packet(&stream).unwrap().unwrap();
        assert_eq!(p1, Packet::new(PROT_EDONKEY, 0x01, vec![0xAA]));
        let (p2, c2) = read_packet(&stream[c1..]).unwrap().unwrap();
        assert_eq!(p2, Packet::new(PROT_EMULE, 0x60, vec![0x11, 0x22]));
        assert_eq!(c1 + c2, stream.len());
    }

    #[test]
    fn read_rejects_unknown_protocol() {
        let bytes = [0x99u8, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_packet(&bytes), Err(IoError::BadHeader(0x99)));
    }

    #[test]
    fn read_rejects_oversized_payload() {
        // packetlength = MAX+2 -> payload_size = MAX+1 > MAX_PACKET_SIZE.
        let plen = (MAX_PACKET_SIZE as u32) + 2;
        let mut bytes = vec![0xE3u8];
        bytes.extend_from_slice(&plen.to_le_bytes());
        bytes.push(0x01);
        assert_eq!(read_packet(&bytes), Err(IoError::TooBig));
    }

    #[test]
    fn compress_then_decompress_round_trips_and_remaps_protocol() {
        let payload = vec![b'z'; 2000]; // highly compressible
        let p = Packet::new(PROT_EMULE, 0x33, payload.clone());
        let packed = compress(&p);
        assert_eq!(packed.protocol, PROT_PACKED);
        assert!(packed.payload.len() < payload.len());
        let unpacked = decompress(&packed, MAX_PACKET_SIZE).unwrap();
        assert_eq!(unpacked, p);
    }

    #[test]
    fn compress_keeps_incompressible_unchanged() {
        // A tiny payload will not shrink; protocol stays PROT_EMULE.
        let p = Packet::new(PROT_EMULE, 0x33, vec![0x01]);
        assert_eq!(compress(&p), p);
    }

    #[test]
    fn kad_and_ed2kv2_pack_to_their_variants() {
        let big = vec![0u8; 2000];
        assert_eq!(
            compress(&Packet::new(PROT_KAD, 0x21, big.clone())).protocol,
            PROT_KAD_PACKED
        );
        assert_eq!(
            compress(&Packet::new(PROT_ED2KV2, 0x47, big)).protocol,
            PROT_ED2KV2_PACKED
        );
    }

    #[test]
    fn decompress_rejects_non_packed() {
        let p = Packet::new(PROT_EMULE, 0x33, vec![0x01, 0x02]);
        assert_eq!(
            decompress(&p, MAX_PACKET_SIZE),
            Err(IoError::BadHeader(PROT_EMULE))
        );
    }

    #[test]
    fn decompress_respects_max_size() {
        let payload = vec![b'z'; 5000];
        let packed = compress(&Packet::new(PROT_EMULE, 0x33, payload));
        // Decompressed is 5000 bytes; cap at 100 -> TooBig.
        assert_eq!(decompress(&packed, 100), Err(IoError::TooBig));
    }
}
