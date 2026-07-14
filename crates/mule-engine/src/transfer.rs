//! Client-to-client file-transfer message codecs (the download side). See
//! BaseClient.cpp / DownloadClient.cpp / PartFile.cpp and protocol-understanding
//! Part 2. Pure; the transfer state machine that drives these lands next.
//!
//! Offsets follow aMule's wire convention: block ends are EXCLUSIVE on the wire
//! (aMule writes `EndOffset + 1`), so this module's `(start, end)` pairs are
//! start-inclusive / end-exclusive throughout.

use mule_proto::{IoError, Packet, Reader, Writer, PROT_EDONKEY, PROT_EMULE};

// Opcodes. Protocol byte noted; most are base eDonkey (0xE3).
pub const OP_SENDINGPART: u8 = 0x46; // E3
pub const OP_REQUESTPARTS: u8 = 0x47; // E3
pub const OP_FILEREQANSNOFIL: u8 = 0x48; // E3
pub const OP_SETREQFILEID: u8 = 0x4F; // E3
pub const OP_FILESTATUS: u8 = 0x50; // E3
pub const OP_HASHSETREQUEST: u8 = 0x51; // E3
pub const OP_HASHSETANSWER: u8 = 0x52; // E3
pub const OP_STARTUPLOADREQ: u8 = 0x54; // E3
pub const OP_ACCEPTUPLOADREQ: u8 = 0x55; // E3
pub const OP_OUTOFPARTREQS: u8 = 0x57; // E3
pub const OP_REQUESTFILENAME: u8 = 0x58; // E3
pub const OP_REQFILENAMEANSWER: u8 = 0x59; // E3
pub const OP_QUEUERANKING: u8 = 0x60; // C5 (eMule ext)
pub const OP_COMPRESSEDPART_I64: u8 = 0xA1; // C5
pub const OP_SENDINGPART_I64: u8 = 0xA2; // C5
pub const OP_REQUESTPARTS_I64: u8 = 0xA3; // C5

/// The requestable transfer block size (180 KiB).
pub const EMBLOCKSIZE: u64 = 184_320;
/// Blocks requested per OP_REQUESTPARTS on the wire (always 3).
pub const STANDARD_BLOCKS_REQUEST: usize = 3;

/// A parsed OP_REQUESTPARTS: the file hash plus its `(start, end_exclusive)`
/// blocks (zero-padding removed).
pub type RequestedBlocks = ([u8; 16], Vec<(u64, u64)>);

fn read_hash16(r: &mut Reader) -> Result<[u8; 16], IoError> {
    let mut h = [0u8; 16];
    h.copy_from_slice(&r.read_bytes(16)?);
    Ok(h)
}

fn hash_only(opcode: u8, hash: &[u8; 16]) -> Packet {
    Packet::new(PROT_EDONKEY, opcode, hash.to_vec())
}

/// OP_REQUESTFILENAME: ask a peer for the name of the file with this hash.
pub fn build_request_filename(hash: &[u8; 16]) -> Packet {
    hash_only(OP_REQUESTFILENAME, hash)
}

/// OP_SETREQFILEID: tell the peer which file we want (before OP_FILESTATUS).
pub fn build_set_req_file_id(hash: &[u8; 16]) -> Packet {
    hash_only(OP_SETREQFILEID, hash)
}

/// OP_STARTUPLOADREQ: ask to enter the peer's upload queue for this file.
pub fn build_start_upload_req(hash: &[u8; 16]) -> Packet {
    hash_only(OP_STARTUPLOADREQ, hash)
}

/// OP_HASHSETREQUEST: request the peer's part-hash list for this file.
pub fn build_hashset_request(hash: &[u8; 16]) -> Packet {
    hash_only(OP_HASHSETREQUEST, hash)
}

/// Parse OP_REQFILENAMEANSWER: (file hash, filename bytes).
pub fn parse_req_filename_answer(payload: &[u8]) -> Result<([u8; 16], Vec<u8>), IoError> {
    let mut r = Reader::new(payload);
    let hash = read_hash16(&mut r)?;
    let name = r.read_string_u16()?;
    Ok((hash, name))
}

/// OP_QUEUERANKING payload is exactly this long: a u16 rank + 10 zero bytes.
/// Upstream rejects any other size outright, so we do too.
pub const QUEUE_RANKING_LEN: usize = 12;

/// Parse OP_QUEUERANKING (u16 rank + 10 zero pad).
pub fn parse_queue_ranking(payload: &[u8]) -> Result<u16, IoError> {
    if payload.len() != QUEUE_RANKING_LEN {
        return Err(IoError::UnexpectedEof);
    }
    Reader::new(payload).read_u16()
}

/// OP_QUEUERANKING: tell a waiting downloader its 1-BASED place in our queue.
///
/// Rank 0 means "not queued" and is never sent - callers must not pass it.
/// The 10 trailing zero bytes are not optional; upstream size-checks the packet.
/// This is sent only on queue insertion and on each re-ask, NOT on a timer.
pub fn build_queue_ranking(rank: u16) -> Packet {
    debug_assert!(
        rank > 0,
        "rank is 1-based; 0 means not queued and is not sent"
    );
    let mut w = Writer::new();
    w.write_u16(rank);
    w.write_bytes(&[0u8; QUEUE_RANKING_LEN - 2]);
    Packet::new(PROT_EMULE, OP_QUEUERANKING, w.into_inner())
}

/// OP_OUTOFPARTREQS (empty): revoke a slot, bouncing the peer back to the queue.
/// Upstream immediately re-queues the client, so a fresh OP_QUEUERANKING follows.
pub fn build_out_of_part_reqs() -> Packet {
    Packet::new(PROT_EDONKEY, OP_OUTOFPARTREQS, Vec::new())
}

/// OP_FILEREQANSNOFIL: "I do not have that file."
///
/// Note the upstream asymmetry this mirrors: only OP_SETREQFILEID (and the
/// multipackets) get this answer. An OP_REQUESTFILENAME or OP_STARTUPLOADREQ for
/// an unknown file is answered with SILENCE, not with this packet.
pub fn build_file_req_ans_no_fil(hash: &[u8; 16]) -> Packet {
    let mut w = Writer::new();
    w.write_bytes(hash);
    Packet::new(PROT_EDONKEY, OP_FILEREQANSNOFIL, w.into_inner())
}

/// Which parts of a file a peer holds (OP_FILESTATUS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileStatus {
    pub hash: [u8; 16],
    /// True if the peer has the COMPLETE file (part count field was 0).
    pub complete: bool,
    /// Per eD2k-part availability (empty when `complete`).
    pub parts: Vec<bool>,
}

impl FileStatus {
    /// True if the peer has part `i` (or the whole file).
    pub fn has_part(&self, i: usize) -> bool {
        self.complete || self.parts.get(i).copied().unwrap_or(false)
    }
}

/// Parse OP_FILESTATUS: hash, u16 part count, then ceil(parts/8) bitfield bytes
/// (bit `1<<i` LSB-first per part). A part-count of 0 means a complete source.
pub fn parse_file_status(payload: &[u8]) -> Result<FileStatus, IoError> {
    let mut r = Reader::new(payload);
    let hash = read_hash16(&mut r)?;
    let part_count = r.read_u16()? as usize;
    if part_count == 0 {
        return Ok(FileStatus {
            hash,
            complete: true,
            parts: Vec::new(),
        });
    }
    let nbytes = part_count.div_ceil(8);
    let bits = r.read_bytes(nbytes)?;
    let mut parts = Vec::with_capacity(part_count);
    for i in 0..part_count {
        parts.push(bits[i / 8] & (1 << (i % 8)) != 0);
    }
    Ok(FileStatus {
        hash,
        complete: false,
        parts,
    })
}

/// Encode a part-availability bitfield the way OP_FILESTATUS / extended requests
/// do: u16 part count + ceil(parts/8) bytes (bit `1<<i` LSB-first).
pub fn write_part_status(parts: &[bool]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u16(parts.len() as u16);
    for chunk in parts.chunks(8) {
        let mut byte = 0u8;
        for (i, &have) in chunk.iter().enumerate() {
            if have {
                byte |= 1 << i;
            }
        }
        w.write_u8(byte);
    }
    w.into_inner()
}

/// Build OP_REQUESTPARTS for up to 3 blocks, each `(start, end_exclusive)`. Uses
/// the 64-bit variant (OP_REQUESTPARTS_I64, prot 0xC5) if any offset exceeds
/// 32 bits, else the legacy 32-bit form (prot 0xE3). Always writes 3 slots
/// (starts first, then ends); missing slots are zero-padded and ignored by the
/// uploader.
pub fn build_request_parts(hash: &[u8; 16], blocks: &[(u64, u64)]) -> Packet {
    let needs_i64 = blocks
        .iter()
        .any(|&(s, e)| s > u32::MAX as u64 || e > u32::MAX as u64);
    let slot = |i: usize| blocks.get(i).copied().unwrap_or((0, 0));
    let mut w = Writer::new();
    w.write_bytes(hash);
    if needs_i64 {
        for i in 0..STANDARD_BLOCKS_REQUEST {
            w.write_u64(slot(i).0);
        }
        for i in 0..STANDARD_BLOCKS_REQUEST {
            w.write_u64(slot(i).1);
        }
        Packet::new(PROT_EMULE, OP_REQUESTPARTS_I64, w.into_inner())
    } else {
        for i in 0..STANDARD_BLOCKS_REQUEST {
            w.write_u32(slot(i).0 as u32);
        }
        for i in 0..STANDARD_BLOCKS_REQUEST {
            w.write_u32(slot(i).1 as u32);
        }
        Packet::new(PROT_EDONKEY, OP_REQUESTPARTS, w.into_inner())
    }
}

/// A received block of file data (OP_SENDINGPART / _I64).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendingPart {
    pub hash: [u8; 16],
    pub start: u64,
    /// Exclusive end; `data.len() == end - start`.
    pub end: u64,
    pub data: Vec<u8>,
}

/// Parse OP_SENDINGPART (`i64 = false`) or OP_SENDINGPART_I64 (`i64 = true`):
/// hash, start, exclusive end, then the raw block bytes.
pub fn parse_sending_part(payload: &[u8], i64: bool) -> Result<SendingPart, IoError> {
    let mut r = Reader::new(payload);
    let hash = read_hash16(&mut r)?;
    let (start, end) = if i64 {
        (r.read_u64()?, r.read_u64()?)
    } else {
        (r.read_u32()? as u64, r.read_u32()? as u64)
    };
    let data = r.read_bytes(r.remaining())?;
    Ok(SendingPart {
        hash,
        start,
        end,
        data,
    })
}

/// OP_REQFILENAMEANSWER: reply to a filename request (hash + filename).
pub fn build_req_filename_answer(hash: &[u8; 16], name: &[u8]) -> Packet {
    let mut w = Writer::new();
    w.write_bytes(hash);
    w.write_string_u16(name);
    Packet::new(PROT_EDONKEY, OP_REQFILENAMEANSWER, w.into_inner())
}

/// OP_FILESTATUS advertising a COMPLETE source (part count 0).
pub fn build_file_status_complete(hash: &[u8; 16]) -> Packet {
    let mut w = Writer::new();
    w.write_bytes(hash);
    w.write_u16(0);
    Packet::new(PROT_EDONKEY, OP_FILESTATUS, w.into_inner())
}

/// OP_ACCEPTUPLOADREQ (empty): grant the requester an upload slot.
pub fn build_accept_upload() -> Packet {
    Packet::new(PROT_EDONKEY, OP_ACCEPTUPLOADREQ, Vec::new())
}

/// OP_SENDINGPART / _I64: serve a block `data` covering `[start, end)`. Uses the
/// 64-bit variant when an offset exceeds 32 bits.
pub fn build_sending_part(hash: &[u8; 16], start: u64, end: u64, data: &[u8]) -> Packet {
    let i64 = start > u32::MAX as u64 || end > u32::MAX as u64;
    let mut w = Writer::new();
    w.write_bytes(hash);
    if i64 {
        w.write_u64(start);
        w.write_u64(end);
        w.write_bytes(data);
        Packet::new(PROT_EMULE, OP_SENDINGPART_I64, w.into_inner())
    } else {
        w.write_u32(start as u32);
        w.write_u32(end as u32);
        w.write_bytes(data);
        Packet::new(PROT_EDONKEY, OP_SENDINGPART, w.into_inner())
    }
}

/// Parse OP_REQUESTPARTS (`i64 = false`) or _I64 (`i64 = true`): the file hash
/// and the non-empty `(start, end_exclusive)` blocks (zero-padding is dropped).
pub fn parse_request_parts(payload: &[u8], i64: bool) -> Result<RequestedBlocks, IoError> {
    let mut r = Reader::new(payload);
    let hash = read_hash16(&mut r)?;
    let mut starts = [0u64; STANDARD_BLOCKS_REQUEST];
    let mut ends = [0u64; STANDARD_BLOCKS_REQUEST];
    for s in starts.iter_mut() {
        *s = if i64 {
            r.read_u64()?
        } else {
            r.read_u32()? as u64
        };
    }
    for e in ends.iter_mut() {
        *e = if i64 {
            r.read_u64()?
        } else {
            r.read_u32()? as u64
        };
    }
    let blocks = starts
        .iter()
        .zip(ends.iter())
        .filter(|(s, e)| e > s)
        .map(|(&s, &e)| (s, e))
        .collect();
    Ok((hash, blocks))
}

/// Parse OP_HASHSETANSWER: (file hash, part hashes).
pub fn parse_hashset_answer(payload: &[u8]) -> Result<([u8; 16], Vec<[u8; 16]>), IoError> {
    let mut r = Reader::new(payload);
    let hash = read_hash16(&mut r)?;
    let count = r.read_u16()? as usize;
    let mut parts = Vec::new(); // untrusted count
    for _ in 0..count {
        parts.push(read_hash16(&mut r)?);
    }
    Ok((hash, parts))
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    #[test]
    fn hash_only_requests() {
        assert_eq!(
            build_request_filename(&H),
            Packet::new(PROT_EDONKEY, OP_REQUESTFILENAME, H.to_vec())
        );
        assert_eq!(build_start_upload_req(&H).opcode, OP_STARTUPLOADREQ);
        assert_eq!(build_hashset_request(&H).opcode, OP_HASHSETREQUEST);
    }

    #[test]
    fn file_status_bitfield_round_trip() {
        // 10 parts: parts 0,3,9 present.
        let mut parts = vec![false; 10];
        parts[0] = true;
        parts[3] = true;
        parts[9] = true;
        let bits = write_part_status(&parts);
        // u16=10, then ceil(10/8)=2 bytes: byte0 = 1<<0 | 1<<3 = 0x09; byte1 = 1<<1 = 0x02
        assert_eq!(bits, vec![0x0A, 0x00, 0x09, 0x02]);

        let mut payload = H.to_vec();
        payload.extend_from_slice(&bits);
        let fs = parse_file_status(&payload).unwrap();
        assert!(!fs.complete);
        assert_eq!(fs.parts, parts);
        assert!(fs.has_part(0) && fs.has_part(3) && fs.has_part(9));
        assert!(!fs.has_part(1));
    }

    #[test]
    fn file_status_complete_source() {
        let mut payload = H.to_vec();
        payload.extend_from_slice(&[0x00, 0x00]); // part count 0
        let fs = parse_file_status(&payload).unwrap();
        assert!(fs.complete);
        assert!(fs.has_part(999));
    }

    #[test]
    fn request_parts_legacy_layout() {
        let pkt = build_request_parts(&H, &[(0, 184_320), (184_320, 368_640)]);
        assert_eq!(pkt.protocol, PROT_EDONKEY);
        assert_eq!(pkt.opcode, OP_REQUESTPARTS);
        // hash + 3 starts + 3 ends (u32 LE), third slot zero.
        let mut expected = H.to_vec();
        for s in [0u32, 184_320, 0] {
            expected.extend_from_slice(&s.to_le_bytes());
        }
        for e in [184_320u32, 368_640, 0] {
            expected.extend_from_slice(&e.to_le_bytes());
        }
        assert_eq!(pkt.payload, expected);
    }

    #[test]
    fn request_parts_switches_to_i64_for_large_offsets() {
        let big = 5_000_000_000u64;
        let pkt = build_request_parts(&H, &[(big, big + EMBLOCKSIZE)]);
        assert_eq!(pkt.protocol, PROT_EMULE);
        assert_eq!(pkt.opcode, OP_REQUESTPARTS_I64);
        assert_eq!(pkt.payload.len(), 16 + 3 * 8 * 2);
    }

    #[test]
    fn sending_part_round_trips() {
        let mut payload = H.to_vec();
        payload.extend_from_slice(&100u32.to_le_bytes()); // start
        payload.extend_from_slice(&104u32.to_le_bytes()); // end (exclusive)
        payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // 4 data bytes
        let sp = parse_sending_part(&payload, false).unwrap();
        assert_eq!(sp.hash, H);
        assert_eq!((sp.start, sp.end), (100, 104));
        assert_eq!(sp.data, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(sp.data.len() as u64, sp.end - sp.start);
    }

    #[test]
    fn request_parts_parse_round_trip() {
        let blocks = vec![(0u64, 184_320u64), (184_320, 300_000)];
        let pkt = build_request_parts(&H, &blocks);
        let (hash, got) = parse_request_parts(&pkt.payload, false).unwrap();
        assert_eq!(hash, H);
        assert_eq!(got, blocks); // zero third slot dropped
    }

    #[test]
    fn sending_part_build_parse_round_trip() {
        let data = vec![0x55u8; 300];
        let pkt = build_sending_part(&H, 1000, 1300, &data);
        assert_eq!(pkt.opcode, OP_SENDINGPART);
        let sp = parse_sending_part(&pkt.payload, false).unwrap();
        assert_eq!((sp.start, sp.end), (1000, 1300));
        assert_eq!(sp.data, data);
    }

    #[test]
    fn hashset_and_filename_and_ranking() {
        let (a, b) = ([0x11; 16], [0x22; 16]);
        let mut payload = H.to_vec();
        payload.extend_from_slice(&2u16.to_le_bytes());
        payload.extend_from_slice(&a);
        payload.extend_from_slice(&b);
        assert_eq!(parse_hashset_answer(&payload).unwrap(), (H, vec![a, b]));

        let mut fna = H.to_vec();
        fna.extend_from_slice(&3u16.to_le_bytes());
        fna.extend_from_slice(b"vid");
        assert_eq!(
            parse_req_filename_answer(&fna).unwrap(),
            (H, b"vid".to_vec())
        );

        let ranking = [0x0A, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(parse_queue_ranking(&ranking).unwrap(), 10);
    }
}
