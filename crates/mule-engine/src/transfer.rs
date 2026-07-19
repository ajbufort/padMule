//! Client-to-client file-transfer message codecs (the download side). See
//! BaseClient.cpp / DownloadClient.cpp / PartFile.cpp and protocol-understanding
//! Part 2. Pure; driven by `transfer_session` / `multi_source` / `fetch`.
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
pub const OP_FILEDESC: u8 = 0x61; // C5 (eMule ext) - a source's rating + comment

/// eMule MAXFILECOMMENTLEN (Constants.h:54): comments are capped at 50 chars.
pub const MAX_FILE_COMMENT_LEN: usize = 50;

/// Build OP_FILEDESC: `<rating u8><comment u32-len string>` (SendCommentInfo,
/// UploadClient.cpp:613-616). Comment truncated to MAX_FILE_COMMENT_LEN chars.
pub fn build_file_desc(rating: u8, comment: &str) -> Packet {
    let text: String = comment.chars().take(MAX_FILE_COMMENT_LEN).collect();
    let mut w = Writer::new();
    w.write_u8(rating.min(5));
    let bytes = text.as_bytes();
    w.write_u32(bytes.len() as u32);
    w.write_bytes(bytes);
    Packet::new(PROT_EMULE, OP_FILEDESC, w.into_inner())
}

/// Parse OP_FILEDESC: `<rating u8><comment u32-len string>`. Faithful to
/// eMule ProcessMuleCommentPacket (BaseClient.cpp:1185-1197): a rating > 5 is
/// treated as 0 (unrated), and the comment is truncated to
/// MAX_FILE_COMMENT_LEN chars (lossy UTF-8, safe against a lying length).
pub fn parse_file_desc(payload: &[u8]) -> Result<(u8, String), IoError> {
    let mut r = Reader::new(payload);
    let rating = r.read_u8()?;
    let rating = if rating > 5 { 0 } else { rating };
    let len = r.read_u32()? as usize;
    let bytes = r.read_bytes(len)?;
    let comment: String = String::from_utf8_lossy(&bytes)
        .chars()
        .take(MAX_FILE_COMMENT_LEN)
        .collect();
    Ok((rating, comment))
}
pub const OP_COMPRESSEDPART: u8 = 0x40; // C5
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

/// OP_REQUESTFILENAME: ask a peer for the name of the file with this hash (bare
/// form, no extended info). Only valid to send if we advertise
/// ExtendedRequestsVersion == 0; otherwise use [`build_request_filename_ext`].
pub fn build_request_filename(hash: &[u8; 16]) -> Packet {
    hash_only(OP_REQUESTFILENAME, hash)
}

/// OP_REQUESTFILENAME with the extended requester info that eMule appends when it
/// advertises ExtendedRequestsVersion > 0 (which padMule does, via MISCOPTIONS1).
///
/// This is NOT optional: aMule's ProcessExtendedInfo (UploadClient.cpp:193)
/// THROWS and disconnects a client that advertised extended requests but sent a
/// bare 16-byte request. The payload is `<hash 16><u16 our-part-count><u16
/// complete-sources>`. We send part-count 0 ("we have no parts of this file yet",
/// true for a fresh download - upstream's `nED2KUpPartCount == 0` branch skips
/// the bitfield) followed by a 0 complete-source count for the version>1 field.
pub fn build_request_filename_ext(hash: &[u8; 16]) -> Packet {
    let mut w = Writer::new();
    w.write_bytes(hash);
    w.write_u16(0); // nED2KUpPartCount: we hold no parts yet
    w.write_u16(0); // complete-sources count (read when ExtendedRequestsVersion > 1)
    Packet::new(PROT_EDONKEY, OP_REQUESTFILENAME, w.into_inner())
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

/// OP_FILESTATUS advertising a PARTIAL source: which eD2k parts we hold.
///
/// Note the asymmetry with `build_file_status_complete`: a complete source sends
/// a part count of 0 rather than an all-ones bitfield.
pub fn build_file_status(hash: &[u8; 16], parts: &[bool]) -> Packet {
    let mut w = Writer::new();
    w.write_bytes(hash);
    w.write_bytes(&write_part_status(parts));
    Packet::new(PROT_EDONKEY, OP_FILESTATUS, w.into_inner())
}

/// OP_HASHSETANSWER: the per-part MD4 list, which the downloader needs before it
/// can verify anything on a multi-part file.
pub fn build_hashset_answer(hash: &[u8; 16], part_hashes: &[[u8; 16]]) -> Packet {
    let mut w = Writer::new();
    w.write_bytes(hash);
    w.write_u16(part_hashes.len() as u16);
    for h in part_hashes {
        w.write_bytes(h);
    }
    Packet::new(PROT_EDONKEY, OP_HASHSETANSWER, w.into_inner())
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

/// One range of the file to persist, produced by [`BlockReceiver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockWrite {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Why a received data packet was rejected. Every one of these means the peer
/// sent something it should not have; the caller drops the peer.
#[derive(Debug)]
pub enum BlockError {
    /// The packet's file hash was not the file we are downloading.
    WrongFile,
    /// The declared range is empty/inverted, outside the file, outside anything
    /// we requested, or disagrees with the payload length.
    BadRange,
    /// A compressed block failed to inflate (or tried to overrun its block).
    Decompress,
    /// The packet was truncated.
    Truncated,
}

impl From<IoError> for BlockError {
    fn from(_: IoError) -> Self {
        BlockError::Truncated
    }
}

struct PackedBlock {
    decomp: flate2::Decompress,
    out: Vec<u8>,
    written: u64,
    total: u64,
}

/// Reassembles the reply to ONE `OP_REQUESTPARTS` batch: it accepts the peer's
/// `OP_SENDINGPART` / `OP_COMPRESSEDPART` packets (32- and 64-bit variants),
/// validates each against the exact ranges we asked for, transparently inflates
/// per-block-compressed data, and yields the bytes to persist.
///
/// Every rejection path returns an error rather than panicking or looping: a
/// peer we connected to is untrusted, and the review found that the old inline
/// loops could be made to panic (a payload longer than its declared range) or
/// hang forever (a zero-length block that never advanced the counter). This type
/// is the single hardened place both download drivers go through.
///
/// Compression note: a compressed block is ONE zlib stream split across several
/// `OP_COMPRESSEDPART` packets that all carry the block's START offset (never the
/// running write position) plus a size field aMule ignores. We keep a streaming
/// inflater per block and emit each newly produced run at
/// `block_start + bytes_already_written`, exactly as `ProcessBlockPacket` does.
pub struct BlockReceiver {
    hash: [u8; 16],
    file_size: u64,
    /// requested `(start, end_exclusive)` blocks
    blocks: Vec<(u64, u64)>,
    /// real (decompressed) bytes still expected across the batch
    remaining: u64,
    /// streaming inflate state for blocks that arrive compressed, keyed by start
    packed: std::collections::HashMap<u64, PackedBlock>,
}

impl BlockReceiver {
    pub fn new(hash: [u8; 16], file_size: u64, blocks: &[(u64, u64)]) -> Self {
        let remaining = blocks.iter().map(|(s, e)| e - s).sum();
        BlockReceiver {
            hash,
            file_size,
            blocks: blocks.to_vec(),
            remaining,
            packed: std::collections::HashMap::new(),
        }
    }

    /// True once every requested byte has been received.
    pub fn is_done(&self) -> bool {
        self.remaining == 0
    }

    /// Feed one received packet. Non-data opcodes (queue ranking, etc.) yield no
    /// writes. Data packets yield the bytes to persist, or an error if the peer
    /// sent something outside what we asked for.
    pub fn accept(&mut self, opcode: u8, payload: &[u8]) -> Result<Vec<BlockWrite>, BlockError> {
        match opcode {
            OP_SENDINGPART => self.accept_raw(payload, false),
            OP_SENDINGPART_I64 => self.accept_raw(payload, true),
            OP_COMPRESSEDPART => self.accept_packed(payload, false),
            OP_COMPRESSEDPART_I64 => self.accept_packed(payload, true),
            _ => Ok(Vec::new()),
        }
    }

    fn check_hash(&self, r: &mut Reader) -> Result<(), BlockError> {
        if read_hash16(r)? != self.hash {
            return Err(BlockError::WrongFile);
        }
        Ok(())
    }

    /// The requested block that fully contains `[start, end)`, if any.
    fn containing_block(&self, start: u64, end: u64) -> Option<(u64, u64)> {
        self.blocks
            .iter()
            .copied()
            .find(|&(s, e)| s <= start && end <= e)
    }

    fn accept_raw(&mut self, payload: &[u8], i64: bool) -> Result<Vec<BlockWrite>, BlockError> {
        let mut r = Reader::new(payload);
        self.check_hash(&mut r)?;
        let (start, end) = if i64 {
            (r.read_u64()?, r.read_u64()?)
        } else {
            (r.read_u32()? as u64, r.read_u32()? as u64)
        };
        let data = r.read_bytes(r.remaining())?;
        // The guard aMule uses (DownloadClient.cpp:905): reject an empty/inverted
        // range, a range past EOF, one we never asked for, or one whose declared
        // length disagrees with the payload (the old code's copy_from_slice
        // panicked on exactly this).
        if end <= start
            || end > self.file_size
            || data.len() as u64 != end - start
            || self.containing_block(start, end).is_none()
        {
            return Err(BlockError::BadRange);
        }
        self.remaining = self.remaining.saturating_sub(data.len() as u64);
        Ok(vec![BlockWrite {
            offset: start,
            data,
        }])
    }

    fn accept_packed(&mut self, payload: &[u8], i64: bool) -> Result<Vec<BlockWrite>, BlockError> {
        let mut r = Reader::new(payload);
        self.check_hash(&mut r)?;
        let start = if i64 {
            r.read_u64()?
        } else {
            r.read_u32()? as u64
        };
        let _declared = r.read_u32()?; // total compressed size; aMule ignores it here
        let frag = r.read_bytes(r.remaining())?;
        // An empty fragment can never make progress; refusing it closes the only
        // way a compressed stream could spin the receive loop forever.
        if frag.is_empty() {
            return Err(BlockError::BadRange);
        }
        // A compressed packet always names the block's START; it must be a block
        // we actually requested.
        let total = match self.blocks.iter().find(|&&(s, _)| s == start) {
            Some(&(s, e)) => e - s,
            None => return Err(BlockError::BadRange),
        };

        let pb = self.packed.entry(start).or_insert_with(|| PackedBlock {
            decomp: flate2::Decompress::new(true),
            // Reserve exactly the block size: the stream decompresses to that and
            // no more, so decompress_vec can never grow (or overrun) the buffer.
            out: Vec::with_capacity(total as usize),
            written: 0,
            total,
        });

        let before = pb.out.len();
        let in_before = pb.decomp.total_in();
        let status = pb
            .decomp
            .decompress_vec(&frag, &mut pb.out, flate2::FlushDecompress::Sync)
            .map_err(|_| BlockError::Decompress)?;
        let produced = (pb.out.len() - before) as u64;
        let consumed = pb.decomp.total_in() - in_before;

        // Over-expansion (zip bomb / wrong-size block): output has hit the block
        // cap but the peer still has compressed input we could not consume. A
        // legitimate block decompresses to exactly its size and consumes all its
        // input; the trailing adler checksum consumes input but produces nothing,
        // so this check does not misfire on it.
        if pb.out.len() as u64 == pb.total && consumed < frag.len() as u64 {
            return Err(BlockError::Decompress);
        }
        // If the zlib stream ended, the block must be exactly its requested size -
        // a stream that ends short would otherwise never complete and hang.
        if matches!(status, flate2::Status::StreamEnd) && pb.written + produced != pb.total {
            return Err(BlockError::Decompress);
        }
        if produced == 0 {
            return Ok(Vec::new()); // needs more input; not done, not an error
        }
        let offset = start + pb.written;
        let data = pb.out[before..].to_vec();
        pb.written += produced;
        self.remaining = self.remaining.saturating_sub(produced);
        Ok(vec![BlockWrite { offset, data }])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_desc_round_trips_and_clamps() {
        // Normal.
        let (r, c) = parse_file_desc(&build_file_desc(4, "solid rip").payload).unwrap();
        assert_eq!((r, c.as_str()), (4, "solid rip"));
        // A rating > 5 is clamped to 5 on build; a hostile raw > 5 reads as 0.
        let (r, _) = parse_file_desc(&build_file_desc(9, "x").payload).unwrap();
        assert_eq!(r, 5);
        let hostile = Packet::new(PROT_EMULE, OP_FILEDESC, vec![0x2A, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            parse_file_desc(&hostile.payload).unwrap(),
            (0, String::new())
        );
        // Comment truncated to 50 chars.
        let long = "a".repeat(100);
        let (_, c) = parse_file_desc(&build_file_desc(3, &long).payload).unwrap();
        assert_eq!(c.chars().count(), MAX_FILE_COMMENT_LEN);
    }

    const H: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F,
    ];

    // ---- BlockReceiver: the hardened receive path (review findings 1, 2, 3) ----

    /// Build a raw OP_SENDINGPART payload with an arbitrary declared range and
    /// arbitrary data - so a test can lie about the range the way a peer could.
    fn raw_payload(hash: &[u8; 16], start: u32, end: u32, data: &[u8]) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_bytes(hash);
        w.write_u32(start);
        w.write_u32(end);
        w.write_bytes(data);
        w.into_inner()
    }

    /// Compress `data` as one zlib stream and frame it as an OP_COMPRESSEDPART
    /// carrying `block_start` (the way an uploader packs a whole block).
    fn packed_payload(hash: &[u8; 16], block_start: u32, data: &[u8]) -> Vec<u8> {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write as _;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(1));
        enc.write_all(data).unwrap();
        let z = enc.finish().unwrap();
        let mut w = Writer::new();
        w.write_bytes(hash);
        w.write_u32(block_start);
        w.write_u32(z.len() as u32); // the size field aMule ignores on receive
        w.write_bytes(&z);
        w.into_inner()
    }

    #[test]
    fn accepts_a_normal_raw_block() {
        let data = vec![0xABu8; 1000];
        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 1000)]);
        let writes = rx
            .accept(OP_SENDINGPART, &raw_payload(&H, 0, 1000, &data))
            .unwrap();
        assert_eq!(writes, vec![BlockWrite { offset: 0, data }]);
        assert!(rx.is_done());
    }

    #[test]
    fn a_raw_block_longer_than_its_declared_range_is_rejected_not_a_panic() {
        // Review finding 1: the old code did buf[0..1].copy_from_slice(&[..100])
        // and panicked. The guard must reject it instead.
        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 1000)]);
        let payload = raw_payload(&H, 0, 1, &[0u8; 100]); // says 1 byte, sends 100
        assert!(matches!(
            rx.accept(OP_SENDINGPART, &payload),
            Err(BlockError::BadRange)
        ));
    }

    #[test]
    fn a_zero_length_raw_block_is_rejected_so_the_loop_cannot_hang() {
        // Review finding 2: start==end added 0 to the counter forever.
        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 1000)]);
        let payload = raw_payload(&H, 500, 500, &[]);
        assert!(matches!(
            rx.accept(OP_SENDINGPART, &payload),
            Err(BlockError::BadRange)
        ));
        assert!(!rx.is_done());
    }

    #[test]
    fn a_block_past_eof_or_outside_the_request_is_rejected() {
        let mut rx = BlockReceiver::new(H, 1000, &[(0, 500)]);
        // Past EOF.
        assert!(matches!(
            rx.accept(OP_SENDINGPART, &raw_payload(&H, 900, 1100, &[0u8; 200])),
            Err(BlockError::BadRange)
        ));
        // Inside the file but outside anything we asked for.
        assert!(matches!(
            rx.accept(OP_SENDINGPART, &raw_payload(&H, 600, 700, &[0u8; 100])),
            Err(BlockError::BadRange)
        ));
    }

    #[test]
    fn a_block_for_the_wrong_file_is_rejected() {
        // Review: "do we even CHECK the hash in SENDINGPART?" Now we do.
        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 1000)]);
        let other = [0xFFu8; 16];
        let payload = raw_payload(&other, 0, 1000, &[0u8; 1000]);
        assert!(matches!(
            rx.accept(OP_SENDINGPART, &payload),
            Err(BlockError::WrongFile)
        ));
    }

    #[test]
    fn accepts_a_compressed_block_and_inflates_it() {
        // Review finding 3: compressed blocks used to be dropped -> hang forever.
        let data: Vec<u8> = (0..1000u32).map(|i| i as u8).collect();
        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 1000)]);
        let writes = rx
            .accept(OP_COMPRESSEDPART, &packed_payload(&H, 0, &data))
            .unwrap();
        let got: Vec<u8> = writes.into_iter().flat_map(|w| w.data).collect();
        assert_eq!(got, data);
        assert!(rx.is_done());
    }

    #[test]
    fn a_compressed_block_split_across_several_packets_reassembles() {
        // The realistic case: one block's zlib stream arrives in fragments that
        // all name the block START, and output must be written sequentially.
        let data: Vec<u8> = (0..5000u32).map(|i| (i * 3) as u8).collect();
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write as _;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::new(1));
        enc.write_all(&data).unwrap();
        let z = enc.finish().unwrap();

        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 5000)]);
        let mut assembled = vec![0u8; 5000];
        // Feed the compressed stream in 64-byte fragments, each a COMPRESSEDPART
        // naming block start 0.
        for chunk in z.chunks(64) {
            let mut w = Writer::new();
            w.write_bytes(&H);
            w.write_u32(0); // block start, constant across fragments
            w.write_u32(z.len() as u32);
            w.write_bytes(chunk);
            for bw in rx.accept(OP_COMPRESSEDPART, &w.into_inner()).unwrap() {
                let s = bw.offset as usize;
                assembled[s..s + bw.data.len()].copy_from_slice(&bw.data);
            }
        }
        assert!(rx.is_done());
        assert_eq!(assembled, data);
    }

    #[test]
    fn an_empty_compressed_fragment_is_rejected_so_it_cannot_spin() {
        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 1000)]);
        let mut w = Writer::new();
        w.write_bytes(&H);
        w.write_u32(0);
        w.write_u32(0);
        // no fragment bytes
        assert!(matches!(
            rx.accept(OP_COMPRESSEDPART, &w.into_inner()),
            Err(BlockError::BadRange)
        ));
    }

    #[test]
    fn garbage_compressed_data_errors_rather_than_corrupting() {
        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 1000)]);
        let mut w = Writer::new();
        w.write_bytes(&H);
        w.write_u32(0);
        w.write_u32(4);
        w.write_bytes(&[0xDE, 0xAD, 0xBE, 0xEF]); // not a zlib stream
        assert!(matches!(
            rx.accept(OP_COMPRESSEDPART, &w.into_inner()),
            Err(BlockError::Decompress)
        ));
    }

    #[test]
    fn a_compressed_block_that_inflates_past_its_size_is_rejected() {
        // A zip-bomb-style block: claims block size 100 but the stream expands to
        // 100_000. The reserved capacity caps output at 100, and we reject when
        // the decompressor still wants to produce more.
        let big = vec![7u8; 100_000];
        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 100)]);
        let r = rx.accept(OP_COMPRESSEDPART, &packed_payload(&H, 0, &big));
        // Either the overrun guard or the decompressor's own bounds fire; both are
        // errors, and crucially it does not allocate 100_000 bytes or panic.
        assert!(r.is_err());
    }

    #[test]
    fn unrelated_opcodes_yield_no_writes() {
        let mut rx = BlockReceiver::new(H, 10_000, &[(0, 1000)]);
        assert!(rx.accept(OP_QUEUERANKING, &[0u8; 12]).unwrap().is_empty());
        assert!(!rx.is_done());
    }

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
