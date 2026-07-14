//! Finding sources for a file: from the server (OP_GETSOURCES) and from peers
//! (source exchange). See docs/raw/wave4d-upstream-research-2026-07-14.md
//! section 3.
//!
//! # IP byte order - the thing that is easiest to get wrong
//!
//! Every integer here is little-endian, but the MEANING of a source's 32-bit id
//! depends on where it came from:
//!
//! | source                   | wire bytes `b0 b1 b2 b3` mean |
//! |--------------------------|-------------------------------|
//! | server OP_FOUNDSOURCES   | IP `b0.b1.b2.b3` ("ed2k" order) |
//! | SX record v1 / v2        | IP `b0.b1.b2.b3` ("ed2k" order) |
//! | SX record v3 / v4        | IP `b3.b2.b1.b0` ("hybrid", byte-SWAPPED) |
//!
//! v3 adds no bytes over v2 - the ONLY difference is that id flip. (Upstream did
//! it so a HighID client whose IP ends in `.0` is not misread as a LowID.)
//!
//! `Source::ip` is always stored in the ed2k convention (first octet in the low
//! byte), matching the rest of padMule; the codec does the swapping.
//!
//! # Deliberate divergences from aMule 3.0.1 (it has bugs here)
//!
//! - `parse_request_sources2` accepts `len >= 19` and reads the hash at the
//!   cursor. aMule checks `size != 16` and reads the hash at offset 0, so it
//!   *always* throws on a standalone SX2 request and disconnects the peer. Its
//!   own error message names the wrong opcode - a copy-paste tell. Still broken
//!   in amule-master.
//! - `build_answer_sources` picks the id byte order from the version it is
//!   actually WRITING. aMule's `CPartFile` picks it from the peer's announced SX1
//!   version instead, which sends byte-reversed IPs to any peer whose SX1 and SX2
//!   versions disagree. aMule's own `CKnownFile` and eMule both get this right.
//! - The OBFU "userhash follows" flag is `0x80`. The upstream header comment says
//!   `0x08`; the code says `0x80`. The code is right.

use mule_proto::{
    compress, IoError, Packet, Reader, Writer, OLD_MAX_FILE_SIZE, PROT_EDONKEY, PROT_EMULE,
};

// Server (0xE3).
pub const OP_GETSOURCES: u8 = 0x19;
pub const OP_GETSOURCES_OBFU: u8 = 0x23;
pub const OP_CALLBACKREQUEST: u8 = 0x1C;
pub const OP_CALLBACKREQUESTED: u8 = 0x35;
pub const OP_CALLBACK_FAIL: u8 = 0x36;
pub const OP_FOUNDSOURCES: u8 = 0x42;
pub const OP_FOUNDSOURCES_OBFU: u8 = 0x44;

// Peer source exchange (0xC5).
pub const OP_REQUESTSOURCES: u8 = 0x81;
pub const OP_ANSWERSOURCES: u8 = 0x82;
pub const OP_REQUESTSOURCES2: u8 = 0x83;
pub const OP_ANSWERSOURCES2: u8 = 0x84;

/// The SX version padMule speaks. 4 is the newest and what both aMule and eMule
/// negotiate over SX2.
pub const SOURCE_EXCHANGE_VERSION: u8 = 4;

/// Upstream's emit loop breaks AFTER writing, so it sends up to 501, not 500.
/// Both clients size their buffers for 501; we match, and accept 501 too.
pub const MAX_SOURCES_PER_ANSWER: usize = 501;

/// Crypt-option bits in an SX v4 record.
pub const CRYPT_SUPPORTED: u8 = 0x01;
pub const CRYPT_REQUESTED: u8 = 0x02;
pub const CRYPT_REQUIRED: u8 = 0x04;

/// In an OBFU OP_FOUNDSOURCES record, this bit means a 16-byte userhash follows.
/// NOT 0x08, whatever the upstream header comment claims.
pub const FOUND_SOURCES_HAS_USERHASH: u8 = 0x80;

/// A source announced by a peer during source exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// ed2k convention: first octet in the low byte.
    pub ip: u32,
    pub port: u16,
    pub server_ip: u32,
    pub server_port: u16,
    /// Present from SX v2 on.
    pub user_hash: Option<[u8; 16]>,
    /// Present in SX v4 only.
    pub crypt: Option<u8>,
}

/// A source announced by the SERVER (OP_FOUNDSOURCES). Servers give less than
/// peers do: no server address, and identity only on the obfuscated variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundSource {
    /// ed2k convention: first octet in the low byte. Never swapped.
    pub ip: u32,
    pub port: u16,
    pub crypt: Option<u8>,
    pub user_hash: Option<[u8; 16]>,
}

/// A server telling us a LowID peer wants to reach us (OP_CALLBACKREQUESTED).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackRequested {
    pub ip: u32,
    pub port: u16,
    pub crypt: Option<u8>,
    pub user_hash: Option<[u8; 16]>,
}

fn read_hash16(r: &mut Reader) -> Result<[u8; 16], IoError> {
    let mut h = [0u8; 16];
    h.copy_from_slice(&r.read_bytes(16)?);
    Ok(h)
}

/// Record size on the wire for an SX version, straight from upstream's own size
/// checks: `nCount*(4+2+4+2)`, `+16` for the userhash, `+1` for the crypt byte
/// (PartFile.cpp:2934-2946).
///
/// v2 and v3 are the SAME size - they differ only in id byte order, which is why
/// an SX1 receiver has to disambiguate them from the sender's announced version
/// rather than from the length.
fn sx_record_len(version: u8) -> Option<usize> {
    match version {
        1 => Some(4 + 2 + 4 + 2),
        2 | 3 => Some(4 + 2 + 4 + 2 + 16),
        4 => Some(4 + 2 + 4 + 2 + 16 + 1),
        _ => None,
    }
}

/// From SX v3 on, the id travels byte-swapped ("hybrid" order).
fn sx_id_to_wire(ip_ed2k: u32, version: u8) -> u32 {
    if version >= 3 {
        ip_ed2k.swap_bytes()
    } else {
        ip_ed2k
    }
}

fn sx_id_from_wire(id: u32, version: u8) -> u32 {
    if version >= 3 {
        id.swap_bytes()
    } else {
        id
    }
}

// ---------------------------------------------------------------- server side

/// True if `size` needs the 64-bit ("large file") eD2k encodings. Boundary is
/// `OLD_MAX_FILE_SIZE`, NOT `u32::MAX` - the two differ by ~4.9 M bytes and a
/// file in that band must still be treated as large.
pub fn is_large_file(size: u64) -> bool {
    size > OLD_MAX_FILE_SIZE
}

/// OP_GETSOURCES: ask our server who has this file.
///
/// aMule never sends the bare 16-byte legacy form - the size always goes out.
/// A LARGE file (`is_large_file`) uses the sentinel form (`0u32` then a u64 size).
/// Upstream requires the server to advertise large-file support and DROPS the
/// request otherwise rather than downgrading it, so the caller MUST gate a large
/// file on that server flag - hence [`is_large_file`] is public.
pub fn build_get_sources(hash: &[u8; 16], size: u64, obfuscated: bool) -> Packet {
    let mut w = Writer::new();
    w.write_bytes(hash);
    if is_large_file(size) {
        w.write_u32(0); // sentinel: a 64-bit size follows
        w.write_u64(size);
    } else {
        w.write_u32(size as u32);
    }
    let op = if obfuscated {
        OP_GETSOURCES_OBFU
    } else {
        OP_GETSOURCES
    };
    Packet::new(PROT_EDONKEY, op, w.into_inner())
}

/// Parse OP_FOUNDSOURCES (or the OBFU variant). The count is a single byte, so a
/// server can never return more than 255 sources in one packet.
pub fn parse_found_sources(
    payload: &[u8],
    obfuscated: bool,
) -> Result<([u8; 16], Vec<FoundSource>), IoError> {
    let mut r = Reader::new(payload);
    let hash = read_hash16(&mut r)?;
    let count = r.read_u8()? as usize;
    let mut out = Vec::new();
    for _ in 0..count {
        let ip = r.read_u32()?; // ed2k order: never swapped here
        let port = r.read_u16()?;
        let (crypt, user_hash) = if obfuscated {
            let c = r.read_u8()?;
            let uh = if c & FOUND_SOURCES_HAS_USERHASH != 0 {
                Some(read_hash16(&mut r)?)
            } else {
                None
            };
            (Some(c), uh)
        } else {
            (None, None)
        };
        out.push(FoundSource {
            ip,
            port,
            crypt,
            user_hash,
        });
    }
    Ok((hash, out))
}

/// OP_CALLBACKREQUEST: ask our server to poke a LowID peer for us.
///
/// The id is written as-is - deliberately NOT byte-reversed, to match what
/// servers expect. Only valid for a LowID source on the server we are on.
pub fn build_callback_request(client_id: u32) -> Packet {
    let mut w = Writer::new();
    w.write_u32(client_id);
    Packet::new(PROT_EDONKEY, OP_CALLBACKREQUEST, w.into_inner())
}

/// Parse OP_CALLBACKREQUESTED: a LowID peer is reaching out via the server.
/// The crypt/userhash tail is present only on packets of 23 bytes or more.
pub fn parse_callback_requested(payload: &[u8]) -> Result<CallbackRequested, IoError> {
    let mut r = Reader::new(payload);
    let ip = r.read_u32()?;
    let port = r.read_u16()?;
    let (crypt, user_hash) = if payload.len() >= 23 {
        let c = r.read_u8()?;
        (Some(c), Some(read_hash16(&mut r)?))
    } else {
        (None, None)
    };
    Ok(CallbackRequested {
        ip,
        port,
        crypt,
        user_hash,
    })
}

// ------------------------------------------------------------------ peer side

/// OP_REQUESTSOURCES (SX1): 16-byte hash only.
pub fn build_request_sources(hash: &[u8; 16]) -> Packet {
    Packet::new(PROT_EMULE, OP_REQUESTSOURCES, hash.to_vec())
}

/// OP_REQUESTSOURCES2 (SX2): version, then options, THEN the hash. 19 bytes.
/// (Upstream's own header comment claims hash-first; both senders prove it wrong.)
pub fn build_request_sources2(hash: &[u8; 16], version: u8) -> Packet {
    let mut w = Writer::new();
    w.write_u8(version);
    w.write_u16(0); // options: reserved, always zero
    w.write_bytes(hash);
    Packet::new(PROT_EMULE, OP_REQUESTSOURCES2, w.into_inner())
}

/// Parse OP_REQUESTSOURCES (SX1).
pub fn parse_request_sources(payload: &[u8]) -> Result<[u8; 16], IoError> {
    if payload.len() < 16 {
        return Err(IoError::UnexpectedEof);
    }
    read_hash16(&mut Reader::new(payload))
}

/// Parse OP_REQUESTSOURCES2 (SX2) -> (requested version, file hash).
///
/// Accepts `len >= 19` and reads the hash AFTER the version+options, which is
/// what the senders actually emit. aMule rejects `len != 16` here and then reads
/// the hash from offset 0, so it can never process a standalone SX2 request.
pub fn parse_request_sources2(payload: &[u8]) -> Result<(u8, [u8; 16]), IoError> {
    if payload.len() < 19 {
        return Err(IoError::UnexpectedEof);
    }
    let mut r = Reader::new(payload);
    let version = r.read_u8()?;
    let _options = r.read_u16()?;
    Ok((version, read_hash16(&mut r)?))
}

/// Build OP_ANSWERSOURCES (`sx2 = false`) or OP_ANSWERSOURCES2 (`sx2 = true`).
///
/// `version` is the record version actually written, and it - not the peer's
/// announced SX1 version - decides the id byte order. Sources beyond
/// `MAX_SOURCES_PER_ANSWER` are dropped. The packet is zlib-packed if it exceeds
/// 354 bytes and compression actually shrinks it (which flips the protocol byte
/// to 0xD4 but leaves the opcode alone).
pub fn build_answer_sources(
    hash: &[u8; 16],
    sources: &[Source],
    version: u8,
    sx2: bool,
) -> Option<Packet> {
    sx_record_len(version)?;
    let sources = &sources[..sources.len().min(MAX_SOURCES_PER_ANSWER)];

    let mut w = Writer::new();
    if sx2 {
        w.write_u8(version);
    }
    w.write_bytes(hash);
    w.write_u16(sources.len() as u16);
    for s in sources {
        w.write_u32(sx_id_to_wire(s.ip, version));
        w.write_u16(s.port);
        w.write_u32(s.server_ip);
        w.write_u16(s.server_port);
        if version >= 2 {
            w.write_bytes(&s.user_hash.unwrap_or([0u8; 16]));
        }
        if version >= 4 {
            w.write_u8(s.crypt.unwrap_or(0));
        }
    }
    let op = if sx2 {
        OP_ANSWERSOURCES2
    } else {
        OP_ANSWERSOURCES
    };
    let p = Packet::new(PROT_EMULE, op, w.into_inner());
    Some(pack_if_large(p))
}

/// Upstream tries to zlib-pack a source-exchange answer once it exceeds this.
pub const SX_PACK_THRESHOLD: usize = 354;

/// Pack `p` if it is worth it. `compress` already leaves the packet alone when
/// compression would not shrink it, so this only adds the size gate.
fn pack_if_large(p: Packet) -> Packet {
    if p.payload.len() > SX_PACK_THRESHOLD {
        compress(&p)
    } else {
        p
    }
}

/// Parse OP_ANSWERSOURCES (`sx2 = false`) or OP_ANSWERSOURCES2 (`sx2 = true`).
///
/// The caller must have already un-packed a 0xD4 packet (the opcode is unchanged
/// when packed, so the framing layer cannot tell them apart).
///
/// For SX1 the record version is NOT on the wire: v2 and v3 records are both 30
/// bytes, so we disambiguate by size and fall back to the sender's ANNOUNCED SX1
/// version (from its hello). A packet whose length does not match the announced
/// version exactly is rejected, as upstream does - a mismatch means we would be
/// guessing at the id byte order, and guessing wrong yields reversed IPs.
pub fn parse_answer_sources(
    payload: &[u8],
    sx2: bool,
    announced_sx1_version: u8,
) -> Result<([u8; 16], Vec<Source>), IoError> {
    let mut r = Reader::new(payload);
    let version = if sx2 { r.read_u8()? } else { 0 };
    let hash = read_hash16(&mut r)?;
    let count = r.read_u16()? as usize;
    let body = r.remaining();

    let version = if sx2 {
        // SX2 carries its version explicitly; just sanity-check the length.
        let len = sx_record_len(version).ok_or(IoError::BadTag(version))?;
        if count.checked_mul(len) != Some(body) {
            return Err(IoError::UnexpectedEof);
        }
        version
    } else {
        resolve_sx1_version(count, body, announced_sx1_version)?
    };

    if count > MAX_SOURCES_PER_ANSWER {
        return Err(IoError::TooBig);
    }

    let mut out = Vec::new();
    for _ in 0..count {
        let ip = sx_id_from_wire(r.read_u32()?, version);
        let port = r.read_u16()?;
        let server_ip = r.read_u32()?;
        let server_port = r.read_u16()?;
        let user_hash = if version >= 2 {
            Some(read_hash16(&mut r)?)
        } else {
            None
        };
        let crypt = if version >= 4 {
            Some(r.read_u8()?)
        } else {
            None
        };
        out.push(Source {
            ip,
            port,
            server_ip,
            server_port,
            user_hash,
            crypt,
        });
    }
    Ok((hash, out))
}

/// Work out which record version an SX1 answer used, from its size plus the
/// sender's announced version. Ambiguity is an error, never a guess.
fn resolve_sx1_version(count: usize, body: usize, announced: u8) -> Result<u8, IoError> {
    // Derived from sx_record_len so the sizes cannot drift out of sync with the
    // codec - keeping a second hardcoded copy here is how you ship a client that
    // rejects every real answer.
    let fits = |v: u8| sx_record_len(v).and_then(|len| count.checked_mul(len)) == Some(body);
    if fits(1) && announced == 1 {
        Ok(1)
    } else if fits(2) && announced == 2 {
        Ok(2)
    } else if fits(3) && announced > 2 {
        // v2 and v3 are the same length; only the announced version separates
        // them, and they disagree about id byte order.
        Ok(3)
    } else if fits(4) && announced == 4 {
        Ok(4)
    } else {
        Err(IoError::UnexpectedEof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::{decompress, MAX_PACKET_SIZE, PROT_PACKED};

    const H: [u8; 16] = [0xAB; 16];
    /// 10.0.0.33 in the ed2k convention: first octet in the low byte.
    const IP_ED2K: u32 = 0x2100_000A;

    fn src(ip: u32) -> Source {
        Source {
            ip,
            port: 4662,
            server_ip: 0x1122_3344,
            server_port: 4242,
            user_hash: Some([0xCD; 16]),
            crypt: Some(CRYPT_SUPPORTED),
        }
    }

    #[test]
    fn get_sources_always_carries_the_size() {
        let p = build_get_sources(&H, 1000, false);
        assert_eq!(p.opcode, OP_GETSOURCES);
        assert_eq!(p.payload.len(), 16 + 4);
        assert_eq!(&p.payload[16..20], &1000u32.to_le_bytes());
    }

    #[test]
    fn a_large_file_uses_the_zero_sentinel_then_a_u64() {
        let size = 5_000_000_000u64;
        let p = build_get_sources(&H, size, false);
        assert_eq!(p.payload.len(), 16 + 4 + 8);
        assert_eq!(&p.payload[16..20], &0u32.to_le_bytes());
        assert_eq!(&p.payload[20..28], &size.to_le_bytes());
    }

    #[test]
    fn the_large_file_boundary_is_old_max_not_u32_max() {
        // Review finding 5: the boundary is OLD_MAX_FILE_SIZE (4_290_048_000),
        // confirmed identical in eMule 0.50a (OLD_MAX_EMULE_FILE_SIZE). A file in
        // the (OLD_MAX_FILE_SIZE, u32::MAX] band must use the 64-bit sentinel form,
        // NOT a plain u32 - otherwise a server that knows the file under its true
        // 64-bit size never matches the query.
        assert!(!is_large_file(OLD_MAX_FILE_SIZE));
        assert!(is_large_file(OLD_MAX_FILE_SIZE + 1));
        assert!(is_large_file(u32::MAX as u64)); // the band that u32::MAX would miss

        // Exactly at the boundary: plain u32 form.
        let at = build_get_sources(&H, OLD_MAX_FILE_SIZE, false);
        assert_eq!(at.payload.len(), 16 + 4);
        // One byte over: 64-bit sentinel form.
        let over = build_get_sources(&H, OLD_MAX_FILE_SIZE + 1, false);
        assert_eq!(over.payload.len(), 16 + 4 + 8);
        assert_eq!(&over.payload[16..20], &0u32.to_le_bytes());
    }

    #[test]
    fn obfuscated_get_sources_uses_its_own_opcode() {
        assert_eq!(build_get_sources(&H, 1, true).opcode, OP_GETSOURCES_OBFU);
    }

    #[test]
    fn found_sources_ip_is_not_swapped() {
        let mut w = Writer::new();
        w.write_bytes(&H);
        w.write_u8(1);
        w.write_u32(IP_ED2K);
        w.write_u16(4662);
        let (hash, srcs) = parse_found_sources(&w.into_inner(), false).unwrap();
        assert_eq!(hash, H);
        assert_eq!(srcs.len(), 1);
        assert_eq!(srcs[0].ip, IP_ED2K);
        assert_eq!(srcs[0].port, 4662);
        assert!(srcs[0].crypt.is_none());
    }

    #[test]
    fn obfuscated_found_sources_reads_a_userhash_only_on_bit_0x80() {
        // Two records: one with the userhash flag, one without.
        let mut w = Writer::new();
        w.write_bytes(&H);
        w.write_u8(2);
        w.write_u32(IP_ED2K);
        w.write_u16(1);
        w.write_u8(FOUND_SOURCES_HAS_USERHASH | CRYPT_SUPPORTED);
        w.write_bytes(&[0xEE; 16]);
        w.write_u32(IP_ED2K);
        w.write_u16(2);
        w.write_u8(CRYPT_SUPPORTED); // no 0x80 -> no userhash follows
        let (_, srcs) = parse_found_sources(&w.into_inner(), true).unwrap();
        assert_eq!(srcs[0].user_hash, Some([0xEE; 16]));
        assert_eq!(srcs[1].user_hash, None);
        // Crucially, record 2 parsed at the right offset - proof we did not
        // consume 16 phantom bytes for the missing hash.
        assert_eq!(srcs[1].port, 2);
    }

    #[test]
    fn callback_request_writes_the_id_unswapped() {
        let p = build_callback_request(0x0102_0304);
        assert_eq!(p.payload, 0x0102_0304u32.to_le_bytes());
    }

    #[test]
    fn callback_requested_tail_appears_only_at_23_bytes() {
        let mut short = Writer::new();
        short.write_u32(IP_ED2K);
        short.write_u16(4662);
        let cb = parse_callback_requested(&short.into_inner()).unwrap();
        assert_eq!(cb.ip, IP_ED2K);
        assert!(cb.crypt.is_none() && cb.user_hash.is_none());

        let mut long = Writer::new();
        long.write_u32(IP_ED2K);
        long.write_u16(4662);
        long.write_u8(CRYPT_REQUESTED);
        long.write_bytes(&[0x77; 16]);
        let bytes = long.into_inner();
        assert_eq!(bytes.len(), 23);
        let cb = parse_callback_requested(&bytes).unwrap();
        assert_eq!(cb.crypt, Some(CRYPT_REQUESTED));
        assert_eq!(cb.user_hash, Some([0x77; 16]));
    }

    #[test]
    fn sx2_request_is_version_first_and_19_bytes() {
        let p = build_request_sources2(&H, SOURCE_EXCHANGE_VERSION);
        assert_eq!(p.payload.len(), 19);
        assert_eq!(p.payload[0], SOURCE_EXCHANGE_VERSION);
        assert_eq!(&p.payload[1..3], &0u16.to_le_bytes());
        assert_eq!(&p.payload[3..19], &H);

        // The parse aMule cannot do: a real 19-byte SX2 request.
        let (v, h) = parse_request_sources2(&p.payload).unwrap();
        assert_eq!(v, SOURCE_EXCHANGE_VERSION);
        assert_eq!(h, H);
    }

    #[test]
    fn sx1_request_is_the_bare_hash() {
        let p = build_request_sources(&H);
        assert_eq!(p.payload, H.to_vec());
        assert_eq!(parse_request_sources(&p.payload).unwrap(), H);
        assert!(parse_request_sources(&H[..15]).is_err());
    }

    #[test]
    fn v1_records_are_12_bytes_and_carry_no_identity() {
        let p = build_answer_sources(&H, &[src(IP_ED2K)], 1, false).unwrap();
        assert_eq!(p.payload.len(), 16 + 2 + 12);
        let (hash, srcs) = parse_answer_sources(&p.payload, false, 1).unwrap();
        assert_eq!(hash, H);
        assert_eq!(srcs[0].ip, IP_ED2K);
        assert_eq!(srcs[0].user_hash, None);
        assert_eq!(srcs[0].crypt, None);
    }

    #[test]
    fn v2_and_v3_are_the_same_size_but_flip_the_id_byte_order() {
        let v2 = build_answer_sources(&H, &[src(IP_ED2K)], 2, false).unwrap();
        let v3 = build_answer_sources(&H, &[src(IP_ED2K)], 3, false).unwrap();
        assert_eq!(v2.payload.len(), v3.payload.len(), "v2/v3 are both 28-byte");

        // The id field is at offset 18 (16 hash + 2 count).
        let id_v2 = u32::from_le_bytes(v2.payload[18..22].try_into().unwrap());
        let id_v3 = u32::from_le_bytes(v3.payload[18..22].try_into().unwrap());
        assert_eq!(id_v2, IP_ED2K);
        assert_eq!(id_v3, IP_ED2K.swap_bytes(), "v3 must send the hybrid order");
        assert_ne!(id_v2, id_v3);

        // Both must decode back to the SAME ip. If the byte order were handled
        // wrong, one of these would come back reversed.
        assert_eq!(
            parse_answer_sources(&v2.payload, false, 2).unwrap().1[0].ip,
            IP_ED2K
        );
        assert_eq!(
            parse_answer_sources(&v3.payload, false, 3).unwrap().1[0].ip,
            IP_ED2K
        );
    }

    #[test]
    fn v4_appends_the_crypt_byte() {
        let p = build_answer_sources(&H, &[src(IP_ED2K)], 4, false).unwrap();
        assert_eq!(p.payload.len(), 16 + 2 + 29);
        let (_, srcs) = parse_answer_sources(&p.payload, false, 4).unwrap();
        assert_eq!(srcs[0].crypt, Some(CRYPT_SUPPORTED));
        assert_eq!(srcs[0].ip, IP_ED2K);
    }

    #[test]
    fn sx2_answers_carry_their_version_inline() {
        let p = build_answer_sources(&H, &[src(IP_ED2K)], 4, true).unwrap();
        assert_eq!(p.opcode, OP_ANSWERSOURCES2);
        assert_eq!(p.payload[0], 4);
        // The announced SX1 version is irrelevant for SX2 - pass a wrong one.
        let (_, srcs) = parse_answer_sources(&p.payload, true, 1).unwrap();
        assert_eq!(srcs[0].ip, IP_ED2K);
        assert_eq!(srcs[0].crypt, Some(CRYPT_SUPPORTED));
    }

    #[test]
    fn an_sx1_answer_that_contradicts_the_announced_version_is_rejected() {
        // 30-byte records but the peer announced v1 (14-byte) -> ambiguous, drop.
        let p = build_answer_sources(&H, &[src(IP_ED2K)], 2, false).unwrap();
        assert!(parse_answer_sources(&p.payload, false, 1).is_err());
        // 31-byte records announced as v2 -> drop.
        let p4 = build_answer_sources(&H, &[src(IP_ED2K)], 4, false).unwrap();
        assert!(parse_answer_sources(&p4.payload, false, 2).is_err());
    }

    #[test]
    fn an_unknown_version_is_refused_rather_than_guessed() {
        assert!(build_answer_sources(&H, &[src(IP_ED2K)], 5, false).is_none());
        assert!(build_answer_sources(&H, &[src(IP_ED2K)], 0, false).is_none());
    }

    #[test]
    fn a_big_answer_is_zlib_packed_and_round_trips() {
        // 50 v4 records = 1450 bytes of body, well past the 354-byte threshold.
        // All-identical records compress hard, so packing definitely wins.
        let sources: Vec<Source> = (0..50).map(|_| src(IP_ED2K)).collect();
        let p = build_answer_sources(&H, &sources, 4, false).unwrap();
        assert_eq!(p.protocol, PROT_PACKED, "should have packed");
        assert_eq!(
            p.opcode, OP_ANSWERSOURCES,
            "opcode must NOT change when packed"
        );

        let un = decompress(&p, MAX_PACKET_SIZE).unwrap();
        let (_, srcs) = parse_answer_sources(&un.payload, false, 4).unwrap();
        assert_eq!(srcs.len(), 50);
        assert_eq!(srcs[49].ip, IP_ED2K);
    }

    #[test]
    fn a_small_answer_is_left_unpacked() {
        let p = build_answer_sources(&H, &[src(IP_ED2K)], 4, false).unwrap();
        assert_eq!(p.protocol, PROT_EMULE);
    }

    #[test]
    fn we_emit_at_most_501_sources() {
        let sources: Vec<Source> = (0..600).map(|_| src(IP_ED2K)).collect();
        let p = build_answer_sources(&H, &sources, 4, false).unwrap();
        let un = decompress(&p, MAX_PACKET_SIZE).unwrap();
        let count = u16::from_le_bytes(un.payload[16..18].try_into().unwrap());
        assert_eq!(count as usize, MAX_SOURCES_PER_ANSWER);
    }

    #[test]
    fn a_truncated_answer_errors_rather_than_panicking() {
        let p = build_answer_sources(&H, &[src(IP_ED2K)], 4, false).unwrap();
        for cut in 1..p.payload.len() {
            let _ = parse_answer_sources(&p.payload[..cut], false, 4);
        }
    }

    #[test]
    fn a_lying_count_cannot_make_us_overallocate() {
        // Claim 60000 sources with no body behind them.
        let mut w = Writer::new();
        w.write_bytes(&H);
        w.write_u16(60_000);
        assert!(parse_answer_sources(&w.into_inner(), false, 4).is_err());
    }
}
