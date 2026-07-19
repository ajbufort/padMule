//! eD2k server search: build OP_SEARCHREQUEST and parse OP_SEARCHRESULT. See
//! SearchList.cpp:156-257 (CSearchExprTarget), :714-830 (CreateSearchData), and
//! docs/wiki/protocol-understanding.md Part 1.
//!
//! Only the common ANDed-terms form is built (a keyword plus size/type/extension
//! filters, all ANDed) - aMule's optimized path for searches without OR/NOT.
//! The full boolean tree (OR/NOT, parenthesized) and global UDP search are
//! deferred.

use mule_proto::{read_tag, IoError, Packet, Reader, Tag, Writer, PROT_EDONKEY};

/// Server search request opcode (protocol 0xE3).
pub const OP_SEARCHREQUEST: u8 = 0x16;
/// Server search result opcode.
pub const OP_SEARCHRESULT: u8 = 0x33;

// Search comparison operators (Constants.h ED2K_SEARCH_OP_*).
pub const ED2K_SEARCH_OP_EQUAL: u8 = 0;
pub const ED2K_SEARCH_OP_GREATER: u8 = 1;
pub const ED2K_SEARCH_OP_LESS: u8 = 2;

// File tag ids used in search parameters (FileTags.h).
const FT_FILESIZE: u8 = 0x02;
const FT_FILETYPE: u8 = 0x03;
const FT_FILEFORMAT: u8 = 0x04;
const FT_SOURCES: u8 = 0x15;

/// A server search query. Only `keyword` is required; the rest are AND filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchParams {
    pub keyword: String,
    /// e.g. "Video", "Audio" (ASCII file-type category).
    pub file_type: Option<String>,
    pub min_size: Option<u32>,
    pub max_size: Option<u32>,
    /// Minimum availability (sources). eMule queries FT_SOURCES; we express `>=N`
    /// as `> N-1` so old dserver-only indexes (no GREATER_EQUAL op) honor it too.
    pub min_sources: Option<u32>,
    /// e.g. "avi" (FT_FILEFORMAT).
    pub extension: Option<String>,
}

fn write_and(w: &mut Writer) {
    w.write_u8(0x00); // boolean operator parameter type
    w.write_u8(0x00); // AND
}

fn write_keyword(w: &mut Writer, s: &str) {
    w.write_u8(0x01); // string parameter type
    w.write_string_u16(s.as_bytes());
}

fn write_string_meta(w: &mut Writer, tag_id: u8, s: &str) {
    w.write_u8(0x02); // string-with-metatag parameter type
    w.write_string_u16(s.as_bytes());
    w.write_u16(1); // meta tag id length
    w.write_u8(tag_id);
}

fn write_numeric_meta(w: &mut Writer, tag_id: u8, op: u8, value: u32) {
    w.write_u8(0x03); // numeric (int32) parameter type
    w.write_u32(value);
    w.write_u8(op);
    w.write_u16(1); // meta tag id length
    w.write_u8(tag_id);
}

/// One term of a search expression, in aMule's parameter order.
enum Term<'a> {
    Keyword(&'a str),
    StringMeta(u8, &'a str),
    NumericMeta(u8, u8, u32),
}

fn write_term(w: &mut Writer, t: &Term) {
    match *t {
        Term::Keyword(s) => write_keyword(w, s),
        Term::StringMeta(id, s) => write_string_meta(w, id, s),
        Term::NumericMeta(id, op, v) => write_numeric_meta(w, id, op, v),
    }
}

/// Write the ANDed search-expression tree for `p` into `w`. This is the SAME
/// payload for both the TCP OP_SEARCHREQUEST and the UDP global-search opcodes
/// (eMule reuses the identical packet body, only changing the opcode -
/// SearchResultsWnd.cpp:1320-1341), so both callers share this encoder.
fn write_search_tree(w: &mut Writer, p: &SearchParams) {
    let mut terms: Vec<Term> = vec![Term::Keyword(&p.keyword)];
    if let Some(ft) = &p.file_type {
        terms.push(Term::StringMeta(FT_FILETYPE, ft));
    }
    if let Some(sz) = p.min_size {
        terms.push(Term::NumericMeta(FT_FILESIZE, ED2K_SEARCH_OP_GREATER, sz));
    }
    if let Some(sz) = p.max_size {
        terms.push(Term::NumericMeta(FT_FILESIZE, ED2K_SEARCH_OP_LESS, sz));
    }
    if let Some(min) = p.min_sources {
        // `>= min` as `> min-1`; min 0 is a no-op filter, so skip it.
        if min > 0 {
            terms.push(Term::NumericMeta(
                FT_SOURCES,
                ED2K_SEARCH_OP_GREATER,
                min - 1,
            ));
        }
    }
    if let Some(ext) = &p.extension {
        terms.push(Term::StringMeta(FT_FILEFORMAT, ext));
    }

    let n = terms.len();
    for (i, t) in terms.iter().enumerate() {
        // aMule writes an AND before every parameter except the last.
        if i + 1 < n {
            write_and(w);
        }
        write_term(w, t);
    }
}

/// Build an OP_SEARCHREQUEST packet for `p` (ANDed-terms form).
pub fn build_search_request(p: &SearchParams) -> Packet {
    let mut w = Writer::new();
    write_search_tree(&mut w, p);
    Packet::new(PROT_EDONKEY, OP_SEARCHREQUEST, w.into_inner())
}

/// One file in a search result.
#[derive(Debug, Clone, PartialEq)]
pub struct SearchResultFile {
    pub hash: [u8; 16],
    pub id: u32,
    pub port: u16,
    pub tags: Vec<Tag>,
}

fn read_hash16(r: &mut Reader) -> Result<[u8; 16], IoError> {
    let mut h = [0u8; 16];
    h.copy_from_slice(&r.read_bytes(16)?);
    Ok(h)
}

/// Read one result record `<hash 16><id 4><port 2><tagcount 4><tag>*` from `r`.
/// Shared by the TCP array parser and the UDP chained parser (they carry the
/// identical per-file record; only the framing around it differs).
fn read_one_result_file(r: &mut Reader) -> Result<SearchResultFile, IoError> {
    let hash = read_hash16(r)?;
    let id = r.read_u32()?;
    let port = r.read_u16()?;
    let tagcount = r.read_u32()?;
    let mut tags = Vec::new();
    for _ in 0..tagcount {
        tags.push(read_tag(r)?);
    }
    Ok(SearchResultFile {
        hash,
        id,
        port,
        tags,
    })
}

/// Parse an OP_SEARCHRESULT payload into its result files.
pub fn parse_search_result(payload: &[u8]) -> Result<Vec<SearchResultFile>, IoError> {
    let mut r = Reader::new(payload);
    let count = r.read_u32()?;
    // Do NOT pre-allocate from the untrusted count; grow as we read.
    let mut out = Vec::new();
    for _ in 0..count {
        out.push(read_one_result_file(&mut r)?);
    }
    Ok(out)
}

// -------------------------------------------------- global server UDP search

/// Global-search request opcodes (all PROT_EDONKEY, sent as raw UDP datagrams to
/// a server's UDP port = its TCP port + 4). 0x98 is the UNIVERSAL fallback every
/// server understands; 0x92/0x90 are opcode-only optimizations for
/// EXT_GETFILES/large-file-UDP servers (deferred - padMule's u32-size searches
/// never need the large-file path). See opcodes.h:190-195, SearchResultsWnd.cpp.
pub const OP_GLOBSEARCHREQ: u8 = 0x98;
/// Global-search response opcode (one `<hash><id><port><tags>` record per
/// segment; multiple records are chained, each behind its own `[0xE3][0x99]`).
pub const OP_GLOBSEARCHRES: u8 = 0x99;

/// Build a global-search UDP datagram body for `p`: the SAME search tree as the
/// TCP request, wrapped as OP_GLOBSEARCHREQ (the universal 0x98 form). The
/// returned `Packet`'s UDP header is `[PROT_EDONKEY][OP_GLOBSEARCHREQ]` (2 bytes,
/// no length field - the datagram boundary is the framing).
pub fn build_global_search_udp(p: &SearchParams) -> Packet {
    let mut w = Writer::new();
    write_search_tree(&mut w, p);
    Packet::new(PROT_EDONKEY, OP_GLOBSEARCHREQ, w.into_inner())
}

/// Parse an OP_GLOBSEARCHRES datagram payload (the bytes AFTER the leading
/// `[0xE3][0x99]` header the caller already stripped). Unlike TCP, there is NO
/// count field: it is one result record, optionally followed by more records
/// each prefixed by another `[0xE3][0x99]` sub-header (UDPSocket.cpp:237-279).
/// Stops at the first non-`[0xE3][0x99]` continuation or a short/garbled record,
/// returning whatever parsed cleanly (a truncated trailing record is not fatal).
pub fn parse_global_search_res(payload: &[u8]) -> Result<Vec<SearchResultFile>, IoError> {
    let mut r = Reader::new(payload);
    let mut out = Vec::new();
    loop {
        match read_one_result_file(&mut r) {
            Ok(f) => out.push(f),
            // A malformed FIRST record is a real error; a malformed later one just
            // ends the chain with what we have.
            Err(e) if out.is_empty() => return Err(e),
            Err(_) => break,
        }
        // Another record only follows if the next two bytes are a fresh
        // [0xE3][0x99] sub-header; anything else (or end of datagram) ends it.
        if r.remaining() < 2 {
            break;
        }
        let prot = r.read_u8()?;
        let op = r.read_u8()?;
        if prot != PROT_EDONKEY || op != OP_GLOBSEARCHRES {
            break;
        }
    }
    Ok(out)
}

/// Which network a search should run on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchMethod {
    /// eD2k server (local) search - fast, and typically more results for a
    /// popular file.
    Server,
    /// Kad (serverless) search - broader reach, no server needed.
    Kad,
}

/// eMule 0.70b's "Automatic" search method: pick the network by connectivity.
/// Prefer the server when connected (a local search is quick), else fall back to
/// Kad; `None` if neither network is available.
///
/// NOT on padMule's current search path: `Engine::search` queries the server
/// AND Kad concurrently and merges (better than either alone), so it never
/// chooses one. Kept as the connectivity-selection primitive for a future
/// bandwidth-constrained "one network only" mode.
pub fn choose_search_method(server_connected: bool, kad_ready: bool) -> Option<SearchMethod> {
    if server_connected {
        Some(SearchMethod::Server)
    } else if kad_ready {
        Some(SearchMethod::Kad)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::{read_packet, write_packet, TagName, TagValue};

    #[test]
    fn automatic_search_method_prefers_server_then_kad() {
        assert_eq!(choose_search_method(true, true), Some(SearchMethod::Server));
        assert_eq!(
            choose_search_method(true, false),
            Some(SearchMethod::Server)
        );
        assert_eq!(choose_search_method(false, true), Some(SearchMethod::Kad));
        assert_eq!(choose_search_method(false, false), None);
    }

    #[test]
    fn single_keyword_has_no_and() {
        let p = SearchParams {
            keyword: "movie".to_string(),
            ..Default::default()
        };
        let pkt = build_search_request(&p);
        assert_eq!(pkt.opcode, OP_SEARCHREQUEST);
        // [01][05 00]["movie"]
        assert_eq!(
            pkt.payload,
            vec![0x01, 0x05, 0x00, b'm', b'o', b'v', b'i', b'e']
        );
    }

    #[test]
    fn keyword_and_min_size() {
        let p = SearchParams {
            keyword: "movie".to_string(),
            min_size: Some(1000),
            ..Default::default()
        };
        let pkt = build_search_request(&p);
        let expected = vec![
            0x00,
            0x00, // AND
            0x01,
            0x05,
            0x00,
            b'm',
            b'o',
            b'v',
            b'i',
            b'e', // keyword
            0x03,
            0xE8,
            0x03,
            0x00,
            0x00,                   // numeric int32 = 1000
            ED2K_SEARCH_OP_GREATER, // op
            0x01,
            0x00,        // tag-id length = 1
            FT_FILESIZE, // 0x02
        ];
        assert_eq!(pkt.payload, expected);
    }

    #[test]
    fn full_query_anded_and_round_trips() {
        let p = SearchParams {
            keyword: "big".to_string(),
            file_type: Some("Video".to_string()),
            min_size: Some(1),
            max_size: Some(2),
            min_sources: Some(5),
            extension: Some("avi".to_string()),
        };
        let pkt = build_search_request(&p);
        // 6 terms -> 5 ANDs before terms 0..4, none before the last.
        let and_count = pkt
            .payload
            .windows(2)
            .filter(|w| w == &[0x00u8, 0x00])
            .count();
        assert!(and_count >= 5);
        // Framing round-trip.
        let wire = write_packet(&pkt);
        let (parsed, consumed) = read_packet(&wire).unwrap().unwrap();
        assert_eq!(parsed, pkt);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn min_sources_becomes_a_greater_than_n_minus_one_term() {
        // `>= 1` availability must serialize as FT_SOURCES > 0, so old
        // dserver-only indexes (which lack the GREATER_EQUAL op) still honor it.
        let p = SearchParams {
            keyword: "x".to_string(),
            min_sources: Some(1),
            ..Default::default()
        };
        let pkt = build_search_request(&p);
        // Numeric-meta term: [int32 value=0][op=GREATER][taglen=1,0][FT_SOURCES].
        let expected_term = [
            0x00,
            0x00,
            0x00,
            0x00, // value 0 (= 1 - 1)
            ED2K_SEARCH_OP_GREATER,
            0x01,
            0x00,
            FT_SOURCES,
        ];
        assert!(
            pkt.payload
                .windows(expected_term.len())
                .any(|w| w == expected_term),
            "min_sources 1 -> FT_SOURCES > 0"
        );
        // min_sources 0 must add NO term (a no-op filter).
        let none = SearchParams {
            keyword: "x".to_string(),
            min_sources: Some(0),
            ..Default::default()
        };
        assert!(!build_search_request(&none)
            .payload
            .windows(1)
            .any(|w| w == [FT_SOURCES]));
    }

    #[test]
    fn parse_one_result_file() {
        // count=1, hash 00..0F, id=0x0A000001, port=4662, 2 tags:
        // FT_FILENAME(0x01) STRING "f", FT_FILESIZE(0x02) UINT32 100.
        let mut payload = vec![0x01, 0x00, 0x00, 0x00]; // count = 1
        payload.extend_from_slice(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]); // hash
        payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x0A]); // id
        payload.extend_from_slice(&[0x36, 0x12]); // port 4662
        payload.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // tagcount = 2
        payload.extend_from_slice(&[0x02, 0x01, 0x00, 0x01, 0x01, 0x00, b'f']); // FT_FILENAME "f"
        payload.extend_from_slice(&[0x03, 0x01, 0x00, 0x02, 0x64, 0x00, 0x00, 0x00]); // FT_FILESIZE 100

        let files = parse_search_result(&payload).unwrap();
        assert_eq!(files.len(), 1);
        let f = &files[0];
        assert_eq!(f.id, 0x0A00_0001);
        assert_eq!(f.port, 4662);
        assert_eq!(
            f.tags,
            vec![
                Tag {
                    name: TagName::Id(0x01),
                    value: TagValue::Str(b"f".to_vec())
                },
                Tag {
                    name: TagName::Id(0x02),
                    value: TagValue::U32(100)
                },
            ]
        );
    }

    #[test]
    fn parse_result_truncated_errors() {
        // count says 1 but no file data follows.
        assert_eq!(
            parse_search_result(&[0x01, 0x00, 0x00, 0x00]),
            Err(IoError::UnexpectedEof)
        );
    }

    // One result record on the wire: <hash 16><id 4 LE><port 2 LE><tagcount 4 LE=0>.
    fn record(hash: u8, id: u32, port: u16) -> Vec<u8> {
        let mut v = vec![hash; 16];
        v.extend_from_slice(&id.to_le_bytes());
        v.extend_from_slice(&port.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes()); // tagcount 0
        v
    }

    #[test]
    fn global_search_udp_reuses_the_tcp_tree_only_the_opcode_differs() {
        let p = SearchParams {
            keyword: "linux".into(),
            min_size: Some(1000),
            ..Default::default()
        };
        let tcp = build_search_request(&p);
        let udp = build_global_search_udp(&p);
        // Same PROT_EDONKEY body, but the global-search opcode 0x98.
        assert_eq!(udp.protocol, PROT_EDONKEY);
        assert_eq!(udp.opcode, OP_GLOBSEARCHREQ);
        assert_eq!(udp.opcode, 0x98);
        assert_eq!(tcp.opcode, OP_SEARCHREQUEST);
        // The search-expression tree is byte-identical (eMule reuses the packet).
        assert_eq!(udp.payload, tcp.payload);
    }

    #[test]
    fn parse_global_search_res_chains_records_by_the_0xe3_0x99_subheader() {
        // One record, then [0xE3][0x99] + a second record, then trailing junk that
        // is NOT a fresh sub-header (so the chain ends cleanly, junk ignored).
        let mut buf = record(0xAA, 0x0A00_0001, 4662);
        buf.push(PROT_EDONKEY);
        buf.push(OP_GLOBSEARCHRES);
        buf.extend_from_slice(&record(0xBB, 0x0A00_0002, 4663));
        buf.extend_from_slice(&[0x11, 0x22]); // not [0xE3][0x99] -> stop

        let files = parse_global_search_res(&buf).unwrap();
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].hash, [0xAA; 16]);
        assert_eq!(files[0].port, 4662);
        assert_eq!(files[1].hash, [0xBB; 16]);
        assert_eq!(files[1].id, 0x0A00_0002);
    }

    #[test]
    fn parse_global_search_res_single_record_and_empty_are_handled() {
        // A single record with no continuation.
        let one = parse_global_search_res(&record(0xCC, 7, 99)).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].id, 7);
        // A truncated FIRST record is a real error (nothing parsed).
        assert!(parse_global_search_res(&[0x00; 4]).is_err());
    }
}
