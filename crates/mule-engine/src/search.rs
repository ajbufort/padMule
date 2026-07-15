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

/// A server search query. Only `keyword` is required; the rest are AND filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SearchParams {
    pub keyword: String,
    /// e.g. "Video", "Audio" (ASCII file-type category).
    pub file_type: Option<String>,
    pub min_size: Option<u32>,
    pub max_size: Option<u32>,
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

/// Build an OP_SEARCHREQUEST packet for `p` (ANDed-terms form).
pub fn build_search_request(p: &SearchParams) -> Packet {
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
    if let Some(ext) = &p.extension {
        terms.push(Term::StringMeta(FT_FILEFORMAT, ext));
    }

    let mut w = Writer::new();
    let n = terms.len();
    for (i, t) in terms.iter().enumerate() {
        // aMule writes an AND before every parameter except the last.
        if i + 1 < n {
            write_and(&mut w);
        }
        write_term(&mut w, t);
    }
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

/// Parse an OP_SEARCHRESULT payload into its result files.
pub fn parse_search_result(payload: &[u8]) -> Result<Vec<SearchResultFile>, IoError> {
    let mut r = Reader::new(payload);
    let count = r.read_u32()?;
    // Do NOT pre-allocate from the untrusted count; grow as we read.
    let mut out = Vec::new();
    for _ in 0..count {
        let hash = read_hash16(&mut r)?;
        let id = r.read_u32()?;
        let port = r.read_u16()?;
        let tagcount = r.read_u32()?;
        let mut tags = Vec::new();
        for _ in 0..tagcount {
            tags.push(read_tag(&mut r)?);
        }
        out.push(SearchResultFile {
            hash,
            id,
            port,
            tags,
        });
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
            extension: Some("avi".to_string()),
        };
        let pkt = build_search_request(&p);
        // 5 terms -> 4 ANDs before terms 0..3, none before the last.
        let and_count = pkt
            .payload
            .windows(2)
            .filter(|w| w == &[0x00u8, 0x00])
            .count();
        assert!(and_count >= 4);
        // Framing round-trip.
        let wire = write_packet(&pkt);
        let (parsed, consumed) = read_packet(&wire).unwrap().unwrap();
        assert_eq!(parsed, pkt);
        assert_eq!(consumed, wire.len());
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
}
