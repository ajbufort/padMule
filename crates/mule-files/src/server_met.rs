//! server.met: the eD2k server list. See docs/raw reference section 5
//! (ServerList.cpp:94-197 load, 689-825 save).
//!
//! Layout: `u8` header (0xE0 on write; load accepts 0xE0 or 0x0E), `u32` server
//! count, then per server: `u32` IP, `u16` port, `u32` tag count, then that many
//! MET-format tags. The IP is stored verbatim (eMule byte-order convention);
//! this codec keeps it opaque. Records preserve exactly what was read so a
//! read-then-write round-trips bit-for-bit (the header byte is preserved rather
//! than forced to 0xE0). Archive-wrapped server.met (gzip/zip from a URL) is a
//! separate higher-layer concern, not handled here.

use mule_proto::{read_tag, write_tag, IoError, Reader, Tag, Writer};

/// server.met header written by aMule.
pub const SERVER_MET_HEADER: u8 = 0xE0;
/// Legacy header also accepted on load.
pub const SERVER_MET_HEADER_LEGACY: u8 = 0x0E;

/// One server entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Server {
    /// IP as stored on disk (opaque uint32, eMule byte convention).
    pub ip: u32,
    pub port: u16,
    pub tags: Vec<Tag>,
}

/// A parsed server.met.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerMet {
    /// Header byte as read (preserved for byte-identical round-trip).
    pub header: u8,
    pub servers: Vec<Server>,
}

/// Parse a raw (unwrapped) server.met.
pub fn read_server_met(bytes: &[u8]) -> Result<ServerMet, IoError> {
    let mut r = Reader::new(bytes);
    let header = r.read_u8()?;
    if header != SERVER_MET_HEADER && header != SERVER_MET_HEADER_LEGACY {
        return Err(IoError::BadTag(header));
    }
    let count = r.read_u32()?;
    // Do NOT pre-allocate from the untrusted count; grow as we read. A bogus count
    // (e.g. 0xFFFFFFFF from a hostile/MITM'd URL via update_server_list) would make
    // Vec::with_capacity request ~137 GB and abort the process before a single
    // element is read. Growing incrementally means a short body just hits EOF and
    // errors cheaply. Mirrors parse_search_result_page's rule.
    let mut servers = Vec::new();
    for _ in 0..count {
        let ip = r.read_u32()?;
        let port = r.read_u16()?;
        let tagcount = r.read_u32()?;
        let mut tags = Vec::new();
        for _ in 0..tagcount {
            tags.push(read_tag(&mut r)?);
        }
        servers.push(Server { ip, port, tags });
    }
    Ok(ServerMet { header, servers })
}

/// Serialize a server.met, reproducing aMule's byte layout.
pub fn write_server_met(m: &ServerMet) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u8(m.header);
    w.write_u32(m.servers.len() as u32);
    for s in &m.servers {
        w.write_u32(s.ip);
        w.write_u16(s.port);
        w.write_u32(s.tags.len() as u32);
        for t in &s.tags {
            write_tag(&mut w, t);
        }
    }
    w.into_inner()
}

/// Merge `incoming` server entries into `base`: keep every `base` entry verbatim
/// (tags + order preserved), then append each `incoming` entry whose `(ip, port)`
/// is not already present in `base`. `base.header` is preserved. Only the APPENDED
/// set is deduped against `base`; any pre-existing duplicates in `base` are left
/// untouched, so the UI's index-keyed server rows stay valid.
pub fn merge_server_met(base: &ServerMet, incoming: &ServerMet) -> ServerMet {
    let mut servers = base.servers.clone();
    let mut have: std::collections::HashSet<(u32, u16)> =
        base.servers.iter().map(|s| (s.ip, s.port)).collect();
    for s in &incoming.servers {
        // insert() is false when the key was already present -> skip that entry.
        if have.insert((s.ip, s.port)) {
            servers.push(s.clone());
        }
    }
    ServerMet {
        header: base.header,
        servers,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::{TagName, TagValue};

    const GOLDEN: &[u8] = &[
        0xE0, // header
        0x01, 0x00, 0x00, 0x00, // server count = 1
        0x04, 0x03, 0x02, 0x01, // ip = 0x01020304 (verbatim)
        0x35, 0x12, // port = 0x1235
        0x01, 0x00, 0x00, 0x00, // tagcount = 1
        // tag: STRING id=0x01 "eD2K"
        0x02, 0x01, 0x00, 0x01, 0x04, 0x00, b'e', b'D', b'2', b'K',
    ];

    fn golden_parsed() -> ServerMet {
        ServerMet {
            header: 0xE0,
            servers: vec![Server {
                ip: 0x01020304,
                port: 0x1235,
                tags: vec![Tag::id(0x01, TagValue::Str(b"eD2K".to_vec()))],
            }],
        }
    }

    #[test]
    fn reads_golden() {
        assert_eq!(read_server_met(GOLDEN).unwrap(), golden_parsed());
    }

    #[test]
    fn writes_golden_byte_identical() {
        assert_eq!(write_server_met(&golden_parsed()), GOLDEN);
    }

    #[test]
    fn rejects_bad_header() {
        let bytes = [0x99, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_server_met(&bytes), Err(IoError::BadTag(0x99)));
    }

    #[test]
    fn a_huge_untrusted_count_errors_instead_of_pre_allocating() {
        // count claims 4.29 billion servers but the body ends -> EOF error, NOT a
        // ~137 GB Vec::with_capacity that would abort the process (the #18 URL DoS).
        assert_eq!(
            read_server_met(&[0xE0, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(IoError::UnexpectedEof)
        );
        // Same guard on the per-server tag count.
        let mut b = vec![0xE0, 0x01, 0x00, 0x00, 0x00]; // count = 1
        b.extend_from_slice(&[0x04, 0x03, 0x02, 0x01]); // ip
        b.extend_from_slice(&[0x35, 0x12]); // port
        b.extend_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]); // tagcount = huge
        assert_eq!(read_server_met(&b), Err(IoError::UnexpectedEof));
    }

    #[test]
    fn accepts_legacy_header_and_preserves_it() {
        let mut bytes = GOLDEN.to_vec();
        bytes[0] = 0x0E; // legacy header
        let parsed = read_server_met(&bytes).unwrap();
        assert_eq!(parsed.header, 0x0E);
        // Round-trips the legacy header rather than forcing 0xE0.
        assert_eq!(write_server_met(&parsed), bytes);
    }

    #[test]
    fn merge_appends_only_new_addresses_and_preserves_base() {
        let base = ServerMet {
            header: 0xE0,
            servers: vec![
                Server {
                    ip: 0x0A00_0001,
                    port: 4661,
                    tags: vec![Tag::id(0x01, TagValue::Str(b"A".to_vec()))],
                },
                Server {
                    ip: 0x0A00_0002,
                    port: 4661,
                    tags: vec![],
                },
            ],
        };
        let incoming = ServerMet {
            header: 0x0E, // different header -> ignored, base.header wins
            servers: vec![
                // duplicate of base entry A (same ip+port) -> skipped, base tag kept
                Server {
                    ip: 0x0A00_0001,
                    port: 4661,
                    tags: vec![Tag::id(0x01, TagValue::Str(b"A-renamed".to_vec()))],
                },
                // new entry C -> appended
                Server {
                    ip: 0x0A00_0003,
                    port: 5000,
                    tags: vec![Tag::id(0x01, TagValue::Str(b"C".to_vec()))],
                },
            ],
        };
        let merged = merge_server_met(&base, &incoming);
        assert_eq!(merged.header, 0xE0);
        let addrs: Vec<(u32, u16)> = merged.servers.iter().map(|s| (s.ip, s.port)).collect();
        assert_eq!(
            addrs,
            vec![
                (0x0A00_0001, 4661),
                (0x0A00_0002, 4661),
                (0x0A00_0003, 5000)
            ]
        );
        // Base entry A kept its ORIGINAL tag (the incoming duplicate did not clobber).
        assert_eq!(
            merged.servers[0].tags[0].value,
            TagValue::Str(b"A".to_vec())
        );
        // Round-trips on disk.
        assert_eq!(read_server_met(&write_server_met(&merged)).unwrap(), merged);
    }

    #[test]
    fn round_trips_multi_server_and_empty() {
        let m = ServerMet {
            header: 0xE0,
            servers: vec![
                Server {
                    ip: 0xDEADBEEF,
                    port: 4661,
                    tags: vec![
                        Tag::id(0x01, TagValue::Str(b"server one".to_vec())),
                        Tag::id(0x87, TagValue::U32(50_000)), // ST_MAXUSERS
                        Tag {
                            name: TagName::Str(b"users".to_vec()),
                            value: TagValue::U32(1234),
                        },
                    ],
                },
                Server {
                    ip: 0x7F000001,
                    port: 5000,
                    tags: vec![],
                },
            ],
        };
        let bytes = write_server_met(&m);
        assert_eq!(read_server_met(&bytes).unwrap(), m);

        let empty = ServerMet {
            header: 0xE0,
            servers: vec![],
        };
        let eb = write_server_met(&empty);
        assert_eq!(eb, vec![0xE0, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(read_server_met(&eb).unwrap(), empty);
    }
}
