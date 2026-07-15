//! eD2k link and magnet URI parsing. Turns a pasted link into a structured
//! target the engine can act on: a file to download, a server to add, a search
//! to run. Covers the classic `ed2k://|file|...|/` and `ed2k://|server|...`
//! forms, the `ed2k://|search|term|/` link (an eMule 0.70b addition), and
//! `magnet:?xt=urn:ed2k:...` URIs (name, length, ed2k hash, AICH hash, sources).

use std::net::SocketAddr;

/// A parsed eD2k / magnet link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ed2kLink {
    File(FileLink),
    /// `ed2k://|server|<ip-or-host>|<port>|/`.
    Server {
        host: String,
        port: u16,
    },
    /// `ed2k://|serverlist|<url>|/`.
    ServerList {
        url: String,
    },
    /// `ed2k://|search|<term>|/`.
    Search {
        term: String,
    },
}

/// A downloadable file from an `ed2k://|file|...` link or a magnet URI.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FileLink {
    pub name: String,
    pub size: u64,
    /// The ed2k (MD4) file hash.
    pub hash: [u8; 16],
    /// The AICH root hash (`h=` / `urn:aich:`), if present.
    pub aich: Option<[u8; 20]>,
    /// Directly-listed sources (`sources,ip:port,...` / magnet `xs=`).
    pub sources: Vec<SocketAddr>,
}

/// Parse an `ed2k://` link or a `magnet:` URI.
pub fn parse_link(input: &str) -> Option<Ed2kLink> {
    let s = input.trim();
    if let Some(rest) = s.strip_prefix("magnet:?") {
        return parse_magnet(rest);
    }
    let rest = s.strip_prefix("ed2k://")?;
    parse_ed2k(rest)
}

fn parse_ed2k(rest: &str) -> Option<Ed2kLink> {
    // Pipe-delimited; a leading '|' yields an empty first field.
    let f: Vec<&str> = rest.split('|').collect();
    // f[0] == "" (before the first '|'); f[1] is the kind.
    let kind = f.get(1)?;
    match *kind {
        "file" => {
            let name = url_decode(f.get(2)?);
            let size = f.get(3)?.parse::<u64>().ok()?;
            let hash = hex16(f.get(4)?)?;
            let mut link = FileLink {
                name,
                size,
                hash,
                aich: None,
                sources: Vec::new(),
            };
            // Optional trailing segments: h=<aich>, sources,ip:port,...
            for seg in f.iter().skip(5) {
                if let Some(a) = seg.strip_prefix("h=") {
                    link.aich = base32_20(a);
                } else if let Some(src) = seg.strip_prefix("sources,") {
                    link.sources.extend(parse_sources(src));
                }
            }
            Some(Ed2kLink::File(link))
        }
        "server" => Some(Ed2kLink::Server {
            host: (*f.get(2)?).to_string(),
            port: f.get(3)?.parse().ok()?,
        }),
        "serverlist" => Some(Ed2kLink::ServerList {
            url: (*f.get(2)?).to_string(),
        }),
        "search" => Some(Ed2kLink::Search {
            term: url_decode(f.get(2)?),
        }),
        _ => None,
    }
}

fn parse_magnet(query: &str) -> Option<Ed2kLink> {
    let mut link = FileLink::default();
    let mut have_hash = false;
    for pair in query.split('&') {
        let (key, val) = pair.split_once('=')?;
        // `xt` may repeat (ed2k + aich); strip a `.N` suffix eMule sometimes adds.
        let key = key.split('.').next().unwrap_or(key);
        let val = url_decode(val);
        match key {
            "xt" => {
                if let Some(h) = val.strip_prefix("urn:ed2k:") {
                    if let Some(hash) = hex16(h) {
                        link.hash = hash;
                        have_hash = true;
                    }
                } else if let Some(a) = val.strip_prefix("urn:aich:") {
                    link.aich = base32_20(a);
                }
            }
            "xl" => link.size = val.parse().unwrap_or(0),
            "dn" => link.name = val,
            "xs" | "as" => {
                // A source may be a bare host:port or a URL wrapping one.
                if let Ok(addr) = val.trim_start_matches("ed2kftp://").parse::<SocketAddr>() {
                    link.sources.push(addr);
                }
            }
            _ => {}
        }
    }
    have_hash.then_some(Ed2kLink::File(link))
}

fn parse_sources(list: &str) -> Vec<SocketAddr> {
    list.split(',').filter_map(|s| s.parse().ok()).collect()
}

/// Decode 32 hex chars to 16 bytes.
fn hex16(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    let b = s.as_bytes();
    for (i, o) in out.iter_mut().enumerate() {
        *o = (hex_nib(b[2 * i])? << 4) | hex_nib(b[2 * i + 1])?;
    }
    Some(out)
}

fn hex_nib(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode a 32-char RFC 4648 base32 string (A-Z, 2-7) to 20 bytes - the AICH
/// root hash form used in ed2k links / magnet `urn:aich`.
fn base32_20(s: &str) -> Option<[u8; 20]> {
    if s.len() != 32 {
        return None;
    }
    let mut bits: u64 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::with_capacity(20);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return None,
        } as u64;
        bits = (bits << 5) | v;
        nbits += 5;
        if nbits >= 8 {
            nbits -= 8;
            out.push((bits >> nbits) as u8);
        }
    }
    out.try_into().ok()
}

/// Percent-decode (and `+` -> space) a link field.
fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => match (hex_nib(b[i + 1]), hex_nib(b[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH_HEX: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";
    const HASH: [u8; 16] = [
        0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89,
        0xc0,
    ];

    #[test]
    fn parses_a_basic_file_link() {
        let s = format!("ed2k://|file|movie.avi|733934592|{HASH_HEX}|/");
        let Ed2kLink::File(f) = parse_link(&s).unwrap() else {
            panic!("expected file")
        };
        assert_eq!(f.name, "movie.avi");
        assert_eq!(f.size, 733_934_592);
        assert_eq!(f.hash, HASH);
        assert!(f.aich.is_none());
    }

    #[test]
    fn parses_a_file_link_with_aich_and_sources() {
        // AICH: 32 base32 chars; sources appended.
        let aich_b32 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // 32 'A' -> 20 zero bytes
        let s = format!(
            "ed2k://|file|my file.pdf|1024|{HASH_HEX}|h={aich_b32}|sources,1.2.3.4:4662,5.6.7.8:1234|/"
        );
        let Ed2kLink::File(f) = parse_link(&s).unwrap() else {
            panic!()
        };
        assert_eq!(f.name, "my file.pdf");
        assert_eq!(f.aich, Some([0u8; 20]));
        assert_eq!(
            f.sources,
            vec![
                "1.2.3.4:4662".parse().unwrap(),
                "5.6.7.8:1234".parse().unwrap()
            ]
        );
    }

    #[test]
    fn url_encoded_name_is_decoded() {
        let s = format!("ed2k://|file|a%20b%2Bc.txt|10|{HASH_HEX}|/");
        let Ed2kLink::File(f) = parse_link(&s).unwrap() else {
            panic!()
        };
        assert_eq!(f.name, "a b+c.txt");
    }

    #[test]
    fn parses_server_serverlist_and_search_links() {
        assert_eq!(
            parse_link("ed2k://|server|45.87.41.16|6262|/").unwrap(),
            Ed2kLink::Server {
                host: "45.87.41.16".into(),
                port: 6262
            }
        );
        assert_eq!(
            parse_link("ed2k://|serverlist|http://example.org/server.met|/").unwrap(),
            Ed2kLink::ServerList {
                url: "http://example.org/server.met".into()
            }
        );
        assert_eq!(
            parse_link("ed2k://|search|linux iso|/").unwrap(),
            Ed2kLink::Search {
                term: "linux iso".into()
            }
        );
    }

    #[test]
    fn parses_a_magnet_uri() {
        let s = format!(
            "magnet:?xt=urn:ed2k:{HASH_HEX}&xl=1024&dn=cool+file.iso&xt=urn:aich:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&xs=9.9.9.9:4662"
        );
        let Ed2kLink::File(f) = parse_link(&s).unwrap() else {
            panic!()
        };
        assert_eq!(f.hash, HASH);
        assert_eq!(f.size, 1024);
        assert_eq!(f.name, "cool file.iso");
        assert_eq!(f.aich, Some([0u8; 20]));
        assert_eq!(f.sources, vec!["9.9.9.9:4662".parse().unwrap()]);
    }

    #[test]
    fn rejects_junk_and_wrong_hash_length() {
        assert!(parse_link("http://example.org").is_none());
        assert!(parse_link("ed2k://|file|x|10|tooshort|/").is_none());
        assert!(parse_link("magnet:?dn=noHash").is_none());
    }
}
