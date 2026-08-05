//! First-run bootstrap data: a fresh install has no `server.met` and no
//! `nodes.dat`, so it knows no eD2k servers and no Kad contacts and can reach
//! nothing. aMule solves this by fetching a current list; we do the same.
//!
//! Why we fetch rather than bundle: a bundled list ROTS. The 2026-07-13 log
//! records exactly that failure - every login attempt failed against a stale
//! vendored list, and the fix was a current one from upd.emule-security.org.
//!
//! The HTTP here is deliberately hand-rolled over a raw tokio socket, byte-safe
//! (server.met/nodes.dat are BINARY - decoding them as UTF-8 would corrupt them).
//! It also sidesteps iOS App Transport Security entirely: ATS governs
//! URLSession/CFNetwork, not raw BSD sockets, so a cleartext http:// fetch works
//! on-device with no Info.plist exemption.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// Current, trusted sources (see docs/wiki/build-progress.md - the working
/// source proven live on 2026-07-13).
pub const SERVER_MET_URL: &str = "http://upd.emule-security.org/server.met";
pub const NODES_DAT_URL: &str = "http://upd.emule-security.org/nodes.dat";

#[derive(Debug)]
pub enum BootstrapError {
    BadUrl,
    Io(String),
    Http(u16),
    Empty,
}

impl std::fmt::Display for BootstrapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootstrapError::BadUrl => write!(f, "unusable URL"),
            BootstrapError::Io(e) => write!(f, "network error: {e}"),
            BootstrapError::Http(s) => write!(f, "HTTP {s}"),
            BootstrapError::Empty => write!(f, "empty response"),
        }
    }
}

impl std::error::Error for BootstrapError {}

/// Split `http://host[:port]/path`. Only http is used by these endpoints.
fn split_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), 80u16),
    };
    if host.is_empty() {
        return None;
    }
    Some((host, port, path.to_string()))
}

/// Find the end of the HTTP head in a RAW byte buffer and return
/// `(status, body_start)`. Byte-safe: never decodes the body as text.
fn split_head(buf: &[u8]) -> Option<(u16, usize)> {
    let end = buf.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = &buf[..end];
    let line_end = head.windows(2).position(|w| w == b"\r\n")?;
    let status_line = std::str::from_utf8(&head[..line_end]).ok()?;
    let status: u16 = status_line.split_whitespace().nth(1)?.parse().ok()?;
    Some((status, end))
}

/// GET `url` and return the raw body bytes.
pub async fn http_get_bytes(url: &str) -> Result<Vec<u8>, BootstrapError> {
    let (host, port, path) = split_url(url).ok_or(BootstrapError::BadUrl)?;
    let mut stream = timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| BootstrapError::Io("connect timeout".into()))?
    .map_err(|e| BootstrapError::Io(e.to_string()))?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: padMule\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| BootstrapError::Io(e.to_string()))?;
    // Cap the response so a hostile/MITM'd host (update_server_list now accepts a
    // user-entered URL) cannot stream unbounded data into memory for the whole 30s.
    // A server.met / nodes.dat is far under this; a larger body is truncated and
    // then fails to parse, which is reported cleanly rather than OOMing.
    const MAX_HTTP_BODY: u64 = 16 * 1024 * 1024;
    let mut buf = Vec::new();
    timeout(
        Duration::from_secs(30),
        (&mut stream).take(MAX_HTTP_BODY).read_to_end(&mut buf),
    )
    .await
    .map_err(|_| BootstrapError::Io("read timeout".into()))?
    .map_err(|e| BootstrapError::Io(e.to_string()))?;

    let (status, body_at) = split_head(&buf).ok_or(BootstrapError::Empty)?;
    if status != 200 {
        return Err(BootstrapError::Http(status));
    }
    let body = buf[body_at..].to_vec();
    if body.is_empty() {
        return Err(BootstrapError::Empty);
    }
    // Transparently unwrap an archive-wrapped list before returning. Every caller
    // wants list DATA (a server.met / nodes.dat to parse or write), never the raw
    // archive, so this is the right single place.
    Ok(maybe_decompress(body))
}

/// gzip magic (`\x1f\x8b`).
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
/// ZIP local-file-header signature (`PK\x03\x04`).
const ZIP_MAGIC: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];
/// Cap on decompressed output. A server.met with tens of thousands of servers is
/// far under this; the bound stops a hostile or MITM'd URL (update_server_list
/// takes a user-entered URL) turning a tiny archive into an OOM - the wire-level
/// 16 MiB body cap does not help once a gzip bomb is inside.
const MAX_DECOMPRESSED: usize = 32 * 1024 * 1024;

/// Transparently unwrap an archive-wrapped list.
///
/// Many published `server.met` lists are served gzipped (`server.met.gz`) or,
/// less often, zipped; without this they arrive as opaque bytes and are rejected
/// as "not a server.met", silently excluding some of the best sources. Anything
/// that is not a recognised archive - INCLUDING a plain, already-decompressed
/// `.met`/`.dat` - is returned unchanged, so this is safe on every fetched body.
/// A malformed or over-cap archive also falls through to the raw bytes, which the
/// caller's validator then rejects cleanly rather than trusting garbage.
pub fn maybe_decompress(body: Vec<u8>) -> Vec<u8> {
    if body.starts_with(&GZIP_MAGIC) {
        if let Some(out) = gunzip(&body) {
            return out;
        }
    } else if body.starts_with(&ZIP_MAGIC) {
        if let Some(out) = unzip_first(&body) {
            return out;
        }
    }
    body
}

fn gunzip(body: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut out = Vec::new();
    // Read one past the cap so an over-limit stream is detectable, not silently
    // truncated into plausible-looking garbage.
    let mut dec = flate2::read::GzDecoder::new(body).take(MAX_DECOMPRESSED as u64 + 1);
    dec.read_to_end(&mut out).ok()?;
    (out.len() <= MAX_DECOMPRESSED && !out.is_empty()).then_some(out)
}

/// Extract the FIRST entry of a ZIP (a list archive holds exactly one file).
/// Handles the common stored (0) and deflate (8) methods; anything else - an
/// unknown method, or a streaming entry whose size lives in a trailing data
/// descriptor (general-purpose bit 3) that needs the central directory to locate
/// - returns None, and the raw bytes are kept.
fn unzip_first(body: &[u8]) -> Option<Vec<u8>> {
    use std::io::Read;
    if body.len() < 30 {
        return None;
    }
    let le16 = |i: usize| u16::from_le_bytes([body[i], body[i + 1]]);
    let le32 = |i: usize| u32::from_le_bytes([body[i], body[i + 1], body[i + 2], body[i + 3]]);

    let flags = le16(6);
    if flags & 0x0008 != 0 {
        return None; // size deferred to a data descriptor - not resolvable here
    }
    let method = le16(8);
    let comp_size = le32(18) as usize;
    let name_len = le16(26) as usize;
    let extra_len = le16(28) as usize;
    let data_start = 30usize.checked_add(name_len)?.checked_add(extra_len)?;
    let data_end = data_start.checked_add(comp_size)?;
    if data_end > body.len() {
        return None;
    }
    let data = &body[data_start..data_end];
    let out = match method {
        0 => data.to_vec(),
        8 => {
            let mut o = Vec::new();
            let mut dec = flate2::read::DeflateDecoder::new(data).take(MAX_DECOMPRESSED as u64 + 1);
            dec.read_to_end(&mut o).ok()?;
            o
        }
        _ => return None,
    };
    (out.len() <= MAX_DECOMPRESSED && !out.is_empty()).then_some(out)
}

/// What `ensure` did, so the engine can report it honestly to the UI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetched {
    /// Already on disk; nothing fetched.
    AlreadyPresent,
    /// Downloaded and written.
    Downloaded,
    /// Not present and the download failed (caller carries on with what it has).
    Failed,
}

/// Ensure a USABLE `name` exists in `dir`, downloading from `url` if it is
/// missing or unusable. Never overwrites a good file, and never fails hard - a
/// bootstrap fetch is best effort; the engine must still start (and can retry
/// later) without one.
///
/// `validate` gates BOTH ends: what we write (a captive-portal or error page
/// must not be saved as if it were a real `.met`) and what we accept as already
/// present.
///
/// That second use is the fix for an empty Servers tab. The guard used to be
/// "exists and len > 0", so a `server.met` that was non-empty but held ZERO
/// servers - or did not parse at all - counted as present on every launch,
/// forever, and the screen read "No server list on disk" until the user
/// happened to find the Refresh button. Seen on the device 2026-08-04. A
/// prune that removes the last server produces exactly that file, so this is
/// reachable in normal use, not just from a corrupt write.
pub async fn ensure(
    dir: &Path,
    name: &str,
    url: &str,
    validate: impl Fn(&[u8]) -> bool,
) -> Fetched {
    let path = dir.join(name);
    if std::fs::read(&path)
        .map(|b| !b.is_empty() && validate(&b))
        .unwrap_or(false)
    {
        return Fetched::AlreadyPresent;
    }
    match http_get_bytes(url).await {
        Ok(body) if validate(&body) => {
            if std::fs::write(&path, &body).is_ok() {
                Fetched::Downloaded
            } else {
                Fetched::Failed
            }
        }
        _ => Fetched::Failed,
    }
}

/// A server.met must parse and hold at least one server.
pub fn looks_like_server_met(b: &[u8]) -> bool {
    mule_files::read_server_met(b)
        .map(|m| !m.servers.is_empty())
        .unwrap_or(false)
}

/// A nodes.dat must parse and hold at least one contact.
pub fn looks_like_nodes_dat(b: &[u8]) -> bool {
    mule_files::read_nodes_dat(b)
        .map(|n| !n.contacts.is_empty())
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_urls() {
        assert_eq!(
            split_url("http://upd.emule-security.org/server.met"),
            Some((
                "upd.emule-security.org".to_string(),
                80,
                "/server.met".to_string()
            ))
        );
        assert_eq!(
            split_url("http://h:8080/x"),
            Some(("h".to_string(), 8080, "/x".to_string()))
        );
        assert_eq!(split_url("https://x/y"), None, "only http is used here");
    }

    #[test]
    fn splits_http_head_byte_safely() {
        // A body with bytes that are NOT valid UTF-8 must survive intact - this
        // is the whole point: server.met/nodes.dat are binary.
        let mut raw = b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n".to_vec();
        raw.extend_from_slice(&[0xE0, 0xFF, 0x00]);
        let (status, at) = split_head(&raw).unwrap();
        assert_eq!(status, 200);
        assert_eq!(&raw[at..], &[0xE0, 0xFF, 0x00]);
    }

    #[test]
    fn reports_non_200() {
        let raw = b"HTTP/1.1 404 Not Found\r\n\r\nnope".to_vec();
        assert_eq!(split_head(&raw).unwrap().0, 404);
    }

    #[test]
    fn validators_reject_junk() {
        // An HTML error page must never be saved as a server list.
        assert!(!looks_like_server_met(b"<html>404</html>"));
        assert!(!looks_like_nodes_dat(b"<html>404</html>"));
        assert!(!looks_like_server_met(&[]));
    }

    /// A minimal but REAL server.met (one server), so decompression is validated
    /// against the actual parser, not a stand-in blob.
    fn sample_server_met() -> Vec<u8> {
        use mule_files::{write_server_met, Server, ServerMet};
        write_server_met(&ServerMet {
            header: 0xE0,
            servers: vec![Server {
                ip: 0x0102_0304,
                port: 4242,
                tags: vec![],
            }],
        })
    }

    #[test]
    fn gunzips_a_wrapped_server_met() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let raw = sample_server_met();
        assert!(looks_like_server_met(&raw));

        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(&raw).unwrap();
        let gz = enc.finish().unwrap();
        assert_ne!(gz, raw, "the gzip must actually differ from the payload");

        let out = maybe_decompress(gz);
        assert_eq!(out, raw, "gunzip must recover the exact bytes");
        assert!(
            looks_like_server_met(&out),
            "a gzipped list must parse after unwrapping"
        );
    }

    #[test]
    fn unwraps_a_stored_zip_entry() {
        let raw = sample_server_met();
        // Hand-build a ZIP local file header with a single STORED entry named "x".
        let name = b"x";
        let mut zip = Vec::new();
        zip.extend_from_slice(&ZIP_MAGIC); // signature
        zip.extend_from_slice(&[20, 0]); // version needed
        zip.extend_from_slice(&[0, 0]); // flags (no data descriptor)
        zip.extend_from_slice(&[0, 0]); // method 0 = stored
        zip.extend_from_slice(&[0, 0, 0, 0]); // mod time/date
        zip.extend_from_slice(&[0, 0, 0, 0]); // crc (unchecked here)
        zip.extend_from_slice(&(raw.len() as u32).to_le_bytes()); // compressed size
        zip.extend_from_slice(&(raw.len() as u32).to_le_bytes()); // uncompressed size
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes()); // name len
        zip.extend_from_slice(&[0, 0]); // extra len
        zip.extend_from_slice(name); // name
        zip.extend_from_slice(&raw); // stored data

        let out = maybe_decompress(zip);
        assert_eq!(out, raw, "a stored zip entry must extract verbatim");
        assert!(looks_like_server_met(&out));
    }

    #[test]
    fn plain_and_malformed_bytes_pass_through_unchanged() {
        // A plain (already-decompressed) server.met is returned as-is.
        let raw = sample_server_met();
        assert_eq!(maybe_decompress(raw.clone()), raw);
        // Gzip magic but truncated garbage: fall through to the raw bytes so the
        // validator rejects it, never a panic and never invented content.
        let fake_gz = vec![0x1f, 0x8b, 0x08, 0x00, 0xAA, 0xBB];
        assert_eq!(maybe_decompress(fake_gz.clone()), fake_gz);
        // ZIP magic but too short to hold a header.
        let fake_zip = vec![0x50, 0x4b, 0x03, 0x04, 0x00];
        assert_eq!(maybe_decompress(fake_zip.clone()), fake_zip);
    }

    #[tokio::test]
    async fn ensure_keeps_an_existing_file_and_never_fetches() {
        let dir = std::env::temp_dir().join(format!("padmule-boot-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("server.met"), b"existing").unwrap();
        // A bogus URL would fail if it were used; AlreadyPresent proves it isn't.
        let r = ensure(&dir, "server.met", "http://127.0.0.1:1/x", |_| true).await;
        assert_eq!(r, Fetched::AlreadyPresent);
        assert_eq!(std::fs::read(dir.join("server.met")).unwrap(), b"existing");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ensure_refetches_a_file_that_is_present_but_unusable() {
        // THE EMPTY SERVERS TAB. The guard used to be "exists and len > 0", so a
        // server.met that was non-empty but held ZERO servers - or did not parse
        // at all - counted as AlreadyPresent on every launch, forever. The
        // Servers screen then read "No server list on disk" with no way back
        // except the user finding the Refresh button, which is exactly what was
        // seen on the device 2026-08-04.
        //
        // `validate` was already sitting right there, used only to gate what we
        // WRITE. Using it on what we already HAVE is the whole fix.
        let dir = std::env::temp_dir().join(format!("padmule-boot3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("server.met"), b"not a real met").unwrap();
        // Bogus URL, so a re-fetch ATTEMPT surfaces as Failed. The point is that
        // it is not AlreadyPresent: the old code never even tried.
        let r = ensure(&dir, "server.met", "http://127.0.0.1:1/x", |b| {
            looks_like_server_met(b)
        })
        .await;
        assert_eq!(
            r,
            Fetched::Failed,
            "an unusable file must be re-fetched, not accepted forever"
        );
        // The bad file is left alone rather than deleted - having something is
        // never worse than having nothing, and the next launch tries again.
        assert!(dir.join("server.met").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn ensure_is_best_effort_when_the_fetch_fails() {
        let dir = std::env::temp_dir().join(format!("padmule-boot2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Port 1 refuses -> Failed, no file, no panic.
        let r = ensure(&dir, "nodes.dat", "http://127.0.0.1:1/x", |_| true).await;
        assert_eq!(r, Fetched::Failed);
        assert!(!dir.join("nodes.dat").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod live {
    use super::*;
    /// Live network check (ignored by default; run with --ignored).
    #[tokio::test]
    #[ignore]
    async fn fetches_real_server_met_and_nodes_dat() {
        let b = http_get_bytes(SERVER_MET_URL).await.expect("server.met");
        assert!(looks_like_server_met(&b), "got {} bytes", b.len());
        let n = http_get_bytes(NODES_DAT_URL).await.expect("nodes.dat");
        assert!(looks_like_nodes_dat(&n), "got {} bytes", n.len());
        println!("server.met {} bytes, nodes.dat {} bytes", b.len(), n.len());
    }
}
