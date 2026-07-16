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
    let mut buf = Vec::new();
    timeout(Duration::from_secs(30), stream.read_to_end(&mut buf))
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
    Ok(body)
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

/// Ensure `name` exists in `dir`, downloading from `url` if missing. Never
/// overwrites an existing file, and never fails hard - a bootstrap fetch is best
/// effort; the engine must still start (and can retry later) without one.
///
/// `validate` gates what we write: a captive-portal or error page must not be
/// saved as if it were a real `.met`.
pub async fn ensure(
    dir: &Path,
    name: &str,
    url: &str,
    validate: impl Fn(&[u8]) -> bool,
) -> Fetched {
    let path = dir.join(name);
    if path.exists()
        && std::fs::metadata(&path)
            .map(|m| m.len() > 0)
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
