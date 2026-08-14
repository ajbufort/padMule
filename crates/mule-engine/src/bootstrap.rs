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
//!
//! BOTH schemes are supported. `https://` is fetched over rustls with
//! certificate verification ON (see [`tls_config`]); `http://` is unchanged, byte
//! for byte, because the eserver/amuled oracles are plaintext and breaking them
//! would be worse than the gap.
//! Supporting https is what eMule already does - it hands WinInet
//! `INTERNET_FLAG_SECURE` for `AFX_INET_SERVICE_HTTPS`
//! (refs/emule-0.70b/eMule0.70b-Sources/srchybrid/HttpDownloadDlg.cpp:461-463) -
//! so rejecting an https URL was padMule's own limitation, not the authority's.

use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

/// Current, trusted sources (see docs/wiki/build-progress.md - the working
/// source proven live on 2026-07-13).
///
/// TLS BY DEFAULT, WITH A PLAINTEXT FALLBACK ([`fetch_bootstrap_list`]). A fresh
/// install that cannot fetch a server list has no way to start, and the bootstrap
/// is the one thing a new user cannot work around - so an https-ONLY default
/// would trade a real availability risk for a guarantee that a downgrade attack
/// defeats anyway. What the default does buy, and it is worth having, is that a
/// PASSIVE observer past the VPN exit no longer learns from a cleartext request
/// that this device runs an eD2k client.
///
/// STATE THE LIMIT: this is NOT MITM protection. An ACTIVE attacker blocks 443
/// and the fetch downgrades itself, by design. The only thing that bounds the
/// damage of an injected list is the INGESTION VETTING on the way in
/// (`Engine::vet_downloaded_servers` for server.met, `gate_loaded_nodes` for
/// nodes.dat) - never the transport. Do not let this comment, or a release note,
/// grow into a claim that it is.
pub const SERVER_MET_URL: &str = "https://upd.emule-security.org/server.met";
pub const NODES_DAT_URL: &str = "https://upd.emule-security.org/nodes.dat";

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

/// Which transport a URL asks for. Nothing else is accepted - an unknown scheme
/// (or none at all) is a `BadUrl`, never a silent downgrade to plaintext.
///
/// PUBLIC since the built-in bootstrap URLs became `https://` with a plaintext
/// fallback: a caller can no longer tell from the URL which transport actually
/// served the bytes, and that is exactly what a session needs to be told. It was
/// private before, when a URL string in was the whole story.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    /// Plaintext over a bare TCP socket.
    Http,
    /// TLS with certificate verification.
    Https,
}

impl std::fmt::Display for Scheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Scheme::Http => write!(f, "http"),
            Scheme::Https => write!(f, "https"),
        }
    }
}

/// Split `http://host[:port]/path` or `https://host[:port]/path`.
fn split_url(url: &str) -> Option<(Scheme, String, u16, String)> {
    // https FIRST: "http://" is not a prefix of "https://", but ordering the
    // check the other way round is the classic way to get that wrong later.
    let (scheme, rest, default_port) = match url.strip_prefix("https://") {
        Some(rest) => (Scheme::Https, rest, 443u16),
        None => (Scheme::Http, url.strip_prefix("http://")?, 80u16),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (authority.to_string(), default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((scheme, host, port, path.to_string()))
}

/// The trust anchors used to verify an `https://` server.
///
/// ROOTS ROT - a known, accepted cost. These are the Mozilla CA set COMPILED IN
/// via `webpki-roots`, not the device's trust store, so the set only changes when
/// padMule is rebuilt: a root distrusted upstream stays trusted here, and a newly
/// added root stays unknown here, until the next release. The alternative,
/// `rustls-platform-verifier`, reads the OS store and never rots, but reaching
/// the Apple trust store means linking a system framework, and the iOS final
/// link is performed by xcodebuild from `ios/project.yml` - a linkage change
/// that cannot be tested on this dev box, where there is no Apple toolchain.
/// Revisit once CI has proven the plain rustls build; the full rationale, and
/// what was and was not verified for it, is in the workspace `Cargo.toml`.
fn tls_roots() -> RootCertStore {
    RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    }
}

/// The shared TLS client config, built once.
///
/// Certificate verification is ON and there is no way to turn it off: this is the
/// only config this module builds, `with_root_certificates` is the only verifier
/// path it offers, and no "accept invalid certificates" escape hatch exists -
/// behind a feature flag or otherwise. A verification failure surfaces as an
/// [`BootstrapError::Io`], i.e. the fetch simply did not happen.
fn tls_config() -> Arc<ClientConfig> {
    static CFG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CFG.get_or_init(|| {
        // The crypto provider is named EXPLICITLY rather than taken from the
        // process default, so this cannot begin panicking at runtime if a second
        // rustls provider ever enters the dependency graph.
        Arc::new(
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring supports rustls's default protocol versions")
                .with_root_certificates(tls_roots())
                .with_no_client_auth(),
        )
    })
    .clone()
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

/// GET `url` and return the raw body bytes. `http://` goes over a bare socket,
/// `https://` over TLS; nothing else is accepted.
pub async fn http_get_bytes(url: &str) -> Result<Vec<u8>, BootstrapError> {
    let (scheme, host, port, path) = split_url(url).ok_or(BootstrapError::BadUrl)?;
    let tcp = timeout(
        Duration::from_secs(10),
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    .map_err(|_| BootstrapError::Io("connect timeout".into()))?
    .map_err(|e| BootstrapError::Io(e.to_string()))?;

    match scheme {
        Scheme::Http => request_and_read(tcp, &host, &path).await,
        Scheme::Https => {
            // An IP-literal host is accepted here too (rustls verifies it against
            // the certificate's IP SANs); only a syntactically impossible name is
            // a BadUrl.
            let name = ServerName::try_from(host.clone()).map_err(|_| BootstrapError::BadUrl)?;
            // The handshake gets its own bound, matching the connect timeout: a
            // peer that completes the TCP connect and then stalls mid-handshake
            // must not hold the fetch open indefinitely.
            // TIMED, and the timing is reported in the error rather than
            // discarded. On 2026-08-14 the device fell back to plaintext for
            // server.met and then completed the handshake over TLS for nodes.dat
            // SECONDS LATER, to the SAME HOST, in the SAME launch - which rules
            // out the network and points at the FIRST handshake in a process
            // being slower than the ones after it (provider setup and decoding
            // the root list are one-time costs charged entirely to it, and they
            // are counted inside this budget). "TLS handshake timeout" alone
            // could not distinguish that from a stalled peer; the elapsed time
            // and the config-build time can.
            let cfg_started = std::time::Instant::now();
            let cfg = tls_config();
            let cfg_ms = cfg_started.elapsed().as_millis();
            let hs_started = std::time::Instant::now();
            let tls = timeout(
                Duration::from_secs(10),
                TlsConnector::from(cfg).connect(name, tcp),
            )
            .await
            .map_err(|_| {
                BootstrapError::Io(format!(
                    "TLS handshake timeout after {}ms (tls config build {}ms)",
                    hs_started.elapsed().as_millis(),
                    cfg_ms
                ))
            })?
            .map_err(|e| BootstrapError::Io(format!("TLS: {e}")))?;
            request_and_read(tls, &host, &path).await
        }
    }
}

/// Whether a failed `https://` attempt may be retried in the clear.
///
/// ONLY a transport failure, which is what `Io` is here: the connect, the TLS
/// handshake, or the read never landed, so nothing about the file itself is
/// known. Every other variant means the exchange DID happen - `Http` carries a
/// status the host chose (a 404 over TLS means the file is gone, and fetching the
/// same nothing in the clear gains exactly nothing), `Empty` means it answered
/// with no body, and `BadUrl` never reached a socket at all.
fn tls_attempt_never_landed(err: &BootstrapError) -> bool {
    matches!(err, BootstrapError::Io(_))
}

/// GET a BUILT-IN bootstrap list, preferring TLS and falling back to plaintext
/// when the TLS attempt never landed. Returns the body and the transport that
/// actually served it.
///
/// Scoped to the built-in URLs on purpose. A user-configured server-list URL goes
/// through [`http_get_bytes`] instead, so an `https://` one THEY chose is fetched
/// over TLS or not at all - the availability argument that justifies a downgrade
/// (see [`SERVER_MET_URL`]) applies to the cold-start path and to nothing else.
pub async fn fetch_bootstrap_list(url: &str) -> Result<(Vec<u8>, Scheme), BootstrapError> {
    let Some(rest) = url.strip_prefix("https://") else {
        // Nothing to downgrade FROM: fetch it as written.
        return http_get_bytes(url).await.map(|b| (b, Scheme::Http));
    };
    match http_get_bytes(url).await {
        Ok(body) => Ok((body, Scheme::Https)),
        Err(e) if tls_attempt_never_landed(&e) => http_get_bytes(&format!("http://{rest}"))
            .await
            .map(|b| (b, Scheme::Http)),
        Err(e) => Err(e),
    }
}

/// Send the GET and read the capped response off an already-connected stream.
///
/// Generic over the transport so the request shape, the body cap, the read
/// timeout and the head/status handling are literally the same code for
/// plaintext and TLS, and cannot drift apart.
async fn request_and_read<S>(
    mut stream: S,
    host: &str,
    path: &str,
) -> Result<Vec<u8>, BootstrapError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
    let read = timeout(
        Duration::from_secs(30),
        (&mut stream).take(MAX_HTTP_BODY).read_to_end(&mut buf),
    )
    .await
    .map_err(|_| BootstrapError::Io("read timeout".into()))?;
    match read {
        Ok(_) => {}
        // A TLS peer that answers `Connection: close` by closing the TCP socket
        // WITHOUT first sending close_notify surfaces as UnexpectedEof; real
        // servers do this. Keep what arrived rather than discarding a complete
        // response over a missing shutdown record. This is not a new weakness:
        // the plaintext path has always ended on a bare FIN and relied on the
        // caller's validator (`looks_like_server_met` / `looks_like_nodes_dat`)
        // to reject a truncated body, which a full parse does. If nothing at all
        // arrived, the `split_head` below fails cleanly as Empty.
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(BootstrapError::Io(e.to_string())),
    }

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
    /// Downloaded and written, over the transport named - which is NOT decidable
    /// from the URL any more, since the built-in ones are https with a plaintext
    /// fallback.
    Downloaded(Scheme),
    /// Not present and the download failed (caller carries on with what it has).
    Failed,
}

/// Whether `dir/name` is already a USABLE list - the exact question `ensure` asks
/// before it decides to fetch, exposed so a caller doing its own fetching (the
/// VETTED server.met path, `Engine::ensure_server_list`) asks the same one and
/// the two cannot drift apart.
///
/// `validate` is deliberately the raw parse test, NOT an ingestion gate: a file
/// holding only the loopback eserver oracle, or only a LAN server the user added,
/// is usable, and answering "no" here would make the next launch fetch over the
/// top of it.
pub fn is_usable(dir: &Path, name: &str, validate: impl Fn(&[u8]) -> bool) -> bool {
    std::fs::read(dir.join(name))
        .map(|b| !b.is_empty() && validate(&b))
        .unwrap_or(false)
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
///
/// WRITES THE FETCHED BODY VERBATIM, so this is only correct for a file whose
/// contents are gated somewhere ELSE. nodes.dat is: `gate_loaded_nodes` filters
/// every contact at LOAD. server.met is NOT, and no longer comes through here -
/// see `Engine::ensure_server_list`.
pub async fn ensure(
    dir: &Path,
    name: &str,
    url: &str,
    validate: impl Fn(&[u8]) -> bool,
) -> Fetched {
    if is_usable(dir, name, &validate) {
        return Fetched::AlreadyPresent;
    }
    match fetch_bootstrap_list(url).await {
        Ok((body, via)) if validate(&body) => {
            if std::fs::write(dir.join(name), &body).is_ok() {
                Fetched::Downloaded(via)
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
                Scheme::Http,
                "upd.emule-security.org".to_string(),
                80,
                "/server.met".to_string()
            ))
        );
        assert_eq!(
            split_url("http://h:8080/x"),
            Some((Scheme::Http, "h".to_string(), 8080, "/x".to_string()))
        );
    }

    /// An https URL must parse, pick the TLS transport, and default to port 443 -
    /// not 80, which would connect to a plaintext listener and hand it a
    /// ClientHello.
    #[test]
    fn splits_https_urls_with_the_tls_default_port() {
        assert_eq!(
            split_url("https://example.org/list.met"),
            Some((
                Scheme::Https,
                "example.org".to_string(),
                443,
                "/list.met".to_string()
            ))
        );
        assert_eq!(
            split_url("https://h:8443/x"),
            Some((Scheme::Https, "h".to_string(), 8443, "/x".to_string()))
        );
        // No scheme, and schemes we do not speak, stay rejected - an unknown
        // scheme must never fall through to plaintext.
        assert_eq!(split_url("ftp://x/y"), None);
        assert_eq!(split_url("upd.emule-security.org/server.met"), None);
        assert_eq!(split_url("https://"), None, "empty host");
    }

    /// The verifier must be fed a REAL trust anchor set. An empty root store would
    /// still "verify certificates" - it would just reject every one of them - and
    /// the only symptom would be that https never works, which is easy to blame on
    /// the network.
    #[test]
    fn the_tls_roots_are_a_real_ca_set() {
        let roots = tls_roots();
        assert!(
            roots.roots.len() > 50,
            "expected the webpki-roots CA set, got {} anchors",
            roots.roots.len()
        );
        // And the config actually builds with them - this call is what would
        // panic if the crypto provider were misconfigured - and is built ONCE.
        let cfg = tls_config();
        assert!(
            Arc::ptr_eq(&cfg, &tls_config()),
            "the client config must be built once and shared"
        );
    }

    /// Read whatever a client sends on one loopback connection, then hang up.
    /// Returns the bound port and a handle yielding the first bytes received.
    ///
    /// This is the only way to prove the transport OFFLINE: no certificate is
    /// presented, so both fetches below fail - the assertion is about the bytes
    /// padMule PUT ON THE WIRE, which is exactly the property under test.
    async fn first_bytes_listener() -> (u16, tokio::task::JoinHandle<Vec<u8>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return Vec::new();
            };
            let mut buf = vec![0u8; 512];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            buf.truncate(n);
            buf
        });
        (port, handle)
    }

    /// THE LOAD-BEARING TEST for this change: an `https://` URL must produce a TLS
    /// ClientHello, never a cleartext `GET`. Without it, "https support" could be
    /// nothing but a relaxed scheme check that then speaks plaintext to port 443 -
    /// which would LOOK like it worked against any server that tolerates it, while
    /// giving up every guarantee TLS was added for.
    #[tokio::test]
    async fn the_https_path_speaks_tls_not_plaintext() {
        let (port, seen) = first_bytes_listener().await;
        // The listener never presents a certificate, so this must fail; the
        // failure is expected and irrelevant. The wire bytes are the evidence.
        let r = http_get_bytes(&format!("https://127.0.0.1:{port}/x")).await;
        assert!(r.is_err(), "a listener with no certificate cannot succeed");
        let bytes = seen.await.unwrap();
        assert!(
            bytes.len() > 5,
            "the client sent {} bytes - no handshake happened",
            bytes.len()
        );
        assert!(
            !bytes.starts_with(b"GET "),
            "https sent a CLEARTEXT request: {:?}",
            String::from_utf8_lossy(&bytes[..bytes.len().min(32)])
        );
        // TLS record layer: content type 0x16 (handshake), then the legacy
        // version 0x03 0x01, then the ClientHello message type 0x01.
        assert_eq!(bytes[0], 0x16, "not a TLS handshake record");
        assert_eq!(&bytes[1..3], &[0x03, 0x01], "not a TLS record version");
        assert_eq!(bytes[5], 0x01, "not a ClientHello");
    }

    /// The control, and the guarantee that mattered most: `http://` is UNCHANGED.
    /// The oracles (eserver, amuled) and the published bootstrap endpoints are
    /// plaintext, so a client that started sending ClientHellos to them would be a
    /// worse regression than the gap this change closes.
    #[tokio::test]
    async fn the_http_path_still_speaks_plaintext() {
        let (port, seen) = first_bytes_listener().await;
        let _ = http_get_bytes(&format!("http://127.0.0.1:{port}/server.met")).await;
        let bytes = seen.await.unwrap();
        let text = String::from_utf8_lossy(&bytes).to_string();
        assert!(
            text.starts_with("GET /server.met HTTP/1.1\r\n"),
            "http must still send a cleartext GET, got {text:?}"
        );
        assert!(text.contains("Host: 127.0.0.1\r\n"), "got {text:?}");
        assert!(text.contains("Connection: close\r\n"), "got {text:?}");
    }

    /// The DECISION Anthony made, guarded against a silent revert: the built-in
    /// bootstrap URLs default to TLS. A passive observer past the VPN exit
    /// otherwise learns from the cleartext request that this device runs an eD2k
    /// client, and these two fetches are the first thing a fresh install does.
    #[test]
    fn the_builtin_bootstrap_urls_default_to_tls() {
        assert!(
            SERVER_MET_URL.starts_with("https://"),
            "got {SERVER_MET_URL}"
        );
        assert!(NODES_DAT_URL.starts_with("https://"), "got {NODES_DAT_URL}");
    }

    /// Which failures may downgrade, stated as the pure decision so it can be
    /// enumerated offline - a real 404-over-TLS test would need a local CA.
    ///
    /// The 404 case is the one that matters: the host ANSWERED, so the file is
    /// gone, and a plaintext retry fetches the same nothing while giving up the
    /// only thing the https default buys.
    #[test]
    fn only_a_transport_failure_may_downgrade() {
        assert!(tls_attempt_never_landed(&BootstrapError::Io(
            "connect timeout".into()
        )));
        assert!(tls_attempt_never_landed(&BootstrapError::Io(
            "TLS: invalid peer certificate".into()
        )));
        assert!(!tls_attempt_never_landed(&BootstrapError::Http(404)));
        assert!(!tls_attempt_never_landed(&BootstrapError::Http(500)));
        assert!(!tls_attempt_never_landed(&BootstrapError::Empty));
        assert!(!tls_attempt_never_landed(&BootstrapError::BadUrl));
    }

    /// Serve `body` as an HTTP 200 to every connection, forever, counting them.
    /// The COUNT is the evidence: it is what distinguishes "TLS was tried and
    /// then downgraded" (2) from "plaintext was sent straight away" (1).
    async fn counting_http_server(body: Vec<u8>) -> (u16, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = seen.clone();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let body = body.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = sock.write_all(head.as_bytes()).await;
                    let _ = sock.write_all(&body).await;
                    let _ = sock.shutdown().await;
                });
            }
        });
        (port, seen)
    }

    /// THE LOAD-BEARING TEST for the https default: when the TLS attempt cannot
    /// land, the fetch falls back to plaintext and STILL RETURNS THE BYTES. A
    /// fresh install that cannot fetch a server list has no way to start, which
    /// is the whole reason the fallback exists.
    ///
    /// The listener speaks plaintext HTTP only, so the ClientHello is answered
    /// with an HTTP response and rustls rejects it - a real TLS-unavailable host,
    /// offline. Two connections is the proof the TLS attempt was actually MADE:
    /// with one, the code would simply have ignored the https scheme.
    #[tokio::test]
    async fn https_falls_back_to_plaintext_when_the_tls_attempt_never_lands() {
        let payload = sample_server_met();
        let (port, seen) = counting_http_server(payload.clone()).await;

        let (body, via) = fetch_bootstrap_list(&format!("https://127.0.0.1:{port}/server.met"))
            .await
            .expect("the fallback must still deliver a list");
        assert_eq!(body, payload, "the fallback must return the real bytes");
        assert_eq!(via, Scheme::Http, "the fallback must SAY it went plaintext");
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "TLS must be tried FIRST and plaintext only as the retry"
        );

        // And a plaintext URL must not grow a speculative TLS probe: one
        // connection, one scheme, unchanged from before this feature existed.
        let (port, seen) = counting_http_server(payload.clone()).await;
        let (body, via) = fetch_bootstrap_list(&format!("http://127.0.0.1:{port}/server.met"))
            .await
            .expect("plaintext is unchanged");
        assert_eq!(body, payload);
        assert_eq!(via, Scheme::Http);
        assert_eq!(
            seen.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "an http:// URL must be fetched once, with no TLS attempt"
        );
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

    /// THE DEFAULT MUST ACTUALLY HOLD against the real host, which no offline
    /// test can show: `fetch_bootstrap_list` falls back to plaintext on its own,
    /// so a `Scheme::Http` here means padMule is quietly bootstrapping in the
    /// clear every time and nothing else would say so. Run this after any change
    /// to the URLs or the TLS config.
    ///
    /// Run: cargo test -p mule-engine --lib -- --ignored --exact \
    ///      bootstrap::live::the_builtin_urls_really_are_served_over_tls
    #[tokio::test]
    #[ignore]
    async fn the_builtin_urls_really_are_served_over_tls() {
        for url in [SERVER_MET_URL, NODES_DAT_URL] {
            let (body, via) = fetch_bootstrap_list(url)
                .await
                .unwrap_or_else(|e| panic!("{url}: {e}"));
            assert_eq!(via, Scheme::Https, "{url} fell back to plaintext");
            println!("{url}: {} bytes over {via}", body.len());
        }
    }

    /// The end-to-end proof the offline tests CANNOT give: a full TLS handshake
    /// against a real certificate, verified against the compiled-in roots, with a
    /// real server.met coming back and parsing.
    ///
    /// The offline suite proves only that a ClientHello leaves the socket. That is
    /// the mechanism, not the precondition - a config that trusts nothing sends an
    /// identical ClientHello and then fails every handshake, and the offline test
    /// could not tell the difference. This is the test that can, so it is worth
    /// having even though it is ignored by default (the suite must stay offline).
    ///
    /// Run: cargo test -p mule-engine --lib -- --ignored --exact \
    ///      bootstrap::live::fetches_a_real_server_met_over_https
    #[tokio::test]
    #[ignore]
    async fn fetches_a_real_server_met_over_https() {
        // The SAME canonical host as SERVER_MET_URL, which also answers on 443.
        let b = http_get_bytes("https://upd.emule-security.org/server.met")
            .await
            .expect("https server.met");
        assert!(looks_like_server_met(&b), "got {} bytes", b.len());
        println!("https server.met {} bytes", b.len());
    }

    /// And the other half: certificate verification must actually REJECT. Without
    /// this, "https support" could be a verifier that accepts anything, and the
    /// positive test above would still pass.
    #[tokio::test]
    #[ignore]
    async fn https_refuses_a_certificate_that_does_not_verify() {
        let r = http_get_bytes("https://expired.badssl.com/").await;
        let Err(BootstrapError::Io(msg)) = r else {
            panic!("an expired certificate must not be accepted, got {r:?}");
        };
        assert!(
            msg.starts_with("TLS: "),
            "expected a TLS failure, got {msg}"
        );
        println!("rejected as expected: {msg}");
    }
}
