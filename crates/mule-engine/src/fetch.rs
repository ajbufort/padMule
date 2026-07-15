//! End-to-end fetch orchestration (Wave 7): "give a hash, get the file". Unifies
//! candidate sources discovered from different backends (Kad source search,
//! server OP_FOUNDSOURCES, peer source exchange) into one connectable
//! [`PeerSource`] set, then drives [`Download`] to completion across them.
//!
//! The discovery backends disagree on IP byte order, which is the whole reason
//! this normalisation lives in one place:
//!   - Kad `TAG_SOURCEIP` is the host-order value; its dotted quad is the
//!     big-endian view (`Ipv4Addr::from(ip)`) - eMule does `ED2KID = SWAP(ip)`
//!     then displays `ED2KID` low-byte-first, which is the same thing.
//!   - Server / peer-exchange sources use the eD2k convention: the first octet
//!     is the LOW byte (`Ipv4Addr::new(ip, ip>>8, ip>>16, ip>>24)`).

use crate::multi_source::{download_from_peer, Download};
use crate::peer::HelloInfo;
use crate::peer_conn::{connect_peer, connect_peer_obf};
use crate::sources::FoundSource;
use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;

/// Which discovery backend surfaced a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceOrigin {
    Kad,
    Server,
    PeerExchange,
}

/// A directly-connectable download source, normalised across discovery origins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSource {
    /// Resolved, ready-to-connect address.
    pub addr: SocketAddr,
    /// The source's userhash, if known - lets us obfuscate the connection.
    pub user_hash: Option<[u8; 16]>,
    pub origin: SourceOrigin,
}

/// eD2k-convention IP u32 (first octet in the low byte) to an `Ipv4Addr`.
fn ed2k_ip(ip: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        ip as u8,
        (ip >> 8) as u8,
        (ip >> 16) as u8,
        (ip >> 24) as u8,
    )
}

impl PeerSource {
    /// From a Kad source-search result. Only HighID types (1 and 4) carry a
    /// directly-connectable IP:port; firewalled types (3/5/6) need a
    /// buddy/callback and are skipped. Kad IP is the big-endian view; the
    /// userhash is the source client hash in canonical form.
    pub fn from_kad(s: &mule_kad::Source) -> Option<Self> {
        if !matches!(s.source_type, 1 | 4) {
            return None;
        }
        let ip = s.ip?;
        let tcp = s.tcp_port?;
        if ip == 0 || tcp == 0 {
            return None;
        }
        Some(PeerSource {
            addr: SocketAddr::from((Ipv4Addr::from(ip), tcp)),
            user_hash: Some(s.client_hash.to_hash()),
            origin: SourceOrigin::Kad,
        })
    }

    /// From a server OP_FOUNDSOURCES entry (eD2k low-byte IP). A LowID id
    /// (`< 0x0100_0000`) is not directly connectable - it needs a server
    /// callback - and is skipped here.
    pub fn from_found(s: &FoundSource) -> Option<Self> {
        if s.port == 0 || s.ip < 0x0100_0000 {
            return None;
        }
        Some(PeerSource {
            addr: SocketAddr::from((ed2k_ip(s.ip), s.port)),
            user_hash: s.user_hash,
            origin: SourceOrigin::Server,
        })
    }
}

/// Collects candidate sources from any number of discovery backends, de-duping
/// by address so the same peer is not dialed twice.
#[derive(Debug, Default)]
pub struct SourceRegistry {
    sources: Vec<PeerSource>,
}

impl SourceRegistry {
    pub fn new() -> Self {
        SourceRegistry::default()
    }

    /// Add a source; returns `false` if an equal address was already known.
    pub fn add(&mut self, s: PeerSource) -> bool {
        if self.sources.iter().any(|e| e.addr == s.addr) {
            return false;
        }
        self.sources.push(s);
        true
    }

    /// Add every connectable Kad source from a resolve result.
    pub fn add_kad(&mut self, sources: &[mule_kad::Source]) -> usize {
        sources
            .iter()
            .filter_map(PeerSource::from_kad)
            .filter(|s| self.add(s.clone()))
            .count()
    }

    /// Add every connectable server source.
    pub fn add_found(&mut self, sources: &[FoundSource]) -> usize {
        sources
            .iter()
            .filter_map(PeerSource::from_found)
            .filter(|s| self.add(s.clone()))
            .count()
    }

    pub fn sources(&self) -> &[PeerSource] {
        &self.sources
    }

    pub fn len(&self) -> usize {
        self.sources.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }
}

/// The result of a fetch attempt.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct FetchOutcome {
    /// Sources we attempted to connect to.
    pub sources_tried: usize,
    /// Sources that completed a peer handshake.
    pub peers_connected: usize,
    /// Whether the file is now complete.
    pub completed: bool,
    /// Bytes present in the store after the attempt.
    pub bytes_present: u64,
}

/// Connect to `src` (obfuscated if we know its userhash, else plaintext) and
/// download into `dl` until the peer stops or the deadline hits.
async fn fetch_one(
    dl: &Download,
    src: &PeerSource,
    me: &HelloInfo,
    per_peer: Duration,
) -> Result<(), ()> {
    let connect = async {
        match src.user_hash {
            Some(h) => connect_peer_obf(src.addr, me, &h).await,
            None => connect_peer(src.addr, me).await,
        }
    };
    let (_peer, mut fs) = match timeout(per_peer, connect).await {
        Ok(Ok(v)) => v,
        _ => return Err(()),
    };
    let _ = timeout(per_peer, download_from_peer(&mut fs, dl)).await;
    Ok(())
}

/// Download `dl` from a set of candidate sources, one after another, until the
/// file is complete or the sources are exhausted. Per-peer failures (dead peer,
/// no file, queued) are skipped - the next source is tried.
pub async fn fetch_from_sources(
    dl: &Arc<Download>,
    sources: &[PeerSource],
    me: &HelloInfo,
    per_peer: Duration,
) -> FetchOutcome {
    let mut out = FetchOutcome::default();
    for src in sources {
        if dl.is_complete().await {
            break;
        }
        out.sources_tried += 1;
        if fetch_one(dl, src, me, per_peer).await.is_ok() {
            out.peers_connected += 1;
        }
    }
    out.completed = dl.is_complete().await;
    out.bytes_present = dl.size().await - dl.missing().await;
    out
}

/// How the download manager runs.
#[derive(Debug, Clone, Copy)]
pub struct ManagerConfig {
    /// Peers to download from concurrently. A `Download` reserves distinct block
    /// ranges per peer, so parallel peers split the work safely.
    pub parallel: usize,
    /// Timeout for one peer session (connect + a burst of blocks).
    pub per_peer: Duration,
    /// How many times to sweep the source set. eD2k peers ration upload slots -
    /// they serve a burst then queue/drop you - so retrying accumulates the file
    /// across reconnects (the `.part` persists progress between sweeps).
    pub rounds: usize,
}

impl Default for ManagerConfig {
    fn default() -> Self {
        ManagerConfig {
            parallel: 4,
            per_peer: Duration::from_secs(45),
            rounds: 8,
        }
    }
}

/// The download manager: pull `dl` to completion from `sources`, `parallel` peers
/// at a time, sweeping the set up to `rounds` times. Stops early once complete.
/// Source discovery/refresh is the caller's job (re-issue get-sources / a Kad
/// search between calls and pass a wider set).
pub async fn download_file(
    dl: &Arc<Download>,
    sources: &[PeerSource],
    me: &HelloInfo,
    config: ManagerConfig,
) -> FetchOutcome {
    let mut out = FetchOutcome::default();
    let parallel = config.parallel.max(1);
    for _round in 0..config.rounds.max(1) {
        if dl.is_complete().await || sources.is_empty() {
            break;
        }
        let queue: Arc<Mutex<VecDeque<PeerSource>>> =
            Arc::new(Mutex::new(sources.iter().cloned().collect()));
        let mut handles = Vec::with_capacity(parallel);
        for _ in 0..parallel {
            let dl = Arc::clone(dl);
            let me = me.clone();
            let queue = Arc::clone(&queue);
            let per = config.per_peer;
            handles.push(tokio::spawn(async move {
                // (sources_tried, peers_connected) for this worker.
                let mut tried = 0usize;
                let mut connected = 0usize;
                loop {
                    if dl.is_complete().await {
                        break;
                    }
                    let Some(src) = queue.lock().await.pop_front() else {
                        break;
                    };
                    tried += 1;
                    if fetch_one(&dl, &src, &me, per).await.is_ok() {
                        connected += 1;
                    }
                }
                (tried, connected)
            }));
        }
        for h in handles {
            if let Ok((tried, connected)) = h.await {
                out.sources_tried += tried;
                out.peers_connected += connected;
            }
        }
    }
    out.completed = dl.is_complete().await;
    out.bytes_present = dl.size().await - dl.missing().await;
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_kad::Source;
    use mule_proto::Kad128;

    #[test]
    fn kad_highid_source_uses_the_big_endian_ip_view() {
        // A real resolved Kad source: host-order ip 0x3176F386 -> 49.118.243.134.
        let s = Source {
            client_hash: Kad128::from_hash(&[0xAB; 16]),
            source_type: 1,
            ip: Some(0x3176_F386),
            tcp_port: Some(4662),
            udp_port: Some(4672),
        };
        let ps = PeerSource::from_kad(&s).unwrap();
        assert_eq!(ps.addr, "49.118.243.134:4662".parse().unwrap());
        assert_eq!(ps.origin, SourceOrigin::Kad);
        // The userhash is the canonical form of the client hash.
        assert_eq!(ps.user_hash, Some([0xAB; 16]));
    }

    #[test]
    fn firewalled_kad_sources_are_not_directly_connectable() {
        for t in [3u8, 5, 6] {
            let s = Source {
                client_hash: Kad128::default(),
                source_type: t,
                ip: Some(0x3176_F386),
                tcp_port: Some(4662),
                udp_port: Some(4672),
            };
            assert!(
                PeerSource::from_kad(&s).is_none(),
                "type {t} needs a callback"
            );
        }
    }

    #[test]
    fn server_source_uses_the_ed2k_low_byte_ip_view() {
        // eD2k low-byte: 49.118.243.134 -> 49 | 118<<8 | 243<<16 | 134<<24.
        let ip = 49u32 | (118 << 8) | (243 << 16) | (134 << 24);
        let s = FoundSource {
            ip,
            port: 4662,
            crypt: None,
            user_hash: Some([0xCD; 16]),
        };
        let ps = PeerSource::from_found(&s).unwrap();
        assert_eq!(ps.addr, "49.118.243.134:4662".parse().unwrap());
        assert_eq!(ps.origin, SourceOrigin::Server);
    }

    #[test]
    fn lowid_server_source_is_skipped() {
        let s = FoundSource {
            ip: 123_456, // < 0x01000000 -> LowID, needs a callback
            port: 4662,
            crypt: None,
            user_hash: None,
        };
        assert!(PeerSource::from_found(&s).is_none());
    }

    #[test]
    fn registry_dedups_by_address_across_origins() {
        let mut reg = SourceRegistry::new();
        let kad = Source {
            client_hash: Kad128::default(),
            source_type: 1,
            ip: Some(0x3176_F386), // 49.118.243.134
            tcp_port: Some(4662),
            udp_port: Some(4672),
        };
        // The same peer from the server (eD2k low-byte 49.118.243.134, same port).
        let srv = FoundSource {
            ip: 49u32 | (118 << 8) | (243 << 16) | (134 << 24),
            port: 4662,
            crypt: None,
            user_hash: None,
        };
        assert_eq!(reg.add_kad(std::slice::from_ref(&kad)), 1);
        assert_eq!(
            reg.add_found(std::slice::from_ref(&srv)),
            0,
            "same addr - deduped"
        );
        assert_eq!(reg.len(), 1);
    }
}
