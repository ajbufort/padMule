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

use crate::multi_source::{download_from_peer_at, Download, SecIdentCtx};
use crate::peer::HelloInfo;
use crate::peer_conn::{connect_peer, connect_peer_obf};
use crate::secure_ident::Identity;
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

    /// Drop sources for which `blocked` is true (e.g. an IP-filter hit). Returns
    /// how many were removed.
    pub fn drop_blocked(&mut self, blocked: impl Fn(SocketAddr) -> bool) -> usize {
        let before = self.sources.len();
        self.sources.retain(|s| !blocked(s.addr));
        before - self.sources.len()
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
/// download into `dl` until the peer stops or the deadline hits. `Ok(bytes)`
/// with the count this source delivered (0 if it connected but only queued us);
/// `Err(())` if we could not even connect/handshake.
async fn fetch_one(
    dl: &Download,
    src: &PeerSource,
    me: &HelloInfo,
    per_peer: Duration,
    identity: Option<&Arc<Identity>>,
) -> Result<u64, ()> {
    let connect = async {
        match src.user_hash {
            Some(h) => connect_peer_obf(src.addr, me, &h).await,
            None => connect_peer(src.addr, me).await,
        }
    };
    let (peer, mut fs) = match timeout(per_peer, connect).await {
        Ok(Ok(v)) => v,
        _ => return Err(()),
    };
    // Record what we learned about this source (software, obfuscation, LowID)
    // for the per-source UI. Obfuscated iff we knew its userhash and dialed obf.
    let low_id = peer.client_id < 0x0100_0000;
    dl.note_source(
        peer.client_software(),
        src.addr,
        src.user_hash.is_some(),
        low_id,
    )
    .await;
    // Secure-ident: run it inline with the transfer when we have an identity.
    // `peer_supports` (from the peer's advertised MISCOPTIONS1) tells us whether
    // to proactively ask it to prove itself. Verifying it marks the source's blue
    // seal; it never gates or delays the download.
    let sec = identity.map(|id| {
        let peer_supports = peer
            .capabilities()
            .map(|c| c.sec_ident != 0)
            .unwrap_or(false);
        SecIdentCtx {
            identity: Arc::clone(id),
            peer_supports,
        }
    });
    // Multi-source manager: bail the instant this peer queues us and try another
    // source rather than burning `per_peer` in its queue. Pass the addr so a
    // rating/comment (OP_FILEDESC) the source sends is recorded against it.
    match timeout(
        per_peer,
        download_from_peer_at(&mut fs, dl, true, Some(src.addr), sec),
    )
    .await
    {
        Ok(Ok(bytes)) => Ok(bytes),
        _ => Ok(0), // connected but delivered nothing (queued / dropped)
    }
}

/// Per-source delivery history, so the manager tries proven-good sources first.
#[derive(Debug, Default)]
pub struct PeerScoreboard {
    peers: std::collections::HashMap<SocketAddr, PeerStat>,
}

#[derive(Debug, Default, Clone, Copy)]
struct PeerStat {
    bytes: u64,
    sessions: u32,
    fails: u32,
}

/// Each connect failure costs this many bytes of "score", so a source that keeps
/// refusing sinks below untried sources (score 0), which sink below deliverers.
const FAIL_PENALTY: i64 = 1_000_000;

impl PeerScoreboard {
    pub fn new() -> Self {
        PeerScoreboard::default()
    }

    fn record(&mut self, addr: SocketAddr, bytes: u64) {
        let e = self.peers.entry(addr).or_default();
        e.bytes += bytes;
        e.sessions += 1;
    }

    fn record_fail(&mut self, addr: SocketAddr) {
        self.peers.entry(addr).or_default().fails += 1;
    }

    /// Higher is better. Unknown sources score 0 (tried after proven deliverers,
    /// before proven failures).
    pub fn score(&self, addr: &SocketAddr) -> i64 {
        match self.peers.get(addr) {
            None => 0,
            Some(s) => s.bytes as i64 - s.fails as i64 * FAIL_PENALTY,
        }
    }
}

/// Download `dl` from a set of candidate sources, one after another, until the
/// file is complete or the sources are exhausted. Per-peer failures (dead peer,
/// no file, queued) are skipped - the next source is tried.
pub async fn fetch_from_sources(
    dl: &Arc<Download>,
    sources: &[PeerSource],
    me: &HelloInfo,
    per_peer: Duration,
    identity: Option<&Arc<Identity>>,
) -> FetchOutcome {
    let mut out = FetchOutcome::default();
    for src in sources {
        if dl.is_complete().await {
            break;
        }
        out.sources_tried += 1;
        if fetch_one(dl, src, me, per_peer, identity).await.is_ok() {
            out.peers_connected += 1;
        }
    }
    out.completed = dl.is_complete().await;
    out.bytes_present = dl.size().await - dl.missing().await;
    out
}

/// How the download manager runs. Two shapes, on purpose:
/// - `Fixed`: an exact peer count + sweep budget, for the CLI/test harnesses that
///   deliberately tune those (they do not carry a user priority).
/// - `ByPriority`: BOTH the concurrent-peer count AND the sweep-round budget are
///   read LIVE from the `Download`'s priority every round (see [`download_file`]),
///   so a mid-session priority change on an actively-fetching download biases the
///   ongoing sweep in both dimensions. This is what the engine uses.
#[derive(Debug, Clone, Copy)]
pub enum ManagerConfig {
    Fixed {
        /// Peers to download from concurrently.
        parallel: usize,
        /// Timeout for one peer session (connect + a burst of blocks).
        per_peer: Duration,
        /// How many times to sweep the source set (see the per-round note below).
        rounds: usize,
    },
    ByPriority {
        per_peer: Duration,
    },
}

impl ManagerConfig {
    /// Concurrent peers for the current round, given the download's live priority.
    fn parallel(&self, priority: u8) -> usize {
        match self {
            ManagerConfig::Fixed { parallel, .. } => *parallel,
            ManagerConfig::ByPriority { .. } => parallel_for_priority(priority),
        }
    }
    /// Sweep-round budget, given the download's live priority.
    fn rounds(&self, priority: u8) -> usize {
        match self {
            ManagerConfig::Fixed { rounds, .. } => *rounds,
            ManagerConfig::ByPriority { .. } => rounds_for_priority(priority),
        }
    }
    fn per_peer(&self) -> Duration {
        match self {
            ManagerConfig::Fixed { per_peer, .. } | ManagerConfig::ByPriority { per_peer } => {
                *per_peer
            }
        }
    }
}

/// Concurrent peers to pull from for a download at `priority`. More peers = more
/// simultaneous upload-slot requests = faster byte accumulation; honest network
/// effort (contacting more of the known sources at once), not a bandwidth grab.
/// PR_NORMAL keeps the historical default of 4, so Normal downloads are unchanged.
pub fn parallel_for_priority(priority: u8) -> usize {
    match priority {
        crate::part_store::PR_LOW => 2,
        crate::part_store::PR_HIGH => 6,
        _ => 4,
    }
}

/// Sweep rounds for a download at `priority`: a higher priority re-sweeps the
/// source set more times before giving up. PR_NORMAL keeps the historical 8.
pub fn rounds_for_priority(priority: u8) -> usize {
    match priority {
        crate::part_store::PR_LOW => 6,
        crate::part_store::PR_HIGH => 12,
        _ => 8,
    }
}

/// The download manager: pull `dl` to completion from `sources`, sweeping the set
/// up to a round budget with several peers at a time. Stops early once complete.
/// Both the peer count and the round budget come from `config` and, for
/// `ByPriority`, are re-read from the download's LIVE priority every round - so
/// raising an actively-fetching download to High immediately widens both.
/// Source discovery/refresh is the caller's job (re-issue get-sources / a Kad
/// search between calls and pass a wider set).
pub async fn download_file(
    dl: &Arc<Download>,
    sources: &[PeerSource],
    me: &HelloInfo,
    config: ManagerConfig,
    identity: Option<Arc<Identity>>,
) -> FetchOutcome {
    let mut out = FetchOutcome::default();
    // Learned across rounds: which sources actually delivered.
    let scoreboard = Arc::new(Mutex::new(PeerScoreboard::new()));
    let mut round = 0usize;
    loop {
        // Both bounds are read live each round from the download's priority (for
        // ByPriority), so a mid-session priority change biases the ongoing sweep
        // in BOTH dimensions - the round budget and the concurrent-peer count.
        if round >= config.rounds(dl.priority()).max(1) {
            break;
        }
        if dl.is_complete().await || dl.is_cancelled() || sources.is_empty() {
            break;
        }
        round += 1;
        let parallel = config.parallel(dl.priority()).max(1);
        // Order the sweep best-first by what each source delivered in prior
        // rounds (proven deliverers, then untried, then proven failures).
        let mut ordered: Vec<PeerSource> = sources.to_vec();
        {
            let sb = scoreboard.lock().await;
            ordered.sort_by_key(|s| std::cmp::Reverse(sb.score(&s.addr)));
        }
        let queue: Arc<Mutex<VecDeque<PeerSource>>> = Arc::new(Mutex::new(ordered.into()));
        let mut handles = Vec::with_capacity(parallel);
        for _ in 0..parallel {
            let dl = Arc::clone(dl);
            let me = me.clone();
            let queue = Arc::clone(&queue);
            let scoreboard = Arc::clone(&scoreboard);
            let per = config.per_peer();
            let identity = identity.clone();
            handles.push(tokio::spawn(async move {
                // (sources_tried, peers_connected) for this worker.
                let mut tried = 0usize;
                let mut connected = 0usize;
                loop {
                    if dl.is_complete().await || dl.is_cancelled() {
                        break;
                    }
                    let Some(src) = queue.lock().await.pop_front() else {
                        break;
                    };
                    tried += 1;
                    match fetch_one(&dl, &src, &me, per, identity.as_ref()).await {
                        Ok(bytes) => {
                            connected += 1;
                            scoreboard.lock().await.record(src.addr, bytes);
                        }
                        Err(()) => scoreboard.lock().await.record_fail(src.addr),
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
    fn drop_blocked_removes_filtered_sources() {
        use mule_files::{IpFilter, DEFAULT_IPFILTER_LEVEL};
        let mut reg = SourceRegistry::new();
        // Two directly-connectable server sources: one blocked, one not.
        let bad_ip = 10u32 | (5 << 24); // eD2k low-byte 10.0.0.5
        let ok_ip = 8u32 | (8 << 8) | (8 << 16) | (8 << 24); // 8.8.8.8
        for ip in [bad_ip, ok_ip] {
            reg.add_found(&[FoundSource {
                ip,
                port: 4662,
                crypt: None,
                user_hash: None,
            }]);
        }
        assert_eq!(reg.len(), 2);
        let filter = IpFilter::parse("10.0.0.0 - 10.0.0.255 , 0 , x\n", DEFAULT_IPFILTER_LEVEL);
        let dropped = reg.drop_blocked(|addr| match addr {
            SocketAddr::V4(v4) => filter.is_blocked(*v4.ip()),
            SocketAddr::V6(_) => false,
        });
        assert_eq!(dropped, 1);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.sources()[0].addr, "8.8.8.8:4662".parse().unwrap());
    }

    #[test]
    fn scoreboard_ranks_deliverers_above_untried_above_failures() {
        let mut sb = PeerScoreboard::new();
        let good: SocketAddr = "1.1.1.1:1".parse().unwrap();
        let bad: SocketAddr = "2.2.2.2:2".parse().unwrap();
        let untried: SocketAddr = "3.3.3.3:3".parse().unwrap();
        sb.record(good, 5_000_000);
        sb.record_fail(bad);
        sb.record_fail(bad);
        // Proven deliverer > untried (0) > proven failure.
        assert!(sb.score(&good) > sb.score(&untried));
        assert_eq!(sb.score(&untried), 0);
        assert!(sb.score(&untried) > sb.score(&bad));
        // A connect that delivered 0 bytes still counts as a (weak) session, not
        // a failure - it does not go negative.
        let queued: SocketAddr = "4.4.4.4:4".parse().unwrap();
        sb.record(queued, 0);
        assert_eq!(sb.score(&queued), 0);
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
