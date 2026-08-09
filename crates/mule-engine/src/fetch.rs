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

use crate::credit_store::CreditStore;
use crate::crypt_policy::{should_obfuscate_outbound, CryptPrefs, PeerCrypt};
use crate::multi_source::{download_from_peer_at, Download, PeerSession, SecIdentCtx};
use crate::peer::HelloInfo;
use crate::peer_conn::{connect_peer, connect_peer_obf};
use crate::secure_ident::Identity;
use crate::share::CreditCtx;
use crate::sources::FoundSource;
use mule_files::IpFilter;
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
    /// The source's userhash, if known - the RC4 key seed, so obfuscation is
    /// impossible without it (necessary, but NOT sufficient: see `crypt`).
    pub user_hash: Option<[u8; 16]>,
    /// The source's obfuscation connect-options byte, if the discovery channel
    /// carried one (Kad TAG_ENCRYPTION, an SX v4 record, or the obfuscated
    /// server source/callback). `None` = never learned -> dial PLAINTEXT.
    pub crypt: Option<u8>,
    pub origin: SourceOrigin,
}

/// eD2k-convention IP u32 (first octet in the low byte) to an `Ipv4Addr`.
/// Delegates to THE one definition (2026-08-09 consolidation); the local name
/// stays because "ed2k ip" is what this module's call sites are converting.
fn ed2k_ip(ip: u32) -> Ipv4Addr {
    mule_files::ip_from_met_u32(ip)
}

/// A publicly routable unicast IPv4 - the only thing that can be a real eD2k
/// SOURCE. Rejects loopback / RFC1918 / link-local / CGNAT / multicast /
/// broadcast / reserved, UNCONDITIONALLY (independent of the user ipfilter, which
/// may be absent on a fresh install). This closes "SSRF-lite": a hostile server or
/// Kad node cannot hand us 127.0.0.1 or a LAN address and make us port-probe it.
/// Interop-safe: a real source is always on a public IP (eMule's IsGoodIP does the
/// same), so no legitimate peer is dropped.
pub fn is_routable_public_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_documentation()
        // 100.64.0.0/10 carrier-grade NAT (not covered by is_private on stable).
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        // 240.0.0.0/4 reserved / experimental.
        || o[0] >= 240)
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
        let addr = Ipv4Addr::from(ip);
        if !is_routable_public_v4(addr) {
            return None;
        }
        Some(PeerSource {
            addr: SocketAddr::from((addr, tcp)),
            user_hash: Some(s.client_hash.to_hash()),
            crypt: s.crypt,
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
        let addr = ed2k_ip(s.ip);
        if !is_routable_public_v4(addr) {
            return None;
        }
        Some(PeerSource {
            addr: SocketAddr::from((addr, s.port)),
            user_hash: s.user_hash,
            crypt: s.crypt,
            origin: SourceOrigin::Server,
        })
    }

    /// From a peer source-exchange record (OP_ANSWERSOURCES). Same eD2k
    /// low-byte IP convention as a server source - `parse_answer_sources` has
    /// already undone the v3+ "hybrid" byte swap - so a LowID id and an
    /// unroutable address are refused exactly as they are there.
    pub fn from_sx(s: &crate::sources::Source) -> Option<Self> {
        if s.port == 0 || s.ip < 0x0100_0000 {
            return None;
        }
        let addr = ed2k_ip(s.ip);
        if !is_routable_public_v4(addr) {
            return None;
        }
        Some(PeerSource {
            addr: SocketAddr::from((addr, s.port)),
            user_hash: s.user_hash,
            crypt: s.crypt,
            origin: SourceOrigin::PeerExchange,
        })
    }

    /// Whether to dial this source with obfuscation. Delegates to the single
    /// eMule-faithful predicate ([`crypt_policy::should_obfuscate_outbound`]),
    /// which needs BOTH the userhash (the RC4 key seed) and the peer's own
    /// advertised crypt support - the latter learned from the discovery channel,
    /// since a hello only exists once the connection already does.
    pub fn should_obfuscate(&self, ours: &CryptPrefs) -> bool {
        should_obfuscate_outbound(
            PeerCrypt::from_connect_options(self.crypt),
            ours,
            self.user_hash.is_some(),
        )
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

/// How long a DIAL may take, separate from the whole-session budget.
///
/// MEASURED, on both networks, and the number changed once the device data
/// arrived - which is why it is written down rather than assumed:
///
/// On this box, of 76 successful handshakes 75 landed under 1s and one at 1-2s;
/// NOT ONE connected after 2s, while 57 dials burned the full 45s and every one
/// failed. That alone argued for a very short deadline.
///
/// On the iPad over a VPN the tail is REAL: 1 connection landed in 5-10s and
/// TWO in 20-45s, out of 315. So "a 5s cap is free" was true only of the
/// unencapsulated path. 10s keeps 313 of those 315 (99.4%) and still kills the
/// 63 dials that each burned 45s - about 37 minutes of worker time in one run.
///
/// It matters far more here than upstream: both authorities use
/// CONNECTION_TIMEOUT = 40s (eMule opcodes.h:62, aMule Constants.h:33-35), but
/// eMule multiplexes hundreds of sockets so a stalled one costs it nothing,
/// whereas padMule gives a download only FOUR workers - so one black-holed
/// address is a quarter of that file's dialing capacity, held for the duration.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The dial deadline for a session allowed `per_peer` in total.
///
/// Never longer than the session budget itself: a caller that deliberately
/// passes a short `per_peer` (the CLI, the tests) must not have its dial silently
/// extended past the budget it chose.
fn connect_deadline(per_peer: Duration) -> Duration {
    CONNECT_TIMEOUT.min(per_peer)
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
    credit_store: Option<&Arc<CreditStore>>,
) -> Result<u64, ()> {
    // Obfuscate only when eMule would (crypt_policy, byte-faithful to
    // BaseClient.cpp:1647): we hold the userhash AND the source advertised crypt
    // support. Dialing obfuscated on the hash alone sends an RC4 handshake to a
    // peer that may read it as a malformed packet and hang up - and nothing,
    // here or in eMule, retries such a dial in plaintext.
    let obfuscate = src.should_obfuscate(&CryptPrefs::default());
    let connect = async {
        match (obfuscate, src.user_hash) {
            (true, Some(h)) => connect_peer_obf(src.addr, me, &h).await,
            _ => connect_peer(src.addr, me).await,
        }
    };
    crate::stats::note_dial();
    let dial_started = std::time::Instant::now();
    let dialed = timeout(connect_deadline(per_peer), connect).await;
    crate::stats::note_dial_time(
        dial_started.elapsed().as_millis() as u64,
        matches!(dialed, Ok(Ok(_))),
    );
    let (peer, mut fs) = match dialed {
        Ok(Ok(v)) => v,
        _ => return Err(()),
    };
    crate::stats::note_connected();
    // Record what we learned about this source (software, obfuscation, LowID)
    // for the per-source UI. Report the connection we ACTUALLY made, so the
    // SourcesView lock reflects the wire rather than merely knowing a hash.
    let low_id = peer.client_id < 0x0100_0000;
    dl.note_source(
        peer.client_software(),
        src.addr,
        obfuscate,
        low_id,
        src.origin,
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
    // Credit what this source gives us against ITS userhash (from the handshake),
    // so it earns a better place in our upload queue later.
    let credit: Option<CreditCtx> = credit_store.map(|cs| (Arc::clone(cs), peer.user_hash));
    // Source exchange: ask this peer who ELSE holds the file, but only if it
    // advertised SX support (aMule requires SX2 or SX1 v>1,
    // IsSourceRequestAllowed) and only once per peer for this download.
    let peer_does_sx = peer
        .capabilities()
        .map(|c| c.source_ex2 || c.source_exchange > 1)
        .unwrap_or(false);
    let ask_sources = peer_does_sx && dl.mark_asked_sources(src.addr.ip());
    // The peer's AICH version gates the root ask + recovery requests.
    let peer_aich = peer.capabilities().map(|c| c.aich).unwrap_or(0);
    let session = PeerSession {
        sec,
        credit,
        ask_sources,
        peer_aich,
    };
    // Multi-source manager: bail the instant this peer queues us and try another
    // source rather than burning `per_peer` in its queue. Pass the addr so a
    // rating/comment (OP_FILEDESC) the source sends is recorded against it.
    match timeout(
        per_peer,
        download_from_peer_at(&mut fs, dl, true, Some(src.addr), session),
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
        // The CLI harness does not persist credits, so no accrual here.
        if fetch_one(dl, src, me, per_peer, identity, None)
            .await
            .is_ok()
        {
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
    credit_store: Option<Arc<CreditStore>>,
    ip_filter: Option<Arc<IpFilter>>,
) -> FetchOutcome {
    let mut out = FetchOutcome::default();
    // The working set GROWS: peers answer our source-exchange requests mid-sweep
    // (see PeerSession::ask_sources), and those sources join the dial pool for
    // later rounds. Starts as the caller's discovered set.
    let mut pool: Vec<PeerSource> = sources.to_vec();
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
        // Fold in sources peers handed us since the last round. Each is
        // re-validated exactly like a Kad/server source (from_sx: LowID and
        // unroutable addresses refused) AND re-checked against the user
        // blocklist, which a mid-sweep source would otherwise bypass.
        for s in dl.take_sx_sources() {
            let Some(ps) = PeerSource::from_sx(&s) else {
                continue;
            };
            if let (Some(f), SocketAddr::V4(v4)) = (&ip_filter, ps.addr) {
                if f.is_blocked(*v4.ip()) {
                    continue;
                }
            }
            if !pool.iter().any(|e| e.addr == ps.addr) {
                pool.push(ps);
            }
        }
        if dl.is_complete().await || dl.is_cancelled() || pool.is_empty() {
            break;
        }
        round += 1;
        let parallel = config.parallel(dl.priority()).max(1);
        // Order the sweep best-first by what each source delivered in prior
        // rounds (proven deliverers, then untried, then proven failures).
        let mut ordered: Vec<PeerSource> = pool.clone();
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
            let credit_store = credit_store.clone();
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
                    // Skip a source banned for delivering a corrupt part to this
                    // file (per-source poisoning defense, multi_source::localize_corruption).
                    if dl.is_banned(&src.addr) {
                        // Counted: the ban set is in-memory and never expires,
                        // so a download can quietly ban its way to zero usable
                        // sources and look identical to one with none.
                        crate::stats::note_skipped_banned();
                        continue;
                    }
                    tried += 1;
                    match fetch_one(
                        &dl,
                        &src,
                        &me,
                        per,
                        identity.as_ref(),
                        credit_store.as_ref(),
                    )
                    .await
                    {
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
        // A Kad source, host-order ip 0x01020304 -> 1.2.3.4. A SYNTHETIC
        // placeholder, not a captured peer: this repo is public and a real
        // address harvested off the live network identifies a real person.
        // It must stay ROUTABLE though - `is_routable_public_v4` rejects the
        // RFC5737 documentation ranges, so those cannot be used here.
        let s = Source {
            client_hash: Kad128::from_hash(&[0xAB; 16]),
            source_type: 1,
            ip: Some(0x0102_0304),
            tcp_port: Some(4662),
            udp_port: Some(4672),
            crypt: None,
        };
        let ps = PeerSource::from_kad(&s).unwrap();
        assert_eq!(ps.addr, "1.2.3.4:4662".parse().unwrap());
        assert_eq!(ps.origin, SourceOrigin::Kad);
        // The userhash is the canonical form of the client hash.
        assert_eq!(ps.user_hash, Some([0xAB; 16]));
    }

    #[test]
    fn the_dial_obfuscates_only_a_source_that_advertised_crypt() {
        // The live rule (eMule Connect(), BaseClient.cpp:1647): knowing the
        // userhash is necessary but NOT sufficient - the peer must have told us
        // it speaks obfuscation. Before this, padMule obfuscated on a known hash
        // alone, so a crypt-DISABLED source was dialed with an RC4 handshake it
        // could not answer and was lost with no plaintext retry (eMule has none
        // either; it simply never dials obfuscated blind).
        let base = Source {
            client_hash: Kad128::from_hash(&[0xAB; 16]),
            source_type: 1,
            ip: Some(0x0102_0304),
            tcp_port: Some(4662),
            udp_port: Some(4672),
            crypt: None,
        };
        let unknown = PeerSource::from_kad(&base).unwrap();
        assert!(unknown.user_hash.is_some(), "we DO hold its hash");
        assert!(
            !unknown.should_obfuscate(&CryptPrefs::default()),
            "no advertised crypt support -> plaintext dial"
        );

        let supports = PeerSource::from_kad(&Source {
            crypt: Some(0x01),
            ..base.clone()
        })
        .unwrap();
        assert!(supports.should_obfuscate(&CryptPrefs::default()));

        // Advertised support but no userhash (no RC4 key seed) -> plaintext.
        let mut keyless = supports.clone();
        keyless.user_hash = None;
        assert!(!keyless.should_obfuscate(&CryptPrefs::default()));
    }

    #[test]
    fn a_peer_exchanged_source_is_connectable_with_its_hash_and_crypt() {
        // Source exchange is the third discovery channel (peers telling us about
        // peers). Its v2+ record carries the userhash and its v4 record the
        // crypt byte, so an SX source can be dialed obfuscated like any other.
        let s = crate::sources::Source {
            ip: 0x8602_0102, // ed2k low-byte order -> 2.1.2.134
            port: 4662,
            server_ip: 0,
            server_port: 0,
            user_hash: Some([0xEE; 16]),
            crypt: Some(0x01),
        };
        let ps = PeerSource::from_sx(&s).unwrap();
        assert_eq!(ps.addr, "2.1.2.134:4662".parse().unwrap());
        assert_eq!(ps.origin, SourceOrigin::PeerExchange);
        assert!(ps.should_obfuscate(&CryptPrefs::default()));

        // A LowID id is not directly connectable, and an unroutable address is
        // refused by the same SSRF guard the other channels use.
        let low = crate::sources::Source {
            ip: 0x0000_0042,
            ..s.clone()
        };
        assert!(PeerSource::from_sx(&low).is_none());
        let lan = crate::sources::Source {
            ip: 0x0100_A8C0, // 192.168.0.1 in ed2k order
            ..s.clone()
        };
        assert!(PeerSource::from_sx(&lan).is_none());
    }

    #[test]
    fn a_server_source_carries_its_crypt_options_to_the_dial() {
        // The obfuscated OP_FOUNDSOURCES variant carries the same connect-options
        // byte; it must reach the dial decision like the Kad tag does.
        let s = FoundSource {
            ip: 0x8602_0102, // ed2k low-byte order
            port: 4662,
            crypt: Some(0x03),
            user_hash: Some([0xCD; 16]),
        };
        let ps = PeerSource::from_found(&s).unwrap();
        assert_eq!(ps.crypt, Some(0x03));
        assert!(ps.should_obfuscate(&CryptPrefs::default()));
    }

    #[test]
    fn firewalled_kad_sources_are_not_directly_connectable() {
        for t in [3u8, 5, 6] {
            let s = Source {
                client_hash: Kad128::default(),
                source_type: t,
                ip: Some(0x0102_0304),
                tcp_port: Some(4662),
                udp_port: Some(4672),
                crypt: None,
            };
            assert!(
                PeerSource::from_kad(&s).is_none(),
                "type {t} needs a callback"
            );
        }
    }

    #[test]
    fn server_source_uses_the_ed2k_low_byte_ip_view() {
        // eD2k low-byte: 1.2.3.4 -> 1 | 2<<8 | 3<<16 | 4<<24.
        let ip = 1u32 | (2 << 8) | (3 << 16) | (4 << 24);
        let s = FoundSource {
            ip,
            port: 4662,
            crypt: None,
            user_hash: Some([0xCD; 16]),
        };
        let ps = PeerSource::from_found(&s).unwrap();
        assert_eq!(ps.addr, "1.2.3.4:4662".parse().unwrap());
        assert_eq!(ps.origin, SourceOrigin::Server);
    }

    #[test]
    fn reserved_and_lan_sources_are_rejected_ssrf_guard() {
        // A hostile server/Kad node handing us loopback/LAN must NOT become a
        // dialable source (SSRF-lite), independent of any user ipfilter.
        for octets in [
            [127, 0, 0, 1],       // loopback
            [192, 168, 1, 5],     // RFC1918
            [10, 0, 0, 7],        // RFC1918
            [172, 16, 0, 9],      // RFC1918
            [169, 254, 1, 1],     // link-local
            [100, 100, 0, 1],     // CGNAT 100.64/10
            [224, 0, 0, 1],       // multicast
            [255, 255, 255, 255], // broadcast
            [0, 0, 0, 0],         // unspecified
        ] {
            assert!(
                !is_routable_public_v4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
                "{octets:?} must be rejected"
            );
            // eD2k low-byte-first encoding of the same address.
            let ip = octets[0] as u32
                | (octets[1] as u32) << 8
                | (octets[2] as u32) << 16
                | (octets[3] as u32) << 24;
            let s = FoundSource {
                ip,
                port: 4662,
                crypt: None,
                user_hash: None,
            };
            assert!(
                PeerSource::from_found(&s).is_none(),
                "{octets:?} must not become a source"
            );
        }
        // A normal public address still works.
        assert!(is_routable_public_v4(Ipv4Addr::new(49, 118, 243, 134)));
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
        // Two directly-connectable PUBLIC server sources: one ipfilter-blocked, one
        // not. (Public, because the always-on SSRF guard now drops LAN/reserved IPs
        // before they can even enter the registry.)
        let bad_ip = 1u32 | (2 << 8) | (3 << 16) | (4 << 24); // 1.2.3.4 (blocked below)
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
        let filter = IpFilter::parse("1.2.3.0 - 1.2.3.255 , 0 , x\n", DEFAULT_IPFILTER_LEVEL);
        let dropped = reg.drop_blocked(|addr| match addr {
            SocketAddr::V4(v4) => filter.is_blocked(*v4.ip()),
            SocketAddr::V6(_) => false,
        });
        assert_eq!(dropped, 1);
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.sources()[0].addr, "8.8.8.8:4662".parse().unwrap());
    }

    #[test]
    fn the_dial_deadline_is_short_but_never_outlives_the_session_budget() {
        // A black-holed address used to hold one of a download's FOUR workers
        // for the whole 45s session budget. The dial now gets its own, far
        // shorter deadline - measured, not guessed: on the VPN 313 of 315 real
        // connections land inside 10s, while 63 dials in one run burned 45s
        // each and connected zero times.
        let session = Duration::from_secs(45);
        assert_eq!(connect_deadline(session), CONNECT_TIMEOUT);
        assert!(
            CONNECT_TIMEOUT < session,
            "the dial deadline must be shorter than the session budget, or it \
             does nothing"
        );
        // ...but a caller that deliberately chose a SHORTER budget keeps it.
        // Extending a 2s budget to 10s would break the CLI and the tests that
        // bound their own runtime.
        let brief = Duration::from_secs(2);
        assert_eq!(connect_deadline(brief), brief);
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
            ip: Some(0x0102_0304), // 1.2.3.4
            tcp_port: Some(4662),
            udp_port: Some(4672),
            crypt: None,
        };
        // The same peer from the server (eD2k low-byte 1.2.3.4, same port).
        let srv = FoundSource {
            ip: 1u32 | (2 << 8) | (3 << 16) | (4 << 24),
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
