//! Downloading one file from several peers at once.
//!
//! A `Download` owns the `.part` file and the set of block reservations. Each
//! peer runs its own task against it: claim blocks nobody else is fetching, ask
//! for them, write what arrives, release what it did not get.
//!
//! The reservation set is what makes multi-source work at all - without it every
//! peer would race to fetch block 0. Two properties are load-bearing:
//!
//! - A peer only ever gets blocks from parts it actually HAS (per its
//!   OP_FILESTATUS bitfield).
//! - Reservations are ALWAYS released when a peer goes away, whether it finished,
//!   errored, or vanished mid-block. A leaked reservation is a block no other
//!   peer will ever be offered, and the download would stall a few bytes short
//!   with no visible error.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex as StdMutex};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::credit_store::now_secs;
use crate::framed::FramedStream;
use crate::part_file::data_part_count;
use crate::part_store::PartStore;
use crate::secure_ident::{
    Identity, SecureIdentSession, OP_PUBLICKEY, OP_SECIDENTSTATE, OP_SIGNATURE,
};
use crate::share::CreditCtx;
use crate::sources::{
    build_request_sources2, parse_answer_sources, Source as SxSource, OP_ANSWERSOURCES,
    OP_ANSWERSOURCES2, SOURCE_EXCHANGE_VERSION,
};
use crate::transfer::{
    build_aich_file_hash_req, build_aich_request, build_hashset_request,
    build_request_filename_ext, build_request_parts, build_set_req_file_id, build_start_upload_req,
    parse_aich_answer, parse_aich_file_hash_ans, parse_file_desc, parse_file_status,
    parse_hashset_answer, AichAnswer, BlockReceiver, FileStatus, EMBLOCKSIZE, OP_ACCEPTUPLOADREQ,
    OP_AICHANSWER, OP_AICHFILEHASHANS, OP_FILEDESC, OP_FILEREQANSNOFIL, OP_FILESTATUS,
    OP_HASHSETANSWER, OP_OUTOFPARTREQS, OP_QUEUERANKING, STANDARD_BLOCKS_REQUEST,
};
use crate::transfer_session::TransferError;
use mule_proto::{AichTree, Packet, PARTSIZE};

/// Inputs the download-side secure-ident exchange needs: our RSA identity, and
/// whether the peer advertised secure-ident support in its HELLO (so we know to
/// proactively ask it to prove itself, matching a real eMule downloader).
pub struct SecIdentCtx {
    pub identity: Arc<Identity>,
    pub peer_supports: bool,
}

/// The optional extras one download connection can carry, bundled so the
/// transfer functions keep a readable arity: the secure-ident context, the
/// credit sink for bytes this source gives us, and whether to ask this peer for
/// more sources (source exchange).
#[derive(Default)]
pub struct PeerSession {
    pub sec: Option<SecIdentCtx>,
    pub credit: Option<CreditCtx>,
    /// Ask this peer for other sources of the file. The caller decides, since
    /// it knows both the peer's advertised SX support and whether we already
    /// asked this IP ([`Download::mark_asked_sources`]).
    pub ask_sources: bool,
    /// The peer's announced AICH version (hello MISCOPTIONS1 bits 29-31).
    /// Gates the root ask and recovery requests on eMule's own
    /// IsSupportingAICH bit-0 test.
    pub peer_aich: u8,
}

/// The AICH trust states padMule holds in memory (eMule EAICHStatus,
/// SHAHashSet.h:74-81, minus the set-level states).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AichStatus {
    /// No root known yet.
    Empty,
    /// A root is known but has not met the vote threshold - recovery stays OFF.
    Untrusted,
    /// The root won the source vote (>= 10 distinct /20s and >= 92% agreement).
    Trusted,
    /// The root is part of the file's identity (ed2k link) - never displaced.
    Verified,
    /// A root that recovery PROVED wrong for this file (its "verified" blocks
    /// completed a part whose MD4 still disagrees). Terminal: eMule's
    /// AICH_ERROR is likewise never re-trusted, because `UntrustedHashReceived`
    /// only accepts EMPTY/UNTRUSTED/TRUSTED (SHAHashSet.cpp:956-963) - without
    /// it, a poisoned root would be re-trusted and loop forever.
    Error,
}

/// Master-root trust + recovery bookkeeping for one download (the CPartFile
/// half of eMule's CAICHRecoveryHashSet coupling).
struct AichState {
    status: AichStatus,
    master: Option<[u8; 20]>,
    /// Votes: candidate root -> the /20-masked IPs signing it. eMule
    /// AddSigningIP masks the network-order dword with 0x00F0FFFF
    /// (SHAHashSet.cpp:523-532) = keep octet1, octet2, and the top nibble of
    /// octet3; one /20 signs at most ONE hash (:975-983).
    votes: HashMap<[u8; 20], HashSet<u32>>,
    /// Which root each source IP reported - a recovery ask goes only to a
    /// source whose reported root IS the trusted one (eMule PartFile.cpp:6089).
    reported: HashMap<IpAddr, [u8; 20]>,
    /// Parts whose MD4 failed, awaiting block recovery (eMule
    /// m_liRequestedData). One in-flight ask per part; a claim an abandoned
    /// connection left behind is re-askable after AICH_CLAIM_STALE_SECS -
    /// upstream has NO timeout at all (cleanup only on disconnect), a
    /// wire-neutral padMule improvement.
    pending: HashMap<u64, PendingRecovery>,
}

/// One part awaiting AICH block recovery.
struct PendingRecovery {
    /// The live claim: who asked, and when (epoch secs). `None` = unclaimed.
    /// The OWNER matters, not just the time: without it a stale-expired
    /// claim's late answer would apply on top of the new claimant's, and
    /// either connection's failure could release the other's claim.
    claim: Option<(IpAddr, u64)>,
    /// Who fed each of this part's blocks AT THE MOMENT the part was blamed.
    /// Block-level bans are drawn from THIS snapshot, never from the live
    /// map: once a part is re-gapped the sweep starts re-filling it, and a
    /// good source's fresh bytes would otherwise make it the "sole
    /// contributor" of a block whose stale on-disk bytes fail the recovery
    /// hash - banning exactly the source that was fixing the file.
    contributors: HashMap<u64, HashSet<IpAddr>>,
}

/// One connection's AICH recovery-ask state.
#[derive(Default)]
struct AichAsk {
    /// The part we have an ask in flight for on this connection.
    asked: Option<u64>,
    /// Parts this source already failed to serve here (never re-asked).
    refused: HashSet<u64>,
}

/// eMule MINUNIQUEIPS_TOTRUST (SHAHashSet.cpp:42).
const AICH_MIN_UNIQUE_IPS: usize = 10;
/// eMule MINPERCENTAGE_TOTRUST (SHAHashSet.cpp:43 - the macro says 92; the
/// nearby comment says 95 and is wrong).
const AICH_MIN_PERCENT: usize = 92;
/// A pending recovery ask older than this is considered abandoned.
const AICH_CLAIM_STALE_SECS: u64 = 60;

/// The /20 vote mask (see [`AichState::votes`]).
fn aich_vote_key(ip: IpAddr) -> u32 {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            u32::from_be_bytes([o[0], o[1], o[2] & 0xF0, 0])
        }
        // eMule is v4-only here; a v6 source folds to one bucket per /48-ish
        // prefix using the leading bytes (never reachable on today's wire).
        IpAddr::V6(v6) => {
            let o = v6.octets();
            u32::from_be_bytes([o[0], o[1], o[2], o[3]])
        }
    }
}

/// What we learned about one source we connected to, for the per-source UI.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub addr: SocketAddr,
    /// Client software display string (from the HELLO CT_EMULE_VERSION tag).
    pub software: String,
    /// Whether our connection to it was obfuscated (RC4).
    pub obfuscated: bool,
    /// Whether the peer reported a LowID (id < 0x0100_0000).
    pub low_id: bool,
    /// Whether we cryptographically verified its identity (secure-ident).
    pub verified: bool,
    /// Its rating for this file (0-5, from OP_FILEDESC); 0 = unrated.
    pub rating: u8,
    /// Its comment on this file (from OP_FILEDESC); empty if none.
    pub comment: String,
    /// Wall-clock second this source was last CONNECTED or last gave us bytes.
    /// The badge counts only recently-live sources: `note_source` upserts by
    /// address and nothing ever removed a record, so the count was every source
    /// EVER contacted for this download and only ever grew - which is why the
    /// Transfers badge read 99 while the Search tab said 12 for the same file.
    pub last_seen: u64,
    /// How we DISCOVERED this source - the eD2k server, Kad, or a source
    /// exchange with another peer. Already known at dial time
    /// (`fetch::PeerSource::origin`); it just was not carried this far, so the
    /// UI could show which discovery channel is actually feeding a download.
    pub origin: crate::fetch::SourceOrigin,
}

/// One file being pulled from many peers.
pub struct Download {
    inner: Mutex<Inner>,
    /// Metadata about each source we have connected to, keyed by address. A
    /// SEPARATE lock from `inner`, so recording a source never contends the
    /// hot transfer lock.
    sources: Mutex<Vec<SourceInfo>>,
    /// Set when the user cancels. The fetch workers check it and stop; a
    /// lock-free atomic so cancelling never has to wait on the transfer lock.
    cancelled: AtomicBool,
    /// The user's download priority (PR_LOW/PR_NORMAL/PR_HIGH). A lock-free
    /// atomic so the fetch manager can read it every round without touching the
    /// transfer lock; the canonical copy is persisted in the PartStore.
    priority: AtomicU8,
    /// Preview mode: when set, block selection is forward-SEQUENTIAL instead of
    /// rarest-first, so the file grows contiguously from offset 0 and the user can
    /// play its leading run while it is still downloading. Transient, not persisted.
    preview: AtomicBool,
    /// Claimed by whoever runs the one-shot finalize (verify -> move). Prevents the
    /// fetch-task tail and the 1s heartbeat finalize-sweep from both finalizing the
    /// same download. Reset if finalize fails so a re-fetched file can finalize again.
    finalizing: AtomicBool,
    /// True while a `download_file` task is live for this download. Prevents
    /// resume()/resume_fetches from stacking a SECOND concurrent fetch task on top
    /// of one that is still running (pause() does not abort the old task), which
    /// would multiply outbound peer connections every background/foreground cycle.
    fetching: AtomicBool,
    /// When the idle-retry sweep last PICKED this download, as engine-uptime
    /// seconds. Starvation guard: the sweep used to sort by priority and take
    /// `.first()`, and Rust's sort is STABLE, so with every download at the same
    /// (Normal) priority it returned the SAME one every single time and every
    /// other download was never retried at all. With dozens queued that is not
    /// "slow", it is "never".
    last_retry_at: AtomicU64,
    /// Wall-clock second at which this download last COMMITTED bytes. Drives the
    /// "actually receiving right now" indicator: a row can be registered, hold
    /// sources and still be moving nothing, and the screen could not tell those
    /// apart.
    last_byte_at: AtomicU64,
    /// Which source IP(s) contributed to each AICH BLOCK (keyed by the block's
    /// lattice start offset), recorded as data commits. On a part-hash failure
    /// the union over the part's blocks gives the old per-part view; after
    /// AICH recovery each BAD BLOCK's sole contributor is blamed individually -
    /// which is what defeats the "share every poisoned part with a good
    /// source" evasion 8ai documented. Values are IPs, NOT SocketAddrs: a
    /// LowID source reaches us on a fresh ephemeral port every callback, so a
    /// port-inclusive key would never match. A separate std lock: a quick
    /// insert on the hot commit path must never contend the async transfer lock.
    block_sources: StdMutex<HashMap<u64, HashSet<IpAddr>>>,
    /// AICH master-root trust + recovery bookkeeping (see [`AichState`]).
    aich: StdMutex<AichState>,
    /// Source IPs banned for THIS download after being caught delivering a corrupt
    /// part (eMule's CorruptionBlackBox, per-file). BOTH the outbound fetch sweep
    /// AND the inbound called-back-source path skip them.
    banned: StdMutex<HashSet<IpAddr>>,
    /// Sources peers handed us via source exchange (OP_ANSWERSOURCES), waiting
    /// for the fetch manager to drain and dial them. Collected off the async
    /// transfer lock, like the two sets above.
    sx_sources: StdMutex<Vec<SxSource>>,
    /// Peer IPs we have already asked for sources on this download. eMule
    /// rate-limits the same exchange per client (SOURCECLIENTREASKS = 40 min,
    /// x MINCOMMONPENALTY=4 for a non-rare file); a padMule download is a
    /// foreground, bounded affair, so asking each peer AT MOST ONCE per download
    /// is simpler and never more aggressive than upstream.
    asked_sources: StdMutex<HashSet<IpAddr>>,
}

struct Inner {
    store: PartStore,
    /// Blocks some peer has asked for and not yet delivered.
    reserved: Vec<(u64, u64)>,
    /// Per data-part swarm availability: how many peer sessions have reported
    /// holding each part. Drives rarest-first block selection.
    availability: Vec<u32>,
}

/// Once the file is within this many bytes of complete, a peer that finds all
/// remaining blocks reserved enters endgame and races them - so a slow/queuing
/// peer can't stall the last block. Kept small (a few blocks) so the redundant
/// re-requests only touch the tail of the download.
const ENDGAME_LIMIT: u64 = 4 * crate::transfer::EMBLOCKSIZE;

impl Download {
    pub fn new(store: PartStore) -> Arc<Self> {
        let parts = data_part_count(store.pf.size) as usize;
        let priority = AtomicU8::new(store.priority);
        Arc::new(Download {
            inner: Mutex::new(Inner {
                store,
                reserved: Vec::new(),
                availability: vec![0u32; parts],
            }),
            sources: Mutex::new(Vec::new()),
            cancelled: AtomicBool::new(false),
            priority,
            preview: AtomicBool::new(false),
            finalizing: AtomicBool::new(false),
            fetching: AtomicBool::new(false),
            last_retry_at: AtomicU64::new(0),
            last_byte_at: AtomicU64::new(0),
            block_sources: StdMutex::new(HashMap::new()),
            aich: StdMutex::new(AichState {
                status: AichStatus::Empty,
                master: None,
                votes: HashMap::new(),
                reported: HashMap::new(),
                pending: HashMap::new(),
            }),
            banned: StdMutex::new(HashSet::new()),
            sx_sources: StdMutex::new(Vec::new()),
            asked_sources: StdMutex::new(HashSet::new()),
        })
    }

    /// Record sources a peer handed us via source exchange. They are dialed only
    /// after the fetch manager drains them, so nothing here touches the network.
    pub fn note_sx_sources(&self, sources: Vec<SxSource>) {
        if sources.is_empty() {
            return;
        }
        self.sx_sources.lock().unwrap().extend(sources);
    }

    /// Take the source-exchange sources learned since the last call. Destructive:
    /// the fetch manager folds each into its dial queue exactly once.
    pub fn take_sx_sources(&self) -> Vec<SxSource> {
        std::mem::take(&mut *self.sx_sources.lock().unwrap())
    }

    /// Claim the right to ask `ip` for sources on this download. `true` only the
    /// FIRST time, so one peer is never asked twice (see `asked_sources`).
    pub fn mark_asked_sources(&self, ip: IpAddr) -> bool {
        self.asked_sources.lock().unwrap().insert(ip)
    }

    /// Claim the single in-flight fetch slot. The FIRST caller gets `true` and must
    /// clear it with `end_fetch` when its task ends; a caller that gets `false`
    /// must NOT spawn a duplicate fetch task (one is already running).
    pub fn try_begin_fetch(&self) -> bool {
        self.fetching
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Release the in-flight fetch slot (the fetch task has ended).
    pub fn end_fetch(&self) {
        self.fetching.store(false, Ordering::Release);
    }

    /// True while a fetch task is live for this download.
    /// True if bytes landed within the last `window_secs`. Deliberately a TIME
    /// window rather than an instantaneous rate: at a block boundary, or between
    /// blocks on a slow link, a rate legitimately reads zero, and an indicator
    /// that blinks off every few seconds is worse than none. Same reasoning as
    /// keep-awake watching a WINDOW of rate samples.
    pub fn is_receiving(&self, now_secs: u64, window_secs: u64) -> bool {
        let last = self.last_byte_at.load(Ordering::Relaxed);
        last != 0 && now_secs.saturating_sub(last) <= window_secs
    }

    /// When the retry sweep last picked this download (engine-uptime seconds).
    pub fn last_retry_at(&self) -> u64 {
        self.last_retry_at.load(Ordering::Relaxed)
    }

    /// Stamp it as picked, so the sweep moves on to someone else next time.
    pub fn mark_retried(&self, at_secs: u64) {
        self.last_retry_at.store(at_secs, Ordering::Relaxed);
    }

    pub fn is_fetching(&self) -> bool {
        self.fetching.load(Ordering::Acquire)
    }

    /// Claim the right to finalize this download exactly once (complete -> verify
    /// -> move). The FIRST caller gets `true`; concurrent callers get `false`, so
    /// the fetch tail and the heartbeat sweep never double-finalize the same file.
    pub fn try_begin_finalize(&self) -> bool {
        self.finalizing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Release the finalize claim (finalize failed - the file was re-gapped for a
    /// re-fetch), so it can be finalized again once it re-completes.
    pub fn reset_finalize(&self) {
        self.finalizing.store(false, Ordering::Release);
    }

    /// Record (or refresh) the base facts about a source we connected to:
    /// software, obfuscation, and LowID. Keyed by address; a reconnect updates
    /// those fields but preserves any rating/comment/verified already learned.
    pub async fn note_source(
        &self,
        software: String,
        addr: SocketAddr,
        obfuscated: bool,
        low_id: bool,
        origin: crate::fetch::SourceOrigin,
    ) {
        let mut g = self.sources.lock().await;
        if let Some(s) = g.iter_mut().find(|s| s.addr == addr) {
            s.software = software;
            s.obfuscated = obfuscated;
            s.low_id = low_id;
            s.origin = origin;
            s.last_seen = crate::credit_store::now_secs() as u64;
        } else {
            g.push(SourceInfo {
                addr,
                software,
                obfuscated,
                low_id,
                verified: false,
                rating: 0,
                comment: String::new(),
                last_seen: crate::credit_store::now_secs() as u64,
                origin,
            });
        }
    }

    /// How many CONNECTED sources came from each discovery channel, as
    /// `(server, kad, source-exchange)`. Feeds the per-transfer origin badge:
    /// "which channel is actually feeding this download" is invisible otherwise,
    /// and it is the question a user asks when one file flies and another crawls.
    /// How long a source stays counted in the badge after we last heard from it.
    /// A peer that dropped ten minutes ago is not "a source you have" in any
    /// sense a user means.
    pub const SOURCE_FRESH_SECS: u64 = 180;

    pub async fn source_origins(&self) -> (u32, u32, u32) {
        let now = crate::credit_store::now_secs() as u64;
        let g = self.sources.lock().await;
        let mut counts = (0u32, 0u32, 0u32);
        for s in g.iter() {
            // Only sources still in play. Counting every address ever contacted
            // made the badge grow without bound over a session.
            if now.saturating_sub(s.last_seen) > Self::SOURCE_FRESH_SECS {
                continue;
            }
            match s.origin {
                crate::fetch::SourceOrigin::Server => counts.0 += 1,
                crate::fetch::SourceOrigin::Kad => counts.1 += 1,
                crate::fetch::SourceOrigin::PeerExchange => counts.2 += 1,
            }
        }
        counts
    }

    /// Attach a source's rating + comment (from OP_FILEDESC). No-op if we have no
    /// record of that address yet (the base note comes first on connect).
    pub async fn note_source_comment(&self, addr: SocketAddr, rating: u8, comment: String) {
        let mut g = self.sources.lock().await;
        if let Some(s) = g.iter_mut().find(|s| s.addr == addr) {
            s.rating = rating.min(5);
            s.comment = comment;
        }
    }

    /// Mark a source as identity-verified (secure-ident succeeded).
    pub async fn note_source_verified(&self, addr: SocketAddr) {
        let mut g = self.sources.lock().await;
        if let Some(s) = g.iter_mut().find(|s| s.addr == addr) {
            s.verified = true;
        }
    }

    /// Snapshot of every source we have connected to (for the per-source UI).
    pub async fn sources(&self) -> Vec<SourceInfo> {
        self.sources.lock().await.clone()
    }

    /// A download-row summary of what sources said: the average rating over rated
    /// sources (0 = none rated), and whether any source left a comment.
    pub async fn rating_summary(&self) -> (u8, bool) {
        let g = self.sources.lock().await;
        let (sum, count) = g
            .iter()
            .filter(|s| s.rating > 0)
            .fold((0u32, 0u32), |acc, s| (acc.0 + s.rating as u32, acc.1 + 1));
        let avg = sum.checked_div(count).unwrap_or(0) as u8;
        let has_comment = g.iter().any(|s| !s.comment.is_empty());
        (avg, has_comment)
    }

    /// Mark this download cancelled. The fetch workers notice within a block and
    /// stop; the engine then removes it and deletes the `.part`.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// The current download priority (PR_LOW/PR_NORMAL/PR_HIGH). Read lock-free
    /// by the fetch manager every round, so a live change biases the ongoing
    /// sweep, not just the next spawn.
    pub fn priority(&self) -> u8 {
        self.priority.load(Ordering::Relaxed)
    }

    /// Set the download priority and persist it to part.met so it survives a
    /// restart. Best-effort persistence: a failed met write leaves the live
    /// atomic updated (the sweep still honors it this session).
    pub async fn set_priority(&self, priority: u8) {
        self.priority.store(priority, Ordering::Relaxed);
        let mut g = self.inner.lock().await;
        g.store.priority = priority;
        let _ = g.store.save_met();
    }

    /// Re-open the ENTIRE file for download and persist - the last resort when the
    /// whole-file hash fails but no individual part could be blamed (e.g. a spoofed
    /// hashset). Forces a full re-download instead of stranding a corrupt file.
    pub async fn reset_all_gaps(&self) {
        let mut g = self.inner.lock().await;
        g.store.pf.reset_all_gaps();
        let _ = g.store.save_met();
    }

    /// Flush this download's on-disk `.part.met` (its gap list + priority). The hot
    /// receive path (`commit`) only fills the IN-MEMORY gap list, so without a flush
    /// on the durability boundary a suspend-kill loses ALL session progress and
    /// re-downloads from scratch. Called from `pause()`/`shutdown()`.
    pub async fn persist(&self) {
        let mut g = self.inner.lock().await;
        let _ = g.store.save_met();
    }

    /// Whether preview mode is on (first+last-then-sequential block bias).
    pub fn is_preview(&self) -> bool {
        self.preview.load(Ordering::Relaxed)
    }

    /// Turn preview mode on/off. Read lock-free by the fetch manager every round,
    /// so it re-biases the ongoing sweep, not just the next spawn. Not persisted -
    /// it is a transient viewing intent.
    pub fn set_preview(&self, on: bool) {
        self.preview.store(on, Ordering::Relaxed);
    }

    /// Bytes available CONTIGUOUSLY from offset 0 - the leading prefix a player
    /// can read from the raw `.part` (see `PartFile::contiguous_prefix`).
    pub async fn contiguous_prefix(&self) -> u64 {
        self.inner.lock().await.store.pf.contiguous_prefix()
    }

    /// The `(part_path, contiguous_prefix)` a preview snapshot needs, or None when
    /// nothing contiguous is available yet. Holds the lock ONLY to read the path +
    /// length; the caller then copies `[0, prefix)` from its own read handle
    /// (outside the lock), so copying a large prefix never stalls the download.
    pub async fn preview_target(&self) -> Option<(std::path::PathBuf, u64)> {
        let g = self.inner.lock().await;
        let len = g.store.pf.contiguous_prefix();
        if len == 0 {
            return None;
        }
        Some((g.store.part_path().to_path_buf(), len))
    }

    /// Delete the backing `.part` and `.part.met`. Best effort: an open file
    /// handle a worker still holds keeps the bytes readable until it drops, but
    /// the files are gone from disk at once so a restart will not resume them.
    pub async fn discard_files(&self) {
        self.inner.lock().await.store.remove_backing_files();
    }

    /// Fold a peer's file-status bitfield into the swarm-availability counts, so
    /// later block selection knows which parts are rare.
    pub async fn note_status(&self, status: &FileStatus) {
        let mut g = self.inner.lock().await;
        for p in 0..g.availability.len() {
            if status.has_part(p) {
                g.availability[p] += 1;
            }
        }
    }

    /// Parts we still need that NO source has ever been seen holding.
    ///
    /// Answers the one question a stalled near-complete download cannot answer
    /// from the screen: is padMule failing to ASK for the tail, or does the
    /// swarm simply not HAVE it? Those are opposite bugs with opposite fixes,
    /// and "90% done, 86 sources, zero bytes" looks identical either way.
    ///
    /// `availability` is CUMULATIVE - `note_status` only ever increments, and
    /// nothing decrements when a peer goes away. That is a feature here: a zero
    /// means no source we have EVER talked to reported holding that part, which
    /// is the conservative reading. A part held by a peer that has since gone is
    /// NOT counted as missing, so this never overstates the problem.
    ///
    /// Returns `(still needed, of those unavailable)`.
    pub async fn part_availability(&self) -> (u64, u64) {
        let g = self.inner.lock().await;
        let wanted = g.store.pf.wanted_parts();
        let missing = wanted
            .iter()
            .filter(|&&p| g.availability.get(p as usize).copied().unwrap_or(0) == 0)
            .count();
        (wanted.len() as u64, missing as u64)
    }

    /// Does this peer hold ANY part we still have bytes missing in?
    ///
    /// Deliberately ignores reservations: a part another worker is fetching
    /// right now is still a part this peer could serve later, so it makes the
    /// peer worth a slot. Only a peer that can never help us answers false.
    pub async fn has_needed_part(&self, status: &FileStatus) -> bool {
        let g = self.inner.lock().await;
        g.store
            .pf
            .wanted_parts()
            .into_iter()
            .any(|p| status.has_part(p as usize))
    }

    pub async fn hash(&self) -> [u8; 16] {
        self.inner.lock().await.store.pf.hash
    }

    pub async fn size(&self) -> u64 {
        self.inner.lock().await.store.pf.size
    }

    /// The download's advertised filename (lossy UTF-8).
    pub async fn name(&self) -> String {
        String::from_utf8_lossy(&self.inner.lock().await.store.name).into_owned()
    }

    pub async fn is_complete(&self) -> bool {
        self.inner.lock().await.store.is_complete()
    }

    pub async fn missing(&self) -> u64 {
        self.inner.lock().await.store.pf.missing()
    }

    /// True if we still need the part-hash list before anything can be verified.
    ///
    /// This MUST match `PartFile::verify_part`'s "use the part hash" condition
    /// (`data_part_count > 1 || size == PARTSIZE`). An exactly-PARTSIZE file has a
    /// single data part but a two-entry hashset, so it verifies against the PART
    /// hash - if we gated only on `> 1` we would never fetch the hashset, and the
    /// file would be moved into place UNVERIFIED, defeating the very divergence
    /// that exists to catch a corrupt PARTSIZE file.
    pub async fn needs_hashset(&self) -> bool {
        let g = self.inner.lock().await;
        let size = g.store.pf.size;
        (data_part_count(size) > 1 || size == PARTSIZE) && g.store.pf.part_hashes.is_empty()
    }

    pub async fn set_hashset(&self, hashes: Vec<[u8; 16]>) {
        let mut g = self.inner.lock().await;
        g.store.pf.part_hashes = hashes;
    }

    /// The per-part MD4s, if a hashset was fetched (empty for a single-part
    /// file). Captured when a finished download becomes a shared source, so we
    /// can answer OP_HASHSETREQUEST without re-reading the file.
    pub async fn part_hashes(&self) -> Vec<[u8; 16]> {
        self.inner.lock().await.store.pf.part_hashes.clone()
    }

    /// Claim up to `max` blocks this peer can actually serve, rarest-first. If
    /// nothing fresh is left but the file is nearly done, enter endgame and race
    /// the final reserved blocks.
    async fn take_blocks(&self, status: &FileStatus, max: usize) -> Vec<(u64, u64)> {
        // Cancelled: hand out nothing, so the peer session ends and the worker
        // loop falls through to its cancellation check.
        if self.is_cancelled() {
            return Vec::new();
        }
        let preview = self.preview.load(Ordering::Relaxed);
        let mut g = self.inner.lock().await;
        let reserved = g.reserved.clone();
        let avail = g.availability.clone();
        let missing = g.store.pf.missing();
        let rarity = |p: u64| avail.get(p as usize).copied().unwrap_or(0);
        let has = |p: u64| status.has_part(p as usize);

        let mut blocks = g
            .store
            .pf
            .next_blocks(&has, &reserved, max, &rarity, false, preview);
        if blocks.is_empty() && missing > 0 && missing <= ENDGAME_LIMIT {
            blocks = g
                .store
                .pf
                .next_blocks(&has, &reserved, max, &rarity, true, preview);
        }
        g.reserved.extend_from_slice(&blocks);
        blocks
    }

    /// Give blocks back to the pool so another peer can fetch them.
    async fn release(&self, blocks: &[(u64, u64)]) {
        if blocks.is_empty() {
            return;
        }
        let mut g = self.inner.lock().await;
        g.reserved.retain(|b| !blocks.contains(b));
    }

    /// Write received bytes through to disk and close their gap.
    /// Crate-visible so the share-side end-to-end tests can stage a download.
    pub(crate) async fn commit(
        &self,
        start: u64,
        data: &[u8],
        source: Option<SocketAddr>,
    ) -> io::Result<()> {
        // Bytes really arrived. This is what the activity indicator reads - a
        // row can be registered, hold sources and still be moving nothing, and
        // until now the screen could not tell those apart.
        let now = u64::from(crate::credit_store::now_secs());
        self.last_byte_at.store(now, Ordering::Relaxed);
        // Keep the DELIVERING source fresh, or a transfer running longer than
        // SOURCE_FRESH_SECS from one peer would age out of the badge while that
        // peer is visibly still sending. Cheap: the list is tens of entries and
        // the critical section is a find-and-store.
        if let Some(addr) = source {
            let mut g = self.sources.lock().await;
            if let Some(si) = g.iter_mut().find(|s| s.addr == addr) {
                si.last_seen = now;
            }
        }
        // Remember which source fed each AICH block this write touches, so a
        // later failure can be attributed - per part without AICH
        // (localize_corruption), per BLOCK with it (apply_aich_recovery).
        if let Some(addr) = source {
            let end = start.saturating_add(data.len() as u64);
            let mut bs = self.block_sources.lock().unwrap();
            let mut pos = start;
            while pos < end {
                let part_start = pos - pos % PARTSIZE;
                let key = part_start + ((pos - part_start) / EMBLOCKSIZE) * EMBLOCKSIZE;
                bs.entry(key).or_default().insert(addr.ip());
                // next lattice boundary: the block's end, capped at the part's
                pos = (key + EMBLOCKSIZE).min(part_start + PARTSIZE);
            }
        }
        let mut g = self.inner.lock().await;
        g.store.write_block(start, data)
    }

    /// True if `addr`'s IP was banned for this download (caught delivering
    /// corruption). Compared by IP, so it catches a LowID source dialing back from
    /// a new ephemeral port. Both serve paths (sweep + callback) consult this.
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        self.banned.lock().unwrap().contains(&addr.ip())
    }

    /// Banned source IPs so far, for tests/telemetry.
    pub fn banned_sources(&self) -> Vec<IpAddr> {
        self.banned.lock().unwrap().iter().copied().collect()
    }

    /// Verify every part whose bytes have all arrived. A part that fails is
    /// re-opened for download; the caller keeps going until nothing is missing.
    pub async fn verify_ready_parts(&self) -> io::Result<()> {
        let mut g = self.inner.lock().await;
        let n = data_part_count(g.store.pf.size);
        for part in 0..n {
            // Verify any part whose bytes have all arrived (this re-checks a
            // previously-corrupted part too, now that its bytes are back).
            if g.store.pf.is_part_complete(part) {
                g.store.verify_part(part)?;
            }
        }
        g.store.save_met()?;
        Ok(())
    }

    /// After a whole-file hash failure, blame the individual corrupt part(s)
    /// against the peer hashset and re-open ONLY those, so one bad source does not
    /// force re-downloading the whole file (eMule verifies each part as it
    /// completes; padMule does it here, still per-part). Returns true if it
    /// localized the damage (re-opened >=1 blamed part); false if it cannot - no
    /// hashset yet, or every part hashes fine so the hashset itself is suspect -
    /// in which case the caller falls back to re-opening the whole file.
    ///
    /// Off the download lock, mirroring [`verify_whole_file`]: snapshot under a
    /// brief lock, hash each complete part in `spawn_blocking`, then re-gap the
    /// bad ones under a brief lock - so a large file never stalls the heartbeat.
    pub async fn localize_corruption(&self) -> bool {
        let (path, size, part_hashes, complete) = {
            let g = self.inner.lock().await;
            let pf = &g.store.pf;
            if pf.part_hashes.is_empty() {
                return false; // no hashset -> cannot blame a single part
            }
            let n = data_part_count(pf.size);
            let complete: Vec<u64> = (0..n).filter(|&p| pf.is_part_complete(p)).collect();
            (
                g.store.part_path().to_path_buf(),
                pf.size,
                pf.part_hashes.clone(),
                complete,
            )
        };
        let bad = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = std::fs::File::open(&path)?;
            let mut bad = Vec::new();
            for p in complete {
                let Some(&expected) = part_hashes.get(p as usize) else {
                    continue;
                };
                let len = crate::part_file::part_size(p, size) as usize;
                let mut buf = vec![0u8; len];
                f.seek(SeekFrom::Start(p * PARTSIZE))?;
                f.read_exact(&mut buf)?;
                if mule_proto::md4(&buf) != expected {
                    bad.push(p);
                }
            }
            io::Result::Ok(bad)
        })
        .await;
        let bad = match bad {
            Ok(Ok(b)) if !b.is_empty() => b,
            // Read error, or no part could be blamed (spoofed hashset) -> let the
            // caller re-open the whole file.
            _ => return false,
        };
        let mut g = self.inner.lock().await;
        for p in &bad {
            g.store.pf.mark_corrupt(*p);
        }
        let _ = g.store.save_met();
        drop(g);
        // Attribute each bad part to its SOLE contributor and BAN it (eMule's
        // CorruptionBlackBox, per-file). Only a sole contributor is unambiguous -
        // a part fed by several sources is NOT blamed AT THIS GRANULARITY (AICH
        // recovery below narrows the blame to individual blocks), so a good
        // source is never false-banned. Clear each bad part's contributor
        // entries: its bytes were just re-gapped, so a re-fetch re-attributes.
        // ...and queue each bad part for AICH block recovery, CAPTURING its
        // contributor map first: once the part is re-gapped the sweep starts
        // re-filling it, so only this snapshot can tell who fed the bytes that
        // actually failed (eMule fires RequestAICHRecovery at this same
        // moment, PartFile.cpp:4851-4853). Harmless if no root is ever
        // trusted - the entry simply never gets claimed.
        {
            let mut bs = self.block_sources.lock().unwrap();
            let mut banned = self.banned.lock().unwrap();
            let mut a = self.aich.lock().unwrap();
            for p in &bad {
                let (ps, pe) = (p * PARTSIZE, (p + 1) * PARTSIZE);
                let keys: Vec<u64> = bs
                    .keys()
                    .filter(|k| (ps..pe).contains(k))
                    .copied()
                    .collect();
                // Snapshot, then clear: the live map is re-attributed by the
                // re-fetch, this copy is frozen evidence for the recovery pass.
                let contributors: HashMap<u64, HashSet<IpAddr>> = keys
                    .iter()
                    .filter_map(|k| bs.remove(k).map(|v| (*k, v)))
                    .collect();
                let union: HashSet<IpAddr> = contributors.values().flatten().copied().collect();
                if union.len() == 1 {
                    banned.extend(union);
                }
                // A part can fail MD4 AGAIN before its recovery ever runs (a
                // root only becomes trusted once 10 unique /20s agree, so the
                // early rounds have none). The blocks just re-fetched are the
                // ones that failed this time, so their contributors REPLACE
                // the previous round's; blocks nobody re-sent keep the
                // evidence we already had. An `or_insert` here dropped the
                // fresh map wholesale and left the stale one to be blamed -
                // which would ban the EARLIER source for bytes it never sent,
                // the one thing the sole-contributor rule exists to prevent.
                match a.pending.entry(*p) {
                    std::collections::hash_map::Entry::Occupied(mut o) => {
                        o.get_mut().contributors.extend(contributors);
                    }
                    std::collections::hash_map::Entry::Vacant(v) => {
                        v.insert(PendingRecovery {
                            claim: None,
                            contributors,
                        });
                    }
                }
            }
        }
        true
    }

    /// Set the AICH master root from the file's IDENTITY (an ed2k link that
    /// carried an aich part) - VERIFIED, never displaced by votes (eMule
    /// PartFile.cpp:197-201).
    pub fn set_aich_master_verified(&self, root: [u8; 20]) {
        let mut a = self.aich.lock().unwrap();
        a.master = Some(root);
        a.status = AichStatus::Verified;
    }

    /// The trusted/verified master root, if recovery is allowed to use one.
    pub fn aich_trusted_root(&self) -> Option<[u8; 20]> {
        let a = self.aich.lock().unwrap();
        matches!(a.status, AichStatus::Trusted | AichStatus::Verified)
            .then_some(a.master)
            .flatten()
    }

    /// A source reported its AICH root: record it against the source and vote
    /// (eMule UntrustedHashReceived, SHAHashSet.cpp:955-1031): one /20 signs
    /// one hash; at least MINUNIQUEIPS_TOTRUST distinct /20s AND at least
    /// MINPERCENTAGE_TOTRUST agreement promote the winner to TRUSTED, else
    /// it stays the UNTRUSTED front-runner. A VERIFIED root ignores votes.
    pub fn note_aich_root(&self, ip: IpAddr, root: [u8; 20]) {
        let mut a = self.aich.lock().unwrap();
        a.reported.insert(ip, root);
        // VERIFIED is authoritative and ERROR is terminal: neither takes votes
        // (eMule accepts a vote only in EMPTY/UNTRUSTED/TRUSTED,
        // SHAHashSet.cpp:956-963).
        if matches!(a.status, AichStatus::Verified | AichStatus::Error) {
            return;
        }
        let key = aich_vote_key(ip);
        // One /20 may sign only ONE hash (:975-983).
        //
        // DELIBERATE DEVIATION, in the safe direction: eMule runs this
        // cross-hash sweep only when the received hash is NEW (`!bFound`,
        // SHAHashSet.cpp:964-989), so a /20 that already signed root A still
        // counts toward an already-KNOWN root B, and upstream can cross the
        // threshold on votes padMule discards. We apply the rule uniformly.
        // The cost is that trust is reached slightly later (a delayed 0x9B -
        // no wire difference); the gain is that the one trust path the app
        // has is harder to stuff. That matters because a VERIFIED root -
        // eMule's primary defence, where a link-carried root ignores votes
        // outright (PartFile.cpp:197-201) - is reachable today only through
        // `mule-cli link`: the engine has no link-ingestion path, and search
        // hits carry no AICH hash, so there is nothing to plumb a root FROM
        // yet. When link ingestion lands, wire it to
        // `set_aich_master_verified` and this deviation can be revisited.
        if a.votes
            .iter()
            .any(|(r, ips)| *r != root && ips.contains(&key))
        {
            return;
        }
        a.votes.entry(root).or_default().insert(key);
        let total: usize = a.votes.values().map(|s| s.len()).sum();
        let (best, most) = a
            .votes
            .iter()
            .max_by_key(|(_, s)| s.len())
            .map(|(r, s)| (*r, s.len()))
            .expect("just inserted");
        if most >= AICH_MIN_UNIQUE_IPS && 100 * most / total >= AICH_MIN_PERCENT {
            a.master = Some(best);
            a.status = AichStatus::Trusted;
        } else {
            a.master = Some(best);
            a.status = AichStatus::Untrusted;
        }
    }

    /// Claim one pending recovery ask for a source at `ip` (eMule
    /// RequestAICHRecovery's eligibility, PartFile.cpp:6064-6090): a
    /// trusted/verified root, the source having REPORTED exactly that root,
    /// the part bigger than one block, and no live ask for the part. Returns
    /// the (part, root) to put on the wire; the claim self-expires if the
    /// answer never comes.
    pub fn claim_aich_recovery(&self, ip: IpAddr, size: u64) -> Option<(u64, [u8; 20])> {
        let mut a = self.aich.lock().unwrap();
        let root = matches!(a.status, AichStatus::Trusted | AichStatus::Verified)
            .then_some(a.master)
            .flatten()?;
        if a.reported.get(&ip) != Some(&root) || size <= EMBLOCKSIZE {
            return None;
        }
        let now = u64::from(now_secs());
        let part = a
            .pending
            .iter()
            .find(|(p, pend)| {
                // A part index that does not fit the wire field could never be
                // asked for correctly (the u16 would silently name a DIFFERENT
                // part), so it is not claimable at all. Only reachable past
                // eMule's own file-size ceiling.
                **p <= u64::from(u16::MAX)
                    && crate::part_file::part_size(**p, size) > EMBLOCKSIZE
                    && match pend.claim {
                        None => true,
                        Some((_, t)) => now.saturating_sub(t) > AICH_CLAIM_STALE_SECS,
                    }
            })
            .map(|(p, _)| *p)?;
        a.pending.get_mut(&part)?.claim = Some((ip, now));
        Some((part, root))
    }

    /// A recovery ask failed (refusal, bad data, or a source that answered
    /// wrongly): release the claim so ANOTHER source can be asked (eMule
    /// ClientAICHRequestFailed retries elsewhere, SHAHashSet.cpp:1033-1043).
    /// Only the CLAIM OWNER may release it - a late answer from a connection
    /// whose stale claim has already been handed on must not free the new
    /// asker's claim out from under it.
    pub fn aich_recovery_failed(&self, part: u64, ip: IpAddr) {
        let mut a = self.aich.lock().unwrap();
        if let Some(p) = a.pending.get_mut(&part) {
            if p.claim.map(|(owner, _)| owner) == Some(ip) {
                p.claim = None;
            }
        }
    }

    /// True if `ip` currently owns the recovery claim on `part` (the gate the
    /// apply path uses, so a superseded claimant's late answer is dropped).
    fn owns_aich_claim(&self, part: u64, ip: IpAddr) -> bool {
        self.aich
            .lock()
            .unwrap()
            .pending
            .get(&part)
            .and_then(|p| p.claim)
            .map(|(owner, _)| owner)
            == Some(ip)
    }

    /// Apply VERIFIED recovery data for one part (eMule
    /// AICHRecoveryDataAvailable, PartFile.cpp:6136-6247): hash the part's
    /// bytes on disk per ~180KB block against the verified leaves, FILL back
    /// the blocks that match (their bytes were fine all along), keep or
    /// re-open the mismatching ones, and blame each bad block's SOLE
    /// contributor - the per-BLOCK attribution that closes 8ai's honest
    /// limitation. Returns (verified_blocks, bad_blocks).
    pub async fn apply_aich_recovery(
        &self,
        part: u64,
        verified: &[(u64, u64, [u8; 20])],
    ) -> io::Result<(usize, usize)> {
        let spans: Vec<(u64, u64, [u8; 20])> = verified.to_vec();
        let mut good = 0usize;
        let mut bad = 0usize;
        // Hash AND apply under ONE hold of the transfer lock, so no `commit`
        // can land between reading a block and judging it. aMule added exactly
        // this lock for exactly this reason (PartFile.cpp:3920-3931, issue
        // #586: "the AICH-recovery read can interleave with a concurrent
        // Seek+Write ... the recovery hash is computed over the wrong bytes").
        // Bounded work, unlike the whole-file verify this deliberately does NOT
        // copy: one part is at most PARTSIZE (9.28 MB) to read and SHA-1.
        let (results, part_now_complete) = {
            let mut g = self.inner.lock().await;
            let path = g.store.part_path().to_path_buf();
            let results = tokio::task::spawn_blocking(move || {
                use sha1::{Digest, Sha1};
                use std::io::{Read, Seek, SeekFrom};
                let mut f = std::fs::File::open(&path)?;
                let mut out: Vec<(u64, u64, bool)> = Vec::with_capacity(spans.len());
                for (start, len, want) in spans {
                    let mut buf = vec![0u8; len as usize];
                    f.seek(SeekFrom::Start(start))?;
                    f.read_exact(&mut buf)?;
                    let got: [u8; 20] = {
                        let mut h = Sha1::new();
                        h.update(&buf);
                        h.finalize().into()
                    };
                    out.push((start, len, got == want));
                }
                io::Result::Ok(out)
            })
            .await
            .map_err(io::Error::other)??;
            for (start, len, ok) in &results {
                if *ok {
                    g.store.pf.fill_gap(*start, start + len);
                    good += 1;
                } else {
                    // Still wrong: keep it open. Re-opening is safe - the hash
                    // it failed is anchored to the TRUSTED root.
                    g.store.pf.reopen_range(*start, start + len);
                    bad += 1;
                }
            }
            let _ = g.store.save_met();
            let complete = g.store.pf.is_part_complete(part);
            (results, complete)
        };
        // Per-BLOCK blame, from the contributor snapshot frozen when the part
        // was blamed - NEVER the live map, which the re-fetch has been writing
        // into since. And skip any block the re-fetch has ALREADY touched: its
        // bytes are no longer the ones the snapshot's source delivered, so a
        // mismatch says nothing about that source.
        let snapshot = {
            let a = self.aich.lock().unwrap();
            a.pending
                .get(&part)
                .map(|p| p.contributors.clone())
                .unwrap_or_default()
        };
        {
            let bs = self.block_sources.lock().unwrap();
            let mut banned = self.banned.lock().unwrap();
            for (start, _len, ok) in &results {
                if *ok || bs.contains_key(start) {
                    continue;
                }
                if let Some(srcs) = snapshot.get(start) {
                    if srcs.len() == 1 {
                        banned.extend(srcs.iter().copied());
                    }
                }
            }
        }
        // If recovery COMPLETED the part, its MD4 must now agree - otherwise
        // the "verified" leaves were anchored to a root that is not this
        // file's, and trusting it further would loop forever (fill -> whole-
        // file MD4 fails -> blame -> fill ...). eMule/aMule take the same
        // belt-and-braces step and mark the hashset AICH_ERROR on mismatch
        // (PartFile.cpp:3969-3980 / :6210-6221); Error is terminal, so a root
        // proven wrong for this file can never be re-trusted.
        if part_now_complete {
            let mut g = self.inner.lock().await;
            // verify_part re-gaps the part itself on a mismatch (mark_corrupt),
            // so a failure here leaves the file in the same honest state a
            // plain MD4 failure would. `None` = no part hash to check against,
            // which is not a verdict.
            // NAME THE VERDICT IT HOLDS: `Ok(Some(false))` is verify_part
            // saying the part does NOT match. This read as `agrees` before,
            // which is the exact inversion a later reader "corrects" into a
            // real bug.
            let disagrees = matches!(g.store.verify_part(part), Ok(Some(false)));
            let _ = g.store.save_met();
            drop(g);
            if disagrees {
                let mut a = self.aich.lock().unwrap();
                a.status = AichStatus::Error;
                a.master = None;
                a.pending.clear();
                return Ok((0, results.len()));
            }
        }
        // The part's recovery is DONE (good blocks filled, bad ones open for a
        // clean re-fetch); a future MD4 failure re-queues it.
        self.aich.lock().unwrap().pending.remove(&part);
        Ok((good, bad))
    }

    /// Recompute the whole-file ed2k hash from the bytes actually on disk and
    /// compare it to `want`.
    ///
    /// This is the end-to-end proof that what we assembled IS what was asked
    /// for, and for many files it is the ONLY one: `verify_part` needs the
    /// peer's hashset, and a file of a single part has no part hashes at all.
    /// Hashed part-by-part, so a large file is never held in memory.
    pub async fn verify_whole_file(&self, size: u64, want: [u8; 16]) -> bool {
        // Snapshot the backing path under a BRIEF lock, then rehash off the lock
        // AND off the async reactor via spawn_blocking: a multi-GB MD4 is slow and
        // CPU-bound. Holding the download lock across it would stall the 1s
        // downloads() heartbeat - which runs under the shared engine lock - and so
        // pause()/every FFI call. Mirrors the preview snapshot's off-lock read.
        let path = {
            let g = self.inner.lock().await;
            g.store.part_path().to_path_buf()
        };
        let got = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = std::fs::File::open(&path)?;
            mule_proto::ed2k_hash_parts(size, |p| {
                let mut buf = vec![0u8; crate::part_file::part_size(p, size) as usize];
                f.seek(SeekFrom::Start(p * mule_proto::PARTSIZE))?;
                f.read_exact(&mut buf)?;
                io::Result::Ok(buf)
            })
        })
        .await;
        matches!(got, Ok(Ok(g)) if g == want)
    }

    /// Like [`Self::verify_whole_file`], but ALSO builds the file's AICH tree
    /// in the SAME streaming pass - eMule computes MD4 and AICH in one disk
    /// pass too (KnownFile.cpp:1053-1137), and a finished file is about to be
    /// shared, so this is where its recovery hashset comes from for free.
    /// Returns `(md4_ok, Some((master_root, leaf_hashes)))`; the AICH half is
    /// best-effort and never affects the verification verdict, and is `None`
    /// whenever the MD4 failed (the bytes are wrong - hashing them again after
    /// repair produces the real hashset).
    pub async fn verify_whole_file_and_aich(
        &self,
        size: u64,
        want: [u8; 16],
    ) -> (bool, Option<([u8; 20], Vec<[u8; 20]>)>) {
        let path = {
            let g = self.inner.lock().await;
            g.store.part_path().to_path_buf()
        };
        let got = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = std::fs::File::open(&path)?;
            let mut aich = mule_proto::AichLeafHasher::new(size);
            let md4 = mule_proto::ed2k_hash_parts(size, |p| {
                let mut buf = vec![0u8; crate::part_file::part_size(p, size) as usize];
                f.seek(SeekFrom::Start(p * mule_proto::PARTSIZE))?;
                f.read_exact(&mut buf)?;
                // Parts arrive in order, so the leaf hasher sees the file
                // sequentially; a feed error just yields no tree at finish().
                if let Some(h) = aich.as_mut() {
                    h.update(&buf);
                }
                io::Result::Ok(buf)
            })?;
            let set = aich
                .and_then(|h| h.finish())
                .and_then(|t| Some((t.master_hash()?, t.leaves()?)));
            io::Result::Ok((md4, set))
        })
        .await;
        match got {
            Ok(Ok((md4, set))) if md4 == want => (true, set),
            _ => (false, None),
        }
    }

    /// Take the finished store back out (to move the file into place).
    pub async fn into_store(self: Arc<Self>) -> Option<PartStore> {
        Arc::try_unwrap(self)
            .ok()
            .map(|d| d.inner.into_inner().store)
    }

    /// Move the finished file into `dest` through the lock, WITHOUT needing sole
    /// ownership of the Arc. Unlike `into_store`, this never fails just because a
    /// concurrent holder (the 1s downloads() poll, cancel, set_download_priority)
    /// happens to hold an Arc clone at the same instant - which would otherwise
    /// leave a byte-complete `.part` stranded.
    pub async fn finish_to(&self, dest: &std::path::Path) -> std::io::Result<()> {
        let mut g = self.inner.lock().await;
        // Atomic with the move: if the user cancelled while we were finalizing, do
        // NOT move the file into place. cancel_download sets `cancelled` before it
        // takes this same inner lock to delete the files, so checking it here (under
        // the lock, no await before the move) makes cancel and finalize mutually
        // exclusive - the file is either moved or deleted, never both. Relaxed is
        // enough: the `inner` mutex provides the happens-before (every other use of
        // this flag is Relaxed too - do not read ordering semantics into it).
        if self.cancelled.load(Ordering::Relaxed) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Interrupted,
                "cancelled during finalize",
            ));
        }
        g.store.finish_in_place(dest)
    }
}

/// Resume every in-progress download in `dir` by opening each `NNN.part` from
/// its `.part.met`, ordered by index. Unreadable/corrupt part files are skipped.
/// This is the engine's on-start resume: the `.part` persists progress across
/// launches, so a download picks up exactly where it left off.
pub fn resume_downloads(dir: &std::path::Path) -> Vec<Arc<Download>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut indices: Vec<u32> = entries
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix(".part.met")
                .and_then(|stem| stem.parse::<u32>().ok())
        })
        .collect();
    indices.sort_unstable();
    indices
        .into_iter()
        .filter_map(|i| PartStore::open(dir, i).ok().map(Download::new))
        .collect()
}

/// Pull whatever we can from one peer, until it has nothing left to give.
///
/// Returns when the file is complete, when this peer holds no block we still
/// need, or on error. Reservations are released on every one of those paths.
/// Returns the number of bytes this session delivered (for peer scoring).
///
/// `bail_on_queue`: what to do when the peer answers OP_STARTUPLOADREQ with a
/// queue ranking instead of an accept. `true` (a multi-source hunt with other
/// sources to try) returns `TransferError::Queued` immediately so the caller
/// moves on; `false` (a single dedicated source, e.g. a direct peer download or a
/// called-back peer) waits in the queue for the slot, like a normal client.
pub async fn download_from_peer<S>(
    fs: &mut FramedStream<S>,
    dl: &Download,
    bail_on_queue: bool,
) -> Result<u64, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    download_from_peer_at(fs, dl, bail_on_queue, None, PeerSession::default()).await
}

/// As [`download_from_peer`], but `peer` names the source address (so a rating +
/// comment it sends via OP_FILEDESC, and an identity verification, can be recorded
/// against it) and `sec` carries the secure-ident context (our RSA identity +
/// whether the peer advertised support), enabling mutual secure-identification
/// inline with the transfer. `sec = None` disables it (plain download).
pub async fn download_from_peer_at<S>(
    fs: &mut FramedStream<S>,
    dl: &Download,
    bail_on_queue: bool,
    peer: Option<SocketAddr>,
    session: PeerSession,
) -> Result<u64, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut held: Vec<(u64, u64)> = Vec::new();
    let r = run_peer(fs, dl, &mut held, bail_on_queue, peer, session).await;
    // Whatever happened, do not strand blocks nobody else will be offered.
    dl.release(&held).await;
    r
}

/// If `pkt` is a source's OP_FILEDESC, record its rating + comment against
/// `peer` (when known). Unsolicited and one-shot; safe to call from any loop.
async fn note_comment_if_desc(pkt: &Packet, dl: &Download, peer: Option<SocketAddr>) {
    if pkt.opcode == OP_FILEDESC {
        if let Some(addr) = peer {
            if let Ok((rating, comment)) = parse_file_desc(&pkt.payload) {
                dl.note_source_comment(addr, rating, comment).await;
            }
        }
    }
}

/// Handle a packet that is NOT the one a read loop is waiting for: a source's
/// rating/comment (OP_FILEDESC), and the secure-ident exchange (OP_SECIDENTSTATE
/// / OP_PUBLICKEY / OP_SIGNATURE). Secure-ident is best-effort and NEVER blocks
/// the transfer - it just answers packets the loop was going to read anyway: we
/// reply so the peer can verify us, mark the source verified once its signature
/// checks out, and drop a malformed packet silently. Nothing here awaits new data.
async fn handle_aux_packet<S>(
    pkt: &Packet,
    sec: &mut Option<(SecureIdentSession, Arc<Identity>)>,
    fs: &mut FramedStream<S>,
    dl: &Download,
    peer: Option<SocketAddr>,
    aich: &mut AichAsk,
) -> Result<(), TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    note_comment_if_desc(pkt, dl, peer).await;
    // A peer's answer to our source request. Unsolicited answers are fine to
    // accept too (aMule likewise just processes what arrives); every source is
    // re-validated by the fetch manager before it is ever dialed, so a hostile
    // list can at worst waste our own connection attempts.
    if matches!(pkt.opcode, OP_ANSWERSOURCES | OP_ANSWERSOURCES2) {
        let sx2 = pkt.opcode == OP_ANSWERSOURCES2;
        if let Ok((h, sources)) = parse_answer_sources(&pkt.payload, sx2, SOURCE_EXCHANGE_VERSION) {
            // Only for the file this connection is about.
            if h == dl.hash().await {
                dl.note_sx_sources(sources);
            }
        }
    }
    if matches!(pkt.opcode, OP_SECIDENTSTATE | OP_PUBLICKEY | OP_SIGNATURE) {
        if let Some((session, id)) = sec.as_mut() {
            // A malformed secure-ident packet is dropped (Err ignored), never
            // fatal to the download.
            if let Ok(replies) = session.on_packet(id, pkt.opcode, &pkt.payload) {
                for reply in replies {
                    fs.write_packet(&reply).await?;
                }
                if session.peer_verified() {
                    if let Some(addr) = peer {
                        dl.note_source_verified(addr).await;
                    }
                }
            }
        }
    }
    // The source's AICH root answer: a VOTE toward trusting a master root
    // (and the eligibility record a later recovery ask checks).
    if pkt.opcode == OP_AICHFILEHASHANS {
        if let Ok((h, root)) = parse_aich_file_hash_ans(&pkt.payload) {
            if h == dl.hash().await {
                if let Some(addr) = peer {
                    dl.note_aich_root(addr.ip(), root);
                }
            }
        }
    }
    // The recovery answer for the part WE asked this source about. Checked
    // BEFORE parsing: an unsolicited 0x9C is a flood vector, and parsing it
    // first would cost a copy of the whole payload plus a lock acquisition per
    // packet. (eMule treats an unsolicited answer as a packet error and drops
    // the connection; ignoring it is the gentler end of the same rule.)
    if pkt.opcode == OP_AICHANSWER && aich.asked.is_some() {
        if let Some(addr) = peer {
            handle_aich_answer(&pkt.payload, dl, aich, addr.ip()).await;
        }
    }
    Ok(())
}

/// Process an OP_AICHANSWER (eMule ProcessAICHAnswer,
/// DownloadClient.cpp:2286-2325): the echoes must match what we asked on THIS
/// connection (`aich_asked` - eMule matches the recorded request per client),
/// the echoed root must be the trusted master, and the payload must verify
/// against it. The refusal form and every failure release the claim so
/// ANOTHER source can be asked; a good answer fills back the part's verified
/// blocks and blames the bad ones. `ip` is this connection's peer: only the
/// claim OWNER may release or apply, so a superseded claimant's late answer
/// cannot disturb the new asker.
async fn handle_aich_answer(payload: &[u8], dl: &Download, aich: &mut AichAsk, ip: IpAddr) {
    let Some(asked) = aich.asked else { return };
    // Whatever happens below, this ask is over.
    aich.asked = None;
    // A malformed answer is a FAILED ask, not a no-op: leaving the claim in
    // place would strand the part until the 60s staleness timer.
    let Ok(ans) = parse_aich_answer(payload) else {
        aich.refused.insert(asked);
        dl.aich_recovery_failed(asked, ip);
        return;
    };
    let our_hash = dl.hash().await;
    match ans {
        AichAnswer::Failure(h) => {
            // A NORMAL outcome (the source cannot serve this part right now).
            if h == our_hash {
                aich.refused.insert(asked);
                dl.aich_recovery_failed(asked, ip);
            }
        }
        AichAnswer::Recovery {
            hash,
            part,
            root,
            recovery,
        } => {
            let part = u64::from(part);
            if hash != our_hash || part != asked || dl.aich_trusted_root() != Some(root) {
                aich.refused.insert(asked);
                dl.aich_recovery_failed(asked, ip);
                return;
            }
            let size = dl.size().await;
            let verified = AichTree::with_master(size, root)
                .filter(|_| part * PARTSIZE < size)
                .and_then(|mut t| {
                    t.read_recovery_data(part * PARTSIZE, &recovery)
                        .then(|| t.part_block_hashes(part * PARTSIZE))
                        .flatten()
                });
            match verified {
                // Apply only while we still OWN the claim: if ours expired and
                // another source has since been asked, this answer is stale
                // and applying it would race the current claimant's pass.
                Some(blocks) if dl.owns_aich_claim(part, ip) => {
                    let _ = dl.apply_aich_recovery(part, &blocks).await;
                }
                Some(_) => {}
                None => {
                    aich.refused.insert(part);
                    dl.aich_recovery_failed(part, ip);
                }
            }
        }
    }
}

/// Wait for the peer to grant us an upload slot (OP_ACCEPTUPLOADREQ).
///
/// Its own function because it is entered TWICE: once after the initial
/// OP_STARTUPLOADREQ, and again whenever the peer later revokes the slot with
/// OP_OUTOFPARTREQS and puts us back on its queue. `bail_on_queue` decides what
/// a queue ranking means here - move on to another source, or wait our turn.
///
/// Nothing re-sends OP_STARTUPLOADREQ on the second entry: upstream re-queues us
/// itself as part of revoking (`AddClientToQueue(this, true)`,
/// UploadClient.cpp:781), so asking again would be a duplicate request for a
/// place we already hold.
async fn await_slot<S>(
    fs: &mut FramedStream<S>,
    dl: &Download,
    sec: &mut Option<(SecureIdentSession, Arc<Identity>)>,
    peer: Option<SocketAddr>,
    aich: &mut AichAsk,
    bail_on_queue: bool,
) -> Result<(), TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let pkt = fs.read_packet_unpacked().await?;
        match pkt.opcode {
            OP_ACCEPTUPLOADREQ => {
                crate::stats::note_accepted();
                return Ok(());
            }
            OP_QUEUERANKING if bail_on_queue => {
                crate::stats::note_queued();
                return Err(TransferError::Queued);
            }
            _ => {
                crate::stats::note_unexpected(pkt.opcode);
                handle_aux_packet(&pkt, sec, fs, dl, peer, aich).await?
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_peer<S>(
    fs: &mut FramedStream<S>,
    dl: &Download,
    held: &mut Vec<(u64, u64)>,
    bail_on_queue: bool,
    peer: Option<SocketAddr>,
    session: PeerSession,
) -> Result<u64, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hash = dl.hash().await;
    let PeerSession {
        sec,
        credit,
        ask_sources,
        peer_aich,
    } = session;
    // The AICH part (if any) we asked THIS source recovery data for; the
    // answer handler matches against it like eMule matches its recorded
    // per-client request.
    let mut aich = AichAsk::default();

    // Secure-ident, when enabled: build our session and - if the peer advertised
    // support - proactively ask it to prove it owns its userhash, exactly as a
    // real eMule downloader does right after the hello. Fire-and-forget: the
    // exchange rides along on packets the transfer loops read anyway, and we NEVER
    // wait on it, so a peer that does not answer just stays unverified.
    let mut sec: Option<(SecureIdentSession, Arc<Identity>)> = match sec {
        Some(ctx) => {
            let session = SecureIdentSession::new(&ctx.identity);
            if ctx.peer_supports {
                let start = session.start();
                fs.write_packet(&start).await?;
            }
            Some((session, ctx.identity))
        }
        None => None,
    };

    // Ask what this peer has.
    fs.write_packet(&build_request_filename_ext(&hash)).await?;
    fs.write_packet(&build_set_req_file_id(&hash)).await?;
    // ...and, in the same breath, ask it who ELSE has the file (source exchange).
    // aMule asks here too - bundled into its multipacket file request, or sent
    // standalone (DownloadClient.cpp:249-258 / :305-320) - gated by
    // IsSourceRequestAllowed(). The answer is folded in by handle_aux_packet; we
    // never wait for it, so a peer that stays silent costs us nothing.
    if ask_sources {
        fs.write_packet(&build_request_sources2(&hash, SOURCE_EXCHANGE_VERSION))
            .await?;
    }
    // Ask an AICH-capable source for its master root (the standalone 0x9E,
    // eMule's non-multipacket send site, DownloadClient.cpp:471-479). ALWAYS
    // asked, even with a VERIFIED root in hand: the answer is a trust vote
    // AND the per-source eligibility record a recovery ask requires (the
    // source must have REPORTED the trusted root, PartFile.cpp:6089) - eMule
    // likewise gathers every source's claimed root, and treats one that
    // differs from a verified hash as file-not-found. Fire-and-forget.
    if peer_aich & 1 != 0 {
        fs.write_packet(&build_aich_file_hash_req(&hash)).await?;
    }
    let status = loop {
        let pkt = fs.read_packet_unpacked().await?;
        match pkt.opcode {
            OP_FILEREQANSNOFIL => {
                crate::stats::note_nofile();
                return Err(TransferError::NoFile);
            }
            OP_FILESTATUS => break parse_file_status(&pkt.payload)?,
            // A source's OP_FILEDESC (rating/comment) or a secure-ident packet
            // can arrive here; neither is what we are waiting for.
            _ => {
                crate::stats::note_unexpected(pkt.opcode);
                handle_aux_packet(&pkt, &mut sec, fs, dl, peer, &mut aich).await?
            }
        }
    };
    crate::stats::note_status();
    // Record what this peer holds so block selection knows which parts are rare.
    dl.note_status(&status).await;

    // NOTHING HERE FOR US. eMule reads the same status and, when the peer holds
    // no part it needs, sets DS_NONEEDEDPARTS and swaps away WITHOUT ever asking
    // for an upload slot (DownloadClient.cpp:634-641; the slot request at :545-549
    // is the else-branch). padMule asked unconditionally, and the stress funnel
    // priced that: of 7 slots it actually WON, 6 went to peers holding nothing it
    // needed - the scarcest thing on eD2k, spent on nothing, while the worker sat
    // through the queue wait to get it.
    //
    // Fast-bail makes this worse than it sounds, because it SELECTS for such
    // peers: a client that just started downloading this file has a free upload
    // slot precisely because it has nothing to upload, so it is exactly the peer
    // that answers instantly instead of queueing us.
    //
    // Ok(0) rather than an error: the peer is healthy and honest, it simply has
    // nothing yet. Scoring it as a failure would sink it below untried sources
    // forever, when it may well have parts by the next sweep.
    if !dl.has_needed_part(&status).await {
        crate::stats::note_no_needed_parts();
        return Ok(0);
    }

    // A multi-part file cannot be verified without the part hashes.
    if dl.needs_hashset().await {
        crate::stats::note_hashset_need();
        fs.write_packet(&build_hashset_request(&hash)).await?;
        loop {
            let pkt = fs.read_packet_unpacked().await?;
            if pkt.opcode == OP_HASHSETANSWER {
                let (_h, hashes) = parse_hashset_answer(&pkt.payload)?;
                dl.set_hashset(hashes).await;
                crate::stats::note_hashset_got();
                break;
            }
            crate::stats::note_unexpected(pkt.opcode);
            handle_aux_packet(&pkt, &mut sec, fs, dl, peer, &mut aich).await?;
        }
    }

    // Ask for a slot. A peer with a free slot answers OP_ACCEPTUPLOADREQ; a busy
    // one answers OP_QUEUERANKING (we are now Nth in its queue). For a completion
    // hunt across many thin sources, sitting in a queue is dead time - bail the
    // instant we are queued so the sweep moves to the next source. A real
    // background client would instead keep the slot and wait its turn.
    crate::stats::note_slot_ask();
    fs.write_packet(&build_start_upload_req(&hash)).await?;
    await_slot(fs, dl, &mut sec, peer, &mut aich, bail_on_queue).await?;

    // Fetch blocks until this peer has nothing we still need.
    let size = dl.size().await;
    let mut delivered = 0u64;
    // Funnel bookkeeping: count this SESSION once, not once per block round.
    let mut asked_once = false;
    let mut counted_delivery = false;
    loop {
        // A corrupt part awaiting AICH recovery: ask THIS source for its block
        // hashes if it is eligible (capable, reported the trusted root, no ask
        // in flight here). The answer rides the aux channel; the transfer is
        // never blocked on it.
        if peer_aich & 1 != 0 && aich.asked.is_none() {
            if let Some(ip) = peer.map(|a| a.ip()) {
                match dl.claim_aich_recovery(ip, size) {
                    // Already refused by THIS source: hand the claim straight
                    // back so another source can take it. eMule likewise moves
                    // on to a different client after a failure, rather than
                    // re-asking the one that just said no.
                    Some((part, _)) if aich.refused.contains(&part) => {
                        dl.aich_recovery_failed(part, ip);
                    }
                    Some((part, root)) => {
                        fs.write_packet(&build_aich_request(&hash, part as u16, &root))
                            .await?;
                        aich.asked = Some(part);
                    }
                    None => {}
                }
            }
        }
        let blocks = dl.take_blocks(&status, STANDARD_BLOCKS_REQUEST).await;
        if blocks.is_empty() {
            if !asked_once {
                // Granted a slot, then found nothing this peer could serve us -
                // it holds no part we still need, or every one is reserved.
                crate::stats::note_no_blocks();
            }
            return Ok(delivered);
        }
        if !asked_once {
            asked_once = true;
            crate::stats::note_requested();
        }
        held.extend_from_slice(&blocks);

        fs.write_packet(&build_request_parts(&hash, &blocks))
            .await?;

        // One hardened receiver validates every reply (raw or compressed) against
        // exactly these blocks - a hostile peer cannot panic or wedge it.
        //
        // CONTINUOUS TOP-UP. This used to wait for ALL THREE blocks before
        // asking for anything more, so every batch boundary cost a full RTT of
        // dead air - which is worst exactly where padMule runs: cellular, or a
        // VPN tunnel, where the round trip is ~200ms. Both authorities keep the
        // window FULL instead: eMule re-requests the moment ONE block completes
        // (`SendBlockRequests` from the block-finished branch,
        // DownloadClient.cpp:1270-1276, with `CreateBlockRequests` topping the
        // pending list back up to 3, :870-892). Depth stays 3 - eMule never
        // asks for more, and aMule master's [3,24] clamp cites a "pending range"
        // eMule does not actually request (see CLAUDE.md's authority note).
        //
        // DELIBERATE DEVIATION, and it is the safer half of the trade: eMule
        // re-states its WHOLE window every time, re-naming the blocks still in
        // flight, which is only harmless because the uploader dedups them
        // (`AddReqBlock`, UploadClient.cpp:665-680 - the check padMule was
        // missing until row 8bm). padMule asks for ONLY THE NEW blocks. The
        // uploader APPENDS requests to its queue rather than replacing them, so
        // an incremental ask pipelines identically; it halves the request
        // chatter, and it removes any chance of a peer's re-sent bytes being
        // counted twice against a block still in flight.
        let mut rx = BlockReceiver::new(hash, size, &blocks);
        // Set once the download has no further blocks to hand out: the window
        // then drains rather than being topped up, and the loop ends when the
        // last in-flight block lands.
        let mut no_more_blocks = false;
        while !rx.is_done() {
            let pkt = fs.read_packet_unpacked().await?;
            // A secure-ident packet, a late OP_FILEDESC, or an AICH answer can
            // interleave with block data on the same connection; handle it and
            // keep waiting for the blocks we asked for.
            if matches!(
                pkt.opcode,
                OP_SECIDENTSTATE
                    | OP_PUBLICKEY
                    | OP_SIGNATURE
                    | OP_FILEDESC
                    | OP_AICHFILEHASHANS
                    | OP_AICHANSWER
            ) {
                handle_aux_packet(&pkt, &mut sec, fs, dl, peer, &mut aich).await?;
                continue;
            }
            // THE SLOT IS OVER. Not an error and not an edge case - it is how
            // every upload turn ends. Both authorities revoke with this the
            // moment CheckForTimeOver() trips, at 10 MB uploaded or one hour
            // (eMule 0.50a UploadClient.cpp:722-725 + :767-782, aMule master
            // UploadClient.cpp:463-466, UploadQueue.cpp:609-616), then put us
            // straight back on the queue.
            //
            // padMule had no handler, and `BlockReceiver::accept` yields no
            // writes for a non-data opcode, so this loop went on waiting for
            // bytes that were never coming - until the CALLER's per-peer
            // timeout, 45s of one of only four worker slots for that download.
            // Every source that fed us 10 MB then parked a worker. That is the
            // "partially download, then stop or slow to a crawl" report.
            //
            // aMule's own receive side does exactly what happens below: a
            // DOWNLOADING client goes back to ON_QUEUE (ClientTCPSocket.cpp:
            // 727-736). Whether that means "wait our turn" or "go find another
            // source" is the same fast-bail question the slot wait already
            // answers, so it is deferred to the same flag.
            if pkt.opcode == OP_OUTOFPARTREQS {
                crate::stats::note_revoked();
                if bail_on_queue {
                    // Report the bytes rather than an error: this source DID
                    // deliver and behaved correctly, so the manager must score
                    // it as a proven deliverer and come back to it.
                    return Ok(delivered);
                }
                // Waiting our turn: give the in-flight blocks back first, so
                // they are not stranded behind our place in the queue.
                dl.release(held).await;
                held.clear();
                await_slot(fs, dl, &mut sec, peer, &mut aich, bail_on_queue).await?;
                break;
            }
            let writes = rx.accept(pkt.opcode, &pkt.payload)?;
            // A packet that produced no writes is one this loop had no use for
            // while it was waiting for block data. Tallied by opcode, because
            // "the session stalled after being granted a slot" does not say
            // WHICH packet padMule failed to act on - and the answer decides
            // whether the fix is a policy change or a missing handler.
            if writes.is_empty() {
                crate::stats::note_unexpected(pkt.opcode);
            }
            for w in writes {
                if !counted_delivery {
                    counted_delivery = true;
                    crate::stats::note_delivered();
                }
                delivered += w.data.len() as u64;
                crate::stats::add_downloaded(w.data.len() as u64);
                // Accrue what this source GAVE us against its credit record - this
                // is what earns a peer a better place in OUR upload queue later.
                if let Some((cs, uh)) = &credit {
                    cs.add_downloaded(*uh, w.data.len() as u64, now_secs());
                }
                dl.commit(w.offset, &w.data, peer)
                    .await
                    .map_err(TransferError::Io)?;
            }
            // Any block that just closed is released immediately (so another
            // source can take the next one) and replaced, keeping three in
            // flight across the batch boundary instead of stalling on it.
            let done = rx.take_completed();
            if done.is_empty() {
                continue;
            }
            dl.release(&done).await;
            held.retain(|b| !done.contains(b));
            if no_more_blocks {
                continue;
            }
            let more = dl.take_blocks(&status, done.len()).await;
            if more.is_empty() {
                // Nothing left to reserve (the file is fully claimed, or we were
                // cancelled). Drain what is in flight and finish honestly.
                no_more_blocks = true;
                continue;
            }
            held.extend_from_slice(&more);
            rx.add_blocks(&more);
            fs.write_packet(&build_request_parts(&hash, &more)).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::HelloInfo;
    use crate::peer_conn::{accept_peer, connect_peer};
    use crate::transfer_session::{serve, ServedFile};
    use mule_proto::{ed2k_hash, md4, PARTSIZE};
    use std::path::PathBuf;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn we_ask_a_peer_for_sources_and_collect_its_answer() {
        // Source exchange, ask side. A faithful other-side: an uploader that
        // answers OP_REQUESTSOURCES2 with an OP_ANSWERSOURCES2 record set,
        // exactly as aMule's CreateSrcInfoPacket does for a peer in its upload
        // list. padMule must SEND the request during its file-request sequence
        // (aMule bundles/sends it there, DownloadClient.cpp:249-258) and hand
        // the parsed sources to the Download for the fetch manager to dial.
        use crate::sources::{
            build_answer_sources, parse_request_sources2, Source, OP_REQUESTSOURCES2,
        };
        use crate::transfer::{
            build_accept_upload, build_file_status_complete, build_sending_part,
            parse_request_parts, OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_STARTUPLOADREQ,
        };
        let dir = tmpdir("sx-ask");
        let data: Vec<u8> = (0..40_000u32).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let hash = ed2k_hash(&data);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = data.clone();
        let server = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "server");
            let (_p, mut fs) = accept_peer(&listener, &me).await.unwrap();
            let mut asked = false;
            while let Ok(pkt) = fs.read_packet_unpacked().await {
                match pkt.opcode {
                    OP_REQUESTSOURCES2 => {
                        // Answer with one usable source, SX v4 (userhash+crypt).
                        let (ver, h) = parse_request_sources2(&pkt.payload).unwrap();
                        assert_eq!(ver, SOURCE_EXCHANGE_VERSION, "we request the newest SX");
                        assert_eq!(h, hash);
                        asked = true;
                        let srcs = vec![Source {
                            ip: 0x8602_0102,
                            port: 4662,
                            server_ip: 0,
                            server_port: 0,
                            user_hash: Some([0xEE; 16]),
                            crypt: Some(0x01),
                        }];
                        let p = build_answer_sources(&hash, &srcs, SOURCE_EXCHANGE_VERSION, true)
                            .unwrap();
                        let _ = fs.write_packet(&p).await;
                    }
                    OP_REQUESTFILENAME => {
                        let _ = fs.write_packet(&build_file_status_complete(&hash)).await;
                    }
                    OP_STARTUPLOADREQ => {
                        let _ = fs.write_packet(&build_accept_upload()).await;
                    }
                    OP_REQUESTPARTS => {
                        if let Ok((_h, blocks)) = parse_request_parts(&pkt.payload, false) {
                            for (s, e) in blocks {
                                if s <= e && (e as usize) <= served.len() {
                                    let _ = fs
                                        .write_packet(&build_sending_part(
                                            &hash,
                                            s,
                                            e,
                                            &served[s as usize..e as usize],
                                        ))
                                        .await;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            asked
        });

        let store = PartStore::create(&dir, 1, hash, data.len() as u64, b"sx.bin").unwrap();
        let dl = Download::new(store);
        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        let session = PeerSession {
            ask_sources: true,
            ..Default::default()
        };
        let got = download_from_peer_at(&mut fs, &dl, false, Some(addr), session)
            .await
            .unwrap();
        assert_eq!(got, data.len() as u64, "the transfer still completes");

        let learned = dl.take_sx_sources();
        assert_eq!(learned.len(), 1, "the peer's sources reached the Download");
        assert_eq!(learned[0].user_hash, Some([0xEE; 16]));
        assert_eq!(learned[0].crypt, Some(0x01));
        // Draining is destructive: the fetch manager consumes each source once.
        assert!(dl.take_sx_sources().is_empty());
        // The once-per-peer gate is the CALLER's claim (fetch_one asks only if it
        // wins it), so exercise that primitive directly: eMule rate-limits the
        // same exchange per client at SOURCECLIENTREASKS = 40 min.
        assert!(dl.mark_asked_sources(addr.ip()), "first claim wins");
        assert!(
            !dl.mark_asked_sources(addr.ip()),
            "a second ask is suppressed"
        );

        drop(fs);
        let _ = server.await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("padmule-ms-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn aich_root_vote_follows_emule_thresholds() {
        let dir = tmpdir("aichvote");
        let store = PartStore::create(&dir, 1, [0xAB; 16], 1_000_000, b"v.bin").unwrap();
        let dl = Download::new(store);
        let root_a = [0xAA; 20];
        let root_b = [0xBB; 20];

        // 9 distinct /20s: still UNTRUSTED (>= 10 required).
        for i in 0..9u8 {
            dl.note_aich_root(ip(&format!("10.{i}.0.1")), root_a);
        }
        assert_eq!(dl.aich_trusted_root(), None, "9 < MINUNIQUEIPS_TOTRUST");
        // Two more voters from ONE /20 that already signed: no advance
        // (one /20 signs once - the mask keeps the top nibble of octet 3).
        dl.note_aich_root(ip("10.0.15.9"), root_a); // same /20 as 10.0.0.1
        assert_eq!(dl.aich_trusted_root(), None, "a /20 cannot vote twice");
        // The 10th distinct /20 promotes to TRUSTED (10/10 = 100% >= 92%).
        dl.note_aich_root(ip("10.9.0.1"), root_a);
        assert_eq!(dl.aich_trusted_root(), Some(root_a));
        // One dissenting /20 drops agreement to 10/11 = 90% < 92%: demoted,
        // exactly as eMule re-evaluates on every vote.
        dl.note_aich_root(ip("172.16.0.1"), root_b);
        assert_eq!(dl.aich_trusted_root(), None, "90% < MINPERCENTAGE_TOTRUST");
        // A VERIFIED root (ed2k link identity) ignores votes entirely.
        dl.set_aich_master_verified(root_b);
        for i in 0..12u8 {
            dl.note_aich_root(ip(&format!("192.{i}.0.1")), root_a);
        }
        assert_eq!(
            dl.aich_trusted_root(),
            Some(root_b),
            "votes never displace VERIFIED"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn aich_recovery_claim_lifecycle() {
        let dir = tmpdir("aichclaim");
        let size = 2 * PARTSIZE;
        let store = PartStore::create(&dir, 1, [0xAB; 16], size, b"c.bin").unwrap();
        let dl = Download::new(store);
        let root = [0x5A; 20];
        dl.set_aich_master_verified(root);
        // No pending parts yet: nothing to claim.
        let src = ip("9.9.9.9");
        dl.note_aich_root(src, root);
        assert_eq!(dl.claim_aich_recovery(src, size), None);
        // Queue part 1 (the private path localize_corruption uses).
        dl.aich.lock().unwrap().pending.insert(
            1,
            PendingRecovery {
                claim: None,
                contributors: HashMap::new(),
            },
        );
        // A source that reported a DIFFERENT root is ineligible (eMule
        // PartFile.cpp:6089 - the source must have reported the trusted root).
        let liar = ip("8.8.8.8");
        dl.note_aich_root(liar, [0xEE; 20]);
        assert_eq!(dl.claim_aich_recovery(liar, size), None);
        // The matching source claims it; a second concurrent claim is refused
        // (one in-flight ask per part).
        assert_eq!(dl.claim_aich_recovery(src, size), Some((1, root)));
        assert_eq!(dl.claim_aich_recovery(src, size), None);
        // Failure releases it for the NEXT source.
        dl.aich_recovery_failed(1, src);
        assert_eq!(dl.claim_aich_recovery(src, size), Some((1, root)));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn aich_recovery_fills_good_blocks_and_bans_the_block_poisoner() {
        // THE 8ai closure: an attacker who always shares a poisoned part with a
        // good source evaded the sole-contributor PART ban. With AICH the blame
        // lands on the single bad BLOCK - whose sole contributor is unambiguous.
        let dir = tmpdir("aichrepair");
        let size = (PARTSIZE + 4 * EMBLOCKSIZE + 500) as usize;
        let good: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(13)) as u8)
            .collect();
        let hash = ed2k_hash(&good);
        let ph = vec![
            md4(&good[..PARTSIZE as usize]),
            md4(&good[PARTSIZE as usize..]),
        ];
        let store = PartStore::create(&dir, 1, hash, size as u64, b"r.bin").unwrap();
        let dl = Download::new(store);
        dl.set_hashset(ph).await;

        let good_src: SocketAddr = "1.2.3.4:4662".parse().unwrap();
        let bad_src: SocketAddr = "5.6.7.8:4662".parse().unwrap();
        // Part 0 wholly from GOOD. Part 1: block 1 (a 180KB lattice block) from
        // BAD - and CORRUPTED - the rest from GOOD.
        dl.commit(0, &good[..PARTSIZE as usize], Some(good_src))
            .await
            .unwrap();
        let p1 = PARTSIZE as usize;
        let b1_start = p1 + EMBLOCKSIZE as usize;
        let b1_end = p1 + 2 * EMBLOCKSIZE as usize;
        dl.commit(PARTSIZE, &good[p1..b1_start], Some(good_src))
            .await
            .unwrap();
        let mut poisoned = good[b1_start..b1_end].to_vec();
        poisoned[7] ^= 0xFF;
        dl.commit(b1_start as u64, &poisoned, Some(bad_src))
            .await
            .unwrap();
        dl.commit(b1_end as u64, &good[b1_end..], Some(good_src))
            .await
            .unwrap();
        assert!(dl.is_complete().await);

        // MD4 localization: part 1 blamed + re-gapped, but fed by TWO sources,
        // so the part-level ban must stay silent (no false positive)...
        assert!(dl.localize_corruption().await);
        assert!(!dl.is_banned(&bad_src), "part-level blame is ambiguous");
        assert!(!dl.is_banned(&good_src));

        // ...then AICH recovery pinpoints the block. Trusted root via the link
        // path; the true tree plays the answering source's verified leaves.
        let tree = mule_proto::AichTree::from_file_data(&good).unwrap();
        dl.set_aich_master_verified(tree.master_hash().unwrap());
        let blocks = tree.part_block_hashes(PARTSIZE).unwrap();
        let (kept, reopened) = dl.apply_aich_recovery(1, &blocks).await.unwrap();
        assert_eq!(reopened, 1, "exactly the poisoned block stays open");
        assert_eq!(kept, blocks.len() - 1, "every good block filled back");
        assert_eq!(
            dl.missing().await,
            EMBLOCKSIZE,
            "only one 180KB block remains to re-fetch, not a 9.28MB part"
        );
        assert!(
            dl.is_banned(&bad_src),
            "the BLOCK's sole contributor is banned"
        );
        assert!(!dl.is_banned(&good_src), "the good source is untouched");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_refetching_source_is_never_blamed_by_a_recovery_pass() {
        // THE REVIEW'S HEADLINE RACE: once a part is re-gapped the sweep starts
        // re-filling it, so by the time recovery data arrives a GOOD source may
        // have written blocks - and, reading bytes mid-flight, the recovery
        // hash can call one bad. Blame must come from the contributor snapshot
        // frozen at blame time, and must skip any block the re-fetch touched.
        let dir = tmpdir("aichrace");
        let size = (PARTSIZE + 4 * EMBLOCKSIZE + 500) as usize;
        let good: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(11)) as u8)
            .collect();
        let hash = ed2k_hash(&good);
        let ph = vec![
            md4(&good[..PARTSIZE as usize]),
            md4(&good[PARTSIZE as usize..]),
        ];
        let store = PartStore::create(&dir, 1, hash, size as u64, b"race.bin").unwrap();
        let dl = Download::new(store);
        dl.set_hashset(ph).await;

        let bad_src: SocketAddr = "5.6.7.8:4662".parse().unwrap();
        let rescuer: SocketAddr = "1.2.3.4:4662".parse().unwrap();
        // Part 1 arrives WHOLLY from the bad source, corrupted.
        let p1 = PARTSIZE as usize;
        dl.commit(0, &good[..p1], Some(bad_src)).await.unwrap();
        let mut poisoned = good[p1..].to_vec();
        // Corrupt a byte inside part 1's SECOND lattice block - the very block
        // the rescuer will be re-fetching when recovery lands.
        let b_start = p1 + EMBLOCKSIZE as usize;
        poisoned[EMBLOCKSIZE as usize + 5] ^= 0xFF;
        dl.commit(PARTSIZE, &poisoned, Some(bad_src)).await.unwrap();
        assert!(dl.localize_corruption().await);
        assert!(dl.is_banned(&bad_src), "sole contributor of the part");

        // The rescuer now re-fetches that block - but its bytes have NOT hit
        // the disk yet (mid-flight: `commit` records the contributor before
        // the write), so the recovery pass reads the STALE poisoned bytes and
        // calls the block bad. Blaming from the live map would ban the rescuer.
        {
            let mut bs = dl.block_sources.lock().unwrap();
            bs.entry(b_start as u64).or_default().insert(rescuer.ip());
        }
        let tree = mule_proto::AichTree::from_file_data(&good).unwrap();
        dl.set_aich_master_verified(tree.master_hash().unwrap());
        let blocks = tree.part_block_hashes(PARTSIZE).unwrap();
        dl.apply_aich_recovery(1, &blocks).await.unwrap();
        assert!(
            !dl.is_banned(&rescuer),
            "the source REPAIRING the part must never be banned for its stale bytes"
        );
    }

    #[tokio::test]
    async fn a_root_that_recovery_disproves_is_terminally_distrusted() {
        // A poisoned root whose "verified" leaves match the poisoned bytes
        // completes the part - and its MD4 still disagrees. Without the
        // recheck the download loops forever (fill -> whole-file MD4 fails ->
        // blame -> fill). eMule marks the hashset AICH_ERROR, which is never
        // re-trusted (PartFile.cpp:3969-3980).
        let dir = tmpdir("aichpoison");
        let size = (PARTSIZE + 4 * EMBLOCKSIZE + 77) as usize;
        let good: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(19)) as u8)
            .collect();
        let hash = ed2k_hash(&good);
        let ph = vec![
            md4(&good[..PARTSIZE as usize]),
            md4(&good[PARTSIZE as usize..]),
        ];
        let store = PartStore::create(&dir, 1, hash, size as u64, b"p.bin").unwrap();
        let dl = Download::new(store);
        dl.set_hashset(ph).await;
        let attacker: SocketAddr = "9.9.9.9:4662".parse().unwrap();
        let p1 = PARTSIZE as usize;
        let mut poisoned = good.clone();
        poisoned[p1 + 3] ^= 0xFF;
        dl.commit(0, &poisoned[..p1], Some(attacker)).await.unwrap();
        dl.commit(PARTSIZE, &poisoned[p1..], Some(attacker))
            .await
            .unwrap();
        assert!(dl.localize_corruption().await);

        // The attacker's root: the tree over the POISONED bytes, so its leaves
        // "verify" the corruption.
        let evil = mule_proto::AichTree::from_file_data(&poisoned).unwrap();
        let evil_root = evil.master_hash().unwrap();
        dl.set_aich_master_verified(evil_root);
        let blocks = evil.part_block_hashes(PARTSIZE).unwrap();
        dl.apply_aich_recovery(1, &blocks).await.unwrap();

        assert_eq!(
            dl.aich_trusted_root(),
            None,
            "a root disproved by the part MD4 is dropped, not kept"
        );
        assert!(
            !dl.is_complete().await,
            "the part is re-opened, not accepted"
        );
        // Terminal: no amount of further voting can re-trust ANY root.
        for i in 0..12u8 {
            dl.note_aich_root(ip(&format!("10.{i}.0.1")), evil_root);
        }
        assert_eq!(
            dl.aich_trusted_root(),
            None,
            "AICH_ERROR is terminal - votes cannot revive it"
        );
    }

    #[tokio::test]
    async fn only_the_claim_owner_can_release_or_apply() {
        let dir = tmpdir("aichowner");
        let size = 2 * PARTSIZE;
        let store = PartStore::create(&dir, 1, [0xAB; 16], size, b"o.bin").unwrap();
        let dl = Download::new(store);
        let root = [0x5A; 20];
        dl.set_aich_master_verified(root);
        let a = ip("1.1.1.1");
        let b = ip("2.2.2.2");
        dl.note_aich_root(a, root);
        dl.note_aich_root(b, root);
        dl.aich.lock().unwrap().pending.insert(
            1,
            PendingRecovery {
                claim: None,
                contributors: HashMap::new(),
            },
        );
        assert_eq!(dl.claim_aich_recovery(a, size), Some((1, root)));
        assert!(dl.owns_aich_claim(1, a) && !dl.owns_aich_claim(1, b));
        // B cannot release A's claim...
        dl.aich_recovery_failed(1, b);
        assert!(dl.owns_aich_claim(1, a), "a non-owner cannot release");
        // ...but A can, and then B may take it.
        dl.aich_recovery_failed(1, a);
        assert_eq!(dl.claim_aich_recovery(b, size), Some((1, root)));
        assert!(dl.owns_aich_claim(1, b) && !dl.owns_aich_claim(1, a));
    }

    #[tokio::test]
    async fn verify_pass_also_builds_the_aich_tree() {
        // finish_download persists what THIS returns, so the tree built in the
        // verify pass must equal one built independently from the same bytes.
        let dir = tmpdir("aichpass");
        let size = (PARTSIZE + 300_000) as usize;
        let good: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(23)) as u8)
            .collect();
        let hash = ed2k_hash(&good);
        let store = PartStore::create(&dir, 1, hash, size as u64, b"a.bin").unwrap();
        let dl = Download::new(store);
        dl.commit(0, &good[..PARTSIZE as usize], None)
            .await
            .unwrap();
        dl.commit(PARTSIZE, &good[PARTSIZE as usize..], None)
            .await
            .unwrap();
        let (ok, set) = dl.verify_whole_file_and_aich(size as u64, hash).await;
        assert!(ok, "md4 verifies");
        let (root, leaves) = set.expect("aich set built in the same pass");
        let want = mule_proto::AichTree::from_file_data(&good).unwrap();
        assert_eq!(root, want.master_hash().unwrap());
        assert_eq!(leaves, want.leaves().unwrap());
        // An MD4 mismatch yields NO aich set - wrong bytes must not be hashed
        // into a servable tree.
        let (ok2, set2) = dl.verify_whole_file_and_aich(size as u64, [0xEE; 16]).await;
        assert!(!ok2 && set2.is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn localize_corruption_re_opens_only_the_bad_part() {
        // One bad source delivering one corrupt part must NOT force re-downloading
        // the whole file: localize_corruption blames the individual part against
        // the hashset and re-opens only it.
        let dir = tmpdir("localize");
        let size = (PARTSIZE + 300_000) as usize;
        let good: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(17)) as u8)
            .collect();
        let hash = ed2k_hash(&good);
        let ph = vec![
            md4(&good[..PARTSIZE as usize]),
            md4(&good[PARTSIZE as usize..]),
        ];
        let store = PartStore::create(&dir, 1, hash, size as u64, b"loc.bin").unwrap();
        let dl = Download::new(store);
        dl.set_hashset(ph).await;

        // Part 0 arrives intact from GOOD; part 1 arrives corrupted from BAD.
        let good_src: SocketAddr = "1.2.3.4:4662".parse().unwrap();
        let bad_src: SocketAddr = "5.6.7.8:4662".parse().unwrap();
        dl.commit(0, &good[..PARTSIZE as usize], Some(good_src))
            .await
            .unwrap();
        let mut bad = good[PARTSIZE as usize..].to_vec();
        bad[0] ^= 0xFF;
        dl.commit(PARTSIZE, &bad, Some(bad_src)).await.unwrap();
        assert!(dl.is_complete().await, "all bytes present");
        assert!(
            !dl.verify_whole_file(size as u64, hash).await,
            "the corrupt part fails the whole-file hash"
        );

        assert!(dl.localize_corruption().await, "localized the bad part");
        assert!(!dl.is_complete().await, "part 1 re-opened");
        assert_eq!(
            dl.missing().await,
            crate::part_file::part_size(1, size as u64),
            "ONLY part 1 was re-opened, not the whole file"
        );
        // The SOLE contributor of the bad part is banned; the good source is not.
        assert!(
            dl.is_banned(&bad_src),
            "the corrupt part's source is banned"
        );
        assert!(
            !dl.is_banned(&good_src),
            "the source of the GOOD part is never banned"
        );
        // Banned by IP, not SocketAddr: the same host on a DIFFERENT port (a LowID
        // source dialing back from a fresh ephemeral port) is still caught.
        let bad_callback: SocketAddr = "5.6.7.8:51000".parse().unwrap();
        assert!(
            dl.is_banned(&bad_callback),
            "the ban catches the same IP on a new port (LowID callback case)"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn the_idle_retry_sweep_rotates_instead_of_starving() {
        // THE BUG behind "many files partially download and then stop or crawl"
        // with dozens queued. The sweep picked ONE idle download per 45s using
        // `sort_by_key(Reverse(priority))` then `.first()`. Rust's sort is
        // STABLE, so with every download at the same Normal priority it returned
        // the SAME one on every sweep, forever - the rest were never retried at
        // all. Not slow: never.
        //
        // This drives the same selection the sweep uses. Priority still wins;
        // within a tier the least-recently-retried goes next, and the stamp is
        // applied on SELECTION so a retry that finds no sources still yields.
        struct D {
            name: &'static str,
            priority: u8,
            last: u64,
        }
        fn pick(ds: &mut [D], now: u64) -> &'static str {
            let i = ds
                .iter()
                .enumerate()
                .min_by_key(|(_, d)| (std::cmp::Reverse(d.priority), d.last))
                .map(|(i, _)| i)
                .unwrap();
            ds[i].last = now;
            ds[i].name
        }

        // Six equal-priority downloads, as a real queue looks.
        let mut ds: Vec<D> = ["a", "b", "c", "d", "e", "f"]
            .iter()
            .map(|n| D {
                name: n,
                priority: 1,
                last: 0,
            })
            .collect();
        let picked: Vec<&str> = (1..=6).map(|t| pick(&mut ds, t)).collect();
        assert_eq!(
            picked,
            vec!["a", "b", "c", "d", "e", "f"],
            "every download must get a turn - the old code returned 'a' six times"
        );
        // Seventh sweep wraps to the oldest again.
        assert_eq!(pick(&mut ds, 7), "a", "rotation wraps");

        // Priority still wins, but cannot starve its own tier.
        let mut ds = vec![
            D {
                name: "high1",
                priority: 2,
                last: 0,
            },
            D {
                name: "high2",
                priority: 2,
                last: 0,
            },
            D {
                name: "normal",
                priority: 1,
                last: 0,
            },
        ];
        assert_eq!(pick(&mut ds, 1), "high1");
        assert_eq!(
            pick(&mut ds, 2),
            "high2",
            "the other High goes next, not High1 again"
        );
        assert_eq!(pick(&mut ds, 3), "high1", "then back round the High tier");
    }

    #[tokio::test]
    async fn the_block_window_is_topped_up_before_the_batch_finishes() {
        // THE MECHANISM, measured directly: padMule must ask for a replacement
        // block as soon as ONE of the three lands, not wait for all three.
        // eMule re-requests from the block-finished branch
        // (DownloadClient.cpp:1270-1276); stop-and-wait costs a full RTT at
        // every batch boundary, which on a cellular or VPN link is ~200ms of
        // dead air each time.
        //
        // The mock is what makes this non-vacuous: it sends ONE block and then
        // REFUSES to send the rest until a SECOND OP_REQUESTPARTS arrives. Under
        // the old stop-and-wait driver both sides wait for each other forever,
        // so a regression DEADLOCKS - which the timeout below turns into a clean
        // failure instead of a hung suite.
        use crate::transfer::{
            build_sending_part, parse_request_parts, OP_REQUESTPARTS, OP_REQUESTPARTS_I64,
        };
        use mule_proto::{ed2k_hash, EMBLOCKSIZE};

        let size = (4 * EMBLOCKSIZE) as usize;
        let data: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(7)) as u8)
            .collect();
        let hash = ed2k_hash(&data);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = data.clone();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xC1; 16], 0, 4662, 4672, "up");
            let (_p, mut fs) = accept_peer(&listener, &me).await.unwrap();
            let mut requests = 0usize;
            let mut sent_first = false;
            // Serve metadata, then the deliberately-stalled block schedule.
            while let Ok(pkt) = fs.read_packet_unpacked().await {
                match pkt.opcode {
                    OP_REQUESTPARTS | OP_REQUESTPARTS_I64 => {
                        let (_h, blocks) =
                            parse_request_parts(&pkt.payload, pkt.opcode == OP_REQUESTPARTS_I64)
                                .unwrap();
                        requests += 1;
                        if !sent_first {
                            // Exactly ONE block, then silence: the downloader
                            // must top up off this single completion.
                            let (s, e) = blocks[0];
                            let _ = fs
                                .write_packet(&build_sending_part(
                                    &hash,
                                    s,
                                    e,
                                    &served[s as usize..e as usize],
                                ))
                                .await;
                            sent_first = true;
                        } else {
                            // The top-up arrived - the thing under test. Now
                            // finish everything so the download can complete.
                            for (s, e) in blocks {
                                if e > s {
                                    let _ = fs
                                        .write_packet(&build_sending_part(
                                            &hash,
                                            s,
                                            e,
                                            &served[s as usize..e as usize],
                                        ))
                                        .await;
                                }
                            }
                        }
                    }
                    // Minimal metadata answers so the driver reaches the block
                    // phase: name, "I have it all", and a granted slot. The file
                    // is a single part, so no hashset is requested.
                    crate::transfer::OP_REQUESTFILENAME => {
                        let _ = fs
                            .write_packet(&crate::transfer::build_req_filename_answer(
                                &hash,
                                b"topup.bin",
                            ))
                            .await;
                    }
                    crate::transfer::OP_SETREQFILEID => {
                        let _ = fs
                            .write_packet(&crate::transfer::build_file_status_complete(&hash))
                            .await;
                    }
                    crate::transfer::OP_STARTUPLOADREQ => {
                        let _ = fs
                            .write_packet(&crate::transfer::build_accept_upload())
                            .await;
                    }
                    _ => {}
                }
            }
            requests
        });

        let dir = tmpdir("topup");
        let store = PartStore::create(&dir, 1, hash, size as u64, b"topup.bin").unwrap();
        let dl = Download::new(store);
        let me = HelloInfo::baseline([0xC2; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();

        // A stop-and-wait regression hangs here; 20s converts that to a failure.
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            download_from_peer(&mut fs, &dl, false),
        )
        .await
        .expect("topping up must not deadlock - the driver waited for the whole batch");
        assert!(got.is_ok(), "download failed: {got:?}");
        drop(fs);
        let _ = up.await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_small_file_is_fully_reserved_by_its_own_workers() {
        // WHY THIS TEST EXISTS: the fetch funnel measured 12 of 17 hard-won
        // upload slots ending in "accepted, no block to take", and the arithmetic
        // says why. The manager runs `parallel_for_priority(PR_NORMAL) = 4`
        // workers, each reserving STANDARD_BLOCKS_REQUEST = 3 blocks of
        // EMBLOCKSIZE - so 4 x 3 x 180KiB = 2.11 MB of a download can be under
        // reservation at once. Any file SMALLER than that is entirely spoken for
        // the moment its own workers start, and every further peer session finds
        // nothing to take - including one that just won a slot, the scarcest
        // thing on eD2k.
        //
        // The band is NARROWER than that arithmetic alone suggests, and this
        // test exists because assuming otherwise was wrong: below
        // ENDGAME_LIMIT (4 blocks, 737 KB) `take_blocks` enters endgame and
        // races the reserved blocks instead of returning empty, so the smallest
        // files rescue themselves. The exposed band is
        //
        //     ENDGAME_LIMIT (737 KB)  <  still missing  <  2.11 MB
        //
        // plus, at any size, a peer holding only parts whose blocks are already
        // spoken for. So this mechanism is REAL but does not on its own account
        // for the 12-of-17 measured live - that remains open.
        //
        // Documents the mechanism; asserts no fix. Changing it is a policy call
        // (fewer workers on small files, a wider endgame, finer reservations)
        // and belongs to its own measured pass.
        use crate::transfer::build_file_status_complete;
        use mule_proto::ed2k_hash;

        // Nine blocks: comfortably past ENDGAME_LIMIT, and exactly what three
        // workers reserve - so the fourth arrives to nothing.
        let size = (9 * EMBLOCKSIZE) as usize;
        let data: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(5)) as u8)
            .collect();
        let hash = ed2k_hash(&data);
        let dir = tmpdir("smallreserve");
        let store = PartStore::create(&dir, 1, hash, size as u64, b"small.bin").unwrap();
        let dl = Download::new(store);
        assert!(
            (size as u64) > ENDGAME_LIMIT,
            "must be past endgame, or take_blocks races the reservations instead"
        );

        // Every peer here holds the WHOLE file, so nothing is refused for lack
        // of availability - only for lack of an UNRESERVED block.
        let complete = parse_file_status(&build_file_status_complete(&hash).payload).unwrap();
        for w in 0..3 {
            let got = dl.take_blocks(&complete, STANDARD_BLOCKS_REQUEST).await;
            assert_eq!(got.len(), STANDARD_BLOCKS_REQUEST, "worker {w} reserves 3");
        }

        // The fourth peer is a COMPLETE source that would have served us, and it
        // may well have just spent a queue wait winning that slot.
        assert!(
            dl.has_needed_part(&complete).await,
            "the file is entirely missing, so the peer does hold parts we need"
        );
        assert!(
            dl.take_blocks(&complete, STANDARD_BLOCKS_REQUEST)
                .await
                .is_empty(),
            "this is the measured 'accepted, no block to take': a useful source \
             turned away because its own siblings hold every block"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_source_holding_nothing_we_need_is_never_asked_for_a_slot() {
        // eMule reads OP_FILESTATUS and, if the peer holds no part it needs,
        // goes to DS_NONEEDEDPARTS and swaps away - the upload-slot request is
        // the ELSE branch (DownloadClient.cpp:634-641 vs :545-549). An upload
        // slot is the scarcest thing on the network; asking a peer that has
        // nothing for one wastes both sides' time.
        //
        // The peer here is the common real case the stress funnel kept finding:
        // another DOWNLOADER of the same file, zero parts so far - which is
        // exactly the peer with a free upload slot to give.
        use crate::transfer::{build_file_status, OP_STARTUPLOADREQ};
        use mule_proto::{ed2k_hash, PARTSIZE};

        // Two data parts, so the status carries a real (all-zero) bitfield
        // rather than the "complete" shorthand.
        let size = (PARTSIZE + 4096) as usize;
        let data: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(3)) as u8)
            .collect();
        let hash = ed2k_hash(&data);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xC7; 16], 0, 4662, 4672, "up");
            let (_p, mut fs) = accept_peer(&listener, &me).await.unwrap();
            let mut asked_for_a_slot = false;
            while let Ok(pkt) = fs.read_packet_unpacked().await {
                match pkt.opcode {
                    crate::transfer::OP_SETREQFILEID => {
                        // "I am downloading this too, and I have none of it."
                        let _ = fs
                            .write_packet(&build_file_status(&hash, &[false, false]))
                            .await;
                    }
                    OP_STARTUPLOADREQ => asked_for_a_slot = true,
                    _ => {}
                }
            }
            asked_for_a_slot
        });

        let dir = tmpdir("noneeded");
        let store = PartStore::create(&dir, 1, hash, size as u64, b"noneeded.bin").unwrap();
        let dl = Download::new(store);
        let me = HelloInfo::baseline([0xC8; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();

        let got = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            download_from_peer(&mut fs, &dl, true),
        )
        .await
        .expect("a useless source must be dropped promptly, not waited on");
        assert_eq!(
            got.expect("holding nothing we need is not a transfer error"),
            0
        );
        drop(fs);
        assert!(
            !up.await.unwrap(),
            "asked a peer with zero parts for an upload slot"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_revoked_slot_ends_the_session_instead_of_hanging_until_the_timeout() {
        // OP_OUTOFPARTREQS (0x57) is how an uploader says "your turn is over, go
        // back on the queue". It is NOT an edge case: it is the ordinary end of
        // every slot. eMule 0.50a UploadClient.cpp:722-725 and aMule master
        // UploadClient.cpp:463-466 both call
        // SendOutOfPartReqsAndAddToWaitingQueue() the moment CheckForTimeOver()
        // trips, and that trips at 10 MB uploaded or one hour
        // (UploadQueue.cpp:609-616 - the same 10 MB padMule itself encodes as
        // upload_queue::SESSION_MAX_BYTES). So every source that hands padMule
        // 10 MB then sends this.
        //
        // padMule had no handler. `BlockReceiver::accept` returns no writes for
        // any non-data opcode, so the block loop kept waiting for bytes that
        // were never coming - until the caller's 45s per-peer timeout, holding
        // one of only FOUR concurrent worker slots for that download the whole
        // time. That is the "partially download and then stop or slow to a
        // crawl" report.
        //
        // The mock is the upstream sequence verbatim: grant a slot, serve ONE
        // block, then revoke and re-queue (0x57 followed by a fresh
        // OP_QUEUERANKING, exactly as AddClientToQueue does) and go quiet
        // WITHOUT closing the socket - a close would have ended the loop by
        // itself and hidden the bug.
        use crate::transfer::{
            build_out_of_part_reqs, build_queue_ranking, build_sending_part, parse_request_parts,
            OP_REQUESTPARTS, OP_REQUESTPARTS_I64,
        };
        use mule_proto::{ed2k_hash, EMBLOCKSIZE};

        let size = (4 * EMBLOCKSIZE) as usize;
        let data: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(11)) as u8)
            .collect();
        let hash = ed2k_hash(&data);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = data.clone();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xC3; 16], 0, 4662, 4672, "up");
            let (_p, mut fs) = accept_peer(&listener, &me).await.unwrap();
            let mut revoked = false;
            while let Ok(pkt) = fs.read_packet_unpacked().await {
                match pkt.opcode {
                    OP_REQUESTPARTS | OP_REQUESTPARTS_I64 => {
                        let (_h, blocks) =
                            parse_request_parts(&pkt.payload, pkt.opcode == OP_REQUESTPARTS_I64)
                                .unwrap();
                        if revoked {
                            continue;
                        }
                        let (s, e) = blocks[0];
                        let _ = fs
                            .write_packet(&build_sending_part(
                                &hash,
                                s,
                                e,
                                &served[s as usize..e as usize],
                            ))
                            .await;
                        // The slot is now spent. Revoke it and re-queue us,
                        // then answer nothing further.
                        revoked = true;
                        let _ = fs.write_packet(&build_out_of_part_reqs()).await;
                        let _ = fs.write_packet(&build_queue_ranking(7)).await;
                    }
                    crate::transfer::OP_REQUESTFILENAME => {
                        let _ = fs
                            .write_packet(&crate::transfer::build_req_filename_answer(
                                &hash,
                                b"kick.bin",
                            ))
                            .await;
                    }
                    crate::transfer::OP_SETREQFILEID => {
                        let _ = fs
                            .write_packet(&crate::transfer::build_file_status_complete(&hash))
                            .await;
                    }
                    crate::transfer::OP_STARTUPLOADREQ => {
                        let _ = fs
                            .write_packet(&crate::transfer::build_accept_upload())
                            .await;
                    }
                    _ => {}
                }
            }
        });

        let dir = tmpdir("outofpartreqs");
        let store = PartStore::create(&dir, 1, hash, size as u64, b"kick.bin").unwrap();
        let dl = Download::new(store);
        let me = HelloInfo::baseline([0xC4; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();

        // 5s stands in for the caller's 45s per-peer budget: the session must
        // end on the revocation, not wait out a timeout. MUTATION-CHECK by
        // deleting the OP_OUTOFPARTREQS arm in `run_peer` - this goes red.
        let got = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            download_from_peer(&mut fs, &dl, true),
        )
        .await
        .expect("a revoked slot must end the session, not hang until the peer timeout");

        // It reports the BYTES, not an error: the peer behaved correctly and
        // gave us real data, so the manager must score it as a proven deliverer
        // and come back to it rather than record a failure against it.
        assert_eq!(
            got.expect("a revoked slot is not a transfer error"),
            EMBLOCKSIZE,
            "the revocation must report what the source delivered"
        );
        // The block it DID serve was committed, not thrown away.
        assert_eq!(
            dl.missing().await,
            (size - EMBLOCKSIZE as usize) as u64,
            "the one delivered block must be kept"
        );
        drop(fs);
        let _ = up.await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_dedicated_source_waits_out_a_revoked_slot_and_finishes_the_file() {
        // The other half of OP_OUTOFPARTREQS. A called-back LowID source dialed
        // US and cannot be redialed, so for it (`bail_on_queue = false`) the
        // right answer to a revoked slot is aMule's own: go back to ON_QUEUE and
        // wait for the next turn (ClientTCPSocket.cpp:727-736), not walk away.
        //
        // The mock revokes mid-file and then GRANTS A SECOND SLOT, so the test
        // fails if padMule either hangs on the revocation or gives up on it.
        use crate::transfer::{
            build_accept_upload, build_out_of_part_reqs, build_sending_part, parse_request_parts,
            OP_REQUESTPARTS, OP_REQUESTPARTS_I64,
        };
        use mule_proto::{ed2k_hash, EMBLOCKSIZE};

        let size = (6 * EMBLOCKSIZE) as usize;
        let data: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(13)) as u8)
            .collect();
        let hash = ed2k_hash(&data);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = data.clone();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xC5; 16], 0, 4662, 4672, "up");
            let (_p, mut fs) = accept_peer(&listener, &me).await.unwrap();
            let mut revoked = false;
            let mut asked_with_no_slot = false;
            while let Ok(pkt) = fs.read_packet_unpacked().await {
                match pkt.opcode {
                    OP_REQUESTPARTS | OP_REQUESTPARTS_I64 => {
                        let (_h, blocks) =
                            parse_request_parts(&pkt.payload, pkt.opcode == OP_REQUESTPARTS_I64)
                                .unwrap();
                        if !revoked {
                            // The turn ends with NO data served for this
                            // request. Serving a block first would not
                            // discriminate: the continuous top-up (row 8bn)
                            // legitimately fires a replacement request the
                            // instant a block completes, so that request is
                            // already in flight before the revocation is even
                            // read. With nothing completing here, the only
                            // reason to send another request is failing to go
                            // back on the queue.
                            revoked = true;
                            let _ = fs.write_packet(&build_out_of_part_reqs()).await;
                            // A real uploader serves nothing between revoking a
                            // slot and granting the next one. A downloader that
                            // merely stops waiting for data - instead of
                            // returning to ON_QUEUE - asks again inside this
                            // window while holding no slot. That request is
                            // consumed here and never answered, so it then
                            // hangs and the outer timeout fails the test too.
                            let early = tokio::time::timeout(
                                std::time::Duration::from_millis(300),
                                fs.read_packet_unpacked(),
                            )
                            .await;
                            asked_with_no_slot = early.is_ok();
                            let _ = fs.write_packet(&build_accept_upload()).await;
                        } else {
                            for (s, e) in blocks {
                                if e > s {
                                    let _ = fs
                                        .write_packet(&build_sending_part(
                                            &hash,
                                            s,
                                            e,
                                            &served[s as usize..e as usize],
                                        ))
                                        .await;
                                }
                            }
                        }
                    }
                    crate::transfer::OP_REQUESTFILENAME => {
                        let _ = fs
                            .write_packet(&crate::transfer::build_req_filename_answer(
                                &hash,
                                b"requeue.bin",
                            ))
                            .await;
                    }
                    crate::transfer::OP_SETREQFILEID => {
                        let _ = fs
                            .write_packet(&crate::transfer::build_file_status_complete(&hash))
                            .await;
                    }
                    crate::transfer::OP_STARTUPLOADREQ => {
                        let _ = fs.write_packet(&build_accept_upload()).await;
                    }
                    _ => {}
                }
            }
            asked_with_no_slot
        });

        let dir = tmpdir("requeue");
        let store = PartStore::create(&dir, 1, hash, size as u64, b"requeue.bin").unwrap();
        let dl = Download::new(store);
        let me = HelloInfo::baseline([0xC6; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();

        let got = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            download_from_peer(&mut fs, &dl, false),
        )
        .await
        .expect("waiting out a revoked slot must not deadlock");
        assert!(got.is_ok(), "download failed: {got:?}");
        assert_eq!(
            dl.missing().await,
            0,
            "the file completes across the requeue"
        );
        drop(fs);
        assert!(
            !up.await.unwrap(),
            "asked for parts while holding no slot - a revoked slot must send us \
             back to the queue, not straight back to requesting"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_second_corruption_round_re_attributes_instead_of_blaming_the_first_source() {
        // A part can fail MD4 twice before recovery ever runs: a root is only
        // trusted once 10 unique /20s report it, so the early rounds have none
        // and `pending` just accumulates. Round 2's contributors must REPLACE
        // round 1's for the blocks that were re-fetched - otherwise the stale
        // map is what the recovery pass blames, and it bans a source for bytes
        // it never sent, breaking the sole-contributor no-false-positive rule.
        let dir = tmpdir("localize-reattribute");
        let size = (PARTSIZE + 300_000) as usize;
        let good: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(23)) as u8)
            .collect();
        let hash = ed2k_hash(&good);
        let ph = vec![
            md4(&good[..PARTSIZE as usize]),
            md4(&good[PARTSIZE as usize..]),
        ];
        let store = PartStore::create(&dir, 1, hash, size as u64, b"reattr.bin").unwrap();
        let dl = Download::new(store);
        dl.set_hashset(ph).await;

        let a: SocketAddr = "1.1.1.1:4662".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:4662".parse().unwrap();
        dl.commit(0, &good[..PARTSIZE as usize], Some(a))
            .await
            .unwrap();
        let mut bad = good[PARTSIZE as usize..].to_vec();
        bad[0] ^= 0xFF;

        // Round 1: A alone feeds the bad part.
        dl.commit(PARTSIZE, &bad, Some(a)).await.unwrap();
        assert!(dl.localize_corruption().await);
        // Round 2: the re-gapped part comes back from B, still bad.
        dl.commit(PARTSIZE, &bad, Some(b)).await.unwrap();
        assert!(dl.localize_corruption().await);

        let a2 = dl.aich.lock().unwrap();
        let pend = a2.pending.get(&1).expect("part 1 queued for recovery");
        let blamed: HashSet<IpAddr> = pend.contributors.values().flatten().copied().collect();
        assert!(
            blamed.contains(&b.ip()),
            "the source that actually re-sent the bad blocks must be on the hook"
        );
        assert!(
            !blamed.contains(&a.ip()),
            "round 1's source must not be blamed for round 2's bytes"
        );
        drop(a2);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_part_from_two_sources_bans_neither_no_false_positive() {
        // Without AICH block hashes we cannot tell WHICH of two contributors sent
        // the bad block, so a part fed by more than one source blames NOBODY - a
        // good source is never false-banned.
        let dir = tmpdir("localize-shared");
        let size = (PARTSIZE + 300_000) as usize;
        let good: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(17)) as u8)
            .collect();
        let hash = ed2k_hash(&good);
        let ph = vec![
            md4(&good[..PARTSIZE as usize]),
            md4(&good[PARTSIZE as usize..]),
        ];
        let store = PartStore::create(&dir, 1, hash, size as u64, b"loc.bin").unwrap();
        let dl = Download::new(store);
        dl.set_hashset(ph).await;

        let a: SocketAddr = "1.1.1.1:4662".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:4662".parse().unwrap();
        // Part 0 intact (from A). Part 1 corrupt, delivered in TWO blocks from A and B.
        dl.commit(0, &good[..PARTSIZE as usize], Some(a))
            .await
            .unwrap();
        let mut bad = good[PARTSIZE as usize..].to_vec();
        bad[0] ^= 0xFF;
        let half = bad.len() / 2;
        dl.commit(PARTSIZE, &bad[..half], Some(a)).await.unwrap();
        dl.commit(PARTSIZE + half as u64, &bad[half..], Some(b))
            .await
            .unwrap();

        assert!(dl.localize_corruption().await, "localized the bad part");
        assert!(
            dl.banned_sources().is_empty(),
            "a part with two contributors blames neither"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn localize_corruption_declines_without_a_hashset() {
        // A single-part file (no hashset) cannot blame a part - the caller must
        // fall back to re-opening the whole file.
        let dir = tmpdir("localize-none");
        let file: Vec<u8> = (0..400_000u32)
            .map(|i| (i.wrapping_mul(13)) as u8)
            .collect();
        let hash = ed2k_hash(&file);
        let store = PartStore::create(&dir, 1, hash, file.len() as u64, b"one.bin").unwrap();
        let dl = Download::new(store);
        dl.commit(0, &file, None).await.unwrap();
        assert!(
            !dl.localize_corruption().await,
            "no hashset -> cannot localize"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn finish_to_moves_the_file_even_with_a_concurrent_arc_holder() {
        // The old into_store path used Arc::try_unwrap, which failed - and
        // stranded the byte-complete .part - if ANY other Arc<Download> clone
        // existed at that instant (the 1s downloads() poll, cancel, set_priority).
        // finish_to goes through the lock instead, so a live clone can't strand it.
        let dir = tmpdir("finish-concurrent");
        let store = PartStore::create(&dir, 1, [0x33; 16], 500, b"done.bin").unwrap();
        let part_path = dir.join("001.part");
        let met_path = dir.join("001.part.met");
        assert!(part_path.exists());
        let dl = Download::new(store);

        // Simulate a concurrent holder (e.g. the downloads() poll) keeping a clone.
        let holder = Arc::clone(&dl);

        let dest = dir.join("done.bin");
        dl.finish_to(&dest).await.unwrap();

        assert!(dest.exists(), "the file must be moved into place");
        assert!(!part_path.exists(), "the .part is renamed away");
        assert!(!met_path.exists(), "the .part.met is removed");
        // The clone is still alive throughout - it did not block the finish.
        assert_eq!(Arc::strong_count(&holder), 2);
        drop(holder);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn finish_to_refuses_to_move_a_cancelled_download() {
        // A cancel that lands during finalize must WIN: finish_to bails (Err) under
        // the lock instead of moving + sharing the file the user cancelled.
        let dir = tmpdir("finish-cancel");
        let store = PartStore::create(&dir, 1, [0x44; 16], 500, b"c.bin").unwrap();
        let part_path = dir.join("001.part");
        let dl = Download::new(store);
        dl.cancel();
        let dest = dir.join("c.bin");
        assert!(dl.finish_to(&dest).await.is_err(), "cancelled -> no move");
        assert!(
            !dest.exists(),
            "the cancelled file was NOT moved into place"
        );
        assert!(
            part_path.exists(),
            ".part is left for cancel_download to delete"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fetch_and_finalize_guards_admit_exactly_one_claimant() {
        let dir = tmpdir("guards");
        let store = PartStore::create(&dir, 1, [0x55; 16], 500, b"g.bin").unwrap();
        let dl = Download::new(store);
        // Only the FIRST caller may spawn a fetch task; released on task end.
        assert!(dl.try_begin_fetch());
        assert!(!dl.try_begin_fetch(), "a second fetch task is refused");
        assert!(dl.is_fetching());
        dl.end_fetch();
        assert!(!dl.is_fetching());
        assert!(dl.try_begin_fetch(), "re-claimable after the task ends");
        // Same one-shot semantics for finalize; released only on a failed finalize.
        assert!(dl.try_begin_finalize());
        assert!(!dl.try_begin_finalize(), "a second finalize is refused");
        dl.reset_finalize();
        assert!(
            dl.try_begin_finalize(),
            "re-claimable after a failed finalize"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_sources_comment_is_recorded_during_the_session() {
        use crate::transfer::{build_file_desc, build_file_req_ans_no_fil, OP_SETREQFILEID};
        let dir = tmpdir("filedesc");
        let hash = [0x77; 16];
        let store = PartStore::create(&dir, 1, hash, 400_000, b"c.bin").unwrap();
        let dl = Download::new(store);
        let addr: SocketAddr = "9.9.9.9:4662".parse().unwrap();
        // fetch_one records the base source before driving the session.
        dl.note_source(
            "aMule 3.0.1".into(),
            addr,
            true,
            false,
            crate::fetch::SourceOrigin::Server,
        )
        .await;

        let (client, server) = tokio::io::duplex(8192);
        let mut client_fs = FramedStream::new(client);
        let mut server_fs = FramedStream::new(server);
        // The "source": after the file request it pushes an unsolicited comment,
        // then declines the file (so the session ends quickly but the comment was
        // already recorded).
        let src = tokio::spawn(async move {
            // Consume the two request packets (REQUESTFILENAME, SETREQFILEID).
            loop {
                let pkt = server_fs.read_packet_unpacked().await.unwrap();
                if pkt.opcode == OP_SETREQFILEID {
                    break;
                }
            }
            server_fs
                .write_packet(&build_file_desc(5, "verified good rip"))
                .await
                .unwrap();
            server_fs
                .write_packet(&build_file_req_ans_no_fil(&hash))
                .await
                .unwrap();
        });

        let r = download_from_peer_at(
            &mut client_fs,
            &dl,
            false,
            Some(addr),
            PeerSession::default(),
        )
        .await;
        assert!(matches!(r, Err(TransferError::NoFile)));
        let _ = src.await;

        let srcs = dl.sources().await;
        let s = srcs.iter().find(|s| s.addr == addr).unwrap();
        assert_eq!(s.rating, 5);
        assert_eq!(s.comment, "verified good rip");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn downloading_from_a_source_accrues_its_credit() {
        use crate::credit_store::CreditStore;
        use crate::peer_conn::{accept_peer, connect_peer};
        use crate::transfer::{
            build_accept_upload, build_file_status_complete, build_sending_part,
            parse_request_parts, OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_STARTUPLOADREQ,
        };
        use mule_proto::ed2k_hash;
        use tokio::net::TcpListener;

        let dir = tmpdir("dlaccrue");
        let data: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(17)) as u8)
            .collect();
        let hash = ed2k_hash(&data);
        let src_hash = [0xBB; 16];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_data = data.clone();
        let server = tokio::spawn(async move {
            let me = HelloInfo::baseline(src_hash, 0, 4662, 4672, "src");
            let Ok((_p, mut fs)) = accept_peer(&listener, &me).await else {
                return;
            };
            while let Ok(pkt) = fs.read_packet_unpacked().await {
                match pkt.opcode {
                    OP_REQUESTFILENAME => {
                        let _ = fs.write_packet(&build_file_status_complete(&hash)).await;
                    }
                    OP_STARTUPLOADREQ => {
                        let _ = fs.write_packet(&build_accept_upload()).await;
                    }
                    OP_REQUESTPARTS => {
                        if let Ok((_h, blocks)) = parse_request_parts(&pkt.payload, false) {
                            for (s, e) in blocks {
                                if s <= e && (e as usize) <= server_data.len() {
                                    let _ = fs
                                        .write_packet(&build_sending_part(
                                            &hash,
                                            s,
                                            e,
                                            &server_data[s as usize..e as usize],
                                        ))
                                        .await;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        let store_pf = PartStore::create(&dir, 1, hash, data.len() as u64, b"s.bin").unwrap();
        let dl = Download::new(store_pf);
        let credits = Arc::new(CreditStore::empty(true));
        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        let credit = Some((Arc::clone(&credits), src_hash));
        let got = download_from_peer_at(
            &mut fs,
            &dl,
            false,
            Some(addr),
            PeerSession {
                credit,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(got, data.len() as u64, "the whole file transferred");

        // The source is credited with what it GAVE us (byte-compat via clients.met).
        let bytes = credits.save();
        let back = mule_files::read_clients_met(&bytes).unwrap();
        let e = back
            .entries
            .iter()
            .find(|e| e.user_hash == src_hash)
            .expect("the source has a credit record");
        assert_eq!(
            e.downloaded,
            data.len() as u64,
            "the source earned credit for the bytes it gave us"
        );

        drop(fs);
        let _ = server.await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn the_badge_counts_sources_in_play_not_every_one_ever_seen() {
        // Anthony's cross-tab report: the Search tab said 12 sources and the
        // Transfers badge said 99 for the SAME file. Cause: `note_source`
        // upserts by address and nothing ever removed a record, so the badge was
        // every address EVER contacted for that download and only grew. A peer
        // that dropped ten minutes ago is not "a source you have".
        let dir = tmpdir("fresh-sources");
        let store = PartStore::create(&dir, 1, [0x44; 16], 400_000, b"f.bin").unwrap();
        let dl = Download::new(store);
        let a: SocketAddr = "1.1.1.1:4662".parse().unwrap();
        let b: SocketAddr = "2.2.2.2:4662".parse().unwrap();
        dl.note_source(
            "a".into(),
            a,
            false,
            false,
            crate::fetch::SourceOrigin::Server,
        )
        .await;
        dl.note_source("b".into(), b, false, false, crate::fetch::SourceOrigin::Kad)
            .await;
        assert_eq!(dl.source_origins().await, (1, 1, 0), "both fresh");

        // Age BOTH well past the window, as a long session does.
        {
            let mut g = dl.sources.lock().await;
            for s in g.iter_mut() {
                s.last_seen = 0;
            }
        }
        assert_eq!(
            dl.source_origins().await,
            (0, 0, 0),
            "stale sources must not be counted - this is the 99-vs-12 bug"
        );

        // A source that is still DELIVERING stays counted: commit refreshes it,
        // so a transfer longer than the window does not age out mid-flight.
        dl.commit(0, &[7u8; 32], Some(a)).await.unwrap();
        assert_eq!(
            dl.source_origins().await,
            (1, 0, 0),
            "the delivering source is live again; the silent one is not"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn source_origin_counts_split_by_discovery_channel() {
        // The badge's data. A source that reached us by CALLBACK must be counted
        // too: only the outbound sweep called note_source, so a called-back peer
        // delivered bytes while appearing in neither the per-source sheet nor the
        // badge - a transfer visibly progressing with NO source listed, which is
        // exactly what Anthony saw on glass (676 KB of 787.6 MB, no indicator).
        // A callback is Server-origin because that is the only channel that can
        // produce one here.
        let dir = tmpdir("origins");
        let store = PartStore::create(&dir, 1, [0x33; 16], 400_000, b"o.bin").unwrap();
        let dl = Download::new(store);
        let srv: SocketAddr = "1.2.3.4:4662".parse().unwrap();
        let kad: SocketAddr = "5.6.7.8:4662".parse().unwrap();
        let sx: SocketAddr = "9.9.9.9:4662".parse().unwrap();
        let cb: SocketAddr = "7.7.7.7:5001".parse().unwrap();

        assert_eq!(
            dl.source_origins().await,
            (0, 0, 0),
            "nothing connected yet"
        );
        dl.note_source(
            "a".into(),
            srv,
            false,
            false,
            crate::fetch::SourceOrigin::Server,
        )
        .await;
        dl.note_source(
            "b".into(),
            kad,
            false,
            false,
            crate::fetch::SourceOrigin::Kad,
        )
        .await;
        dl.note_source(
            "c".into(),
            sx,
            false,
            false,
            crate::fetch::SourceOrigin::PeerExchange,
        )
        .await;
        // The called-back LowID peer - the case that was missing entirely.
        dl.note_source(
            "d".into(),
            cb,
            false,
            true,
            crate::fetch::SourceOrigin::Server,
        )
        .await;
        assert_eq!(
            dl.source_origins().await,
            (2, 1, 1),
            "server (incl. the callback), kad, source-exchange"
        );

        // A reconnect UPDATES rather than double-counting.
        dl.note_source(
            "a2".into(),
            srv,
            true,
            false,
            crate::fetch::SourceOrigin::Server,
        )
        .await;
        assert_eq!(dl.source_origins().await, (2, 1, 1), "upsert, not append");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn note_source_upserts_and_preserves_learned_fields() {
        let dir = tmpdir("srcinfo");
        let store = PartStore::create(&dir, 1, [0x11; 16], 400_000, b"s.bin").unwrap();
        let dl = Download::new(store);
        let a: SocketAddr = "1.2.3.4:4662".parse().unwrap();
        let b: SocketAddr = "5.6.7.8:4662".parse().unwrap();

        dl.note_source(
            "aMule 3.0.1".into(),
            a,
            true,
            false,
            crate::fetch::SourceOrigin::Server,
        )
        .await;
        dl.note_source(
            "eMule 0.50a".into(),
            b,
            false,
            true,
            crate::fetch::SourceOrigin::Kad,
        )
        .await;
        // A comment + a verification land on source a.
        dl.note_source_comment(a, 5, "great".into()).await;
        dl.note_source_verified(a).await;
        // A reconnect to a refreshes the base fields but keeps rating/comment/verified.
        dl.note_source(
            "aMule 3.0.1".into(),
            a,
            true,
            false,
            crate::fetch::SourceOrigin::Server,
        )
        .await;

        let mut srcs = dl.sources().await;
        assert_eq!(srcs.len(), 2, "one entry per address");
        srcs.sort_by_key(|s| s.addr);
        let sa = srcs.iter().find(|s| s.addr == a).unwrap();
        assert_eq!(sa.software, "aMule 3.0.1");
        assert!(sa.obfuscated && !sa.low_id);
        assert_eq!(sa.rating, 5);
        assert_eq!(sa.comment, "great");
        assert!(sa.verified, "verification survives a base re-note");
        let sb = srcs.iter().find(|s| s.addr == b).unwrap();
        assert!(!sb.obfuscated && sb.low_id && sb.rating == 0 && !sb.verified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_cancelled_download_hands_out_no_more_blocks() {
        use crate::transfer::{build_file_status_complete, parse_file_status};
        let dir = tmpdir("cancel-blocks");
        let hash = [0xCD; 16];
        let store = PartStore::create(&dir, 1, hash, 400_000, b"y.bin").unwrap();
        let dl = Download::new(store);
        // A complete source has every part, so a live download claims blocks...
        let status = parse_file_status(&build_file_status_complete(&hash).payload).unwrap();
        assert!(
            !dl.take_blocks(&status, 3).await.is_empty(),
            "a live download should hand out blocks"
        );
        // ...until it is cancelled, after which it claims none and the workers stop.
        dl.cancel();
        assert!(
            dl.take_blocks(&status, 3).await.is_empty(),
            "a cancelled download must hand out no blocks"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn an_exactly_partsize_file_still_fetches_its_hashset() {
        // Review finding 4: needs_hashset gated on `> 1` skipped the hashset for a
        // single-DATA-part PARTSIZE file, so verify_part returned None forever and
        // the file was accepted UNVERIFIED. It must report needing the hashset.
        let dir = tmpdir("needs-hashset");
        let store = PartStore::create(&dir, 1, [0xAB; 16], PARTSIZE, b"exact.bin").unwrap();
        let dl = Download::new(store);
        assert_eq!(data_part_count(PARTSIZE), 1, "one DATA part");
        assert!(dl.needs_hashset().await, "must still fetch the hashset");

        // Once the hashset is set, it no longer needs one.
        dl.set_hashset(vec![[1; 16], [2; 16]]).await;
        assert!(!dl.needs_hashset().await);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Spawn a serving peer that holds `available` parts of `data`.
    async fn spawn_server(
        data: Vec<u8>,
        hash: [u8; 16],
        part_hashes: Vec<[u8; 16]>,
        available: Option<Vec<bool>>,
        tag: u8,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let me = HelloInfo::baseline([tag; 16], 0, 4662, 4672, "server");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let f = ServedFile {
                    hash,
                    name: b"movie.bin",
                    data: &data,
                    part_hashes: &part_hashes,
                    available: available.as_deref(),
                };
                let _ = serve(&mut fs, &f).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn secure_ident_verifies_a_source_inline_with_the_download() {
        use crate::transfer::{
            build_accept_upload, build_file_status_complete, build_sending_part,
            parse_request_parts, OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_STARTUPLOADREQ,
        };
        let dir = tmpdir("secident-verify");
        let data: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let hash = ed2k_hash(&data);

        // A mock UPLOADER that advertises secure-ident, INITIATES it toward the
        // downloader (as a real eMule does right after the hello), responds to the
        // downloader's own request, and serves the file - all interleaved on one
        // connection. This is the FAITHFUL other-side the reverted attempt lacked.
        let server_data = data.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "server").with_secident();
            let (_p, mut fs) = accept_peer(&listener, &me).await.unwrap();
            let server_id = Identity::generate();
            let mut sess = SecureIdentSession::new(&server_id);
            // Initiate: ask the downloader to prove it owns its userhash.
            fs.write_packet(&sess.start()).await.unwrap();
            while let Ok(pkt) = fs.read_packet_unpacked().await {
                match pkt.opcode {
                    OP_SECIDENTSTATE | OP_PUBLICKEY | OP_SIGNATURE => {
                        if let Ok(replies) = sess.on_packet(&server_id, pkt.opcode, &pkt.payload) {
                            for r in replies {
                                let _ = fs.write_packet(&r).await;
                            }
                        }
                    }
                    OP_REQUESTFILENAME => {
                        let _ = fs.write_packet(&build_file_status_complete(&hash)).await;
                    }
                    OP_STARTUPLOADREQ => {
                        let _ = fs.write_packet(&build_accept_upload()).await;
                    }
                    OP_REQUESTPARTS => {
                        if let Ok((_h, blocks)) = parse_request_parts(&pkt.payload, false) {
                            for (s, e) in blocks {
                                if s <= e && (e as usize) <= server_data.len() {
                                    let _ = fs
                                        .write_packet(&build_sending_part(
                                            &hash,
                                            s,
                                            e,
                                            &server_data[s as usize..e as usize],
                                        ))
                                        .await;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        let store = PartStore::create(&dir, 1, hash, data.len() as u64, b"s.bin").unwrap();
        let dl = Download::new(store);
        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl").with_secident();
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        // Register the source so a verification is recorded against it.
        dl.note_source(
            "server".into(),
            addr,
            false,
            false,
            crate::fetch::SourceOrigin::Server,
        )
        .await;
        let sec = Some(SecIdentCtx {
            identity: Arc::new(Identity::generate()),
            peer_supports: true,
        });
        let got = download_from_peer_at(
            &mut fs,
            &dl,
            false,
            Some(addr),
            PeerSession {
                sec,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(got, data.len() as u64, "the whole file transferred");
        assert!(dl.is_complete().await, "download completed");
        assert!(
            dl.sources().await.iter().any(|s| s.verified),
            "the source must be cryptographically verified via secure-ident"
        );

        drop(fs);
        let _ = server.await;
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn three_peers_split_one_file_and_the_hash_matches() {
        let dir = tmpdir("three");
        // 600 KB: 4 blocks, so the three peers must genuinely share the work.
        let file: Vec<u8> = (0..600_000u32)
            .map(|i| (i.wrapping_mul(31)) as u8)
            .collect();
        let hash = ed2k_hash(&file);

        let mut addrs = Vec::new();
        for tag in 0..3u8 {
            addrs.push(spawn_server(file.clone(), hash, vec![], None, 0xB0 + tag).await);
        }

        let store = PartStore::create(&dir, 1, hash, file.len() as u64, b"movie.bin").unwrap();
        let dl = Download::new(store);

        let mut tasks = Vec::new();
        for (i, addr) in addrs.into_iter().enumerate() {
            let dl = dl.clone();
            tasks.push(tokio::spawn(async move {
                let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663 + i as u16, 4673, "dl");
                let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
                download_from_peer(&mut fs, &dl, false).await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }

        assert!(
            dl.is_complete().await,
            "still missing {}",
            dl.missing().await
        );
        dl.verify_ready_parts().await.unwrap();

        // The bytes on DISK must match, not just an in-memory buffer.
        let mut store = dl.into_store().await.unwrap();
        assert_eq!(store.read_part(0).unwrap(), file);
        assert_eq!(ed2k_hash(&store.read_part(0).unwrap()), hash);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn two_peers_holding_disjoint_parts_still_complete_the_file() {
        let dir = tmpdir("disjoint");
        // Two full parts: peer A has only part 0, peer B only part 1. Neither can
        // finish the file alone, so this only passes if availability is honoured
        // AND the two are combined.
        let size = (PARTSIZE + 300_000) as usize;
        let file: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(17)) as u8)
            .collect();
        let hash = ed2k_hash(&file);
        let ph = vec![
            md4(&file[..PARTSIZE as usize]),
            md4(&file[PARTSIZE as usize..]),
        ];

        let a = spawn_server(
            file.clone(),
            hash,
            ph.clone(),
            Some(vec![true, false]),
            0xC1,
        )
        .await;
        let b = spawn_server(
            file.clone(),
            hash,
            ph.clone(),
            Some(vec![false, true]),
            0xC2,
        )
        .await;

        let store = PartStore::create(&dir, 1, hash, size as u64, b"big.bin").unwrap();
        let dl = Download::new(store);

        let mut tasks = Vec::new();
        for (i, addr) in [a, b].into_iter().enumerate() {
            let dl = dl.clone();
            tasks.push(tokio::spawn(async move {
                let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4700 + i as u16, 4673, "dl");
                let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
                download_from_peer(&mut fs, &dl, false).await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }

        assert!(dl.is_complete().await, "missing {}", dl.missing().await);
        // The hashset arrived over the wire, so both parts can be verified.
        dl.verify_ready_parts().await.unwrap();

        let mut store = dl.into_store().await.unwrap();
        assert!(store.pf.corrupted().is_empty(), "no part should be corrupt");
        assert_eq!(store.read_part(0).unwrap(), file[..PARTSIZE as usize]);
        assert_eq!(store.read_part(1).unwrap(), file[PARTSIZE as usize..]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_peer_that_dies_mid_transfer_does_not_strand_its_blocks() {
        let dir = tmpdir("strand");
        let file: Vec<u8> = (0..400_000u32)
            .map(|i| (i.wrapping_mul(13)) as u8)
            .collect();
        let hash = ed2k_hash(&file);

        let store = PartStore::create(&dir, 1, hash, file.len() as u64, b"m.bin").unwrap();
        let dl = Download::new(store);

        // A peer that accepts, then hangs up immediately after the handshake.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        tokio::spawn(async move {
            let me = HelloInfo::baseline([0xDD; 16], 0, 4662, 4672, "dead");
            if let Ok((_p, fs)) = accept_peer(&dead, &me).await {
                drop(fs); // vanish
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4800, 4673, "dl");
        if let Ok((_p, mut fs)) = connect_peer(dead_addr, &me).await {
            // Expected to fail - the point is what it leaves behind.
            let _ = download_from_peer(&mut fs, &dl, false).await;
        }

        // Nothing must remain reserved, or a healthy peer would never be offered
        // those blocks and the download would stall forever.
        assert!(
            dl.inner.lock().await.reserved.is_empty(),
            "dead peer stranded its reservations"
        );

        // A good peer can now finish the whole file.
        let good = spawn_server(file.clone(), hash, vec![], None, 0xEE).await;
        let me = HelloInfo::baseline([0xAB; 16], 0x0A00_0001, 4801, 4673, "dl2");
        let (_p, mut fs) = connect_peer(good, &me).await.unwrap();
        download_from_peer(&mut fs, &dl, false).await.unwrap();

        assert!(dl.is_complete().await);
        let mut store = dl.into_store().await.unwrap();
        assert_eq!(store.read_part(0).unwrap(), file);

        std::fs::remove_dir_all(&dir).ok();
    }
}
