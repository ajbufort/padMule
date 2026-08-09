//! mule-ffi: the UniFFI seam between the Rust engine and the native (SwiftUI)
//! iPad shell. It wraps [`mule_engine::Engine`] in an FFI-friendly facade -
//! opaque hashes become hex strings, the event stream is drained by polling, and
//! the async `&mut self` lifecycle is driven on an internal tokio runtime so the
//! exported methods are simple and synchronous.
//!
//! The Swift bindings are generated from the compiled cdylib by the
//! `uniffi-bindgen` bin target (see its docs) - in CI for the device build.
//! The SwiftUI app (`ios/`) consumes this surface on-device; Rust-side tests
//! here validate the facade without Apple tooling.

use std::sync::Arc;

use mule_engine::{
    AddResult, Engine, EngineEvent, EngineState, HitStatus, RankedFile,
    SearchFilters as EngineSearchFilters, SearchOutcome as EngineSearchOutcome,
    ServerListUpdate as EngineServerListUpdate, Trust,
};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;

uniffi::setup_scaffolding!();

/// Decode a 32-char hex file hash. The UI round-trips whatever `search` handed
/// it, so a malformed value means a caller bug, not user input.
fn parse_hash16(hex_str: &str) -> Option<[u8; 16]> {
    let raw = hex::decode(hex_str).ok()?;
    let arr: [u8; 16] = raw.try_into().ok()?;
    Some(arr)
}

/// The coarse lifecycle state the UI shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum EngineStateFfi {
    Stopped,
    Running,
    Paused,
    /// Backgrounded but still SERVING - the listener and server login are up so
    /// peers keep downloading from us. Only reachable while an audio keepalive
    /// holds the app awake; see `MuleEngine::pause_for_seeding`.
    Seeding,
}

impl From<EngineState> for EngineStateFfi {
    fn from(s: EngineState) -> Self {
        match s {
            EngineState::Stopped => EngineStateFfi::Stopped,
            EngineState::Running => EngineStateFfi::Running,
            EngineState::Paused => EngineStateFfi::Paused,
            EngineState::Seeding => EngineStateFfi::Seeding,
        }
    }
}

/// An observable engine event, flattened for FFI (the progress hash is hex).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum EngineEventFfi {
    State {
        state: EngineStateFfi,
    },
    Status {
        text: String,
    },
    Server {
        text: String,
    },
    /// The server dropped/kicked us - the UI raises a prominent dialog.
    ServerDropped {
        addr: String,
    },
    /// Our public address changed between two logins - on a VPN, the tunnel
    /// dropping. Sharing has ALREADY been paused by the engine; the UI must say
    /// so loudly. Deliberately payload-free: the address is exactly what must
    /// never reach the screen.
    PublicAddressChanged,
    Kad {
        contacts: u32,
    },
    Progress {
        hash: String,
        have: u64,
        total: u64,
    },
    /// A download finished, was hash-verified, and landed in the downloads
    /// folder. Typed rather than a prose match on the accompanying server line -
    /// the UI acts on this (the finish beep).
    Finished {
        name: String,
    },
}

impl From<EngineEvent> for EngineEventFfi {
    fn from(e: EngineEvent) -> Self {
        match e {
            EngineEvent::State(s) => EngineEventFfi::State { state: s.into() },
            EngineEvent::Status(text) => EngineEventFfi::Status { text },
            EngineEvent::Server(text) => EngineEventFfi::Server { text },
            EngineEvent::ServerDropped { addr } => EngineEventFfi::ServerDropped { addr },
            EngineEvent::PublicAddressChanged => EngineEventFfi::PublicAddressChanged,
            EngineEvent::Kad { contacts } => EngineEventFfi::Kad {
                contacts: contacts as u32,
            },
            EngineEvent::Finished { name } => EngineEventFfi::Finished { name },
            EngineEvent::Progress { hash, have, total } => EngineEventFfi::Progress {
                hash: hex::encode(hash),
                have,
                total,
            },
        }
    }
}

/// The persistent node identity (hex-encoded for display).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct IdentityInfo {
    pub userhash: String,
    pub kad_id: String,
}

/// The live server login, once one has accepted us. `None` when offline.
///
/// Carries no client id by design - a HighID id encodes our public IP and this
/// goes straight onto a screen. See `mule_engine::ServerInfo`.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerInfoFfi {
    pub addr: String,
    /// The server's display NAME from server.met, when known. The engine has
    /// carried this since the connected-line change but only ever baked it into
    /// the status STRING, so every other place that showed a server - the
    /// Servers header, the Status screen's Server row - still printed a bare IP.
    pub name: Option<String>,
    pub low_id: bool,
    /// True when this server answers related-files searches, so the UI can offer
    /// the true `related::` query instead of a filename-keyword search.
    pub related_search: bool,
}

/// Cumulative file-data bytes moved this session. The UI samples these monotonic
/// totals each poll to derive the transfer-rate history and the up:down ratio.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct TransferStats {
    pub total_down: u64,
    pub total_up: u64,
}

/// One row of the Servers screen: a `server.met` entry enriched with a live UDP
/// status probe. `users`/`files` are meaningful only when `alive`; a dead server
/// is shown greyed out and cannot be selected.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ServerEntryFfi {
    /// "ip:port" - the handle to pass to `connect_to_server`.
    pub addr: String,
    pub name: String,
    pub users: u32,
    pub files: u32,
    pub alive: bool,
    pub connected: bool,
    /// A user favorite: kept by `prune_dead_servers` even when down.
    pub pinned: bool,
    /// Silent so far, but NOT yet judged dead - it has never answered a probe
    /// and has missed fewer than three rounds. On a cold start this is every
    /// server, and the UI must say "checking" rather than "no reply": the probe
    /// is UDP and the login is TCP, so a silent server is very often perfectly
    /// reachable (proven live 2026-08-05).
    pub checking: bool,
}

/// The outcome of a search: hits (with whether the server has more pages to load)
/// or a throttle notice. `Throttled` is a normal answer the UI reports, not an
/// error - mirrors `AddOutcome`.
#[derive(Debug, Clone, PartialEq, uniffi::Enum)]
pub enum SearchOutcome {
    Results {
        hits: Vec<SearchHit>,
        more_available: bool,
    },
    Throttled {
        wait_secs: u32,
    },
}

/// The outcome of auto-updating the server list from a URL.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum ServerListUpdate {
    Updated { added: u32, total: u32 },
    BadUrl,
    NotServerMet,
    Unreachable,
}

/// A snapshot of one in-progress download.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DownloadInfo {
    pub hash: String,
    pub name: String,
    pub size: u64,
    pub have: u64,
    pub complete: bool,
    /// Average rating across rated sources (0 = none; 1 = Fake .. 5 = Excellent).
    pub rating: u8,
    /// True if any source left a comment (view them in the per-source sheet).
    pub has_comment: bool,
    /// Download priority: 0 = Low, 1 = Normal, 2 = High. Biases how many sources
    /// this download contacts at once.
    pub priority: u8,
    /// True when preview mode is on (block selection biased to grow the file
    /// contiguously from the start so it can be played incomplete).
    pub preview: bool,
    /// Bytes available CONTIGUOUSLY from offset 0 - how much of the file a media
    /// player can read right now (see `preview_snapshot`).
    pub contiguous_prefix: u64,
    /// USER-paused (eMule 0.70b PauseFile): not driven until resumed, and the
    /// flag survives a restart. The row says "Paused".
    pub paused: bool,
    /// Past the max-active cap: registered, not paused, not driven YET -
    /// admitted in add order when a slot frees, except that a row ACTIVELY
    /// RECEIVING keeps its slot first (so resuming an older row cannot flip a
    /// pulling row to "Queued" mid-transfer). The row says "Queued".
    /// padMule's own policy (eMule has no such cap); derived by the same
    /// `queued_flags` rule the engine's sweeps enforce, over rows built by
    /// the same `Download::admission_row` constructor.
    pub queued: bool,
    /// True if bytes landed in the last few seconds - "actually receiving right
    /// now", as opposed to merely registered and hopeful. A TIME window, not an
    /// instantaneous rate: at a block boundary the rate legitimately reads zero,
    /// and an indicator that blinks off every few seconds is worse than none.
    pub receiving: bool,
    /// Sources that HANDSHAKED with us in the last few minutes, by channel.
    /// Zero across all three does NOT mean none were found - see the pool pair
    /// below, which is what tells those two apart.
    pub sources_server: u32,
    pub sources_kad: u32,
    pub sources_exchange: u32,
    /// What the LAST source lookup produced: `sources_found` went into the dial
    /// pool, `sources_callback` are LowID peers that can only reach us by being
    /// poked through the server.
    ///
    /// Without these an idle row is unreadable: "no sources exist" and "plenty
    /// of sources exist and none can be reached" are opposite problems that both
    /// render as a blank. See `Download::note_source_pool`.
    pub sources_found: u32,
    pub sources_callback: u32,
    /// Parts still needed, and how many of those NO source has ever been seen
    /// holding. The pair answers what a stalled near-complete download otherwise
    /// cannot: is padMule failing to ASK for the tail, or does the swarm not
    /// HAVE it? Opposite bugs, opposite fixes, and identical on screen without
    /// this. Conservative by construction - see `Download::part_availability`.
    pub parts_needed: u64,
    pub parts_unavailable: u64,
    /// How many peer statuses `parts_unavailable` is drawn from - the SAMPLE
    /// SIZE. That count only means "the swarm lacks these parts" in proportion
    /// to this; from one source it means "the one peer we found lacks them".
    /// Carried so the UI can say so rather than overstate.
    ///
    /// It is REPORTS, not distinct sources, and the UI must not call it sources:
    /// `download_file` re-sweeps its pool every round and nothing evicts a
    /// source, so one peer contributes one report per session it completes.
    pub part_status_reports: u32,
}

/// One complete file we are serving to peers (the shared library).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SharedFileInfo {
    pub hash: String,
    pub name: String,
    pub size: u64,
    /// The local user's own rating, 0 = unrated, else 1-5 (1 = Fake .. 5 =
    /// Excellent). Served to downloaders (with the comment) via OP_FILEDESC.
    pub rating: u8,
    pub comment: String,
}

/// One source we have connected to for a download (the per-source detail view).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SourceInfoFfi {
    pub addr: String,
    pub software: String,
    pub obfuscated: bool,
    pub low_id: bool,
    pub verified: bool,
    /// 0 = unrated, else 1-5 (1 = Fake .. 5 = Excellent).
    pub rating: u8,
    pub comment: String,
}

/// Pre-search filters pushed onto the server query. A `0` field means "unset".
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct SearchFilters {
    /// True = only files with at least one source (availability >= 1).
    pub complete_only: bool,
    /// Minimum / maximum size in BYTES; 0 = no bound.
    pub min_size: u64,
    pub max_size: u64,
    /// True = also query the whole serverlist over UDP (global search), not just
    /// the connected server. Slower + noisier, so it is opt-in.
    pub global: bool,
}

impl From<SearchFilters> for EngineSearchFilters {
    fn from(f: SearchFilters) -> Self {
        EngineSearchFilters {
            min_sources: if f.complete_only { Some(1) } else { None },
            min_size: (f.min_size > 0).then_some(f.min_size),
            max_size: (f.max_size > 0).then_some(f.max_size),
            global: f.global,
        }
    }
}

/// A search hit's local state (already have / fetching / new).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum HitStatusFfi {
    New,
    Downloading,
    Have,
}

impl From<HitStatus> for HitStatusFfi {
    fn from(s: HitStatus) -> Self {
        match s {
            HitStatus::New => HitStatusFfi::New,
            HitStatus::Downloading => HitStatusFfi::Downloading,
            HitStatus::Have => HitStatusFfi::Have,
        }
    }
}

/// One ranked, deduped search hit. `hash` is hex - the handle to pass back to
/// [`MuleEngine::add_download`].
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct SearchHit {
    /// Where this hit came from: "server", "kad", or "server + kad" (a popular
    /// file legitimately arrives from both, which is why the engine tracks it as
    /// a bitset). Empty when unknown.
    pub origin: String,
    pub hash: String,
    pub name: String,
    pub size: u64,
    /// Best advertised availability seen across the raw results.
    pub sources: u32,
    /// Full-file copies advertised; 0 if none.
    pub complete_sources: u32,
    /// Display category (Video/Audio/Archive/Document/Image/Program/Other).
    pub file_type: String,
    /// Media metadata, empty/0 when the result did not carry it.
    pub artist: String,
    pub album: String,
    pub title: String,
    pub length_secs: u32,
    pub bitrate: u32,
    pub codec: String,
    /// Server rating 0-5 (0 = none, 1 = Fake, 2 = Poor, 3 = Fair, 4 = Good,
    /// 5 = Excellent). Usually 0 - most servers do not advertise a rating.
    pub rating: u8,
    /// False when the metadata is self-contradictory (e.g. one hash advertising
    /// two sizes). Shown, not hidden: the user decides.
    pub trusted: bool,
    /// Why it is not trusted, empty when it is.
    pub warning: String,
    /// Whether we already have it, are fetching it, or it is new.
    pub status: HitStatusFfi,
}

/// What [`MuleEngine::add_download`] did. "No sources" is a normal answer on a
/// P2P network, so this is a result the UI reports, not an error it throws.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum AddOutcome {
    Started,
    AlreadyAdded,
    NoSources,
    NotConnected,
    Rejected { reason: String },
}

impl From<AddResult> for AddOutcome {
    fn from(r: AddResult) -> Self {
        match r {
            AddResult::Started => AddOutcome::Started,
            AddResult::AlreadyAdded => AddOutcome::AlreadyAdded,
            AddResult::NoSources => AddOutcome::NoSources,
            AddResult::NotConnected => AddOutcome::NotConnected,
            AddResult::BadRequest(r) => AddOutcome::Rejected {
                reason: r.to_string(),
            },
            AddResult::Failed(m) => AddOutcome::Rejected { reason: m },
        }
    }
}

/// Errors crossing the FFI boundary.
#[derive(Debug, uniffi::Error)]
pub enum FfiError {
    Io { message: String },
}

impl std::fmt::Display for FfiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FfiError::Io { message } => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for FfiError {}

/// Map the engine's search outcome to the FFI one, converting ranked files to
/// hits (which needs `&g` for hit status) and carrying the throttle/more flags.
async fn search_outcome_to_ffi(g: &Engine, outcome: EngineSearchOutcome) -> SearchOutcome {
    match outcome {
        EngineSearchOutcome::Results {
            ranked,
            more_available,
        } => SearchOutcome::Results {
            hits: ranked_to_hits(g, ranked).await,
            more_available,
        },
        EngineSearchOutcome::Throttled { wait_secs } => SearchOutcome::Throttled { wait_secs },
    }
}

/// Render the ORIGIN_* bitset as something a person can read. Both bits set is
/// the common case for a popular file and is worth saying explicitly - it means
/// two independent networks agree the file exists.
fn origin_label(bits: u8) -> String {
    let server = bits & (mule_engine::ORIGIN_SERVER | mule_engine::ORIGIN_GLOBAL) != 0;
    let kad = bits & mule_engine::ORIGIN_KAD != 0;
    match (server, kad) {
        (true, true) => "server + kad".to_string(),
        (true, false) => "server".to_string(),
        (false, true) => "kad".to_string(),
        (false, false) => String::new(),
    }
}

/// Map engine `RankedFile`s to FFI `SearchHit`s, tagging each with its
/// have/fetching/new status. Shared by `search` and `related_search`. `g` is
/// borrowed immutably, so call it AFTER the `&mut self` search has returned its
/// owned Vec - the borrows never overlap.
async fn ranked_to_hits(g: &Engine, ranked: Vec<RankedFile>) -> Vec<SearchHit> {
    let mut out = Vec::with_capacity(ranked.len());
    for r in ranked {
        let status = g.hit_status(r.hash).await.into();
        let origin = origin_label(r.origins);
        let trusted = r.is_trusted();
        let warning = match r.trust {
            Trust::Ok => String::new(),
            Trust::Suspect(why) => why.to_string(),
        };
        out.push(SearchHit {
            origin,
            hash: hex::encode(r.hash),
            name: r.name,
            size: r.size,
            sources: r.sources,
            complete_sources: r.complete_sources,
            file_type: r.file_type,
            artist: r.artist,
            album: r.album,
            title: r.title,
            length_secs: r.length_secs,
            bitrate: r.bitrate,
            codec: r.codec,
            rating: r.rating,
            trusted,
            warning,
            status,
        });
    }
    out
}

/// How recently bytes must have landed for a row to read as ACTIVE. Three
/// seconds spans an ordinary gap between blocks without holding the light on
/// through a real stall.
const RECEIVING_WINDOW_SECS: u64 = 3;

/// The single object the native UI holds. Thread-safe; drive it with the
/// lifecycle methods and poll [`MuleEngine::drain_events`].
#[derive(uniffi::Object)]
pub struct MuleEngine {
    rt: Runtime,
    inner: Mutex<Engine>,
    /// Read-only handles that do NOT need the engine lock. This is what stops a
    /// long `search`/`crawl` - which holds `&mut Engine` across its whole
    /// network wait - from freezing the 1s UI poll behind it.
    handles: mule_engine::engine::EngineHandles,
    events: Mutex<UnboundedReceiver<EngineEvent>>,
}

#[uniffi::export]
impl MuleEngine {
    /// Load (or create) the identity under `config_dir` and build the engine.
    ///
    /// `downloads_dir` is where COMPLETED files are moved. The iOS app passes
    /// its Documents directory so finished downloads appear in the Files app -
    /// `config_dir` (Application Support) is invisible to the user, and a file
    /// they cannot open is not really downloaded.
    #[uniffi::constructor]
    pub fn new(config_dir: String, downloads_dir: String) -> Result<Arc<Self>, FfiError> {
        let (mut engine, rx) = Engine::new(&config_dir).map_err(|e| FfiError::Io {
            message: e.to_string(),
        })?;
        engine.set_downloads_dir(&downloads_dir);
        // TWO WORKERS, AND THE RECEIVE PATH BLOCKS ON THEM. Flagged by the
        // 2026-08-08 reanalysis and DELIBERATELY NOT CHANGED, because it is a
        // hypothesis until someone measures it - but the next person to measure
        // "padMule handles many downloads badly" should start here:
        //
        //   `Download::commit` (multi_source.rs) takes the download's inner
        //   lock and calls `PartStore::write_block`, which is a SYNCHRONOUS
        //   `File::write_all` with no `spawn_blocking` - the one uninsulated
        //   blocking call in an engine that otherwise wraps hashing, part
        //   verification and AICH reads carefully. With 2 workers, two
        //   concurrent ~180KB writes can occupy BOTH, stalling the server link,
        //   the Kad loop and the UI poll for the duration.
        //
        // The max-active cap (`set_max_active_downloads`) defaults to 0 =
        // unlimited, and each active download gets up to ~4 peer workers
        // (`parallel_for_priority`), so at the default the offered load still
        // scales with the number of downloads while the runtime does not.
        // Raising this number is the cheap experiment; moving the write off the
        // reactor is the real fix, and it needs care because the lock is held
        // across it.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| FfiError::Io {
                message: e.to_string(),
            })?;
        let handles = engine.handles();
        Ok(Arc::new(MuleEngine {
            rt,
            handles,
            inner: Mutex::new(engine),
            events: Mutex::new(rx),
        }))
    }

    /// App started/foregrounded: load state and resume transfers.
    pub fn start(&self) {
        self.rt
            .block_on(async { self.inner.lock().await.start().await });
    }

    /// App backgrounded: checkpoint and release sockets.
    pub fn pause(&self) {
        self.rt
            .block_on(async { self.inner.lock().await.pause().await });
    }

    /// App backgrounded but STILL SERVING: keep the inbound listener and the
    /// server login up so peers can keep downloading from us, and stop
    /// everything that initiates work.
    ///
    /// THE CALLER MUST ALREADY HOLD AN AUDIO KEEPALIVE. Without one iOS
    /// suspends the process within seconds and every socket this preserves dies
    /// anyway - so a caller that cannot start the keepalive must call `pause()`
    /// instead, and be honest on screen about which happened.
    pub fn pause_for_seeding(&self) {
        self.rt
            .block_on(async { self.inner.lock().await.pause_for_seeding().await });
    }

    /// App foregrounded again: rebuild and reconnect.
    pub fn resume(&self) {
        self.rt
            .block_on(async { self.inner.lock().await.resume().await });
    }

    /// Final checkpoint and stop.
    pub fn shutdown(&self) {
        self.rt
            .block_on(async { self.inner.lock().await.shutdown().await });
    }

    /// The current coarse lifecycle state.
    pub fn state(&self) -> EngineStateFfi {
        // LOCK-FREE. Measured 2026-08-07: an action issued during a search waits
        // ~12s behind it, and four of the five engine calls the 1s UI poll makes
        // were taking that lock to read a bool or a Copy enum. The status poll
        // must never queue behind network I/O.
        self.handles.state().into()
    }

    /// The persistent node identity.
    pub fn identity(&self) -> IdentityInfo {
        self.rt.block_on(async {
            let g = self.inner.lock().await;
            IdentityInfo {
                userhash: hex::encode(g.userhash()),
                kad_id: hex::encode(g.kad_id().to_hash()),
            }
        })
    }

    /// The live server login (address + HighID/LowID), or `None` when no server
    /// currently has us. HighID-vs-LowID decides whether peers can reach us, so
    /// this is the most useful line on the screen.
    pub fn server_info(&self) -> Option<ServerInfoFfi> {
        // LOCK-FREE. This was the FIFTH reader on the 1s UI poll and the one the
        // 2026-08-07 round missed: the other four moved to `EngineHandles` while
        // this kept taking the engine lock, so the whole "fast" poll still queued
        // behind every search - and since the Swift side runs it on the same
        // queue as the event drain, the status banners did too.
        self.handles.server_info().map(|s| ServerInfoFfi {
            addr: s.addr,
            name: s.name,
            low_id: s.low_id,
            related_search: s.related_search,
        })
    }

    /// How many Kad contacts the routing table holds.
    pub fn kad_contacts(&self) -> u32 {
        // LOCK-FREE, refreshed by `publish_status` on the heartbeat, so at most
        // one beat stale rather than blocking for the length of a search.
        self.handles.kad_contacts() as u32
    }

    /// The Servers screen: read server.met and PROBE each server's UDP status
    /// port, returning the list with liveness + fresh user/file counts. Blocks a
    /// few seconds while the pings resolve - run it off the UI thread. padMule
    /// does NOT auto-connect; the user picks a live (alive) server.
    pub fn server_list(&self) -> Vec<ServerEntryFfi> {
        self.rt.block_on(async {
            self.inner
                .lock()
                .await
                .probe_server_list()
                .await
                .into_iter()
                .map(|e| ServerEntryFfi {
                    addr: e.addr.to_string(),
                    name: e.name,
                    users: e.users.unwrap_or(0),
                    files: e.files.unwrap_or(0),
                    alive: e.alive,
                    connected: e.connected,
                    pinned: e.pinned,
                    checking: e.checking,
                })
                .collect()
        })
    }

    /// Fetch a server.met from `url` (plain http) and MERGE it into the on-disk
    /// list - existing servers (and tags) are kept, only new ones appended. Call
    /// `server_list()` afterwards to re-probe. Blocks on the fetch; off the UI
    /// thread. The default list URL is `http://upd.emule-security.org/server.met`.
    pub fn update_server_list(&self, url: String) -> ServerListUpdate {
        self.rt.block_on(async {
            match self.inner.lock().await.update_server_list(&url).await {
                EngineServerListUpdate::Updated { added, total } => {
                    ServerListUpdate::Updated { added, total }
                }
                EngineServerListUpdate::BadUrl => ServerListUpdate::BadUrl,
                EngineServerListUpdate::NotServerMet => ServerListUpdate::NotServerMet,
                EngineServerListUpdate::Unreachable => ServerListUpdate::Unreachable,
            }
        })
    }

    /// Pin/unpin a server ("ip:port"); a pinned server survives `prune_dead_servers`.
    pub fn set_server_pinned(&self, addr: String, pinned: bool) {
        self.rt
            .block_on(async { self.inner.lock().await.set_server_pinned(&addr, pinned) });
    }

    /// Probe the list and drop every dead, unpinned server, rewriting server.met.
    /// Returns how many were removed. Blocks ~3s on the probe; off the UI thread.
    pub fn prune_dead_servers(&self) -> u32 {
        self.rt
            .block_on(async { self.inner.lock().await.prune_dead_servers().await })
    }

    /// Recursively crawl known servers for the OTHER servers they know (asking
    /// up to `rounds`, clamped to 3), merging the safe survivors into
    /// server.met. Returns how many NEW servers were added. Silence from most
    /// servers is normal - few answer this request. Blocks for several
    /// seconds, like a search; off the UI thread.
    pub fn crawl_servers(&self, rounds: u32) -> u32 {
        self.rt
            .block_on(async { self.inner.lock().await.crawl_servers(rounds).await })
    }

    /// Connect to the server at `addr` ("ip:port"). Returns false if the address
    /// is malformed or the login was refused/timed out. Blocks up to ~12s.
    pub fn connect_to_server(&self, addr: String) -> bool {
        let Ok(sa) = addr.parse::<std::net::SocketAddr>() else {
            return false;
        };
        self.rt
            .block_on(async { self.inner.lock().await.connect_to_server(sa).await })
    }

    /// Disconnect from the current server at the user's request (Kad + downloads
    /// keep running).
    pub fn disconnect_server(&self) {
        self.rt
            .block_on(async { self.inner.lock().await.disconnect_server().await });
    }

    /// Cumulative session transfer totals (down, up) in bytes. Polled by the UI
    /// to draw the rate history + ratio; monotonic, so sampling is race-free.
    pub fn transfer_stats(&self) -> TransferStats {
        let (total_down, total_up) = self.handles.transfer_totals();
        TransferStats {
            total_down,
            total_up,
        }
    }

    /// Whether padMule serves the files it has to other peers. `false` is
    /// "Leech Mode": downloading still works, but nothing is uploaded.
    pub fn is_sharing(&self) -> bool {
        self.handles.is_sharing()
    }

    /// Turn uploading on or off. Off is the download-only "Leech Mode"; it takes
    /// effect on the next inbound peer, so no reconnect is needed.
    pub fn set_sharing(&self, on: bool) {
        self.rt
            .block_on(async { self.inner.lock().await.set_sharing(on) });
    }

    /// True while sharing is off BECAUSE the public address changed under us
    /// (a dropped VPN tunnel, a network switch). The UI keeps saying why until
    /// the user turns sharing back on, which clears it. Persists across
    /// launches: the engine restores it from disk at construction, so a fresh
    /// process still reports true here - and still refuses to serve - until
    /// the user resumes.
    pub fn sharing_paused_for_ip_change(&self) -> bool {
        self.handles.sharing_paused_for_ip_change() // LOCK-FREE
    }

    /// Override the eD2k ports. Takes effect on the NEXT start().
    ///
    /// `advertised` is what servers and peers are told; pass it equal to
    /// `listen` for the ordinary home-router case. They differ when an external
    /// forwarder maps one port to another - a VPN with remote-to-local port
    /// forwarding - and then peers must dial the EXTERNAL port while padMule
    /// listens on the local one.
    /// `kad_advertised` is the same split for Kad's UDP port: `kad` is BOUND
    /// (it must equal the local port the provider forwards TO) and this is what
    /// peers are told to dial. Pass it equal to `kad` for the same-port case.
    pub fn set_ports(&self, listen: u16, advertised: u16, kad: u16, kad_advertised: u16) {
        self.rt.block_on(async {
            self.inner
                .lock()
                .await
                .set_ports(listen, advertised, kad, kad_advertised)
        });
    }

    /// Turn the UPnP port-mapping attempt on or off. Off is correct on a VPN,
    /// where the provider does the forwarding and a mapping on the LAN router
    /// the tunnel bypasses accomplishes nothing.
    pub fn set_upnp_enabled(&self, on: bool) {
        self.rt
            .block_on(async { self.inner.lock().await.set_upnp_enabled(on) });
    }

    /// The "update server list when connecting" pref (eMule AddServersFromServer):
    /// a fresh login asks the server for its own server list (OP_GETSERVERLIST),
    /// feeding the gossip harvest. Defaults ON in the engine; takes effect on the
    /// next connect/resume.
    pub fn set_add_servers_from_server(&self, on: bool) {
        self.rt
            .block_on(async { self.inner.lock().await.set_add_servers_from_server(on) });
    }

    /// Snapshots of every in-progress download - NO ENGINE LOCK.
    ///
    /// This reads the downloads `Arc` and each `Download`'s own lock, so it
    /// keeps answering while a ~20s search or ~10s crawl holds `&mut Engine`.
    /// That is the whole point: the progress numbers are what the user watches,
    /// and they used to freeze for the entire search.
    ///
    /// It used to ALSO be the engine's heartbeat. That is now `heartbeat()` -
    /// reading is not maintenance, and bundling them is what forced the read to
    /// take the lock in the first place.
    pub fn downloads(&self) -> Vec<DownloadInfo> {
        self.rt.block_on(async {
            let mut out = Vec::new();
            let now = u64::from(mule_engine::credit_store::now_secs());
            let dls = self.handles.downloads().await;
            // Queued is derived by THE one admission rule the sweeps enforce
            // (mule_engine::multi_source::queued_flags) over rows built by
            // the one constructor (Download::admission_row - same staleness
            // window, same field order) and the same shared cap - not
            // re-implemented here.
            let mut rows = Vec::with_capacity(dls.len());
            for dl in &dls {
                rows.push(dl.admission_row(now).await);
            }
            let queued = mule_engine::multi_source::queued_flags(self.handles.max_active(), &rows);
            for (i, dl) in dls.iter().enumerate() {
                let size = dl.size().await;
                // `size` and `missing()` are read under separate locks, so the
                // pair is not an atomic snapshot; `saturating_sub` keeps a
                // transient `missing > size` from wrapping to a nonsense `have`
                // in release (or panicking across the FFI in debug).
                let have = size.saturating_sub(dl.missing().await);
                let (rating, has_comment) = dl.rating_summary().await;
                let origins = dl.source_origins().await;
                let parts = dl.part_availability().await;
                let pool = dl.source_pool();
                out.push(DownloadInfo {
                    hash: hex::encode(dl.hash().await),
                    name: dl.name().await,
                    size,
                    have,
                    complete: rows[i].1,
                    paused: rows[i].0,
                    queued: queued[i],
                    rating,
                    has_comment,
                    priority: dl.priority(),
                    preview: dl.is_preview(),
                    contiguous_prefix: dl.contiguous_prefix().await,
                    receiving: dl.is_receiving(now, RECEIVING_WINDOW_SECS),
                    sources_server: origins.0,
                    sources_kad: origins.1,
                    sources_exchange: origins.2,
                    sources_found: pool.0,
                    sources_callback: pool.1,
                    parts_needed: parts.0,
                    parts_unavailable: parts.1,
                    part_status_reports: parts.2,
                });
            }
            out
        })
    }

    /// THE ENGINE'S HEARTBEAT. The UI must call this about once a second.
    ///
    /// It drains pending share re-announces, finalizes downloads that completed
    /// outside a fetch task, detects a server drop/kick, runs the periodic
    /// checkpoint, unshares files deleted in the Files app, re-drives idle
    /// downloads, merges gossip-harvested servers into server.met, refreshes the
    /// Kad routing table, runs the Kad LIVENESS SWEEP (eMule's `OnSmallTimer`:
    /// probe the oldest due contact per bin, remove whoever failed to answer),
    /// and PUBLISHES one due shared file/keyword to the Kad DHT. That is TEN:
    /// the sentence said seven for as long as `maintain_kad` had existed,
    /// because it was added to the BODY without being added to the list that
    /// enumerates it - the same shape as a test that pins "these callers" and
    /// names all but one. It then drifted AGAIN across the language boundary
    /// (the Swift caller still said seven after this was corrected to eight),
    /// so the number now lives ONLY on this side of the seam - Swift's
    /// `EngineModel.refresh()` points here instead of keeping a copy - and
    /// `the_stated_heartbeat_duty_count_matches_the_calls_the_body_makes`
    /// derives the real count from the body and goes RED when this sentence,
    /// or the wiring comment below, disagrees.
    ///
    /// IF THIS STOPS BEING CALLED, all TEN stop SILENTLY - nothing errors and
    /// nothing on screen changes; downloads simply stall, finished files are
    /// never shared, and a kick goes unnoticed. It used to be a side effect of
    /// `downloads()`, which made it impossible to forget but also forced every
    /// progress read to queue behind a 20s search. Split deliberately; the
    /// coupling is now a caller obligation, stated here because that is the
    /// price of the split.
    ///
    /// ONE LOCK PER DUTY, NOT ONE FOR THE WHOLE BEAT (2026-08-07). These are
    /// independent maintainers that already ran in sequence, but they took the
    /// engine lock ONCE between them - so a beat that happened to include a Kad
    /// refresh (up to 3s) and an idle-download retry (up to 6s) held the lock for
    /// most of ten seconds, and every user action issued in that window waited
    /// behind ALL of it. Releasing between duties makes the worst wait the
    /// longest SINGLE duty instead of their sum; a user action simply interleaves
    /// at the next boundary. Nothing here depends on another duty's state within
    /// the same beat - anything that slips past one boundary is picked up by the
    /// next beat a second later, which is what these maintainers already assume.
    pub fn heartbeat(&self) {
        self.rt.block_on(async {
            self.inner.lock().await.maintain_shares().await;
            self.inner.lock().await.finalize_completed().await;
            self.inner.lock().await.poll_server_drop().await;
            self.inner.lock().await.maintain_checkpoint().await;
            self.inner.lock().await.maintain_share_verify().await;
            self.inner.lock().await.maintain_resume_fetches().await;
            self.inner.lock().await.maintain_server_harvest().await;
            // Kad routing-table maintenance. Rate-limited to KAD_REFRESH_EVERY
            // inside, so calling it every heartbeat costs a comparison.
            self.inner.lock().await.maintain_kad().await;
            // The OTHER half of Kad maintenance (eMule's OnSmallTimer): age
            // contacts, probe the oldest due one per bin, remove whoever failed
            // to answer. Rate-limited to KAD_SWEEP_EVERY inside.
            self.inner.lock().await.maintain_kad_liveness().await;
            // PUBLISH one due shared file/keyword to the Kad DHT (eMule's STORE
            // half). Rate-limited to KAD_PUBLISH_EVERY inside, one job per
            // pass, bounded at KAD_PUBLISH_BUDGET. DUTY TEN - if you add
            // another, update the count HERE and in the doc above; the
            // source-scan test named there stays RED until both agree with
            // the body. Swift states no number any more (its refresh() points
            // at this roster), because a count across the language boundary
            // is one no Rust test can reach - which is how this drifted FIVE
            // times (7->8->9->10, and a wiki page was still saying eight on
            // 2026-08-09) before it was pinned.
            self.inner.lock().await.maintain_kad_publish().await;
            // Refresh the derived status values LAST, so what the lock-free
            // readers see reflects everything this beat just did.
            self.inner.lock().await.publish_status();
        });
    }

    /// The sources connected for one download (per-source detail). Empty for an
    /// unknown/finished hash.
    pub fn download_sources(&self, hash: String) -> Vec<SourceInfoFfi> {
        let Some(h) = parse_hash16(&hash) else {
            return Vec::new();
        };
        self.rt.block_on(async {
            self.inner
                .lock()
                .await
                .download_sources(h)
                .await
                .into_iter()
                .map(|s| SourceInfoFfi {
                    addr: s.addr.to_string(),
                    software: s.software,
                    obfuscated: s.obfuscated,
                    low_id: s.low_id,
                    verified: s.verified,
                    rating: s.rating,
                    comment: s.comment,
                })
                .collect()
        })
    }

    /// Stop serving one shared file (keeps the file on disk). Returns false if
    /// that hash was not being shared.
    pub fn unshare_file(&self, hash: String) -> bool {
        let Some(h) = parse_hash16(&hash) else {
            return false;
        };
        self.rt
            .block_on(async { self.inner.lock().await.unshare_file(h).await })
    }

    /// How many IP-blocklist ranges are loaded (0 = no filter placed).
    pub fn ip_filter_ranges(&self) -> u32 {
        self.handles.ip_filter_ranges() as u32 // LOCK-FREE
    }

    /// Whether a router port mapping is currently held. The UI needs this to stay
    /// HONEST about the Stop action: a user on cellular, behind CGNAT, or on a
    /// router without UPnP never had a mapping, so telling them the port was
    /// "handed back" would describe work that never happened. A boolean, never
    /// the address - that is our public IP.
    pub fn has_port_mapping(&self) -> bool {
        self.handles.has_port_mapping()
    }

    /// Snapshots of the shared library - the complete files we serve to peers.
    pub fn shared_files(&self) -> Vec<SharedFileInfo> {
        self.rt.block_on(async {
            self.handles
                .shared_files()
                .await
                .into_iter()
                .map(|(hash, name, size, rating, comment)| SharedFileInfo {
                    hash: hex::encode(hash),
                    name,
                    size,
                    rating,
                    comment,
                })
                .collect()
        })
    }

    /// Set the local user's own rating (0-5, 0 = clear) and comment on a shared
    /// file, persisted and served to downloaders via OP_FILEDESC. Returns false
    /// if that hash is not in the shared library.
    pub fn set_file_rating(&self, hash: String, rating: u8, comment: String) -> bool {
        let Some(h) = parse_hash16(&hash) else {
            return false;
        };
        self.rt.block_on(async {
            self.inner
                .lock()
                .await
                .set_file_rating(h, rating, comment)
                .await
        })
    }

    /// Set a download's priority: 0 = Low, 1 = Normal, 2 = High (an unknown
    /// value clamps to Normal). Persisted and honored by the running fetch.
    /// Returns false if that hash is not an active download.
    pub fn set_download_priority(&self, hash: String, priority: u8) -> bool {
        let Some(h) = parse_hash16(&hash) else {
            return false;
        };
        self.rt.block_on(async {
            self.inner
                .lock()
                .await
                .set_download_priority(h, priority)
                .await
        })
    }

    /// Turn preview mode on/off for a download - biases block selection so the
    /// file grows contiguously from the start (playable while incomplete).
    /// Returns false if that hash is not an active download.
    pub fn set_preview(&self, hash: String, on: bool) -> bool {
        let Some(h) = parse_hash16(&hash) else {
            return false;
        };
        self.rt
            .block_on(async { self.inner.lock().await.set_preview(h, on).await })
    }

    /// Copy the contiguous-from-start prefix of a download to `dest_path` (a file
    /// the UI hands to a media player), returning the bytes written. 0 if the hash
    /// is unknown, nothing contiguous is available yet, or the copy failed. The
    /// engine lock is held ONLY to resolve the source path + length; the copy runs
    /// on a blocking thread with NO lock held, so snapshotting a large prefix never
    /// stalls the download or the 1s heartbeat.
    pub fn preview_snapshot(&self, hash: String, dest_path: String) -> u64 {
        let Some(h) = parse_hash16(&hash) else {
            return 0;
        };
        self.rt.block_on(async {
            let Some((src, len)) = self.inner.lock().await.preview_target(h).await else {
                return 0;
            };
            let dest = std::path::PathBuf::from(dest_path);
            tokio::task::spawn_blocking(move || {
                mule_engine::copy_file_prefix(&src, &dest, len).unwrap_or(0)
            })
            .await
            .unwrap_or(0)
        })
    }

    /// Search the connected server. BLOCKS for up to ~20s waiting on the
    /// server, so call it off the UI thread. Empty means no server, no answer,
    /// or genuinely no hits - all of which the UI renders the same way.
    pub fn search(&self, keyword: String, filters: SearchFilters) -> SearchOutcome {
        self.rt.block_on(async {
            let mut g = self.inner.lock().await;
            let outcome = g.search(&keyword, filters.into()).await;
            search_outcome_to_ffi(&g, outcome).await
        })
    }

    /// Fetch the next page of the last search and merge it into the results -
    /// eMule's "Load more results" (server-only). Only meaningful right after a
    /// `search` whose outcome had `more_available = true`; otherwise it returns
    /// the current results with `more_available = false`. Blocks up to ~20s.
    pub fn search_more(&self) -> SearchOutcome {
        self.rt.block_on(async {
            let mut g = self.inner.lock().await;
            let outcome = g.search_more().await;
            search_outcome_to_ffi(&g, outcome).await
        })
    }

    /// Related-files search: find the files a server's index associates with this
    /// hash (eMule's `related::` feature). Returns empty when the hash is
    /// malformed or the connected server does not advertise related-search
    /// support - the UI checks `ServerInfoFfi::related_search` and falls back to a
    /// filename keyword search in that case. Results have the same shape as
    /// `search`, so the UI renders them through the same list.
    pub fn related_search(&self, hash: String) -> SearchOutcome {
        let Some(h) = parse_hash16(&hash) else {
            return SearchOutcome::Results {
                hits: Vec::new(),
                more_available: false,
            };
        };
        self.rt.block_on(async {
            let mut g = self.inner.lock().await;
            let outcome = g.related_search(h).await;
            search_outcome_to_ffi(&g, outcome).await
        })
    }

    /// Start downloading a search hit. Returns as soon as the transfer is
    /// registered, NOT when the file lands - watch `downloads()` for progress.
    /// Blocks briefly (up to ~10s) asking the server for sources.
    pub fn add_download(&self, hash: String, size: u64, name: String) -> AddOutcome {
        let Some(h) = parse_hash16(&hash) else {
            return AddOutcome::Rejected {
                reason: "malformed file hash".to_string(),
            };
        };
        self.rt.block_on(async {
            self.inner
                .lock()
                .await
                .add_download(h, size, &name)
                .await
                .into()
        })
    }

    /// Cancel and remove an in-progress download, deleting its part files.
    /// Returns false if no download with that hash is active. Blocks briefly.
    pub fn cancel_download(&self, hash: String) -> bool {
        let Some(h) = parse_hash16(&hash) else {
            return false;
        };
        self.rt
            .block_on(async { self.inner.lock().await.cancel_download(h).await })
    }

    /// Pause ONE download (eMule 0.70b PauseFile): its workers stop within a
    /// block, the entry and bytes stay, and the pause persists across
    /// restarts (part.met FT_STATUS). Returns false for an unknown hash.
    pub fn pause_download(&self, hash: String) -> bool {
        let Some(h) = parse_hash16(&hash) else {
            return false;
        };
        self.rt
            .block_on(async { self.inner.lock().await.pause_download(h).await })
    }

    /// Resume a paused download (eMule 0.70b ResumeFile). The next retry
    /// sweep re-drives it, subject to the max-active admission.
    pub fn resume_download(&self, hash: String) -> bool {
        let Some(h) = parse_hash16(&hash) else {
            return false;
        };
        self.rt
            .block_on(async { self.inner.lock().await.resume_download(h).await })
    }

    /// Set the max-active download cap (0 = unlimited): how many incomplete,
    /// unpaused downloads the fetch pipeline drives at once; the rest report
    /// `queued` and are admitted in add order as slots free.
    pub fn set_max_active_downloads(&self, n: u32) {
        self.rt
            .block_on(async { self.inner.lock().await.set_max_active_downloads(n) });
    }

    /// THE FETCH FUNNEL, as a printable block: how far down the eD2k request
    /// sequence each peer session got, every opcode read out of turn, and the
    /// dial-duration histogram. See `mule_engine::stats`.
    ///
    /// LOCK-FREE ON PURPOSE - it reads process-global atomics and never touches
    /// the engine lock. That is the whole point: a stalled download is exactly
    /// when the engine is busy, and a diagnostic that queued behind `search` or
    /// a source hunt would be unreadable precisely when it is needed (the same
    /// reasoning as the lock-free status polls).
    pub fn fetch_report(&self) -> String {
        mule_engine::stats::fetch_report()
    }

    /// THE KAD LOOKUP PROFILE, as a printable block: time to first result and
    /// to completion per value lookup, requests sent / answered / timed out
    /// per kind, a per-request RTT histogram with timeouts as their own row,
    /// and the in-flight high-water mark.
    ///
    /// The previous panel counted lookup ROUNDS and rounds held open by a
    /// silent peer; it answered its question (57% silent - build-progress row
    /// 8cm, the before-figure) and the lookup went EVENT-DRIVEN (eMule
    /// CSearch: per-request deadlines, value asks interleaved), so rounds no
    /// longer exist to count. See `mule_engine::stats` for why each field
    /// survives the rewrite.
    ///
    /// LOCK-FREE, like `fetch_report` and for the same reason.
    pub fn kad_report(&self) -> String {
        mule_engine::stats::kad_report()
    }

    /// Zero the fetch counters AND the Kad lookup profile - both panels are
    /// diagnostics and share one Reset, so a reset -> reproduce -> read cycle
    /// covers everything on the Stats screen. They are cumulative since LAUNCH,
    /// so by the time something is worth investigating they are dominated by the
    /// healthy minutes before it. Session byte totals are NOT reset.
    pub fn reset_fetch_stats(&self) {
        mule_engine::stats::reset_fetch_stats();
        mule_engine::stats::reset_kad_stats();
    }

    /// Drain and return every engine event queued since the last call. The UI
    /// polls this (e.g. on a timer) to observe state/progress changes.
    pub fn drain_events(&self) -> Vec<EngineEventFfi> {
        self.rt.block_on(async {
            let mut rx = self.events.lock().await;
            let mut out = Vec::new();
            while let Ok(e) = rx.try_recv() {
                out.push(e.into());
            }
            out
        })
    }
}

/// The fetch funnel as a free function, for the stress harness - which prints it
/// without holding a `MuleEngine`. See `mule_engine::stats`.
///
/// The app reads the same report through `MuleEngine::fetch_report` above, which
/// IS exported (Stats -> Fetch diagnostics, shipped in build-progress row 8bv).
/// This doc used to say the Swift binding deliberately had no method for it;
/// that was true when the funnel was harness-only and stopped being true the day
/// the on-device panel landed, thirty lines up from here.
pub fn fetch_report() -> String {
    mule_engine::stats::fetch_report()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!("padmule-ffi-{tag}-{}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    /// Build the facade with the engine forced OFFLINE (no list fetch, no server
    /// dial, no 4662 bind) so facade tests stay hermetic. `set_offline` is
    /// deliberately not exported - the app must never silently run offline - so
    /// tests assemble the facade by hand instead of going through `new()`.
    fn offline_engine(config_dir: &str, downloads_dir: &str) -> Arc<MuleEngine> {
        let (mut engine, rx) = Engine::new(config_dir).unwrap();
        engine.set_downloads_dir(downloads_dir);
        engine.set_offline(true);
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let handles = engine.handles();
        Arc::new(MuleEngine {
            rt,
            handles,
            inner: Mutex::new(engine),
            events: Mutex::new(rx),
        })
    }

    #[test]
    fn the_ui_polls_answer_while_the_engine_lock_is_held() {
        // THE POINT OF THE SPLIT. Engine::search holds `&mut Engine` across its
        // whole tokio::join! of the server, Kad and global arms - up to ~20s -
        // and every UI poll used to queue behind that, so the transfer numbers
        // froze for the entire search.
        //
        // Hold the engine lock explicitly and prove the five read-only polls
        // still answer. If any of them regresses to taking `inner`, this test
        // does not fail slowly - it DEADLOCKS, which the timeout below turns
        // into a clean failure.
        let dir = tmp("lockfree");
        let _ = std::fs::create_dir_all(&dir);
        let e = offline_engine(&dir, &dir);
        let e2 = Arc::clone(&e);

        // A thread parks on the engine mutex, standing in for a long search.
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            e2.rt.block_on(async {
                let _guard = e2.inner.lock().await;
                tx.send(()).unwrap();
                // Keep holding until the reads are done.
                let _ = done_rx.recv();
            });
        });
        rx.recv().unwrap(); // the lock is now held

        let reads = std::thread::spawn(move || {
            let _ = e.downloads();
            let _ = e.shared_files();
            let _ = e.is_sharing();
            let _ = e.transfer_stats();
            let _ = e.has_port_mapping();
            "read"
        });
        // Generous: this either returns in microseconds or never.
        std::thread::sleep(std::time::Duration::from_secs(3));
        assert!(
            reads.is_finished(),
            "a UI poll blocked on the engine lock - the split regressed"
        );
        assert_eq!(reads.join().unwrap(), "read");

        done_tx.send(()).unwrap();
        holder.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_hit_has_the_rich_fields() {
        // Compile-level guarantee that the record carries the new shape.
        let h = SearchHit {
            origin: "server + kad".to_string(),
            hash: "00".to_string(),
            name: "x".to_string(),
            size: 1,
            sources: 2,
            complete_sources: 1,
            file_type: "Audio".to_string(),
            artist: "a".to_string(),
            album: "b".to_string(),
            title: "c".to_string(),
            length_secs: 10,
            bitrate: 128,
            codec: "mp3".to_string(),
            rating: 4,
            trusted: true,
            warning: String::new(),
            status: HitStatusFfi::New,
        };
        assert_eq!(h.file_type, "Audio");
        assert_eq!(h.rating, 4);
        assert_eq!(h.status, HitStatusFfi::New);
    }

    /// The per-file pause/resume and max-active surface (row 8dd): unknown and
    /// malformed hashes answer false through the whole stack, and the cap
    /// setter provably writes the engine's shared atomic - read back through
    /// `handles.max_active()`, the SAME value `downloads()` feeds to
    /// `queued_flags`. What the cap DOES to rows is engine-tested
    /// (`the_max_active_cap_gates_the_retry_sweep_and_pausing_promotes`, the
    /// two-sweep test); rows cannot be registered here, because the offline
    /// engine's `add_download` refuses with `NotConnected` before creating one.
    #[test]
    fn pause_resume_and_the_max_active_cap_surface_through_the_facade() {
        let dir = tmp("pause-facade");
        let _ = std::fs::remove_dir_all(&dir);
        let eng = offline_engine(&dir, &format!("{dir}-dl"));
        // Unknown hashes answer a clean false through the whole stack.
        assert!(!eng.pause_download("00".repeat(16)));
        assert!(!eng.resume_download("ff".repeat(16)));
        assert!(!eng.pause_download("not-hex".into()), "malformed hash");
        // Default first, so the 3 below is provably WRITTEN by the setter
        // rather than a lucky initial value.
        assert_eq!(eng.handles.max_active(), 0, "the default is 0 = unlimited");
        eng.set_max_active_downloads(3);
        assert_eq!(
            eng.handles.max_active(),
            3,
            "the FFI setter must reach the engine's shared cap atomic"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The "Share uploads" / Leech-Mode setting round-trips through the facade.
    #[test]
    fn sharing_setting_round_trips_via_the_facade() {
        let dir = tmp("sharing");
        let _ = std::fs::remove_dir_all(&dir);
        // offline_engine, not MuleEngine::new: keep the test hermetic even if a
        // future edit adds a start() (the exact drift the 8aa lint fixed once).
        let eng = offline_engine(&dir, &format!("{dir}-dl"));
        assert!(eng.is_sharing(), "sharing defaults ON");
        eng.set_sharing(false);
        assert!(!eng.is_sharing(), "Leech Mode: sharing OFF");
        eng.set_sharing(true);
        assert!(eng.is_sharing(), "back ON");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every search wire-filter setting maps to the engine query as designed:
    /// "complete only" -> min_sources >= 1, the size bounds appear only when set,
    /// and the global toggle passes through.
    #[test]
    fn search_filter_settings_map_to_the_wire() {
        let off: EngineSearchFilters = SearchFilters {
            complete_only: false,
            min_size: 0,
            max_size: 0,
            global: false,
        }
        .into();
        assert_eq!(off.min_sources, None);
        assert_eq!(off.min_size, None);
        assert_eq!(off.max_size, None);
        assert!(!off.global);

        let on: EngineSearchFilters = SearchFilters {
            complete_only: true,
            min_size: 1024,
            max_size: 4096,
            global: true,
        }
        .into();
        assert_eq!(
            on.min_sources,
            Some(1),
            "complete-only -> at least one source"
        );
        assert_eq!(on.min_size, Some(1024));
        assert_eq!(on.max_size, Some(4096));
        assert!(on.global);
    }

    // Not a #[tokio::test]: the facade owns its own runtime and block_on would
    // panic inside an ambient one.
    #[test]
    fn facade_drives_lifecycle_and_surfaces_events() {
        let dir = tmp("life");
        let _ = std::fs::remove_dir_all(&dir);
        let dl_dir = format!("{dir}-downloads");
        let eng = offline_engine(&dir, &dl_dir);

        assert_eq!(eng.state(), EngineStateFfi::Stopped);
        // Identity is a 32-hex-char userhash.
        assert_eq!(eng.identity().userhash.len(), 32);

        eng.start();
        assert_eq!(eng.state(), EngineStateFfi::Running);
        eng.pause();
        assert_eq!(eng.state(), EngineStateFfi::Paused);
        eng.resume();
        assert_eq!(eng.state(), EngineStateFfi::Running);

        // The lifecycle emitted observable events, including the reconnect banner.
        let evs = eng.drain_events();
        assert!(evs.iter().any(|e| matches!(
            e,
            EngineEventFfi::State {
                state: EngineStateFfi::Running
            }
        )));
        assert!(evs
            .iter()
            .any(|e| matches!(e, EngineEventFfi::Status { text } if text == "Reconnecting...")));

        eng.shutdown();
        assert_eq!(eng.state(), EngineStateFfi::Stopped);
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dl_dir);
    }

    /// THE STATUS POLL MUST NOT QUEUE BEHIND A LONG ENGINE OPERATION.
    ///
    /// Measured on device 2026-08-07: a "Refresh server list" tapped 1.9s into a
    /// search took 20.62s against 7.5-9.3s idle. Four of the five engine calls
    /// the 1s UI poll makes were taking the engine lock - to read a `bool`, a
    /// `Copy` enum, and an `Arc::len`. A search can hold that lock for twenty
    /// seconds.
    ///
    /// This test HOLDS THE LOCK and asserts the readers still answer. It fails -
    /// by timing out rather than by assertion - the moment any of them goes back
    /// to `inner.lock()`, which is precisely how the regression would otherwise
    /// return unnoticed.
    ///
    /// IT COVERED FOUR OF THE FIVE, AND THAT IS WHY THE FIFTH SURVIVED. The
    /// commit that added this listed `server_info` among the calls it had made
    /// lock-free and left it on `inner.lock()`; the test went green because it
    /// never called it. A test that pins "these readers" has to name every one of
    /// them, or the missing name is exactly where the defect hides.
    #[test]
    fn the_status_readers_answer_while_the_engine_lock_is_held() {
        let dir = std::env::temp_dir().join(format!("padmule-ffi-lockfree-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let e = MuleEngine::new(
            dir.to_string_lossy().into_owned(),
            dir.to_string_lossy().into_owned(),
        )
        .unwrap();

        // Take the engine lock and hold it well past any plausible read.
        let held = std::sync::Arc::clone(&e);
        let (tx, rx) = std::sync::mpsc::channel();
        let hog = std::thread::spawn(move || {
            held.rt.block_on(async {
                let _g = held.inner.lock().await;
                tx.send(()).unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            });
        });
        rx.recv().unwrap(); // the lock is now definitely held

        // EVERY read the Swift `refreshFast()` makes, in the order it makes them.
        // Adding one to that closure without adding it here is what let
        // `server_info` stay lock-taking on the lock-free queue.
        let t0 = std::time::Instant::now();
        let _ = e.state();
        let _ = e.kad_contacts();
        let _ = e.ip_filter_ranges();
        let _ = e.sharing_paused_for_ip_change();
        let _ = e.server_info();
        let _ = e.downloads();
        let _ = e.shared_files();
        let _ = e.is_sharing();
        let _ = e.transfer_stats();
        let _ = e.has_port_mapping();
        let elapsed = t0.elapsed();

        assert!(
            elapsed < std::time::Duration::from_millis(500),
            "the status readers took {elapsed:?} while the engine lock was held - \
             one of them is taking the lock again, so the UI will freeze for the \
             length of every search"
        );
        hog.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE STATED HEARTBEAT DUTY COUNT CANNOT ROT. The prose above
    /// `heartbeat()` says how many background duties the beat drives, and that
    /// number drifted FIVE times (7->8->9->10, plus a wiki page still saying
    /// eight on 2026-08-09) because nothing pinned it: a duty was added to the
    /// BODY without being added to the sentence that counts it.
    ///
    /// Two INDEPENDENT sides, in the spirit of mule-engine's
    /// `every_kad_counter_reaches_the_reset`:
    /// - the CODE side scans `heartbeat()`'s own body for the engine calls it
    ///   actually makes, minus the one deliberately framed as a refresh (the
    ///   status publish);
    /// - the PROSE side is the literal phrases "That is <N>:", "all <N> stop"
    ///   and "DUTY <N>" that state the count, where <N> is the number word
    ///   RENDERED FROM THE CODE COUNT, not written into this test.
    ///
    /// Add an eleventh duty without touching the prose and the rendered word
    /// moves while the phrases stand still - RED. Bump the prose without
    /// adding the duty and the phrases move while the rendered word stands
    /// still - RED. The expected number appears nowhere in this test, and no
    /// phrase is spelled out here with a real number word inside it, so the
    /// whole-file scan can never match the test against itself.
    ///
    /// What it CANNOT catch: a duty that skips the one-lock-per-duty pattern
    /// (batched under a shared guard, or driven through `self.handles`); a
    /// second refresh-not-duty call (conservatively RED until the exclusion
    /// below names it); and any count stated OUTSIDE this file - which is
    /// exactly why Swift's `EngineModel.refresh()` no longer states one, and
    /// why the wiki sites belong to the KB pass, not to this test.
    #[test]
    fn the_stated_heartbeat_duty_count_matches_the_calls_the_body_makes() {
        let src = include_str!("lib.rs");
        // concat!, so this test's own source cannot match the marker.
        let sig = concat!("pub fn heart", "beat(&self)");
        let start = src.find(sig).expect("heartbeat() not found in lib.rs");
        // The body ends at the first close brace back at method indent.
        let end = src[start..]
            .find("\n    }")
            .expect("heartbeat() body end not found");
        let body = &src[start..start + end];

        // Every engine call the beat makes takes the lock per duty, so the
        // lock-take is the countable footprint of a duty.
        let engine_calls = body.matches("self.inner.lock().await.").count();
        let refreshes = body.matches(concat!("publish", "_status")).count();
        assert_eq!(
            refreshes, 1,
            "the beat should end with exactly ONE status refresh; a second \
             refresh-not-duty call must be named in this exclusion"
        );
        let duties = engine_calls - refreshes;

        const WORDS: [&str; 17] = [
            "ZERO", "ONE", "TWO", "THREE", "FOUR", "FIVE", "SIX", "SEVEN", "EIGHT", "NINE", "TEN",
            "ELEVEN", "TWELVE", "THIRTEEN", "FOURTEEN", "FIFTEEN", "SIXTEEN",
        ];
        assert!(duties < WORDS.len(), "{duties} duties - extend WORDS");
        let word = WORDS[duties];

        // Scan the whole file, so a phrase moved within it still counts.
        for phrase in [
            format!("That is {word}:"),
            format!("all {word} stop"),
            format!("DUTY {word}"),
        ] {
            assert!(
                src.contains(&phrase),
                "heartbeat() drives {duties} duties but the prose never says \
                 {phrase:?} - the stated count has drifted from the body \
                 again; update the doc comment and the wiring comment (Swift \
                 states no number by design, and the wiki sites are the KB \
                 pass's job)"
            );
        }
    }
}
