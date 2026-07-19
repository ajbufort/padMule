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
    SearchFilters as EngineSearchFilters, Trust,
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
}

impl From<EngineState> for EngineStateFfi {
    fn from(s: EngineState) -> Self {
        match s {
            EngineState::Stopped => EngineStateFfi::Stopped,
            EngineState::Running => EngineStateFfi::Running,
            EngineState::Paused => EngineStateFfi::Paused,
        }
    }
}

/// An observable engine event, flattened for FFI (the progress hash is hex).
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum EngineEventFfi {
    State { state: EngineStateFfi },
    Status { text: String },
    Server { text: String },
    Kad { contacts: u32 },
    Progress { hash: String, have: u64, total: u64 },
}

impl From<EngineEvent> for EngineEventFfi {
    fn from(e: EngineEvent) -> Self {
        match e {
            EngineEvent::State(s) => EngineEventFfi::State { state: s.into() },
            EngineEvent::Status(text) => EngineEventFfi::Status { text },
            EngineEvent::Server(text) => EngineEventFfi::Server { text },
            EngineEvent::Kad { contacts } => EngineEventFfi::Kad {
                contacts: contacts as u32,
            },
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
    NoServer,
    Rejected { reason: String },
}

impl From<AddResult> for AddOutcome {
    fn from(r: AddResult) -> Self {
        match r {
            AddResult::Started => AddOutcome::Started,
            AddResult::AlreadyAdded => AddOutcome::AlreadyAdded,
            AddResult::NoSources => AddOutcome::NoSources,
            AddResult::NoServer => AddOutcome::NoServer,
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

/// Map engine `RankedFile`s to FFI `SearchHit`s, tagging each with its
/// have/fetching/new status. Shared by `search` and `related_search`. `g` is
/// borrowed immutably, so call it AFTER the `&mut self` search has returned its
/// owned Vec - the borrows never overlap.
async fn ranked_to_hits(g: &Engine, ranked: Vec<RankedFile>) -> Vec<SearchHit> {
    let mut out = Vec::with_capacity(ranked.len());
    for r in ranked {
        let status = g.hit_status(r.hash).await.into();
        let trusted = r.is_trusted();
        let warning = match r.trust {
            Trust::Ok => String::new(),
            Trust::Suspect(why) => why.to_string(),
        };
        out.push(SearchHit {
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

/// The single object the native UI holds. Thread-safe; drive it with the
/// lifecycle methods and poll [`MuleEngine::drain_events`].
#[derive(uniffi::Object)]
pub struct MuleEngine {
    rt: Runtime,
    inner: Mutex<Engine>,
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
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| FfiError::Io {
                message: e.to_string(),
            })?;
        Ok(Arc::new(MuleEngine {
            rt,
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
        self.rt
            .block_on(async { self.inner.lock().await.state() })
            .into()
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
        self.rt.block_on(async {
            self.inner
                .lock()
                .await
                .server_info()
                .map(|s| ServerInfoFfi {
                    addr: s.addr,
                    low_id: s.low_id,
                    related_search: s.related_search,
                })
        })
    }

    /// How many Kad contacts the routing table holds.
    pub fn kad_contacts(&self) -> u32 {
        self.rt
            .block_on(async { self.inner.lock().await.kad_contacts() as u32 })
    }

    /// Cumulative session transfer totals (down, up) in bytes. Polled by the UI
    /// to draw the rate history + ratio; monotonic, so sampling is race-free.
    pub fn transfer_stats(&self) -> TransferStats {
        self.rt.block_on(async {
            let (total_down, total_up) = self.inner.lock().await.transfer_totals();
            TransferStats {
                total_down,
                total_up,
            }
        })
    }

    /// Whether padMule serves the files it has to other peers. `false` is
    /// "Leech Mode": downloading still works, but nothing is uploaded.
    pub fn is_sharing(&self) -> bool {
        self.rt
            .block_on(async { self.inner.lock().await.is_sharing() })
    }

    /// Turn uploading on or off. Off is the download-only "Leech Mode"; it takes
    /// effect on the next inbound peer, so no reconnect is needed.
    pub fn set_sharing(&self, on: bool) {
        self.rt
            .block_on(async { self.inner.lock().await.set_sharing(on) });
    }

    /// Snapshots of every in-progress download.
    pub fn downloads(&self) -> Vec<DownloadInfo> {
        self.rt.block_on(async {
            let mut g = self.inner.lock().await;
            let mut out = Vec::new();
            for dl in g.downloads().await {
                let size = dl.size().await;
                let have = size - dl.missing().await;
                let (rating, has_comment) = dl.rating_summary().await;
                out.push(DownloadInfo {
                    hash: hex::encode(dl.hash().await),
                    name: dl.name().await,
                    size,
                    have,
                    complete: dl.is_complete().await,
                    rating,
                    has_comment,
                    priority: dl.priority(),
                });
            }
            // The 1s downloads() poll is the engine's heartbeat: drain any pending
            // share change here, so a download that finished mid-session gets
            // re-announced to the server (OP_OFFERFILES) within about a second.
            g.maintain_shares().await;
            out
        })
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
        self.rt
            .block_on(async { self.inner.lock().await.ip_filter_ranges() as u32 })
    }

    /// Snapshots of the shared library - the complete files we serve to peers.
    pub fn shared_files(&self) -> Vec<SharedFileInfo> {
        self.rt.block_on(async {
            self.inner
                .lock()
                .await
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

    /// Search the connected server. BLOCKS for up to ~20s waiting on the
    /// server, so call it off the UI thread. Empty means no server, no answer,
    /// or genuinely no hits - all of which the UI renders the same way.
    pub fn search(&self, keyword: String, filters: SearchFilters) -> Vec<SearchHit> {
        self.rt.block_on(async {
            let mut g = self.inner.lock().await;
            let ranked = g.search(&keyword, filters.into()).await;
            ranked_to_hits(&g, ranked).await
        })
    }

    /// Related-files search: find the files a server's index associates with this
    /// hash (eMule's `related::` feature). Returns empty when the hash is
    /// malformed or the connected server does not advertise related-search
    /// support - the UI checks `ServerInfoFfi::related_search` and falls back to a
    /// filename keyword search in that case. Results have the same shape as
    /// `search`, so the UI renders them through the same list.
    pub fn related_search(&self, hash: String) -> Vec<SearchHit> {
        let Some(h) = parse_hash16(&hash) else {
            return Vec::new();
        };
        self.rt.block_on(async {
            let mut g = self.inner.lock().await;
            let ranked = g.related_search(h).await;
            ranked_to_hits(&g, ranked).await
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

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> String {
        std::env::temp_dir()
            .join(format!("padmule-ffi-{tag}-{}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn search_hit_has_the_rich_fields() {
        // Compile-level guarantee that the record carries the new shape.
        let h = SearchHit {
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

    // Not a #[tokio::test]: the facade owns its own runtime and block_on would
    // panic inside an ambient one.
    #[test]
    fn facade_drives_lifecycle_and_surfaces_events() {
        let dir = tmp("life");
        let _ = std::fs::remove_dir_all(&dir);
        let dl_dir = format!("{dir}-downloads");
        let eng = MuleEngine::new(dir.clone(), dl_dir.clone()).unwrap();

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
}
