//! The Engine facade: the single object the native UI drives, and the seam Wave
//! 8's UniFFI layer wraps. It owns the persistent identity and config directory,
//! runs the foreground/background lifecycle state machine, and emits an event
//! stream the UI observes.
//!
//! The lifecycle is the biggest deviation from desktop aMule (see
//! docs/wiki/ipados-constraints.md): iPadOS suspends a backgrounded app and
//! reclaims its sockets, so the honest model is foreground-only -
//!   - `pause()` (app backgrounded): checkpoint to disk, pause the server link,
//!     drop the Kad socket, abort the listener. Idempotent.
//!   - `resume()` (app foregrounded): rebind the listener FIRST (the HighID
//!     ordering), reconnect the server, re-bootstrap Kad - emitting
//!     "Reconnecting..." then "Connected". Idempotent, correct across an IP
//!     change.
//!
//! KNOWN GAP (candidate fix, not yet built): neither touches DOWNLOADS. An
//! in-flight fetch task keeps its own peer sockets across pause(), and a
//! download resumed from disk by `start()` gets no fetch task at all - only
//! `add_download` spawns one - so a restarted `.part` progresses only when a
//! called-back peer dials our listener.

use crate::bootstrap;
use crate::catalog::{catalog, tag_str, tag_u64, RankedFile};
use crate::connection::{ServerEvent, ServerState};
use crate::fetch::{download_file, ManagerConfig, PeerSource, SourceRegistry};
use crate::framed::FramedStream;
use crate::identity::NodeIdentity;
use crate::kad_live::KadNode;
use crate::link::ServerLink;
use crate::multi_source::{download_from_peer, resume_downloads, Download};
use crate::part_store::PartStore;
use crate::peer::HelloInfo;
use crate::peer_conn::peer_handshake_inbound;
use crate::search::{SearchParams, SearchResultFile};
use crate::server_messages::{LoginRequest, DEFAULT_SERVER_FLAGS};
use crate::share::{head_hash, is_upload_request, serve_shared, SharedFile, UploadGate};
use crate::transfer::build_file_req_ans_no_fil;
use mule_files::{
    read_nodes_dat, read_server_met, write_nodes_dat, IpFilter, KadContact, NodesDat,
    DEFAULT_IPFILTER_LEVEL,
};
use mule_kad::RoutingTable;
use mule_proto::{Kad128, Packet, Tag, TagValue};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// The ports padMule advertises and listens on (eD2k TCP, Kad UDP).
const TCP_PORT: u16 = 4662;
const KAD_UDP_PORT: u16 = 4672;

/// Decode a server.met IP uint32 (first octet in the LOW byte - the eD2k
/// convention, not network order).
fn ip_from_met_u32(ip: u32) -> Ipv4Addr {
    Ipv4Addr::new(
        ip as u8,
        (ip >> 8) as u8,
        (ip >> 16) as u8,
        (ip >> 24) as u8,
    )
}

/// A routing table's live contacts in the on-disk `nodes.dat` shape. Taking the
/// table (not a `&[Contact]`) keeps mule-kad's contact type out of this signature.
fn routing_to_nodes(rt: &RoutingTable) -> Vec<KadContact> {
    rt.contacts()
        .into_iter()
        .map(|c| KadContact {
            id: c.id,
            ip: c.ip,
            udp_port: c.udp_port,
            tcp_port: c.tcp_port,
            version: c.version,
            udp_key: 0,
            udp_key_ip: 0,
            verified: false,
        })
        .collect()
}

/// How long to wait for a server's search answer / source list. Servers reply in
/// well under this or not at all.
const SEARCH_WAIT: Duration = Duration::from_secs(20);
const SOURCES_WAIT: Duration = Duration::from_secs(10);

/// How long a Kad keyword lookup may run before we take whatever it has found.
/// Kad is the serverless half of search; bounded so a slow lookup never hangs
/// the box, and it runs concurrently with the server search so it is usually free.
const KAD_SEARCH_WAIT: Duration = Duration::from_secs(15);
/// Per-node wait during a Kad keyword lookup.
const KAD_PER_QUERY: Duration = Duration::from_millis(750);

/// How long to wait for an inbound peer to speak first. A leecher sends
/// OP_REQUESTFILENAME within a round-trip; a called-back LowID source stays
/// silent, waiting for us to drive the download of one of OUR files. This
/// timeout is what routes each connection to the right half of the listener.
const SERVE_PEEK: Duration = Duration::from_secs(3);

/// The most simultaneous uploads we grant. Modest by desktop standards (aMule
/// floors at 20) because an iPad on a phone uplink is not a seedbox; a peer that
/// finds us full is answered "no file" and moves on rather than swamping us.
const MAX_UPLOAD_SLOTS: usize = 8;
/// How many peers may wait for a slot before we decline further requests. A
/// small cap is honest for a foreground-only client (eMule's desktop default is
/// thousands, which assumes an always-on seedbox); a queued peer holds an open
/// connection here, so this also bounds fd/memory use.
const UPLOAD_QUEUE_CAP: usize = 32;
/// Total wall-clock budget for the resume-fetch pass in `start()`, and the
/// per-download cap on source-finding within it. Small so a batch of dead
/// downloads cannot stall startup (which holds the FFI engine lock).
const RESUME_BUDGET: Duration = Duration::from_secs(8);
const RESUME_PER_DL: Duration = Duration::from_secs(4);

/// The next free `NNN.part` index in `dir`. aMule numbers part files this way and
/// `resume_downloads` finds them by that name, so a new download MUST NOT reuse
/// an index some existing `.part.met` already claims - that would silently
/// clobber a transfer in progress.
fn next_part_index(dir: &Path) -> u32 {
    let mut max = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if let Some(n) = e
                .file_name()
                .to_string_lossy()
                .strip_suffix(".part.met")
                .and_then(|s| s.parse::<u32>().ok())
            {
                max = max.max(n);
            }
        }
    }
    max + 1
}

/// A filename safe to create in `downloads_dir`. P2P filenames are attacker
/// controlled: a name like `../../Library/Preferences/x` or one with a NUL
/// must not escape the directory we chose.
fn safe_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    if cleaned.is_empty() {
        "download".to_string()
    } else {
        cleaned
    }
}

/// A destination that does not overwrite an existing file: `name`, `name (2)`,
/// `name (3)`... Finishing a download must never silently destroy a file the
/// user already has.
fn unique_dest(dest: PathBuf) -> PathBuf {
    if !dest.exists() {
        return dest;
    }
    let dir = dest.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let stem = dest
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());
    let ext = dest.extension().map(|e| e.to_string_lossy().into_owned());
    for n in 2..1000 {
        let fname = match &ext {
            Some(e) => format!("{stem} ({n}).{e}"),
            None => format!("{stem} ({n})"),
        };
        let cand = dir.join(fname);
        if !cand.exists() {
            return cand;
        }
    }
    dest
}

/// The persisted shared-library file (upstream-faithful `known.met`): the
/// complete files we will re-serve after a restart. Lives in the config dir
/// alongside the other `.met` files; the actual bytes are in the downloads dir.
const KNOWN_MET: &str = "known.met";
const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;

/// Load the IP blocklist from the config dir if present. Reads `ipfilter.dat`
/// then `.p2p`/`guarding.p2p` (both text line-forms parse the same), at the
/// default filter level. Returns `None` if no file exists or nothing blocks.
fn load_ip_filter(config_dir: &Path) -> Option<Arc<IpFilter>> {
    let candidates = ["ipfilter.dat", "ipfilter.p2p", "guarding.p2p"];
    let mut text = String::new();
    for name in candidates {
        // Read as bytes + lossy, NOT read_to_string: real community lists carry
        // Latin-1/Windows-1252 bytes in the description field, and strict UTF-8
        // would discard the whole file (fail-open). The parser ignores
        // descriptions, so a lossy decode loads identical ranges.
        if let Ok(bytes) = std::fs::read(config_dir.join(name)) {
            text.push_str(&String::from_utf8_lossy(&bytes));
            text.push('\n');
        }
    }
    if text.trim().is_empty() {
        return None;
    }
    let filter = IpFilter::parse(&text, DEFAULT_IPFILTER_LEVEL);
    if filter.is_empty() {
        None
    } else {
        Some(Arc::new(filter))
    }
}

/// Rebuild the shared library from `known.met`: every complete file a prior
/// session saved that STILL exists on disk (a user can delete a file from the
/// Files app, and we must not advertise a source we can no longer serve). The
/// on-disk name is stored verbatim, so the path is `downloads_dir / name`.
fn load_shared_library(config_dir: &Path, downloads_dir: &Path) -> Vec<SharedFile> {
    let Ok(bytes) = std::fs::read(config_dir.join(KNOWN_MET)) else {
        return Vec::new();
    };
    let Ok(met) = mule_files::read_known_met(&bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in met.entries {
        let (Some(name), Some(size)) =
            (tag_str(&e.tags, FT_FILENAME), tag_u64(&e.tags, FT_FILESIZE))
        else {
            continue;
        };
        let path = downloads_dir.join(&name);
        // Re-share only if the file is still there AND its size matches what we
        // hashed. The downloads dir is the user-visible Files folder, so a file
        // can be deleted and a DIFFERENT one saved under the same name; sharing
        // the old hash would then serve bytes that fail the peer's hash check. A
        // size mismatch reliably flags a replaced/truncated file (we do not
        // re-hash a possibly-huge file on every launch to catch a same-size
        // edit - that is aMule's date-triggered rehash, out of scope on iOS).
        match std::fs::metadata(&path) {
            Ok(m) if m.len() == size => {}
            _ => continue,
        }
        out.push(SharedFile {
            hash: e.file_hash,
            size,
            name: name.into_bytes(),
            part_hashes: e.part_hashes,
            path,
        });
    }
    out
}

/// Append one finished file to `known.met` so it re-shares after a restart.
/// Idempotent by hash. Best-effort: a write failure just means it will not
/// persist, never a crash (the in-memory share still works this session).
fn persist_shared_file(config_dir: &Path, sf: &SharedFile) {
    let path = config_dir.join(KNOWN_MET);
    let mut met = std::fs::read(&path)
        .ok()
        .and_then(|b| mule_files::read_known_met(&b).ok())
        .unwrap_or(mule_files::KnownMet {
            header: mule_files::MET_HEADER,
            entries: Vec::new(),
        });
    if met.entries.iter().any(|e| e.file_hash == sf.hash) {
        return;
    }
    // A file past the 32-bit boundary needs the large-file header + a U64 size
    // tag; otherwise the 32-bit form (matches mule-files' own writer choice).
    let large = sf.size > mule_proto::OLD_MAX_FILE_SIZE;
    if large {
        met.header = mule_files::MET_HEADER_WITH_LARGEFILES;
    }
    let size_val = if large {
        TagValue::U64(sf.size)
    } else {
        TagValue::U32(sf.size as u32)
    };
    let date = std::fs::metadata(&sf.path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    met.entries.push(mule_files::KnownFileEntry {
        date,
        file_hash: sf.hash,
        part_hashes: sf.part_hashes.clone(),
        tags: vec![
            Tag::id(FT_FILENAME, TagValue::Str(sf.name.clone())),
            Tag::id(FT_FILESIZE, size_val),
        ],
    });
    // Atomic: write a temp file then rename over known.met, so a crash mid-write
    // cannot leave a torn file that load_shared_library would read as empty and
    // silently reset the whole library.
    let bytes = mule_files::write_known_met(&met);
    let tmp = path.with_extension("met.tmp");
    if std::fs::write(&tmp, &bytes).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Verify a finished download and move it into place.
///
/// The whole-file ed2k hash is checked FIRST, and this is not belt-and-braces:
/// `download_file` never calls `verify_ready_parts`, and a file of one part has
/// no part hash to verify against at all, so this is the ONLY thing standing
/// between corrupt bytes and the user's Files app. We asked for hash X; we hand
/// over hash X or nothing. It is computed part-by-part so a large file is never
/// held in memory.
/// The engine-side handles a finished download needs, bundled so the completion
/// tail spawned in [`Engine::spawn_fetch`] can hand them off in one move.
struct FinishCtx {
    registry: Arc<Mutex<Vec<Arc<Download>>>>,
    shared: Arc<Mutex<Vec<SharedFile>>>,
    config_dir: PathBuf,
    /// Serializes the known.met read-modify-write across concurrently-finishing
    /// downloads (each runs in its own task) so no entry is lost to a race.
    known_met_lock: Arc<Mutex<()>>,
    events: mpsc::UnboundedSender<EngineEvent>,
}

async fn finish_download(
    dl: Arc<Download>,
    ctx: FinishCtx,
    hash: [u8; 16],
    size: u64,
    dest: PathBuf,
) {
    let FinishCtx {
        registry,
        shared,
        config_dir,
        known_met_lock,
        events,
    } = ctx;
    let name = dl.name().await;
    let verified = dl.verify_whole_file(size, hash).await;
    if !verified {
        let _ = events.send(EngineEvent::Server(format!(
            "'{name}' finished but FAILED verification - keeping the .part, not saving"
        )));
        return;
    }
    // Capture the hashset BEFORE into_store consumes the store: a finished file
    // becomes a shared source, and answering OP_HASHSETREQUEST needs these.
    let part_hashes = dl.part_hashes().await;
    // Drop our registry handle so the store can be taken back out of the Arc.
    registry.lock().await.retain(|d| !Arc::ptr_eq(d, &dl));
    let Some(store) = dl.into_store().await else {
        let _ = events.send(EngineEvent::Server(format!(
            "'{name}' verified but is still in use - it will be saved on the next start"
        )));
        return;
    };
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let dest = unique_dest(dest);
    match store.finish(&dest) {
        Ok(()) => {
            // Seed it: a verified, complete file is a full source other peers can
            // pull. The listener only serves it while sharing is on. Use the
            // ACTUAL on-disk name (unique_dest may have renamed it), so the
            // persisted library can rebuild `path` as downloads_dir / name.
            let on_disk_name = dest
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or(name.clone());
            let sf = SharedFile {
                hash,
                size,
                name: on_disk_name.into_bytes(),
                part_hashes,
                path: dest.clone(),
            };
            {
                // Serialize the known.met read-modify-write against other
                // finishing downloads (re-share after a restart).
                let _g = known_met_lock.lock().await;
                persist_shared_file(&config_dir, &sf);
            }
            shared.lock().await.push(sf);
            let _ = events.send(EngineEvent::Server(format!(
                "Saved '{}'",
                dest.file_name().unwrap_or_default().to_string_lossy()
            )));
        }
        Err(e) => {
            let _ = events.send(EngineEvent::Server(format!("could not save '{name}': {e}")));
        }
    }
}

/// Serve one leecher: a peer that reached our listener and asked for a file
/// (`first` is the request packet the listener already read).
///
/// In Leech Mode (sharing off) we honestly decline with "no file" so the peer
/// moves on. Otherwise we serve, and [`serve_shared`] handles the slot: it
/// grants one immediately if free, or QUEUES the peer (OP_QUEUERANKING) and
/// grants a freed slot in place. The permit is held inside serve_shared for the
/// whole session.
async fn serve_inbound<S>(
    fs: &mut FramedStream<S>,
    shared: &Arc<Mutex<Vec<SharedFile>>>,
    sharing: &Arc<AtomicBool>,
    gate: &Arc<UploadGate>,
    first: Packet,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !sharing.load(Ordering::Relaxed) {
        // Leech Mode: we may hold the file, but we are not sharing - say so.
        if let Some(h) = head_hash(&first.payload) {
            let _ = fs.write_packet(&build_file_req_ans_no_fil(&h)).await;
        }
        return;
    }
    let library = shared.lock().await.clone();
    let _ = serve_shared(fs, &library, Some(first), Some(gate)).await;
}

/// What [`Engine::add_download`] did. Not an Error type: "no sources yet" is a
/// normal answer on a P2P network, not a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddResult {
    /// Registered and the transfer is running.
    Started,
    /// This hash is already downloading.
    AlreadyAdded,
    /// Nobody the server knows has this file.
    NoSources,
    /// No server is currently connected.
    NoServer,
    /// The request itself made no sense.
    BadRequest(&'static str),
    /// Could not create the part file.
    Failed(String),
}

/// Whether a search hit is something we already have, are fetching, or is new.
/// Mirrors eMule's colored result states. "Have" is best-effort: it knows files
/// finished this session (shared library) + complete downloads, not files sitting
/// in the downloads directory from a prior run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitStatus {
    New,
    Downloading,
    Have,
}

/// A distilled Kad keyword result in the raw tagged shape the [`catalog`]
/// expects, so server and Kad hits for one hash dedupe and rank together. The id
/// tags mirror `catalog`'s: 0x01 filename, 0x02 filesize, 0x15 sources.
fn kad_to_search(f: &mule_kad::FileResult) -> SearchResultFile {
    SearchResultFile {
        hash: f.hash,
        id: 0,
        port: 0,
        tags: vec![
            Tag::id(0x01, TagValue::Str(f.name.as_bytes().to_vec())),
            Tag::id(0x02, TagValue::U64(f.size)),
            Tag::id(0x15, TagValue::U32(f.sources)),
        ],
    }
}

/// Flatten a server-link event into the UI's event stream.
fn map_server_event(e: ServerEvent) -> EngineEvent {
    match e {
        ServerEvent::State(s) => EngineEvent::Server(format!("{s:?}")),
        ServerEvent::Message(m) => EngineEvent::Server(m),
        ServerEvent::Status { users, files } => {
            EngineEvent::Server(format!("{users} users, {files} files"))
        }
        ServerEvent::ServerList(l) => EngineEvent::Server(format!("{} servers known", l.len())),
    }
}

/// The coarse lifecycle state the UI shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    /// Not started (or shut down): no sockets, nothing running.
    Stopped,
    /// Foreground: sockets live, server/Kad connected, transfers active.
    Running,
    /// Backgrounded: sockets released, state checkpointed, transfers paused.
    Paused,
}

/// An observable engine event. Kept simple (no lifetimes/generics) so the Wave-8
/// UniFFI layer can carry it to Swift directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    /// The coarse lifecycle state changed.
    State(EngineState),
    /// A human-readable status line ("Reconnecting...", "Connected", "Paused").
    Status(String),
    /// A server connection update.
    Server(String),
    /// Kad status: the routing table now holds this many contacts.
    Kad { contacts: usize },
    /// Per-download progress.
    Progress {
        hash: [u8; 16],
        have: u64,
        total: u64,
    },
}

/// What the server told us at login. Kept because HighID-vs-LowID decides
/// whether peers can reach us at all, and on a sideloaded iPad there is no
/// debugger - this screen IS the diagnostic.
///
/// Deliberately does NOT carry the client id: a HighID id ENCODES our public
/// IP, and this struct exists to be rendered on a screen that gets
/// screenshotted. `low_id` is the whole answer; the id itself is not worth the
/// leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// The server we are logged into ("ip:port").
    pub addr: String,
    /// True when the server handed us a LowID (no reachable inbound port).
    pub low_id: bool,
}

/// Optional pre-search filters pushed onto the server query (and re-applied to
/// the merged result set so Kad hits obey them too). `None` = unfiltered.
#[derive(Debug, Clone, Copy, Default)]
pub struct SearchFilters {
    /// Minimum availability (source count). `Some(1)` = complete/live only.
    pub min_sources: Option<u32>,
    /// Minimum / maximum file size in BYTES.
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
}

/// The padMule engine. Create with [`Engine::new`], drive with the lifecycle
/// methods, observe via the returned event receiver.
pub struct Engine {
    identity: NodeIdentity,
    config_dir: PathBuf,
    state: EngineState,
    events: mpsc::UnboundedSender<EngineEvent>,
    /// Persisted Kad contacts (loaded from / saved to `nodes.dat`).
    routing: RoutingTable,
    /// In-progress downloads (resumed from disk on start). Shared with the
    /// listener task: a peer that connects to US (a LowID source we asked the
    /// server to call back) has to be routed into the download it is answering,
    /// and the listener cannot borrow `&self`.
    downloads: Arc<Mutex<Vec<Arc<Download>>>>,
    /// Where COMPLETED files are moved. Defaults to `config_dir/downloads`; on
    /// iOS the app passes its Documents dir so the Files app can see them - a
    /// finished file nobody can open is not a finished download.
    downloads_dir: PathBuf,
    /// Complete files we will serve to peers, populated as downloads finish.
    /// Shared with the listener, which serves them on request (the upload side).
    shared: Arc<Mutex<Vec<SharedFile>>>,
    /// The upload switch. `false` is "Leech Mode": we still download, but serve
    /// nothing. An atomic so the listener task reads it without taking a lock.
    sharing: Arc<AtomicBool>,
    /// Upload slots + wait queue (see `MAX_UPLOAD_SLOTS` / `UPLOAD_QUEUE_CAP`).
    /// Shared with the listener; serve_shared grants/queues against it.
    upload_gate: Arc<UploadGate>,
    /// Serializes known.met writes across concurrently-finishing downloads.
    known_met_lock: Arc<Mutex<()>>,
    /// The live eD2k server link, once logged in.
    server: Option<ServerLink>,
    /// What that login yielded (server address + HighID/LowID), for the UI.
    connection: Option<ServerInfo>,
    /// The live Kad node (owns the UDP socket), once bootstrapped.
    kad: Option<KadNode>,
    /// The inbound peer listener's accept loop (dropping it frees port 4662).
    listener: Option<JoinHandle<()>>,
    /// Sender handed to each ServerLink; its forwarder task is spawned once.
    server_tx: Option<mpsc::Sender<ServerEvent>>,
    /// The IP blocklist (ipfilter.dat / .p2p), if the user placed one. Shared with
    /// the listener task so inbound peers are gated too. `None` = no filtering.
    ip_filter: Option<Arc<IpFilter>>,
    /// Suppress ALL network activity. Tests set this so the unit suite never
    /// touches the real network; the UI never does.
    offline: bool,
}

impl Engine {
    /// Load (or create) the identity in `config_dir` and return the engine plus
    /// the event stream the UI drains.
    pub fn new(
        config_dir: impl AsRef<Path>,
    ) -> io::Result<(Self, mpsc::UnboundedReceiver<EngineEvent>)> {
        let config_dir = config_dir.as_ref().to_path_buf();
        let identity = NodeIdentity::load_or_create(&config_dir)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let routing = RoutingTable::new(identity.kad_id);
        let engine = Engine {
            identity,
            downloads_dir: config_dir.join("downloads"),
            config_dir,
            state: EngineState::Stopped,
            events: tx,
            routing,
            downloads: Arc::new(Mutex::new(Vec::new())),
            shared: Arc::new(Mutex::new(Vec::new())),
            sharing: Arc::new(AtomicBool::new(true)),
            upload_gate: Arc::new(UploadGate::new(
                Arc::new(Semaphore::new(MAX_UPLOAD_SLOTS)),
                UPLOAD_QUEUE_CAP,
            )),
            known_met_lock: Arc::new(Mutex::new(())),
            ip_filter: None,
            server: None,
            connection: None,
            kad: None,
            listener: None,
            server_tx: None,
            offline: false,
        };
        Ok((engine, rx))
    }

    /// Suppress all network activity (tests only - the UI never calls this).
    /// Without it the unit suite would fetch lists and dial real servers.
    pub fn set_offline(&mut self, offline: bool) {
        self.offline = offline;
    }

    /// True once an eD2k server has accepted our login.
    pub fn is_online(&self) -> bool {
        self.server
            .as_ref()
            .map(|s| s.is_connected())
            .unwrap_or(false)
    }

    /// What our login yielded, once a server has accepted us.
    pub fn server_info(&self) -> Option<ServerInfo> {
        if self.is_online() {
            self.connection.clone()
        } else {
            None
        }
    }

    /// An honest one-line status for the UI - never claims a connection we do
    /// not have. Carries the HighID/LowID answer, because a bare "Connected"
    /// hides the one fact that decides whether peers can reach us.
    fn online_status(&self) -> String {
        if self.is_online() {
            match &self.connection {
                Some(c) => format!(
                    "Connected to {} ({})",
                    c.addr,
                    if c.low_id { "LowID" } else { "HighID" }
                ),
                None => "Connected".to_string(),
            }
        } else if self.offline {
            "Offline (network disabled)".to_string()
        } else {
            "Offline - no server accepted a login".to_string()
        }
    }

    /// The number of Kad contacts currently held.
    pub fn kad_contacts(&self) -> usize {
        self.routing.len()
    }

    /// The in-progress downloads. Cheap: clones `Arc`s, not files.
    pub async fn downloads(&self) -> Vec<Arc<Download>> {
        self.downloads.lock().await.clone()
    }

    /// How many IP-blocklist ranges are loaded (0 = no filter). For the UI.
    pub fn ip_filter_ranges(&self) -> usize {
        self.ip_filter.as_ref().map_or(0, |f| f.len())
    }

    /// The complete files we are currently serving to peers, as (hash, name,
    /// size). Reflects the persisted library plus anything finished this session;
    /// empty in Leech Mode is still what we HOLD, not what we serve.
    pub async fn shared_files(&self) -> Vec<([u8; 16], String, u64)> {
        self.shared
            .lock()
            .await
            .iter()
            .map(|s| {
                (
                    s.hash,
                    String::from_utf8_lossy(&s.name).into_owned(),
                    s.size,
                )
            })
            .collect()
    }

    /// Where completed files land. The iOS app points this at its Documents dir
    /// so finished downloads show up in the Files app.
    pub fn set_downloads_dir(&mut self, dir: impl AsRef<Path>) {
        self.downloads_dir = dir.as_ref().to_path_buf();
    }

    /// Whether padMule serves files to peers. `false` is "Leech Mode":
    /// downloading still works, but we upload nothing.
    pub fn is_sharing(&self) -> bool {
        self.sharing.load(Ordering::Relaxed)
    }

    /// Turn uploading on or off. Off is the download-only "Leech Mode"; the
    /// listener consults this per connection, so it takes effect immediately.
    pub fn set_sharing(&self, on: bool) {
        self.sharing.store(on, Ordering::Relaxed);
    }

    pub fn state(&self) -> EngineState {
        self.state
    }
    pub fn userhash(&self) -> [u8; 16] {
        self.identity.userhash
    }
    pub fn kad_id(&self) -> Kad128 {
        self.identity.kad_id
    }
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    fn emit(&self, e: EngineEvent) {
        let _ = self.events.send(e);
    }

    fn set_state(&mut self, s: EngineState) {
        if self.state != s {
            self.state = s;
            self.emit(EngineEvent::State(s));
        }
    }

    /// Start from `Stopped` -> `Running`. Idempotent (a no-op if already
    /// running). Loads the persisted Kad contacts and resumes in-progress
    /// downloads from disk, emitting an event for each. Phase 4 spins up the live
    /// server + Kad sockets on top.
    pub async fn start(&mut self) {
        if self.state == EngineState::Running {
            return;
        }
        let _ = std::fs::create_dir_all(&self.config_dir);

        // Load the IP blocklist if the user placed one. Best-effort: absent or
        // unparseable means no filtering (never a startup failure).
        self.ip_filter = load_ip_filter(&self.config_dir);
        if let Some(f) = &self.ip_filter {
            self.emit(EngineEvent::Server(format!(
                "IP filter: {} ranges blocked",
                f.len()
            )));
        }

        // A FRESH INSTALL HAS NEITHER LIST, so it knows no servers and no Kad
        // contacts and could reach nothing. Fetch them (best effort - a failure
        // must not stop the engine; we simply come up offline and can retry).
        if !self.offline {
            self.emit(EngineEvent::Status("Fetching network lists...".into()));
            bootstrap::ensure(
                &self.config_dir,
                "server.met",
                bootstrap::SERVER_MET_URL,
                bootstrap::looks_like_server_met,
            )
            .await;
            bootstrap::ensure(
                &self.config_dir,
                "nodes.dat",
                bootstrap::NODES_DAT_URL,
                bootstrap::looks_like_nodes_dat,
            )
            .await;
        }

        // Persisted Kad contacts.
        if let Ok(bytes) = std::fs::read(self.config_dir.join("nodes.dat")) {
            if let Ok(nd) = read_nodes_dat(&bytes) {
                self.routing.load_nodes(&nd.contacts);
            }
        }
        self.emit(EngineEvent::Kad {
            contacts: self.routing.len(),
        });
        // In-progress downloads.
        let resumed = resume_downloads(&self.config_dir);
        for dl in &resumed {
            let total = dl.size().await;
            let have = total - dl.missing().await;
            let hash = dl.hash().await;
            self.emit(EngineEvent::Progress { hash, have, total });
        }
        *self.downloads.lock().await = resumed;

        // Complete files from prior sessions - re-share them (the list was
        // session-only before, so uploads forgot their library on every launch).
        let library = load_shared_library(&self.config_dir, &self.downloads_dir);
        *self.shared.lock().await = library;

        // Go live. ORDER MATTERS: the inbound listener must exist BEFORE we log
        // in, because the server decides HighID vs LowID by connecting back to
        // the port we advertise. No listener = LowID = a second-class peer.
        if !self.offline {
            self.emit(EngineEvent::Status("Opening port...".into()));
            self.start_listener().await;
            self.map_port().await;
            self.emit(EngineEvent::Status("Connecting...".into()));
            self.connect_server().await;
            self.start_kad().await;
            // Report Running BEFORE the (time-bounded) resume pass, so the engine
            // is usable and the state is honest even while resume_fetches works.
            self.set_state(EngineState::Running);
            self.emit(EngineEvent::Status(self.online_status()));
            // Downloads resumed from disk above were registered but have no
            // transfer task yet; now that the server + Kad are up, find sources
            // and drive them (otherwise they wait passively for a callback).
            self.resume_fetches().await;
            return;
        }

        self.set_state(EngineState::Running);
        self.emit(EngineEvent::Status(self.online_status()));
    }

    /// Bind the inbound peer port and accept connections. This is what earns a
    /// HighID: the server's HighID test is a bare TCP connect+close (no eD2k
    /// HELLO), so simply ACCEPTING is enough to pass it. Real peers that follow
    /// get a proper hello handshake. Idempotent; a bind failure is survivable
    /// (we just stay LowID).
    ///
    /// An accepted peer plays one of two roles, told apart by who speaks first
    /// (see [`SERVE_PEEK`]): a LEECHER wants to download from us and sends
    /// OP_REQUESTFILENAME straight away, so we serve it from our shared files; a
    /// called-back LowID SOURCE for one of our downloads stays silent, so we
    /// drive the download instead.
    async fn start_listener(&mut self) {
        if self.listener.is_some() {
            return;
        }
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), TCP_PORT);
        let Ok(listener) = TcpListener::bind(bind).await else {
            self.emit(EngineEvent::Server(format!(
                "port {TCP_PORT} unavailable - expect LowID"
            )));
            return;
        };
        let me = HelloInfo::baseline(self.identity.userhash, 0, TCP_PORT, KAD_UDP_PORT, "padMule");
        let downloads = Arc::clone(&self.downloads);
        let shared = Arc::clone(&self.shared);
        let sharing = Arc::clone(&self.sharing);
        let gate = Arc::clone(&self.upload_gate);
        let ip_filter = self.ip_filter.clone();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, peer)) = listener.accept().await else {
                    continue;
                };
                let me = me.clone();
                let downloads = Arc::clone(&downloads);
                let shared = Arc::clone(&shared);
                let sharing = Arc::clone(&sharing);
                let gate = Arc::clone(&gate);
                let ip_filter = ip_filter.clone();
                tokio::spawn(async move {
                    let mut fs = FramedStream::new(stream);
                    // A bare connect+close (the server's HighID probe) ends here.
                    if timeout(Duration::from_secs(8), peer_handshake_inbound(&mut fs, &me))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    // Drop a blocklisted PEER now (after the handshake, so the
                    // server's bare-connect HighID probe - which never completes a
                    // handshake and already returned above - is never filtered and
                    // HighID is safe).
                    if let (Some(f), SocketAddr::V4(v4)) = (&ip_filter, peer) {
                        if f.is_blocked(*v4.ip()) {
                            return;
                        }
                    }
                    // Peek who speaks first. Cancel-safe: a silent source buffers
                    // no bytes, so a timeout here loses nothing and the download
                    // path below reads cleanly (see framed::read_packet).
                    match timeout(SERVE_PEEK, fs.read_packet_unpacked()).await {
                        Ok(Ok(pkt)) if is_upload_request(pkt.opcode) => {
                            serve_inbound(&mut fs, &shared, &sharing, &gate, pkt).await;
                        }
                        // Spoke, but not an upload request, or the link errored:
                        // nothing we can do with it.
                        Ok(_) => {}
                        // Silent: a called-back source. Offer it every unfinished
                        // download and let it serve whichever it actually has.
                        // Do NOT hold the lock across the transfer.
                        Err(_) => {
                            let pending: Vec<Arc<Download>> = downloads.lock().await.clone();
                            for dl in pending {
                                if dl.is_complete().await {
                                    continue;
                                }
                                match timeout(
                                    Duration::from_secs(120),
                                    download_from_peer(&mut fs, &dl, false),
                                )
                                .await
                                {
                                    // Delivered something - keep it on this
                                    // download rather than offering it others.
                                    Ok(Ok(n)) if n > 0 => break,
                                    // Connection is spent either way once it errors.
                                    Ok(Err(_)) | Err(_) => break,
                                    Ok(Ok(_)) => {}
                                }
                            }
                        }
                    }
                });
            }
        });
        self.listener = Some(handle);
    }

    /// Best-effort: ask the gateway (UPnP, multicast then unicast) to forward our
    /// port, so a real device with no hand-configured router rule can still earn a
    /// HighID. The RESULT is emitted either way - success or the failure reason -
    /// because on a debugger-less device this line is the only window into why the
    /// port did or did not open. Messages are prefixed "UPnP:" so the UI can pin
    /// them to a durable row instead of the transient notice.
    async fn map_port(&self) {
        match crate::upnp::map_port(TCP_PORT, "padMule", 0).await {
            Ok(_ip) => {
                // The external IP the gateway reports is deliberately NOT emitted:
                // this reaches the UI, and that is our public IP verbatim.
                self.emit(EngineEvent::Server(format!("UPnP: mapped port {TCP_PORT}")));
            }
            Err(e) => {
                self.emit(EngineEvent::Server(format!(
                    "UPnP: could not map port {TCP_PORT} ({e})"
                )));
            }
        }
    }

    /// The ServerEvent -> EngineEvent forwarder, spawned exactly once. Must be
    /// called from inside the runtime (start/resume), never from `new`.
    fn server_sender(&mut self) -> mpsc::Sender<ServerEvent> {
        if let Some(tx) = &self.server_tx {
            return tx.clone();
        }
        let (tx, mut rx) = mpsc::channel(64);
        let out = self.events.clone();
        tokio::spawn(async move {
            while let Some(e) = rx.recv().await {
                let _ = out.send(map_server_event(e));
            }
        });
        self.server_tx = Some(tx.clone());
        tx
    }

    /// Try each server in `server.met` until one accepts a login. Best effort:
    /// coming up offline is a valid outcome, not an error.
    async fn connect_server(&mut self) {
        let Ok(bytes) = std::fs::read(self.config_dir.join("server.met")) else {
            self.emit(EngineEvent::Server("no server list on disk".into()));
            return;
        };
        let Ok(met) = read_server_met(&bytes) else {
            self.emit(EngineEvent::Server("server list is unreadable".into()));
            return;
        };
        let login = LoginRequest {
            user_hash: self.identity.userhash,
            client_id: 0,
            tcp_port: TCP_PORT,
            nick: "padMule".to_string(),
            server_flags: DEFAULT_SERVER_FLAGS,
        };
        let tx = self.server_sender();
        for srv in met.servers.iter().take(10) {
            let addr = SocketAddr::new(IpAddr::V4(ip_from_met_u32(srv.ip)), srv.port);
            let mut link = ServerLink::new(addr, login.clone(), tx.clone());
            if let Ok(Ok(ServerState::Connected { low_id, .. })) =
                timeout(Duration::from_secs(12), link.connect()).await
            {
                // The client id is deliberately NOT recorded here: a HighID id
                // encodes our public IP and this text reaches the screen.
                self.connection = Some(ServerInfo {
                    addr: addr.to_string(),
                    low_id,
                });
                self.emit(EngineEvent::Server(format!(
                    "Connected to {addr} ({})",
                    if low_id { "LowID" } else { "HighID" }
                )));
                self.server = Some(link);
                return;
            }
        }
        self.emit(EngineEvent::Server("no server accepted a login".into()));
    }

    /// Bind the Kad UDP socket and bootstrap off the persisted contacts.
    async fn start_kad(&mut self) {
        let contacts: Vec<KadContact> = match std::fs::read(self.config_dir.join("nodes.dat")) {
            Ok(b) => read_nodes_dat(&b).map(|n| n.contacts).unwrap_or_default(),
            Err(_) => Vec::new(),
        };
        if contacts.is_empty() {
            self.emit(EngineEvent::Server("no Kad contacts to bootstrap".into()));
            return;
        }
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), KAD_UDP_PORT);
        // The PERSISTED identity, so our Kad ID and the UDP verify keys peers
        // stored for us survive a restart (identity.rs names re-keying Kad on
        // every start as the failure a stable identity exists to prevent).
        let Ok(mut node) = KadNode::bind_with_identity(
            bind,
            TCP_PORT,
            self.identity.kad_id,
            self.identity.kad_udp_key,
        )
        .await
        else {
            self.emit(EngineEvent::Server("Kad UDP port unavailable".into()));
            return;
        };
        match node
            .bootstrap_any(&contacts, Duration::from_millis(1200), 40)
            .await
        {
            Ok(_) => {
                // Fold what Kad learned back into the persisted routing table.
                self.routing.load_nodes(&routing_to_nodes(node.routing()));
                self.emit(EngineEvent::Kad {
                    contacts: node.contacts_known(),
                });
                self.kad = Some(node);
            }
            Err(_) => self.emit(EngineEvent::Server("Kad bootstrap failed".into())),
        }
    }

    /// Search BOTH the connected server AND the Kad network, deduped + ranked by
    /// [`catalog`]. Either half may be absent: a serverless client still gets Kad
    /// hits, a client with no Kad contacts still gets server hits, and a file on
    /// both merges by hash. Empty only when neither has anything (or we are
    /// offline) - not worth an error the UI would render as "no results" anyway.
    ///
    /// The two run concurrently, so the wait is the SLOWER of the two, not the
    /// sum. Blocks up to `SEARCH_WAIT`; the FFI facade runs it off the UI thread.
    /// Filters (bounds in BYTES) are applied on the server wire query and to the
    /// merged set.
    pub async fn search(&mut self, keyword: &str, filters: SearchFilters) -> Vec<RankedFile> {
        let keyword = keyword.trim();
        if self.offline || keyword.is_empty() {
            return Vec::new();
        }
        let params = SearchParams {
            keyword: keyword.to_string(),
            file_type: None,
            // Push size + availability onto the server query so the ~200-result
            // cap fills with matches instead of junk. Min size clamps to 32-bit
            // (widening only); a max above 4 GiB is omitted from the wire and
            // enforced client-side below (see mule-cli fetch-complete).
            min_size: filters.min_size.map(|b| b.min(u32::MAX as u64) as u32),
            max_size: filters
                .max_size
                .and_then(|b| (b <= u32::MAX as u64).then_some(b as u32)),
            min_sources: filters.min_sources,
            // NOT the keyword: the search box means the word, not the file type
            // (mule-cli's fetch-complete pins an extension only because it hunts
            // for a ".pdf" when asked for "pdf").
            extension: None,
        };
        // The server link and the Kad node are separate fields, so both can be
        // borrowed and driven at once.
        let server = self.server.as_mut();
        let kad = self.kad.as_mut();
        let (server_files, kad_files) = tokio::join!(
            async {
                match server {
                    Some(link) => link.search(&params, SEARCH_WAIT).await.unwrap_or_default(),
                    None => Vec::new(),
                }
            },
            async {
                match kad {
                    // Bounded so a slow lookup cannot hang the search; a lookup
                    // that misses the budget just contributes nothing this time.
                    Some(node) => timeout(
                        KAD_SEARCH_WAIT,
                        node.resolve_keyword(keyword, 50, KAD_PER_QUERY),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default(),
                    None => Vec::new(),
                }
            },
        );
        // Fold the Kad hits (already distilled) into the same shape the server
        // hits arrive in, so a single catalog pass dedupes across both by hash.
        let mut combined = server_files;
        combined.extend(kad_files.iter().map(kad_to_search));
        let mut ranked = catalog(&combined);
        // Apply the same bounds to the merged set, so Kad hits (not filtered on
        // the wire) and any server slack obey the user's filters too.
        ranked.retain(|r| {
            filters.min_sources.is_none_or(|m| r.sources >= m)
                && filters.min_size.is_none_or(|m| r.size >= m)
                && filters.max_size.is_none_or(|m| r.size <= m)
        });
        ranked
    }

    /// Classify a search hit's hash against our downloads + shared files, so the
    /// UI can show an already-have / fetching / new indicator per result.
    pub async fn hit_status(&self, hash: [u8; 16]) -> HitStatus {
        for dl in self.downloads.lock().await.iter() {
            if dl.hash().await == hash {
                return if dl.is_complete().await {
                    HitStatus::Have
                } else {
                    HitStatus::Downloading
                };
            }
        }
        if self.shared.lock().await.iter().any(|s| s.hash == hash) {
            return HitStatus::Have;
        }
        HitStatus::New
    }

    /// Start downloading `hash`. Asks the server AND Kad who has it (see
    /// [`Engine::find_sources`]), creates the part file, registers the download,
    /// and spawns the transfer - returning as soon as it is registered, NOT when
    /// the file lands. Progress is observed via [`Engine::downloads`]; the
    /// finished file is moved to `downloads_dir`.
    ///
    /// Idempotent: asking twice for the same hash is a no-op, not a second
    /// part file racing the first.
    pub async fn add_download(&mut self, hash: [u8; 16], size: u64, name: &str) -> AddResult {
        if size == 0 {
            return AddResult::BadRequest("file size is unknown");
        }
        for dl in self.downloads.lock().await.iter() {
            if dl.hash().await == hash {
                return AddResult::AlreadyAdded;
            }
        }
        if self.offline {
            return AddResult::NoServer;
        }
        if self.server.is_none() {
            return AddResult::NoServer;
        }
        let (reg, lowids) = self.find_sources(hash, size).await;
        if reg.is_empty() && lowids.is_empty() {
            return AddResult::NoSources;
        }

        // aMule numbers part files NNN.part in one directory and
        // resume_downloads finds them by that name, so take the next free index.
        let index = next_part_index(&self.config_dir);
        let store = match PartStore::create(&self.config_dir, index, hash, size, name.as_bytes()) {
            Ok(s) => s,
            Err(e) => return AddResult::Failed(e.to_string()),
        };
        let dl = Download::new(store);
        self.downloads.lock().await.push(Arc::clone(&dl));

        self.request_callbacks(&lowids).await;
        self.spawn_fetch(dl, hash, size, name, reg.sources().to_vec());
        AddResult::Started
    }

    /// Discover who has `hash`: the connected server (get_sources) AND Kad
    /// (resolve_sources) CONCURRENTLY, folding both into one registry so a
    /// serverless client still gets Kad sources and vice versa. Returns the
    /// registry plus the LowID source IPs worth a server callback (empty unless
    /// WE are HighID - a LowID cannot receive a callback).
    async fn find_sources(&mut self, hash: [u8; 16], size: u64) -> (SourceRegistry, Vec<u32>) {
        let low_id = self.connection.as_ref().map(|c| c.low_id).unwrap_or(true);
        // The two lookups touch disjoint fields (server link vs Kad node), so
        // run them together; the wait is the slower of the two, not the sum.
        let server = self.server.as_mut();
        let kad = self.kad.as_mut();
        let (found, kad_sources) = tokio::join!(
            async {
                match server {
                    Some(link) => link
                        .get_sources(&hash, size, SOURCES_WAIT)
                        .await
                        .unwrap_or_default(),
                    None => Vec::new(),
                }
            },
            async {
                match kad {
                    // Bounded like the search path: a slow lookup contributes
                    // nothing rather than hanging the Get.
                    Some(node) => timeout(
                        KAD_SEARCH_WAIT,
                        node.resolve_sources(&Kad128::from_hash(&hash), size, 20, KAD_PER_QUERY),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .map(|o| o.sources)
                    .unwrap_or_default(),
                    None => Vec::new(),
                }
            }
        );
        let mut reg = SourceRegistry::new();
        reg.add_found(&found);
        reg.add_kad(&kad_sources);
        // Never dial a blocklisted peer. LowID callback sources are gated on the
        // inbound side instead (they dial US), so only direct sources are dropped
        // here.
        if let Some(filter) = &self.ip_filter {
            reg.drop_blocked(|addr| match addr {
                SocketAddr::V4(v4) => filter.is_blocked(*v4.ip()),
                SocketAddr::V6(_) => false,
            });
        }
        // A LowID source cannot accept our connection; the server has to poke it
        // for us. Only worth asking if WE are reachable - a LowID asking a LowID
        // to call back is the one case eD2k simply cannot route.
        let lowids: Vec<u32> = if low_id {
            Vec::new()
        } else {
            found
                .iter()
                .filter(|s| s.ip != 0 && s.ip < 0x0100_0000 && s.port != 0)
                .map(|s| s.ip)
                .collect()
        };
        (reg, lowids)
    }

    /// Ask the server to poke each LowID source so it dials our listener.
    async fn request_callbacks(&mut self, lowids: &[u32]) {
        for id in lowids {
            if let Some(link) = self.server.as_mut() {
                let _ = link.request_callback(*id).await;
            }
        }
    }

    /// Spawn the transfer task for an already-registered download: pull from
    /// `sources`, then verify + save on completion (or bail if cancelled).
    fn spawn_fetch(
        &self,
        dl: Arc<Download>,
        hash: [u8; 16],
        size: u64,
        name: &str,
        sources: Vec<PeerSource>,
    ) {
        let me = HelloInfo::baseline(self.identity.userhash, 0, TCP_PORT, KAD_UDP_PORT, "padMule");
        let dest = self.downloads_dir.join(safe_filename(name));
        let events = self.events.clone();
        let ctx = FinishCtx {
            registry: Arc::clone(&self.downloads),
            shared: Arc::clone(&self.shared),
            config_dir: self.config_dir.clone(),
            known_met_lock: Arc::clone(&self.known_met_lock),
            events: events.clone(),
        };
        let dl_task = dl;
        tokio::spawn(async move {
            download_file(&dl_task, &sources, &me, ManagerConfig::default()).await;
            // Cancelled while in flight: the engine already removed it and deleted
            // the .part. Do NOT finish or emit - there is nothing to save.
            if dl_task.is_cancelled() {
                return;
            }
            let total = dl_task.size().await;
            let have = total - dl_task.missing().await;
            let _ = events.send(EngineEvent::Progress { hash, have, total });
            if dl_task.is_complete().await {
                finish_download(dl_task, ctx, hash, size, dest).await;
            }
        });
    }

    /// Re-drive downloads resumed from disk by `start()`. Each was registered but
    /// had NO transfer task, so it progressed only if a called-back peer happened
    /// to dial our listener; this finds fresh sources and spawns the fetch, the
    /// same pipeline `add_download` uses. Best-effort: a resumed download with no
    /// sources right now stays registered and idle (a later run may find some).
    async fn resume_fetches(&mut self) {
        let pending: Vec<Arc<Download>> = {
            let guard = self.downloads.lock().await;
            let mut v = Vec::new();
            for dl in guard.iter() {
                if !dl.is_complete().await && !dl.is_cancelled() {
                    v.push(Arc::clone(dl));
                }
            }
            v
        };
        // Bound the whole pass: start() holds the FFI engine lock for its whole
        // duration, so a batch of dead downloads (each up to KAD_SEARCH_WAIT in
        // find_sources) must not stall startup and delay pause(). Downloads not
        // reached stay registered + idle (best-effort, as documented) and fetch
        // via an inbound callback or the next start.
        let deadline = tokio::time::Instant::now() + RESUME_BUDGET;
        for dl in pending {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let hash = dl.hash().await;
            let size = dl.size().await;
            let name = dl.name().await;
            let Ok((reg, lowids)) = timeout(RESUME_PER_DL, self.find_sources(hash, size)).await
            else {
                continue; // source-finding overran its budget; leave it idle
            };
            if reg.is_empty() && lowids.is_empty() {
                continue;
            }
            self.request_callbacks(&lowids).await;
            self.spawn_fetch(dl, hash, size, &name, reg.sources().to_vec());
        }
    }

    /// Cancel and remove an in-progress download, deleting its `.part` files.
    /// Returns false if no download with that hash is active (already finished,
    /// or never started). The fetch workers stop within a block of `cancel()`,
    /// and the outer task then bails without saving.
    pub async fn cancel_download(&mut self, hash: [u8; 16]) -> bool {
        let mut guard = self.downloads.lock().await;
        let mut found = None;
        for (i, dl) in guard.iter().enumerate() {
            if dl.hash().await == hash {
                found = Some(i);
                break;
            }
        }
        let Some(i) = found else {
            return false;
        };
        let dl = guard.remove(i);
        drop(guard);
        dl.cancel();
        dl.discard_files().await;
        let name = dl.name().await;
        self.emit(EngineEvent::Server(format!("Removed '{name}'")));
        true
    }

    /// App backgrounded: checkpoint to disk and release sockets. Idempotent - a
    /// no-op unless currently `Running`. `Running` -> `Paused`.
    pub async fn pause(&mut self) {
        if self.state != EngineState::Running {
            return;
        }
        // Release the sockets ourselves rather than let iPadOS reclaim them
        // out from under us - that is what makes resume predictable.
        if let Some(s) = &mut self.server {
            s.pause().await;
        }
        self.kad = None; // dropping the KadNode closes its UDP socket
        if let Some(h) = self.listener.take() {
            h.abort(); // release TCP 4662; resume() rebinds it
        }
        self.checkpoint();
        self.emit(EngineEvent::Status("Paused".into()));
        self.set_state(EngineState::Paused);
    }

    /// App foregrounded: rebuild sockets, reconnect, re-bootstrap. Idempotent - a
    /// no-op unless currently `Paused`. `Paused` -> `Running`. The real reconnect
    /// (listener rebind, server link, Kad) runs between the two status lines.
    pub async fn resume(&mut self) {
        if self.state != EngineState::Paused {
            return;
        }
        // The banner goes up BEFORE the work, so the UI is honest while we wait.
        self.emit(EngineEvent::Status("Reconnecting...".into()));
        self.set_state(EngineState::Running);

        if !self.offline {
            // Rebind the inbound port first - same HighID reason as start().
            self.start_listener().await;
            // Re-run the handshake on the existing link, or find a new server if
            // we never had one (or the old one is gone). Correct across an IP
            // change, which is the whole point on a mobile device.
            let resumed = match &mut self.server {
                Some(s) => match timeout(Duration::from_secs(12), s.resume()).await {
                    Ok(Ok(ServerState::Connected { low_id, .. })) => {
                        // Re-record: the ID can flip across an IP change, which
                        // is exactly what resume() exists to survive.
                        if let Some(c) = &mut self.connection {
                            c.low_id = low_id;
                        }
                        true
                    }
                    _ => false,
                },
                None => false,
            };
            if !resumed {
                self.server = None;
                self.connection = None;
                self.connect_server().await;
            }
            self.start_kad().await;
        }

        self.emit(EngineEvent::Status(self.online_status()));
    }

    /// Final checkpoint and stop. Safe from any state.
    pub async fn shutdown(&mut self) {
        self.checkpoint();
        self.set_state(EngineState::Stopped);
    }

    /// Persist durable state: the identity and the Kad routing table
    /// (`nodes.dat`). Each download's `.part.met` is written by its PartStore as
    /// blocks land, so progress is already durable.
    fn checkpoint(&self) {
        let _ = self.identity.save(&self.config_dir);
        let contacts = routing_to_nodes(&self.routing);
        let nd = NodesDat {
            version: 2,
            contacts,
        };
        let _ = std::fs::write(self.config_dir.join("nodes.dat"), write_nodes_dat(&nd));
    }

    /// Seed the routing table with Kad contacts (e.g. from a fresh nodes.dat or a
    /// live bootstrap), so the next checkpoint persists them.
    pub fn add_kad_contacts(&mut self, contacts: &[KadContact]) {
        self.routing.load_nodes(contacts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("padmule-engine-{tag}-{}", std::process::id()))
    }

    async fn drain(rx: &mut mpsc::UnboundedReceiver<EngineEvent>) -> Vec<EngineEvent> {
        let mut out = Vec::new();
        while let Ok(e) = rx.try_recv() {
            out.push(e);
        }
        out
    }

    #[tokio::test]
    async fn cancel_download_removes_it_and_deletes_the_part_files() {
        let dir = tmp("cancel");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        // Register an in-progress download backed by a real .part in config_dir.
        let store = PartStore::create(&dir, 1, [0xAB; 16], 1000, b"x.bin").unwrap();
        engine.downloads.lock().await.push(Download::new(store));
        assert!(dir.join("001.part").exists());
        assert!(dir.join("001.part.met").exists());

        // Cancelling it removes it from the list and deletes both files.
        assert!(engine.cancel_download([0xAB; 16]).await, "should cancel");
        assert!(engine.downloads().await.is_empty());
        assert!(!dir.join("001.part").exists());
        assert!(!dir.join("001.part.met").exists());

        // Cancelling a hash we are not downloading is a no-op, not a lie.
        assert!(!engine.cancel_download([0x00; 16]).await);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn kad_hits_flow_through_the_catalog_and_merge_with_server_hits() {
        // A Kad result and a server result for the SAME hash must collapse to one
        // ranked file with the better availability - the whole point of merging
        // the two discovery paths into one search.
        let h = [0x42; 16];
        let server = SearchResultFile {
            hash: h,
            id: 0,
            port: 0,
            tags: vec![
                Tag::id(0x01, TagValue::Str(b"clip.mp4".to_vec())),
                Tag::id(0x02, TagValue::U32(1000)),
                Tag::id(0x15, TagValue::U32(4)),
            ],
        };
        let kad = mule_kad::FileResult {
            hash: h,
            name: "clip.mp4".into(),
            size: 1000,
            sources: 30,
        };
        let combined = vec![server, kad_to_search(&kad)];
        let cat = catalog(&combined);
        assert_eq!(cat.len(), 1, "same hash from both sources merges to one");
        assert_eq!(cat[0].sources, 30, "the better availability wins");
        assert_eq!(cat[0].size, 1000);
        assert_eq!(cat[0].name, "clip.mp4");
        assert!(cat[0].is_trusted());
    }

    #[tokio::test]
    async fn hit_status_reports_downloading_have_and_new() {
        let dir = tmp("hitstatus");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (engine, _rx) = Engine::new(&dir).unwrap();

        // An in-progress (incomplete) download -> Downloading.
        let store = PartStore::create(&dir, 1, [0xAA; 16], 1000, b"a.bin").unwrap();
        engine.downloads.lock().await.push(Download::new(store));
        assert_eq!(engine.hit_status([0xAA; 16]).await, HitStatus::Downloading);

        // A shared (finished) file -> Have.
        engine.shared.lock().await.push(SharedFile {
            hash: [0xBB; 16],
            size: 10,
            name: b"b.bin".to_vec(),
            part_hashes: vec![],
            path: dir.join("b.bin"),
        });
        assert_eq!(engine.hit_status([0xBB; 16]).await, HitStatus::Have);

        // Anything else -> New.
        assert_eq!(engine.hit_status([0xCC; 16]).await, HitStatus::New);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn leech_mode_refuses_a_file_we_actually_hold() {
        use crate::transfer::{build_request_filename_ext, OP_FILEREQANSNOFIL};
        // We DO hold this hash, but sharing is off - so the honest answer to a
        // leecher is "no file", not a transfer.
        let hash = [0x5A; 16];
        let shared = Arc::new(Mutex::new(vec![SharedFile {
            hash,
            size: 100,
            name: b"held.bin".to_vec(),
            part_hashes: vec![],
            path: PathBuf::from("/does/not/matter"),
        }]));
        let sharing = Arc::new(AtomicBool::new(false)); // Leech Mode
        let gate = Arc::new(UploadGate::new(
            Arc::new(Semaphore::new(MAX_UPLOAD_SLOTS)),
            UPLOAD_QUEUE_CAP,
        ));

        let (client, server) = tokio::io::duplex(8192);
        let mut server_fs = FramedStream::new(server);
        let mut client_fs = FramedStream::new(client);

        let first = build_request_filename_ext(&hash);
        let srv = tokio::spawn(async move {
            serve_inbound(&mut server_fs, &shared, &sharing, &gate, first).await
        });

        let reply = client_fs.read_packet_unpacked().await.unwrap();
        assert_eq!(
            reply.opcode, OP_FILEREQANSNOFIL,
            "Leech Mode must decline, not serve"
        );
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn a_full_queue_ranks_the_peer_then_grants_when_a_slot_frees() {
        use crate::transfer::{
            build_request_filename_ext, build_start_upload_req, parse_queue_ranking,
            OP_ACCEPTUPLOADREQ, OP_QUEUERANKING,
        };
        // One slot, already occupied by a held permit, so the next requester must
        // queue instead of being served or refused.
        let sem = Arc::new(Semaphore::new(1));
        let held = Arc::clone(&sem).try_acquire_owned().unwrap();
        let gate = Arc::new(UploadGate::new(Arc::clone(&sem), UPLOAD_QUEUE_CAP));

        let hash = [0x7C; 16];
        let shared = vec![SharedFile {
            hash,
            size: 100,
            name: b"q.bin".to_vec(),
            part_hashes: vec![],
            path: PathBuf::from("/does/not/matter"),
        }];

        let (client, server) = tokio::io::duplex(8192);
        let mut server_fs = FramedStream::new(server);
        let mut client_fs = FramedStream::new(client);

        let gate2 = Arc::clone(&gate);
        let srv = tokio::spawn(async move {
            let _ = serve_shared(&mut server_fs, &shared, None, Some(&gate2)).await;
        });

        // Name the file, then ask to upload - the slot is taken, so we are queued.
        client_fs
            .write_packet(&build_request_filename_ext(&hash))
            .await
            .unwrap();
        let _ = client_fs.read_packet_unpacked().await.unwrap(); // filename answer
        client_fs
            .write_packet(&build_start_upload_req(&hash))
            .await
            .unwrap();
        let ranked = client_fs.read_packet_unpacked().await.unwrap();
        assert_eq!(ranked.opcode, OP_QUEUERANKING, "at capacity -> a rank");
        assert_eq!(
            parse_queue_ranking(&ranked.payload).unwrap(),
            1,
            "first in line"
        );
        assert_eq!(gate.waiting(), 1);

        // Free the slot -> the queued peer is granted IN PLACE (no reconnect).
        drop(held);
        let accepted = client_fs.read_packet_unpacked().await.unwrap();
        assert_eq!(
            accepted.opcode, OP_ACCEPTUPLOADREQ,
            "the freed slot is granted"
        );

        drop(client_fs);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn a_gated_peer_that_skips_startupload_gets_no_data() {
        // A peer that names a file then jumps straight to OP_REQUESTPARTS - never
        // asking for a slot - must NOT be served, or it would bypass the cap and
        // the queue. It should get the filename answer and then nothing.
        use crate::transfer::{build_request_filename_ext, build_request_parts, OP_SENDINGPART};
        let hash = [0x3A; 16];
        let shared = vec![SharedFile {
            hash,
            size: 300,
            name: b"g.bin".to_vec(),
            part_hashes: vec![],
            path: PathBuf::from("/does/not/matter"),
        }];
        let gate = Arc::new(UploadGate::new(
            Arc::new(Semaphore::new(MAX_UPLOAD_SLOTS)),
            UPLOAD_QUEUE_CAP,
        ));

        let (client, server) = tokio::io::duplex(8192);
        let mut server_fs = FramedStream::new(server);
        let mut client_fs = FramedStream::new(client);

        let gate2 = Arc::clone(&gate);
        let srv = tokio::spawn(async move {
            let _ = serve_shared(&mut server_fs, &shared, None, Some(&gate2)).await;
        });

        client_fs
            .write_packet(&build_request_filename_ext(&hash))
            .await
            .unwrap();
        let ans = client_fs.read_packet_unpacked().await.unwrap(); // filename answer
        assert_ne!(ans.opcode, OP_SENDINGPART);
        // Ask for bytes WITHOUT a slot grant.
        client_fs
            .write_packet(&build_request_parts(&hash, &[(0, 300)]))
            .await
            .unwrap();
        // No data should come back; a short wait must time out, not yield a part.
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            client_fs.read_packet_unpacked(),
        )
        .await;
        assert!(
            got.is_err(),
            "an ungranted peer must receive no OP_SENDINGPART"
        );
        drop(client_fs);
        let _ = srv.await;
    }

    #[tokio::test]
    async fn sharing_on_serves_a_held_file_to_a_leecher() {
        let dir = tmp("serve-inbound");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(29)) as u8)
            .collect();
        let hash = mule_proto::ed2k_hash(&data);
        let path = dir.join("f.bin");
        std::fs::write(&path, &data).unwrap();
        let shared = Arc::new(Mutex::new(vec![SharedFile {
            hash,
            size: data.len() as u64,
            name: b"f.bin".to_vec(),
            part_hashes: vec![],
            path,
        }]));
        let sharing = Arc::new(AtomicBool::new(true));
        let gate = Arc::new(UploadGate::new(
            Arc::new(Semaphore::new(MAX_UPLOAD_SLOTS)),
            UPLOAD_QUEUE_CAP,
        ));

        let (client, server) = tokio::io::duplex(128 * 1024);
        let mut server_fs = FramedStream::new(server);
        let mut client_fs = FramedStream::new(client);

        let srv = tokio::spawn(async move {
            // The listener peeks the first packet before deciding; do the same.
            let first = server_fs.read_packet_unpacked().await.unwrap();
            serve_inbound(&mut server_fs, &shared, &sharing, &gate, first).await;
        });

        let got = crate::transfer_session::download_file(&mut client_fs, &hash, data.len() as u64)
            .await
            .unwrap();
        assert_eq!(got, data);
        assert_eq!(mule_proto::ed2k_hash(&got), hash);

        drop(client_fs);
        srv.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn new_loads_identity_and_starts_stopped() {
        let dir = tmp("new");
        let _ = std::fs::remove_dir_all(&dir);
        let (engine, _rx) = Engine::new(&dir).unwrap();
        assert_eq!(engine.state(), EngineState::Stopped);
        assert_eq!(engine.userhash()[5], 14, "identity loaded");
        assert!(dir.join("preferences.dat").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A P2P filename comes from a stranger. It must never steer a write out of
    /// the directory we chose.
    #[test]
    fn filenames_from_the_network_cannot_escape_the_downloads_dir() {
        for (raw, want) in [
            // Separators become underscores; the leading dots are then stripped,
            // so a traversal attempt collapses to an inert single name.
            (
                "../../Library/Preferences/evil",
                "_.._Library_Preferences_evil",
            ),
            ("/etc/passwd", "_etc_passwd"),
            ("..\\..\\windows\\system32", "_.._windows_system32"),
            ("nul\0byte.txt", "nul_byte.txt"),
            ("line\nbreak.txt", "line_break.txt"),
            // Names that are nothing but dots/space have no content to keep.
            ("..", "download"),
            (".", "download"),
            ("   ", "download"),
            ("", "download"),
            // An ordinary name is left completely alone.
            ("ordinary file.pdf", "ordinary file.pdf"),
        ] {
            let got = safe_filename(raw);
            assert_eq!(got, want, "safe_filename({raw:?})");
            // The real invariant: whatever comes out is ONE path component that
            // joins inside the parent.
            let joined = Path::new("/downloads").join(&got);
            assert_eq!(
                joined.parent(),
                Some(Path::new("/downloads")),
                "{raw:?} escaped to {joined:?}"
            );
        }
    }

    /// Finishing a download must never destroy a file the user already has.
    #[test]
    fn a_finished_file_never_overwrites_an_existing_one() {
        let dir = tmp("uniq");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let first = dir.join("a.pdf");
        assert_eq!(unique_dest(first.clone()), first, "free name is used as-is");

        std::fs::write(&first, b"original").unwrap();
        let second = unique_dest(first.clone());
        assert_eq!(second.file_name().unwrap(), "a (2).pdf");

        std::fs::write(&second, b"second").unwrap();
        assert_eq!(unique_dest(first).file_name().unwrap(), "a (3).pdf");
        // The original is untouched.
        assert_eq!(std::fs::read(dir.join("a.pdf")).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A new download must not claim an index an existing .part.met already uses
    /// - that would clobber a transfer in progress.
    #[test]
    fn a_new_part_index_never_collides_with_an_existing_one() {
        let dir = tmp("idx");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(next_part_index(&dir), 1, "empty dir starts at 1");

        std::fs::write(dir.join("1.part.met"), b"x").unwrap();
        std::fs::write(dir.join("2.part.met"), b"x").unwrap();
        assert_eq!(next_part_index(&dir), 3);

        // A gap must NOT be reused while a higher index is live: 7 exists, so
        // the next is 8, not the free 3.
        std::fs::write(dir.join("7.part.met"), b"x").unwrap();
        assert_eq!(next_part_index(&dir), 8);

        // Unrelated files are ignored.
        std::fs::write(dir.join("preferences.dat"), b"x").unwrap();
        std::fs::write(dir.join("notanumber.part.met"), b"x").unwrap();
        assert_eq!(next_part_index(&dir), 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn add_download_refuses_what_it_cannot_do_instead_of_pretending() {
        let dir = tmp("add");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        // A zero size means we do not know the file - a part store cannot even
        // be sized. Refuse rather than create a broken download.
        assert_eq!(
            engine.add_download([1; 16], 0, "x.pdf").await,
            AddResult::BadRequest("file size is unknown")
        );
        // No server -> say so; do not silently create a download nothing feeds.
        assert_eq!(
            engine.add_download([1; 16], 1000, "x.pdf").await,
            AddResult::NoServer
        );
        assert!(
            engine.downloads().await.is_empty(),
            "nothing was registered"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn search_is_empty_rather_than_erroring_when_no_server_has_us() {
        let dir = tmp("search");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        let f = SearchFilters::default();
        assert!(engine.search("anything", f).await.is_empty());
        assert!(
            engine.search("", f).await.is_empty(),
            "empty keyword is a no-op"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The device screen is our only diagnostic, so the ID type must reach it.
    /// This pins the honesty gate: no server, no claim.
    #[tokio::test]
    async fn server_info_is_none_until_a_server_accepts_us() {
        let dir = tmp("srvinfo");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        assert_eq!(engine.server_info(), None, "no login yet");
        engine.start().await;
        assert_eq!(
            engine.server_info(),
            None,
            "offline start logs into nothing"
        );
        assert!(
            !engine.online_status().contains("HighID") && !engine.online_status().contains("LowID"),
            "must not invent an ID we were never given: {}",
            engine.online_status()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A remembered login must not survive losing the server: `server_info` is
    /// gated on `is_online`, which pause() falsifies by design.
    #[tokio::test]
    async fn server_info_reports_the_id_type_and_clears_when_offline() {
        let dir = tmp("srvid");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        // Stand in for a real login (no server needed to pin the reporting).
        engine.connection = Some(ServerInfo {
            addr: "192.0.2.1:4242".to_string(),
            low_id: true,
        });
        // Still not online -> still no claim, remembered or not.
        assert_eq!(engine.server_info(), None, "is_online gates the claim");
        assert!(!engine.online_status().contains("LowID"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn lifecycle_transitions_and_events() {
        let dir = tmp("life");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        engine.start().await;
        assert_eq!(engine.state(), EngineState::Running);
        engine.pause().await;
        assert_eq!(engine.state(), EngineState::Paused);
        engine.resume().await;
        assert_eq!(engine.state(), EngineState::Running);
        engine.shutdown().await;
        assert_eq!(engine.state(), EngineState::Stopped);

        let evs = drain(&mut rx).await;
        // The key state changes are all present and ordered.
        let states: Vec<EngineState> = evs
            .iter()
            .filter_map(|e| match e {
                EngineEvent::State(s) => Some(*s),
                _ => None,
            })
            .collect();
        assert_eq!(
            states,
            vec![
                EngineState::Running,
                EngineState::Paused,
                EngineState::Running,
                EngineState::Stopped
            ]
        );
        // The reconnect banner is emitted on resume.
        assert!(evs.contains(&EngineEvent::Status("Reconnecting...".into())));
        // The status after the banner must be HONEST: offline here, because the
        // test suppresses the network. It must never claim a connection we lack.
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::Status(s) if s.starts_with("Offline"))),
            "resume must report real connectivity, not a hardcoded 'Connected'"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn lifecycle_methods_are_idempotent() {
        let dir = tmp("idem");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        // pause/resume before start are no-ops.
        engine.pause().await;
        engine.resume().await;
        assert_eq!(engine.state(), EngineState::Stopped);

        engine.start().await;
        engine.start().await; // second start is a no-op
        engine.pause().await;
        engine.pause().await; // second pause is a no-op
        engine.resume().await;
        engine.resume().await; // second resume is a no-op

        let evs = drain(&mut rx).await;
        let n_running = evs
            .iter()
            .filter(|e| matches!(e, EngineEvent::State(EngineState::Running)))
            .count();
        // Running was entered exactly twice (start, resume) - not on the repeats.
        assert_eq!(n_running, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn kad_contacts_persist_through_checkpoint_and_reload() {
        use mule_files::KadContact;
        use mule_proto::Kad128;
        let dir = tmp("kad");
        let _ = std::fs::remove_dir_all(&dir);
        let contacts: Vec<KadContact> = (1..=3u8)
            .map(|i| KadContact {
                id: Kad128::from_hash(&[i; 16]),
                ip: 0x0A00_0000 | i as u32,
                udp_port: 4000 + i as u16,
                tcp_port: 5000 + i as u16,
                version: 8,
                udp_key: 0,
                udp_key_ip: 0,
                verified: false,
            })
            .collect();
        {
            let (mut engine, _rx) = Engine::new(&dir).unwrap();
            engine.set_offline(true);
            engine.add_kad_contacts(&contacts);
            engine.start().await;
            engine.pause().await; // checkpoint writes nodes.dat
            assert!(dir.join("nodes.dat").exists());
        }
        // A fresh engine on the same dir loads them on start.
        let (mut engine2, mut rx) = Engine::new(&dir).unwrap();
        engine2.set_offline(true);
        engine2.start().await;
        assert_eq!(engine2.kad_contacts(), 3);
        let evs = drain(&mut rx).await;
        assert!(evs.contains(&EngineEvent::Kad { contacts: 3 }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_resumes_an_in_progress_download() {
        use crate::part_store::PartStore;
        use mule_proto::ed2k_hash;
        let dir = tmp("resume");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Lay down a part file for a 5000-byte download (nothing written yet).
        let data = vec![9u8; 5000];
        let hash = ed2k_hash(&data);
        let store = PartStore::create(&dir, 1, hash, 5000, b"resume.bin").unwrap();
        drop(store); // leaves 001.part + 001.part.met on disk

        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        engine.start().await;
        assert_eq!(engine.downloads().await.len(), 1, "the .part is resumed");
        let evs = drain(&mut rx).await;
        assert!(evs.iter().any(|e| matches!(
            e,
            EngineEvent::Progress { total, have, .. } if *total == 5000 && *have == 0
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_library_persists_reloads_and_skips_deleted() {
        let dir = tmp("known-met-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let downloads = dir.join("downloads");
        std::fs::create_dir_all(&downloads).unwrap();
        // One file still on disk, one the user later deleted from Files.
        std::fs::write(downloads.join("kept.bin"), b"hello").unwrap();
        let kept = SharedFile {
            hash: [0x11; 16],
            size: 5,
            name: b"kept.bin".to_vec(),
            part_hashes: vec![],
            path: downloads.join("kept.bin"),
        };
        let gone = SharedFile {
            hash: [0x22; 16],
            size: 9,
            name: b"gone.bin".to_vec(),
            part_hashes: vec![[0xAB; 16], [0xCD; 16]],
            path: downloads.join("gone.bin"), // never written to disk
        };
        persist_shared_file(&dir, &kept);
        persist_shared_file(&dir, &gone);
        persist_shared_file(&dir, &kept); // idempotent by hash

        // known.met stayed byte-valid and holds both entries once each.
        let met =
            mule_files::read_known_met(&std::fs::read(dir.join("known.met")).unwrap()).unwrap();
        assert_eq!(met.entries.len(), 2, "each hash persisted exactly once");

        // Reload only re-shares the file that still exists on disk.
        let lib = load_shared_library(&dir, &downloads);
        assert_eq!(lib.len(), 1);
        assert_eq!(lib[0].hash, [0x11; 16]);
        assert_eq!(lib[0].size, 5);
        assert_eq!(lib[0].name, b"kept.bin");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_loads_an_ip_filter_when_present() {
        let dir = tmp("ipfilter-load");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A Latin-1 byte (0xE9) in the description, as real community lists have:
        // the file must still load (bytes + lossy, not strict UTF-8).
        std::fs::write(
            dir.join("ipfilter.dat"),
            b"# test list\n10.0.0.0 - 10.0.0.255 , 0 , R\xE9seau bad range\n",
        )
        .unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        assert_eq!(engine.ip_filter_ranges(), 0, "not loaded until start");
        engine.start().await;
        assert_eq!(
            engine.ip_filter_ranges(),
            1,
            "start() loads ipfilter.dat despite a non-UTF-8 description byte"
        );
        assert!(engine
            .ip_filter
            .as_ref()
            .unwrap()
            .is_blocked("10.0.0.9".parse().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn resume_fetches_with_no_sources_leaves_the_download_resumable() {
        // resume_fetches finds fresh sources for each resumed .part and spawns a
        // transfer. With no server and no Kad node (nothing to find), it must be
        // a safe no-op: the download stays registered and incomplete, so a later
        // run (or an inbound callback) can still complete it. It must NOT drop,
        // complete, or panic on it.
        use crate::part_store::PartStore;
        let dir = tmp("resume-fetch-noop");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = PartStore::create(&dir, 1, [0x11; 16], 5000, b"r.bin").unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.downloads.lock().await.push(Download::new(store));

        engine.resume_fetches().await; // no server, no kad -> no sources found

        let dls = engine.downloads().await;
        assert_eq!(dls.len(), 1, "the download is still registered");
        assert!(
            !dls[0].is_complete().await,
            "still incomplete, still resumable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn checkpoint_persists_identity_on_pause() {
        let dir = tmp("ckpt");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        let uh = engine.userhash();
        std::fs::remove_file(dir.join("preferences.dat")).unwrap();
        engine.start().await;
        engine.pause().await; // checkpoint re-writes identity
        assert!(dir.join("preferences.dat").exists());
        let re =
            mule_files::read_preferences_dat(&std::fs::read(dir.join("preferences.dat")).unwrap())
                .unwrap();
        assert_eq!(re, uh);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// The real thing, exactly as a FRESH iPad install experiences it: an empty
    /// config dir with no server.met and no nodes.dat -> fetch both, log into a
    /// live eD2k server, bootstrap Kad. Ignored by default (needs the network);
    /// run with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn fresh_install_goes_online_and_bootstraps_kad() {
        let dir = std::env::temp_dir().join(format!("padmule-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        assert!(!dir.join("server.met").exists(), "fresh: no server list");
        assert!(!dir.join("nodes.dat").exists(), "fresh: no Kad contacts");

        engine.start().await;

        // It fetched the bootstrap data it had none of.
        assert!(dir.join("server.met").exists(), "server.met was fetched");
        assert!(dir.join("nodes.dat").exists(), "nodes.dat was fetched");
        // It logged into a real server and bootstrapped Kad.
        assert!(engine.is_online(), "a live server accepted our login");
        assert!(engine.kad_contacts() > 0, "Kad routing table is populated");

        let mut evs = Vec::new();
        while let Ok(e) = rx.try_recv() {
            evs.push(e);
        }
        println!("--- engine events on a fresh start ---");
        for e in &evs {
            println!("{e:?}");
        }
        assert!(evs
            .iter()
            .any(|e| matches!(e, EngineEvent::Status(s) if s == "Connected")));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
