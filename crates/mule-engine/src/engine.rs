//! The Engine facade: the single object the native UI drives, and the seam Wave
//! 8's UniFFI layer wraps. It owns the persistent identity and config directory,
//! runs the foreground/background lifecycle state machine, and emits an event
//! stream the UI observes.
//!
//! The lifecycle is the biggest deviation from desktop aMule (see
//! docs/wiki/ipados-constraints.md): iPadOS suspends a backgrounded app and
//! reclaims its sockets, so the honest model is foreground-only -
//!   - `pause()` (app backgrounded): checkpoint to disk, tear down sockets, mark
//!     transfers paused. Idempotent.
//!   - `resume()` (app foregrounded): rebuild sockets, reconnect the server,
//!     re-bootstrap Kad, resume transfers - emitting "Reconnecting..." then
//!     "Connected". Idempotent, and correct across an IP change.
//!
//! Phase 2 lands the lifecycle state machine, identity ownership, event stream,
//! and checkpoint. Phases 3/4 fill `start`/`resume`/`checkpoint` with the real
//! server + Kad + download-manager wiring.

use crate::bootstrap;
use crate::connection::{ServerEvent, ServerState};
use crate::framed::FramedStream;
use crate::identity::NodeIdentity;
use crate::kad_live::KadNode;
use crate::link::ServerLink;
use crate::multi_source::{resume_downloads, Download};
use crate::peer::HelloInfo;
use crate::peer_conn::peer_handshake_inbound;
use crate::server_messages::{LoginRequest, DEFAULT_SERVER_FLAGS};
use mule_files::{read_nodes_dat, read_server_met, write_nodes_dat, KadContact, NodesDat};
use mule_kad::RoutingTable;
use mule_proto::Kad128;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
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

/// The padMule engine. Create with [`Engine::new`], drive with the lifecycle
/// methods, observe via the returned event receiver.
pub struct Engine {
    identity: NodeIdentity,
    config_dir: PathBuf,
    state: EngineState,
    events: mpsc::UnboundedSender<EngineEvent>,
    /// Persisted Kad contacts (loaded from / saved to `nodes.dat`).
    routing: RoutingTable,
    /// In-progress downloads (resumed from disk on start).
    downloads: Vec<Arc<Download>>,
    /// The live eD2k server link, once logged in.
    server: Option<ServerLink>,
    /// The live Kad node (owns the UDP socket), once bootstrapped.
    kad: Option<KadNode>,
    /// The inbound peer listener's accept loop (dropping it frees port 4662).
    listener: Option<JoinHandle<()>>,
    /// Sender handed to each ServerLink; its forwarder task is spawned once.
    server_tx: Option<mpsc::Sender<ServerEvent>>,
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
            config_dir,
            state: EngineState::Stopped,
            events: tx,
            routing,
            downloads: Vec::new(),
            server: None,
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

    /// An honest one-line status for the UI - never claims a connection we do
    /// not have.
    fn online_status(&self) -> String {
        if self.is_online() {
            "Connected".to_string()
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

    /// The in-progress downloads.
    pub fn downloads(&self) -> &[Arc<Download>] {
        &self.downloads
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
        self.downloads = resume_downloads(&self.config_dir);
        for dl in &self.downloads {
            let total = dl.size().await;
            let have = total - dl.missing().await;
            let hash = dl.hash().await;
            self.emit(EngineEvent::Progress { hash, have, total });
        }

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
        }

        self.set_state(EngineState::Running);
        self.emit(EngineEvent::Status(self.online_status()));
    }

    /// Bind the inbound peer port and accept connections. This is what earns a
    /// HighID: the server's HighID test is a bare TCP connect+close (no eD2k
    /// HELLO), so simply ACCEPTING is enough to pass it. Real peers that follow
    /// get a proper hello handshake. Idempotent; a bind failure is survivable
    /// (we just stay LowID).
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
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    continue;
                };
                let me = me.clone();
                tokio::spawn(async move {
                    let mut fs = FramedStream::new(stream);
                    // A bare connect+close (the server's probe) just ends here.
                    let _ =
                        timeout(Duration::from_secs(8), peer_handshake_inbound(&mut fs, &me)).await;
                });
            }
        });
        self.listener = Some(handle);
    }

    /// Best-effort: ask the gateway to forward our port, so a real device (which
    /// has no hand-configured router rule) can still earn a HighID. Tries NAT-PMP
    /// and UPnP - consumer gateways speak one or the other.
    async fn map_port(&self) {
        if let Ok(ext) = crate::upnp::map_port(TCP_PORT, "padMule", 0).await {
            self.emit(EngineEvent::Server(format!(
                "UPnP mapped port {TCP_PORT} (external IP {ext})"
            )));
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
            if let Ok(Ok(ServerState::Connected { id, low_id })) =
                timeout(Duration::from_secs(12), link.connect()).await
            {
                self.emit(EngineEvent::Server(format!(
                    "Connected to {addr} ({}, id {id:#x})",
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
        let Ok(mut node) = KadNode::bind(bind, TCP_PORT).await else {
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
    /// no-op unless currently `Paused`. `Paused` -> `Running`. Phase 3 does the
    /// real reconnect between the two status lines.
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
                Some(s) => matches!(
                    timeout(Duration::from_secs(12), s.resume()).await,
                    Ok(Ok(ServerState::Connected { .. }))
                ),
                None => false,
            };
            if !resumed {
                self.server = None;
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
    async fn new_loads_identity_and_starts_stopped() {
        let dir = tmp("new");
        let _ = std::fs::remove_dir_all(&dir);
        let (engine, _rx) = Engine::new(&dir).unwrap();
        assert_eq!(engine.state(), EngineState::Stopped);
        assert_eq!(engine.userhash()[5], 14, "identity loaded");
        assert!(dir.join("preferences.dat").exists());
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
        assert_eq!(engine.downloads().len(), 1, "the .part is resumed");
        let evs = drain(&mut rx).await;
        assert!(evs.iter().any(|e| matches!(
            e,
            EngineEvent::Progress { total, have, .. } if *total == 5000 && *have == 0
        )));
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
