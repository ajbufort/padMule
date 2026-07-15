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

use crate::identity::NodeIdentity;
use crate::multi_source::{resume_downloads, Download};
use mule_files::{read_nodes_dat, write_nodes_dat, KadContact, NodesDat};
use mule_kad::RoutingTable;
use mule_proto::Kad128;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::mpsc;

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
        };
        Ok((engine, rx))
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
        self.set_state(EngineState::Running);
        self.emit(EngineEvent::Status("Started".into()));
    }

    /// App backgrounded: checkpoint to disk and release sockets. Idempotent - a
    /// no-op unless currently `Running`. `Running` -> `Paused`.
    pub async fn pause(&mut self) {
        if self.state != EngineState::Running {
            return;
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
        self.emit(EngineEvent::Status("Reconnecting...".into()));
        self.set_state(EngineState::Running);
        self.emit(EngineEvent::Status("Connected".into()));
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
        let contacts: Vec<KadContact> = self
            .routing
            .contacts()
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
            .collect();
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
        assert!(evs.contains(&EngineEvent::Status("Connected".into())));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn lifecycle_methods_are_idempotent() {
        let dir = tmp("idem");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();

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
            engine.add_kad_contacts(&contacts);
            engine.start().await;
            engine.pause().await; // checkpoint writes nodes.dat
            assert!(dir.join("nodes.dat").exists());
        }
        // A fresh engine on the same dir loads them on start.
        let (mut engine2, mut rx) = Engine::new(&dir).unwrap();
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
