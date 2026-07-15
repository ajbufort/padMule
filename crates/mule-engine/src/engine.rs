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
use mule_proto::Kad128;
use std::io;
use std::path::{Path, PathBuf};
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
        let engine = Engine {
            identity,
            config_dir,
            state: EngineState::Stopped,
            events: tx,
        };
        Ok((engine, rx))
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
    /// running). Phases 3/4: connect the server, bootstrap Kad, resume downloads.
    pub async fn start(&mut self) {
        if self.state == EngineState::Running {
            return;
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

    /// Persist durable state. Phase 2 saves the identity; Phase 3 adds the Kad
    /// routing table (nodes.dat) and each download's `.part.met`.
    fn checkpoint(&self) {
        let _ = self.identity.save(&self.config_dir);
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
