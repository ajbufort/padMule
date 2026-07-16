//! mule-ffi: the UniFFI seam between the Rust engine and the native (SwiftUI)
//! iPad shell. It wraps [`mule_engine::Engine`] in an FFI-friendly facade -
//! opaque hashes become hex strings, the event stream is drained by polling, and
//! the async `&mut self` lifecycle is driven on an internal tokio runtime so the
//! exported methods are simple and synchronous.
//!
//! The Swift bindings are generated from the compiled cdylib by the
//! `uniffi-bindgen` bin target (see its docs). On-device wiring is Wave 8; this
//! crate is validated here by compiling + generating bindings + Rust-side tests.

use std::sync::Arc;

use mule_engine::{Engine, EngineEvent, EngineState};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::UnboundedReceiver;
use tokio::sync::Mutex;

uniffi::setup_scaffolding!();

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
}

/// A snapshot of one in-progress download.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct DownloadInfo {
    pub hash: String,
    pub name: String,
    pub size: u64,
    pub have: u64,
    pub complete: bool,
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
    #[uniffi::constructor]
    pub fn new(config_dir: String) -> Result<Arc<Self>, FfiError> {
        let (engine, rx) = Engine::new(&config_dir).map_err(|e| FfiError::Io {
            message: e.to_string(),
        })?;
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
                })
        })
    }

    /// How many Kad contacts the routing table holds.
    pub fn kad_contacts(&self) -> u32 {
        self.rt
            .block_on(async { self.inner.lock().await.kad_contacts() as u32 })
    }

    /// Snapshots of every in-progress download.
    pub fn downloads(&self) -> Vec<DownloadInfo> {
        self.rt.block_on(async {
            let g = self.inner.lock().await;
            let mut out = Vec::new();
            for dl in g.downloads() {
                let size = dl.size().await;
                let have = size - dl.missing().await;
                out.push(DownloadInfo {
                    hash: hex::encode(dl.hash().await),
                    name: dl.name().await,
                    size,
                    have,
                    complete: dl.is_complete().await,
                });
            }
            out
        })
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

    // Not a #[tokio::test]: the facade owns its own runtime and block_on would
    // panic inside an ambient one.
    #[test]
    fn facade_drives_lifecycle_and_surfaces_events() {
        let dir = tmp("life");
        let _ = std::fs::remove_dir_all(&dir);
        let eng = MuleEngine::new(dir.clone()).unwrap();

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
    }
}
