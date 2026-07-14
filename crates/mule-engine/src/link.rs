//! `ServerLink`: the server-connection lifecycle manager. It owns the current
//! socket and implements the clean pause/resume required on iPadOS (see
//! docs/wiki/lifecycle-and-reactivation.md): `pause()` drops the socket and
//! reports PausedForBackground; `resume()` reconnects and re-runs the
//! (idempotent) login handshake. State transitions are emitted as events so the
//! UI is never stale.

use crate::connection::{connect_server, login_handshake, ServerEvent, ServerState};
use crate::framed::{FrameError, FramedStream};
use crate::server_messages::LoginRequest;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

/// Owns one server connection and its lifecycle.
pub struct ServerLink {
    addr: SocketAddr,
    login: LoginRequest,
    events: mpsc::Sender<ServerEvent>,
    conn: Option<FramedStream<TcpStream>>,
    state: ServerState,
}

impl ServerLink {
    /// Create a link (initially Disconnected; nothing connects until `connect`).
    pub fn new(addr: SocketAddr, login: LoginRequest, events: mpsc::Sender<ServerEvent>) -> Self {
        ServerLink {
            addr,
            login,
            events,
            conn: None,
            state: ServerState::Disconnected,
        }
    }

    /// The current observable state.
    pub fn state(&self) -> &ServerState {
        &self.state
    }

    /// True when logged in.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ServerState::Connected { .. })
    }

    async fn set_state(&mut self, s: ServerState) {
        self.state = s.clone();
        let _ = self.events.send(ServerEvent::State(s)).await;
    }

    async fn establish(&mut self) -> Result<ServerState, FrameError> {
        self.set_state(ServerState::Connecting).await;
        match self.try_establish().await {
            Ok(state) => {
                // login_handshake already emitted the Connected/Rejected event.
                self.state = state.clone();
                Ok(state)
            }
            Err(e) => {
                self.conn = None;
                self.set_state(ServerState::Disconnected).await;
                Err(e)
            }
        }
    }

    async fn try_establish(&mut self) -> Result<ServerState, FrameError> {
        let mut fs = connect_server(self.addr).await?;
        let state = login_handshake(&mut fs, &self.login, &self.events).await?;
        self.conn = Some(fs);
        Ok(state)
    }

    /// Connect and log in.
    pub async fn connect(&mut self) -> Result<ServerState, FrameError> {
        self.establish().await
    }

    /// Resume after a pause: reconnect and re-run the handshake (idempotent).
    pub async fn resume(&mut self) -> Result<ServerState, FrameError> {
        self.establish().await
    }

    /// Pause for backgrounding: drop the socket and report PausedForBackground.
    pub async fn pause(&mut self) {
        self.conn = None; // dropping the FramedStream closes the TcpStream
        self.set_state(ServerState::PausedForBackground).await;
    }

    /// Disconnect deliberately.
    pub async fn disconnect(&mut self) {
        self.conn = None;
        self.set_state(ServerState::Disconnected).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_messages::{DEFAULT_SERVER_FLAGS, OP_IDCHANGE};
    use mule_proto::{Packet, PROT_EDONKEY};
    use tokio::net::TcpListener;

    fn sample_login() -> LoginRequest {
        LoginRequest {
            user_hash: [0x22; 16],
            client_id: 0,
            tcp_port: 4662,
            nick: "padMule".to_string(),
            server_flags: DEFAULT_SERVER_FLAGS,
        }
    }

    /// A local mock server that answers every login with a HighID IDCHANGE.
    async fn spawn_mock_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let (sock, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut sfs = FramedStream::new(sock);
                    if sfs.read_packet().await.is_err() {
                        return;
                    }
                    let _ = sfs
                        .write_packet(&Packet::new(
                            PROT_EDONKEY,
                            OP_IDCHANGE,
                            0x0A00_0001u32.to_le_bytes().to_vec(),
                        ))
                        .await;
                    // Hold the connection until the client drops it.
                    let _ = sfs.read_packet().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn connect_pause_resume_over_a_real_socket() {
        let addr = spawn_mock_server().await;
        let (tx, mut rx) = mpsc::channel(64);
        let mut link = ServerLink::new(addr, sample_login(), tx);

        let connected = ServerState::Connected {
            id: 0x0A00_0001,
            low_id: false,
        };

        assert_eq!(link.connect().await.unwrap(), connected);
        assert!(link.is_connected());

        link.pause().await;
        assert_eq!(*link.state(), ServerState::PausedForBackground);
        assert!(!link.is_connected());

        assert_eq!(link.resume().await.unwrap(), connected);
        assert!(link.is_connected());

        // The State-event stream is honest across the whole lifecycle. Dropping
        // the link does not emit (drop is not async), so it is exactly these
        // five transitions.
        drop(link);
        let mut states = Vec::new();
        while let Some(ev) = rx.recv().await {
            if let ServerEvent::State(s) = ev {
                states.push(s);
            }
        }
        assert_eq!(
            states,
            vec![
                ServerState::Connecting,
                connected.clone(),
                ServerState::PausedForBackground,
                ServerState::Connecting,
                connected,
            ]
        );
    }

    #[tokio::test]
    async fn connect_failure_reports_disconnected() {
        // Nothing is listening on this port.
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let (tx, _rx) = mpsc::channel(16);
        let mut link = ServerLink::new(addr, sample_login(), tx);
        assert!(link.connect().await.is_err());
        assert_eq!(*link.state(), ServerState::Disconnected);
    }
}
