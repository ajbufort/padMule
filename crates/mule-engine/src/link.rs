//! `ServerLink`: the server-connection lifecycle manager. It owns the current
//! socket and implements the clean pause/resume required on iPadOS (see
//! docs/wiki/lifecycle-and-reactivation.md): `pause()` drops the socket and
//! reports PausedForBackground; `resume()` reconnects and re-runs the
//! (idempotent) login handshake. State transitions are emitted as events so the
//! UI is never stale.

use crate::connection::{connect_server, login_handshake, ServerEvent, ServerState};
use crate::framed::{FrameError, FramedStream};
use crate::search::{build_search_request, parse_search_result, SearchParams, SearchResultFile};
use crate::server_messages::LoginRequest;
use crate::sources::{build_callback_request, build_get_sources, parse_found_sources, FoundSource};
use mule_proto::Packet;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// Asking a link that holds no socket to talk is a caller bug, not a wire
/// failure - name it rather than inventing a protocol error.
fn not_connected() -> FrameError {
    FrameError::Io(std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "server link is not connected",
    ))
}

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

    /// The server address this link is for (used to skip it in a global UDP
    /// fan-out - it was already queried over TCP).
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// True when logged in.
    pub fn is_connected(&self) -> bool {
        matches!(self.state, ServerState::Connected { .. })
    }

    /// True when the connected server advertised related-search support (it
    /// answers `related::<hash>` queries). False when disconnected or on a
    /// server that did not set the flag.
    pub fn related_search_supported(&self) -> bool {
        matches!(
            self.state,
            ServerState::Connected {
                related_search: true,
                ..
            }
        )
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

    /// True if the server has CLOSED its side of the connection (a clean kick or a
    /// drop). Cancel-safe: `peek` never removes bytes from the socket, so calling
    /// this between requests loses nothing and cannot corrupt framing. `Ok(0)` from
    /// a peek is the EOF signal; a short timeout means "no data, still connected".
    pub async fn peek_dropped(&self) -> bool {
        let Some(fs) = self.conn.as_ref() else {
            return false;
        };
        let mut buf = [0u8; 1];
        match timeout(Duration::from_millis(5), fs.get_ref().peek(&mut buf)).await {
            Ok(Ok(0)) => true,  // EOF: the server closed the connection
            Ok(Ok(_)) => false, // data waiting (peeked, not consumed): still up
            Ok(Err(_)) => true, // socket error: treat as dropped
            Err(_) => false,    // no data within the peek window: still connected
        }
    }

    /// Send `pkt`, then read until a `want` packet arrives or `wait` elapses.
    /// A server interleaves unsolicited traffic (status, messages, server lists)
    /// with replies, so anything else seen on the way is forwarded to the event
    /// stream rather than dropped - it is exactly what the UI wants to show.
    ///
    /// A timeout is NOT an error: eD2k servers simply say nothing when they have
    /// no answer (an unknown hash, a keyword they cannot match). `None` means
    /// "no reply", which every caller here treats as an empty result.
    async fn request(
        &mut self,
        pkt: &Packet,
        want: u8,
        wait: Duration,
    ) -> Result<Option<Packet>, FrameError> {
        let Some(fs) = self.conn.as_mut() else {
            return Err(not_connected());
        };
        fs.write_packet(pkt).await?;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok(None);
            }
            match timeout(remaining, fs.read_packet_unpacked()).await {
                Ok(Ok(p)) if p.opcode == want => return Ok(Some(p)),
                // Some other server packet - surface it and keep waiting.
                Ok(Ok(p)) => {
                    if let Some(ev) = crate::connection::classify_server_packet(&p) {
                        let _ = self.events.send(ev).await;
                    }
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(None),
            }
        }
    }

    /// Search the server's index. Empty when the server has nothing to say.
    pub async fn search(
        &mut self,
        params: &SearchParams,
        wait: Duration,
    ) -> Result<Vec<SearchResultFile>, FrameError> {
        let pkt = build_search_request(params);
        match self
            .request(&pkt, crate::search::OP_SEARCHRESULT, wait)
            .await?
        {
            Some(p) => Ok(parse_search_result(&p.payload).unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Ask the server who has `hash`.
    pub async fn get_sources(
        &mut self,
        hash: &[u8; 16],
        size: u64,
        wait: Duration,
    ) -> Result<Vec<FoundSource>, FrameError> {
        let pkt = build_get_sources(hash, size, false);
        match self
            .request(&pkt, crate::sources::OP_FOUNDSOURCES, wait)
            .await?
        {
            Some(p) => Ok(parse_found_sources(&p.payload, false)
                .map(|(_, s)| s)
                .unwrap_or_default()),
            None => Ok(Vec::new()),
        }
    }

    /// Ask the server to tell a LowID client to call US back. Fire-and-forget:
    /// the answer, if any, arrives as an inbound connection on our listener.
    pub async fn request_callback(&mut self, client_id: u32) -> Result<(), FrameError> {
        let Some(fs) = self.conn.as_mut() else {
            return Err(not_connected());
        };
        fs.write_packet(&build_callback_request(client_id)).await
    }

    /// Announce our shared files to the server (OP_OFFERFILES) so it indexes them
    /// for keyword search and can hand us out as a source. Fire-and-forget (no
    /// reply). `client_id`/`client_port` are our real ID + port when HighID, else
    /// the FILE_COMPLETE_ID/PORT markers (all our shares are complete).
    pub async fn offer_files(
        &mut self,
        files: &[crate::server_messages::OfferedFile<'_>],
        client_id: u32,
        client_port: u16,
    ) -> Result<(), FrameError> {
        let Some(fs) = self.conn.as_mut() else {
            return Err(not_connected());
        };
        fs.write_packet(&crate::server_messages::build_offer_files(
            files,
            client_id,
            client_port,
        ))
        .await
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
            related_search: false,
        };

        assert_eq!(link.connect().await.unwrap(), connected);
        assert!(link.is_connected());
        assert!(
            !link.related_search_supported(),
            "the mock advertises no flags"
        );

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

    /// A mock that logs us in, then answers ONE search - but slips an
    /// unsolicited OP_SERVERMESSAGE in front of the result, exactly as a real
    /// server interleaves its chatter with replies.
    async fn spawn_search_mock() -> SocketAddr {
        use crate::server_messages::OP_SERVERMESSAGE;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut sfs = FramedStream::new(sock);
                    // Login.
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
                    // The search request.
                    if sfs.read_packet().await.is_err() {
                        return;
                    }
                    // Chatter first - the link must forward it and keep waiting.
                    let mut msg = (5u16).to_le_bytes().to_vec();
                    msg.extend_from_slice(b"hello");
                    let _ = sfs
                        .write_packet(&Packet::new(PROT_EDONKEY, OP_SERVERMESSAGE, msg))
                        .await;
                    // Then the real answer (the byte-exact shape from
                    // search.rs::parse_one_result_file).
                    let mut payload = vec![0x01, 0x00, 0x00, 0x00]; // count = 1
                    payload.extend_from_slice(&[0xAA; 16]); // hash
                    payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x0A]); // id
                    payload.extend_from_slice(&[0x36, 0x12]); // port 4662
                    payload.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]); // tagcount = 2
                    payload.extend_from_slice(&[0x02, 0x01, 0x00, 0x01, 0x01, 0x00, b'f']);
                    payload.extend_from_slice(&[0x03, 0x01, 0x00, 0x02, 0x64, 0x00, 0x00, 0x00]);
                    let _ = sfs
                        .write_packet(&Packet::new(
                            PROT_EDONKEY,
                            crate::search::OP_SEARCHRESULT,
                            payload,
                        ))
                        .await;
                    let _ = sfs.read_packet().await;
                });
            }
        });
        addr
    }

    #[tokio::test]
    async fn search_round_trips_and_forwards_chatter_seen_on_the_way() {
        let addr = spawn_search_mock().await;
        let (tx, mut rx) = mpsc::channel(64);
        let mut link = ServerLink::new(addr, sample_login(), tx);
        link.connect().await.unwrap();

        let params = SearchParams {
            keyword: "f".to_string(),
            file_type: None,
            min_size: None,
            max_size: None,
            min_sources: None,
            extension: None,
        };
        let files = link.search(&params, Duration::from_secs(5)).await.unwrap();
        assert_eq!(files.len(), 1, "the search result parsed");
        assert_eq!(files[0].hash, [0xAA; 16]);

        // The unsolicited message that arrived BEFORE the result must have been
        // forwarded, not swallowed - that chatter is what the UI shows.
        drop(link);
        let mut msgs = Vec::new();
        while let Some(ev) = rx.recv().await {
            if let ServerEvent::Message(m) = ev {
                msgs.push(m);
            }
        }
        assert_eq!(msgs, vec!["hello".to_string()]);
    }

    #[tokio::test]
    async fn search_on_a_disconnected_link_errors_rather_than_hanging() {
        let (tx, _rx) = mpsc::channel(16);
        let mut link = ServerLink::new("127.0.0.1:1".parse().unwrap(), sample_login(), tx);
        let params = SearchParams {
            keyword: "x".to_string(),
            file_type: None,
            min_size: None,
            max_size: None,
            min_sources: None,
            extension: None,
        };
        assert!(link.search(&params, Duration::from_secs(1)).await.is_err());
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
