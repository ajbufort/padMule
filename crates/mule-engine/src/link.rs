//! `ServerLink`: the server-connection lifecycle manager. It owns the current
//! socket and implements the clean pause/resume required on iPadOS (see
//! docs/wiki/lifecycle-and-reactivation.md): `pause()` drops the socket and
//! reports PausedForBackground; `resume()` reconnects and re-runs the
//! (idempotent) login handshake. State transitions are emitted as events so the
//! UI is never stale.

use crate::connection::{connect_server, login_handshake, ServerEvent, ServerState};
use crate::framed::{FrameError, FramedStream};
use crate::search::{
    build_search_more_request, build_search_request, parse_search_result_page, SearchParams,
    SearchResultFile, SearchResultPage,
};
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

/// What a server search actually did - because "no results" has THREE causes
/// and they used to be indistinguishable.
///
/// **WHY THIS TYPE EXISTS.** `read_search_page` returned an empty
/// `SearchResultPage` for a genuinely empty index, for a server that never
/// answered, AND for a payload that would not parse; the engine then
/// `unwrap_or_default()`-ed the `Err` on top, making a fourth. Four distinct
/// events, one indistinguishable output, reaching the user as a bare
/// "No results." On 2026-08-13 that cost a night: the app reported zero results
/// for a query the CLI answered with four hits against the same server, and
/// nothing in the code, the UI or the logs could say which case it was.
///
/// **THE RULE THIS ENCODES:** an empty answer and a failed question are
/// different facts. A caller that only wants files may still flatten them (see
/// [`ServerLink::search`]), but it must do so DELIBERATELY rather than by
/// default.
#[derive(Debug)]
pub enum ServerSearchOutcome {
    /// The server answered and the payload parsed. **May legitimately contain
    /// ZERO files** - that is an empty index, not a failure.
    Page(SearchResultPage),
    /// No OP_SEARCHRESULT arrived within the budget. On a long-lived shared link
    /// this is either a real timeout or a demux miss, and the two are worth
    /// telling apart later; today it is at least distinguishable from success.
    NoAnswer { waited: Duration },
    /// The server answered and the payload did NOT parse. Carries the size and
    /// the parser's own complaint, because "malformed" without a length is not
    /// actionable.
    Malformed { bytes: usize, why: String },
}

impl ServerSearchOutcome {
    /// The files, flattening both failures to empty. Named so a reader can see
    /// the information being discarded at the call site.
    pub fn files(self) -> Vec<SearchResultFile> {
        match self {
            ServerSearchOutcome::Page(p) => p.files,
            _ => Vec::new(),
        }
    }

    /// A short human-readable reason, or `None` when the server answered.
    /// This is what the UI shows instead of an unqualified "No results."
    pub fn failure_reason(&self) -> Option<String> {
        match self {
            ServerSearchOutcome::Page(_) => None,
            ServerSearchOutcome::NoAnswer { waited } => Some(format!(
                "the server did not answer the search within {}s",
                waited.as_secs()
            )),
            ServerSearchOutcome::Malformed { bytes, why } => Some(format!(
                "the server sent {bytes} bytes we could not read ({why})"
            )),
        }
    }
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

    /// Drain any buffered server packets (unsolicited MOTD / status / a kick
    /// message -> the event stream) and detect a drop, without blocking. Returns
    /// true if the server CLOSED the connection (a clean kick or a drop), having
    /// set the state to Disconnected. Call from the 1s heartbeat.
    ///
    /// Cancel-safe: FramedStream buffers and tokio's read consumes nothing on a
    /// timed-out read, so this cannot corrupt framing. Draining (rather than a bare
    /// peek) is what catches a kick that arrives as a MESSAGE FOLLOWED BY a close -
    /// a peek would only see the buffered message and wrongly report "still up".
    pub async fn poll_incoming(&mut self) -> bool {
        // Bound the burst so a chatty server cannot spin the heartbeat.
        for _ in 0..64 {
            if self.conn.is_none() {
                return false;
            }
            let result = {
                let fs = self.conn.as_mut().unwrap();
                timeout(Duration::from_millis(5), fs.read_packet_unpacked()).await
            };
            match result {
                Ok(Ok(pkt)) => {
                    if let Some(ev) = crate::connection::classify_server_packet(&pkt) {
                        let _ = self.events.send(ev).await;
                    }
                }
                // EOF or a read error -> the server dropped us.
                Ok(Err(_)) => {
                    self.conn = None;
                    self.set_state(ServerState::Disconnected).await;
                    return true;
                }
                // No COMPLETE packet ready within the window -> still connected.
                Err(_) => return false,
            }
        }
        false
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

    /// See [`ServerSearchOutcome`] for why this is an enum rather than a page.
    ///
    /// Search the server's index. Empty when the server has nothing to say.
    ///
    /// **This flattens [`ServerSearchOutcome::NoAnswer`] and
    /// [`ServerSearchOutcome::Malformed`] back into an empty vec**, which is correct
    /// for the CLI and for `related_search` (both of which only want the files),
    /// but is exactly the conflation that hid a live defect for a night on the
    /// app path. Anything that RENDERS the result to a user should call
    /// [`search_page`](Self::search_page) and report the outcome.
    pub async fn search(
        &mut self,
        params: &SearchParams,
        wait: Duration,
    ) -> Result<Vec<SearchResultFile>, FrameError> {
        Ok(self.search_page(params, wait).await?.files())
    }

    /// Like [`search`](Self::search) but reports WHICH of the three "no results"
    /// outcomes happened, plus the trailing "more results available" flag.
    pub async fn search_page(
        &mut self,
        params: &SearchParams,
        wait: Duration,
    ) -> Result<ServerSearchOutcome, FrameError> {
        let pkt = build_search_request(params);
        self.read_search_page(&pkt, wait).await
    }

    /// Ask for the NEXT page of the last search (bodiless OP_QUERY_MORE_RESULT;
    /// the query is held server-side, so this MUST run on the same connection).
    pub async fn search_more(&mut self, wait: Duration) -> Result<ServerSearchOutcome, FrameError> {
        let pkt = build_search_more_request();
        self.read_search_page(&pkt, wait).await
    }

    /// Send `pkt`, read one OP_SEARCHRESULT, and say WHAT HAPPENED.
    ///
    /// **THIS FUNCTION USED TO RETURN AN EMPTY PAGE FOR THREE DIFFERENT EVENTS:**
    /// a genuinely empty index, a server that never answered, and a payload
    /// that would not parse. The call site then added a fourth by
    /// `unwrap_or_default()`-ing the `Err`. So "the server has nothing" and
    /// "the search failed" were byte-identical to every caller, to the UI and to
    /// the logs. That is not hypothetical: on 2026-08-13 the app returned zero
    /// results for a query a CLI control answered with four hits, on the same
    /// server, and NOTHING anywhere could say which of the three had happened.
    /// The variants exist so that question is answerable.
    async fn read_search_page(
        &mut self,
        pkt: &Packet,
        wait: Duration,
    ) -> Result<ServerSearchOutcome, FrameError> {
        match self
            .request(pkt, crate::search::OP_SEARCHRESULT, wait)
            .await?
        {
            // A page that parses is the answer, EVEN IF IT HAS ZERO FILES - an
            // empty index is a legitimate reply and must stay distinct from the
            // two failures below.
            Some(p) => match parse_search_result_page(&p.payload) {
                Ok(page) => Ok(ServerSearchOutcome::Page(page)),
                Err(e) => Ok(ServerSearchOutcome::Malformed {
                    bytes: p.payload.len(),
                    why: e.to_string(),
                }),
            },
            None => Ok(ServerSearchOutcome::NoAnswer { waited: wait }),
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

    /// Ask the server for its known-servers list (OP_GETSERVERLIST, bodiless).
    /// Fire-and-forget, like both authorities: the answer arrives as an
    /// unsolicited OP_SERVERLIST (plus an OP_SERVERIDENT, which a server sends
    /// ONLY to a client that asked - eMule ServerSocket.cpp:431), forwarded by
    /// the event path into the engine's gossip harvest.
    pub async fn request_server_list(&mut self) -> Result<(), FrameError> {
        let Some(fs) = self.conn.as_mut() else {
            return Err(not_connected());
        };
        fs.write_packet(&crate::server_messages::build_get_server_list())
            .await
    }

    /// Announce our shared files to the server (OP_OFFERFILES) so it indexes them
    /// for keyword search and can hand us out as a source. Fire-and-forget (no
    /// reply). padMule always passes the FILE_COMPLETE_ID/PORT markers for
    /// `client_id`/`client_port` - even on HighID - so our public IP never
    /// enters the server's search index (see `Engine::offer_shared_to`).
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

    /// THE THREE "NO RESULTS" CAUSES MUST BE TELLABLE APART.
    ///
    /// This is the regression pin for the defect that cost a night on
    /// 2026-08-13: the app reported zero results for a query a CLI control
    /// answered with four hits, and nothing could say whether the server had
    /// nothing, never answered, or sent something unreadable. All three used to
    /// produce an identical empty `SearchResultPage`.
    ///
    /// The mock answers the SEARCH with whatever `reply` says, so each arm is
    /// driven through the REAL `read_search_page`, not by constructing the enum.
    async fn search_against(reply: Option<Vec<u8>>) -> ServerSearchOutcome {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
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
            // The search request.
            if sfs.read_packet().await.is_err() {
                return;
            }
            match reply {
                Some(payload) => {
                    let _ = sfs
                        .write_packet(&Packet::new(
                            PROT_EDONKEY,
                            crate::search::OP_SEARCHRESULT,
                            payload,
                        ))
                        .await;
                }
                // Answer NOTHING, so the read hits its budget.
                None => {
                    let _ = sfs.read_packet().await;
                }
            }
        });
        let (tx, _rx) = mpsc::channel(64);
        let mut link = ServerLink::new(addr, sample_login(), tx);
        link.connect().await.unwrap();
        let params = SearchParams {
            keyword: "anything".to_string(),
            ..Default::default()
        };
        link.search_page(&params, Duration::from_millis(400))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn an_empty_index_is_a_page_and_not_a_failure() {
        // count = 0, no trailing byte: a well-formed, genuinely empty answer.
        let out = search_against(Some(0u32.to_le_bytes().to_vec())).await;
        match &out {
            ServerSearchOutcome::Page(p) => assert!(p.files.is_empty()),
            other => panic!("an empty index must be a Page, got {other:?}"),
        }
        assert!(
            out.failure_reason().is_none(),
            "a server that answered with nothing has NOT failed - conflating \
             the two is the whole defect this type exists to prevent"
        );
    }

    #[tokio::test]
    async fn a_server_that_never_answers_is_noanswer_not_an_empty_page() {
        let out = search_against(None).await;
        assert!(
            matches!(out, ServerSearchOutcome::NoAnswer { .. }),
            "a timeout must not masquerade as an empty index, got {out:?}"
        );
        let why = out.failure_reason().expect("a timeout is a failure");
        assert!(
            why.contains("did not answer"),
            "the reason must name the timeout so a user can act on it: {why}"
        );
    }

    #[tokio::test]
    async fn an_unparseable_payload_is_malformed_and_carries_its_size() {
        // A count field claiming 9999 records with no records behind it.
        let out = search_against(Some(9999u32.to_le_bytes().to_vec())).await;
        match &out {
            ServerSearchOutcome::Malformed { bytes, .. } => assert_eq!(*bytes, 4),
            other => panic!("a truncated page must be Malformed, got {other:?}"),
        }
        assert!(out.failure_reason().is_some());
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
