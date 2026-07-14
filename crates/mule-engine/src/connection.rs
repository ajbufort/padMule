//! Server connection: drive the login handshake over a framed stream and emit
//! connection-state events. This is the seam the iPad UI observes (see
//! docs/wiki/lifecycle-and-reactivation.md): the engine reports state as an
//! EVENT STREAM so the UI is never stale, and the handshake is idempotent so
//! `resume()` (a future 3c-2 layer) can simply re-run it after a pause.

use crate::framed::{FrameError, FramedStream};
use crate::server_messages::{
    build_login_request, parse_id_change, parse_server_list, parse_server_message,
    parse_server_status, LoginRequest, OP_IDCHANGE, OP_SERVERLIST, OP_SERVERMESSAGE,
    OP_SERVERSTATUS,
};
use mule_proto::{decompress, MAX_PACKET_SIZE, PROT_PACKED};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// The observable state of a server connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerState {
    Disconnected,
    Connecting,
    /// Logged in. `low_id` distinguishes a server-local LowID from a directly
    /// reachable HighID.
    Connected {
        id: u32,
        low_id: bool,
    },
    /// Paused because the app is backgrounded (iPadOS lifecycle).
    PausedForBackground,
    /// The server refused to assign a client ID.
    Rejected,
}

/// An event emitted while a server connection runs. The UI renders directly
/// from these; it never polls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerEvent {
    State(ServerState),
    /// A server MOTD / status message.
    Message(String),
    /// Server population.
    Status {
        users: u32,
        files: u32,
    },
    /// Peer-server gossip (IP, port) to grow the server list.
    ServerList(Vec<(u32, u16)>),
}

/// Send the login and read the server's reply burst until the login answer
/// (OP_IDCHANGE) arrives, emitting events as packets come in. Returns the final
/// state (`Connected{..}` or `Rejected`). The caller emits `Connecting` before
/// the TCP connect and constructs the `FramedStream` from the connected socket.
pub async fn login_handshake<S>(
    fs: &mut FramedStream<S>,
    login: &LoginRequest,
    tx: &mpsc::Sender<ServerEvent>,
) -> Result<ServerState, FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fs.write_packet(&build_login_request(login)).await?;

    loop {
        let mut pkt = fs.read_packet().await?;
        if pkt.protocol == PROT_PACKED {
            pkt = decompress(&pkt, MAX_PACKET_SIZE)?;
        }
        match pkt.opcode {
            OP_SERVERMESSAGE => {
                if let Ok(m) = parse_server_message(&pkt.payload) {
                    let _ = tx.send(ServerEvent::Message(m)).await;
                }
            }
            OP_SERVERSTATUS => {
                if let Ok((users, files)) = parse_server_status(&pkt.payload) {
                    let _ = tx.send(ServerEvent::Status { users, files }).await;
                }
            }
            OP_SERVERLIST => {
                if let Ok(list) = parse_server_list(&pkt.payload) {
                    let _ = tx.send(ServerEvent::ServerList(list)).await;
                }
            }
            OP_IDCHANGE => {
                let ic = parse_id_change(&pkt.payload)?;
                let state = if ic.is_rejected() {
                    ServerState::Rejected
                } else {
                    ServerState::Connected {
                        id: ic.new_id,
                        low_id: ic.is_low_id(),
                    }
                };
                let _ = tx.send(ServerEvent::State(state.clone())).await;
                return Ok(state);
            }
            // OP_SERVERIDENT and anything else before the login answer are
            // ignored for the handshake.
            _ => {}
        }
    }
}

/// Connect a TCP socket to `addr` and wrap it for framing.
pub async fn connect_server(
    addr: std::net::SocketAddr,
) -> std::io::Result<FramedStream<tokio::net::TcpStream>> {
    let stream = tokio::net::TcpStream::connect(addr).await?;
    Ok(FramedStream::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server_messages::{DEFAULT_SERVER_FLAGS, OP_LOGINREQUEST};
    use mule_proto::{compress, Packet, Writer, PROT_EDONKEY};

    fn sample_login() -> LoginRequest {
        LoginRequest {
            user_hash: [0x11; 16],
            client_id: 0,
            tcp_port: 4662,
            nick: "padMule".to_string(),
            server_flags: DEFAULT_SERVER_FLAGS,
        }
    }

    fn server_status_payload(users: u32, files: u32) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(users);
        w.write_u32(files);
        w.into_inner()
    }

    fn server_message_payload(msg: &str) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_string_u16(msg.as_bytes());
        w.into_inner()
    }

    #[tokio::test]
    async fn handshake_reaches_highid_and_streams_events() {
        let (client, server) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let mut sfs = FramedStream::new(server);
            let login = sfs.read_packet().await.unwrap();
            assert_eq!(login.opcode, OP_LOGINREQUEST);
            // Reply burst: message, status, IDCHANGE (HighID 0x0A000001).
            sfs.write_packet(&Packet::new(
                PROT_EDONKEY,
                OP_SERVERMESSAGE,
                server_message_payload("welcome to padMule test server"),
            ))
            .await
            .unwrap();
            sfs.write_packet(&Packet::new(
                PROT_EDONKEY,
                OP_SERVERSTATUS,
                server_status_payload(1000, 2_000_000),
            ))
            .await
            .unwrap();
            sfs.write_packet(&Packet::new(
                PROT_EDONKEY,
                OP_IDCHANGE,
                0x0A00_0001u32.to_le_bytes().to_vec(),
            ))
            .await
            .unwrap();
        });

        let mut cfs = FramedStream::new(client);
        let (tx, mut rx) = mpsc::channel(16);
        let state = login_handshake(&mut cfs, &sample_login(), &tx)
            .await
            .unwrap();
        drop(tx);
        server_task.await.unwrap();

        assert_eq!(
            state,
            ServerState::Connected {
                id: 0x0A00_0001,
                low_id: false
            }
        );

        let mut events = Vec::new();
        while let Some(e) = rx.recv().await {
            events.push(e);
        }
        assert_eq!(
            events,
            vec![
                ServerEvent::Message("welcome to padMule test server".to_string()),
                ServerEvent::Status {
                    users: 1000,
                    files: 2_000_000
                },
                ServerEvent::State(ServerState::Connected {
                    id: 0x0A00_0001,
                    low_id: false
                }),
            ]
        );
    }

    #[tokio::test]
    async fn handshake_reports_rejection() {
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut sfs = FramedStream::new(server);
            let _ = sfs.read_packet().await.unwrap();
            // new_id == 0 -> rejected.
            sfs.write_packet(&Packet::new(PROT_EDONKEY, OP_IDCHANGE, vec![0, 0, 0, 0]))
                .await
                .unwrap();
        });
        let mut cfs = FramedStream::new(client);
        let (tx, _rx) = mpsc::channel(16);
        let state = login_handshake(&mut cfs, &sample_login(), &tx)
            .await
            .unwrap();
        server_task.await.unwrap();
        assert_eq!(state, ServerState::Rejected);
    }

    #[tokio::test]
    async fn handshake_decompresses_a_packed_reply() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server_task = tokio::spawn(async move {
            let mut sfs = FramedStream::new(server);
            let _ = sfs.read_packet().await.unwrap();
            // A long repetitive message compresses; server sends it packed.
            let big = "spam ".repeat(200);
            let packed = compress(&Packet::new(
                PROT_EDONKEY,
                OP_SERVERMESSAGE,
                server_message_payload(&big),
            ));
            assert_eq!(packed.protocol, PROT_PACKED);
            sfs.write_packet(&packed).await.unwrap();
            sfs.write_packet(&Packet::new(
                PROT_EDONKEY,
                OP_IDCHANGE,
                100u32.to_le_bytes().to_vec(), // LowID
            ))
            .await
            .unwrap();
        });
        let mut cfs = FramedStream::new(client);
        let (tx, mut rx) = mpsc::channel(16);
        let state = login_handshake(&mut cfs, &sample_login(), &tx)
            .await
            .unwrap();
        drop(tx);
        server_task.await.unwrap();

        assert_eq!(
            state,
            ServerState::Connected {
                id: 100,
                low_id: true
            }
        );
        // The packed message was decompressed and delivered.
        match rx.recv().await.unwrap() {
            ServerEvent::Message(m) => assert_eq!(m, "spam ".repeat(200)),
            other => panic!("expected Message, got {other:?}"),
        }
    }
}
