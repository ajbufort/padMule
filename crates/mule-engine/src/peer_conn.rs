//! Client-to-client connection: drive the HELLO handshake over a socket, both
//! directions. The opener sends OP_HELLO and reads OP_HELLOANSWER; the accepter
//! reads OP_HELLO and replies OP_HELLOANSWER (see peer.rs / protocol-
//! understanding Part 2). `accept_peer` is the inbound listener that makes
//! HighID meaningful - it is what a server or peer connects BACK to.

use crate::framed::{FrameError, FramedStream};
use crate::peer::{build_hello, build_hello_answer, parse_hello, HelloInfo, ParsedHello};
use crate::peer::{OP_HELLO, OP_HELLOANSWER};
use mule_proto::{decompress, IoError, MAX_PACKET_SIZE, PROT_PACKED};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};

/// Read the next packet, decompressing it if it arrived zlib-packed.
async fn read_unpacked<S>(fs: &mut FramedStream<S>) -> Result<mule_proto::Packet, FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let pkt = fs.read_packet().await?;
    if pkt.protocol == PROT_PACKED {
        Ok(decompress(&pkt, MAX_PACKET_SIZE)?)
    } else {
        Ok(pkt)
    }
}

/// Perform the outbound handshake (we opened the connection): send OP_HELLO,
/// read the peer's OP_HELLOANSWER, return the peer's parsed hello.
pub async fn peer_handshake_outbound<S>(
    fs: &mut FramedStream<S>,
    my: &HelloInfo,
) -> Result<ParsedHello, FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fs.write_packet(&build_hello(my)).await?;
    let pkt = read_unpacked(fs).await?;
    if pkt.opcode != OP_HELLOANSWER {
        return Err(FrameError::Protocol(IoError::BadTag(pkt.opcode)));
    }
    Ok(parse_hello(&pkt.payload, false)?)
}

/// Perform the inbound handshake (we accepted the connection): read the peer's
/// OP_HELLO, reply OP_HELLOANSWER, return the peer's parsed hello.
pub async fn peer_handshake_inbound<S>(
    fs: &mut FramedStream<S>,
    my: &HelloInfo,
) -> Result<ParsedHello, FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let pkt = read_unpacked(fs).await?;
    if pkt.opcode != OP_HELLO {
        return Err(FrameError::Protocol(IoError::BadTag(pkt.opcode)));
    }
    let peer = parse_hello(&pkt.payload, true)?;
    fs.write_packet(&build_hello_answer(my)).await?;
    Ok(peer)
}

/// Connect to a peer and complete the outbound handshake.
pub async fn connect_peer(
    addr: std::net::SocketAddr,
    my: &HelloInfo,
) -> Result<(ParsedHello, FramedStream<TcpStream>), FrameError> {
    let stream = TcpStream::connect(addr).await?;
    let mut fs = FramedStream::new(stream);
    let peer = peer_handshake_outbound(&mut fs, my).await?;
    Ok((peer, fs))
}

/// Accept one inbound peer connection and complete the inbound handshake. This
/// is the HighID listener path (a server or peer connecting back to us).
pub async fn accept_peer(
    listener: &TcpListener,
    my: &HelloInfo,
) -> Result<(ParsedHello, FramedStream<TcpStream>), FrameError> {
    let (stream, _addr) = listener.accept().await?;
    let mut fs = FramedStream::new(stream);
    let peer = peer_handshake_inbound(&mut fs, my).await?;
    Ok((peer, fs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn two_peers_complete_the_handshake_on_loopback() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Bob accepts.
        let bob = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "bob");
        let bob_task = tokio::spawn(async move {
            let (alice_seen, _fs) = accept_peer(&listener, &bob).await.unwrap();
            alice_seen
        });

        // Alice connects.
        let alice = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "alice");
        let (bob_seen, _fs) = connect_peer(addr, &alice).await.unwrap();
        let alice_seen = bob_task.await.unwrap();

        // Each side learned the other's identity...
        assert_eq!(alice_seen.user_hash, [0xAA; 16]);
        assert_eq!(alice_seen.tcp_port, 4663);
        assert_eq!(bob_seen.user_hash, [0xBB; 16]);
        assert_eq!(bob_seen.tcp_port, 4662);

        // ...and the other's capabilities decode.
        let caps = bob_seen.capabilities().unwrap();
        assert_eq!(caps.udp_ver, 4);
        assert_eq!(caps.data_comp, 1);
        assert!(caps.large_files);
    }

    #[tokio::test]
    async fn outbound_rejects_a_non_helloanswer_reply() {
        use mule_proto::{Packet, PROT_EDONKEY};
        let (client, server) = tokio::io::duplex(4096);
        let server_task = tokio::spawn(async move {
            let mut sfs = FramedStream::new(server);
            let _hello = sfs.read_packet().await.unwrap();
            // Reply with the wrong opcode.
            sfs.write_packet(&Packet::new(PROT_EDONKEY, 0x59, vec![]))
                .await
                .unwrap();
        });
        let mut cfs = FramedStream::new(client);
        let me = HelloInfo::baseline([0x01; 16], 0, 4662, 4672, "me");
        let res = peer_handshake_outbound(&mut cfs, &me).await;
        assert!(matches!(
            res,
            Err(FrameError::Protocol(IoError::BadTag(0x59)))
        ));
        server_task.await.unwrap();
    }
}
