//! Async packet framing over a byte stream. Wraps `mule_proto`'s streaming
//! `read_packet`/`write_packet` around any tokio `AsyncRead + AsyncWrite`, so
//! the same logic drives a real `TcpStream` and an in-memory test duplex.

use core::fmt;
use mule_proto::{read_packet, write_packet, IoError, Packet};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// A framing or transport error.
#[derive(Debug)]
pub enum FrameError {
    /// The bytes did not form a valid packet (bad protocol byte, oversize).
    Protocol(IoError),
    /// Underlying socket I/O error.
    Io(std::io::Error),
    /// The peer closed the connection.
    Closed,
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Protocol(e) => write!(f, "protocol error: {e}"),
            FrameError::Io(e) => write!(f, "io error: {e}"),
            FrameError::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<IoError> for FrameError {
    fn from(e: IoError) -> Self {
        FrameError::Protocol(e)
    }
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        FrameError::Io(e)
    }
}

/// Reads and writes eD2k packets over an async byte stream, optionally through
/// the eMule obfuscation layer (RC4 on the raw bytes). Obfuscation is transparent
/// to the packet codec: the ciphers are applied to exactly the bytes read from /
/// written to the socket, in order, which is all a stream cipher needs.
pub struct FramedStream<S> {
    stream: S,
    buf: Vec<u8>,
    /// RC4 ciphers when the stream is obfuscated (`send` encrypts our writes,
    /// `recv` decrypts reads). `None` for a plaintext stream.
    ciphers: Option<mule_proto::StreamCiphers>,
}

impl<S> FramedStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap `stream` as a plaintext connection.
    pub fn new(stream: S) -> Self {
        FramedStream {
            stream,
            buf: Vec::new(),
            ciphers: None,
        }
    }

    /// Wrap `stream` as an OBFUSCATED connection whose handshake has already run,
    /// yielding `ciphers`. `prefix` is any already-read plaintext bytes to
    /// re-inject (normally empty for the obfuscated case).
    pub fn obfuscated(stream: S, ciphers: mule_proto::StreamCiphers) -> Self {
        FramedStream {
            stream,
            buf: Vec::new(),
            ciphers: Some(ciphers),
        }
    }

    /// Wrap `stream` as plaintext, but with `prefix` bytes already consumed from
    /// it (e.g. the marker byte the obfuscation auto-detector peeked and found to
    /// be a plaintext eD2k header). Those bytes are the head of the first packet.
    pub fn plaintext_with_prefix(stream: S, prefix: &[u8]) -> Self {
        FramedStream {
            stream,
            buf: prefix.to_vec(),
            ciphers: None,
        }
    }

    /// True if this connection is obfuscated.
    pub fn is_obfuscated(&self) -> bool {
        self.ciphers.is_some()
    }

    /// Read the next full packet, awaiting more bytes as needed. Errors with
    /// `Closed` if the peer disconnects mid-frame.
    pub async fn read_packet(&mut self) -> Result<Packet, FrameError> {
        loop {
            if let Some((pkt, consumed)) = read_packet(&self.buf)? {
                self.buf.drain(..consumed);
                return Ok(pkt);
            }
            let mut chunk = [0u8; 8192];
            let n = self.stream.read(&mut chunk).await?;
            if n == 0 {
                return Err(FrameError::Closed);
            }
            // Decrypt exactly the bytes just read, in order, before framing.
            if let Some(c) = self.ciphers.as_mut() {
                c.recv.apply(&mut chunk[..n]);
            }
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// Read the next packet, transparently decompressing it if it arrived
    /// zlib-packed (protocol 0xD4/0xF5/0xE5).
    pub async fn read_packet_unpacked(&mut self) -> Result<Packet, FrameError> {
        let pkt = self.read_packet().await?;
        if pkt.protocol == mule_proto::PROT_PACKED {
            Ok(mule_proto::decompress(&pkt, mule_proto::MAX_PACKET_SIZE)?)
        } else {
            Ok(pkt)
        }
    }

    /// Write one packet and flush it.
    pub async fn write_packet(&mut self, p: &Packet) -> Result<(), FrameError> {
        let mut bytes = write_packet(p);
        // Encrypt exactly the bytes we are about to send, in order.
        if let Some(c) = self.ciphers.as_mut() {
            c.send.apply(&mut bytes);
        }
        self.stream.write_all(&bytes).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Consume the wrapper, returning the underlying stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::PROT_EDONKEY;

    #[tokio::test]
    async fn round_trips_packets_over_a_duplex() {
        let (a, b) = tokio::io::duplex(4096);
        let mut writer = FramedStream::new(a);
        let mut reader = FramedStream::new(b);

        let sent = Packet::new(PROT_EDONKEY, 0x01, vec![0xAA, 0xBB, 0xCC]);
        writer.write_packet(&sent).await.unwrap();
        let got = reader.read_packet().await.unwrap();
        assert_eq!(got, sent);
    }

    #[tokio::test]
    async fn reassembles_a_packet_split_across_reads() {
        let (mut a, b) = tokio::io::duplex(4096);
        let mut reader = FramedStream::new(b);
        let pkt = Packet::new(PROT_EDONKEY, 0x34, vec![0x11; 100]);
        let wire = write_packet(&pkt);
        // Feed the wire bytes in two chunks with the read already pending.
        let reader_task = tokio::spawn(async move { reader.read_packet().await });
        {
            use tokio::io::AsyncWriteExt;
            a.write_all(&wire[..3]).await.unwrap();
            a.flush().await.unwrap();
            a.write_all(&wire[3..]).await.unwrap();
            a.flush().await.unwrap();
        }
        let got = reader_task.await.unwrap().unwrap();
        assert_eq!(got, pkt);
    }

    #[tokio::test]
    async fn closed_peer_yields_closed_error() {
        let (a, b) = tokio::io::duplex(4096);
        drop(a); // peer hangs up
        let mut reader = FramedStream::new(b);
        assert!(matches!(
            reader.read_packet().await,
            Err(FrameError::Closed)
        ));
    }
}
