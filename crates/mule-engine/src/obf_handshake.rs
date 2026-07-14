//! The eMule TCP obfuscation handshake, client-to-client. Runs on the raw byte
//! stream BEFORE packet framing; on success the caller wraps the stream in an
//! obfuscated `FramedStream`. See docs/raw/wave5-crypto-research-2026-07-14.md
//! section A.
//!
//! Two entry points:
//! - [`obf_initiate`] - we opened the connection: send the handshake, verify the
//!   responder's reply, return the stream ciphers.
//! - [`obf_accept`] - we accepted a connection: peek the first byte to decide
//!   plaintext vs obfuscated (auto-detection), and if obfuscated run the
//!   responder half of the handshake.

use crate::framed::FrameError;
use mule_proto::obf::{
    build_initiator_handshake, is_plaintext_marker, semi_random_marker, StreamCiphers,
    ENM_OBFUSCATION, MAGICVALUE_SYNC,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// What [`obf_accept`] found on an inbound connection.
pub enum ObfDetect {
    /// The peer is speaking plaintext eD2k; `first` is the protocol byte we
    /// already consumed and must feed back into the framer.
    Plaintext { first: u8 },
    /// The peer is obfuscated; the handshake completed with these ciphers.
    /// Boxed because `StreamCiphers` (two RC4 states) dwarfs the plaintext case.
    Obfuscated(Box<StreamCiphers>),
}

/// A weak, non-cryptographic 32-bit value for the handshake's random key. This
/// only needs to vary between connections; obfuscation is not a security layer,
/// and the RC4 key also mixes in the userhash. Uses the wall clock plus a
/// process-local counter so two near-simultaneous handshakes still differ.
fn weak_random_key() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let c = COUNTER.fetch_add(0x9E37_79B9, Ordering::Relaxed);
    nanos ^ c
}

/// Initiate obfuscation as the connecting client. Generates a random key and
/// sends the handshake with no padding, then waits for and verifies the
/// responder's reply. Returns the ciphers for the now-obfuscated stream.
pub async fn obf_initiate<S>(
    stream: &mut S,
    target_hash: &[u8; 16],
) -> Result<StreamCiphers, FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    obf_initiate_with(stream, target_hash, weak_random_key(), &[]).await
}

/// [`obf_initiate`] with an explicit random key and padding (for tests).
pub async fn obf_initiate_with<S>(
    stream: &mut S,
    target_hash: &[u8; 16],
    random_key: u32,
    padding: &[u8],
) -> Result<StreamCiphers, FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut ciphers = StreamCiphers::initiator(target_hash, random_key);
    let marker = semi_random_marker(random_key as u8);
    let hs = build_initiator_handshake(&mut ciphers.send, marker, random_key, padding);
    stream.write_all(&hs).await?;
    stream.flush().await?;

    // Responder reply: RC4(recv)[ SYNC(4) | methodSelected(1) | padLen(1) | pad ].
    let mut head = [0u8; 6];
    stream.read_exact(&mut head).await?;
    ciphers.recv.apply(&mut head);
    let sync = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    if sync != MAGICVALUE_SYNC {
        return Err(FrameError::Protocol(mule_proto::IoError::BadHeader(
            head[0],
        )));
    }
    let pad_len = head[5] as usize;
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        stream.read_exact(&mut pad).await?;
        ciphers.recv.apply(&mut pad); // advance the keystream past the padding
    }
    Ok(ciphers)
}

/// Detect and (if obfuscated) complete the responder half of the handshake on an
/// inbound connection. `own_hash` is our userhash - the key the initiator used
/// as its target.
pub async fn obf_accept<S>(stream: &mut S, own_hash: &[u8; 16]) -> Result<ObfDetect, FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let first = stream.read_u8().await?;
    if is_plaintext_marker(first) {
        return Ok(ObfDetect::Plaintext { first });
    }

    // Obfuscated: read the 4-byte plaintext random key, then derive our ciphers.
    let mut rk = [0u8; 4];
    stream.read_exact(&mut rk).await?;
    let random_key = u32::from_le_bytes(rk);
    let mut ciphers = StreamCiphers::responder(own_hash, random_key);

    // Verify the encrypted SYNC, then consume methods + padding.
    let mut head = [0u8; 3 + 4]; // sync(4) + methodsSupported(1) + methodPreferred(1) + padLen(1)
    stream.read_exact(&mut head).await?;
    ciphers.recv.apply(&mut head);
    let sync = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
    if sync != MAGICVALUE_SYNC {
        return Err(FrameError::Protocol(mule_proto::IoError::BadHeader(
            head[0],
        )));
    }
    let pad_len = head[6] as usize;
    if pad_len > 0 {
        let mut pad = vec![0u8; pad_len];
        stream.read_exact(&mut pad).await?;
        ciphers.recv.apply(&mut pad);
    }

    // Reply: RC4(send)[ SYNC(4) | methodSelected=0 (1) | padLen=0 (1) ].
    let mut reply = Vec::with_capacity(6);
    reply.extend_from_slice(&MAGICVALUE_SYNC.to_le_bytes());
    reply.push(ENM_OBFUSCATION); // method selected
    reply.push(0); // no padding
    ciphers.send.apply(&mut reply);
    stream.write_all(&reply).await?;
    stream.flush().await?;

    Ok(ObfDetect::Obfuscated(Box::new(ciphers)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framed::FramedStream;
    use mule_proto::{Packet, PROT_EMULE};

    const HASH: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x0E, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x6F,
        0x00,
    ];

    #[tokio::test]
    async fn initiator_and_responder_complete_and_exchange_obfuscated_packets() {
        let (mut a, mut b) = tokio::io::duplex(65536);

        // The responder derives its ciphers from ITS OWN hash, which is the
        // initiator's target - so both sides pass the same HASH here.
        let responder = tokio::spawn(async move {
            let det = obf_accept(&mut b, &HASH).await.unwrap();
            let ciphers = match det {
                ObfDetect::Obfuscated(c) => *c,
                ObfDetect::Plaintext { .. } => panic!("should have detected obfuscation"),
            };
            let mut fs = FramedStream::obfuscated(b, ciphers);
            // Receive one packet, then send one back.
            let got = fs.read_packet().await.unwrap();
            fs.write_packet(&Packet::new(PROT_EMULE, 0x4C, got.payload.clone()))
                .await
                .unwrap();
            got
        });

        let ciphers = obf_initiate(&mut a, &HASH).await.unwrap();
        let mut fs = FramedStream::obfuscated(a, ciphers);
        assert!(fs.is_obfuscated());
        let sent = Packet::new(PROT_EMULE, 0x01, vec![1, 2, 3, 4, 5]);
        fs.write_packet(&sent).await.unwrap();
        let echoed = fs.read_packet().await.unwrap();

        let received_by_responder = responder.await.unwrap();
        assert_eq!(received_by_responder, sent);
        assert_eq!(echoed.opcode, 0x4C);
        assert_eq!(echoed.payload, sent.payload);
    }

    #[tokio::test]
    async fn responder_detects_a_plaintext_peer() {
        let (a, mut b) = tokio::io::duplex(4096);
        // The "initiator" is actually a plaintext client: it writes a normal
        // eD2k packet starting with 0xE3.
        let plain = Packet::new(mule_proto::PROT_EDONKEY, 0x01, vec![9, 9, 9]);
        let writer = tokio::spawn(async move {
            let mut fs = FramedStream::new(a);
            fs.write_packet(&plain).await.unwrap();
            fs.into_inner()
        });

        match obf_accept(&mut b, &HASH).await.unwrap() {
            ObfDetect::Plaintext { first } => {
                assert_eq!(first, 0xE3);
                // Re-inject the peeked byte and read the packet plaintext.
                let mut fs = FramedStream::plaintext_with_prefix(b, &[first]);
                let got = fs.read_packet().await.unwrap();
                assert_eq!(got.opcode, 0x01);
                assert_eq!(got.payload, vec![9, 9, 9]);
            }
            ObfDetect::Obfuscated(_) => panic!("plaintext peer misdetected as obfuscated"),
        }
        let _ = writer.await.unwrap();
    }

    #[tokio::test]
    async fn a_wrong_target_hash_fails_the_sync_check() {
        let (mut a, mut b) = tokio::io::duplex(4096);
        let wrong = [0xFFu8; 16];
        let responder = tokio::spawn(async move {
            // Responder uses a DIFFERENT hash, so its derived keys will not match
            // and the SYNC the initiator gets back will be garbage.
            obf_accept(&mut b, &wrong).await
        });
        let r = obf_initiate(&mut a, &HASH).await;
        assert!(r.is_err(), "sync must not verify with mismatched hashes");
        let _ = responder.await;
    }
}
