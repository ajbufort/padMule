//! A minimal end-to-end file transfer between two padMule engines: a downloader
//! driver that pulls a file, and a matching serving peer. This is the first
//! real transfer (Wave 4c) - it exercises the request -> file-status ->
//! slot-grant -> 3-block-request -> block-receive loop and verifies the ed2k
//! hash. The full transfer engine (queues, multi-source, credits) builds on it.

use crate::framed::{FrameError, FramedStream};
use crate::transfer::{
    build_accept_upload, build_file_status_complete, build_req_filename_answer,
    build_request_filename, build_request_parts, build_sending_part, build_set_req_file_id,
    build_start_upload_req, parse_file_status, parse_request_parts, parse_sending_part,
    EMBLOCKSIZE, OP_ACCEPTUPLOADREQ, OP_FILEREQANSNOFIL, OP_FILESTATUS, OP_REQUESTFILENAME,
    OP_REQUESTPARTS, OP_REQUESTPARTS_I64, OP_SENDINGPART, OP_SENDINGPART_I64, OP_SETREQFILEID,
    OP_STARTUPLOADREQ, STANDARD_BLOCKS_REQUEST,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// A transfer error.
#[derive(Debug)]
pub enum TransferError {
    Frame(FrameError),
    /// The peer does not have the file (OP_FILEREQANSNOFIL).
    NoFile,
    /// A received block fell outside the file bounds.
    BadBlock,
}

impl From<FrameError> for TransferError {
    fn from(e: FrameError) -> Self {
        TransferError::Frame(e)
    }
}

impl From<mule_proto::IoError> for TransferError {
    fn from(e: mule_proto::IoError) -> Self {
        TransferError::Frame(FrameError::Protocol(e))
    }
}

/// Download the `size`-byte file `hash` from an already-handshaked peer, driving
/// the eD2k request sequence. Returns the assembled bytes (the caller verifies
/// the ed2k hash). Assumes a single source that has the whole file.
pub async fn download_file<S>(
    fs: &mut FramedStream<S>,
    hash: &[u8; 16],
    size: u64,
) -> Result<Vec<u8>, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Ask for the file and its status.
    fs.write_packet(&build_request_filename(hash)).await?;
    fs.write_packet(&build_set_req_file_id(hash)).await?;
    loop {
        let pkt = fs.read_packet_unpacked().await?;
        match pkt.opcode {
            OP_FILEREQANSNOFIL => return Err(TransferError::NoFile),
            OP_FILESTATUS => {
                let _status = parse_file_status(&pkt.payload)?;
                break;
            }
            _ => {} // filename answer etc. - ignore
        }
    }

    // Enter the queue and wait for a slot.
    fs.write_packet(&build_start_upload_req(hash)).await?;
    loop {
        let pkt = fs.read_packet_unpacked().await?;
        if pkt.opcode == OP_ACCEPTUPLOADREQ {
            break;
        }
        // OP_QUEUERANKING etc. - keep waiting.
    }

    // Block-request loop: up to 3 blocks of EMBLOCKSIZE per batch, refilled
    // until the file is complete.
    let mut buf = vec![0u8; size as usize];
    let mut next = 0u64;
    while next < size {
        let mut blocks = Vec::new();
        let mut off = next;
        for _ in 0..STANDARD_BLOCKS_REQUEST {
            if off >= size {
                break;
            }
            let end = (off + EMBLOCKSIZE).min(size);
            blocks.push((off, end));
            off = end;
        }
        let batch_total: u64 = blocks.iter().map(|(s, e)| e - s).sum();
        fs.write_packet(&build_request_parts(hash, &blocks)).await?;

        let mut batch_got = 0u64;
        while batch_got < batch_total {
            let pkt = fs.read_packet_unpacked().await?;
            let is_i64 = pkt.opcode == OP_SENDINGPART_I64;
            if pkt.opcode == OP_SENDINGPART || is_i64 {
                let sp = parse_sending_part(&pkt.payload, is_i64)?;
                let s = sp.start as usize;
                let e = sp.end as usize;
                if e > buf.len() || s > e {
                    return Err(TransferError::BadBlock);
                }
                buf[s..e].copy_from_slice(&sp.data);
                batch_got += sp.data.len() as u64;
            }
        }
        next = off;
    }
    Ok(buf)
}

/// A minimal serving peer for an already-handshaked connection: it advertises a
/// complete source for `hash`/`name` and serves requested blocks from `data`.
/// Returns when the peer disconnects.
pub async fn serve_file<S>(
    fs: &mut FramedStream<S>,
    hash: &[u8; 16],
    name: &[u8],
    data: &[u8],
) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let pkt = match fs.read_packet_unpacked().await {
            Ok(p) => p,
            Err(FrameError::Closed) => return Ok(()),
            Err(e) => return Err(e),
        };
        match pkt.opcode {
            OP_REQUESTFILENAME => {
                fs.write_packet(&build_req_filename_answer(hash, name))
                    .await?;
            }
            OP_SETREQFILEID => {
                fs.write_packet(&build_file_status_complete(hash)).await?;
            }
            OP_STARTUPLOADREQ => {
                fs.write_packet(&build_accept_upload()).await?;
            }
            OP_REQUESTPARTS | OP_REQUESTPARTS_I64 => {
                let i64 = pkt.opcode == OP_REQUESTPARTS_I64;
                let (_h, blocks) = match parse_request_parts(&pkt.payload, i64) {
                    Ok(v) => v,
                    Err(e) => return Err(FrameError::Protocol(e)),
                };
                for (s, e) in blocks {
                    let (s, e) = (s as usize, e as usize);
                    if e <= data.len() {
                        fs.write_packet(&build_sending_part(hash, s as u64, e as u64, &data[s..e]))
                            .await?;
                    }
                }
            }
            _ => {} // hashset request etc. - not needed for a single-part file
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::HelloInfo;
    use crate::peer_conn::{accept_peer, connect_peer};
    use mule_proto::ed2k_hash;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn two_engines_transfer_a_file_and_hash_matches() {
        // A ~400 KB file spanning 3 blocks (still one eD2k part, no hashset).
        let file: Vec<u8> = (0..400_000u32)
            .map(|i| (i.wrapping_mul(31)) as u8)
            .collect();
        let hash = ed2k_hash(&file);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Uploader: accept, then serve the file.
        let up_file = file.clone();
        let up_hash = hash;
        let uploader = tokio::spawn(async move {
            let bob = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "bob");
            let (_peer, mut fs) = accept_peer(&listener, &bob).await.unwrap();
            serve_file(&mut fs, &up_hash, b"movie.bin", &up_file)
                .await
                .unwrap();
        });

        // Downloader: connect, then pull the file.
        let alice = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "alice");
        let (_peer, mut fs) = connect_peer(addr, &alice).await.unwrap();
        let got = download_file(&mut fs, &hash, file.len() as u64)
            .await
            .unwrap();

        // The transferred bytes and their ed2k hash match the original.
        assert_eq!(got.len(), file.len());
        assert_eq!(got, file);
        assert_eq!(ed2k_hash(&got), hash);

        drop(fs); // closes the connection so the uploader returns
        uploader.await.unwrap();
    }
}
