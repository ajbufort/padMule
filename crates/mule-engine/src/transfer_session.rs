//! A minimal end-to-end file transfer between two padMule engines: a downloader
//! driver that pulls a file, and a matching serving peer. This is the first
//! real transfer (Wave 4c) - it exercises the request -> file-status ->
//! slot-grant -> 3-block-request -> block-receive loop and verifies the ed2k
//! hash. The full transfer engine (queues, multi-source, credits) builds on it.

use crate::framed::{FrameError, FramedStream};
use crate::transfer::{
    build_accept_upload, build_file_status, build_file_status_complete, build_hashset_answer,
    build_req_filename_answer, build_request_filename_ext, build_request_parts, build_sending_part,
    build_set_req_file_id, build_start_upload_req, parse_file_status, parse_request_parts,
    BlockReceiver, EMBLOCKSIZE, OP_ACCEPTUPLOADREQ, OP_FILEREQANSNOFIL, OP_FILESTATUS,
    OP_HASHSETREQUEST, OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_REQUESTPARTS_I64, OP_SETREQFILEID,
    OP_STARTUPLOADREQ, STANDARD_BLOCKS_REQUEST,
};
use tokio::io::{AsyncRead, AsyncWrite};

/// A transfer error.
#[derive(Debug)]
pub enum TransferError {
    Frame(FrameError),
    /// The peer does not have the file (OP_FILEREQANSNOFIL).
    NoFile,
    /// The peer sent a data packet outside what we asked for (see `BlockError`).
    BadBlock,
    /// Writing to the `.part` file failed.
    Io(std::io::Error),
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

impl From<crate::transfer::BlockError> for TransferError {
    fn from(_: crate::transfer::BlockError) -> Self {
        // Every BlockError means the peer sent something outside the request.
        TransferError::BadBlock
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
    fs.write_packet(&build_request_filename_ext(hash)).await?;
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
    // until the file is complete. The same hardened BlockReceiver the
    // multi-source driver uses validates every reply, so this shares its
    // panic/hang/compression handling rather than re-implementing (and
    // re-mis-implementing) the receive logic.
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
        fs.write_packet(&build_request_parts(hash, &blocks)).await?;

        let mut rx = BlockReceiver::new(*hash, size, &blocks);
        while !rx.is_done() {
            let pkt = fs.read_packet_unpacked().await?;
            for w in rx.accept(pkt.opcode, &pkt.payload)? {
                let s = w.offset as usize;
                buf[s..s + w.data.len()].copy_from_slice(&w.data);
            }
        }
        next = off;
    }
    Ok(buf)
}

/// What a serving peer offers.
pub struct ServedFile<'a> {
    pub hash: [u8; 16],
    pub name: &'a [u8],
    pub data: &'a [u8],
    /// Per-part MD4s, served on OP_HASHSETREQUEST. May be empty for a
    /// single-part file, which needs no hashset.
    pub part_hashes: &'a [[u8; 16]],
    /// Which parts we hold. `None` means a COMPLETE source, which upstream
    /// signals with a part count of 0 rather than an all-ones bitfield.
    pub available: Option<&'a [bool]>,
}

/// A serving peer for an already-handshaked connection. Returns when the peer
/// disconnects.
pub async fn serve<S>(fs: &mut FramedStream<S>, f: &ServedFile<'_>) -> Result<(), FrameError>
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
                fs.write_packet(&build_req_filename_answer(&f.hash, f.name))
                    .await?;
            }
            OP_SETREQFILEID => {
                let p = match f.available {
                    Some(parts) => build_file_status(&f.hash, parts),
                    None => build_file_status_complete(&f.hash),
                };
                fs.write_packet(&p).await?;
            }
            OP_HASHSETREQUEST => {
                fs.write_packet(&build_hashset_answer(&f.hash, f.part_hashes))
                    .await?;
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
                    if e <= f.data.len() {
                        fs.write_packet(&build_sending_part(
                            &f.hash,
                            s as u64,
                            e as u64,
                            &f.data[s..e],
                        ))
                        .await?;
                    }
                }
            }
            _ => {}
        }
    }
}

/// A serving peer that holds the COMPLETE file. Thin wrapper over [`serve`].
pub async fn serve_file<S>(
    fs: &mut FramedStream<S>,
    hash: &[u8; 16],
    name: &[u8],
    data: &[u8],
) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    serve(
        fs,
        &ServedFile {
            hash: *hash,
            name,
            data,
            part_hashes: &[],
            available: None,
        },
    )
    .await
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

    #[tokio::test]
    async fn secure_ident_then_transfer_on_one_connection() {
        // Both engines run the mutual secure-ident exchange right after the hello,
        // THEN transfer the file - proving identity and transfer coexist on one
        // connection with no dropped packets (each side sends its signature before
        // any transfer packet, so run_secure_ident returns before the transfer).
        use crate::secure_ident::{run_secure_ident, Identity};

        let file: Vec<u8> = (0..250_000u32)
            .map(|i| (i.wrapping_mul(17)) as u8)
            .collect();
        let hash = ed2k_hash(&file);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let up_file = file.clone();
        let uploader = tokio::spawn(async move {
            let bob_id = Identity::generate();
            let bob = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "bob");
            let (_peer, mut fs) = accept_peer(&listener, &bob).await.unwrap();
            let verified = run_secure_ident(&mut fs, &bob_id).await.unwrap();
            serve_file(&mut fs, &hash, b"secure.bin", &up_file)
                .await
                .unwrap();
            verified
        });

        let alice_id = Identity::generate();
        let alice = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "alice");
        let (_peer, mut fs) = connect_peer(addr, &alice).await.unwrap();
        let peer_verified = run_secure_ident(&mut fs, &alice_id).await.unwrap();
        let got = download_file(&mut fs, &hash, file.len() as u64)
            .await
            .unwrap();

        // Each side verified the other's identity...
        assert!(peer_verified, "downloader must verify the uploader");
        // ...and the file transferred correctly THROUGH the same connection.
        assert_eq!(got, file);

        drop(fs);
        let uploader_verified = uploader.await.unwrap();
        assert!(uploader_verified, "uploader must verify the downloader");
    }
}
