//! A minimal end-to-end file transfer between two padMule engines: a downloader
//! driver that pulls a file, and a matching serving peer. This is the first
//! real transfer (Wave 4c) - it exercises the request -> file-status ->
//! slot-grant -> 3-block-request -> block-receive loop and verifies the ed2k
//! hash. The full transfer engine (queues, multi-source, credits) builds on it.

use crate::framed::{FrameError, FramedStream};
use crate::transfer::{
    build_accept_upload, build_file_req_ans_no_fil, build_file_status, build_file_status_complete,
    build_hashset_answer, build_multipacket_answer, build_req_filename_answer,
    build_request_filename_ext, build_request_parts, build_sending_part, build_set_req_file_id,
    build_start_upload_req, parse_file_status, parse_multipacket_hash, parse_request_parts,
    BlockReceiver, EMBLOCKSIZE, OP_ACCEPTUPLOADREQ, OP_FILEREQANSNOFIL, OP_FILESTATUS,
    OP_HASHSETREQUEST, OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_REQUESTFILENAME, OP_REQUESTPARTS,
    OP_REQUESTPARTS_I64, OP_SETREQFILEID, OP_STARTUPLOADREQ, STANDARD_BLOCKS_REQUEST,
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
    /// The peer queued us instead of granting an upload slot (OP_QUEUERANKING).
    /// Not a real error - it just means "no free slot here, move on".
    Queued,
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
        if std::env::var_os("SERVE_DEBUG").is_some() {
            eprintln!(
                "  serve <- opcode 0x{:02x} ({} bytes)",
                pkt.opcode,
                pkt.payload.len()
            );
        }
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
            OP_MULTIPACKET | OP_MULTIPACKET_EXT => {
                // A capable downloader bundles the whole file request into one
                // packet. Answer with the name + status pair (build_multipacket_answer
                // documents why the bundled sub-requests need no parsing); an unknown
                // hash gets OP_FILEREQANSNOFIL, exactly as the individual path would.
                match parse_multipacket_hash(&pkt.payload) {
                    Ok(h) if h == f.hash => {
                        fs.write_packet(&build_multipacket_answer(
                            &f.hash,
                            f.name,
                            f.available,
                            None,
                        ))
                        .await?;
                    }
                    Ok(h) => fs.write_packet(&build_file_req_ans_no_fil(&h)).await?,
                    Err(_) => {} // malformed multipacket - ignore
                }
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
                    // The same request-width line the production loop
                    // (`share::serve_shared`) holds, because BOTH authorities
                    // do: eMule 0.50a throws IDS_ERR_LARGEREQBLOCK ("Client
                    // requested too large of a block") on
                    // `i64uTogo > EMBLOCKSIZE*3` (UploadClient.cpp:316-317),
                    // and aMule drops the block with "AddReqBlock: Block
                    // request too large" on the identical condition
                    // (UploadClient.cpp:320-321). Three blocks is the whole
                    // window a real downloader keeps pending, so this refuses
                    // nothing an honest peer asks for - and `s <= e` keeps a
                    // reversed range from panicking the slice below.
                    if s <= e && e <= f.data.len() && e - s <= 3 * EMBLOCKSIZE as usize {
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
    async fn serve_answers_a_multipacket_with_name_and_status() {
        use crate::transfer::{OP_MULTIPACKETANSWER, OP_MULTIPACKET_EXT, OP_REQFILENAMEANSWER};
        use mule_proto::{Packet, PROT_EMULE};

        let data = vec![0xABu8; 1000];
        let hash = ed2k_hash(&data);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let up_data = data.clone();
        let up_hash = hash;
        let uploader = tokio::spawn(async move {
            let bob = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "bob");
            let (_peer, mut fs) = accept_peer(&listener, &bob).await.unwrap();
            serve_file(&mut fs, &up_hash, b"clip.bin", &up_data)
                .await
                .unwrap();
        });

        let alice = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "alice");
        let (_peer, mut fs) = connect_peer(addr, &alice).await.unwrap();

        // A downloader that supports multipacket bundles the whole file request:
        // <hash><u64 size><0x58 OP_REQUESTFILENAME + extended info>...
        let mut payload = Vec::new();
        payload.extend_from_slice(&hash);
        payload.extend_from_slice(&(data.len() as u64).to_le_bytes());
        payload.push(OP_REQUESTFILENAME); // a bundled sub-request; serve ignores the body
        fs.write_packet(&Packet::new(PROT_EMULE, OP_MULTIPACKET_EXT, payload))
            .await
            .unwrap();

        let ans =
            tokio::time::timeout(std::time::Duration::from_secs(2), fs.read_packet_unpacked())
                .await
                .expect("serve must answer the multipacket")
                .unwrap();
        assert_eq!(ans.opcode, OP_MULTIPACKETANSWER);
        assert_eq!(&ans.payload[..16], &hash); // hash first
        assert_eq!(ans.payload[16], OP_REQFILENAMEANSWER); // then the name sub-answer

        drop(fs);
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

    /// The reference serving peer must hold the production request-width line:
    /// eMule 0.50a throws `IDS_ERR_LARGEREQBLOCK` on `i64uTogo > EMBLOCKSIZE*3`
    /// (UploadClient.cpp:316-317) and aMule drops the block on the identical
    /// condition (UploadClient.cpp:320-321), and `share::serve_shared` enforces
    /// the same bound. `serve` is pub and re-exported, so an unbounded copy
    /// would hand any padMule-to-padMule test a peer no real network contains.
    /// Mirrors the share.rs test pair: the legal request afterwards proves the
    /// refusal is SELECTIVE and did not kill the session, which a "no data
    /// came back" test alone would accept.
    #[tokio::test]
    async fn an_oversized_block_request_is_refused_by_the_reference_server() {
        use crate::transfer::OP_SENDINGPART;

        let file = vec![0x5Au8; 3 * EMBLOCKSIZE as usize + 4096];
        let hash = ed2k_hash(&file);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up_file = file.clone();
        let uploader = tokio::spawn(async move {
            let bob = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "bob");
            let (_peer, mut fs) = accept_peer(&listener, &bob).await.unwrap();
            let _ = serve_file(&mut fs, &hash, b"big.bin", &up_file).await;
        });
        let alice = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "alice");
        let (_peer, mut fs) = connect_peer(addr, &alice).await.unwrap();

        // ONE byte past the limit: the boundary is the whole rule, and a test
        // that overshoots by a megabyte would still pass against a bound set
        // anywhere in between.
        let over = 3 * EMBLOCKSIZE + 1;
        fs.write_packet(&build_request_parts(&hash, &[(0u64, over)]))
            .await
            .unwrap();
        // Then a plainly legal block, distinct offset so the two are told apart.
        fs.write_packet(&build_request_parts(&hash, &[(1000u64, 2000u64)]))
            .await
            .unwrap();

        // BOUNDED: a refusal produces no packet at all, so an unbounded read
        // would hang instead of failing.
        let p = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let p = fs.read_packet_unpacked().await.unwrap();
                if p.opcode == OP_SENDINGPART {
                    break p;
                }
            }
        })
        .await
        .expect("the legal block must still be served - nothing came back at all");
        let start = u32::from_le_bytes(p.payload[16..20].try_into().unwrap()) as u64;
        assert_eq!(
            start, 1000,
            "the oversized block must be refused and the legal one still served; \
             a stream starting at 0 means the {over}-byte ask was honoured"
        );

        drop(fs);
        uploader.await.unwrap();
    }

    /// The bound is `> EMBLOCKSIZE * 3`, so a request of EXACTLY three blocks
    /// is legitimate and must still be served - pinned separately (mirroring
    /// share.rs's `a_request_of_exactly_three_blocks_is_still_served`) because
    /// a fix that used `>=`, or clamped to one block, would leave the test
    /// above green while breaking every real eMule downloader.
    #[tokio::test]
    async fn a_request_of_exactly_three_blocks_is_served_by_the_reference_server() {
        use crate::transfer::OP_SENDINGPART;

        let file = vec![0xC3u8; 3 * EMBLOCKSIZE as usize + 4096];
        let hash = ed2k_hash(&file);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up_file = file.clone();
        let uploader = tokio::spawn(async move {
            let bob = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "bob");
            let (_peer, mut fs) = accept_peer(&listener, &bob).await.unwrap();
            let _ = serve_file(&mut fs, &hash, b"exact3.bin", &up_file).await;
        });
        let alice = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "alice");
        let (_peer, mut fs) = connect_peer(addr, &alice).await.unwrap();

        fs.write_packet(&build_request_parts(&hash, &[(0u64, 3 * EMBLOCKSIZE)]))
            .await
            .unwrap();

        // Bounded for the same reason as above: a boundary set one block too
        // tight must FAIL here rather than hang.
        let p = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let p = fs.read_packet_unpacked().await.unwrap();
                if p.opcode == OP_SENDINGPART {
                    break p;
                }
            }
        })
        .await
        .expect("exactly 3 blocks is the LEGAL window - refusing it breaks every real eMule");
        let start = u32::from_le_bytes(p.payload[16..20].try_into().unwrap()) as u64;
        assert_eq!(
            start, 0,
            "exactly 3 blocks is the legal window, not one over"
        );

        drop(fs);
        uploader.await.unwrap();
    }
}
