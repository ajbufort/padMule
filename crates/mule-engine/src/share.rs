//! The upload side: serving files we hold to peers that ask.
//!
//! A [`SharedFile`] is a COMPLETE file on disk we are willing to serve. When a
//! peer that reached our inbound listener asks for a hash we hold,
//! [`serve_shared`] answers the eD2k upload sequence (filename -> file status ->
//! hashset -> slot -> block requests), reading each requested block straight off
//! disk so a large file is never held in memory.
//!
//! Only COMPLETE files are shared for now: a finished download is a full source,
//! which upstream signals with a part count of 0 ([`build_file_status_complete`])
//! rather than an all-ones bitfield. Serving parts of an IN-PROGRESS download is
//! a later step - it needs range reads out of a live `.part` under the download's
//! lock and a real per-part availability bitfield.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use mule_proto::Packet;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::framed::{FrameError, FramedStream};
use crate::transfer::{
    build_accept_upload, build_file_req_ans_no_fil, build_file_status_complete,
    build_hashset_answer, build_req_filename_answer, build_sending_part, parse_request_parts,
    OP_HASHSETREQUEST, OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_REQUESTPARTS_I64, OP_SETREQFILEID,
    OP_STARTUPLOADREQ,
};

/// A complete file we will serve to peers.
#[derive(Debug, Clone)]
pub struct SharedFile {
    pub hash: [u8; 16],
    pub size: u64,
    pub name: Vec<u8>,
    /// Per-part MD4s (empty for a single-part file, which needs no hashset).
    pub part_hashes: Vec<[u8; 16]>,
    /// The finished file on disk, read block-by-block on demand.
    pub path: PathBuf,
}

/// True if `op` is a packet a peer sends when it wants to download FROM us. The
/// inbound listener uses this to tell a leecher (which talks first) from a
/// called-back LowID source (which stays silent, waiting for us to drive the
/// download of one of OUR files).
pub fn is_upload_request(op: u8) -> bool {
    matches!(op, OP_REQUESTFILENAME | OP_SETREQFILEID | OP_STARTUPLOADREQ)
}

/// The 16-byte file hash at the head of an upload-request payload, if present.
/// Both OP_REQUESTFILENAME (and its EXT form) and OP_SETREQFILEID lead with it.
pub fn head_hash(payload: &[u8]) -> Option<[u8; 16]> {
    payload.get(..16).map(|s| {
        let mut h = [0u8; 16];
        h.copy_from_slice(s);
        h
    })
}

/// Read a byte range off a finished file. Opened per request batch: simple, and
/// it keeps only one block (~180 KB) in memory at a time.
fn read_range(path: &Path, start: u64, end: u64) -> io::Result<Vec<u8>> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(start))?;
    let mut buf = vec![0u8; (end - start) as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

/// Serve whatever `library` file a peer asks for, over an already-handshaked
/// connection. `first` is the packet the caller already read to classify this
/// peer as a leecher (fed back in before reading more); pass `None` to read the
/// first packet here. Returns when the peer disconnects.
///
/// A request for a hash we do not hold is answered with OP_FILEREQANSNOFIL, so
/// the peer moves on cleanly rather than hanging. Block ranges outside the file
/// are dropped rather than trusted - the request came from the network.
pub async fn serve_shared<S>(
    fs: &mut FramedStream<S>,
    library: &[SharedFile],
    first: Option<Packet>,
) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let lookup = |payload: &[u8]| {
        head_hash(payload).and_then(|h| library.iter().find(|f| f.hash == h).cloned())
    };
    // The file this peer is after, once it names one.
    let mut file: Option<SharedFile> = None;
    let mut pending = first;
    loop {
        let pkt = match pending.take() {
            Some(p) => p,
            None => match fs.read_packet_unpacked().await {
                Ok(p) => p,
                Err(FrameError::Closed) => return Ok(()),
                Err(e) => return Err(e),
            },
        };
        match pkt.opcode {
            OP_REQUESTFILENAME => {
                file = lookup(&pkt.payload);
                match &file {
                    Some(f) => {
                        fs.write_packet(&build_req_filename_answer(&f.hash, &f.name))
                            .await?
                    }
                    None => {
                        if let Some(h) = head_hash(&pkt.payload) {
                            fs.write_packet(&build_file_req_ans_no_fil(&h)).await?;
                        }
                    }
                }
            }
            OP_SETREQFILEID => {
                if file.is_none() {
                    file = lookup(&pkt.payload);
                }
                match &file {
                    Some(f) => {
                        fs.write_packet(&build_file_status_complete(&f.hash))
                            .await?
                    }
                    None => {
                        if let Some(h) = head_hash(&pkt.payload) {
                            fs.write_packet(&build_file_req_ans_no_fil(&h)).await?;
                        }
                    }
                }
            }
            OP_HASHSETREQUEST => {
                if let Some(f) = &file {
                    fs.write_packet(&build_hashset_answer(&f.hash, &f.part_hashes))
                        .await?;
                }
            }
            OP_STARTUPLOADREQ => {
                if file.is_some() {
                    fs.write_packet(&build_accept_upload()).await?;
                }
            }
            OP_REQUESTPARTS | OP_REQUESTPARTS_I64 => {
                let Some(f) = file.clone() else { continue };
                let is_i64 = pkt.opcode == OP_REQUESTPARTS_I64;
                let (_h, blocks) = match parse_request_parts(&pkt.payload, is_i64) {
                    Ok(v) => v,
                    Err(e) => return Err(FrameError::Protocol(e)),
                };
                for (s, e) in blocks {
                    // The range came off the network: never read past the file.
                    if s <= e && e <= f.size {
                        let data = read_range(&f.path, s, e).map_err(FrameError::Io)?;
                        fs.write_packet(&build_sending_part(&f.hash, s, e, &data))
                            .await?;
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multi_source::{download_from_peer, Download};
    use crate::part_store::PartStore;
    use crate::peer::HelloInfo;
    use crate::peer_conn::{accept_peer, connect_peer};
    use crate::transfer_session::{download_file, TransferError};
    use mule_proto::{ed2k_hash, md4, PARTSIZE};
    use tokio::net::TcpListener;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("padmule-share-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn a_peer_downloads_a_complete_file_we_share() {
        let dir = tmpdir("one");
        // ~400 KB: several blocks, still a single eD2k part (no hashset needed).
        let data: Vec<u8> = (0..400_000u32)
            .map(|i| (i.wrapping_mul(31)) as u8)
            .collect();
        let hash = ed2k_hash(&data);
        let path = dir.join("movie.bin");
        std::fs::write(&path, &data).unwrap();
        let shared = vec![SharedFile {
            hash,
            size: data.len() as u64,
            name: b"movie.bin".to_vec(),
            part_hashes: vec![],
            path,
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None).await;
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        let got = download_file(&mut fs, &hash, data.len() as u64)
            .await
            .unwrap();

        assert_eq!(got, data);
        assert_eq!(ed2k_hash(&got), hash);

        drop(fs);
        up.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_hash_we_do_not_hold_is_refused_not_hung() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // An EMPTY library: whatever is asked for, we do not have it.
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &[], None).await;
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        let r = download_file(&mut fs, &[0x11; 16], 1000).await;
        assert!(
            matches!(r, Err(TransferError::NoFile)),
            "must answer no-file"
        );

        drop(fs);
        up.await.unwrap();
    }

    #[tokio::test]
    async fn a_multipart_shared_file_serves_its_hashset() {
        let dir = tmpdir("two");
        // Two parts, so the downloader must fetch and verify against the hashset.
        let size = (PARTSIZE + 300_000) as usize;
        let data: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(17)) as u8)
            .collect();
        let hash = ed2k_hash(&data);
        let ph = vec![
            md4(&data[..PARTSIZE as usize]),
            md4(&data[PARTSIZE as usize..]),
        ];
        let path = dir.join("big.bin");
        std::fs::write(&path, &data).unwrap();
        let shared = vec![SharedFile {
            hash,
            size: size as u64,
            name: b"big.bin".to_vec(),
            part_hashes: ph.clone(),
            path,
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None).await;
            }
        });

        let store = PartStore::create(&dir, 1, hash, size as u64, b"big.bin").unwrap();
        let dl = Download::new(store);
        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4700, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        download_from_peer(&mut fs, &dl, false).await.unwrap();

        assert!(dl.is_complete().await, "missing {}", dl.missing().await);
        // Verifies against the hashset the seed served over the wire.
        dl.verify_ready_parts().await.unwrap();
        let mut store = dl.into_store().await.unwrap();
        assert!(
            store.pf.corrupted().is_empty(),
            "a part failed verification"
        );
        assert_eq!(store.read_part(0).unwrap(), data[..PARTSIZE as usize]);
        assert_eq!(store.read_part(1).unwrap(), data[PARTSIZE as usize..]);

        drop(fs);
        up.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }
}
