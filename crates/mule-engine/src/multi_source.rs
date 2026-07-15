//! Downloading one file from several peers at once.
//!
//! A `Download` owns the `.part` file and the set of block reservations. Each
//! peer runs its own task against it: claim blocks nobody else is fetching, ask
//! for them, write what arrives, release what it did not get.
//!
//! The reservation set is what makes multi-source work at all - without it every
//! peer would race to fetch block 0. Two properties are load-bearing:
//!
//! - A peer only ever gets blocks from parts it actually HAS (per its
//!   OP_FILESTATUS bitfield).
//! - Reservations are ALWAYS released when a peer goes away, whether it finished,
//!   errored, or vanished mid-block. A leaked reservation is a block no other
//!   peer will ever be offered, and the download would stall a few bytes short
//!   with no visible error.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::framed::FramedStream;
use crate::part_file::data_part_count;
use crate::part_store::PartStore;
use crate::transfer::{
    build_hashset_request, build_request_filename_ext, build_request_parts, build_set_req_file_id,
    build_start_upload_req, parse_file_status, parse_hashset_answer, BlockReceiver, FileStatus,
    OP_ACCEPTUPLOADREQ, OP_FILEREQANSNOFIL, OP_FILESTATUS, OP_HASHSETANSWER,
    STANDARD_BLOCKS_REQUEST,
};
use crate::transfer_session::TransferError;
use mule_proto::PARTSIZE;

/// One file being pulled from many peers.
pub struct Download {
    inner: Mutex<Inner>,
}

struct Inner {
    store: PartStore,
    /// Blocks some peer has asked for and not yet delivered.
    reserved: Vec<(u64, u64)>,
}

impl Download {
    pub fn new(store: PartStore) -> Arc<Self> {
        Arc::new(Download {
            inner: Mutex::new(Inner {
                store,
                reserved: Vec::new(),
            }),
        })
    }

    pub async fn hash(&self) -> [u8; 16] {
        self.inner.lock().await.store.pf.hash
    }

    pub async fn size(&self) -> u64 {
        self.inner.lock().await.store.pf.size
    }

    pub async fn is_complete(&self) -> bool {
        self.inner.lock().await.store.is_complete()
    }

    pub async fn missing(&self) -> u64 {
        self.inner.lock().await.store.pf.missing()
    }

    /// True if we still need the part-hash list before anything can be verified.
    ///
    /// This MUST match `PartFile::verify_part`'s "use the part hash" condition
    /// (`data_part_count > 1 || size == PARTSIZE`). An exactly-PARTSIZE file has a
    /// single data part but a two-entry hashset, so it verifies against the PART
    /// hash - if we gated only on `> 1` we would never fetch the hashset, and the
    /// file would be moved into place UNVERIFIED, defeating the very divergence
    /// that exists to catch a corrupt PARTSIZE file.
    pub async fn needs_hashset(&self) -> bool {
        let g = self.inner.lock().await;
        let size = g.store.pf.size;
        (data_part_count(size) > 1 || size == PARTSIZE) && g.store.pf.part_hashes.is_empty()
    }

    pub async fn set_hashset(&self, hashes: Vec<[u8; 16]>) {
        let mut g = self.inner.lock().await;
        g.store.pf.part_hashes = hashes;
    }

    /// Claim up to `max` blocks this peer can actually serve.
    async fn take_blocks(&self, status: &FileStatus, max: usize) -> Vec<(u64, u64)> {
        let mut g = self.inner.lock().await;
        let reserved = g.reserved.clone();
        let blocks = g
            .store
            .pf
            .next_blocks(&|p| status.has_part(p as usize), &reserved, max);
        g.reserved.extend_from_slice(&blocks);
        blocks
    }

    /// Give blocks back to the pool so another peer can fetch them.
    async fn release(&self, blocks: &[(u64, u64)]) {
        if blocks.is_empty() {
            return;
        }
        let mut g = self.inner.lock().await;
        g.reserved.retain(|b| !blocks.contains(b));
    }

    /// Write received bytes through to disk and close their gap.
    async fn commit(&self, start: u64, data: &[u8]) -> io::Result<()> {
        let mut g = self.inner.lock().await;
        g.store.write_block(start, data)
    }

    /// Verify every part whose bytes have all arrived. A part that fails is
    /// re-opened for download; the caller keeps going until nothing is missing.
    pub async fn verify_ready_parts(&self) -> io::Result<()> {
        let mut g = self.inner.lock().await;
        let n = data_part_count(g.store.pf.size);
        for part in 0..n {
            if g.store.pf.is_part_complete(part) && g.store.pf.corrupted().contains(&part) {
                // Bytes are back after a corruption; re-check it.
                g.store.verify_part(part)?;
            } else if g.store.pf.is_part_complete(part) {
                g.store.verify_part(part)?;
            }
        }
        g.store.save_met()?;
        Ok(())
    }

    /// Take the finished store back out (to move the file into place).
    pub async fn into_store(self: Arc<Self>) -> Option<PartStore> {
        Arc::try_unwrap(self)
            .ok()
            .map(|d| d.inner.into_inner().store)
    }
}

/// Resume every in-progress download in `dir` by opening each `NNN.part` from
/// its `.part.met`, ordered by index. Unreadable/corrupt part files are skipped.
/// This is the engine's on-start resume: the `.part` persists progress across
/// launches, so a download picks up exactly where it left off.
pub fn resume_downloads(dir: &std::path::Path) -> Vec<Arc<Download>> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut indices: Vec<u32> = entries
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_string_lossy()
                .strip_suffix(".part.met")
                .and_then(|stem| stem.parse::<u32>().ok())
        })
        .collect();
    indices.sort_unstable();
    indices
        .into_iter()
        .filter_map(|i| PartStore::open(dir, i).ok().map(Download::new))
        .collect()
}

/// Pull whatever we can from one peer, until it has nothing left to give.
///
/// Returns when the file is complete, when this peer holds no block we still
/// need, or on error. Reservations are released on every one of those paths.
pub async fn download_from_peer<S>(
    fs: &mut FramedStream<S>,
    dl: &Download,
) -> Result<(), TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut held: Vec<(u64, u64)> = Vec::new();
    let r = run_peer(fs, dl, &mut held).await;
    // Whatever happened, do not strand blocks nobody else will be offered.
    dl.release(&held).await;
    r
}

async fn run_peer<S>(
    fs: &mut FramedStream<S>,
    dl: &Download,
    held: &mut Vec<(u64, u64)>,
) -> Result<(), TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hash = dl.hash().await;

    // Ask what this peer has.
    fs.write_packet(&build_request_filename_ext(&hash)).await?;
    fs.write_packet(&build_set_req_file_id(&hash)).await?;
    let status = loop {
        let pkt = fs.read_packet_unpacked().await?;
        match pkt.opcode {
            OP_FILEREQANSNOFIL => return Err(TransferError::NoFile),
            OP_FILESTATUS => break parse_file_status(&pkt.payload)?,
            _ => {}
        }
    };

    // A multi-part file cannot be verified without the part hashes.
    if dl.needs_hashset().await {
        fs.write_packet(&build_hashset_request(&hash)).await?;
        loop {
            let pkt = fs.read_packet_unpacked().await?;
            if pkt.opcode == OP_HASHSETANSWER {
                let (_h, hashes) = parse_hashset_answer(&pkt.payload)?;
                dl.set_hashset(hashes).await;
                break;
            }
        }
    }

    // Queue up and wait for a slot. OP_QUEUERANKING may arrive first, repeatedly.
    fs.write_packet(&build_start_upload_req(&hash)).await?;
    loop {
        let pkt = fs.read_packet_unpacked().await?;
        if pkt.opcode == OP_ACCEPTUPLOADREQ {
            break;
        }
    }

    // Fetch blocks until this peer has nothing we still need.
    let size = dl.size().await;
    loop {
        let blocks = dl.take_blocks(&status, STANDARD_BLOCKS_REQUEST).await;
        if blocks.is_empty() {
            return Ok(());
        }
        held.extend_from_slice(&blocks);

        fs.write_packet(&build_request_parts(&hash, &blocks))
            .await?;

        // One hardened receiver validates every reply (raw or compressed) against
        // exactly these blocks - a hostile peer cannot panic or wedge it.
        let mut rx = BlockReceiver::new(hash, size, &blocks);
        while !rx.is_done() {
            let pkt = fs.read_packet_unpacked().await?;
            for w in rx.accept(pkt.opcode, &pkt.payload)? {
                dl.commit(w.offset, &w.data)
                    .await
                    .map_err(TransferError::Io)?;
            }
        }

        // These are delivered; they are no longer ours to hold.
        dl.release(&blocks).await;
        held.retain(|b| !blocks.contains(b));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::HelloInfo;
    use crate::peer_conn::{accept_peer, connect_peer};
    use crate::transfer_session::{serve, ServedFile};
    use mule_proto::{ed2k_hash, md4, PARTSIZE};
    use std::path::PathBuf;
    use tokio::net::TcpListener;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("padmule-ms-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn an_exactly_partsize_file_still_fetches_its_hashset() {
        // Review finding 4: needs_hashset gated on `> 1` skipped the hashset for a
        // single-DATA-part PARTSIZE file, so verify_part returned None forever and
        // the file was accepted UNVERIFIED. It must report needing the hashset.
        let dir = tmpdir("needs-hashset");
        let store = PartStore::create(&dir, 1, [0xAB; 16], PARTSIZE, b"exact.bin").unwrap();
        let dl = Download::new(store);
        assert_eq!(data_part_count(PARTSIZE), 1, "one DATA part");
        assert!(dl.needs_hashset().await, "must still fetch the hashset");

        // Once the hashset is set, it no longer needs one.
        dl.set_hashset(vec![[1; 16], [2; 16]]).await;
        assert!(!dl.needs_hashset().await);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Spawn a serving peer that holds `available` parts of `data`.
    async fn spawn_server(
        data: Vec<u8>,
        hash: [u8; 16],
        part_hashes: Vec<[u8; 16]>,
        available: Option<Vec<bool>>,
        tag: u8,
    ) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let me = HelloInfo::baseline([tag; 16], 0, 4662, 4672, "server");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let f = ServedFile {
                    hash,
                    name: b"movie.bin",
                    data: &data,
                    part_hashes: &part_hashes,
                    available: available.as_deref(),
                };
                let _ = serve(&mut fs, &f).await;
            }
        });
        addr
    }

    #[tokio::test]
    async fn three_peers_split_one_file_and_the_hash_matches() {
        let dir = tmpdir("three");
        // 600 KB: 4 blocks, so the three peers must genuinely share the work.
        let file: Vec<u8> = (0..600_000u32)
            .map(|i| (i.wrapping_mul(31)) as u8)
            .collect();
        let hash = ed2k_hash(&file);

        let mut addrs = Vec::new();
        for tag in 0..3u8 {
            addrs.push(spawn_server(file.clone(), hash, vec![], None, 0xB0 + tag).await);
        }

        let store = PartStore::create(&dir, 1, hash, file.len() as u64, b"movie.bin").unwrap();
        let dl = Download::new(store);

        let mut tasks = Vec::new();
        for (i, addr) in addrs.into_iter().enumerate() {
            let dl = dl.clone();
            tasks.push(tokio::spawn(async move {
                let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663 + i as u16, 4673, "dl");
                let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
                download_from_peer(&mut fs, &dl).await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }

        assert!(
            dl.is_complete().await,
            "still missing {}",
            dl.missing().await
        );
        dl.verify_ready_parts().await.unwrap();

        // The bytes on DISK must match, not just an in-memory buffer.
        let mut store = dl.into_store().await.unwrap();
        assert_eq!(store.read_part(0).unwrap(), file);
        assert_eq!(ed2k_hash(&store.read_part(0).unwrap()), hash);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn two_peers_holding_disjoint_parts_still_complete_the_file() {
        let dir = tmpdir("disjoint");
        // Two full parts: peer A has only part 0, peer B only part 1. Neither can
        // finish the file alone, so this only passes if availability is honoured
        // AND the two are combined.
        let size = (PARTSIZE + 300_000) as usize;
        let file: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(17)) as u8)
            .collect();
        let hash = ed2k_hash(&file);
        let ph = vec![
            md4(&file[..PARTSIZE as usize]),
            md4(&file[PARTSIZE as usize..]),
        ];

        let a = spawn_server(
            file.clone(),
            hash,
            ph.clone(),
            Some(vec![true, false]),
            0xC1,
        )
        .await;
        let b = spawn_server(
            file.clone(),
            hash,
            ph.clone(),
            Some(vec![false, true]),
            0xC2,
        )
        .await;

        let store = PartStore::create(&dir, 1, hash, size as u64, b"big.bin").unwrap();
        let dl = Download::new(store);

        let mut tasks = Vec::new();
        for (i, addr) in [a, b].into_iter().enumerate() {
            let dl = dl.clone();
            tasks.push(tokio::spawn(async move {
                let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4700 + i as u16, 4673, "dl");
                let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
                download_from_peer(&mut fs, &dl).await
            }));
        }
        for t in tasks {
            t.await.unwrap().unwrap();
        }

        assert!(dl.is_complete().await, "missing {}", dl.missing().await);
        // The hashset arrived over the wire, so both parts can be verified.
        dl.verify_ready_parts().await.unwrap();

        let mut store = dl.into_store().await.unwrap();
        assert!(store.pf.corrupted().is_empty(), "no part should be corrupt");
        assert_eq!(store.read_part(0).unwrap(), file[..PARTSIZE as usize]);
        assert_eq!(store.read_part(1).unwrap(), file[PARTSIZE as usize..]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_peer_that_dies_mid_transfer_does_not_strand_its_blocks() {
        let dir = tmpdir("strand");
        let file: Vec<u8> = (0..400_000u32)
            .map(|i| (i.wrapping_mul(13)) as u8)
            .collect();
        let hash = ed2k_hash(&file);

        let store = PartStore::create(&dir, 1, hash, file.len() as u64, b"m.bin").unwrap();
        let dl = Download::new(store);

        // A peer that accepts, then hangs up immediately after the handshake.
        let dead = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        tokio::spawn(async move {
            let me = HelloInfo::baseline([0xDD; 16], 0, 4662, 4672, "dead");
            if let Ok((_p, fs)) = accept_peer(&dead, &me).await {
                drop(fs); // vanish
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4800, 4673, "dl");
        if let Ok((_p, mut fs)) = connect_peer(dead_addr, &me).await {
            // Expected to fail - the point is what it leaves behind.
            let _ = download_from_peer(&mut fs, &dl).await;
        }

        // Nothing must remain reserved, or a healthy peer would never be offered
        // those blocks and the download would stall forever.
        assert!(
            dl.inner.lock().await.reserved.is_empty(),
            "dead peer stranded its reservations"
        );

        // A good peer can now finish the whole file.
        let good = spawn_server(file.clone(), hash, vec![], None, 0xEE).await;
        let me = HelloInfo::baseline([0xAB; 16], 0x0A00_0001, 4801, 4673, "dl2");
        let (_p, mut fs) = connect_peer(good, &me).await.unwrap();
        download_from_peer(&mut fs, &dl).await.unwrap();

        assert!(dl.is_complete().await);
        let mut store = dl.into_store().await.unwrap();
        assert_eq!(store.read_part(0).unwrap(), file);

        std::fs::remove_dir_all(&dir).ok();
    }
}
