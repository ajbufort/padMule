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
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use crate::framed::FramedStream;
use crate::part_file::data_part_count;
use crate::part_store::PartStore;
use crate::secure_ident::{
    Identity, SecureIdentSession, OP_PUBLICKEY, OP_SECIDENTSTATE, OP_SIGNATURE,
};
use crate::transfer::{
    build_hashset_request, build_request_filename_ext, build_request_parts, build_set_req_file_id,
    build_start_upload_req, parse_file_desc, parse_file_status, parse_hashset_answer,
    BlockReceiver, FileStatus, OP_ACCEPTUPLOADREQ, OP_FILEDESC, OP_FILEREQANSNOFIL, OP_FILESTATUS,
    OP_HASHSETANSWER, OP_QUEUERANKING, STANDARD_BLOCKS_REQUEST,
};
use crate::transfer_session::TransferError;
use mule_proto::{Packet, PARTSIZE};

/// Inputs the download-side secure-ident exchange needs: our RSA identity, and
/// whether the peer advertised secure-ident support in its HELLO (so we know to
/// proactively ask it to prove itself, matching a real eMule downloader).
pub struct SecIdentCtx {
    pub identity: Arc<Identity>,
    pub peer_supports: bool,
}

/// What we learned about one source we connected to, for the per-source UI.
#[derive(Debug, Clone)]
pub struct SourceInfo {
    pub addr: SocketAddr,
    /// Client software display string (from the HELLO CT_EMULE_VERSION tag).
    pub software: String,
    /// Whether our connection to it was obfuscated (RC4).
    pub obfuscated: bool,
    /// Whether the peer reported a LowID (id < 0x0100_0000).
    pub low_id: bool,
    /// Whether we cryptographically verified its identity (secure-ident).
    pub verified: bool,
    /// Its rating for this file (0-5, from OP_FILEDESC); 0 = unrated.
    pub rating: u8,
    /// Its comment on this file (from OP_FILEDESC); empty if none.
    pub comment: String,
}

/// One file being pulled from many peers.
pub struct Download {
    inner: Mutex<Inner>,
    /// Metadata about each source we have connected to, keyed by address. A
    /// SEPARATE lock from `inner`, so recording a source never contends the
    /// hot transfer lock.
    sources: Mutex<Vec<SourceInfo>>,
    /// Set when the user cancels. The fetch workers check it and stop; a
    /// lock-free atomic so cancelling never has to wait on the transfer lock.
    cancelled: AtomicBool,
    /// The user's download priority (PR_LOW/PR_NORMAL/PR_HIGH). A lock-free
    /// atomic so the fetch manager can read it every round without touching the
    /// transfer lock; the canonical copy is persisted in the PartStore.
    priority: AtomicU8,
    /// Preview mode: when set, block selection is forward-SEQUENTIAL instead of
    /// rarest-first, so the file grows contiguously from offset 0 and the user can
    /// play its leading run while it is still downloading. Transient, not persisted.
    preview: AtomicBool,
    /// Claimed by whoever runs the one-shot finalize (verify -> move). Prevents the
    /// fetch-task tail and the 1s heartbeat finalize-sweep from both finalizing the
    /// same download. Reset if finalize fails so a re-fetched file can finalize again.
    finalizing: AtomicBool,
}

struct Inner {
    store: PartStore,
    /// Blocks some peer has asked for and not yet delivered.
    reserved: Vec<(u64, u64)>,
    /// Per data-part swarm availability: how many peer sessions have reported
    /// holding each part. Drives rarest-first block selection.
    availability: Vec<u32>,
}

/// Once the file is within this many bytes of complete, a peer that finds all
/// remaining blocks reserved enters endgame and races them - so a slow/queuing
/// peer can't stall the last block. Kept small (a few blocks) so the redundant
/// re-requests only touch the tail of the download.
const ENDGAME_LIMIT: u64 = 4 * crate::transfer::EMBLOCKSIZE;

impl Download {
    pub fn new(store: PartStore) -> Arc<Self> {
        let parts = data_part_count(store.pf.size) as usize;
        let priority = AtomicU8::new(store.priority);
        Arc::new(Download {
            inner: Mutex::new(Inner {
                store,
                reserved: Vec::new(),
                availability: vec![0u32; parts],
            }),
            sources: Mutex::new(Vec::new()),
            cancelled: AtomicBool::new(false),
            priority,
            preview: AtomicBool::new(false),
            finalizing: AtomicBool::new(false),
        })
    }

    /// Claim the right to finalize this download exactly once (complete -> verify
    /// -> move). The FIRST caller gets `true`; concurrent callers get `false`, so
    /// the fetch tail and the heartbeat sweep never double-finalize the same file.
    pub fn try_begin_finalize(&self) -> bool {
        self.finalizing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    /// Release the finalize claim (finalize failed - the file was re-gapped for a
    /// re-fetch), so it can be finalized again once it re-completes.
    pub fn reset_finalize(&self) {
        self.finalizing.store(false, Ordering::Release);
    }

    /// Record (or refresh) the base facts about a source we connected to:
    /// software, obfuscation, and LowID. Keyed by address; a reconnect updates
    /// those fields but preserves any rating/comment/verified already learned.
    pub async fn note_source(
        &self,
        software: String,
        addr: SocketAddr,
        obfuscated: bool,
        low_id: bool,
    ) {
        let mut g = self.sources.lock().await;
        if let Some(s) = g.iter_mut().find(|s| s.addr == addr) {
            s.software = software;
            s.obfuscated = obfuscated;
            s.low_id = low_id;
        } else {
            g.push(SourceInfo {
                addr,
                software,
                obfuscated,
                low_id,
                verified: false,
                rating: 0,
                comment: String::new(),
            });
        }
    }

    /// Attach a source's rating + comment (from OP_FILEDESC). No-op if we have no
    /// record of that address yet (the base note comes first on connect).
    pub async fn note_source_comment(&self, addr: SocketAddr, rating: u8, comment: String) {
        let mut g = self.sources.lock().await;
        if let Some(s) = g.iter_mut().find(|s| s.addr == addr) {
            s.rating = rating.min(5);
            s.comment = comment;
        }
    }

    /// Mark a source as identity-verified (secure-ident succeeded).
    pub async fn note_source_verified(&self, addr: SocketAddr) {
        let mut g = self.sources.lock().await;
        if let Some(s) = g.iter_mut().find(|s| s.addr == addr) {
            s.verified = true;
        }
    }

    /// Snapshot of every source we have connected to (for the per-source UI).
    pub async fn sources(&self) -> Vec<SourceInfo> {
        self.sources.lock().await.clone()
    }

    /// A download-row summary of what sources said: the average rating over rated
    /// sources (0 = none rated), and whether any source left a comment.
    pub async fn rating_summary(&self) -> (u8, bool) {
        let g = self.sources.lock().await;
        let (sum, count) = g
            .iter()
            .filter(|s| s.rating > 0)
            .fold((0u32, 0u32), |acc, s| (acc.0 + s.rating as u32, acc.1 + 1));
        let avg = sum.checked_div(count).unwrap_or(0) as u8;
        let has_comment = g.iter().any(|s| !s.comment.is_empty());
        (avg, has_comment)
    }

    /// Mark this download cancelled. The fetch workers notice within a block and
    /// stop; the engine then removes it and deletes the `.part`.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    /// The current download priority (PR_LOW/PR_NORMAL/PR_HIGH). Read lock-free
    /// by the fetch manager every round, so a live change biases the ongoing
    /// sweep, not just the next spawn.
    pub fn priority(&self) -> u8 {
        self.priority.load(Ordering::Relaxed)
    }

    /// Set the download priority and persist it to part.met so it survives a
    /// restart. Best-effort persistence: a failed met write leaves the live
    /// atomic updated (the sweep still honors it this session).
    pub async fn set_priority(&self, priority: u8) {
        self.priority.store(priority, Ordering::Relaxed);
        let mut g = self.inner.lock().await;
        g.store.priority = priority;
        let _ = g.store.save_met();
    }

    /// Re-open the ENTIRE file for download and persist - the last resort when the
    /// whole-file hash fails but no individual part could be blamed (e.g. a spoofed
    /// hashset). Forces a full re-download instead of stranding a corrupt file.
    pub async fn reset_all_gaps(&self) {
        let mut g = self.inner.lock().await;
        g.store.pf.reset_all_gaps();
        let _ = g.store.save_met();
    }

    /// Flush this download's on-disk `.part.met` (its gap list + priority). The hot
    /// receive path (`commit`) only fills the IN-MEMORY gap list, so without a flush
    /// on the durability boundary a suspend-kill loses ALL session progress and
    /// re-downloads from scratch. Called from `pause()`/`shutdown()`.
    pub async fn persist(&self) {
        let mut g = self.inner.lock().await;
        let _ = g.store.save_met();
    }

    /// Whether preview mode is on (first+last-then-sequential block bias).
    pub fn is_preview(&self) -> bool {
        self.preview.load(Ordering::Relaxed)
    }

    /// Turn preview mode on/off. Read lock-free by the fetch manager every round,
    /// so it re-biases the ongoing sweep, not just the next spawn. Not persisted -
    /// it is a transient viewing intent.
    pub fn set_preview(&self, on: bool) {
        self.preview.store(on, Ordering::Relaxed);
    }

    /// Bytes available CONTIGUOUSLY from offset 0 - the leading prefix a player
    /// can read from the raw `.part` (see `PartFile::contiguous_prefix`).
    pub async fn contiguous_prefix(&self) -> u64 {
        self.inner.lock().await.store.pf.contiguous_prefix()
    }

    /// The `(part_path, contiguous_prefix)` a preview snapshot needs, or None when
    /// nothing contiguous is available yet. Holds the lock ONLY to read the path +
    /// length; the caller then copies `[0, prefix)` from its own read handle
    /// (outside the lock), so copying a large prefix never stalls the download.
    pub async fn preview_target(&self) -> Option<(std::path::PathBuf, u64)> {
        let g = self.inner.lock().await;
        let len = g.store.pf.contiguous_prefix();
        if len == 0 {
            return None;
        }
        Some((g.store.part_path().to_path_buf(), len))
    }

    /// Delete the backing `.part` and `.part.met`. Best effort: an open file
    /// handle a worker still holds keeps the bytes readable until it drops, but
    /// the files are gone from disk at once so a restart will not resume them.
    pub async fn discard_files(&self) {
        self.inner.lock().await.store.remove_backing_files();
    }

    /// Fold a peer's file-status bitfield into the swarm-availability counts, so
    /// later block selection knows which parts are rare.
    pub async fn note_status(&self, status: &FileStatus) {
        let mut g = self.inner.lock().await;
        for p in 0..g.availability.len() {
            if status.has_part(p) {
                g.availability[p] += 1;
            }
        }
    }

    pub async fn hash(&self) -> [u8; 16] {
        self.inner.lock().await.store.pf.hash
    }

    pub async fn size(&self) -> u64 {
        self.inner.lock().await.store.pf.size
    }

    /// The download's advertised filename (lossy UTF-8).
    pub async fn name(&self) -> String {
        String::from_utf8_lossy(&self.inner.lock().await.store.name).into_owned()
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

    /// The per-part MD4s, if a hashset was fetched (empty for a single-part
    /// file). Captured when a finished download becomes a shared source, so we
    /// can answer OP_HASHSETREQUEST without re-reading the file.
    pub async fn part_hashes(&self) -> Vec<[u8; 16]> {
        self.inner.lock().await.store.pf.part_hashes.clone()
    }

    /// Claim up to `max` blocks this peer can actually serve, rarest-first. If
    /// nothing fresh is left but the file is nearly done, enter endgame and race
    /// the final reserved blocks.
    async fn take_blocks(&self, status: &FileStatus, max: usize) -> Vec<(u64, u64)> {
        // Cancelled: hand out nothing, so the peer session ends and the worker
        // loop falls through to its cancellation check.
        if self.is_cancelled() {
            return Vec::new();
        }
        let preview = self.preview.load(Ordering::Relaxed);
        let mut g = self.inner.lock().await;
        let reserved = g.reserved.clone();
        let avail = g.availability.clone();
        let missing = g.store.pf.missing();
        let rarity = |p: u64| avail.get(p as usize).copied().unwrap_or(0);
        let has = |p: u64| status.has_part(p as usize);

        let mut blocks = g
            .store
            .pf
            .next_blocks(&has, &reserved, max, &rarity, false, preview);
        if blocks.is_empty() && missing > 0 && missing <= ENDGAME_LIMIT {
            blocks = g
                .store
                .pf
                .next_blocks(&has, &reserved, max, &rarity, true, preview);
        }
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
            // Verify any part whose bytes have all arrived (this re-checks a
            // previously-corrupted part too, now that its bytes are back).
            if g.store.pf.is_part_complete(part) {
                g.store.verify_part(part)?;
            }
        }
        g.store.save_met()?;
        Ok(())
    }

    /// Recompute the whole-file ed2k hash from the bytes actually on disk and
    /// compare it to `want`.
    ///
    /// This is the end-to-end proof that what we assembled IS what was asked
    /// for, and for many files it is the ONLY one: `verify_part` needs the
    /// peer's hashset, and a file of a single part has no part hashes at all.
    /// Hashed part-by-part, so a large file is never held in memory.
    pub async fn verify_whole_file(&self, size: u64, want: [u8; 16]) -> bool {
        // Snapshot the backing path under a BRIEF lock, then rehash off the lock
        // AND off the async reactor via spawn_blocking: a multi-GB MD4 is slow and
        // CPU-bound. Holding the download lock across it would stall the 1s
        // downloads() heartbeat - which runs under the shared engine lock - and so
        // pause()/every FFI call. Mirrors the preview snapshot's off-lock read.
        let path = {
            let g = self.inner.lock().await;
            g.store.part_path().to_path_buf()
        };
        let got = tokio::task::spawn_blocking(move || {
            use std::io::{Read, Seek, SeekFrom};
            let mut f = std::fs::File::open(&path)?;
            mule_proto::ed2k_hash_parts(size, |p| {
                let mut buf = vec![0u8; crate::part_file::part_size(p, size) as usize];
                f.seek(SeekFrom::Start(p * mule_proto::PARTSIZE))?;
                f.read_exact(&mut buf)?;
                io::Result::Ok(buf)
            })
        })
        .await;
        matches!(got, Ok(Ok(g)) if g == want)
    }

    /// Take the finished store back out (to move the file into place).
    pub async fn into_store(self: Arc<Self>) -> Option<PartStore> {
        Arc::try_unwrap(self)
            .ok()
            .map(|d| d.inner.into_inner().store)
    }

    /// Move the finished file into `dest` through the lock, WITHOUT needing sole
    /// ownership of the Arc. Unlike `into_store`, this never fails just because a
    /// concurrent holder (the 1s downloads() poll, cancel, set_download_priority)
    /// happens to hold an Arc clone at the same instant - which would otherwise
    /// leave a byte-complete `.part` stranded.
    pub async fn finish_to(&self, dest: &std::path::Path) -> std::io::Result<()> {
        self.inner.lock().await.store.finish_in_place(dest)
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
/// Returns the number of bytes this session delivered (for peer scoring).
///
/// `bail_on_queue`: what to do when the peer answers OP_STARTUPLOADREQ with a
/// queue ranking instead of an accept. `true` (a multi-source hunt with other
/// sources to try) returns `TransferError::Queued` immediately so the caller
/// moves on; `false` (a single dedicated source, e.g. a direct peer download or a
/// called-back peer) waits in the queue for the slot, like a normal client.
pub async fn download_from_peer<S>(
    fs: &mut FramedStream<S>,
    dl: &Download,
    bail_on_queue: bool,
) -> Result<u64, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    download_from_peer_at(fs, dl, bail_on_queue, None, None).await
}

/// As [`download_from_peer`], but `peer` names the source address (so a rating +
/// comment it sends via OP_FILEDESC, and an identity verification, can be recorded
/// against it) and `sec` carries the secure-ident context (our RSA identity +
/// whether the peer advertised support), enabling mutual secure-identification
/// inline with the transfer. `sec = None` disables it (plain download).
pub async fn download_from_peer_at<S>(
    fs: &mut FramedStream<S>,
    dl: &Download,
    bail_on_queue: bool,
    peer: Option<SocketAddr>,
    sec: Option<SecIdentCtx>,
) -> Result<u64, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut held: Vec<(u64, u64)> = Vec::new();
    let r = run_peer(fs, dl, &mut held, bail_on_queue, peer, sec).await;
    // Whatever happened, do not strand blocks nobody else will be offered.
    dl.release(&held).await;
    r
}

/// If `pkt` is a source's OP_FILEDESC, record its rating + comment against
/// `peer` (when known). Unsolicited and one-shot; safe to call from any loop.
async fn note_comment_if_desc(pkt: &Packet, dl: &Download, peer: Option<SocketAddr>) {
    if pkt.opcode == OP_FILEDESC {
        if let Some(addr) = peer {
            if let Ok((rating, comment)) = parse_file_desc(&pkt.payload) {
                dl.note_source_comment(addr, rating, comment).await;
            }
        }
    }
}

/// Handle a packet that is NOT the one a read loop is waiting for: a source's
/// rating/comment (OP_FILEDESC), and the secure-ident exchange (OP_SECIDENTSTATE
/// / OP_PUBLICKEY / OP_SIGNATURE). Secure-ident is best-effort and NEVER blocks
/// the transfer - it just answers packets the loop was going to read anyway: we
/// reply so the peer can verify us, mark the source verified once its signature
/// checks out, and drop a malformed packet silently. Nothing here awaits new data.
async fn handle_aux_packet<S>(
    pkt: &Packet,
    sec: &mut Option<(SecureIdentSession, Arc<Identity>)>,
    fs: &mut FramedStream<S>,
    dl: &Download,
    peer: Option<SocketAddr>,
) -> Result<(), TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    note_comment_if_desc(pkt, dl, peer).await;
    if matches!(pkt.opcode, OP_SECIDENTSTATE | OP_PUBLICKEY | OP_SIGNATURE) {
        if let Some((session, id)) = sec.as_mut() {
            // A malformed secure-ident packet is dropped (Err ignored), never
            // fatal to the download.
            if let Ok(replies) = session.on_packet(id, pkt.opcode, &pkt.payload) {
                for reply in replies {
                    fs.write_packet(&reply).await?;
                }
                if session.peer_verified() {
                    if let Some(addr) = peer {
                        dl.note_source_verified(addr).await;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn run_peer<S>(
    fs: &mut FramedStream<S>,
    dl: &Download,
    held: &mut Vec<(u64, u64)>,
    bail_on_queue: bool,
    peer: Option<SocketAddr>,
    sec: Option<SecIdentCtx>,
) -> Result<u64, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let hash = dl.hash().await;

    // Secure-ident, when enabled: build our session and - if the peer advertised
    // support - proactively ask it to prove it owns its userhash, exactly as a
    // real eMule downloader does right after the hello. Fire-and-forget: the
    // exchange rides along on packets the transfer loops read anyway, and we NEVER
    // wait on it, so a peer that does not answer just stays unverified.
    let mut sec: Option<(SecureIdentSession, Arc<Identity>)> = match sec {
        Some(ctx) => {
            let session = SecureIdentSession::new(&ctx.identity);
            if ctx.peer_supports {
                let start = session.start();
                fs.write_packet(&start).await?;
            }
            Some((session, ctx.identity))
        }
        None => None,
    };

    // Ask what this peer has.
    fs.write_packet(&build_request_filename_ext(&hash)).await?;
    fs.write_packet(&build_set_req_file_id(&hash)).await?;
    let status = loop {
        let pkt = fs.read_packet_unpacked().await?;
        match pkt.opcode {
            OP_FILEREQANSNOFIL => return Err(TransferError::NoFile),
            OP_FILESTATUS => break parse_file_status(&pkt.payload)?,
            // A source's OP_FILEDESC (rating/comment) or a secure-ident packet
            // can arrive here; neither is what we are waiting for.
            _ => handle_aux_packet(&pkt, &mut sec, fs, dl, peer).await?,
        }
    };
    // Record what this peer holds so block selection knows which parts are rare.
    dl.note_status(&status).await;

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
            handle_aux_packet(&pkt, &mut sec, fs, dl, peer).await?;
        }
    }

    // Ask for a slot. A peer with a free slot answers OP_ACCEPTUPLOADREQ; a busy
    // one answers OP_QUEUERANKING (we are now Nth in its queue). For a completion
    // hunt across many thin sources, sitting in a queue is dead time - bail the
    // instant we are queued so the sweep moves to the next source. A real
    // background client would instead keep the slot and wait its turn.
    fs.write_packet(&build_start_upload_req(&hash)).await?;
    loop {
        let pkt = fs.read_packet_unpacked().await?;
        match pkt.opcode {
            OP_ACCEPTUPLOADREQ => break,
            OP_QUEUERANKING if bail_on_queue => return Err(TransferError::Queued),
            _ => handle_aux_packet(&pkt, &mut sec, fs, dl, peer).await?,
        }
    }

    // Fetch blocks until this peer has nothing we still need.
    let size = dl.size().await;
    let mut delivered = 0u64;
    loop {
        let blocks = dl.take_blocks(&status, STANDARD_BLOCKS_REQUEST).await;
        if blocks.is_empty() {
            return Ok(delivered);
        }
        held.extend_from_slice(&blocks);

        fs.write_packet(&build_request_parts(&hash, &blocks))
            .await?;

        // One hardened receiver validates every reply (raw or compressed) against
        // exactly these blocks - a hostile peer cannot panic or wedge it.
        let mut rx = BlockReceiver::new(hash, size, &blocks);
        while !rx.is_done() {
            let pkt = fs.read_packet_unpacked().await?;
            // A secure-ident packet (or a late OP_FILEDESC) can interleave with
            // block data on the same connection; handle it and keep waiting for
            // the blocks we asked for.
            if matches!(
                pkt.opcode,
                OP_SECIDENTSTATE | OP_PUBLICKEY | OP_SIGNATURE | OP_FILEDESC
            ) {
                handle_aux_packet(&pkt, &mut sec, fs, dl, peer).await?;
                continue;
            }
            for w in rx.accept(pkt.opcode, &pkt.payload)? {
                delivered += w.data.len() as u64;
                crate::stats::add_downloaded(w.data.len() as u64);
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
    async fn finish_to_moves_the_file_even_with_a_concurrent_arc_holder() {
        // The old into_store path used Arc::try_unwrap, which failed - and
        // stranded the byte-complete .part - if ANY other Arc<Download> clone
        // existed at that instant (the 1s downloads() poll, cancel, set_priority).
        // finish_to goes through the lock instead, so a live clone can't strand it.
        let dir = tmpdir("finish-concurrent");
        let store = PartStore::create(&dir, 1, [0x33; 16], 500, b"done.bin").unwrap();
        let part_path = dir.join("001.part");
        let met_path = dir.join("001.part.met");
        assert!(part_path.exists());
        let dl = Download::new(store);

        // Simulate a concurrent holder (e.g. the downloads() poll) keeping a clone.
        let holder = Arc::clone(&dl);

        let dest = dir.join("done.bin");
        dl.finish_to(&dest).await.unwrap();

        assert!(dest.exists(), "the file must be moved into place");
        assert!(!part_path.exists(), "the .part is renamed away");
        assert!(!met_path.exists(), "the .part.met is removed");
        // The clone is still alive throughout - it did not block the finish.
        assert_eq!(Arc::strong_count(&holder), 2);
        drop(holder);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_sources_comment_is_recorded_during_the_session() {
        use crate::transfer::{build_file_desc, build_file_req_ans_no_fil, OP_SETREQFILEID};
        let dir = tmpdir("filedesc");
        let hash = [0x77; 16];
        let store = PartStore::create(&dir, 1, hash, 400_000, b"c.bin").unwrap();
        let dl = Download::new(store);
        let addr: SocketAddr = "9.9.9.9:4662".parse().unwrap();
        // fetch_one records the base source before driving the session.
        dl.note_source("aMule 3.0.1".into(), addr, true, false)
            .await;

        let (client, server) = tokio::io::duplex(8192);
        let mut client_fs = FramedStream::new(client);
        let mut server_fs = FramedStream::new(server);
        // The "source": after the file request it pushes an unsolicited comment,
        // then declines the file (so the session ends quickly but the comment was
        // already recorded).
        let src = tokio::spawn(async move {
            // Consume the two request packets (REQUESTFILENAME, SETREQFILEID).
            loop {
                let pkt = server_fs.read_packet_unpacked().await.unwrap();
                if pkt.opcode == OP_SETREQFILEID {
                    break;
                }
            }
            server_fs
                .write_packet(&build_file_desc(5, "verified good rip"))
                .await
                .unwrap();
            server_fs
                .write_packet(&build_file_req_ans_no_fil(&hash))
                .await
                .unwrap();
        });

        let r = download_from_peer_at(&mut client_fs, &dl, false, Some(addr), None).await;
        assert!(matches!(r, Err(TransferError::NoFile)));
        let _ = src.await;

        let srcs = dl.sources().await;
        let s = srcs.iter().find(|s| s.addr == addr).unwrap();
        assert_eq!(s.rating, 5);
        assert_eq!(s.comment, "verified good rip");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn note_source_upserts_and_preserves_learned_fields() {
        let dir = tmpdir("srcinfo");
        let store = PartStore::create(&dir, 1, [0x11; 16], 400_000, b"s.bin").unwrap();
        let dl = Download::new(store);
        let a: SocketAddr = "1.2.3.4:4662".parse().unwrap();
        let b: SocketAddr = "5.6.7.8:4662".parse().unwrap();

        dl.note_source("aMule 3.0.1".into(), a, true, false).await;
        dl.note_source("eMule 0.50a".into(), b, false, true).await;
        // A comment + a verification land on source a.
        dl.note_source_comment(a, 5, "great".into()).await;
        dl.note_source_verified(a).await;
        // A reconnect to a refreshes the base fields but keeps rating/comment/verified.
        dl.note_source("aMule 3.0.1".into(), a, true, false).await;

        let mut srcs = dl.sources().await;
        assert_eq!(srcs.len(), 2, "one entry per address");
        srcs.sort_by_key(|s| s.addr);
        let sa = srcs.iter().find(|s| s.addr == a).unwrap();
        assert_eq!(sa.software, "aMule 3.0.1");
        assert!(sa.obfuscated && !sa.low_id);
        assert_eq!(sa.rating, 5);
        assert_eq!(sa.comment, "great");
        assert!(sa.verified, "verification survives a base re-note");
        let sb = srcs.iter().find(|s| s.addr == b).unwrap();
        assert!(!sb.obfuscated && sb.low_id && sb.rating == 0 && !sb.verified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_cancelled_download_hands_out_no_more_blocks() {
        use crate::transfer::{build_file_status_complete, parse_file_status};
        let dir = tmpdir("cancel-blocks");
        let hash = [0xCD; 16];
        let store = PartStore::create(&dir, 1, hash, 400_000, b"y.bin").unwrap();
        let dl = Download::new(store);
        // A complete source has every part, so a live download claims blocks...
        let status = parse_file_status(&build_file_status_complete(&hash).payload).unwrap();
        assert!(
            !dl.take_blocks(&status, 3).await.is_empty(),
            "a live download should hand out blocks"
        );
        // ...until it is cancelled, after which it claims none and the workers stop.
        dl.cancel();
        assert!(
            dl.take_blocks(&status, 3).await.is_empty(),
            "a cancelled download must hand out no blocks"
        );
        std::fs::remove_dir_all(&dir).ok();
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
    async fn secure_ident_verifies_a_source_inline_with_the_download() {
        use crate::transfer::{
            build_accept_upload, build_file_status_complete, build_sending_part,
            parse_request_parts, OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_STARTUPLOADREQ,
        };
        let dir = tmpdir("secident-verify");
        let data: Vec<u8> = (0..5000u32).map(|i| (i.wrapping_mul(7)) as u8).collect();
        let hash = ed2k_hash(&data);

        // A mock UPLOADER that advertises secure-ident, INITIATES it toward the
        // downloader (as a real eMule does right after the hello), responds to the
        // downloader's own request, and serves the file - all interleaved on one
        // connection. This is the FAITHFUL other-side the reverted attempt lacked.
        let server_data = data.clone();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "server").with_secident();
            let (_p, mut fs) = accept_peer(&listener, &me).await.unwrap();
            let server_id = Identity::generate();
            let mut sess = SecureIdentSession::new(&server_id);
            // Initiate: ask the downloader to prove it owns its userhash.
            fs.write_packet(&sess.start()).await.unwrap();
            while let Ok(pkt) = fs.read_packet_unpacked().await {
                match pkt.opcode {
                    OP_SECIDENTSTATE | OP_PUBLICKEY | OP_SIGNATURE => {
                        if let Ok(replies) = sess.on_packet(&server_id, pkt.opcode, &pkt.payload) {
                            for r in replies {
                                let _ = fs.write_packet(&r).await;
                            }
                        }
                    }
                    OP_REQUESTFILENAME => {
                        let _ = fs.write_packet(&build_file_status_complete(&hash)).await;
                    }
                    OP_STARTUPLOADREQ => {
                        let _ = fs.write_packet(&build_accept_upload()).await;
                    }
                    OP_REQUESTPARTS => {
                        if let Ok((_h, blocks)) = parse_request_parts(&pkt.payload, false) {
                            for (s, e) in blocks {
                                if s <= e && (e as usize) <= server_data.len() {
                                    let _ = fs
                                        .write_packet(&build_sending_part(
                                            &hash,
                                            s,
                                            e,
                                            &server_data[s as usize..e as usize],
                                        ))
                                        .await;
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        let store = PartStore::create(&dir, 1, hash, data.len() as u64, b"s.bin").unwrap();
        let dl = Download::new(store);
        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl").with_secident();
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        // Register the source so a verification is recorded against it.
        dl.note_source("server".into(), addr, false, false).await;
        let sec = Some(SecIdentCtx {
            identity: Arc::new(Identity::generate()),
            peer_supports: true,
        });
        let got = download_from_peer_at(&mut fs, &dl, false, Some(addr), sec)
            .await
            .unwrap();

        assert_eq!(got, data.len() as u64, "the whole file transferred");
        assert!(dl.is_complete().await, "download completed");
        assert!(
            dl.sources().await.iter().any(|s| s.verified),
            "the source must be cryptographically verified via secure-ident"
        );

        drop(fs);
        let _ = server.await;
        std::fs::remove_dir_all(&dir).ok();
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
                download_from_peer(&mut fs, &dl, false).await
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
                download_from_peer(&mut fs, &dl, false).await
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
            let _ = download_from_peer(&mut fs, &dl, false).await;
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
        download_from_peer(&mut fs, &dl, false).await.unwrap();

        assert!(dl.is_complete().await);
        let mut store = dl.into_store().await.unwrap();
        assert_eq!(store.read_part(0).unwrap(), file);

        std::fs::remove_dir_all(&dir).ok();
    }
}
