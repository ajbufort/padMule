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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use mule_proto::Packet;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Duration};

/// Drop a serve connection that goes silent this long between packets. Bounds
/// idle pre-upload sessions (a peer that names a file then never asks) - eMule
/// reaps at CONNECTION_TIMEOUT=40s; we allow more slack for a slow link.
const SERVE_IDLE: Duration = Duration::from_secs(60);
/// Longest a queued peer waits in place for a slot before we close its
/// connection (it can reconnect). Bounds how long a waiter ties up a task/fd.
const QUEUE_WAIT: Duration = Duration::from_secs(120);

/// Undoes an `UploadGate` wait-count increment on drop, so a peer that
/// disconnects while queued (a write error, or the serve future being dropped
/// mid-await) can never leak queue capacity. Without this, `waiting` would
/// ratchet up until `queue_cap` is reached and no peer is ever queued again.
struct WaitTicket<'a> {
    gate: &'a UploadGate,
}

impl<'a> WaitTicket<'a> {
    /// Take a queue ticket. Returns the guard plus how many peers were already
    /// waiting ahead (the caller's 0-based position).
    fn enter(gate: &'a UploadGate) -> (Self, usize) {
        let ahead = gate.waiting.fetch_add(1, Ordering::AcqRel);
        (WaitTicket { gate }, ahead)
    }
}

impl Drop for WaitTicket<'_> {
    fn drop(&mut self) {
        self.gate.waiting.fetch_sub(1, Ordering::AcqRel);
    }
}

use crate::framed::{FrameError, FramedStream};
use crate::secure_ident::{
    Identity, SecureIdentSession, OP_PUBLICKEY, OP_SECIDENTSTATE, OP_SIGNATURE,
};
use crate::transfer::{
    build_accept_upload, build_file_desc, build_file_req_ans_no_fil, build_file_status_complete,
    build_hashset_answer, build_multipacket_answer, build_queue_ranking, build_req_filename_answer,
    build_sending_part, parse_request_parts, OP_HASHSETREQUEST, OP_MULTIPACKET, OP_MULTIPACKET_EXT,
    OP_REQUESTFILENAME, OP_REQUESTPARTS, OP_REQUESTPARTS_I64, OP_SETREQFILEID, OP_STARTUPLOADREQ,
};

/// A bounded upload gate: `slots` concurrent uploads plus a wait queue. When
/// every slot is busy, a new requester is queued and told its 1-based place
/// (OP_QUEUERANKING), then granted a slot IN PLACE on the connection we already
/// hold open the moment one frees.
///
/// Deliberately scoped to that held connection: no cross-connection queue
/// persistence, no slot-grant dial-out to an idled peer, and no UDP
/// OP_REASKFILEPING handling. Those are the always-on desktop-seedbox parts of
/// eMule's design; padMule is foreground-only (sockets die on background), so a
/// long-lived queue would be dishonest here. Rank is arrival-order (FIFO); the
/// wire number is truthful for that ordering, and eMule's score-ordered queue
/// is wire-neutral local policy we can layer on later.
///
/// The announced rank is a BEST-EFFORT snapshot taken when the peer is queued,
/// not a promise: a slot that frees while the peer is still writing its rank can
/// be taken by a peer already parked in `acquire_owned` or by a newcomer's
/// `try_acquire_owned`, so actual grant order is only approximately FIFO. eMule
/// ranks are likewise advisory (recomputed on demand, not a reservation).
pub struct UploadGate {
    slots: Arc<Semaphore>,
    waiting: AtomicUsize,
    queue_cap: usize,
}

impl UploadGate {
    pub fn new(slots: Arc<Semaphore>, queue_cap: usize) -> Self {
        UploadGate {
            slots,
            waiting: AtomicUsize::new(0),
            queue_cap,
        }
    }

    /// Currently-waiting (queued, not yet granted) peers. For tests/telemetry.
    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::Acquire)
    }
}

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
    /// Our rating for this file (0 = none, 1 = Fake .. 5 = Excellent) and comment,
    /// pushed to a leecher (OP_FILEDESC) that accepts comments.
    pub rating: u8,
    pub comment: String,
}

/// True if `op` is a packet a peer sends when it wants to download FROM us. The
/// inbound listener uses this to tell a leecher (which talks first) from a
/// called-back LowID source (which stays silent, waiting for us to drive the
/// download of one of OUR files).
///
/// Includes OP_MULTIPACKET(_EXT): a capable downloader that saw our advertised
/// multipacket bit LEADS with the bundled request instead of a bare
/// OP_REQUESTFILENAME (aMule DownloadClient.cpp:214 SendFileRequest), so the
/// listener must recognise it as the opening upload request too.
pub fn is_upload_request(op: u8) -> bool {
    matches!(
        op,
        OP_REQUESTFILENAME
            | OP_SETREQFILEID
            | OP_STARTUPLOADREQ
            | OP_MULTIPACKET
            | OP_MULTIPACKET_EXT
    )
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

fn is_secident(op: u8) -> bool {
    matches!(op, OP_SECIDENTSTATE | OP_PUBLICKEY | OP_SIGNATURE)
}

/// Our secure-ident state for an inbound serve connection: the session, our RSA
/// identity, and a sink fired ONCE when the peer proves it owns its userhash.
///
/// A serving peer's OP_PUBLICKEY/OP_SIGNATURE (the bytes that verify IT) may
/// arrive either during the classify drain OR interleaved with serving (a real
/// leecher sends its file request between challenging us and answering our
/// challenge), so this is threaded through both [`classify_inbound`] and
/// [`serve_shared`] and drives the exchange on whichever packets arrive - NEVER
/// blocking the transfer, exactly like the download-side `handle_aux_packet`.
pub struct ServeSec {
    session: SecureIdentSession,
    identity: Arc<Identity>,
    on_verified: Box<dyn FnMut() + Send>,
    fired: bool,
}

impl ServeSec {
    pub fn new(
        session: SecureIdentSession,
        identity: Arc<Identity>,
        on_verified: Box<dyn FnMut() + Send>,
    ) -> Self {
        ServeSec {
            session,
            identity,
            on_verified,
            fired: false,
        }
    }

    /// Feed one secure-ident packet, write any replies, and fire the verified
    /// sink the first time the peer's signature checks out. A malformed packet is
    /// dropped (never fatal). Returns Err only on a write failure.
    async fn drive<S>(
        &mut self,
        fs: &mut FramedStream<S>,
        opcode: u8,
        payload: &[u8],
    ) -> Result<(), FrameError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if let Ok(replies) = self.session.on_packet(&self.identity, opcode, payload) {
            for reply in replies {
                fs.write_packet(&reply).await?;
            }
            if self.session.peer_verified() && !self.fired {
                self.fired = true;
                (self.on_verified)();
            }
        }
        Ok(())
    }

    pub fn verified(&self) -> bool {
        self.session.peer_verified()
    }
}

/// How an inbound peer classified itself after the hello.
pub enum InboundKind {
    /// A leecher issued a file request (`first`). `sec` carries the in-flight
    /// secure-ident session so verification can finish DURING serving.
    Leecher {
        first: Packet,
        sec: Option<ServeSec>,
    },
    /// Silent (after any secure-ident): a called-back LowID source. Drive the
    /// download of one of OUR files from it.
    Source,
    /// Spoke something that is neither secure-ident nor a file request; drop it.
    Other,
}

/// Classify an inbound peer as a leecher vs a called-back source, running OUR side
/// of secure identification along the way when `sec` is `Some`.
///
/// This replaces the single first-packet peek: once we ADVERTISE secure-ident,
/// BOTH a capable leecher AND a called-back source LEAD with OP_SECIDENTSTATE
/// (eMule's SendSecIdentStatePacket fires whenever the peer we hello'd advertised
/// support), so classifying on the first packet would drop both. Instead we DRAIN
/// the secure-ident prefix (feeding it into the session) and re-apply the
/// discriminator on what FOLLOWS: the first upload-request opcode => leecher; a
/// read timeout (silence) => source. `sec = None` reproduces the old plain peek.
///
/// Cancel-safety: the timeout is on each individual READ, never around a write
/// (write_packet awaits a whole frame), so a stream is always at a clean packet
/// boundary between operations and the drain cannot corrupt it. A hostile peer
/// streaming OP_SECIDENTSTATE is bounded by `MAX_SECIDENT_PKTS`.
pub async fn classify_inbound<S>(
    fs: &mut FramedStream<S>,
    mut sec: Option<ServeSec>,
    peek: Duration,
) -> InboundKind
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Symmetric with eMule: if we verify this peer, open with our own challenge.
    if let Some(s) = sec.as_ref() {
        if fs.write_packet(&s.session.start()).await.is_err() {
            return InboundKind::Other;
        }
    }
    // The honest exchange is at most challenge + pubkey + signature (+ a possible
    // second state); anything past this before a file request is a flood.
    const MAX_SECIDENT_PKTS: usize = 6;
    // A real secure-ident packet is tiny: state = 5 B, pubkey ~= 120 B, signature
    // ~= 50 B. Reject an oversized one immediately rather than drain up to
    // MAX_SECIDENT_PKTS of them at the 2 MB frame ceiling (hardening: the count
    // bound alone would let a peer push ~6 large payloads before we classify).
    const MAX_SECIDENT_PAYLOAD: usize = 512;
    let mut drained = 0usize;
    loop {
        match timeout(peek, fs.read_packet_unpacked()).await {
            Ok(Ok(pkt)) if is_upload_request(pkt.opcode) => {
                return InboundKind::Leecher { first: pkt, sec };
            }
            Ok(Ok(pkt)) if is_secident(pkt.opcode) => {
                if pkt.payload.len() > MAX_SECIDENT_PAYLOAD {
                    return InboundKind::Other;
                }
                if let Some(s) = sec.as_mut() {
                    if s.drive(fs, pkt.opcode, &pkt.payload).await.is_err() {
                        return InboundKind::Other;
                    }
                }
                drained += 1;
                if drained > MAX_SECIDENT_PKTS {
                    return InboundKind::Other;
                }
            }
            // Spoke something else, or the link errored: nothing to serve.
            Ok(_) => return InboundKind::Other,
            // Silent: a called-back source waiting for us to drive the download.
            Err(_) => return InboundKind::Source,
        }
    }
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
    gate: Option<&UploadGate>,
    peer_accept_comment: u8,
    mut sec: Option<ServeSec>,
) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let lookup = |payload: &[u8]| {
        head_hash(payload).and_then(|h| library.iter().find(|f| f.hash == h).cloned())
    };
    // The file this peer is after, once it names one.
    let mut file: Option<SharedFile> = None;
    // The upload slot, held for the whole session once granted (immediately if a
    // slot is free, or after queueing). Kept alive here so dropping it on return
    // frees the slot for the next waiter.
    let mut permit: Option<OwnedSemaphorePermit> = None;
    let mut pending = first;
    loop {
        let pkt = match pending.take() {
            Some(p) => p,
            // Bound idle time: a peer that stops sending (never asks to upload,
            // or stalls mid-transfer) is dropped rather than holding a task + fd
            // forever. An active transfer keeps packets flowing well within this.
            None => match timeout(SERVE_IDLE, fs.read_packet_unpacked()).await {
                Ok(Ok(p)) => p,
                Ok(Err(FrameError::Closed)) => return Ok(()),
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(()), // idle timeout
            },
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
                file = lookup(&pkt.payload);
                match &file {
                    Some(f) => {
                        fs.write_packet(&build_req_filename_answer(&f.hash, &f.name))
                            .await?;
                        // Push our rating/comment right after the name, exactly as
                        // eMule does (SendCommentInfo) - but only if we have one and
                        // the peer advertised it accepts comments.
                        if peer_accept_comment >= 1 && (f.rating != 0 || !f.comment.is_empty()) {
                            fs.write_packet(&build_file_desc(f.rating, &f.comment))
                                .await?;
                        }
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
            OP_MULTIPACKET | OP_MULTIPACKET_EXT => {
                // A capable downloader bundles its whole file request into one
                // packet. Answer name + status in one OP_MULTIPACKETANSWER (see
                // build_multipacket_answer). We serve complete files only, so the
                // status is a 0 part count; the comment is NOT bundled - eMule/aMule
                // never put OP_FILEDESC in a multipacket answer, and the downloader's
                // reader would desync on it (ClientTCPSocket.cpp:1258 handles only
                // name/status/AICH).
                match lookup(&pkt.payload) {
                    Some(f) => {
                        fs.write_packet(&build_multipacket_answer(&f.hash, &f.name, None))
                            .await?;
                        // Latch it so a following OP_STARTUPLOADREQ/OP_REQUESTPARTS
                        // knows which file this peer is after.
                        file = Some(f);
                    }
                    // Unknown hash: send FNF but do NOT clear a file already latched
                    // for THIS connection - a peer may serve-request several files
                    // over one connection (aMule sets UploadFileID only when found,
                    // ClientTCPSocket.cpp:1120).
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
                let Some(f) = file.clone() else { continue };
                // Already holding a slot (e.g. the peer re-asks): re-accept.
                if permit.is_some() {
                    fs.write_packet(&build_accept_upload()).await?;
                    continue;
                }
                match gate {
                    // Ungated (tests / the differential serve path): grant freely.
                    None => fs.write_packet(&build_accept_upload()).await?,
                    Some(g) => {
                        match Arc::clone(&g.slots).try_acquire_owned() {
                            // A slot was free - grant it right away.
                            Ok(p) => {
                                permit = Some(p);
                                fs.write_packet(&build_accept_upload()).await?;
                            }
                            // At capacity: queue this peer (bounded) and send its
                            // 1-based rank, then wait in place for a slot. The
                            // ticket decrements `waiting` on EVERY exit (a write
                            // error or a dropped future included), so the count
                            // cannot leak.
                            Err(_) => {
                                let (ticket, ahead) = WaitTicket::enter(g);
                                if ahead >= g.queue_cap {
                                    drop(ticket);
                                    fs.write_packet(&build_file_req_ans_no_fil(&f.hash)).await?;
                                    return Ok(());
                                }
                                let rank = ahead.saturating_add(1).min(u16::MAX as usize) as u16;
                                // eMule bans a peer that receives an UNSOLICITED
                                // rank; only ever send it in reply to this ask.
                                fs.write_packet(&build_queue_ranking(rank)).await?;
                                // Wait in place for a freed slot (the fair
                                // semaphore favours the longest waiter), bounded so
                                // a waiter cannot tie up the connection forever.
                                let granted =
                                    timeout(QUEUE_WAIT, Arc::clone(&g.slots).acquire_owned()).await;
                                drop(ticket); // no longer waiting, however this went
                                match granted {
                                    Ok(Ok(p)) => {
                                        permit = Some(p);
                                        fs.write_packet(&build_accept_upload()).await?;
                                    }
                                    // Timed out, or the gate closed: close the
                                    // connection; the peer may reconnect.
                                    _ => return Ok(()),
                                }
                            }
                        }
                    }
                }
            }
            OP_REQUESTPARTS | OP_REQUESTPARTS_I64 => {
                let Some(f) = file.clone() else { continue };
                // A gated peer must hold a granted slot before we stream data -
                // otherwise a peer that skips OP_STARTUPLOADREQ would bypass the
                // slot cap and the queue entirely. Ungated callers (tests / the
                // differential serve path) have no gate and serve freely.
                if gate.is_some() && permit.is_none() {
                    continue;
                }
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
                        crate::stats::add_uploaded(data.len() as u64);
                    }
                }
            }
            // The leecher's OP_PUBLICKEY/OP_SIGNATURE (answering the challenge we
            // issued in classify_inbound) arrive AFTER its file request, so finish
            // verification here - interleaved with serving, never blocking it. A
            // peer that never answers just stays unverified.
            op if is_secident(op) => {
                if let Some(s) = sec.as_mut() {
                    s.drive(fs, op, &pkt.payload).await?;
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

    #[test]
    fn wait_ticket_increments_on_enter_and_decrements_on_drop() {
        // The RAII guard is what keeps a disconnect-while-queued from leaking
        // queue capacity: whatever exit path the serve loop takes, the ticket's
        // Drop runs and undoes the increment.
        let gate = UploadGate::new(std::sync::Arc::new(Semaphore::new(1)), 32);
        assert_eq!(gate.waiting(), 0);
        {
            let (_t, ahead) = WaitTicket::enter(&gate);
            assert_eq!(ahead, 0, "first waiter sees nobody ahead");
            assert_eq!(gate.waiting(), 1);
            let (_t2, ahead2) = WaitTicket::enter(&gate);
            assert_eq!(ahead2, 1, "second waiter sees one ahead");
            assert_eq!(gate.waiting(), 2);
        } // both tickets drop here (as they would on any serve-loop exit)
        assert_eq!(gate.waiting(), 0, "the count is fully released on drop");
    }

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
            rating: 0,
            comment: String::new(),
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None, None, 0, None).await;
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

    #[test]
    fn is_upload_request_recognises_the_opening_opcodes() {
        use crate::transfer::{
            OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_REQUESTFILENAME, OP_SETREQFILEID,
            OP_STARTUPLOADREQ,
        };
        // A multipacket-capable leecher LEADS with OP_MULTIPACKET(_EXT); the
        // listener gate must admit it, or the connection is dropped unanswered.
        for op in [
            OP_REQUESTFILENAME,
            OP_SETREQFILEID,
            OP_STARTUPLOADREQ,
            OP_MULTIPACKET,
            OP_MULTIPACKET_EXT,
        ] {
            assert!(
                is_upload_request(op),
                "opcode 0x{op:02x} must open a serve session"
            );
        }
        // A called-back source stays silent; a data opcode is not an opener.
        assert!(!is_upload_request(0x46)); // OP_SENDINGPART
    }

    #[tokio::test]
    async fn classify_plain_leecher_vs_silent_source() {
        use crate::transfer::build_request_filename_ext;
        use tokio::io::duplex;

        // No secure-ident: a leecher leads with a file request.
        let (client, server) = duplex(8192);
        let mut server_fs = FramedStream::plaintext_with_prefix(server, &[]);
        let mut client_fs = FramedStream::plaintext_with_prefix(client, &[]);
        client_fs
            .write_packet(&build_request_filename_ext(&[7u8; 16]))
            .await
            .unwrap();
        match classify_inbound(&mut server_fs, None, Duration::from_millis(200)).await {
            InboundKind::Leecher { first, sec } => {
                assert_eq!(first.opcode, OP_REQUESTFILENAME);
                assert!(sec.is_none());
            }
            _ => panic!("expected a leecher"),
        }

        // A called-back source stays silent -> Source (keep the client end alive so
        // the read TIMES OUT rather than hitting EOF).
        let (_client2, server2) = duplex(8192);
        let mut server2_fs = FramedStream::plaintext_with_prefix(server2, &[]);
        assert!(matches!(
            classify_inbound(&mut server2_fs, None, Duration::from_millis(100)).await,
            InboundKind::Source
        ));
    }

    #[tokio::test]
    async fn classify_drains_a_secident_prefix_then_classifies() {
        use crate::secure_ident::{build_sec_ident_state, IS_KEYANDSIGNEEDED};
        use crate::transfer::build_request_filename_ext;
        use tokio::io::duplex;

        // A capable leecher LEADS with OP_SECIDENTSTATE, then the file request: the
        // drain must not misread the sec-ident prefix as the classification packet.
        let (client, server) = duplex(8192);
        let mut server_fs = FramedStream::plaintext_with_prefix(server, &[]);
        let mut client_fs = FramedStream::plaintext_with_prefix(client, &[]);
        let id = Arc::new(Identity::generate());
        let sec = ServeSec::new(SecureIdentSession::new(&id), id, Box::new(|| {}));
        client_fs
            .write_packet(&build_sec_ident_state(IS_KEYANDSIGNEEDED, 0x1234_5678))
            .await
            .unwrap();
        client_fs
            .write_packet(&build_request_filename_ext(&[7u8; 16]))
            .await
            .unwrap();
        match classify_inbound(&mut server_fs, Some(sec), Duration::from_millis(300)).await {
            InboundKind::Leecher { first, sec } => {
                assert_eq!(first.opcode, OP_REQUESTFILENAME);
                assert!(sec.is_some());
            }
            _ => panic!("expected a leecher after draining the sec-ident prefix"),
        }
    }

    #[tokio::test]
    async fn classify_bounds_a_secident_flood() {
        use crate::secure_ident::{build_sec_ident_state, IS_KEYANDSIGNEEDED};
        use tokio::io::duplex;

        // A hostile peer streaming OP_SECIDENTSTATE with no file request must be cut
        // off by the packet-count bound, not spin holding the task/fd.
        let (client, server) = duplex(64 * 1024);
        let mut server_fs = FramedStream::plaintext_with_prefix(server, &[]);
        let mut client_fs = FramedStream::plaintext_with_prefix(client, &[]);
        let id = Arc::new(Identity::generate());
        let sec = ServeSec::new(SecureIdentSession::new(&id), id, Box::new(|| {}));
        for i in 0..8u32 {
            client_fs
                .write_packet(&build_sec_ident_state(IS_KEYANDSIGNEEDED, i | 1))
                .await
                .unwrap();
        }
        assert!(matches!(
            classify_inbound(&mut server_fs, Some(sec), Duration::from_millis(300)).await,
            InboundKind::Other
        ));
    }

    #[tokio::test]
    async fn serve_verifies_a_faithful_mock_leecher() {
        // The faithful other-side per [[interop-test-fidelity]]: a mock playing the
        // REAL downloader role - it INITIATES its own OP_SECIDENTSTATE, requests the
        // file, and answers padMule's challenge. NOT both-serve, NOT responder-only.
        use crate::transfer::build_request_filename_ext;
        use std::sync::atomic::{AtomicBool, Ordering};
        use tokio::io::duplex;

        let hash = [0x5A; 16];
        let shared = vec![SharedFile {
            hash,
            size: 100,
            name: b"verify.bin".to_vec(),
            part_hashes: vec![],
            path: PathBuf::from("/does/not/matter"),
            rating: 0,
            comment: String::new(),
        }];

        let (client, server) = duplex(64 * 1024);
        let mut server_fs = FramedStream::plaintext_with_prefix(server, &[]);
        let mut client_fs = FramedStream::plaintext_with_prefix(client, &[]);

        let server_id = Arc::new(Identity::generate());
        let verified = Arc::new(AtomicBool::new(false));
        let v2 = Arc::clone(&verified);

        let server_task = tokio::spawn(async move {
            let sec = ServeSec::new(
                SecureIdentSession::new(&server_id),
                Arc::clone(&server_id),
                Box::new(move || v2.store(true, Ordering::SeqCst)),
            );
            if let InboundKind::Leecher { first, sec } =
                classify_inbound(&mut server_fs, Some(sec), Duration::from_millis(500)).await
            {
                let _ = serve_shared(&mut server_fs, &shared, Some(first), None, 0, sec).await;
            }
        });

        let mock_id = Identity::generate();
        let mut mock = SecureIdentSession::new(&mock_id);
        client_fs.write_packet(&mock.start()).await.unwrap(); // INITIATE (the real role)
        client_fs
            .write_packet(&build_request_filename_ext(&hash))
            .await
            .unwrap(); // -> classified a leecher
        while !mock.is_complete() {
            let pkt = match tokio::time::timeout(
                Duration::from_secs(2),
                client_fs.read_packet_unpacked(),
            )
            .await
            {
                Ok(Ok(p)) => p,
                _ => break,
            };
            if is_secident(pkt.opcode) {
                for reply in mock.on_packet(&mock_id, pkt.opcode, &pkt.payload).unwrap() {
                    client_fs.write_packet(&reply).await.unwrap();
                }
            }
        }
        // Our signature is now sent (and buffered); close so serve_shared drains it
        // and returns.
        drop(client_fs);
        let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        assert!(
            verified.load(Ordering::SeqCst),
            "padMule must verify the mock leecher serve-side"
        );
        assert!(
            mock.peer_verified(),
            "the mock must also verify padMule (mutual)"
        );
    }

    #[tokio::test]
    async fn classify_drains_secident_then_routes_a_silent_source_to_download() {
        // The 8ac-regression guard, end to end: a called-back source that (having
        // seen our advertised secure-ident) LEADS with OP_SECIDENTSTATE then stays
        // silent about files must STILL classify as Source, AND the post-drain
        // stream must be clean for download_from_peer.
        use crate::secure_ident::{build_sec_ident_state, IS_KEYANDSIGNEEDED};
        use crate::transfer::{build_file_req_ans_no_fil, OP_SETREQFILEID};
        use tokio::io::duplex;

        let dir = tmpdir("srcdrain");
        let hash = [0x33; 16];
        let store = PartStore::create(&dir, 1, hash, 400_000, b"s.bin").unwrap();
        let dl = Download::new(store);

        let (client, server) = duplex(64 * 1024);
        let mut us_fs = FramedStream::plaintext_with_prefix(server, &[]); // padMule listener side
        let mut src_fs = FramedStream::plaintext_with_prefix(client, &[]); // the called-back source

        // The source: issue OUR-facing OP_SECIDENTSTATE, then stay silent about
        // files; when download_from_peer requests the file, decline it (NoFile) so
        // the session ends cleanly - proving the post-drain stream is intact.
        let src = tokio::spawn(async move {
            src_fs
                .write_packet(&build_sec_ident_state(IS_KEYANDSIGNEEDED, 0xABCD_0001))
                .await
                .unwrap();
            loop {
                let pkt = src_fs.read_packet_unpacked().await.unwrap();
                if pkt.opcode == OP_SETREQFILEID {
                    break;
                }
            }
            src_fs
                .write_packet(&build_file_req_ans_no_fil(&hash))
                .await
                .unwrap();
        });

        let id = Arc::new(Identity::generate());
        let sec = ServeSec::new(SecureIdentSession::new(&id), id, Box::new(|| {}));
        match classify_inbound(&mut us_fs, Some(sec), Duration::from_millis(200)).await {
            InboundKind::Source => {}
            _ => panic!("a sec-ident-then-silent called-back source must classify as Source"),
        }
        // The handoff: download_from_peer speaks first and reads the FILEREQANSNOFIL
        // cleanly -> NoFile. A corrupted/misframed stream would error or hang.
        let r = download_from_peer(&mut us_fs, &dl, false).await;
        assert!(
            matches!(r, Err(TransferError::NoFile)),
            "post-drain stream must be usable by download_from_peer"
        );
        let _ = src.await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn serve_shared_answers_a_multipacket_with_name_and_status() {
        use crate::transfer::{
            OP_MULTIPACKETANSWER, OP_MULTIPACKET_EXT, OP_REQFILENAMEANSWER, OP_REQUESTFILENAME,
        };
        use mule_proto::{Packet, PROT_EMULE};
        let hash = [0x79; 16];
        let shared = vec![SharedFile {
            hash,
            size: 100,
            name: b"multi.bin".to_vec(),
            part_hashes: vec![],
            path: PathBuf::from("/does/not/matter"),
            rating: 0,
            comment: String::new(),
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None, None, 0, None).await;
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();

        // OP_MULTIPACKET_EXT for the shared file: <hash><u64 size><0x58 ...>.
        let mut payload = Vec::new();
        payload.extend_from_slice(&hash);
        payload.extend_from_slice(&100u64.to_le_bytes());
        payload.push(OP_REQUESTFILENAME);
        fs.write_packet(&Packet::new(PROT_EMULE, OP_MULTIPACKET_EXT, payload))
            .await
            .unwrap();

        let ans = fs.read_packet().await.unwrap();
        assert_eq!(ans.opcode, OP_MULTIPACKETANSWER);
        assert_eq!(&ans.payload[..16], &hash);
        assert_eq!(ans.payload[16], OP_REQFILENAMEANSWER);

        drop(fs);
        up.await.unwrap();
    }

    #[tokio::test]
    async fn we_serve_our_rating_and_comment_when_the_peer_accepts() {
        use crate::transfer::{
            build_request_filename_ext, parse_file_desc, OP_FILEDESC, OP_REQFILENAMEANSWER,
        };
        let hash = [0x77; 16];
        let shared = vec![SharedFile {
            hash,
            size: 100,
            name: b"rated.bin".to_vec(),
            part_hashes: vec![],
            path: PathBuf::from("/does/not/matter"),
            rating: 4,
            comment: "great little file".to_string(),
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                // The peer advertised AcceptCommentVer=1.
                let _ = serve_shared(&mut fs, &shared, None, None, 1, None).await;
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        fs.write_packet(&build_request_filename_ext(&hash))
            .await
            .unwrap();
        // First the filename answer, then - because we have a rating/comment and
        // the peer accepts comments - OP_FILEDESC right behind it (SendCommentInfo).
        let ans = fs.read_packet().await.unwrap();
        assert_eq!(ans.opcode, OP_REQFILENAMEANSWER);
        let desc = fs.read_packet().await.unwrap();
        assert_eq!(desc.opcode, OP_FILEDESC);
        let (rating, comment) = parse_file_desc(&desc.payload).unwrap();
        assert_eq!(rating, 4);
        assert_eq!(comment, "great little file");

        drop(fs);
        up.await.unwrap();
    }

    #[tokio::test]
    async fn we_withhold_the_comment_when_the_peer_does_not_accept() {
        use crate::transfer::{build_request_filename_ext, OP_REQFILENAMEANSWER};
        let hash = [0x78; 16];
        let shared = vec![SharedFile {
            hash,
            size: 100,
            name: b"rated.bin".to_vec(),
            part_hashes: vec![],
            path: PathBuf::from("/does/not/matter"),
            rating: 4,
            comment: "hidden".to_string(),
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                // The peer did NOT advertise AcceptCommentVer.
                let _ = serve_shared(&mut fs, &shared, None, None, 0, None).await;
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        fs.write_packet(&build_request_filename_ext(&hash))
            .await
            .unwrap();
        let ans = fs.read_packet().await.unwrap();
        assert_eq!(ans.opcode, OP_REQFILENAMEANSWER);
        // No OP_FILEDESC follows: the server is now idle-waiting for the next
        // request, so a short read on our side elapses instead of returning a desc.
        let next =
            tokio::time::timeout(std::time::Duration::from_millis(300), fs.read_packet()).await;
        assert!(
            next.is_err(),
            "must not send OP_FILEDESC when the peer does not accept comments"
        );

        drop(fs);
        up.await.unwrap();
    }

    #[tokio::test]
    async fn a_hash_we_do_not_hold_is_refused_not_hung() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // An EMPTY library: whatever is asked for, we do not have it.
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &[], None, None, 0, None).await;
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
            rating: 0,
            comment: String::new(),
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None, None, 0, None).await;
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
