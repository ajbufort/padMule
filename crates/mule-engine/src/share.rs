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

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use mule_proto::Packet;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{timeout, Duration};

/// Drop a serve connection that goes silent this long between packets. Bounds
/// idle pre-upload sessions (a peer that names a file then never asks) - eMule
/// reaps at CONNECTION_TIMEOUT=40s; we allow more slack for a slow link.
const SERVE_IDLE: Duration = Duration::from_secs(60);
/// Longest a queued peer waits in place for a slot before we close its
/// connection (it can reconnect). Bounds how long a waiter ties up a task/fd.
const QUEUE_WAIT: Duration = Duration::from_secs(120);

use crate::credit_store::{now_secs, CreditStore};
use crate::framed::{FrameError, FramedStream};
use crate::secure_ident::{
    Identity, SecureIdentSession, OP_PUBLICKEY, OP_SECIDENTSTATE, OP_SIGNATURE,
};
use crate::sources::{
    build_answer_sources, parse_request_sources, parse_request_sources2, Source as SxSource,
    OP_REQUESTSOURCES, OP_REQUESTSOURCES2, SOURCE_EXCHANGE_VERSION,
};
use crate::transfer::{
    build_accept_upload, build_aich_answer, build_aich_answer_failure, build_aich_file_hash_ans,
    build_file_desc, build_file_req_ans_no_fil, build_file_status_complete, build_hashset_answer,
    build_multipacket_answer, build_queue_ranking, build_req_filename_answer, build_sending_part,
    parse_aich_request, parse_request_parts, EMBLOCKSIZE, OP_AICHFILEHASHREQ, OP_AICHREQUEST,
    OP_HASHSETREQUEST, OP_MULTIPACKET, OP_MULTIPACKET_EXT, OP_REQUESTFILENAME, OP_REQUESTPARTS,
    OP_REQUESTPARTS_I64, OP_SETREQFILEID, OP_STARTUPLOADREQ,
};

/// Re-asking for the SAME file sooner than this is an "aggressive" request
/// (eMule `MIN_REQUESTTIME`, opcodes.h:116 = MIN2MS(10) = 10 minutes).
pub const MIN_REQUESTTIME_SECS: u64 = 600;
/// Bad requests for one file before we stop answering it (eMule `BADCLIENTBAN`,
/// opcodes.h:115 = 4, where it triggers `Ban()`).
pub const BADCLIENTBAN: u32 = 4;

/// Per-connection, per-FILE request scoring - eMule's
/// `CUpDownClient::AddRequestCount` (UploadClient.cpp:895-918). A peer that
/// re-asks about the same file inside `MIN_REQUESTTIME` scores a bad request;
/// one that waits politely has its score DECREMENTED instead, so a long-lived
/// well-behaved peer never creeps into a refusal.
///
/// Scope, deliberately: this gates cheap METADATA requests (name/status/hashset/
/// sources), never block delivery - a downloader legitimately sends a stream of
/// OP_REQUESTPARTS, and throttling those would break transfers. padMule keeps
/// this per-connection because that is the model share.rs already documents (no
/// cross-connection queue persistence); dropping the connection is our
/// equivalent of upstream's `Ban()` for the session.
#[derive(Default)]
pub struct RequestCounter {
    /// file hash -> (last asked at, bad-request score)
    files: HashMap<[u8; 16], (u64, u32)>,
}

impl RequestCounter {
    /// Score a request for `hash` at `now_secs` and report whether to ANSWER it.
    pub fn allow(&mut self, hash: &[u8; 16], now_secs: u64) -> bool {
        let e = self.files.entry(*hash).or_insert((now_secs, 0));
        let (last, score) = *e;
        // The very first ask for a file is always polite (upstream inserts a
        // fresh record with badrequests = 0 and returns).
        if last != now_secs || score > 0 {
            if now_secs.saturating_sub(last) < MIN_REQUESTTIME_SECS {
                e.1 = score.saturating_add(1);
            } else {
                e.1 = score.saturating_sub(1);
            }
        }
        e.0 = now_secs;
        e.1 < BADCLIENTBAN
    }
}

/// A bounded upload gate: `slots_total` concurrent uploads plus a wait queue
/// ordered by CREDIT SCORE. When every slot is busy a new requester is queued and
/// told its 1-based place (OP_QUEUERANKING), then granted a slot IN PLACE on the
/// connection we already hold open the moment one frees - the BEST-scored waiter
/// first (eMule's score-ordered queue, ClientCredits/UploadQueue).
///
/// REWEIGHT-ONLY / NEVER-REFUSE: the score only reorders the queue. No peer is
/// ever denied a slot on its score (score is clamped >= 1.0); a low-credit peer
/// just waits longer, bounded by QUEUE_WAIT, and may reconnect. Admission is
/// refused ONLY when the queue is at `queue_cap` - independent of identity/score.
///
/// Deliberately scoped to the held connection: no cross-connection queue
/// persistence, no slot-grant dial-out to an idled peer, no UDP OP_REASKFILEPING.
/// Those are the always-on desktop-seedbox parts of eMule's design; padMule is
/// foreground-only. The announced rank is a BEST-EFFORT snapshot at queue time;
/// a later-arriving higher-credit peer can outrank it, as in eMule.
pub struct UploadGate {
    inner: std::sync::Mutex<GateInner>,
    /// Woken (all waiters) whenever a slot frees or a waiter leaves; each parked
    /// waiter re-checks whether IT is now the best with a slot to take.
    notify: tokio::sync::Notify,
    queue_cap: usize,
    /// Who we are serving/queueing, per file hash. Read to answer a source
    /// request; a separate lock so it never contends the slot bookkeeping.
    served: std::sync::Mutex<HashMap<[u8; 16], Vec<ServedPeer>>>,
}

/// A peer we are currently uploading to / holding queued for one file - aMule's
/// `m_ClientUploadList`, which is exactly the set its source-exchange answer is
/// built from (`CKnownFile::CreateSrcInfoPacket`).
#[derive(Clone)]
pub struct ServedPeer {
    pub addr: SocketAddr,
    pub user_hash: Option<[u8; 16]>,
    /// The peer's obfuscation connect-options byte, so a source we hand out can
    /// be dialed obfuscated by the receiver (SX v4 carries it).
    pub crypt: Option<u8>,
}

struct GateInner {
    slots_free: usize,
    /// Waiters BEST-FIRST: `(Reverse(score_key), seq)`. Higher score sorts first;
    /// `seq` breaks ties in arrival (FIFO) order.
    waiters: std::collections::BTreeSet<(std::cmp::Reverse<u32>, u64)>,
    next_seq: u64,
}

impl UploadGate {
    pub fn new(slots_total: usize, queue_cap: usize) -> Self {
        UploadGate {
            inner: std::sync::Mutex::new(GateInner {
                slots_free: slots_total,
                waiters: std::collections::BTreeSet::new(),
                next_seq: 0,
            }),
            notify: tokio::sync::Notify::new(),
            queue_cap,
            served: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Remember that `peer` is being served (or is queued) for `hash`, so a
    /// source-exchange request for that file can name it - the padMule
    /// equivalent of aMule adding a client to a file's upload list.
    pub fn note_serving(&self, hash: [u8; 16], peer: ServedPeer) {
        let mut g = self.served.lock().unwrap();
        let v = g.entry(hash).or_default();
        if !v.iter().any(|p| p.addr == peer.addr) {
            v.push(peer);
        }
    }

    /// Forget a peer once its serve session ends (always paired with
    /// `note_serving` by `ServedGuard`, so a dropped connection never leaves a
    /// stale source we would hand to others).
    pub fn stop_serving(&self, hash: &[u8; 16], addr: SocketAddr) {
        let mut g = self.served.lock().unwrap();
        if let Some(v) = g.get_mut(hash) {
            v.retain(|p| p.addr != addr);
            if v.is_empty() {
                g.remove(hash);
            }
        }
    }

    /// The source records to answer a source-exchange request for `hash` with.
    /// Skips the asker itself and any peer we cannot name usefully (no port),
    /// matching aMule's own skips (`cur_src == forClient`, LowID).
    pub fn sources_for(&self, hash: &[u8; 16], exclude: Option<SocketAddr>) -> Vec<SxSource> {
        let g = self.served.lock().unwrap();
        let Some(v) = g.get(hash) else {
            return Vec::new();
        };
        v.iter()
            .filter(|p| Some(p.addr) != exclude)
            .filter_map(|p| {
                // Only a HighID peer on a routable address is worth handing out;
                // a LowID one is unreachable without a callback (aMule skips it).
                let SocketAddr::V4(v4) = p.addr else {
                    return None;
                };
                if !crate::fetch::is_routable_public_v4(*v4.ip()) {
                    return None;
                }
                let o = v4.ip().octets();
                Some(SxSource {
                    // eD2k convention: first octet in the LOW byte.
                    ip: u32::from_le_bytes(o),
                    port: v4.port(),
                    server_ip: 0,
                    server_port: 0,
                    user_hash: p.user_hash,
                    crypt: p.crypt,
                })
            })
            .collect()
    }

    /// Currently-waiting (queued, not yet granted) peers. For tests/telemetry.
    pub fn waiting(&self) -> usize {
        self.inner.lock().unwrap().waiters.len()
    }

    /// Grant a slot immediately IFF one is free AND nobody is queued - a newcomer
    /// must never jump ahead of waiting peers. Returns a guard that frees the slot
    /// (and wakes the best waiter) on drop.
    pub fn try_grant(self: &Arc<Self>) -> Option<SlotGuard> {
        let mut g = self.inner.lock().unwrap();
        if g.slots_free > 0 && g.waiters.is_empty() {
            g.slots_free -= 1;
            Some(SlotGuard {
                gate: Arc::clone(self),
            })
        } else {
            None
        }
    }

    /// Enqueue a waiter with `score_key` (higher = better). Returns its 1-based
    /// rank snapshot + a handle to await a slot, or `None` if the queue is full
    /// (the only refusal, and it is identity-independent).
    pub fn enqueue(self: &Arc<Self>, score_key: u32) -> Option<QueueWaiter> {
        let mut g = self.inner.lock().unwrap();
        if g.waiters.len() >= self.queue_cap {
            return None;
        }
        let seq = g.next_seq;
        g.next_seq += 1;
        let key = (std::cmp::Reverse(score_key), seq);
        // Rank = how many already-queued waiters outrank me, + 1.
        let rank = g.waiters.range(..key).count() + 1;
        g.waiters.insert(key);
        Some(QueueWaiter {
            gate: Arc::clone(self),
            key,
            rank,
            done: false,
        })
    }
}

/// Holds one upload slot; frees it (and wakes the best waiter) on drop.
pub struct SlotGuard {
    gate: Arc<UploadGate>,
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.gate.inner.lock().unwrap().slots_free += 1;
        // Wake all parked waiters; the best-scored one re-checks and takes it.
        self.gate.notify.notify_waiters();
    }
}

/// A queued waiter. Await [`QueueWaiter::granted`] for a slot; DROPPING it before
/// then (a disconnect or a QUEUE_WAIT timeout) removes it from the queue so it can
/// never block the peers behind it - the leak-proofing the old WaitTicket gave.
pub struct QueueWaiter {
    gate: Arc<UploadGate>,
    key: (std::cmp::Reverse<u32>, u64),
    pub rank: usize,
    done: bool,
}

impl QueueWaiter {
    /// Wait until this waiter is the BEST queued AND a slot is free, then take it.
    pub async fn granted(mut self) -> SlotGuard {
        loop {
            // Arm the wake BEFORE checking, so a slot freed between the check and
            // the await is captured (notify_waiters does not store a permit).
            let notified = self.gate.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut g = self.gate.inner.lock().unwrap();
                if g.slots_free > 0 && g.waiters.iter().next() == Some(&self.key) {
                    g.slots_free -= 1;
                    g.waiters.remove(&self.key);
                    self.done = true; // taken: Drop must not re-remove or re-notify
                    return SlotGuard {
                        gate: Arc::clone(&self.gate),
                    };
                }
            }
            notified.await;
        }
    }
}

impl Drop for QueueWaiter {
    fn drop(&mut self) {
        if !self.done {
            self.gate.inner.lock().unwrap().waiters.remove(&self.key);
            // Our departure may make a slot claimable by the next-best waiter.
            self.gate.notify.notify_waiters();
        }
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
    /// The file's AICH master root, when its full hashset is in the known2
    /// store (computed at finish; None for pre-AICH library entries, which
    /// honestly refuse recovery requests until re-completed).
    pub aich_root: Option<[u8; 20]>,
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

/// Whether a multipacket request bundles the OP_AICHFILEHASHREQ sub-op.
///
/// Walks the sub-opcode tail exactly as eMule's reader does
/// (ListenSocket.cpp:1178-1287): OP_REQUESTFILENAME carries the extended
/// requester info the sender wrote for OUR advertised
/// ExtendedRequestsVersion 2 (u16 part count, the availability bitfield when
/// non-zero, u16 complete sources - UploadClient.cpp ProcessExtendedInfo);
/// OP_SETREQFILEID and OP_REQUESTSOURCES are bare; OP_REQUESTSOURCES2 carries
/// u8 version + u16 options; OP_AICHFILEHASHREQ is bare. eMule THROWS on an
/// unknown sub-op; we stop walking instead (keeping anything already found),
/// which preserves the pre-AICH tolerance for malformed tails - the answer is
/// never desynced by what we could not parse.
fn multipacket_wants_aich(payload: &[u8], ext: bool) -> bool {
    let mut pos = 16 + if ext { 8 } else { 0 };
    let mut found = false;
    let take = |pos: &mut usize, n: usize, len: usize| -> bool {
        if *pos + n > len {
            return false;
        }
        *pos += n;
        true
    };
    while pos < payload.len() {
        let op = payload[pos];
        pos += 1;
        match op {
            OP_REQUESTFILENAME => {
                if pos + 2 > payload.len() {
                    return found;
                }
                let pc = u16::from_le_bytes([payload[pos], payload[pos + 1]]) as usize;
                pos += 2;
                if pc > 0 && !take(&mut pos, pc.div_ceil(8), payload.len()) {
                    return found;
                }
                if !take(&mut pos, 2, payload.len()) {
                    return found;
                }
            }
            OP_SETREQFILEID | OP_REQUESTSOURCES => {}
            OP_REQUESTSOURCES2 => {
                if !take(&mut pos, 3, payload.len()) {
                    return found;
                }
            }
            OP_AICHFILEHASHREQ => found = true,
            _ => return found,
        }
    }
    found
}

/// The credit-accounting context for a serve connection: the shared store plus the
/// peer's userhash to accrue against. `None` on non-engine paths (tests / the CLI
/// serve harness), which do not persist credits.
pub type CreditCtx = (Arc<CreditStore>, [u8; 16]);

/// Fired once with the peer's public key when its serve-side identity verifies.
pub type VerifiedSink = Box<dyn FnMut(&[u8]) + Send>;

/// The upload-queue score KEY (higher = better) for the leecher on this connection:
/// its stored credit ratio, gated by whether it has verified its identity THIS
/// session. `None` credit (tests / CLI) or an unknown peer yields the floor. The
/// `[1.0, 10.0]` ratio is scaled to an integer key for the queue ordering.
fn leecher_score_key(credit: &Option<CreditCtx>, sec: &Option<ServeSec>) -> u32 {
    let ratio = match credit {
        Some((store, uh)) => {
            // Transient per-connection verified IP: a peer that proved its identity
            // this session is treated as Identified (we do not track the IP here, so
            // verified_ip == current_ip == 0). Verification may still be pending (the
            // signature can arrive after this request), in which case it scores as an
            // unverified key-bearer for THIS admission - conservative, and fine.
            let verified_ip = sec.as_ref().filter(|s| s.verified()).map(|_| 0u32);
            store.score(uh, verified_ip, 0, false)
        }
        None => 1.0,
    };
    (ratio * 1000.0) as u32
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
    /// Fired once with the peer's public key when its signature checks out (so the
    /// caller can bind the key to the peer's userhash in the credit store).
    on_verified: VerifiedSink,
    fired: bool,
}

impl ServeSec {
    pub fn new(
        session: SecureIdentSession,
        identity: Arc<Identity>,
        on_verified: VerifiedSink,
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
                (self.on_verified)(self.session.peer_pubkey());
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
///
/// `credit` is `Some((store, peer_userhash))` on the live engine path, so the
/// bytes we upload are accrued against this peer's credit record.
#[allow(clippy::too_many_arguments)]
/// The optional extras one SERVE connection carries, bundled to keep the arity
/// readable (the mirror of `PeerSession` on the download side).
#[derive(Default)]
pub struct ServeSession {
    /// Our serve-side secure-ident session (verify the leecher's identity).
    pub sec: Option<ServeSec>,
    /// Credit sink: bytes we upload are accrued against this peer.
    pub credit: Option<CreditCtx>,
    /// The peer's address, so it can be named to OTHER peers in a
    /// source-exchange answer (and excluded from its own).
    pub peer: Option<SocketAddr>,
    /// The peer's obfuscation connect-options byte, derived from its hello, so
    /// an SX v4 record we emit tells the receiver it can dial obfuscated.
    pub peer_crypt: Option<u8>,
    /// The peer's announced SX1 version (hello MISCOPTIONS1). An SX1 request
    /// carries no version, so upstream answers with the version the ASKER
    /// announced; 0 means "no SX1" and such a request goes unanswered.
    pub peer_sx1: u8,
    /// The peer's announced AICH version (hello MISCOPTIONS1 bits 29-31).
    /// Root answers are gated on bit 0, eMule's own IsSupportingAICH test
    /// (updownclient.h:407).
    pub peer_aich: u8,
    /// The known2_64.met hashset store, for serving OP_AICHREQUEST recovery
    /// data. `None` (tests without AICH) refuses recovery honestly.
    pub aich: Option<Arc<crate::known2_store::Known2Store>>,
}

/// Keeps the file's served-peer list honest: registered on latch, removed on
/// EVERY exit (drop), so a disconnect never leaves us handing out a dead source.
struct ServedGuard {
    gate: Arc<UploadGate>,
    hash: [u8; 16],
    addr: SocketAddr,
}

impl Drop for ServedGuard {
    fn drop(&mut self) {
        self.gate.stop_serving(&self.hash, self.addr);
    }
}

pub async fn serve_shared<S>(
    fs: &mut FramedStream<S>,
    library: &[SharedFile],
    first: Option<Packet>,
    gate: Option<&Arc<UploadGate>>,
    peer_accept_comment: u8,
    session: ServeSession,
) -> Result<(), FrameError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ServeSession {
        mut sec,
        credit,
        peer,
        peer_crypt,
        peer_sx1,
        peer_aich,
        aich,
    } = session;
    // Unregisters this peer from the file's served list on EVERY exit path.
    let mut served: Option<ServedGuard> = None;
    // A shared file counts as OURS only while its bytes are still on disk at the
    // size we hashed. The downloads directory is the user-visible Files folder,
    // so a finished file can be deleted (or replaced) under us at any moment,
    // and the in-memory library is only rebuilt at start(). Without this check
    // padMule answered "I have it, COMPLETE", took an upload slot, and then
    // dropped the connection when the read failed - the worst possible shape,
    // because the peer had every reason to trust us. Costs one stat per file
    // REQUEST (not per block), and the miss path is the same FNF/silence the
    // authorities send for a file they do not have.
    let lookup = |payload: &[u8]| {
        head_hash(payload)
            .and_then(|h| library.iter().find(|f| f.hash == h).cloned())
            .filter(|f| matches!(std::fs::metadata(&f.path), Ok(m) if m.len() == f.size))
    };
    // The file this peer is after, once it names one.
    let mut file: Option<SharedFile> = None;
    // The upload slot, held for the whole session once granted (immediately if a
    // slot is free, or after queueing). Kept alive here so dropping it on return
    // frees the slot for the next waiter.
    let mut permit: Option<SlotGuard> = None;
    let mut pending = first;
    // Per-file request scoring for THIS connection (eMule AddRequestCount).
    let mut requests = RequestCounter::default();
    // Register the peer against the file it is after, so OTHER peers asking us
    // for sources can be told about it (and so it is excluded from its own
    // answer). Re-run after each latch point; the guard removes it on exit.
    macro_rules! register_served {
        () => {
            if let (Some(f), Some(g), Some(addr)) = (&file, gate, peer) {
                if served.as_ref().map(|s: &ServedGuard| s.hash) != Some(f.hash) {
                    g.note_serving(
                        f.hash,
                        ServedPeer {
                            addr,
                            user_hash: credit.as_ref().map(|(_, uh)| *uh),
                            crypt: peer_crypt,
                        },
                    );
                    served = Some(ServedGuard {
                        gate: Arc::clone(g),
                        hash: f.hash,
                        addr,
                    });
                }
            }
        };
    }
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
        // Score the cheap metadata requests before answering any of them: each
        // is a small ask with a comparatively expensive answer (a name+status, a
        // hashset, or a whole source list), so an unthrottled peer could make us
        // rebuild them in a loop. Block requests are NEVER scored - a real
        // downloader streams OP_REQUESTPARTS and must not be penalised for it.
        // A peer already holding a slot is exempt, mirroring upstream's
        // `GetDownloadState() != DS_DOWNLOADING` carve-out.
        if permit.is_none()
            && matches!(
                pkt.opcode,
                OP_REQUESTFILENAME
                    | OP_SETREQFILEID
                    | OP_MULTIPACKET
                    | OP_MULTIPACKET_EXT
                    | OP_HASHSETREQUEST
                    | OP_REQUESTSOURCES
                    | OP_REQUESTSOURCES2
                    | OP_AICHFILEHASHREQ
                    | OP_AICHREQUEST
            )
        {
            // Score against the file the packet names; a request with no usable
            // hash is left to the individual arms to reject.
            let asked = head_hash(&pkt.payload)
                .or_else(|| file.as_ref().map(|f| f.hash))
                .unwrap_or([0u8; 16]);
            if !requests.allow(&asked, now_secs() as u64) {
                // Upstream bans here; we hold one connection, so dropping it is
                // the equivalent - the peer may reconnect and start fresh.
                return Ok(());
            }
        }
        match pkt.opcode {
            OP_REQUESTFILENAME => {
                // Only latch a file we actually found: a miss must not clear a
                // file already named on this connection (aMule sets UploadFileID
                // only when found, ClientTCPSocket.cpp:396).
                if let Some(f) = lookup(&pkt.payload) {
                    fs.write_packet(&build_req_filename_answer(&f.hash, &f.name))
                        .await?;
                    // Push our rating/comment right after the name, exactly as
                    // eMule does (SendCommentInfo) - but only if we have one and
                    // the peer advertised it accepts comments.
                    if peer_accept_comment >= 1 && (f.rating != 0 || !f.comment.is_empty()) {
                        fs.write_packet(&build_file_desc(f.rating, &f.comment))
                            .await?;
                    }
                    file = Some(f);
                    register_served!();
                }
                // An UNKNOWN hash draws SILENCE, not FNF: both authorities just
                // break (eMule 0.50a ListenSocket.cpp:374-380, which additionally
                // tracks repeat askers via CheckFailedFileIdReqs; aMule
                // ClientTCPSocket.cpp:381-385). OP_FILEREQANSNOFIL belongs to
                // OP_SETREQFILEID and the multipackets - sending it here would
                // also assert "I do not have that file" about a file we may hold.
            }
            OP_SETREQFILEID => {
                // Always answer about the hash in THIS packet, like aMule
                // (GetFileByID(fileID) on every request, ClientTCPSocket.cpp:440):
                // a peer may switch files on one connection, so a previously
                // latched file must not answer for a different hash. A miss gets
                // FNF - this opcode is where FNF genuinely belongs - and does NOT
                // clear the latch (aMule breaks before SetUploadFileID).
                match lookup(&pkt.payload) {
                    Some(f) => {
                        fs.write_packet(&build_file_status_complete(&f.hash))
                            .await?;
                        file = Some(f);
                        register_served!();
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
                        // Bundle the AICH root iff the request asked for it, the
                        // peer supports AICH, and we know the root - eMule's own
                        // three-way gate (ListenSocket.cpp:1203-1217). This is
                        // the only root channel a multipacket peer ever uses.
                        let ext = pkt.opcode == OP_MULTIPACKET_EXT;
                        let root =
                            if peer_aich & 1 != 0 && multipacket_wants_aich(&pkt.payload, ext) {
                                f.aich_root
                            } else {
                                None
                            };
                        fs.write_packet(&build_multipacket_answer(
                            &f.hash,
                            &f.name,
                            None,
                            root.as_ref(),
                        ))
                        .await?;
                        // Latch it so a following OP_STARTUPLOADREQ/OP_REQUESTPARTS
                        // knows which file this peer is after.
                        file = Some(f);
                        register_served!();
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
            // Source exchange, answer side: name the peers we are currently
            // serving/queueing for this file, exactly as aMule answers from a
            // file's upload list (CreateSrcInfoPacket) - never a general
            // "everyone we ever saw" list. Silence when we know nobody, which is
            // also what upstream does (it returns NULL and sends nothing).
            OP_REQUESTSOURCES | OP_REQUESTSOURCES2 => {
                let sx2 = pkt.opcode == OP_REQUESTSOURCES2;
                // SX2 states its version; SX1 carries none, so upstream answers
                // with the version the ASKER announced in its hello.
                let want = if sx2 {
                    parse_request_sources2(&pkt.payload)
                        .ok()
                        .map(|(v, h)| (v.min(SOURCE_EXCHANGE_VERSION), h))
                } else {
                    parse_request_sources(&pkt.payload)
                        .ok()
                        .map(|h| (peer_sx1, h))
                };
                if let (Some((version, want_hash)), Some(g)) = (want, gate) {
                    if version > 0 && library.iter().any(|f| f.hash == want_hash) {
                        let srcs = g.sources_for(&want_hash, peer);
                        if !srcs.is_empty() {
                            if let Some(p) = build_answer_sources(&want_hash, &srcs, version, sx2) {
                                fs.write_packet(&p).await?;
                            }
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
            OP_AICHFILEHASHREQ => {
                // The standalone root ask (non-multipacket peers,
                // ListenSocket.cpp:1902-1929). Answer only when the peer
                // advertised AICH and we share the file AND know its root;
                // silence otherwise, like every unknown-hash metadata ask.
                if peer_aich & 1 != 0 {
                    if let Some(root) = lookup(&pkt.payload).and_then(|f| f.aich_root) {
                        if let Some(h) = head_hash(&pkt.payload) {
                            fs.write_packet(&build_aich_file_hash_ans(&h, &root))
                                .await?;
                        }
                    }
                }
            }
            OP_AICHREQUEST => {
                // Recovery-data ask. STRICT parse first: eMule throws on any
                // size other than 38 (DownloadClient.cpp:2329-2330), so a
                // malformed packet costs the connection, exactly upstream.
                let (h, part, want_root) = match parse_aich_request(&pkt.payload) {
                    Ok(v) => v,
                    Err(e) => return Err(FrameError::Protocol(e)),
                };
                // Serve conditions transcribed from ProcessAICHRequest
                // (DownloadClient.cpp:2337-2341): shared + hashset available +
                // requested root equals ours + part in range + file AND part
                // bigger than one block. ANY miss draws the explicit 16-byte
                // refusal (:2371-2374) - never silence, the asker uses it to
                // retry another source.
                let answer = lookup(&pkt.payload).and_then(|f| {
                    let root = f.aich_root?;
                    let part_start = u64::from(part) * mule_proto::PARTSIZE;
                    if root != want_root
                        || f.size <= EMBLOCKSIZE
                        || part_start >= f.size
                        || mule_proto::PARTSIZE.min(f.size - part_start) <= EMBLOCKSIZE
                    {
                        return None;
                    }
                    let leaves = aich.as_ref()?.lookup(&root, f.size)?;
                    let mut tree = mule_proto::AichTree::from_leaves(f.size, &leaves)?;
                    let rec = tree.create_part_recovery_data(part_start)?;
                    Some(build_aich_answer(&h, part, &root, &rec))
                });
                fs.write_packet(&answer.unwrap_or_else(|| build_aich_answer_failure(&h)))
                    .await?;
            }
            OP_STARTUPLOADREQ => {
                // Only queue a peer that has named a file we serve (aMule ignores
                // the request unless GetFileByID found one, ClientTCPSocket.cpp:546).
                if file.is_none() {
                    continue;
                }
                // Already holding a slot (e.g. the peer re-asks): re-accept.
                if permit.is_some() {
                    fs.write_packet(&build_accept_upload()).await?;
                    continue;
                }
                match gate {
                    // Ungated (tests / the differential serve path): grant freely.
                    None => fs.write_packet(&build_accept_upload()).await?,
                    Some(g) => {
                        match g.try_grant() {
                            // A slot was free (and nobody queued) - grant it now.
                            Some(guard) => {
                                permit = Some(guard);
                                fs.write_packet(&build_accept_upload()).await?;
                            }
                            // At capacity: queue this peer by its CREDIT SCORE and
                            // send its 1-based rank, then wait for a slot (the best
                            // waiter first), bounded so it cannot tie up forever.
                            None => {
                                let score_key = leecher_score_key(&credit, &sec);
                                let Some(waiter) = g.enqueue(score_key) else {
                                    // Queue full - identity-independent refusal,
                                    // answered with SILENCE like upstream: aMule's
                                    // AddClientToQueue simply returns when
                                    // m_waitinglist is at QueueSize
                                    // (UploadQueue.cpp:508-510), sending no packet.
                                    // (padMule additionally closes here rather than
                                    // holding an unqueued socket open - foreground
                                    // -only, so an idle serve task is not free.)
                                    return Ok(());
                                };
                                let rank = (waiter.rank).min(u16::MAX as usize) as u16;
                                // eMule bans a peer that receives an UNSOLICITED
                                // rank; only ever send it in reply to this ask.
                                fs.write_packet(&build_queue_ranking(rank)).await?;
                                match timeout(QUEUE_WAIT, waiter.granted()).await {
                                    Ok(guard) => {
                                        permit = Some(guard);
                                        fs.write_packet(&build_accept_upload()).await?;
                                    }
                                    // Timed out: the waiter is dropped here, which
                                    // removes it from the queue. Close; peer may
                                    // reconnect.
                                    Err(_) => return Ok(()),
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
                        // Accrue what we gave this peer against its credit record
                        // (raises what it owes us, lowering its future queue score).
                        if let Some((cs, uh)) = &credit {
                            cs.add_uploaded(*uh, data.len() as u64, now_secs());
                        }
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

    /// A REAL file on disk for a `SharedFile` fixture. The serve path now
    /// verifies a shared file still exists at the size we hashed before
    /// claiming we have it, so a fixture path must be real - which also makes
    /// these tests faithful to what a live serve actually sees.
    fn fixture_file(tag: &str, size: usize) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "padmule-serve-{tag}-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&p, vec![0u8; size]).unwrap();
        p
    }
    use crate::multi_source::{download_from_peer, Download};
    use crate::part_store::PartStore;
    use crate::peer::HelloInfo;
    use crate::peer_conn::{accept_peer, connect_peer};
    use crate::transfer_session::{download_file, TransferError};
    use mule_proto::{ed2k_hash, md4, PARTSIZE};
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn queue_grants_the_highest_credit_waiter_first() {
        // The reweight: with one slot held, a LOW-credit peer queues first and a
        // HIGH-credit peer second - the high one must still be granted first.
        let gate = Arc::new(UploadGate::new(1, 32));
        let held = gate.try_grant().unwrap();
        let low = gate.enqueue(1_000).unwrap(); // score 1.0
        let high = gate.enqueue(9_000).unwrap(); // score 9.0
        assert_eq!(gate.waiting(), 2);
        assert_eq!(high.rank, 1, "the higher-credit waiter is ranked ahead");
        assert_eq!(low.rank, 1, "low's rank was 1 when it alone was queued");
        drop(held); // free the only slot; the BEST waiter wins, not the earliest
        let winner = tokio::select! {
            _ = high.granted() => "high",
            _ = low.granted() => "low",
        };
        assert_eq!(winner, "high", "credit outranks arrival order");
    }

    #[test]
    fn a_dropped_waiter_leaves_the_queue() {
        // Leak-proofing: a peer that disconnects (or times out) while queued is
        // removed, so it can never block the peers behind it.
        let gate = Arc::new(UploadGate::new(1, 32));
        let _held = gate.try_grant().unwrap();
        let w = gate.enqueue(5_000).unwrap();
        assert_eq!(gate.waiting(), 1);
        drop(w);
        assert_eq!(gate.waiting(), 0, "a dropped waiter is removed");
    }

    #[test]
    fn the_queue_refuses_only_at_capacity_never_on_score() {
        // never-refuse-on-identity: even a floor-score (1.0) peer is admitted while
        // there is room; the ONLY refusal is a full queue, independent of score.
        let gate = Arc::new(UploadGate::new(1, 2));
        let _held = gate.try_grant().unwrap();
        let _w1 = gate.enqueue(1_000).unwrap(); // floor score, admitted
        let _w2 = gate.enqueue(10_000).unwrap();
        assert!(
            gate.enqueue(10_000).is_none(),
            "a 3rd is refused for CAPACITY, not its score"
        );
        assert_eq!(gate.waiting(), 2);
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("padmule-share-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A shared multi-block file with its AICH hashset staged, plus a client
    /// connection to a serve task running with the given AICH session halves.
    async fn aich_serve_fixture(
        tag: &str,
        peer_aich: u8,
        with_store: bool,
    ) -> (
        Vec<u8>,
        [u8; 16],
        [u8; 20],
        crate::framed::FramedStream<tokio::net::TcpStream>,
        tokio::task::JoinHandle<()>,
        PathBuf,
    ) {
        let dir = tmpdir(tag);
        // 4+ blocks, single eD2k part: recovery-servable (part > EMBLOCKSIZE).
        let data: Vec<u8> = (0..(4 * EMBLOCKSIZE as usize + 123) as u32)
            .map(|i| (i.wrapping_mul(31)) as u8)
            .collect();
        let hash = ed2k_hash(&data);
        let path = dir.join("movie.bin");
        std::fs::write(&path, &data).unwrap();
        let tree = mule_proto::AichTree::from_file_data(&data).unwrap();
        let root = tree.master_hash().unwrap();
        let store = Arc::new(crate::known2_store::Known2Store::load(&dir));
        store.append(&root, &tree.leaves().unwrap()).unwrap();
        let shared = vec![SharedFile {
            hash,
            size: data.len() as u64,
            name: b"movie.bin".to_vec(),
            part_hashes: vec![],
            path,
            rating: 0,
            comment: String::new(),
            aich_root: Some(root),
        }];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let session = ServeSession {
                    peer_aich,
                    aich: with_store.then_some(store),
                    ..Default::default()
                };
                let _ = serve_shared(&mut fs, &shared, None, None, 0, session).await;
            }
        });
        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, fs) = connect_peer(addr, &me).await.unwrap();
        (data, hash, root, fs, up, dir)
    }

    #[tokio::test]
    async fn aich_root_and_recovery_data_are_served() {
        use crate::transfer::{
            build_aich_file_hash_req, build_aich_request, parse_aich_file_hash_ans, AichAnswer,
        };
        let (data, hash, root, mut fs, up, dir) = aich_serve_fixture("aichserve", 1, true).await;

        // 0x9E -> 0x9D with our master root.
        fs.write_packet(&build_aich_file_hash_req(&hash))
            .await
            .unwrap();
        let ans = fs.read_packet_unpacked().await.unwrap();
        assert_eq!(ans.opcode, crate::transfer::OP_AICHFILEHASHANS);
        assert_eq!(
            parse_aich_file_hash_ans(&ans.payload).unwrap(),
            (hash, root)
        );

        // 0x9B part 0 -> 0x9C recovery data that VERIFIES against the root.
        fs.write_packet(&build_aich_request(&hash, 0, &root))
            .await
            .unwrap();
        let ans = fs.read_packet_unpacked().await.unwrap();
        assert_eq!(ans.opcode, crate::transfer::OP_AICHANSWER);
        match crate::transfer::parse_aich_answer(&ans.payload).unwrap() {
            AichAnswer::Recovery {
                hash: h,
                part,
                root: r,
                recovery,
            } => {
                assert_eq!((h, part, r), (hash, 0, root));
                let mut rx = mule_proto::AichTree::with_master(data.len() as u64, root).unwrap();
                assert!(rx.read_recovery_data(0, &recovery), "verifies against root");
                let want = mule_proto::AichTree::from_file_data(&data).unwrap();
                assert_eq!(
                    rx.part_block_hashes(0).unwrap(),
                    want.part_block_hashes(0).unwrap(),
                    "receiver holds the exact block hashes"
                );
            }
            AichAnswer::Failure(_) => panic!("expected recovery data, got the refusal"),
        }
        drop(fs);
        up.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn aich_unservable_requests_draw_the_explicit_refusal() {
        use crate::transfer::{build_aich_request, AichAnswer};
        let (_data, hash, root, mut fs, up, dir) = aich_serve_fixture("aichrefuse", 1, true).await;

        let expect_refusal =
            |ans: mule_proto::Packet, why: &str| match crate::transfer::parse_aich_answer(
                &ans.payload,
            )
            .unwrap()
            {
                AichAnswer::Failure(_) => {}
                _ => panic!("expected the 16-byte refusal: {why}"),
            };
        // Unknown file: eMule still answers (the empty form), never silence.
        fs.write_packet(&build_aich_request(&[0xEE; 16], 0, &root))
            .await
            .unwrap();
        expect_refusal(fs.read_packet_unpacked().await.unwrap(), "unknown hash");
        // Wrong master root.
        let mut bad_root = root;
        bad_root[0] ^= 0xFF;
        fs.write_packet(&build_aich_request(&hash, 0, &bad_root))
            .await
            .unwrap();
        expect_refusal(fs.read_packet_unpacked().await.unwrap(), "wrong root");
        // Part out of range.
        fs.write_packet(&build_aich_request(&hash, 7, &root))
            .await
            .unwrap();
        expect_refusal(
            fs.read_packet_unpacked().await.unwrap(),
            "part 7 of a 1-part file",
        );
        drop(fs);
        up.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn aich_malformed_request_drops_the_connection_and_non_aich_peer_gets_no_root() {
        use crate::transfer::{build_aich_file_hash_req, build_aich_request, AichAnswer};
        // peer_aich = 0: the standalone root ask draws SILENCE (IsSupportingAICH
        // gate), but recovery data is NOT aich-gated in eMule - a valid 0x9B is
        // still answered. Prove the silence by ordering: 0x9E then 0x9B, and the
        // FIRST thing back is the 0x9B answer.
        let (_d, hash, root, mut fs, up, dir) = aich_serve_fixture("aichgate", 0, true).await;
        fs.write_packet(&build_aich_file_hash_req(&hash))
            .await
            .unwrap();
        fs.write_packet(&build_aich_request(&hash, 0, &root))
            .await
            .unwrap();
        let first = fs.read_packet_unpacked().await.unwrap();
        assert_eq!(
            first.opcode,
            crate::transfer::OP_AICHANSWER,
            "0x9E drew silence; the first answer is the 0x9B recovery"
        );
        match crate::transfer::parse_aich_answer(&first.payload).unwrap() {
            AichAnswer::Recovery { .. } => {}
            _ => panic!("valid 0x9B is served regardless of the peer's aich bit"),
        }
        // A malformed (37-byte) 0x9B costs the connection, like eMule's throw.
        let short = mule_proto::Packet::new(
            mule_proto::PROT_EMULE,
            crate::transfer::OP_AICHREQUEST,
            vec![0u8; 37],
        );
        fs.write_packet(&short).await.unwrap();
        assert!(
            fs.read_packet_unpacked().await.is_err(),
            "connection dropped on the malformed request"
        );
        drop(fs);
        up.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn multipacket_bundles_the_aich_root_only_when_asked() {
        use mule_proto::{Packet, Writer, PROT_EMULE};
        // Round 1: multipacket WITH the 0x9E sub-op -> the answer ends with
        // <0x9D><root 20>. Round 2 (fresh connection): WITHOUT it -> no 0x9D.
        for want_aich in [true, false] {
            let tag = if want_aich { "mpaich1" } else { "mpaich0" };
            let (_d, hash, root, mut fs, up, dir) = aich_serve_fixture(tag, 1, true).await;
            let mut w = Writer::new();
            w.write_bytes(&hash);
            w.write_u8(OP_REQUESTFILENAME);
            w.write_u16(0); // ext info: we hold no parts
            w.write_u16(0); // complete sources (our advertised ExtReq v2)
            w.write_u8(OP_SETREQFILEID);
            if want_aich {
                w.write_u8(crate::transfer::OP_AICHFILEHASHREQ);
            }
            fs.write_packet(&Packet::new(PROT_EMULE, OP_MULTIPACKET, w.into_inner()))
                .await
                .unwrap();
            let ans = fs.read_packet_unpacked().await.unwrap();
            assert_eq!(ans.opcode, crate::transfer::OP_MULTIPACKETANSWER);
            let tail_is_root = ans.payload.len() >= 21
                && ans.payload[ans.payload.len() - 21] == crate::transfer::OP_AICHFILEHASHANS
                && ans.payload[ans.payload.len() - 20..] == root[..];
            assert_eq!(
                tail_is_root, want_aich,
                "0x9D sub-answer present iff the request bundled 0x9E (want_aich={want_aich})"
            );
            drop(fs);
            up.await.unwrap();
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    #[tokio::test]
    async fn corrupt_block_is_repaired_over_the_wire_not_redownloaded() {
        // THE WAVE-11 END-TO-END: a padMule downloader holding a part poisoned
        // by one source repairs it against a padMule seeder over the REAL wire
        // loop - root ask (0x9E/0x9D), recovery ask (0x9B/0x9C), verified
        // block fill-back - re-fetching only what is actually bad, and banning
        // the block's feeder. FIFTY 180KB blocks re-gapped, a handful re-sent.
        use crate::multi_source::{download_from_peer_at, Download, PeerSession};
        use crate::part_store::PartStore;
        use crate::peer_conn::connect_peer;
        use mule_proto::{md4, AichTree, PARTSIZE};

        let dir = tmpdir("e2e-repair");
        let size = (PARTSIZE + 20 * EMBLOCKSIZE + 500) as usize;
        let good: Vec<u8> = (0..size as u32)
            .map(|i| (i.wrapping_mul(29)) as u8)
            .collect();
        let hash = ed2k_hash(&good);
        let part_hashes = vec![
            md4(&good[..PARTSIZE as usize]),
            md4(&good[PARTSIZE as usize..]),
        ];

        // The SEEDER: the whole good file + its AICH hashset.
        let seed_path = dir.join("seed.bin");
        std::fs::write(&seed_path, &good).unwrap();
        let tree = AichTree::from_file_data(&good).unwrap();
        let root = tree.master_hash().unwrap();
        let store = Arc::new(crate::known2_store::Known2Store::load(&dir));
        store.append(&root, &tree.leaves().unwrap()).unwrap();
        let shared = vec![SharedFile {
            hash,
            size: size as u64,
            name: b"seed.bin".to_vec(),
            part_hashes: part_hashes.clone(),
            path: seed_path,
            rating: 0,
            comment: String::new(),
            aich_root: Some(root),
        }];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let session = ServeSession {
                    peer_aich: 1,
                    aich: Some(store),
                    ..Default::default()
                };
                let _ = serve_shared(&mut fs, &shared, None, None, 0, session).await;
            }
        });

        // The DOWNLOADER: byte-complete but one block of part 1 poisoned by a
        // "bad" source; MD4 localization re-gaps the whole part and queues it.
        let dldir = dir.join("dl");
        std::fs::create_dir_all(&dldir).unwrap();
        let pstore = PartStore::create(&dldir, 1, hash, size as u64, b"seed.bin").unwrap();
        let dl = Download::new(pstore);
        dl.set_hashset(part_hashes).await;
        let good_src: SocketAddr = "1.2.3.4:4662".parse().unwrap();
        let bad_src: SocketAddr = "5.6.7.8:4662".parse().unwrap();
        let p1 = PARTSIZE as usize;
        let b_start = p1 + 3 * EMBLOCKSIZE as usize;
        let b_end = p1 + 4 * EMBLOCKSIZE as usize;
        dl.commit(0, &good[..p1], Some(good_src)).await.unwrap();
        dl.commit(p1 as u64, &good[p1..b_start], Some(good_src))
            .await
            .unwrap();
        let mut poison = good[b_start..b_end].to_vec();
        poison[99] ^= 0xFF;
        dl.commit(b_start as u64, &poison, Some(bad_src))
            .await
            .unwrap();
        dl.commit(b_end as u64, &good[b_end..], Some(good_src))
            .await
            .unwrap();
        assert!(dl.localize_corruption().await, "part 1 blamed + queued");
        let regapped = dl.missing().await;
        assert_eq!(
            regapped,
            crate::part_file::part_size(1, size as u64),
            "the whole part is open before recovery"
        );
        // The root arrived via the file's ed2k link (VERIFIED).
        dl.set_aich_master_verified(root);

        // One real connection to the seeder does the whole repair.
        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        let session = PeerSession {
            peer_aich: 1,
            ..Default::default()
        };
        let delivered = download_from_peer_at(&mut fs, &dl, true, Some(addr), session)
            .await
            .unwrap();

        assert_eq!(dl.missing().await, 0, "complete again");
        assert!(
            dl.verify_whole_file(size as u64, hash).await,
            "and the bytes are RIGHT"
        );
        assert!(
            delivered < regapped / 2,
            "recovery FILLED most of the part back; only a few blocks were \
             re-sent ({delivered} bytes of a {regapped}-byte part)"
        );
        assert!(
            dl.is_banned(&bad_src),
            "the poisoned block's feeder is banned"
        );
        assert!(!dl.is_banned(&good_src));
        drop(fs);
        up.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
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
            aich_root: None,
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None, None, 0, Default::default()).await;
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
    async fn serving_a_file_accrues_uploaded_bytes_to_the_peers_credit() {
        let dir = tmpdir("accrue");
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
            aich_root: None,
        }];
        let peer_hash = [0xCC; 16];
        let store = Arc::new(CreditStore::empty(true));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let store2 = Arc::clone(&store);
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let credit = Some((store2, peer_hash));
                let _ = serve_shared(
                    &mut fs,
                    &shared,
                    None,
                    None,
                    0,
                    ServeSession {
                        credit,
                        ..Default::default()
                    },
                )
                .await;
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        let got = download_file(&mut fs, &hash, data.len() as u64)
            .await
            .unwrap();
        assert_eq!(got, data);
        drop(fs);
        up.await.unwrap();

        // The bytes we served are accrued against the peer's credit record.
        assert_eq!(store.score(&peer_hash, None, 0, false), 1.0); // no bonus, but tracked
        let bytes = store.save();
        let back = mule_files::read_clients_met(&bytes).unwrap();
        let e = back
            .entries
            .iter()
            .find(|e| e.user_hash == peer_hash)
            .unwrap();
        assert_eq!(e.uploaded, data.len() as u64, "served bytes were accrued");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_high_credit_leecher_is_served_before_a_fresh_one_end_to_end() {
        // The reweight, proven through the FULL serve path (not just the gate): one
        // upload slot, held; a LOW-credit leecher queues FIRST, then a HIGH-credit
        // one queues SECOND. When the slot frees, HIGH must win - which a FIFO queue
        // could never do. This is the client-simulation the reward behavior needs.
        use crate::peer_conn::{accept_peer, connect_peer};
        use crate::transfer::{
            build_request_filename_ext, build_start_upload_req, parse_queue_ranking,
            OP_ACCEPTUPLOADREQ, OP_QUEUERANKING,
        };

        let dir = tmpdir("reweight");
        let data: Vec<u8> = (0..400_000u32)
            .map(|i| (i.wrapping_mul(31)) as u8)
            .collect();
        let hash = ed2k_hash(&data);
        let path = dir.join("m.bin");
        std::fs::write(&path, &data).unwrap();
        let shared = Arc::new(vec![SharedFile {
            hash,
            size: data.len() as u64,
            name: b"m.bin".to_vec(),
            part_hashes: vec![],
            path,
            rating: 0,
            comment: String::new(),
            aich_root: None,
        }]);

        let high_hash = [0x91; 16];
        let low_hash = [0x1a; 16];
        let store = Arc::new(CreditStore::empty(true));
        // HIGH earned a rich history (gave us 30 MiB); LOW is a stranger.
        store.add_downloaded(high_hash, 30 * 1_048_576, now_secs());

        let gate = Arc::new(UploadGate::new(1, 32));
        let held = gate.try_grant().unwrap(); // occupy the only slot

        let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
        let addr = listener.local_addr().unwrap();

        // Serve two accepted connections, each with ITS leecher's credit context
        // (built from the userhash the handshake reveals) - exactly as the engine's
        // accept task does.
        let serve = {
            let (shared, store, gate, listener) = (
                Arc::clone(&shared),
                Arc::clone(&store),
                Arc::clone(&gate),
                Arc::clone(&listener),
            );
            tokio::spawn(async move {
                for _ in 0..2 {
                    let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
                    let Ok((peer, mut fs)) = accept_peer(&listener, &me).await else {
                        return;
                    };
                    let credit = Some((Arc::clone(&store), peer.user_hash));
                    let (shared, gate) = (Arc::clone(&shared), Arc::clone(&gate));
                    tokio::spawn(async move {
                        let _ = serve_shared(
                            &mut fs,
                            &shared,
                            None,
                            Some(&gate),
                            0,
                            ServeSession {
                                credit,
                                ..Default::default()
                            },
                        )
                        .await;
                    });
                }
            })
        };

        // A leecher: connect, name the file, ask to upload -> read its rank.
        async fn queue_up(
            addr: std::net::SocketAddr,
            user_hash: [u8; 16],
            hash: [u8; 16],
        ) -> (crate::framed::FramedStream<tokio::net::TcpStream>, u16) {
            let me = HelloInfo::baseline(user_hash, 0x0A00_0001, 4663, 4673, "leech");
            let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
            fs.write_packet(&build_request_filename_ext(&hash))
                .await
                .unwrap();
            let _ = fs.read_packet_unpacked().await.unwrap(); // filename answer
            fs.write_packet(&build_start_upload_req(&hash))
                .await
                .unwrap();
            let r = fs.read_packet_unpacked().await.unwrap();
            assert_eq!(r.opcode, OP_QUEUERANKING, "slot held -> queued");
            (fs, parse_queue_ranking(&r.payload).unwrap())
        }

        // LOW queues FIRST.
        let (_low_fs, _low_rank) = queue_up(addr, low_hash, hash).await;
        while gate.waiting() < 1 {
            tokio::task::yield_now().await;
        }
        // HIGH queues SECOND but is ranked ahead of the earlier LOW.
        let (mut high_fs, high_rank) = queue_up(addr, high_hash, hash).await;
        assert_eq!(
            high_rank, 1,
            "the high-credit leecher outranks the earlier low one"
        );
        while gate.waiting() < 2 {
            tokio::task::yield_now().await;
        }

        // Free the slot: HIGH wins, though LOW queued first - the reweight in action.
        drop(held);
        let granted = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            high_fs.read_packet_unpacked(),
        )
        .await
        .expect("HIGH must be granted the freed slot")
        .unwrap();
        assert_eq!(
            granted.opcode, OP_ACCEPTUPLOADREQ,
            "the high-credit leecher is served first, not the earlier low-credit one"
        );

        serve.abort();
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
        let sec = ServeSec::new(SecureIdentSession::new(&id), id, Box::new(|_| {}));
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
        let sec = ServeSec::new(SecureIdentSession::new(&id), id, Box::new(|_| {}));
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

    /// A file the user DELETED must never be claimed. Before this, `lookup`
    /// matched purely on the in-memory library, so padMule answered
    /// OP_SETREQFILEID with "COMPLETE" for a file whose bytes were gone, took an
    /// upload slot, and then dropped the connection when the read failed. The
    /// honest answer is the same OP_FILEREQANSNOFIL the authorities send for a
    /// file they do not have.
    #[tokio::test]
    async fn we_never_claim_a_file_whose_bytes_are_gone() {
        use crate::transfer::{OP_FILEREQANSNOFIL, OP_SETREQFILEID};
        use mule_proto::{Packet, PROT_EDONKEY};

        let hash = [0x5B; 16];
        let path = fixture_file("deleted", 100);
        let shared = vec![SharedFile {
            hash,
            size: 100,
            name: b"deleted.bin".to_vec(),
            part_hashes: vec![],
            path: path.clone(),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        }];
        // The user deletes it in the Files app; the library still lists it.
        std::fs::remove_file(&path).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None, None, 0, Default::default()).await;
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        fs.write_packet(&Packet::new(PROT_EDONKEY, OP_SETREQFILEID, hash.to_vec()))
            .await
            .unwrap();

        let ans = fs.read_packet().await.unwrap();
        assert_eq!(
            ans.opcode, OP_FILEREQANSNOFIL,
            "a deleted file must draw file-not-found, never a COMPLETE claim"
        );
        assert_eq!(&ans.payload[..16], &hash);
        drop(fs);
        let _ = up.await;
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
            path: fixture_file("shared", 100),
            rating: 0,
            comment: String::new(),
            aich_root: None,
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
                Box::new(move |_| v2.store(true, Ordering::SeqCst)),
            );
            if let InboundKind::Leecher { first, sec } =
                classify_inbound(&mut server_fs, Some(sec), Duration::from_millis(500)).await
            {
                let _ = serve_shared(
                    &mut server_fs,
                    &shared,
                    Some(first),
                    None,
                    0,
                    ServeSession {
                        sec,
                        ..Default::default()
                    },
                )
                .await;
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
        let sec = ServeSec::new(SecureIdentSession::new(&id), id, Box::new(|_| {}));
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
            path: fixture_file("shared", 100),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None, None, 0, Default::default()).await;
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

    #[test]
    fn repeat_file_requests_are_scored_and_eventually_refused() {
        // eMule 0.50a CUpDownClient::AddRequestCount (UploadClient.cpp:895-918):
        // per (client, FILE), re-asking inside MIN_REQUESTTIME (10 min) bumps a
        // badrequests counter and BADCLIENTBAN=4 bans; a polite gap decrements
        // it instead. Time is injected so the policy is testable without waiting.
        let mut rc = RequestCounter::default();
        let a = [0x11; 16];
        let b = [0x22; 16];

        // First ask for a file is always fine, for any number of DISTINCT files:
        // a peer legitimately asks about several files on one connection.
        assert!(rc.allow(&a, 0));
        assert!(rc.allow(&b, 0));

        // Hammering the SAME file inside the window scores it; the 4th bad
        // request crosses BADCLIENTBAN and is refused.
        assert!(rc.allow(&a, 1));
        assert!(rc.allow(&a, 2));
        assert!(rc.allow(&a, 3));
        assert!(!rc.allow(&a, 4), "BADCLIENTBAN reached -> refuse");

        // The other file is untouched - scoring is per FILE, as upstream.
        assert!(rc.allow(&b, 4));

        // A POLITE re-ask (outside the window) decrements instead of scoring,
        // so a long-lived well-behaved peer recovers rather than creeping to a
        // ban. MIN_REQUESTTIME is 10 minutes.
        let mut polite = RequestCounter::default();
        let t = MIN_REQUESTTIME_SECS;
        assert!(polite.allow(&a, 0));
        assert!(polite.allow(&a, 1)); // bad (score 1)
        assert!(polite.allow(&a, 1 + t)); // polite -> back to 0
        assert!(polite.allow(&a, 1 + 2 * t)); // polite
                                              // Having been forgiven, it can still take the full budget of bad asks.
        assert!(polite.allow(&a, 1 + 2 * t + 1));
        assert!(polite.allow(&a, 1 + 2 * t + 2));
        assert!(polite.allow(&a, 1 + 2 * t + 3));
        assert!(!polite.allow(&a, 1 + 2 * t + 4));
    }

    #[tokio::test]
    async fn we_answer_a_source_request_with_the_peers_we_are_serving() {
        // Source exchange, answer side. aMule answers from the file's UPLOAD
        // list (CreateSrcInfoPacket over m_ClientUploadList) - the peers it is
        // uploading to or holding queued - never a general "every peer we saw"
        // list. So: register a peer as served, then have a DIFFERENT peer ask,
        // and it must be named back (and the asker must never be named to
        // itself). Silence when we know nobody, exactly as upstream.
        use crate::sources::{
            build_request_sources2, parse_answer_sources, OP_ANSWERSOURCES2,
            SOURCE_EXCHANGE_VERSION,
        };
        let hash = [0x6C; 16];
        let shared = vec![SharedFile {
            hash,
            size: 100,
            name: b"sx.bin".to_vec(),
            part_hashes: vec![],
            path: fixture_file("shared", 100),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        }];
        let gate = Arc::new(UploadGate::new(4, 8));

        // A peer we are already serving for this file (HighID, routable).
        let other: SocketAddr = "45.45.0.9:4662".parse().unwrap();
        gate.note_serving(
            hash,
            ServedPeer {
                addr: other,
                user_hash: Some([0xAB; 16]),
                crypt: Some(0x01),
            },
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let g2 = Arc::clone(&gate);
        let asker: SocketAddr = "77.77.0.7:4662".parse().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(
                    &mut fs,
                    &shared,
                    None,
                    Some(&g2),
                    0,
                    ServeSession {
                        peer: Some(asker),
                        ..Default::default()
                    },
                )
                .await;
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();
        fs.write_packet(&build_request_sources2(&hash, SOURCE_EXCHANGE_VERSION))
            .await
            .unwrap();
        let ans = fs.read_packet_unpacked().await.unwrap();
        assert_eq!(ans.opcode, OP_ANSWERSOURCES2);
        let (h, srcs) = parse_answer_sources(&ans.payload, true, SOURCE_EXCHANGE_VERSION).unwrap();
        assert_eq!(h, hash);
        assert_eq!(srcs.len(), 1, "the served peer is named");
        assert_eq!(srcs[0].port, 4662);
        assert_eq!(srcs[0].user_hash, Some([0xAB; 16]));
        assert_eq!(srcs[0].crypt, Some(0x01), "SX v4 carries the crypt byte");

        // The asker is never named to itself, so once IT is the only peer we
        // serve, a request draws silence rather than a self-referential answer.
        gate.stop_serving(&hash, other);
        gate.note_serving(
            hash,
            ServedPeer {
                addr: asker,
                user_hash: None,
                crypt: None,
            },
        );
        assert!(gate.sources_for(&hash, Some(asker)).is_empty());

        drop(fs);
        up.await.unwrap();
    }

    #[tokio::test]
    async fn an_unknown_file_request_is_answered_with_silence_not_fnf() {
        // BOTH authorities stay SILENT on an unknown-hash OP_REQUESTFILENAME:
        // eMule 0.50a ListenSocket.cpp:374-380 (CheckFailedFileIdReqs then
        // break, no packet - it even tracks repeat askers for banning) and aMule
        // ClientTCPSocket.cpp:381-385 (plain break). FNF (OP_FILEREQANSNOFIL) is
        // reserved for OP_SETREQFILEID / the multipackets. Answering it here also
        // asserts "I do not have that file" about a file we may well have.
        use crate::transfer::{
            build_request_filename_ext, OP_FILEREQANSNOFIL, OP_REQFILENAMEANSWER, OP_SETREQFILEID,
        };
        let known = [0x5A; 16];
        let unknown = [0x5B; 16];
        let shared = vec![SharedFile {
            hash: known,
            size: 100,
            name: b"known.bin".to_vec(),
            part_hashes: vec![],
            path: fixture_file("shared", 100),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None, None, 0, Default::default()).await;
            }
        });

        let me = HelloInfo::baseline([0xAA; 16], 0x0A00_0001, 4663, 4673, "dl");
        let (_p, mut fs) = connect_peer(addr, &me).await.unwrap();

        // Ask by NAME for a hash we do not serve -> silence.
        fs.write_packet(&build_request_filename_ext(&unknown))
            .await
            .unwrap();
        // Then ask for a file we DO serve: its answer must be the next packet,
        // proving nothing was emitted for the unknown one.
        fs.write_packet(&build_request_filename_ext(&known))
            .await
            .unwrap();
        let ans = fs.read_packet().await.unwrap();
        assert_eq!(
            ans.opcode, OP_REQFILENAMEANSWER,
            "an unknown OP_REQUESTFILENAME must draw NO packet at all"
        );
        assert_eq!(&ans.payload[..16], &known);

        // OP_SETREQFILEID is the opcode that DOES get FNF (both authorities).
        fs.write_packet(&mule_proto::Packet::new(
            mule_proto::PROT_EMULE,
            OP_SETREQFILEID,
            unknown.to_vec(),
        ))
        .await
        .unwrap();
        let ans = fs.read_packet().await.unwrap();
        assert_eq!(
            ans.opcode, OP_FILEREQANSNOFIL,
            "OP_SETREQFILEID keeps its FNF answer"
        );

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
            path: fixture_file("shared", 100),
            rating: 4,
            comment: "great little file".to_string(),
            aich_root: None,
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                // The peer advertised AcceptCommentVer=1.
                let _ = serve_shared(&mut fs, &shared, None, None, 1, Default::default()).await;
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
            path: fixture_file("shared", 100),
            rating: 4,
            comment: "hidden".to_string(),
            aich_root: None,
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                // The peer did NOT advertise AcceptCommentVer.
                let _ = serve_shared(&mut fs, &shared, None, None, 0, Default::default()).await;
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
                let _ = serve_shared(&mut fs, &[], None, None, 0, Default::default()).await;
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
            aich_root: None,
        }];

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let up = tokio::spawn(async move {
            let me = HelloInfo::baseline([0xBB; 16], 0, 4662, 4672, "seed");
            if let Ok((_p, mut fs)) = accept_peer(&listener, &me).await {
                let _ = serve_shared(&mut fs, &shared, None, None, 0, Default::default()).await;
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
