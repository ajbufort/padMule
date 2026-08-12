//! Live Kad UDP node - the socket driver that turns the Wave 6a/6b/6c codecs
//! into a real conversation with the Kad network (Wave 6 gate). Sends an
//! obfuscated BOOTSTRAP_REQ to known contacts, decodes the BOOTSTRAP_RES, and
//! seeds the routing table; then a HELLO handshake and, later, iterative
//! lookups.
//!
//! IP byte convention (confirmed by live capture, Wave 6b gate): eMule keeps a
//! contact IP in HOST order (MSByte = first octet) and `WriteUInt32`s it
//! little-endian to disk/wire, so our `read_u32` (LE) recovers that host-order
//! value directly - e.g. 5.6.7.250 -> 0x050607FA. The dotted quad is thus
//! the BIG-endian view of `ip` (`Ipv4Addr::from(ip)`), NOT `to_le_bytes` (which
//! yields the reversed 250.7.6.5, a RESERVED address the packet never reaches).
//! (The example used to be an address captured off the live network; this repo
//! is public, so it is now a synthetic one chosen to reverse into reserved
//! space exactly as the captured one did.) A peer's socket IP converts back with `u32::from(Ipv4Addr)`. The
//! same u32 feeds `udp_verify_key`, so the key we issue on send matches the one
//! we recompute on receive (same peer, same convention both directions).

use crate::kad_serve::{answer_request, ServeIdentity};
use crate::stats::KadReqKind;
use mule_files::{IpFilter, KadContact};
use mule_kad::{
    build_bootstrap_req, build_hello_req, build_hello_res_ack, build_kad2_req,
    build_publish_key_req, build_publish_source_req, build_search_key_req_restrictive,
    build_search_source_req, is_acceptable_contact, is_acceptable_contact_ip, kad_deobfuscate,
    kad_keyword_target, kad_obfuscate_request, kad_obfuscate_response, pack_kad,
    parse_bootstrap_res, parse_hello, parse_kad2_res, parse_publish_res, parse_search_res,
    unpack_kad, BootstrapRes, CSearch, FileResult, FloodTracker, FloodVerdict, Hello, KeywordEntry,
    RoutingTable, Source, SourceEntry, WireContact, ALPHA_QUERY, K, KAD_FIND_NODE, MAX_TRACKED_IPS,
    OP_BOOTSTRAP_RES, OP_HELLO_RES, OP_KAD2_RES, OP_PUBLISH_RES, OP_SEARCH_RES,
};
use mule_proto::Kad128;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
/// `kad_live`'s bare `Instant` is tokio's (it drives timeouts); the flood
/// tracker and the out-track list are plain wall-clock bookkeeping, so they use
/// std's. Aliased rather than imported bare so the two can never be confused.
use std::time::Instant as StdInstant;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

use crate::lock::LockRecover;

/// The contact count padMule requests in a KADEMLIA2_REQ (KAD_FIND_NODE = 0x0B).
/// A KADEMLIA2_RES with more than this is a malicious over-long answer and is
/// dropped (eMule caps the response at the requested count, Search.cpp:377).
const KAD_REQUESTED_CONTACTS: usize = 11;
/// The most SOURCES one search may accumulate, however many replies arrive or
/// how much one reply carries. eMule's `SEARCHFINDSOURCE_TOTAL` = 20
/// (Defines.h:68), enforced OUTSIDE the parser at Search.cpp:986
/// (`m_uAnswers > SEARCHFINDSOURCE_TOTAL` -> `PrepareToStop`). padMule
/// enforces the same total at ACCUMULATION, which also stops mid-datagram:
/// `parse_search_res` reads up to 65535 results and the dedupe is a linear
/// scan per result, so an uncapped ingest hands one hostile ~82KB inflated
/// reply O(n^2) work and the whole result set. Stricter than eMule's periodic
/// sweep in the same way the over-long FIND answer drop already is.
const KAD_SEARCH_SOURCE_TOTAL: usize = 20;
/// The keyword twin: eMule's `SEARCHKEYWORD_TOTAL` = 300 (Defines.h:61),
/// enforced by `SearchManager::Process` on its sweep (SearchManager.cpp:347).
/// NOT Search.cpp:819 - that is the STORE path's cap of ten.
const KAD_SEARCH_KEYWORD_TOTAL: usize = 300;
/// How many nodes ONE publish stores to before it stops - eMule's
/// `SEARCHSTOREKEYWORD_TOTAL` / `SEARCHSTOREFILE_TOTAL` = 10 (Defines.h:63-64),
/// enforced the same way the search totals are: as the store target, so a
/// publish walk stops once ten nodes have acknowledged rather than running to
/// the overall deadline. Ten replicas is eMule's whole redundancy for a key.
const KAD_PUBLISH_STORE_TOTAL: usize = 10;
/// How long a liveness probe waits for its `HELLO_RES`. Short on purpose: the
/// sweep runs under the engine lock, and a silent contact is not an error - it
/// just does not get its lease renewed, and a later sweep removes it once its
/// two-minute window lapses.
const KAD_PROBE_WAIT: Duration = Duration::from_millis(1200);

/// A maintenance refresh's overall deadline and spend, in `per_query` units:
/// the lookup ends after `REFRESH_DEADLINE_QUERIES * per_query` and may send at
/// most `REFRESH_DEADLINE_QUERIES * ALPHA_QUERY` FIND_NODEs - the same worst
/// case the old 4-round refresh had, kept as an envelope. Deliberately smaller
/// than a real lookup's [`LOOKUP_DEADLINE_QUERIES`]: this fires on the
/// heartbeat under the engine lock, so its worst case is a user's search
/// waiting behind it. Breadth comes from repeating it against fresh random
/// targets, not from one deep dive. `pub(crate)` so `KAD_MAINTENANCE_BUDGET`
/// can be pinned against the worst case this implies, rather than against a
/// number someone remembered.
pub(crate) const REFRESH_DEADLINE_QUERIES: u32 = 4;

/// A value lookup's overall deadline, in `per_query` units. 16 is the
/// pre-rewrite worst case kept as an envelope: 12 FIND_NODE round windows plus
/// ceil(K/ALPHA_QUERY) = 4 value windows. The event-driven lookup normally
/// finishes far inside it; this is the "overall deadline" leg of its
/// termination (the others: enough results, candidates exhausted).
const LOOKUP_DEADLINE_QUERIES: u32 = 16;

/// A PUBLISH walk's overall deadline, in `per_query` units - the refresh's 4,
/// not a real lookup's 16, and for the same reason: a publish runs on the
/// heartbeat under the engine lock, wrapped in `KAD_PUBLISH_BUDGET` (3s), so
/// its own deadline MUST fit inside that budget (equality is fine, same caveat
/// as the maintenance pin) or the outer cancellation ends every walk instead
/// of the walk terminating itself - the inverted relationship the maintenance
/// path already fixed. With `LOOKUP_DEADLINE_QUERIES` here, 16 x 750ms = 12s
/// structural against a 3s budget meant exactly that. Pinned by
/// `a_kad_publish_walk_fits_inside_its_budget`. Early termination on results
/// is RARE either way: the walk stops at `KAD_PUBLISH_STORE_TOTAL` = 10 acks,
/// which equals `LOOKUP_VALUE_BUDGET` = K = 10, so it must hear back from
/// every value ask it is ever allowed to send - disclosed, not changed,
/// because the store total is eMule's (Defines.h:63-64).
pub(crate) const PUBLISH_DEADLINE_QUERIES: u32 = 4;

/// FIND_NODE spend cap per value lookup - the pre-rewrite structural maximum
/// (12 rounds x ALPHA_QUERY). The rewrite changes WHEN requests go out, not
/// how many a lookup may spend.
const LOOKUP_FIND_BUDGET: usize = 36;

/// Value-request spend cap per lookup - the pre-rewrite maximum (the value
/// phase asked at most the in-tolerance subset of the closest-K frontier).
const LOOKUP_VALUE_BUDGET: usize = K;

/// The stall-recovery cadence and gate, both eMule's: JumpStart runs on a 1s
/// timer (SEARCH_JUMPSTART, Defines.h:48) and returns at once if any response
/// arrived within the last 3 seconds (Search.cpp:281). With per-request
/// deadlines every in-flight request already produces an event, so this tick
/// should never be the thing making progress - it is defense in depth against
/// a lost event, which would otherwise stall the lookup silently until the
/// overall deadline.
const STALL_TICK: Duration = Duration::from_secs(1);
const STALL_AFTER: Duration = Duration::from_secs(3);

/// Bind the Kad UDP socket with SO_REUSEADDR set.
///
/// padMule binds a FIXED Kad port, and `pause()` -> `resume()` closes and rebinds
/// it on every background/foreground cycle - a HARD lifecycle requirement
/// (docs/wiki/lifecycle-and-reactivation.md). aMule had to set this option for
/// precisely that path (LibSocketAsio.cpp:1447-1456, PR #121: "without this Kad
/// and the ed2k client UDP stay broken until the user restarts amule"), and
/// tokio's `UdpSocket::bind` does NOT set it - its `TcpListener::bind` does,
/// which is why only the Kad socket was exposed. A clean drop frees a UDP port
/// anyway (there is no TIME_WAIT); what this covers is iPadOS reclaiming the
/// socket WITHOUT a clean close, which is the state aMule's users hit.
fn bind_kad_socket(addr: SocketAddr) -> Result<UdpSocket, KadError> {
    let sock = socket2::Socket::new(
        socket2::Domain::for_address(addr),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    sock.set_reuse_address(true)?;
    // tokio::net::UdpSocket::from_std requires a non-blocking socket.
    sock.set_nonblocking(true)?;
    sock.bind(&addr.into())?;
    Ok(UdpSocket::from_std(sock.into())?)
}

/// A contact's host-order `ip` u32 to its socket address (big-endian view).
fn contact_addr(ip: u32, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
}

/// A peer's socket IP back to the host-order u32 used for keys/records.
fn ip_u32(addr: &SocketAddr) -> u32 {
    match addr {
        SocketAddr::V4(v4) => (*v4.ip()).into(),
        SocketAddr::V6(_) => 0,
    }
}

/// Errors from a live Kad exchange.
#[derive(Debug)]
pub enum KadError {
    Io(std::io::Error),
    Timeout,
    /// The datagram was plaintext or matched no key.
    NotDecryptable,
    /// The node has no routing contacts yet (bootstrap first).
    NotReady,
    /// A codec/parse error on the decrypted payload.
    Decode(mule_proto::IoError),
    /// A valid Kad frame but not the opcode we awaited.
    Unexpected(u8),
}

impl std::fmt::Display for KadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KadError::Io(e) => write!(f, "io: {e}"),
            KadError::Timeout => write!(f, "timed out"),
            KadError::NotDecryptable => {
                write!(f, "response not decryptable (plaintext or wrong key)")
            }
            KadError::NotReady => write!(f, "no Kad contacts yet (bootstrap first)"),
            KadError::Decode(e) => write!(f, "decode: {e}"),
            KadError::Unexpected(op) => write!(f, "unexpected opcode 0x{op:02x}"),
        }
    }
}

impl From<std::io::Error> for KadError {
    fn from(e: std::io::Error) -> Self {
        KadError::Io(e)
    }
}
impl From<mule_proto::IoError> for KadError {
    fn from(e: mule_proto::IoError) -> Self {
        KadError::Decode(e)
    }
}

/// A live Kad node: a bound UDP socket plus our identity and routing table.
///
/// The socket is OWNED by a read-loop task spawned at bind (see
/// [`run_read_loop`]); every datagram either satisfies a pending outbound
/// request or is answered as an inbound request. The fields the loop must see
/// live behind SHARED handles (`Arc`), because `start_kad` configures the node
/// AFTER binding it - a loop that captured `ip_filter: None` or
/// `advertised_udp_port: None` at bind time would let inbound-learned contacts
/// bypass the user's blocklist and advertise the BOUND port instead of the
/// forwarded one (the "moved the check == removed the check" shape).
pub struct KadNode {
    socket: Arc<UdpSocket>,
    kad_id: Kad128,
    udp_key: u32,
    tcp_port: u16,
    /// The UDP port we actually BOUND.
    udp_port: u16,
    /// The UDP port to ADVERTISE, when it differs from the bound one (0 =
    /// "advertise what we bound"). A VPN forwarder that maps a remote port to a
    /// DIFFERENT local port makes these two genuinely different numbers: we
    /// must bind the local one to receive, but tell peers the remote one or
    /// they dial a port nobody forwards. The eD2k TCP side has had this split
    /// since 8bd. Shared with the read loop, which answers HELLOs with it.
    advertised_udp_port: Arc<AtomicU32>,
    /// The routing table, reached from two directions: the inbound request
    /// handler reads it, lookups write it. A `std` mutex held for one table
    /// operation and NEVER across an await - use [`KadNode::with_routing`].
    ///
    /// POISON-TOLERANT, like every `std` lock on this node
    /// ([`crate::lock::LockRecover`]). `run_read_loop` takes these locks for
    /// EVERY datagram a stranger sends us, so a single panic under one would
    /// otherwise kill Kad for the app's life - and `SlotGuard::drop` takes
    /// `pending`, so a poisoned lock panics DURING an unwind, which aborts the
    /// process. Recovery is safe because all of it is self-healing bookkeeping:
    /// the routing table ages, re-probes and evicts (a torn insert is one
    /// contact, and a contact is only ever a hint we re-verify); a leaked
    /// `pending` slot times out; `flood` and `hello_res_sent` are per-minute
    /// soft counters; `ip_filter` is a single `Arc` swap.
    routing: Arc<Mutex<RoutingTable>>,
    /// The user IP blocklist (ipfilter.dat/.p2p), if loaded. eMule consults it on
    /// every Kad routing insert (RoutingZone.cpp:477); padMule threads the engine's
    /// filter in so a blocklisted range cannot poison the routing table. Shared
    /// with the read loop so inbound-learned contacts face it too.
    ip_filter: Arc<Mutex<Option<Arc<IpFilter>>>>,
    /// Our current public IPv4 (the live equivalent of eMule's
    /// `theApp.GetPublicIP`), learned from the UPnP/SSDP HighID path. A peer's
    /// verify key is `udp_verify_key(peer_secret, THIS)`, so we only echo a stored
    /// key while this still matches what it was minted against. 0 = unknown (echo
    /// no key - byte-identical to the pre-hard-verify wire).
    /// SHARED, not a plain field, for AMENDMENT 2's reason: `start_kad` calls
    /// `set_public_ip` AFTER binding, and the read loop needs it. A verify key
    /// is minted against OUR public ip, so a loop holding a stale 0 would bind
    /// every inbound peer's key to the wrong address and then never echo it.
    current_public_ip: Arc<AtomicU32>,
    /// Outbound requests waiting for their reply, matched by the read loop.
    pending: Arc<Mutex<Vec<PendingSlot>>>,
    /// Slot id source, so `request_batch` can remove exactly its own slots.
    next_seq: AtomicU64,
    /// The owning read loop. Aborted on drop, so `set_kad(None)` still closes
    /// the socket and a resume's rebind never races a stale reader.
    read_loop: tokio::task::JoinHandle<()>,
    /// Session clock origin for contact aging. Deliberately MONOTONIC and
    /// session-local rather than wall time: aging is never persisted (nodes.dat
    /// carries no expiry field, exactly as eMule's does not), so a lease only
    /// has to be comparable within the run that issued it - and a wall clock
    /// that jumps must not mass-expire a healthy table.
    aging: Arc<AgingClock>,
}

impl Drop for KadNode {
    fn drop(&mut self) {
        // The loop holds an `Arc` of the socket; without this the task - and
        // the bound port - would outlive the node, and a resume's fresh loop
        // would race the stale one for datagrams.
        self.read_loop.abort();
    }
}

/// What a matched reply delivers to its waiter: the payload, the
/// receiver-key verdict (eMule bValidReceiverKey), and the sender key the peer
/// wants echoed next time.
type ReplyAnswer = (Vec<u8>, bool, u32);

/// One in-flight outbound request: what it takes to match a reply back to it.
struct PendingSlot {
    seq: u64,
    dest: SocketAddr,
    dest_ip: u32,
    /// Our sender verify key for this destination - the value the peer echoes
    /// as the reply's receiver key (eMule bValidReceiverKey).
    sender_vk: u32,
    /// The opcode this slot awaits. Part of the match, so an interleaved
    /// REQUEST from the same peer falls through to the serve path instead of
    /// being eaten as a non-matching "reply".
    expect: u8,
    tx: tokio::sync::oneshot::Sender<ReplyAnswer>,
}

/// Add a contact to `routing` only if it passes EVERY gate a wire-learned
/// contact faces: routable public ip:port, no legacy DNS-port node, the user's
/// ipfilter, and the anti-sybil per-IP//24 caps. THE ONLY insert path - the
/// node's methods and the read loop both come through here, so an
/// inbound-learned contact cannot bypass what an outbound-learned one faces.
fn gated_add_contact(
    routing: &Mutex<RoutingTable>,
    ip_filter: &Mutex<Option<Arc<IpFilter>>>,
    c: &WireContact,
    verified: bool,
    // `proven_alive`: this contact just PROVED itself alive - it answered
    // something we sent, or sent us a HELLO_REQ. eMule promotes exactly here and
    // nowhere else: `Add(..., bUpdate = true, ...)` reaches `SetAlive` on the
    // found-contact branch (RoutingZone.cpp:588), and the only callers passing
    // true are the inbound HELLO_REQ (KademliaUDPListener.cpp:591), a HELLO_RES
    // to a request of ours (:672), and the BOOTSTRAP_RES responder (:567). A
    // FIND answer promotes NOTHING - its contacts are added `bUpdate = false`
    // (:846) and its responder is not added at all - so hearsay cannot renew a
    // lease. `now` is the aging clock (see `KadNode::aging_now`).
    proven_alive: bool,
    now: u64,
) {
    if !is_acceptable_contact(c.ip, c.udp_port, /*allow_private=*/ false) {
        return;
    }
    // Drop a DNS-port contact from a LEGACY node (anti-reflection: a nodes.dat
    // naming `victim:53` would spray Kad requests at a DNS server). eMule gates
    // this on version <= KADEMLIA_VERSION5_48a (0x05), keeping modern nodes, so
    // match that exactly rather than a blanket reject (which is stricter than
    // eMule - it would drop a node eMule keeps).
    if c.udp_port == 53 && c.version <= 5 {
        return;
    }
    // The user blocklist gates Kad inserts exactly as it gates eD2k sources
    // (eMule RoutingZone.cpp:477): a range the user chose to block never enters
    // the routing table. Fail-open when no filter is loaded. Clone the Arc out
    // so the filter guard is not held while the routing lock is taken.
    let filter = ip_filter.lock_recover().clone();
    if let Some(f) = filter {
        if f.is_blocked_u32(c.ip) {
            return;
        }
    }
    // Anti-sybil (live-layer): cap how many contacts share one IP / /24, so a
    // hostile node cannot flood our routing table with fake IDs behind one
    // address. Skip the cap ONLY for a genuine refresh (same id, SAME ip); a
    // known id arriving at a DIFFERENT ip is a hijack attempt (KadIDs are
    // semi-public) and faces the cap on the new ip like a new contact (Zone::add
    // also clears its verified bit on the ip change). Interop-safe: the real Kad
    // network is IP-diverse, so a legitimate peer is never dropped. One lock
    // across check-and-add, so the cap cannot be raced past.
    let mut t = routing.lock_recover();
    let refresh = t.ip_of(&c.id) == Some(c.ip);
    if c.ip != 0 && !refresh {
        let (same_ip, same_subnet) = t.ip_counts(c.ip);
        if same_ip >= mule_kad::MAX_CONTACTS_PER_IP
            || same_subnet >= mule_kad::MAX_CONTACTS_PER_SUBNET
        {
            return;
        }
    }
    let known = t.contains(&c.id);
    t.add(c.id, c.ip, c.udp_port, c.tcp_port, c.version, verified);
    // Only an EXISTING contact is promoted, matching eMule: its new-contact
    // branch inserts at type 3 (`InitContact`) with no `SetAlive`, even from a
    // HELLO. A first sighting is not yet a proof of liveness we can pass on.
    if proven_alive && known {
        t.set_alive(&c.id, now);
    }
}

/// The closest VERIFIED contacts to `target` as wire contacts, cloned out of
/// the lock so no caller holds it while doing I/O.
fn closest_wire_contacts_serving_in(
    routing: &Mutex<RoutingTable>,
    target: &Kad128,
    count: usize,
) -> Vec<WireContact> {
    let g = routing.lock_recover();
    g.closest_to_serving(target, count)
        .into_iter()
        .map(|c| WireContact {
            id: c.id,
            ip: c.ip,
            udp_port: c.udp_port,
            tcp_port: c.tcp_port,
            version: c.version,
        })
        .collect()
}

fn closest_wire_contacts_in(
    routing: &Mutex<RoutingTable>,
    target: &Kad128,
    want: usize,
) -> Vec<WireContact> {
    routing
        .lock_recover()
        .closest_to(target, want)
        .into_iter()
        .map(|c| WireContact {
            id: c.id,
            ip: c.ip,
            udp_port: c.udp_port,
            tcp_port: c.tcp_port,
            version: c.version,
        })
        .collect()
}

/// A private LAN address in eMule's `IsLANIP` sense: acceptable only when
/// private ranges are allowed (10/8, 172.16/12, 192.168/16). Loopback and
/// other unroutables are NOT "LAN" - they fail both ways.
fn is_lan_ip(ip: u32) -> bool {
    is_acceptable_contact_ip(ip, /*allow_private=*/ true)
        && !is_acceptable_contact_ip(ip, /*allow_private=*/ false)
}

/// Per-ANSWER rules for the SEARCH FRONTIER, from eMule ProcessResponse
/// (Search.cpp:423-473): a node may not answer with itself, may list each IP
/// only once, and may name AT MOST 2 CONTACTS PER PUBLIC /24. The responder's
/// own IP and subnet are pre-seeded (Search.cpp:423-424), so its /24 admits
/// only one more contact.
///
/// NOTE eMule's comment at :457 says "/28 subnet" but the mask is 0xFFFFFF00,
/// which is a /24 - the code is right, the comment is wrong; we follow the
/// code. LAN addresses are exempt from the subnet cap (:458), not from the
/// unique-IP rule; eMule's exempt branch also accidentally RESETS the subnet
/// count, which we skip - a public and a private address can never share a
/// /24, so the difference is unobservable.
///
/// THE FRONTIER ONLY. The routing table takes the same answer through its own
/// gates instead (`gated_add_contact`), because that is eMule's structure too:
/// Process_KADEMLIA2_RES (KademliaUDPListener.cpp:846) hands every basically-
/// acceptable contact to RoutingZone::AddUnfiltered, and only the list passed
/// on to CSearch faces these per-answer rules. Applying them to the table
/// would starve it - see `KadNode::absorb_find_answer`, which keeps the two
/// paths apart.
fn frontier_filter(responder_ip: u32, mut contacts: Vec<WireContact>) -> Vec<WireContact> {
    let mut seen_ips = std::collections::HashSet::new();
    seen_ips.insert(responder_ip);
    let mut subnets: HashMap<u32, u32> = HashMap::new();
    subnets.insert(responder_ip & 0xFFFF_FF00, 1);
    contacts.retain(|c| {
        if !seen_ips.insert(c.ip) {
            return false;
        }
        if !is_lan_ip(c.ip) {
            let n = subnets.entry(c.ip & 0xFFFF_FF00).or_insert(0);
            if *n >= 2 {
                return false;
            }
            *n += 1;
        }
        true
    });
    contacts
}

/// Withdraws whatever pending slots a lookup still owns when it is dropped.
///
/// The lookup's callers CANCEL it - `KAD_SEARCH_WAIT` wraps `resolve_keyword`,
/// `KAD_MAINTENANCE_BUDGET` wraps `refresh_routing` - and a cancelled future
/// never reaches its own cleanup line. A stale slot is not a leak but a
/// misdirection: the read loop would feed the NEXT request's reply from that
/// peer to a receiver nobody holds. Slots answered or withdrawn earlier are
/// simply absent by the time this runs; removing them again is a no-op.
struct SlotGuard {
    pending: Arc<Mutex<Vec<PendingSlot>>>,
    seqs: Vec<u64>,
}

impl SlotGuard {
    fn new(pending: Arc<Mutex<Vec<PendingSlot>>>) -> Self {
        SlotGuard {
            pending,
            seqs: Vec::new(),
        }
    }
    fn track(&mut self, seq: u64) {
        self.seqs.push(seq);
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        self.pending
            .lock_recover()
            .retain(|p| !self.seqs.contains(&p.seq));
    }
}

/// Which lookup request an in-flight future belongs to.
#[derive(Clone, Copy, PartialEq)]
enum ReqKind {
    Find,
    Value,
}

impl ReqKind {
    fn stats(self) -> KadReqKind {
        match self {
            ReqKind::Find => KadReqKind::FindNode,
            ReqKind::Value => KadReqKind::Value,
        }
    }
}

/// One resolved in-flight lookup request: who it went to, how long it took,
/// and the reply if one came inside the per-request deadline.
struct ReqEvent {
    kind: ReqKind,
    contact: WireContact,
    seq: u64,
    rtt: Duration,
    outcome: Option<ReplyAnswer>,
}

/// What kind of value a lookup harvests, if any.
enum ValueAsk<'a> {
    /// Pure node lookup (routing refresh): resolved candidates are consumed
    /// without a value request.
    None,
    /// KADEMLIA2_SEARCH_SOURCE_REQ for the target file hash.
    Sources { file_size: u64 },
    /// KADEMLIA2_SEARCH_KEY_REQ: `words` ride along as the remote filter tree,
    /// `keyword` filters each result locally (eMule Search.cpp:1379-1395).
    Keyword {
        keyword: &'a str,
        words: &'a [String],
    },
    /// STORE the keyword->file index at the closest nodes
    /// (KADEMLIA2_PUBLISH_KEY_REQ). Same iterative FIND_NODE walk, but each
    /// closest responded in-tolerance node gets a STORE, not a SEARCH, and we
    /// count PUBLISH_RES rather than accumulating results - eMule's STOREKEYWORD
    /// flavor of `CSearch` (Search.cpp:815).
    PublishKeyword { entries: &'a [KeywordEntry] },
    /// STORE our source record for a file (KADEMLIA2_PUBLISH_SOURCE_REQ) -
    /// eMule's STOREFILE flavor, its name for storing OURSELVES as a source
    /// of a file ("Try to store yourself as a source", Search.cpp:705).
    PublishSource {
        our_hash: Kad128,
        entry: SourceEntry,
    },
}

impl ValueAsk<'_> {
    /// True for the two STORE flavors - which count PUBLISH_RES instead of
    /// accumulating SEARCH results, and whose reply opcode is OP_PUBLISH_RES.
    fn is_publish(&self) -> bool {
        matches!(
            self,
            ValueAsk::PublishKeyword { .. } | ValueAsk::PublishSource { .. }
        )
    }
}

/// The contact-aging clock, shared by the node and its read loop so a promotion
/// from an inbound HELLO and one from a probe answer are stamped on the SAME
/// timeline. Session-MONOTONIC on purpose: aging is never persisted (neither
/// client's nodes.dat has an expiry field), so a lease only has to be comparable
/// within the run that issued it, and a wall-clock jump must not mass-expire a
/// healthy table.
pub(crate) struct AgingClock {
    origin: Instant,
    /// Test-only forward offset; always 0 in production.
    offset: AtomicU64,
}

impl AgingClock {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
            offset: AtomicU64::new(0),
        }
    }

    pub(crate) fn now(&self) -> u64 {
        self.origin.elapsed().as_secs() + self.offset.load(Ordering::Relaxed)
    }
}

/// What the owning read loop needs. Copies of the immutable identity, and the
/// SAME `Arc` handles the node's setters write through - never captured VALUES,
/// which is the whole point of AMENDMENT 2: `start_kad` configures the node
/// after binding it, so a value captured at spawn would freeze `ip_filter` at
/// `None` and the advertised port at "bound".
struct ReadLoop {
    socket: Arc<UdpSocket>,
    kad_id: Kad128,
    udp_key: u32,
    tcp_port: u16,
    /// The BOUND port - the fallback when nothing is advertised.
    udp_port: u16,
    advertised_udp_port: Arc<AtomicU32>,
    routing: Arc<Mutex<RoutingTable>>,
    ip_filter: Arc<Mutex<Option<Arc<IpFilter>>>>,
    pending: Arc<Mutex<Vec<PendingSlot>>>,
    /// One flood tracker PER SERVED REQUEST OPCODE, keyed inside by source IP.
    /// `FloodTracker` was written for this and had no call site until now.
    flood: Arc<Mutex<HashMap<u8, FloodTracker>>>,
    /// IPs we have sent a HELLO_RES to, and when - eMule's out-track list, the
    /// gate that makes an inbound HELLO_RES_ACK *solicited*. See
    /// [`ACK_SOLICITED_WINDOW`].
    hello_res_sent: Arc<Mutex<HashMap<u32, StdInstant>>>,
    current_public_ip: Arc<AtomicU32>,
    aging: Arc<AgingClock>,
}

/// How long a sent HELLO_RES makes an ACK from that IP acceptable.
///
/// eMule's `IsOnOutTrackList` (PacketTracking.cpp:84-97) matches entries newer
/// than 180 s and REMOVES the entry on a match, so one HELLO_RES buys exactly
/// one ACK. Both properties matter: the window bounds how long a spoofer has,
/// and the consumption stops one solicitation being replayed.
const ACK_SOLICITED_WINDOW: Duration = Duration::from_secs(180);

// Cap on tracked IPs, for the out-track list here and each flood tracker
// alike: ONE definition, `mule_kad::MAX_TRACKED_IPS` (hardening.rs), imported
// above - this file used to mirror the number with a "same value as" comment
// on each side, which is the drift the one-definition rule exists to prevent.
// The reasoning lives with the definition. Worth restating here: the map is
// keyed by an ATTACKER-CONTROLLED value (a UDP source address, trivially
// spoofed), so it prunes on insert and then refuses to grow - deliberately
// fail-open for a NEW ip, because dropping every unknown source under a spray
// would be a self-inflicted outage, and the entries already held keep
// protecting against the floods that actually cost us.

/// The inbound request budget for one IP, per minute, per opcode - eMule's
/// exact numbers from `InTrackListIsAllowedPacket` (PacketTracking.cpp:110-149):
/// BOOTSTRAP_REQ 2, HELLO_REQ 3, KADEMLIA2_REQ 10, PING 2. Over the budget the
/// request is IGNORED; over five times it the IP is BANNED, which is that
/// function's own two-tier shape (:197-204).
///
/// `None` means "not a request we serve" - no tracking, because we drop it
/// anyway. eMule returns true for anything outside its switch, and notably
/// KADEMLIA2_HELLO_RES_ACK is NOT in it: an ACK is a peer's reaction to our own
/// answer, and rate-limiting it would throttle a handshake WE asked for.
fn flood_budget(op: u8) -> Option<u32> {
    match op {
        mule_kad::OP_BOOTSTRAP_REQ => Some(2),
        mule_kad::OP_HELLO_REQ => Some(3),
        mule_kad::OP_KAD2_REQ => Some(10),
        mule_kad::OP_PING => Some(2),
        _ => None,
    }
}

/// Apply the per-opcode flood budget to one inbound request. `true` = serve it.
fn flood_allows(
    flood: &Mutex<HashMap<u8, FloodTracker>>,
    op: u8,
    from_ip: u32,
    now: StdInstant,
) -> bool {
    let Some(budget) = flood_budget(op) else {
        return true; // not a served request; the caller drops it regardless
    };
    let mut map = flood.lock_recover();
    let tracker = map.entry(op).or_insert_with(|| {
        FloodTracker::new(
            Duration::from_secs(60),
            budget,
            // eMule bans at 5x the per-minute allowance.
            budget * 5,
            // CLIENTBANTIME, opcodes.h:122 - HR2MS(2).
            Duration::from_secs(2 * 60 * 60),
        )
    });
    matches!(tracker.record(from_ip, now), FloodVerdict::Allow)
}

/// Note that we answered `ip` with a HELLO_RES, so its ACK is solicited.
/// Prunes expired entries first, then refuses to grow past [`MAX_TRACKED_IPS`].
fn note_hello_res_sent(sent: &Mutex<HashMap<u32, StdInstant>>, ip: u32, now: StdInstant) {
    let mut m = sent.lock_recover();
    m.retain(|_, t| now.duration_since(*t) < ACK_SOLICITED_WINDOW);
    if m.len() < MAX_TRACKED_IPS || m.contains_key(&ip) {
        m.insert(ip, now);
    }
}

/// Did we send `ip` a HELLO_RES within the window? CONSUMES the entry on a
/// match, so one solicitation admits exactly one ACK (eMule removes it too).
fn take_hello_res_sent(sent: &Mutex<HashMap<u32, StdInstant>>, ip: u32, now: StdInstant) -> bool {
    let mut m = sent.lock_recover();
    match m.remove(&ip) {
        Some(t) => now.duration_since(t) < ACK_SOLICITED_WINDOW,
        None => false,
    }
}

/// The single reader of the Kad socket, for the node's life.
///
/// Before this loop existed the socket was read ONLY inside `request_batch`,
/// while awaiting our own replies - so an inbound HELLO, PING or FIND_NODE was
/// dropped on the floor, padMule answered nothing, and it aged out of every
/// routing table that learned it (eMule's OnSmallTimer pings the oldest contact
/// per bin and evicts what stays silent). Each datagram now goes one of three
/// ways: deliver to the pending outbound request it answers, answer it as an
/// inbound request via `kad_serve`, or drop it.
async fn run_read_loop(ctx: ReadLoop) {
    let mut buf = vec![0u8; 8192];
    loop {
        // A UDP socket can surface an ICMP port-unreachable as a recv error
        // (Linux ECONNREFUSED), which is routine when a peer is gone. Each call
        // consumes one queued error, so continuing cannot spin unboundedly.
        let Ok((n, from)) = ctx.socket.recv_from(&mut buf).await else {
            continue;
        };
        let from_ip = ip_u32(&from);
        let Some(dec) = kad_deobfuscate(&buf[..n], &ctx.kad_id, ctx.udp_key, from_ip) else {
            continue; // plaintext or wrong key
        };
        let Ok((op, payload)) = unpack_kad(&dec.payload) else {
            continue;
        };

        // (a) A pending outbound request waiting on this datagram? The demux
        // rules are `request_batch`'s, preserved verbatim: the EXACT address
        // first, so two contacts on one IP (MAX_CONTACTS_PER_IP permits them)
        // cannot swap answers; then the first slot waiting on the same IP,
        // because a reply may arrive from a different source port than was
        // dialled. The opcode is part of the match, so an interleaved REQUEST
        // from a peer we are awaiting falls through to the serve path below.
        let slot = {
            let mut pending = ctx.pending.lock_recover();
            pending
                .iter()
                .position(|p| p.dest == from && p.expect == op)
                .or_else(|| {
                    pending
                        .iter()
                        .position(|p| p.dest_ip == from_ip && p.expect == op)
                })
                // Vec::remove, not swap_remove: "first slot waiting on that IP"
                // is an ORDER-dependent rule, and reordering the survivors
                // would quietly change who is first for the next datagram.
                .map(|i| pending.remove(i))
        };
        if let Some(slot) = slot {
            // bValidReceiverKey = the reply echoed the verify key we issued for
            // this destination (eMule ClientUDPSocket.cpp:127). A send to a
            // receiver that already timed out is the datagram arriving after
            // the deadline - dropped, exactly as before the loop existed.
            let _ = slot
                .tx
                .send((payload, dec.receiver_vk == slot.sender_vk, dec.sender_vk));
            continue;
        }

        // (b) An inbound request. `valid_receiver_key` is the same verdict as
        // above, computed for the SENDER: it echoed the key we issue for its
        // address, proving it receives there.
        let valid_receiver_key = dec.receiver_vk == mule_kad::udp_verify_key(ctx.udp_key, from_ip);
        let now = StdInstant::now();

        // An inbound HELLO_RES_ACK completes the three-way handshake OUR
        // HELLO_RES asked for, so it is handled BEFORE the flood gate and never
        // subject to it: eMule leaves it out of `InTrackListIsAllowedPacket`'s
        // switch for the same reason - throttling it would throttle a handshake
        // we solicited. It is a response, so it produces no answer.
        if op == mule_kad::OP_HELLO_RES_ACK {
            let solicited = take_hello_res_sent(&ctx.hello_res_sent, from_ip, now);
            match crate::kad_serve::accept_hello_res_ack(&payload, solicited, valid_receiver_key) {
                crate::kad_serve::AckVerdict::MarkSenderVerified { sender_id } => {
                    // The other half of eMule's VerifyContact: the bit is set
                    // only if the address we STORED for that id matches the one
                    // this datagram came from (RoutingZone.cpp:985-986).
                    ctx.routing
                        .lock_recover()
                        .verify_contact(&sender_id, from_ip);
                }
                crate::kad_serve::AckVerdict::Drop => {}
            }
            continue;
        }

        // THE FLOOD GATE, placed where eMule places it: before dispatch, so a
        // flooded request is not merely unanswered but never processed - it does
        // not get to add a contact or cost us a table walk either.
        if !flood_allows(&ctx.flood, op, from_ip, now) {
            continue;
        }
        // THE USER'S BLOCKLIST DECIDES WHO WE TALK TO, not just who we remember.
        //
        // A DELIBERATE, DOCUMENTED DIVERGENCE from eMule, and the only one on
        // this path. eMule's `ProcessPacket` (KademliaUDPListener.cpp:236-256)
        // gates an inbound datagram on exactly two things before dispatch - the
        // port-53 unencrypted guard and `InTrackListIsAllowedPacket` - and
        // consults the ipfilter only when INSERTING contacts (`:835`). So a
        // stock eMule will answer an address its user blocklisted.
        //
        // padMule does not, because a blocklist is an explicit instruction
        // ("do not talk to these people") and answering is talking: our reply
        // confirms we exist, at our address, running Kad. It is interop-safe by
        // construction - the only peers it can cut off are ones the user chose
        // to cut off - and fail-open when no filter is loaded, so it changes
        // nothing for a user who never set one.
        //
        // NOT DONE, and checked rather than assumed: the design spec also said
        // "never answer a request whose source is unroutable or private". The
        // source does not support it - see above - and it would break both the
        // loopback mock-peer shape the spec's own Testing section prescribes
        // and the namespaced amuled oracle. Left faithful on purpose.
        if ctx
            .ip_filter
            .lock_recover()
            .as_ref()
            .is_some_and(|f| f.is_blocked_u32(from_ip))
        {
            continue;
        }
        // An inbound HELLO carries enough to be RECORDED (the other served
        // requests name no sender id). Through the gated path only: an inbound
        // requester faces the ipfilter, the port-53 guard and the anti-sybil
        // caps exactly like a wire-learned contact - eMule's
        // Process2HelloRequest does the same via AddContact2.
        if op == mule_kad::OP_HELLO_REQ {
            if let Ok(h) = parse_hello(&payload) {
                // PROVEN: a HELLO_REQ arriving from this address is eMule's
                // canonical liveness signal (bUpdate = true, :591).
                gated_add_contact(
                    &ctx.routing,
                    &ctx.ip_filter,
                    &WireContact {
                        id: h.id,
                        ip: from_ip,
                        // The address we can actually reach it at, not a
                        // claimed one (eMule uses the datagram source too).
                        udp_port: from.port(),
                        tcp_port: h.tcp_port,
                        version: h.version,
                    },
                    valid_receiver_key,
                    /*proven_alive=*/ true,
                    ctx.aging.now(),
                );
                // STORE THE KEY IT HANDED US, exactly as `note_responder` does
                // for a node that answered US. eMule's `AddContact2` takes the
                // senderUDPKey on this path too.
                //
                // Without it the verification is one-directional: the peer can
                // prove its IP to us, but our next request to it echoes NO key,
                // so it cannot prove OURS and we stay unverified in its table -
                // which is the state that gets us evicted. An inbound HELLO is
                // often the FIRST contact, so this is the earliest moment the
                // key is available.
                let our_ip = ctx.current_public_ip.load(Ordering::Relaxed);
                ctx.routing
                    .lock_recover()
                    .note_verify_key(&h.id, from_ip, dec.sender_vk, our_ip);
            }
        }
        // Read at ANSWER time through the shared handle, never captured at
        // spawn: `start_kad` sets this after binding (AMENDMENT 2).
        let advertised = match ctx.advertised_udp_port.load(Ordering::Relaxed) {
            0 => ctx.udp_port,
            p => p as u16,
        };
        let me = ServeIdentity {
            kad_id: ctx.kad_id,
            tcp_port: ctx.tcp_port,
            advertised_udp_port: advertised,
        };
        let Some(answer) = answer_request(
            op,
            &payload,
            from.port(),
            &me,
            valid_receiver_key,
            |t, want| closest_wire_contacts_serving_in(&ctx.routing, t, want),
            |t, want| closest_wire_contacts_in(&ctx.routing, t, want),
        ) else {
            continue; // (c) not served - most of the protocol, deliberately
        };
        // Keyed and addressed the way every faithful responder in this file's
        // tests already answers: RC4 on the key the sender asked us to echo
        // (dec.sender_vk), our own verify key for its address riding along so
        // it can verify US on its next packet.
        // Note the solicitation BEFORE the send, not after: the peer's ACK can
        // be on the wire before our own `send_to` future resolves, and an ACK
        // that beats its own bookkeeping would be dropped as unsolicited.
        if answer.request_ack {
            note_hello_res_sent(&ctx.hello_res_sent, from_ip, now);
        }
        let datagram = kad_obfuscate_response(
            &pack_kad(answer.opcode, answer.payload),
            rand::random(),
            dec.sender_vk,
            mule_kad::udp_verify_key(ctx.udp_key, from_ip),
            rand::random(),
        );
        let _ = ctx.socket.send_to(&datagram, from).await;
    }
}

impl KadNode {
    /// Bind a Kad node on `bind_addr` (e.g. `0.0.0.0:4672`) with a fresh random
    /// identity. `tcp_port` is advertised in HELLO. For one-shot CLI use; a
    /// long-lived client should pass its persisted identity via
    /// [`KadNode::bind_with_identity`] (eMule persists both values - a stable
    /// ID keeps routing-table reciprocity, and a stable install key keeps the
    /// UDP verify keys peers stored for us valid across restarts).
    pub async fn bind(bind_addr: SocketAddr, tcp_port: u16) -> Result<Self, KadError> {
        let kad_id = Kad128::from_words([
            rand::random(),
            rand::random(),
            rand::random(),
            rand::random(),
        ]);
        Self::bind_with_identity(bind_addr, tcp_port, kad_id, rand::random()).await
    }

    /// Bind a Kad node using a persisted identity (`NodeIdentity::kad_id` /
    /// `kad_udp_key`).
    pub async fn bind_with_identity(
        bind_addr: SocketAddr,
        tcp_port: u16,
        kad_id: Kad128,
        udp_key: u32,
    ) -> Result<Self, KadError> {
        let socket = Arc::new(bind_kad_socket(bind_addr)?);
        let udp_port = socket.local_addr()?.port();
        let advertised_udp_port = Arc::new(AtomicU32::new(0));
        let routing = Arc::new(Mutex::new(RoutingTable::new(kad_id)));
        let ip_filter: Arc<Mutex<Option<Arc<IpFilter>>>> = Arc::new(Mutex::new(None));
        let pending: Arc<Mutex<Vec<PendingSlot>>> = Arc::new(Mutex::new(Vec::new()));
        // The owning read loop, for the node's whole life. It shares the
        // HANDLES above rather than capturing values, so configuration applied
        // after this point (`set_ip_filter`, `set_advertised_udp_port`) is
        // visible to it - see AMENDMENT 2 in the kad-serve-loop plan.
        let current_public_ip = Arc::new(AtomicU32::new(0));
        let flood = Arc::new(Mutex::new(HashMap::new()));
        let hello_res_sent = Arc::new(Mutex::new(HashMap::new()));
        let aging = Arc::new(AgingClock::new());
        let read_loop = tokio::spawn(run_read_loop(ReadLoop {
            aging: Arc::clone(&aging),
            flood: Arc::clone(&flood),
            current_public_ip: Arc::clone(&current_public_ip),
            hello_res_sent: Arc::clone(&hello_res_sent),
            socket: Arc::clone(&socket),
            kad_id,
            udp_key,
            tcp_port,
            udp_port,
            advertised_udp_port: Arc::clone(&advertised_udp_port),
            routing: Arc::clone(&routing),
            ip_filter: Arc::clone(&ip_filter),
            pending: Arc::clone(&pending),
        }));
        Ok(KadNode {
            socket,
            kad_id,
            udp_key,
            tcp_port,
            udp_port,
            advertised_udp_port,
            routing,
            ip_filter,
            current_public_ip,
            pending,
            next_seq: AtomicU64::new(0),
            read_loop,
            aging,
        })
    }

    /// Advertise a UDP port different from the one we bound (a VPN remote->local
    /// remap). `None` restores "advertise what we bound".
    /// Takes `&self`: all three of these setters now write through the SHARED
    /// handles the read loop reads (AMENDMENT 2), so none of them needs
    /// exclusive access - and that is the property that makes it safe to call
    /// them AFTER the loop is already running, which `start_kad` does.
    pub fn set_advertised_udp_port(&self, port: Option<u16>) {
        let p = port.filter(|&p| p != 0).map_or(0, u32::from);
        self.advertised_udp_port.store(p, Ordering::Relaxed);
    }

    /// The UDP port peers should dial us on.
    fn advertised_udp(&self) -> u16 {
        match self.advertised_udp_port.load(Ordering::Relaxed) {
            0 => self.udp_port,
            p => p as u16,
        }
    }

    /// Set our current public IPv4 (from the UPnP/SSDP HighID path), against which
    /// stored verify keys are minted + gated. Changing it invalidates the echo of
    /// keys minted for the old IP (they simply stop matching in `verify_key_for`).
    pub fn set_public_ip(&self, ip: u32) {
        self.current_public_ip.store(ip, Ordering::Relaxed);
    }

    /// Install the user IP blocklist so blocklisted ranges are dropped from every
    /// routing insert (matching eMule). `None` = no filter (fail-open).
    pub fn set_ip_filter(&self, filter: Option<std::sync::Arc<IpFilter>>) {
        *self.ip_filter.lock_recover() = filter;
    }

    pub fn kad_id(&self) -> Kad128 {
        self.kad_id
    }

    /// The address the Kad socket is bound to. Test-only for now: the loop's
    /// tests aim datagrams at it; no production caller exists yet (the engine
    /// binds a KNOWN port). Lift the cfg when one appears.
    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.socket
            .local_addr()
            .expect("a bound socket has a local address")
    }

    /// A NON-owning view of the socket, so a test can watch it actually die.
    ///
    /// Exists because `Drop::abort` is otherwise unobservable: the node is gone
    /// by the time you would ask, and the property that matters - "the read
    /// loop released the socket" - is about a task we no longer hold a handle
    /// to. A `Weak` outlives both and answers exactly that question.
    #[cfg(test)]
    pub(crate) fn socket_weak(&self) -> std::sync::Weak<UdpSocket> {
        Arc::downgrade(&self.socket)
    }

    /// Run `f` against the routing table.
    ///
    /// A `std` mutex held for the length of one table operation and NEVER
    /// across an await - the same discipline `Engine::public_ip` and
    /// `harvested_servers` already follow. The table is reached from two
    /// directions (the inbound handler reads it, lookups write it), which is
    /// why it needs a lock at all.
    /// Seconds since this node bound its socket - the clock contact aging runs
    /// on. See [`KadNode::aging_clock`].
    fn aging_now(&self) -> u64 {
        self.aging.now()
    }

    /// Push the aging clock FORWARD, for tests only. The sweep's arms are gated
    /// on eMule's real intervals (a 10s `CheckingType` floor, a 120s probe
    /// window), so without this no test could reach the probe or evict arms
    /// without sleeping for minutes. Production leaves the offset at 0.
    #[cfg(test)]
    pub(crate) fn advance_aging_for_test(&self, secs: u64) {
        self.aging.offset.fetch_add(secs, Ordering::Relaxed);
    }

    /// ONE `OnSmallTimer` PASS (eMule `CRoutingZone::OnSmallTimer`,
    /// RoutingZone.cpp:860-905), the half of Kad maintenance padMule never had:
    /// contacts that failed a probe are REMOVED, and the oldest due contact in
    /// each bin is asked to prove it is still there with a `KADEMLIA2_HELLO_REQ`
    /// (eMule sends `SendMyDetails(KADEMLIA2_HELLO_REQ, ...)` at :898-917 - a
    /// HELLO, never a PING; the PING/PONG traffic is the extern-port path).
    ///
    /// The table decides WHO (pure, offline-tested in `mule_kad::routing`);
    /// this does the I/O. Probes run sequentially under a tight per-probe wait
    /// and a small cap, because this is called from `heartbeat()` with the
    /// engine lock held - the same constraint `maintain_kad` documents.
    ///
    /// Returns the probes sent and the ids REMOVED - the ids, not just a count,
    /// because the caller must delete them from the persisted table too or the
    /// next launch re-imports them (see `Engine::maintain_kad_liveness`).
    pub async fn run_liveness_sweep(&mut self, max_probes: usize) -> (usize, Vec<Kad128>) {
        let now = self.aging_now();
        let outcome = self.with_routing(|t| t.sweep(now, max_probes));
        let removed = outcome.removed;
        crate::stats::note_kad_evicted(removed.len() as u64);
        let mut sent = 0usize;
        for c in outcome.probes {
            let contact = KadContact {
                id: c.id,
                ip: c.ip,
                udp_port: c.udp_port,
                tcp_port: c.tcp_port,
                version: c.version,
                udp_key: c.udp_key,
                udp_key_ip: c.udp_key_ip,
                verified: c.verified,
            };
            sent += 1;
            crate::stats::note_kad_probe_sent();
            // `hello` already does the whole round trip - request, responder
            // bookkeeping, and the ACK leg if the answer asks for one. A
            // TIMEOUT IS NOT AN ERROR HERE and must not be treated as one:
            // eviction is the expiry's job on a later sweep, exactly as
            // eMule's fire-and-forget probe leaves it to `OnSmallTimer`.
            if self.hello(&contact, KAD_PROBE_WAIT).await.is_ok() {
                crate::stats::note_kad_probe_answered();
                // The lease refresh itself happens inside `hello` ->
                // `note_responder(proven_alive = true)`, which is eMule's
                // bUpdate = true HELLO_RES path (KademliaUDPListener.cpp:672).
                // ONE promotion path, not two: a second `set_alive` here would
                // be a rule with two implementations to keep in step.
            }
        }
        (sent, removed)
    }

    pub(crate) fn with_routing<R>(&self, f: impl FnOnce(&mut RoutingTable) -> R) -> R {
        let mut g = self.routing.lock_recover();
        f(&mut g)
    }

    /// The closest VERIFIED contacts to `target`, as wire contacts. Clones out
    /// of the lock so callers never hold it while doing I/O.
    pub(crate) fn closest_wire_contacts(&self, target: &Kad128, want: usize) -> Vec<WireContact> {
        closest_wire_contacts_in(&self.routing, target, want)
    }

    pub fn contacts_known(&self) -> usize {
        self.with_routing(|t| t.len())
    }

    /// Seed this node's routing table from contacts we already hold (nodes.dat
    /// plus whatever a previous live node folded into `Engine::routing`).
    /// Returns the table size after seeding.
    ///
    /// WHY THIS EXISTS. A `KadNode` is constructed with an EMPTY table, and
    /// `bootstrap_any` stops at the FIRST answer - so without this, the table
    /// that every lookup reads held one responder plus the ~20 contacts its
    /// BOOTSTRAP_RES named, on start AND on every resume, no matter how many we
    /// already knew. That is the true content of the 2026-08-05 "138 -> 21"
    /// device report: a table being BUILT, not one being discarded. The 8cd fix
    /// unioned the same contacts into the bootstrap DIAL LIST, which is a
    /// different thing and left this untouched (build-progress 8ce).
    ///
    /// Everything goes through the gated `add_contact`, so a seed list is held
    /// to exactly the rules a wire-learned contact is: routable public address,
    /// no legacy DNS-port contact, the user's ipfilter, and the anti-sybil
    /// per-IP//24 caps. A poisoned nodes.dat therefore gains nothing by arriving
    /// this way instead of over the wire.
    ///
    /// The VERIFIED bit and the stored verify key are carried across, and both
    /// are load-bearing rather than tidiness: `closest_to` is verified-only
    /// (eMule `CRoutingBin::GetClosestTo`, RoutingBin.cpp:244), so seeds that
    /// lost the bit would inflate `contacts_known()` while remaining invisible
    /// to every lookup - a worse state than not seeding, because the number
    /// would then say the problem was fixed.
    pub fn seed_routing(&mut self, contacts: &[KadContact]) -> usize {
        for c in contacts {
            self.add_contact(
                c.id, c.ip, c.udp_port, c.tcp_port, c.version, c.verified,
                /*proven_alive=*/ false,
            );
            // Only for a contact that actually survived the gates - otherwise a
            // blocked address could still park a key against its id.
            if c.udp_key != 0 {
                self.with_routing(|t| {
                    if t.contains(&c.id) {
                        t.note_verify_key(&c.id, c.ip, c.udp_key, c.udp_key_ip);
                    }
                });
            }
        }
        self.contacts_known()
    }

    /// Add a contact to the routing table only if it passes the wire-contact
    /// gates - see [`gated_add_contact`], the ONE insert path, which the read
    /// loop shares.
    ///
    /// The argument list mirrors a wire contact plus the two verdicts the
    /// CALLER holds and the table cannot infer: whether the peer's IP was
    /// receiver-key verified, and whether this sighting is a proof of life
    /// (eMule's `bUpdate`). Bundling them into a struct would move the
    /// decision away from the call site that actually knows it.
    #[allow(clippy::too_many_arguments)]
    fn add_contact(
        &mut self,
        id: Kad128,
        ip: u32,
        udp_port: u16,
        tcp_port: u16,
        version: u8,
        verified: bool,
        proven_alive: bool,
    ) {
        gated_add_contact(
            &self.routing,
            &self.ip_filter,
            &WireContact {
                id,
                ip,
                udp_port,
                tcp_port,
                version,
            },
            verified,
            proven_alive,
            self.aging_now(),
        );
    }

    /// Record a RESPONDING node in one move: insert/refresh it (through the
    /// `add_contact` gates) with its receiver-key verdict as the verified bit,
    /// and store the sender key it handed us (IP-bound) so future requests echo
    /// it and the peer keeps verifying US. Every request/response path that
    /// hears back from a node must call this, or that node's key is lost to the
    /// send-side echo (the 2026-08-02 reanalysis found the two search paths
    /// dropping it).
    /// `proven_alive` is NOT simply "it answered": eMule promotes a lease only
    /// on its `bUpdate = true` paths, and a KADEMLIA2_RES is not one of them -
    /// it does not even re-add the responder (KademliaUDPListener.cpp:767-846).
    /// padMule DOES add it there, deliberately, to capture the sender key (the
    /// 2026-08-02 fix) - but that divergence must not grow a lease refresh, or
    /// a node could keep itself in our serve pool by answering searches alone.
    fn note_responder(
        &mut self,
        c: &WireContact,
        verified: bool,
        sender_vk: u32,
        proven_alive: bool,
    ) {
        self.add_contact(
            c.id,
            c.ip,
            c.udp_port,
            c.tcp_port,
            c.version,
            verified,
            proven_alive,
        );
        let our_ip = self.current_public_ip.load(Ordering::Relaxed);
        self.with_routing(|t| t.note_verify_key(&c.id, c.ip, sender_vk, our_ip));
    }

    /// Send an obfuscated Kad request (NodeID-keyed on `target_id`, our
    /// senderVerifyKey issued for `dest`) and wait for a decryptable reply with
    /// opcode `expect` FROM `dest`, ignoring interleaved/stray datagrams (other
    /// nodes' pings, a HELLO from the peer) until the deadline.
    /// Returns `(payload, valid_receiver_key)`. `valid_receiver_key` is eMule's
    /// `bValidReceiverKey`: the reply echoed back the verify key we issue for
    /// `dest` (`udp_verify_key(our_key, dest_ip)`), proving it came from a node
    /// that actually received our packet at that IP (anti-spoof). It NEVER causes
    /// a drop here - matching eMule, which only hard-drops HELLO_RES_ACK on an
    /// invalid receiver key; for every other opcode it just marks the contact
    /// unverified. The caller uses it to set the contact's `verified` bit.
    ///
    /// A batch of one, so there is exactly ONE receive loop in this file and the
    /// single-request and batched paths cannot drift apart.
    async fn request(
        &self,
        target_id: &Kad128,
        dest: SocketAddr,
        frame: &[u8],
        expect: u8,
        wait: Duration,
    ) -> Result<(Vec<u8>, bool, u32), KadError> {
        let mut answers = self
            .request_batch(&[(*target_id, dest, frame.to_vec())], expect, wait)
            .await;
        answers.pop().expect("one request in, one answer out")
    }

    /// Obfuscate, register and send ONE outbound request; the returned oneshot
    /// resolves when the read loop matches its reply. The ONLY way a request
    /// enters `pending`, shared by `request_batch` (bootstrap / hello) and the
    /// event-driven lookup, so the two paths cannot drift apart.
    ///
    /// Registration happens BEFORE the send, so a reply (loopback is this
    /// fast) cannot arrive while its slot does not exist yet. A failed send
    /// withdraws the slot at once: no reply is coming, and a dead slot must
    /// not swallow another request's IP-fallback match.
    ///
    /// The caller's `guard` tracks the seq HERE, between the push and the send
    /// await. Callers used to track only after this returned, so a
    /// cancellation landing while `send_to` was Pending left a slot no guard
    /// knew about - parked in `pending` for the node's life, eating one
    /// IP-fallback match. No deterministic test exists for that window: a
    /// loopback `send_to` virtually never returns Pending, so the fix is
    /// argued by construction (track precedes the only await) rather than
    /// witnessed red-first. The existing cancellation tests cover the guard's
    /// withdraw-on-drop itself.
    async fn begin_request(
        &self,
        guard: &mut SlotGuard,
        target_id: &Kad128,
        dest: SocketAddr,
        frame: &[u8],
        expect: u8,
    ) -> Result<(u64, tokio::sync::oneshot::Receiver<ReplyAnswer>), KadError> {
        let dest_ip = ip_u32(&dest);
        let sender_vk = mule_kad::udp_verify_key(self.udp_key, dest_ip);
        // ECHO the verify key this contact previously handed us (send-side), so
        // it verifies US - but only while it was minted against our current
        // public IP. 0 for a genuine first contact / unknown / IP-mismatch,
        // which is byte-identical to the pre-hard-verify wire. This is a FIELD
        // flip only; the RC4 obfuscation stays NodeID-keyed, byte-faithful to
        // eMule (EncryptedDatagramSocket.cpp: NodeID always wins when present).
        let our_ip = self.current_public_ip.load(Ordering::Relaxed);
        let echo_vk = self.with_routing(|t| t.verify_key_for(target_id, dest_ip, our_ip));
        let datagram = kad_obfuscate_request(
            frame,
            target_id,
            rand::random(), // random key seed
            echo_vk,        // the peer's key we echo so IT can verify US
            sender_vk,      // our key, want this echoed so WE can verify IT
            rand::random(), // marker randomness
        );
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.pending.lock_recover().push(PendingSlot {
            seq,
            dest,
            dest_ip,
            sender_vk,
            expect,
            tx,
        });
        // Track BEFORE the send await (see the doc above). On a send error the
        // slot is withdrawn below as before; the guard's later retain of a
        // seq already gone is a documented no-op.
        guard.track(seq);
        match self.socket.send_to(&datagram, dest).await {
            Ok(_) => Ok((seq, rx)),
            Err(e) => {
                self.pending.lock_recover().retain(|p| p.seq != seq);
                Err(KadError::Io(e))
            }
        }
    }

    /// Send SEVERAL Kad requests and collect their replies within ONE window,
    /// demultiplexing the shared socket by source address. The one-shot
    /// handshake paths (bootstrap, hello) live here; the LOOKUPS moved on to
    /// [`KadNode::drive_lookup`], whose per-request deadlines share
    /// `begin_request` with this, so the two waiting styles cannot drift in
    /// how they register and match replies.
    ///
    /// HISTORY (it explains the shape). Kademlia's ALPHA is a CONCURRENCY
    /// parameter, but padMule first used it as a batch SIZE and awaited each
    /// member in turn - a lookup round cost `alpha * per_query`, the ~10s
    /// search measured on device 2026-08-07. This batch (one window, requests
    /// concurrent) was the first fix; the round barrier it kept - the window
    /// ends at the SLOWEST member - was measured at 57% of rounds held open by
    /// a silent peer (row 8cm), and the event-driven lookup removed the rounds
    /// entirely.
    ///
    /// THE SINGLE SOCKET is why waiting is delicate at all: `recv_from` hands
    /// each datagram to exactly one waiter, and the pre-loop code DISCARDED
    /// anything not from its own destination - so two concurrent requests
    /// would silently eat each other's replies. The owning read loop matching
    /// datagrams to registered slots is what makes any concurrency safe here.
    ///
    /// Wire-identical. The same datagrams are sent to the same peers with the
    /// same keys; only the order of our own waiting changes.
    async fn request_batch(
        &self,
        reqs: &[(Kad128, SocketAddr, Vec<u8>)],
        expect: u8,
        wait: Duration,
    ) -> Vec<Result<(Vec<u8>, bool, u32), KadError>> {
        // The socket's single reader is the owning loop (`run_read_loop`); this
        // REGISTERS a slot per request and awaits its oneshot. The matching
        // rules live in the loop, moved verbatim: exact address first, then the
        // first slot waiting on the same IP.
        //
        // Withdraw-on-drop covers BOTH exits: the normal tail AND cancellation.
        // The 5s `start_kad` timeout CANCELS this future mid-wait (bootstrap's
        // structural worst case is ~48s of inner waits, so cancellation is the
        // NORMAL path there, not the edge), and a cancelled future never runs a
        // trailing statement - a stale slot then sits at the FRONT of
        // `pending`, wins the IP-fallback match, and swallows the next reply
        // from that peer. Same guard, same reason as the lookup path. Every
        // seq is tracked AT REGISTRATION, inside `begin_request` before its
        // send await: a cancellation while slot 1 is being awaited must still
        // withdraw slots 2 and 3 - and one landing mid-send must withdraw the
        // slot that send had already registered.
        let mut guard = SlotGuard::new(Arc::clone(&self.pending));
        let mut slots: Vec<Result<(u64, tokio::sync::oneshot::Receiver<ReplyAnswer>), KadError>> =
            Vec::with_capacity(reqs.len());
        for (target_id, dest, frame) in reqs {
            // A send that fails is THIS request's failure, not the batch's - the
            // others are already on the wire and their answers are still coming.
            let slot = self
                .begin_request(&mut guard, target_id, *dest, frame, expect)
                .await;
            slots.push(slot);
        }

        // ONE deadline for the whole batch: each slot awaits only what remains
        // of the shared window, so a batch of silent peers costs one window,
        // not one per peer.
        let deadline = Instant::now() + wait;
        let mut answers = Vec::with_capacity(slots.len());
        for slot in slots {
            match slot {
                Err(e) => answers.push(Err(e)),
                Ok((_seq, rx)) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    answers.push(match timeout(remaining, rx).await {
                        Ok(Ok(answer)) => Ok(answer),
                        // Elapsed, or the loop task is gone (node dropping).
                        _ => Err(KadError::Timeout),
                    });
                }
            }
        }
        answers
    }

    /// Send a BOOTSTRAP_REQ to one contact and parse its BOOTSTRAP_RES, seeding
    /// the routing table with the returned contacts (and the responder itself).
    pub async fn bootstrap_from(
        &mut self,
        contact: &KadContact,
        wait: Duration,
    ) -> Result<BootstrapRes, KadError> {
        let (op, payload) = build_bootstrap_req();
        let frame = pack_kad(op, payload);
        let dest = contact_addr(contact.ip, contact.udp_port);
        let (res_payload, verified, sender_vk) = self
            .request(&contact.id, dest, &frame, OP_BOOTSTRAP_RES, wait)
            .await?;
        let res = parse_bootstrap_res(&res_payload)?;
        // The responder itself (at the address we reached) is IP-verified iff its
        // reply echoed our verify key; the listed contacts are always unverified
        // until they prove their own IP (eMule KademliaUDPListener.cpp:567 vs the
        // payload contacts added unverified).
        self.add_contact(
            res.id,
            contact.ip,
            contact.udp_port,
            res.tcp_port,
            res.version,
            verified,
            // PROVEN: the BOOTSTRAP_RES responder is one of eMule's three
            // bUpdate = true paths (KademliaUDPListener.cpp:567).
            /*proven_alive=*/
            true,
        );
        // Store the verify key it handed us (bound to our current public IP) so a
        // later request to it echoes the key and it verifies us in return.
        let our_ip = self.current_public_ip.load(Ordering::Relaxed);
        self.with_routing(|t| t.note_verify_key(&res.id, contact.ip, sender_vk, our_ip));
        for c in &res.contacts {
            self.add_contact(
                c.id, c.ip, c.udp_port, c.tcp_port, c.version, false, /*proven_alive=*/ false,
            );
        }
        Ok(res)
    }

    /// Try each contact in turn until one answers a BOOTSTRAP_REQ. Returns the
    /// (contact index, response) of the first success.
    pub async fn bootstrap_any(
        &mut self,
        contacts: &[KadContact],
        per_contact: Duration,
        max_tries: usize,
    ) -> Result<(usize, BootstrapRes), KadError> {
        let mut last = KadError::Timeout;
        for (i, c) in contacts.iter().take(max_tries).enumerate() {
            match self.bootstrap_from(c, per_contact).await {
                Ok(res) => return Ok((i, res)),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Send a HELLO_REQ, parse the HELLO_RES, and COMPLETE the Kad2 v8 three-way
    /// handshake: store the sender key the peer hands us and, if it asks for an ACK
    /// (misc-option 0x04), reply with a HELLO_RES_ACK echoing that key. The echoed
    /// key == the peer's GetUDPVerifyKey(our IP), so it marks US IP-verified (eMule
    /// Process2HelloResponseAck -> VerifyContact). Without the ACK a v8 node keeps
    /// us UNVERIFIED and deprioritizes/drops us from its routing table.
    pub async fn hello(&mut self, contact: &KadContact, wait: Duration) -> Result<Hello, KadError> {
        // A HELLO_REQ carries NO misc-option 0x04: that bit means "send me a
        // HELLO_RES_ACK" and is the RESPONDER's to set in its HELLO_RES (eMule
        // SendMyDetails, KademliaUDPListener.cpp:139). Setting it on a REQUEST is
        // wrong (it trips aMule's AddContact2 wxFAIL) and earns nothing.
        let (op, payload) = build_hello_req(
            &self.kad_id,
            self.tcp_port,
            Some(self.advertised_udp()),
            None,
        );
        let frame = pack_kad(op, payload);
        let dest = contact_addr(contact.ip, contact.udp_port);
        let (res_payload, verified, peer_vk) = self
            .request(&contact.id, dest, &frame, OP_HELLO_RES, wait)
            .await?;
        let hello = parse_hello(&res_payload)?;
        // Record the responder like every other answered request: insert/refresh
        // it with the receiver-key verdict (eMule Process2HelloResponse ->
        // AddContact2 does the same) and store the sender key it handed us so
        // later requests echo it and it keeps verifying us.
        self.note_responder(
            &WireContact {
                id: contact.id,
                ip: contact.ip,
                udp_port: contact.udp_port,
                tcp_port: hello.tcp_port,
                version: hello.version,
            },
            verified,
            peer_vk,
            // PROVEN: a HELLO_RES to a request of OURS - eMule's :672 path, and
            // the leg the liveness probe rides on.
            /*proven_alive=*/
            true,
        );
        // Third leg: if the HELLO_RES requested an ACK, send it, echoing peer_vk.
        if hello.misc_options.is_some_and(|m| m & 0x04 != 0) {
            self.send_hello_res_ack(&contact.id, dest, peer_vk).await?;
        }
        Ok(hello)
    }

    /// Send a HELLO_RES_ACK to `dest`, echoing `peer_vk` (the sender key the peer
    /// issued us in its HELLO_RES) as our receiver key - the third leg of the Kad2
    /// v8 IP-verification handshake. The peer checks the echoed key against
    /// GetUDPVerifyKey(our IP) and, on a match, marks us IP-verified. Fire-and-
    /// forget: eMule sends the ACK and expects no reply.
    async fn send_hello_res_ack(
        &self,
        target_id: &Kad128,
        dest: SocketAddr,
        peer_vk: u32,
    ) -> Result<(), KadError> {
        let (op, payload) = build_hello_res_ack(&self.kad_id);
        let frame = pack_kad(op, payload);
        let sender_vk = mule_kad::udp_verify_key(self.udp_key, ip_u32(&dest));
        let datagram = kad_obfuscate_request(
            &frame,
            target_id,
            rand::random(), // random key seed
            peer_vk,        // echo the peer's key -> its bValidReceiverKey -> verifies us
            sender_vk,      // our key, so it keeps verifying our future packets
            rand::random(), // marker randomness
        );
        self.socket.send_to(&datagram, dest).await?;
        Ok(())
    }

    /// Absorb one FIND_NODE answer along BOTH of eMule's paths, kept apart:
    ///
    /// - the RESPONDER is recorded (`note_responder`) with its receiver-key
    ///   verdict, and its sender key stored for the send-side echo;
    /// - every listed contact is offered to the ROUTING TABLE through the
    ///   gated insert path - eMule Process_KADEMLIA2_RES hands each basically-
    ///   acceptable contact to AddUnfiltered (KademliaUDPListener.cpp:846)
    ///   BEFORE the search ever sees the list, so the table is fed by every
    ///   answer, never starved by the search's stricter per-answer rules;
    /// - what returns is the SEARCH FRONTIER's view: `frontier_filter` (self,
    ///   unique IPs, 2 per public /24), plus the verified-repoint refusal - a
    ///   KadID is semi-public, so re-pointing a VERIFIED contact to some other
    ///   address is precisely how an attacker takes over a known node's
    ///   identity (eMule CRoutingZone::IsAcceptableContact, RoutingZone.cpp:
    ///   1014-1020; the listener gates pResults on bWasAdded ||
    ///   IsAcceptableContact the same way).
    fn absorb_find_answer(
        &mut self,
        responder: &WireContact,
        verified: bool,
        sender_vk: u32,
        contacts: Vec<WireContact>,
    ) -> Vec<WireContact> {
        // NOT proven: a KADEMLIA2_RES is not a bUpdate = true path in eMule
        // (it does not even re-add the responder). We add it only to capture the
        // sender key; promoting here would let a node hold its place in our
        // serve pool by answering searches alone.
        self.note_responder(responder, verified, sender_vk, /*proven_alive=*/ false);
        for c in &contacts {
            self.add_contact(
                c.id, c.ip, c.udp_port, c.tcp_port, c.version, false, /*proven_alive=*/ false,
            );
        }
        let mut frontier = frontier_filter(responder.ip, contacts);
        self.with_routing(|t| frontier.retain(|c| t.is_acceptable_answer(&c.id, c.ip, c.udp_port)));
        frontier
    }

    /// Send one lookup request and park its reply-or-deadline future in
    /// `inflight`. Returns whether the datagram went out; a send failure is
    /// the caller's cue to mark the contact failed so the frontier is not
    /// stranded waiting on it.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_lookup_request(
        &self,
        inflight: &mut tokio::task::JoinSet<ReqEvent>,
        guard: &mut SlotGuard,
        kind: ReqKind,
        contact: WireContact,
        frame: Vec<u8>,
        expect: u8,
        per_query: Duration,
    ) -> bool {
        let dest = contact_addr(contact.ip, contact.udp_port);
        match self
            .begin_request(guard, &contact.id, dest, &frame, expect)
            .await
        {
            Ok((seq, rx)) => {
                crate::stats::note_kad_request(kind.stats());
                let started = Instant::now();
                inflight.spawn(async move {
                    // THE PER-REQUEST DEADLINE: this future resolves with the
                    // reply or at its own deadline, whichever is first - there
                    // is no round barrier for a silent peer to hold open.
                    let outcome = match timeout(per_query, rx).await {
                        Ok(Ok(answer)) => Some(answer),
                        _ => None,
                    };
                    ReqEvent {
                        kind,
                        contact,
                        seq,
                        rtt: started.elapsed(),
                        outcome,
                    }
                });
                crate::stats::note_kad_inflight(inflight.len() as u64);
                true
            }
            Err(_) => false,
        }
    }

    /// THE EVENT-DRIVEN LOOKUP (eMule `CSearch`). The round-based lookup this
    /// replaces charged every round its slowest member: the final old-panel
    /// device reading (build-progress 8cm) had 57% of FIND_NODE rounds held
    /// open by a peer that never answered, at an average 601ms against the
    /// 750ms cap.
    ///
    /// The shape, per the step-2 design:
    /// - an in-flight set capped at [`ALPHA_QUERY`] FIND_NODEs, each with a
    ///   PER-REQUEST deadline instead of a per-round window;
    /// - a response feeds frontier + routing table (`absorb_find_answer`) and
    ///   can dispatch closer top-alpha contacts IMMEDIATELY, inside the
    ///   response handling (eMule Search.cpp:508);
    /// - value asks INTERLEAVE with the iteration: the closest responded
    ///   in-tolerance node is asked while other FIND_NODEs are still
    ///   outstanding - there is no separate value phase. eMule reaches
    ///   StorePacket the same way but only from its 3s-gated JumpStart tick;
    ///   padMule runs the walk after every state change, because a value ask
    ///   gated behind three seconds of silence would put a 3s floor under
    ///   time-to-first-result. The 3s-gated tick remains as stall recovery.
    /// - termination: enough results, candidates exhausted (nothing in flight
    ///   and nothing left to dispatch), or the overall deadline.
    async fn drive_lookup(
        &mut self,
        target: Kad128,
        value: ValueAsk<'_>,
        want: usize,
        per_query: Duration,
        deadline_queries: u32,
        find_budget: usize,
    ) -> Result<(ResolveOutcome, Vec<FileResult>), KadError> {
        let seeds = self.closest_wire_contacts(&target, 50);
        if seeds.is_empty() {
            return Err(KadError::NotReady); // no routing table - bootstrap first
        }
        // A refresh harvests nobody: a zero value budget makes `harvest`
        // consume resolved entries without ever emitting an ask.
        let value_budget = match &value {
            ValueAsk::None => 0,
            _ => LOOKUP_VALUE_BUDGET,
        };
        // The SEARCH TOTAL. eMule stops a search at SEARCHKEYWORD_TOTAL /
        // SEARCHFINDSOURCE_TOTAL however much was asked for
        // (SearchManager.cpp:329/:347, Search.cpp:986); padMule additionally
        // stops ACCUMULATING there, mid-reply, so one datagram cannot buy
        // O(n^2) dedupe work past the cap. `stop` is what the termination
        // check compares against - a caller wanting more than the network
        // total would otherwise run every search to its full deadline.
        let cap = match &value {
            ValueAsk::Sources { .. } => KAD_SEARCH_SOURCE_TOTAL,
            ValueAsk::Keyword { .. } => KAD_SEARCH_KEYWORD_TOTAL,
            ValueAsk::PublishKeyword { .. } | ValueAsk::PublishSource { .. } => {
                KAD_PUBLISH_STORE_TOTAL
            }
            ValueAsk::None => usize::MAX,
        };
        let stop = want.min(cap);
        let mut cs = CSearch::new(target, seeds, find_budget, value_budget, K);
        let mut out = ResolveOutcome::default();
        let mut files: Vec<FileResult> = Vec::new();
        let mut inflight: tokio::task::JoinSet<ReqEvent> = tokio::task::JoinSet::new();
        let mut finds_inflight = 0usize;
        let mut guard = SlotGuard::new(Arc::clone(&self.pending));
        let t0 = Instant::now();
        let overall = t0 + per_query * deadline_queries;
        // eMule initialises m_uLastResponse to construction time (Search.cpp:84).
        let mut last_response = Instant::now();
        let mut tick = tokio::time::interval(STALL_TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut need_progress = true;

        loop {
            // Enough results? Checked BEFORE dispatching, so the response that
            // satisfies the search does not buy one more harvest-and-refill.
            // (2026-08-09 analysis, recorded because the handoff claimed
            // otherwise: that trailing pass had nothing left to DISPATCH -
            // every prior pass tops the pipeline up, and the walk stops at
            // in-flight entries - so this reorder is hygiene and a bounded
            // CPU saving; the "wasted datagrams on the success path" clause
            // was refuted, not fixed.)
            let results = match &value {
                ValueAsk::Sources { .. } => out.sources.len(),
                ValueAsk::Keyword { .. } => files.len(),
                ValueAsk::PublishKeyword { .. } | ValueAsk::PublishSource { .. } => {
                    out.published_to
                }
                ValueAsk::None => 0,
            };
            if !matches!(value, ValueAsk::None) && results >= stop {
                break; // enough results (the caller's want, or the search total)
            }
            if need_progress {
                need_progress = false;
                // Value asks first - the JumpStart walk's consumption order.
                for c in cs.harvest() {
                    let (frame, expect) = match &value {
                        ValueAsk::Sources { file_size } => {
                            let (op, p) = build_search_source_req(&target, 0, *file_size);
                            (pack_kad(op, p), OP_SEARCH_RES)
                        }
                        ValueAsk::Keyword { words, .. } => {
                            let (op, p) = build_search_key_req_restrictive(&target, 0, words);
                            (pack_kad(op, p), OP_SEARCH_RES)
                        }
                        ValueAsk::PublishKeyword { entries } => {
                            let (op, p) = build_publish_key_req(&target, entries);
                            (pack_kad(op, p), OP_PUBLISH_RES)
                        }
                        ValueAsk::PublishSource { our_hash, entry } => {
                            let (op, p) = build_publish_source_req(&target, our_hash, entry);
                            (pack_kad(op, p), OP_PUBLISH_RES)
                        }
                        // `harvest` gates on a non-zero value budget, which
                        // `ValueAsk::None` never has, so this arm is not
                        // reached today. `continue` rather than `unreachable!`
                        // so a future budget change cannot unwind the whole
                        // lookup driver (and the engine heartbeat with it).
                        ValueAsk::None => continue,
                    };
                    if self
                        .spawn_lookup_request(
                            &mut inflight,
                            &mut guard,
                            ReqKind::Value,
                            c,
                            frame,
                            expect,
                            per_query,
                        )
                        .await
                    {
                        out.nodes_searched += 1;
                    }
                }
                // Keep ALPHA_QUERY FIND_NODEs in flight.
                for c in cs.refill(ALPHA_QUERY.saturating_sub(finds_inflight)) {
                    let (op, p) = build_kad2_req(KAD_FIND_NODE, &target, &c.id);
                    if self
                        .spawn_lookup_request(
                            &mut inflight,
                            &mut guard,
                            ReqKind::Find,
                            c.clone(),
                            pack_kad(op, p),
                            OP_KAD2_RES,
                            per_query,
                        )
                        .await
                    {
                        finds_inflight += 1;
                        out.nodes_queried += 1;
                    } else {
                        cs.on_timeout(&c);
                    }
                }
            }
            if inflight.is_empty() {
                break; // candidates exhausted: nothing in flight, nothing to send
            }
            tokio::select! {
                () = tokio::time::sleep_until(overall) => break, // overall deadline
                Some(joined) = inflight.join_next() => {
                    need_progress = true;
                    let Ok(ev) = joined else {
                        // Only a panicking request task lands here; free the
                        // slot estimate so the lookup cannot wedge (the stall
                        // tick and the overall deadline back this up).
                        finds_inflight = finds_inflight.saturating_sub(1);
                        continue;
                    };
                    if ev.kind == ReqKind::Find {
                        // SATURATING, and the difference is a wedge vs a wobble.
                        // The panic arm above cannot tell which KIND died (there
                        // is no `ev` to read), so it decrements unconditionally -
                        // meaning one panicking VALUE task can leave this at 0
                        // while a real Find is still outstanding. A plain `-= 1`
                        // then wraps in release, `ALPHA_QUERY.saturating_sub` of
                        // a huge number is 0, and the lookup never dispatches
                        // another FIND_NODE until the overall deadline. Counting
                        // slightly low merely over-parallelises for one round;
                        // wrapping stops the search dead.
                        finds_inflight = finds_inflight.saturating_sub(1);
                    }
                    match ev.outcome {
                        Some((payload, verified, sender_vk)) => {
                            last_response = Instant::now();
                            crate::stats::note_kad_reply(ev.kind.stats(), ev.rtt.as_millis() as u64);
                            match ev.kind {
                                ReqKind::Find => match parse_kad2_res(&payload).ok() {
                                    // Drop a malicious over-long answer whole: padMule requests
                                    // KAD_FIND_NODE (11) contacts; a compliant node never exceeds
                                    // that, a hostile one may pad up to 255 fabricated contacts.
                                    // eMule's search rejects the same way (Search.cpp:377), though
                                    // its routing table keeps them; ours drops them everywhere -
                                    // the stricter stance this code already took.
                                    Some(res) if res.contacts.len() <= KAD_REQUESTED_CONTACTS => {
                                        out.find_node_responses += 1;
                                        let frontier = self.absorb_find_answer(
                                            &ev.contact, verified, sender_vk, res.contacts,
                                        );
                                        // eMule's IMMEDIATE dispatch (Search.cpp:508), capped by
                                        // our in-flight bound.
                                        let cap = ALPHA_QUERY.saturating_sub(finds_inflight);
                                        for c in cs.on_response(&ev.contact, frontier, cap) {
                                            let (op, p) = build_kad2_req(KAD_FIND_NODE, &target, &c.id);
                                            if self
                                                .spawn_lookup_request(
                                                    &mut inflight,
                                                    &mut guard,
                                                    ReqKind::Find,
                                                    c.clone(),
                                                    pack_kad(op, p),
                                                    OP_KAD2_RES,
                                                    per_query,
                                                )
                                                .await
                                            {
                                                finds_inflight += 1;
                                                out.nodes_queried += 1;
                                            } else {
                                                cs.on_timeout(&c);
                                            }
                                        }
                                    }
                                    // Over-long or undecodable: no usable answer came, which
                                    // for the frontier is the same as silence.
                                    _ => cs.on_timeout(&ev.contact),
                                },
                                ReqKind::Value if value.is_publish() => {
                                    // A STORE ack: the node accepted our index
                                    // entry. Count it (that IS the publish
                                    // result), and record the responder's key
                                    // like any other reply. eMule reads the
                                    // load factor for backoff; padMule keeps it
                                    // only as a diagnostic today.
                                    //
                                    // TWO DELIBERATE DIVERGENCES, documented
                                    // not changed. (1) padMule never sends
                                    // OP_PUBLISH_RES_ACK: eMule sends it only
                                    // when the reply carries an options byte
                                    // with bit 0 set and the sender key is
                                    // non-empty (KademliaUDPListener.cpp:
                                    // 1579-1588), and stock eMule never SETS
                                    // that bit - all three of its PUBLISH_RES
                                    // senders write only file + load
                                    // (:1379-1384, :1526-1531, :1727-1732).
                                    // (2) `published_to` counts any parseable
                                    // PUBLISH_RES from a slot-matched peer
                                    // without checking the returned file id
                                    // against the published target; eMule
                                    // routes the id to its search
                                    // (`ProcessPublishResult`, :1577-1578).
                                    // The slot match already binds the reply
                                    // to OUR outstanding request, so a wrong
                                    // id could only miscount, not misroute.
                                    if parse_publish_res(&payload).is_ok() {
                                        out.published_to += 1;
                                        self.note_responder(
                                            &ev.contact,
                                            verified,
                                            sender_vk,
                                            /*proven_alive=*/ false,
                                        );
                                    }
                                }
                                ReqKind::Value => {
                                    if let Ok(res) = parse_search_res(&payload) {
                                        out.search_responses += 1;
                                        self.note_responder(
                                            &ev.contact,
                                            verified,
                                            sender_vk,
                                            /*proven_alive=*/ false,
                                        );
                                        let had = results;
                                        match &value {
                                            ValueAsk::Sources { .. } => {
                                                for s in res.results.iter().filter_map(|r| r.as_source()) {
                                                    // The search total, applied at ACCUMULATION:
                                                    // past it, stop scanning entirely - the
                                                    // linear dedupe below is the O(n^2) an
                                                    // uncapped hostile reply would buy.
                                                    if out.sources.len() >= KAD_SEARCH_SOURCE_TOTAL {
                                                        break;
                                                    }
                                                    if !out.sources.iter().any(|e| e.client_hash == s.client_hash) {
                                                        out.sources.push(s);
                                                    }
                                                }
                                            }
                                            ValueAsk::Keyword { keyword, .. } => {
                                                for f in res.results.iter().filter_map(|r| r.as_file()) {
                                                    if files.len() >= KAD_SEARCH_KEYWORD_TOTAL {
                                                        break; // the search total (above)
                                                    }
                                                    // The wire matched ONE word. Apply the rest
                                                    // locally, exactly as eMule does per result
                                                    // (Search.cpp:1379-1395) - without this, a
                                                    // search for "yes prime minister" hands back
                                                    // everything indexed under "yes".
                                                    if !mule_kad::kad_filename_matches(&f.name, keyword) {
                                                        continue;
                                                    }
                                                    if !files.iter().any(|e| e.hash == f.hash) {
                                                        files.push(f);
                                                    }
                                                }
                                            }
                                            // Unreachable: this arm is the
                                            // `ReqKind::Value if !is_publish()`
                                            // branch, so a publish value never
                                            // parses a SEARCH_RES here.
                                            ValueAsk::None
                                            | ValueAsk::PublishKeyword { .. }
                                            | ValueAsk::PublishSource { .. } => {}
                                        }
                                        let have = match &value {
                                            ValueAsk::Sources { .. } => out.sources.len(),
                                            _ => files.len(),
                                        };
                                        if had == 0 && have > 0 {
                                            crate::stats::note_kad_first_result(
                                                t0.elapsed().as_millis() as u64,
                                            );
                                        }
                                    }
                                }
                            }
                        }
                        None => {
                            crate::stats::note_kad_timeout(ev.kind.stats());
                            // Withdraw the dead slot now rather than at guard
                            // drop, so it cannot swallow an IP-fallback match
                            // meant for a later request to the same peer.
                            self.pending
                                .lock_recover()
                                .retain(|p| p.seq != ev.seq);
                            if ev.kind == ReqKind::Find {
                                cs.on_timeout(&ev.contact);
                            }
                        }
                    }
                }
                _ = tick.tick() => {
                    // eMule's stall recovery: JumpStart bails if any response
                    // arrived within the last 3s (Search.cpp:281); past that
                    // it walks and redispatches - our progress pass.
                    if last_response.elapsed() >= STALL_AFTER {
                        need_progress = true;
                    }
                }
            }
        }
        // How close did we get? Leading zero bits of the closest node's
        // distance to the target (higher = closer; a real converged lookup
        // reaches deep).
        if let Some(closest) = cs.closest(1).first() {
            out.closest_prefix_bits = leading_zero_bits(&target.distance(&closest.id));
        }
        if !matches!(value, ValueAsk::None) {
            crate::stats::note_kad_value_lookup_done(t0.elapsed().as_millis() as u64);
        }
        Ok((out, files))
    }

    /// Grow and refresh the routing table with an iterative lookup toward
    /// `target`, asking nobody for sources. Returns the net contacts gained.
    ///
    /// THE GAP THIS FILLS: padMule had NO periodic Kad maintenance of any kind.
    /// The table was fed only by the bootstrap at start and by contacts learned
    /// incidentally when a source lookup or keyword search happened to pass
    /// through them, so it never grew on purpose and stale entries were never
    /// aged out by use. Both authorities run exactly this on a timer - eMule
    /// `CRoutingZone::OnBigTimer` fires a random-target lookup into each stale
    /// bin, aMule mirrors it in RoutingZone.cpp - and it is what keeps a table
    /// broad enough for keyword search to converge.
    ///
    /// Observed live 2026-08-05: after a reinstall wiped `nodes.dat`, the table
    /// sat at 138 contacts and keyword searches returned very few Kad hits.
    /// Anthony flagged both as suspicious; they were the same defect.
    ///
    /// Bounded harder than a real lookup (`REFRESH_DEADLINE_QUERIES`, not 16)
    /// because this runs on the heartbeat under the engine lock: maintenance
    /// must never cost the user a slow search. It converges over repeated
    /// small lookups instead of one deep dive, which also spreads the traffic
    /// out - the point is a table that keeps improving, not one perfect
    /// lookup.
    pub async fn refresh_routing(&mut self, target: &Kad128, per_query: Duration) -> usize {
        crate::stats::note_kad_lookup();
        let before = self.contacts_known();
        // NotReady (no seeds) and every other early exit alike gain 0 contacts.
        let _ = self
            .drive_lookup(
                *target,
                ValueAsk::None,
                0,
                per_query,
                REFRESH_DEADLINE_QUERIES,
                REFRESH_DEADLINE_QUERIES as usize * ALPHA_QUERY,
            )
            .await;
        self.contacts_known().saturating_sub(before)
    }

    /// The Wave-6 goal: resolve an ed2k `file_hash` to sources. An
    /// event-driven FIND_NODE lookup toward the hash over the current routing
    /// table, with SEARCH_SOURCE_REQ interleaved to the closest responded
    /// in-tolerance nodes, collecting sources until at least `want` are found,
    /// the candidates are exhausted, or the overall deadline lands.
    pub async fn resolve_sources(
        &mut self,
        file_hash: &Kad128,
        file_size: u64,
        want: usize,
        per_query: Duration,
    ) -> Result<ResolveOutcome, KadError> {
        crate::stats::note_kad_lookup();
        let (out, _) = self
            .drive_lookup(
                *file_hash,
                ValueAsk::Sources { file_size },
                want,
                per_query,
                LOOKUP_DEADLINE_QUERIES,
                LOOKUP_FIND_BUDGET,
            )
            .await?;
        Ok(out)
    }

    /// Resolve a `keyword` to files over the live Kad network: an event-driven
    /// FIND_NODE lookup toward the keyword hash with KADEMLIA2_SEARCH_KEY_REQ
    /// interleaved to the closest responded in-tolerance nodes. Results are
    /// de-duped by file hash. This is a SERVERLESS search - no eD2k server
    /// needed.
    pub async fn resolve_keyword(
        &mut self,
        keyword: &str,
        want: usize,
        per_query: Duration,
    ) -> Result<Vec<FileResult>, KadError> {
        // ONE WORD GOES ON THE WIRE, NOT THE PHRASE. Kad indexes one entry per
        // word, so hashing the raw query targeted a region nobody publishes to
        // and every multi-word search returned zero - silently, because the
        // lookup converges perfectly on an empty part of the keyspace. Proven
        // 2026-08-07: "Yes Prime Minister" -> 0, "minister" -> a full page.
        // eMule sends `m_listWords.front()` (SearchManager.cpp:140-141) and
        // filters the results by the rest, which `drive_lookup` does per
        // result. The full `words` ride along as a search-expression tree so
        // THAT NODE filters before choosing what to send back - without that,
        // a common primary keyword returns a bounded sample of an enormous
        // pool and the wanted file is simply not in it; local filtering cannot
        // recover what was never sampled.
        crate::stats::note_kad_lookup();
        let words = mule_kad::kad_keywords(keyword);
        let Some(primary) = words.first().cloned() else {
            return Ok(Vec::new()); // nothing indexable (all tokens under 3 bytes)
        };
        let target = kad_keyword_target(&primary);
        let (_, files) = self
            .drive_lookup(
                target,
                ValueAsk::Keyword {
                    keyword,
                    words: &words,
                },
                want,
                per_query,
                LOOKUP_DEADLINE_QUERIES,
                LOOKUP_FIND_BUDGET,
            )
            .await?;
        Ok(files)
    }

    /// PUBLISH `entries` under ONE keyword hash: the same event-driven FIND_NODE
    /// walk toward the keyword's hash, then a KADEMLIA2_PUBLISH_KEY_REQ STORE to
    /// each closest responded in-tolerance node, counting acks until
    /// [`KAD_PUBLISH_STORE_TOTAL`] nodes hold the entry (eMule STOREKEYWORD).
    /// Returns how many nodes acknowledged. The caller hashes the word and
    /// batches at [`mule_kad::PUBLISH_KEY_FILES_PER_PACKET`].
    pub async fn publish_keyword(
        &mut self,
        keyword_target: &Kad128,
        entries: &[KeywordEntry],
        per_query: Duration,
    ) -> Result<usize, KadError> {
        crate::stats::note_kad_lookup();
        let (out, _) = self
            .drive_lookup(
                *keyword_target,
                ValueAsk::PublishKeyword { entries },
                KAD_PUBLISH_STORE_TOTAL,
                per_query,
                PUBLISH_DEADLINE_QUERIES,
                LOOKUP_FIND_BUDGET,
            )
            .await?;
        Ok(out.published_to)
    }

    /// PUBLISH our source record for `file_hash`: the FIND_NODE walk toward the
    /// file hash, then a KADEMLIA2_PUBLISH_SOURCE_REQ STORE to each closest
    /// responded in-tolerance node (eMule STOREFILE, Search.cpp:705). Returns
    /// the ack count.
    pub async fn publish_source(
        &mut self,
        file_hash: &Kad128,
        our_hash: Kad128,
        entry: SourceEntry,
        per_query: Duration,
    ) -> Result<usize, KadError> {
        crate::stats::note_kad_lookup();
        let (out, _) = self
            .drive_lookup(
                *file_hash,
                ValueAsk::PublishSource { our_hash, entry },
                KAD_PUBLISH_STORE_TOTAL,
                per_query,
                PUBLISH_DEADLINE_QUERIES,
                LOOKUP_FIND_BUDGET,
            )
            .await?;
        Ok(out.published_to)
    }
}

/// Leading zero bits of a 128-bit distance (the shared-prefix length with the
/// target); higher means a closer node.
fn leading_zero_bits(d: &Kad128) -> u32 {
    let w = d.words();
    for (i, word) in w.iter().enumerate() {
        if *word != 0 {
            return i as u32 * 32 + word.leading_zeros();
        }
    }
    128
}

/// The result of a source-resolution attempt, with lookup diagnostics so a live
/// run is legible even when a hash currently has no published sources.
#[derive(Debug, Default)]
pub struct ResolveOutcome {
    /// Sources found (empty if the hash has no current Kad sources).
    pub sources: Vec<Source>,
    /// FIND_NODE requests sent during the lookup.
    pub nodes_queried: usize,
    /// FIND_NODE requests that got a KADEMLIA2_RES back (live protocol proof).
    pub find_node_responses: usize,
    /// In-tolerance nodes we sent SEARCH_SOURCE_REQ to.
    pub nodes_searched: usize,
    /// SEARCH_SOURCE_REQs that got a KADEMLIA2_SEARCH_RES back.
    pub search_responses: usize,
    /// Shared-prefix bits between the hash and the closest node the lookup found.
    pub closest_prefix_bits: u32,
    /// For a PUBLISH walk: how many nodes acknowledged the STORE (a
    /// KADEMLIA2_PUBLISH_RES). This IS the publish's result - "stored at N
    /// nodes" - and drives its termination at [`KAD_PUBLISH_STORE_TOTAL`].
    pub published_to: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_ip_uses_the_big_endian_view_confirmed_live() {
        // A nodes.dat contact: wire bytes FA 07 06 05 -> read_u32 LE
        // 0x050607FA -> the IP is 5.6.7.250 (a valid public host), NOT the
        // byte-reversed 250.7.6.5 (reserved). This convention is what made the
        // live Wave-6 bootstrap gate pass. The address is SYNTHETIC but keeps
        // the property the captured one had - reversing it lands in reserved
        // space, which is how the original bug announced itself.
        let ip: u32 = 0x0506_07FA;
        let addr = contact_addr(ip, 4672);
        assert_eq!(addr, "5.6.7.250:4672".parse().unwrap());
        // Round-trips back to the same host-order u32 the record stored.
        assert_eq!(ip_u32(&addr), ip);
    }

    #[test]
    fn ip_u32_round_trips_an_arbitrary_v4() {
        let addr: SocketAddr = "203.0.113.7:1234".parse().unwrap();
        assert_eq!(contact_addr(ip_u32(&addr), 1234), addr);
    }

    // Faithful mock-peer helpers for the receiver-key tests: they play the real
    // responder role (interop-test-fidelity), not a same-role echo.
    use mule_kad::{
        build_bootstrap_res, build_hello_res, kad_obfuscate_response, udp_verify_key,
        OP_HELLO_RES_ACK,
    };

    /// A test KadContact addressed at a mock peer.
    fn test_contact(id: Kad128, addr: SocketAddr) -> KadContact {
        KadContact {
            id,
            ip: ip_u32(&addr),
            udp_port: addr.port(),
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            verified: false,
        }
    }

    #[tokio::test]
    async fn the_kad_socket_sets_reuse_address_so_a_resume_can_rebind_its_fixed_port() {
        // padMule binds a FIXED Kad UDP port; pause() drops the KadNode (closing
        // the socket) and resume() rebinds that same port - a HARD lifecycle
        // requirement. aMule had to set SO_REUSEADDR for exactly this
        // (LibSocketAsio.cpp:1447-1456, PR #121: "without this Kad and the ed2k
        // client UDP stay broken until the user restarts amule"), and tokio's
        // UdpSocket::bind does NOT set it (its TcpListener::bind does, which is
        // why only the Kad socket was exposed). A clean drop frees a UDP port
        // anyway - the case this covers is iPadOS reclaiming the socket WITHOUT
        // a clean close, which is what a background/foreground cycle can do.
        let node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([1, 1, 1, 1]),
            0x1234,
        )
        .await
        .unwrap();
        assert!(
            socket2::SockRef::from(&*node.socket)
                .reuse_address()
                .unwrap(),
            "the Kad UDP socket must set SO_REUSEADDR"
        );
    }

    /// THE POINT OF `request_batch`: its members are CONCURRENT, not
    /// batched-then-awaited.
    ///
    /// Three silent destinations at a 400ms per-query wait. Serially that is
    /// three timeouts back to back (~1.2s); one window is ~0.4s. The lookups
    /// no longer come through here (they run event-driven per-request
    /// deadlines), but bootstrap does, and `bootstrap_any` walks candidates
    /// serially on top of this - re-serialising the batch would multiply that
    /// walk by ALPHA again.
    ///
    /// It fails by TIMING rather than by assertion, which is the only way this
    /// regression can show itself: re-serialising the sends breaks nothing
    /// functionally, it just makes everything slow again.
    #[tokio::test]
    async fn a_batch_of_silent_peers_costs_one_window_not_one_per_peer() {
        let node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([7, 7, 7, 7]),
            0xABCD,
        )
        .await
        .unwrap();
        // Real bound sockets that simply never answer: an unbound port would draw
        // an ICMP unreachable and measure error handling instead of the wait.
        let mut dests = Vec::new();
        let mut _held = Vec::new();
        for _ in 0..3 {
            let s = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            dests.push(s.local_addr().unwrap());
            _held.push(s);
        }
        let (op, payload) = build_bootstrap_req();
        let frame = pack_kad(op, payload);
        let reqs: Vec<(Kad128, SocketAddr, Vec<u8>)> = dests
            .iter()
            .map(|d| (Kad128::from_hash(&[0x11; 16]), *d, frame.clone()))
            .collect();

        let wait = Duration::from_millis(400);
        let t0 = std::time::Instant::now();
        let answers = node.request_batch(&reqs, OP_BOOTSTRAP_RES, wait).await;
        let elapsed = t0.elapsed();

        assert_eq!(answers.len(), 3);
        assert!(
            answers.iter().all(|a| a.is_err()),
            "nobody answered, so every slot must report a timeout"
        );
        assert!(
            elapsed < wait * 2,
            "three silent peers took {elapsed:?} for a {wait:?} window - the batch \
             is being awaited one peer at a time again"
        );
    }

    /// THE RISK the concurrency creates: one socket, several replies. A datagram
    /// must reach the slot that asked for it. Two peers answer in the OPPOSITE
    /// order to the one they were asked in, so a loop that simply filled slots as
    /// answers arrived would swap them and every caller would attribute one node's
    /// contacts to another - silently, since both answers are well-formed.
    #[tokio::test]
    async fn a_batch_matches_each_reply_to_the_peer_that_sent_it() {
        let our_id = Kad128::from_words([4, 4, 4, 4]);
        let node = KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x99)
            .await
            .unwrap();

        // Each mock answers with its OWN tcp_port, which is what identifies whose
        // answer landed where. The second one replies FIRST.
        let mut dests = Vec::new();
        let mut mocks = Vec::new();
        for (i, delay_ms) in [200u64, 20].into_iter().enumerate() {
            let peer_id = Kad128::from_hash(&[0xA0 + i as u8; 16]);
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            dests.push(peer.local_addr().unwrap());
            let tcp_port = 5000 + i as u16;
            mocks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let (n, from) = peer.recv_from(&mut buf).await.unwrap();
                let dec = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)).unwrap();
                tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                let (rop, rpayload) = build_bootstrap_res(&peer_id, tcp_port, 8, &[]);
                let dg = kad_obfuscate_response(
                    &pack_kad(rop, rpayload),
                    0x2468,
                    dec.sender_vk,
                    0,
                    0x80,
                );
                peer.send_to(&dg, from).await.unwrap();
            }));
        }

        let (op, payload) = build_bootstrap_req();
        let frame = pack_kad(op, payload);
        let reqs: Vec<(Kad128, SocketAddr, Vec<u8>)> = dests
            .iter()
            .enumerate()
            .map(|(i, d)| (Kad128::from_hash(&[0xA0 + i as u8; 16]), *d, frame.clone()))
            .collect();

        // 10s, not 3s (8cs): the window only bounds the WAIT for both replies -
        // the demux property under test is timing-free - and full-suite load
        // once pushed a loopback reply past 3s.
        let answers = node
            .request_batch(&reqs, OP_BOOTSTRAP_RES, Duration::from_secs(10))
            .await;

        for (i, answer) in answers.into_iter().enumerate() {
            let (payload, valid, _) = answer.expect("both peers answered inside the window");
            let res = parse_bootstrap_res(&payload).unwrap();
            assert_eq!(
                res.tcp_port,
                5000 + i as u16,
                "slot {i} got another peer's reply - the batch demux is matching \
                 datagrams to the wrong request"
            );
            assert!(
                valid,
                "each peer echoed the sender key issued for ITS address"
            );
        }
        for m in mocks {
            m.await.unwrap();
        }
    }

    #[tokio::test]
    async fn request_reports_a_valid_receiver_key_when_the_peer_echoes_our_sender_key() {
        // A real v2 node decrypts our request, reads the sender verify key we
        // issued for its IP, and echoes it back as the receiver key of a
        // receiver-keyed response. request() must report bValidReceiverKey = true.
        let our_key = 0x1234_5678u32;
        let our_id = Kad128::from_words([9, 9, 9, 9]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, our_key)
                .await
                .unwrap();
        let peer_id = Kad128::from_hash(&[0x55; 16]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, from) = peer.recv_from(&mut buf).await.unwrap();
            // The peer decrypts our request keyed on its OWN id, learning our
            // sender verify key, then echoes it in a receiver-keyed response.
            let dec = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)).unwrap();
            let (rop, rpayload) = build_bootstrap_res(&peer_id, 4662, 8, &[]);
            let rframe = pack_kad(rop, rpayload);
            let dg = kad_obfuscate_response(&rframe, 0x2468, dec.sender_vk, 0, 0x80);
            peer.send_to(&dg, from).await.unwrap();
        });

        let (op, payload) = build_bootstrap_req();
        let frame = pack_kad(op, payload);
        // 10s, not 2s - the scaffold, not the subject. What this test asserts is
        // that a peer echoing our sender key yields `valid`; how long the
        // loopback round trip takes is incidental, and a tight budget turned a
        // busy machine into a red suite roughly once in six full runs while the
        // test passed 15/15 in isolation. Still bounded, so a peer that never
        // answers still fails it.
        let (_res, valid, _sk) = node
            .request(
                &peer_id,
                peer_addr,
                &frame,
                OP_BOOTSTRAP_RES,
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        assert!(
            valid,
            "the peer echoed our sender key -> receiver key is valid"
        );
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn request_reports_an_invalid_receiver_key_for_a_nodeid_path_forgery() {
        // An off-path attacker who knows only our (semi-public) KadID can craft a
        // response that decrypts via the NodeID path, but cannot know the verify
        // key derived from our secret UDP key - so its receiver key is wrong and
        // request() must report bValidReceiverKey = false (the contact will be
        // recorded UNVERIFIED, matching eMule - the packet is still processed).
        let our_key = 0xDEAD_BEEFu32;
        let our_id = Kad128::from_words([1, 2, 3, 4]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, our_key)
                .await
                .unwrap();
        let peer_id = Kad128::from_hash(&[0x66; 16]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (_n, from) = peer.recv_from(&mut buf).await.unwrap();
            // Forge a NodeID-path response keyed on our KadID with a bogus
            // receiver key (the attacker cannot derive the real one).
            let (rop, rpayload) = build_bootstrap_res(&peer_id, 4662, 8, &[]);
            let rframe = pack_kad(rop, rpayload);
            let dg =
                mule_kad::kad_obfuscate_request(&rframe, &our_id, 0x1111, 0xBADD_0000, 0, 0x40);
            peer.send_to(&dg, from).await.unwrap();
        });

        let (op, payload) = build_bootstrap_req();
        let frame = pack_kad(op, payload);
        let (_res, valid, _sk) = node
            .request(
                &peer_id,
                peer_addr,
                &frame,
                OP_BOOTSTRAP_RES,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(!valid, "a NodeID-path forgery has no valid receiver key");
        mock.await.unwrap();

        // Silence the unused-import warning when only one test path uses it.
        let _ = udp_verify_key(our_key, 0);
    }

    /// The sender verify key the mock storing node hands us, which the search
    /// path must capture for the send-side echo.
    const MOCK_SENDER_VK: u32 = 0xFEED_F00D;

    /// A faithful storing-node mock: it answers the lookup's FIND_NODE with an
    /// EMPTY contact list - a real node always answers KADEMLIA2_REQ, and the
    /// event-driven lookup, like eMule's JumpStart walk, only ever value-asks
    /// a node that RESPONDED to its FIND (a tried-unresponded entry is erased
    /// unasked, Search.cpp:330-340) - and then answers the search opcodes.
    /// Loops rather than serving one datagram, and is aborted by the caller.
    fn spawn_search_only_mock(
        peer: UdpSocket,
        peer_id: Kad128,
        target: Kad128,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let Ok((n, from)) = peer.recv_from(&mut buf).await else {
                    return;
                };
                let Some(dec) = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)) else {
                    continue;
                };
                let Ok((op, _)) = unpack_kad(&dec.payload) else {
                    continue;
                };
                let (rop, rpayload) = if op == mule_kad::OP_KAD2_REQ {
                    // "I know nobody closer" - the honest answer of the node
                    // closest to the target.
                    mule_kad::build_kad2_res(&target, &[])
                } else if op == mule_kad::OP_SEARCH_SOURCE_REQ || op == mule_kad::OP_SEARCH_KEY_REQ
                {
                    mule_kad::build_search_res(&peer_id, &target, &[])
                } else {
                    continue;
                };
                let dg = kad_obfuscate_response(
                    &pack_kad(rop, rpayload),
                    0x2468,
                    dec.sender_vk,
                    MOCK_SENDER_VK,
                    0x80,
                );
                let _ = peer.send_to(&dg, from).await;
            }
        })
    }

    #[tokio::test]
    async fn resolve_sources_stores_the_searched_nodes_sender_key() {
        // A node we only ever SEARCH must still get its sender key captured, or
        // the send-side echo never fires for it (2026-08-02 reanalysis gap c-1).
        //
        // Driven through the PUBLIC path rather than the request helper. The
        // capture moved out of that helper when the search went concurrent - the
        // batch collects with `&self` and the CALLER applies `note_responder` - so
        // a test that called the helper and then stored the key itself would pass
        // with the production call site deleted. Mutation-checked: drop the
        // `note_responder` line from `resolve_sources` and this fails.
        let our_id = Kad128::from_words([3, 3, 3, 3]);
        let our_ip = 0x0A00_0001u32;
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x2222)
                .await
                .unwrap();
        node.set_public_ip(our_ip);
        let target = Kad128::from_hash(&[0x44; 16]);
        // Share the target's top bits so the node is inside the storage tolerance
        // and the source phase actually asks it.
        let w = target.words();
        let peer_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3]]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let peer_ip = ip_u32(&peer_addr);
        // Seeded straight into the table: `closest_to` hands out VERIFIED contacts
        // only, and this stands in for one a live lookup had already proved.
        node.with_routing(|t| t.add(peer_id, peer_ip, peer_addr.port(), 4662, 8, true));
        let mock = spawn_search_only_mock(peer, peer_id, target);

        // 10s, not 300ms (8cs): the window only bounds the WAIT for the mock's
        // replies - the property is the stored sender key, not latency - and a
        // loaded box can push a loopback reply past a 300ms-class budget.
        node.resolve_sources(&target, 1000, 1, Duration::from_secs(10))
            .await
            .unwrap();
        mock.abort();
        assert_eq!(
            node.with_routing(|t| t.verify_key_for(&peer_id, peer_ip, our_ip)),
            MOCK_SENDER_VK,
            "resolve_sources stored the searched node's sender key"
        );
    }

    /// A storing-node mock for the PUBLISH driver: answers FIND_NODE with an
    /// empty contact list (so the walk value-asks it, like the search mocks),
    /// then answers a PUBLISH_KEY_REQ / PUBLISH_SOURCE_REQ with a PUBLISH_RES
    /// carrying a load byte. Records the opcode it stored so the test can prove
    /// the RIGHT store went out, not just that something did.
    fn spawn_publish_mock(
        peer: UdpSocket,
        peer_id: Kad128,
        target: Kad128,
        got_key: Arc<std::sync::atomic::AtomicBool>,
        got_source: Arc<std::sync::atomic::AtomicBool>,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let Ok((n, from)) = peer.recv_from(&mut buf).await else {
                    return;
                };
                let Some(dec) = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)) else {
                    continue;
                };
                let Ok((op, body)) = unpack_kad(&dec.payload) else {
                    continue;
                };
                let (rop, rpayload) = if op == mule_kad::OP_KAD2_REQ {
                    mule_kad::build_kad2_res(&target, &[])
                } else if op == mule_kad::OP_PUBLISH_KEY_REQ
                    || op == mule_kad::OP_PUBLISH_SOURCE_REQ
                {
                    if op == mule_kad::OP_PUBLISH_KEY_REQ {
                        got_key.store(true, Ordering::Relaxed);
                    } else {
                        got_source.store(true, Ordering::Relaxed);
                    }
                    // PUBLISH_RES: file 16 | load u8. The file id is the first
                    // 16 bytes of the request body for either publish shape.
                    let mut res = body[..16.min(body.len())].to_vec();
                    res.resize(16, 0);
                    res.push(40); // load factor
                    (mule_kad::OP_PUBLISH_RES, res)
                } else {
                    continue;
                };
                let dg = kad_obfuscate_response(
                    &pack_kad(rop, rpayload),
                    0x2468,
                    dec.sender_vk,
                    MOCK_SENDER_VK,
                    0x80,
                );
                let _ = peer.send_to(&dg, from).await;
            }
        })
    }

    #[tokio::test]
    async fn publish_keyword_stores_at_a_node_and_counts_the_ack() {
        let our_id = Kad128::from_words([5, 5, 5, 7]);
        let our_ip = 0x0A00_0001u32;
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x9999)
                .await
                .unwrap();
        node.set_public_ip(our_ip);
        let target = kad_keyword_target("ubuntu");
        let w = target.words();
        let peer_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3]]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        node.with_routing(|t| t.add(peer_id, ip_u32(&peer_addr), peer_addr.port(), 4662, 8, true));
        let got_key = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let got_source = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mock = spawn_publish_mock(
            peer,
            peer_id,
            target,
            Arc::clone(&got_key),
            Arc::clone(&got_source),
        );
        let entries = vec![KeywordEntry {
            file_id: Kad128::from_hash(&[0xBB; 16]),
            name: "ubuntu.iso".to_string(),
            size: 1000,
            complete_sources: 1,
            file_type: "Iso".to_string(),
        }];
        let stored = node
            // 10s, not 300ms (8cs): a loaded box can make the FIND reply miss a
            // tight window, and then the store is never asked - the publish_source
            // twin flaked exactly so; timing is not the subject here.
            .publish_keyword(&target, &entries, Duration::from_secs(10))
            .await
            .unwrap();
        mock.abort();
        assert!(
            got_key.load(Ordering::Relaxed),
            "a PUBLISH_KEY_REQ went out"
        );
        assert_eq!(stored, 1, "the storing node's ack was counted");
    }

    #[tokio::test]
    async fn publish_source_stores_at_a_node_and_counts_the_ack() {
        let our_id = Kad128::from_words([5, 5, 5, 8]);
        let our_ip = 0x0A00_0001u32;
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0xAAAA)
                .await
                .unwrap();
        node.set_public_ip(our_ip);
        let target = Kad128::from_hash(&[0x77; 16]);
        let w = target.words();
        let peer_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3]]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        node.with_routing(|t| t.add(peer_id, ip_u32(&peer_addr), peer_addr.port(), 4662, 8, true));
        let got_key = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let got_source = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mock = spawn_publish_mock(
            peer,
            peer_id,
            target,
            Arc::clone(&got_key),
            Arc::clone(&got_source),
        );
        let stored = node
            .publish_source(
                &target,
                our_id,
                SourceEntry {
                    size: 1000,
                    tcp_port: 4662,
                    udp_port: Some(4672),
                    crypt: 0,
                },
                // 10s, not 300ms (8cs): a loaded box made the FIND reply miss the
                // window once, so the store was never asked; timing is not the
                // subject here and the walk still terminates on exhaustion.
                Duration::from_secs(10),
            )
            .await
            .unwrap();
        mock.abort();
        assert!(
            got_source.load(Ordering::Relaxed),
            "a PUBLISH_SOURCE_REQ went out"
        );
        assert_eq!(stored, 1, "the storing node's ack was counted");
    }

    #[tokio::test]
    async fn resolve_keyword_stores_the_searched_nodes_sender_key() {
        // The keyword twin of the gap above, through the same public path.
        let our_id = Kad128::from_words([4, 4, 4, 4]);
        let our_ip = 0x0A00_0001u32;
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x3333)
                .await
                .unwrap();
        node.set_public_ip(our_ip);
        // The target is the KEYWORD's hash - the search picks it, not the test.
        let target = kad_keyword_target("minister");
        let w = target.words();
        let peer_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3]]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let peer_ip = ip_u32(&peer_addr);
        node.with_routing(|t| t.add(peer_id, peer_ip, peer_addr.port(), 4662, 8, true));
        let mock = spawn_search_only_mock(peer, peer_id, target);

        // 10s, not 300ms (8cs): same wait-not-property shape as the sources twin
        // above - the assert is the stored sender key, and the walk still ends
        // by exhaustion, so the headroom costs nothing on a passing run.
        node.resolve_keyword("minister", 1, Duration::from_secs(10))
            .await
            .unwrap();
        mock.abort();
        assert_eq!(
            node.with_routing(|t| t.verify_key_for(&peer_id, peer_ip, our_ip)),
            MOCK_SENDER_VK,
            "resolve_keyword stored the searched node's sender key"
        );
    }

    // ---- the event-driven lookup's live-layer behaviours ----

    /// A wire contact at a chosen IP, for the answer-filter tests.
    fn wc(seed: u8, ip: u32) -> WireContact {
        WireContact {
            id: Kad128::from_hash(&[seed; 16]),
            ip,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
        }
    }

    /// eMule's per-answer subnet rule, following ITS CODE not its comment: the
    /// comment at Search.cpp:457 says "/28 subnet" but the mask is 0xFFFFFF00,
    /// which is a /24.
    #[test]
    fn an_answer_may_name_at_most_two_contacts_per_public_slash24() {
        let kept = frontier_filter(
            u32::from(Ipv4Addr::new(198, 51, 100, 1)),
            vec![
                wc(1, u32::from(Ipv4Addr::new(203, 0, 113, 1))),
                wc(2, u32::from(Ipv4Addr::new(203, 0, 113, 2))),
                wc(3, u32::from(Ipv4Addr::new(203, 0, 113, 3))),
            ],
        );
        assert_eq!(
            kept.len(),
            2,
            "the third contact in one public /24 must be dropped from the \
             frontier (Search.cpp:458-473)"
        );
    }

    /// The responder's own subnet is pre-seeded at count 1 (Search.cpp:424),
    /// so its /24 admits only ONE listed contact, not two.
    #[test]
    fn the_responders_own_slash24_starts_at_one() {
        let kept = frontier_filter(
            u32::from(Ipv4Addr::new(203, 0, 113, 9)),
            vec![
                wc(1, u32::from(Ipv4Addr::new(203, 0, 113, 1))),
                wc(2, u32::from(Ipv4Addr::new(203, 0, 113, 2))),
            ],
        );
        assert_eq!(kept.len(), 1);
    }

    /// LAN ranges are exempt from the subnet cap (Search.cpp:458, IsLANIP) -
    /// which is also what keeps offline rigs on RFC1918 addresses honest.
    #[test]
    fn lan_addresses_are_exempt_from_the_subnet_cap() {
        let kept = frontier_filter(
            u32::from(Ipv4Addr::new(198, 51, 100, 1)),
            vec![wc(1, 0x0A00_0001), wc(2, 0x0A00_0002), wc(3, 0x0A00_0003)],
        );
        assert_eq!(kept.len(), 3);
    }

    /// The rules that predate the /24 cap: a node may not answer with itself,
    /// and may not list one IP twice (Search.cpp:423/449).
    #[test]
    fn the_responders_ip_and_duplicate_ips_are_dropped() {
        let kept = frontier_filter(
            u32::from(Ipv4Addr::new(198, 51, 100, 1)),
            vec![
                wc(1, u32::from(Ipv4Addr::new(198, 51, 100, 1))), // itself
                wc(2, u32::from(Ipv4Addr::new(203, 0, 113, 5))),
                wc(3, u32::from(Ipv4Addr::new(203, 0, 113, 5))), // duplicate
            ],
        );
        assert_eq!(kept.len(), 1);
    }

    /// THE SPLIT eMule actually has, pinned: one answer feeds the ROUTING
    /// TABLE through the table's own gates (Process_KADEMLIA2_RES calls
    /// AddUnfiltered for every basically-acceptable contact,
    /// KademliaUDPListener.cpp:846) while the SEARCH FRONTIER faces the
    /// stricter per-answer rules. A test that only checked the frontier would
    /// pass with the table starved - the regression this one exists to
    /// prevent, because a starved table is every FUTURE lookup's seed list.
    #[tokio::test]
    async fn one_answer_feeds_the_table_fully_and_the_frontier_capped() {
        let mut node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([5, 5, 5, 5]),
            0x4444,
        )
        .await
        .unwrap();
        let responder = wc(0xAA, u32::from(Ipv4Addr::new(198, 51, 100, 7)));
        let contacts: Vec<WireContact> = (1u8..=4)
            .map(|i| wc(i, u32::from(Ipv4Addr::new(203, 0, 113, i))))
            .collect();
        let frontier = node.absorb_find_answer(&responder, false, 0, contacts.clone());
        for c in &contacts {
            assert!(
                node.with_routing(|t| t.contains(&c.id)),
                "the table must keep every contact that passes ITS OWN gates - \
                 four distinct public IPs in one /24 are within the table's \
                 MAX_CONTACTS_PER_SUBNET"
            );
        }
        assert_eq!(
            frontier.len(),
            2,
            "the frontier sees at most 2 of the four (the per-answer /24 rule)"
        );
    }

    /// THE EVENT-DRIVEN CORE, live on the wire: a value ask goes out and is
    /// ANSWERED while a silent peer's FIND_NODE is still in flight. The
    /// round-based lookup could not start its value phase until the silent
    /// peer's window expired, so this whole resolve took at least one
    /// `per_query`; event-driven it finishes in milliseconds. The margin
    /// (a 3s per-request deadline against a 1.5s assert) is wide enough for a
    /// loaded test host.
    #[tokio::test]
    async fn a_value_ask_is_answered_while_a_silent_find_is_still_in_flight() {
        let our_id = Kad128::from_words([8, 8, 8, 8]);
        let our_ip = 0x0A00_0001u32;
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x5555)
                .await
                .unwrap();
        node.set_public_ip(our_ip);
        let target = Kad128::from_hash(&[0x66; 16]);
        let w = target.words();
        // M: in tolerance and CLOSER than S; answers the FIND (empty) and then
        // the source ask, with one HighID source.
        let m_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3]]);
        // S: in the frontier but FARTHER, and silent forever.
        let s_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3] ^ 0xFFFF]);
        let m_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let m_addr = m_sock.local_addr().unwrap();
        let s_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s_addr = s_sock.local_addr().unwrap();
        node.with_routing(|t| {
            t.add(m_id, ip_u32(&m_addr), m_addr.port(), 4662, 8, true);
            t.add(s_id, ip_u32(&s_addr), s_addr.port(), 4662, 8, true);
        });
        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let Ok((n, from)) = m_sock.recv_from(&mut buf).await else {
                    return;
                };
                let Some(dec) = kad_deobfuscate(&buf[..n], &m_id, 0, ip_u32(&from)) else {
                    continue;
                };
                let Ok((op, _)) = unpack_kad(&dec.payload) else {
                    continue;
                };
                let (rop, rpayload) = if op == mule_kad::OP_KAD2_REQ {
                    mule_kad::build_kad2_res(&target, &[])
                } else if op == mule_kad::OP_SEARCH_SOURCE_REQ {
                    let result = mule_kad::SearchResult {
                        answer: Kad128::from_hash(&[0x77; 16]),
                        tags: vec![
                            mule_kad::KadTag {
                                name: mule_kad::TAG_SOURCETYPE,
                                value: mule_kad::KadTagValue::Int(1),
                            },
                            mule_kad::KadTag {
                                name: mule_kad::TAG_SOURCEPORT,
                                value: mule_kad::KadTagValue::Int(4662),
                            },
                        ],
                    };
                    mule_kad::build_search_res(&m_id, &target, &[result])
                } else {
                    continue;
                };
                let dg = kad_obfuscate_response(
                    &pack_kad(rop, rpayload),
                    0x2468,
                    dec.sender_vk,
                    MOCK_SENDER_VK,
                    0x80,
                );
                let _ = m_sock.send_to(&dg, from).await;
            }
        });

        let ttfr0 = crate::stats::kad_first_results();
        let t0 = std::time::Instant::now();
        let out = node
            .resolve_sources(&target, 1000, 1, Duration::from_secs(3))
            .await
            .unwrap();
        let elapsed = t0.elapsed();
        mock.abort();
        drop(s_sock); // held silent until here so no ICMP shortcut
        assert_eq!(out.sources.len(), 1, "M's source came back");
        assert!(
            elapsed < Duration::from_millis(1500),
            "took {elapsed:?}: the value ask waited for the silent peer's \
             deadline - the round barrier is back"
        );
        assert!(
            crate::stats::kad_first_results() > ttfr0,
            "time to first result must move with a lookup that found something"
        );
    }

    /// MUTEX POISONING (handoff #35a). Every `KadNode` lock sits on the inbound
    /// UDP path: `run_read_loop` takes `pending`, `flood`, `hello_res_sent`,
    /// `ip_filter` and `routing` for EVERY datagram a stranger sends us. A panic
    /// under any of them would kill the Kad node for the app's life - and
    /// `SlotGuard::drop` takes `pending`, so a poisoned lock would panic
    /// mid-unwind and ABORT the process. Recovery is safe because all five guard
    /// self-healing bookkeeping: the routing table ages, re-probes and evicts;
    /// a leaked pending slot times out; flood counters and the ack-solicited
    /// window are per-minute soft state; `ip_filter` is one `Arc` swap.
    #[tokio::test]
    async fn a_panic_under_a_kad_lock_leaves_the_node_working() {
        let node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([3, 5, 7, 9]),
            0x3579,
        )
        .await
        .unwrap();
        // `flood` / `hello_res_sent` live on the read loop, not the node, so
        // drive their free functions directly - which is the same code the
        // loop calls per datagram.
        let flood: Mutex<HashMap<u8, FloodTracker>> = Mutex::new(HashMap::new());
        let sent: Mutex<HashMap<u32, StdInstant>> = Mutex::new(HashMap::new());
        crate::lock::poison_for_test(&node.routing);
        crate::lock::poison_for_test(&node.ip_filter);
        crate::lock::poison_for_test(&node.pending);
        crate::lock::poison_for_test(&flood);
        crate::lock::poison_for_test(&sent);

        // The gated insert path - the ONLY way a contact enters the table -
        // still takes both the filter and the routing lock and still inserts.
        let c = WireContact {
            id: Kad128::from_hash(&[0x77; 16]),
            ip: 0x0808_0808,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
        };
        gated_add_contact(&node.routing, &node.ip_filter, &c, true, true, 10);
        assert_eq!(node.contacts_known(), 1, "the contact still went in");
        assert_eq!(node.closest_wire_contacts(&c.id, 4).len(), 1);
        node.set_ip_filter(None);

        // The per-datagram gates still answer, and the pending SlotGuard's Drop
        // - the abort path - runs clean.
        let now = StdInstant::now();
        assert!(flood_allows(&flood, mule_kad::OP_PING, 0x0808_0808, now));
        note_hello_res_sent(&sent, 0x0808_0808, now);
        assert!(take_hello_res_sent(&sent, 0x0808_0808, now));
        {
            let mut guard = SlotGuard::new(Arc::clone(&node.pending));
            guard.track(1);
        }
        // Read back WITHOUT the production helper, so this is an independent
        // witness rather than a restatement of the fix.
        assert!(node
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_empty());
    }

    /// `request_batch` is CANCELLED in production - the 5s `start_kad` timeout
    /// wraps `bootstrap_any`, whose structural worst case is ~48s, so the
    /// cancellation is the NORMAL path there - and a cancelled future never
    /// reaches a trailing withdraw statement. A stale slot is a misdirection,
    /// not a leak: it sits at the FRONT of `pending`, wins the IP-fallback
    /// match, and swallows the next reply from that peer into a receiver
    /// nobody holds. The lookup path got `SlotGuard` for exactly this; this
    /// pins the batch path's guard.
    #[tokio::test]
    async fn a_cancelled_request_batch_withdraws_its_pending_slots() {
        let node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([6, 6, 6, 6]),
            0x6666,
        )
        .await
        .unwrap();
        // A bound socket nobody reads: the sends land somewhere real and are
        // never answered, so the batch sits in its wait window until cancelled.
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = silent.local_addr().unwrap();
        let (op, payload) = mule_kad::build_ping();
        let reqs: Vec<(Kad128, SocketAddr, Vec<u8>)> = (0..3u32)
            .map(|i| {
                (
                    Kad128::from_words([9, 9, 9, i]),
                    dest,
                    pack_kad(op, payload.clone()),
                )
            })
            .collect();
        // Cancel mid-window, exactly as the start_kad timeout does. The 300ms
        // is generous: the batch only needs microseconds to REGISTER its slots
        // on loopback, and the window it would otherwise wait is 5s.
        tokio::select! {
            _ = node.request_batch(&reqs, mule_kad::OP_PONG, Duration::from_secs(5)) => {
                panic!("three silent peers cannot complete the batch inside the test");
            }
            () = tokio::time::sleep(Duration::from_millis(300)) => {}
        }
        assert!(
            node.pending.lock_recover().is_empty(),
            "a cancelled batch must withdraw its pending slots on drop"
        );
    }

    /// ONE datagram must not dominate a source search: `parse_search_res`
    /// reads up to 65535 results and the dedupe is a linear scan per result,
    /// so an uncapped ingest hands a single hostile reply O(n^2) work and the
    /// whole result set. eMule caps by SEARCH TOTAL, outside the parser:
    /// `SEARCHFINDSOURCE_TOTAL` = 20 (Defines.h:68), enforced at
    /// Search.cpp:986 (`m_uAnswers > SEARCHFINDSOURCE_TOTAL` ->
    /// `PrepareToStop`). padMule enforces the same total at ACCUMULATION,
    /// which also stops mid-datagram - stricter than eMule's periodic sweep,
    /// the same stricter stance the over-long FIND answer already gets.
    #[tokio::test]
    async fn one_datagram_cannot_push_a_source_search_past_the_search_total() {
        let our_id = Kad128::from_words([5, 5, 5, 5]);
        let our_ip = 0x0A00_0001u32;
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x7777)
                .await
                .unwrap();
        node.set_public_ip(our_ip);
        let target = Kad128::from_hash(&[0x55; 16]);
        let w = target.words();
        let peer_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3]]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        node.with_routing(|t| t.add(peer_id, ip_u32(&peer_addr), peer_addr.port(), 4662, 8, true));
        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let Ok((n, from)) = peer.recv_from(&mut buf).await else {
                    return;
                };
                let Some(dec) = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)) else {
                    continue;
                };
                let Ok((op, _)) = unpack_kad(&dec.payload) else {
                    continue;
                };
                let (rop, rpayload) = if op == mule_kad::OP_KAD2_REQ {
                    mule_kad::build_kad2_res(&target, &[])
                } else if op == mule_kad::OP_SEARCH_SOURCE_REQ {
                    // 25 DISTINCT sources in one reply - five past the total.
                    let results: Vec<mule_kad::SearchResult> = (0..25u32)
                        .map(|i| mule_kad::SearchResult {
                            answer: Kad128::from_words([0x77, 0, 0, i]),
                            tags: vec![
                                mule_kad::KadTag {
                                    name: mule_kad::TAG_SOURCETYPE,
                                    value: mule_kad::KadTagValue::Int(1),
                                },
                                mule_kad::KadTag {
                                    name: mule_kad::TAG_SOURCEPORT,
                                    value: mule_kad::KadTagValue::Int(4662),
                                },
                            ],
                        })
                        .collect();
                    mule_kad::build_search_res(&peer_id, &target, &results)
                } else {
                    continue;
                };
                let dg = kad_obfuscate_response(
                    &pack_kad(rop, rpayload),
                    0x2468,
                    dec.sender_vk,
                    MOCK_SENDER_VK,
                    0x80,
                );
                let _ = peer.send_to(&dg, from).await;
            }
        });
        // 10s, not 300ms (8cs): under full-suite load the big reply once missed
        // the window entirely (left 0, right 20); the cap under test is about
        // COUNT, not latency, and the search still stops at the total.
        let out = node
            .resolve_sources(&target, 1000, 1000, Duration::from_secs(10))
            .await
            .unwrap();
        mock.abort();
        assert_eq!(
            out.sources.len(),
            KAD_SEARCH_SOURCE_TOTAL,
            "the search total caps what one reply can contribute"
        );
    }

    /// The keyword twin: `SEARCHKEYWORD_TOTAL` = 300 (Defines.h:61), enforced
    /// by `SearchManager::Process` comparing `GetAnswers() >=
    /// SEARCHKEYWORD_TOTAL` on its sweep (SearchManager.cpp:347). NOT
    /// Search.cpp:819 - that is the STORE path's cap of ten; the citation this
    /// project once got wrong.
    ///
    /// FIVE storing nodes of 70 results each (350 > 300) rather than one giant
    /// reply, because THIS BOX drops loopback UDP datagrams past ~1472 bytes:
    /// WSL2 mirrored networking discards fragmented loopback UDP while `lo`
    /// claims MTU 65536 (measured 2026-08-09 - 1400B delivered, 1473B gone).
    /// The cap under test is per SEARCH, not per datagram, so several sub-MTU
    /// replies exercise exactly the eMule shape.
    #[tokio::test]
    async fn replies_cannot_push_a_keyword_search_past_the_search_total() {
        let our_id = Kad128::from_words([5, 5, 5, 6]);
        let our_ip = 0x0A00_0001u32;
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x8888)
                .await
                .unwrap();
        node.set_public_ip(our_ip);
        let target = kad_keyword_target("minister");
        let w = target.words();
        let mut mocks = Vec::new();
        for m in 0..5u32 {
            let peer_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3] ^ m]);
            let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let peer_addr = peer.local_addr().unwrap();
            node.with_routing(|t| {
                t.add(peer_id, ip_u32(&peer_addr), peer_addr.port(), 4662, 8, true)
            });
            mocks.push(tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                loop {
                    let Ok((n, from)) = peer.recv_from(&mut buf).await else {
                        return;
                    };
                    let Some(dec) = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)) else {
                        continue;
                    };
                    let Ok((op, _)) = unpack_kad(&dec.payload) else {
                        continue;
                    };
                    let (rop, rpayload) = if op == mule_kad::OP_KAD2_REQ {
                        mule_kad::build_kad2_res(&target, &[])
                    } else if op == mule_kad::OP_SEARCH_KEY_REQ {
                        // 70 DISTINCT files per node, distinct ACROSS nodes.
                        // HIGH-entropy hashes on purpose: an all-zeros pattern
                        // compresses past the receiver's zlib-bomb bound
                        // (`frame.len() * 10 + 300`) and the whole reply is
                        // legitimately dropped; ~1.1KB of incompressible hash
                        // bytes keeps the ratio under 10x while the datagram
                        // stays under the loopback ceiling above.
                        let r = |k: u32| k.wrapping_mul(0x9E37_79B9).rotate_left(13) ^ 0xA5A5_5A5A;
                        let base = m * 0x0100_0000;
                        let results: Vec<mule_kad::SearchResult> = (0..70u32)
                            .map(|i| mule_kad::SearchResult {
                                answer: Kad128::from_words([
                                    r(base + i),
                                    r((base + i) ^ 0x1111),
                                    r((base + i) ^ 0x2222),
                                    r((base + i) ^ 0x3333),
                                ]),
                                tags: vec![
                                    mule_kad::KadTag {
                                        name: mule_kad::TAG_FILENAME,
                                        value: mule_kad::KadTagValue::Str(
                                            "minister sample.avi".into(),
                                        ),
                                    },
                                    mule_kad::KadTag {
                                        name: mule_kad::TAG_FILESIZE,
                                        value: mule_kad::KadTagValue::Int(1024),
                                    },
                                ],
                            })
                            .collect();
                        mule_kad::build_search_res(&peer_id, &target, &results)
                    } else {
                        continue;
                    };
                    let dg = kad_obfuscate_response(
                        &pack_kad(rop, rpayload),
                        0x2468,
                        dec.sender_vk,
                        MOCK_SENDER_VK,
                        0x80,
                    );
                    let _ = peer.send_to(&dg, from).await;
                }
            }));
        }
        // 10s, not 300ms (8cs): the assert is the 300-result accumulation CAP,
        // a count with no timing content; the window only bounds the wait for
        // five loopback replies, which full-suite load can push past 300ms.
        let files = node
            .resolve_keyword("minister", 1000, Duration::from_secs(10))
            .await
            .unwrap();
        for m in &mocks {
            m.abort();
        }
        assert_eq!(
            files.len(),
            KAD_SEARCH_KEYWORD_TOTAL,
            "the search total caps what the replies can contribute"
        );
    }

    /// A lookup whose only seed never answers ends when that request's OWN
    /// deadline fires and the candidates are exhausted - not at the overall
    /// deadline (16x per_query), and without an error: no sources is an
    /// answer.
    #[tokio::test]
    async fn a_lookup_over_only_silent_seeds_ends_at_the_per_request_deadline() {
        let mut node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([9, 9, 9, 9]),
            0x6666,
        )
        .await
        .unwrap();
        let target = Kad128::from_hash(&[0x21; 16]);
        let w = target.words();
        let s_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3]]);
        let s_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let s_addr = s_sock.local_addr().unwrap();
        node.with_routing(|t| t.add(s_id, ip_u32(&s_addr), s_addr.port(), 4662, 8, true));

        let per_query = Duration::from_millis(300);
        let t0 = std::time::Instant::now();
        let out = node
            .resolve_sources(&target, 1000, 5, per_query)
            .await
            .unwrap();
        let elapsed = t0.elapsed();
        drop(s_sock);
        assert!(out.sources.is_empty());
        assert_eq!(out.nodes_queried, 1);
        assert!(
            elapsed < per_query * 8,
            "took {elapsed:?}: exhaustion should end the lookup right after \
             the one per-request deadline, half the 16x overall deadline"
        );
    }

    /// eMule never value-asks a node that did not answer its FIND - the
    /// JumpStart walk erases a tried-unresponded entry unasked (Search.cpp:
    /// 330-340). The old round-based code DID ask such nodes; this pins the
    /// deliberate change, on the wire: the mock counts what actually reaches
    /// it.
    #[tokio::test]
    async fn a_node_that_never_answers_find_node_is_never_value_asked() {
        let mut node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([6, 6, 6, 6]),
            0x7777,
        )
        .await
        .unwrap();
        let target = Kad128::from_hash(&[0x33; 16]);
        let w = target.words();
        let peer_id = Kad128::from_words([w[0], w[1] ^ 1, w[2], w[3]]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        node.with_routing(|t| t.add(peer_id, ip_u32(&peer_addr), peer_addr.port(), 4662, 8, true));
        let asks = Arc::new(AtomicU64::new(0));
        let asks_seen = Arc::clone(&asks);
        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            loop {
                let Ok((n, from)) = peer.recv_from(&mut buf).await else {
                    return;
                };
                let Some(dec) = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)) else {
                    continue;
                };
                let Ok((op, _)) = unpack_kad(&dec.payload) else {
                    continue;
                };
                if op == mule_kad::OP_SEARCH_SOURCE_REQ {
                    asks_seen.fetch_add(1, Ordering::Relaxed);
                }
                // Answers NOTHING - a FIND left unanswered is the case.
            }
        });

        let out = node
            .resolve_sources(&target, 1000, 1, Duration::from_millis(250))
            .await
            .unwrap();
        mock.abort();
        assert_eq!(out.nodes_searched, 0, "we must not even send the ask");
        assert_eq!(
            asks.load(Ordering::Relaxed),
            0,
            "a SEARCH_SOURCE_REQ reached a node that never answered our FIND"
        );
    }

    #[tokio::test]
    async fn request_echoes_a_stored_verify_key_ip_bound() {
        // The send-side: once we hold the key a peer handed us (minted against our
        // current public IP), the next request ECHOES it in receiver_vk so the peer
        // can verify US. A faithful loopback peer reads back that field.
        let our_id = Kad128::from_words([7, 7, 7, 7]);
        let our_ip = 0x0A00_0001u32;
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x1111)
                .await
                .unwrap();
        node.set_public_ip(our_ip);

        let peer_id = Kad128::from_hash(&[0x55; 16]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let peer_ip = ip_u32(&peer_addr);
        let peer_vk = 0xCAFE_BABEu32;

        // Inject the peer with the key it handed us, minted against OUR public IP.
        node.with_routing(|t| {
            t.add(peer_id, peer_ip, peer_addr.port(), 4662, 8, false);
            t.note_verify_key(&peer_id, peer_ip, peer_vk, our_ip);
        });

        let (tx, rx) = tokio::sync::oneshot::channel::<u32>();
        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, from) = peer.recv_from(&mut buf).await.unwrap();
            let dec = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)).unwrap();
            let _ = tx.send(dec.receiver_vk); // what we echoed
            let (rop, rpayload) = build_bootstrap_res(&peer_id, 4662, 8, &[]);
            let dg =
                kad_obfuscate_response(&pack_kad(rop, rpayload), 0x2468, dec.sender_vk, 0, 0x80);
            peer.send_to(&dg, from).await.unwrap();
        });

        let (op, payload) = build_bootstrap_req();
        let frame = pack_kad(op, payload);
        let _ = node
            .request(
                &peer_id,
                peer_addr,
                &frame,
                OP_BOOTSTRAP_RES,
                Duration::from_secs(2),
            )
            .await;
        assert_eq!(
            rx.await.unwrap(),
            peer_vk,
            "the request echoed the peer's stored verify key so it can verify us"
        );
        mock.await.unwrap();

        // IP-bound: after our public IP changes, the stored key no longer matches,
        // so we fall back to echoing 0 (byte-identical to the pre-hard-verify wire).
        node.set_public_ip(0x0B00_0002);
        let now_ip = node.current_public_ip.load(Ordering::Relaxed);
        assert_eq!(
            node.with_routing(|t| t.verify_key_for(&peer_id, peer_ip, now_ip)),
            0
        );
    }

    #[tokio::test]
    async fn hello_completes_the_three_way_handshake_with_a_res_ack() {
        // A v8 responder that requests an ACK (misc-option 0x04 in its HELLO_RES)
        // must receive a HELLO_RES_ACK from us that echoes the sender key it issued
        // -> its bValidReceiverKey is true and it marks US IP-verified (eMule
        // Process2HelloResponseAck -> VerifyContact). Also: our HELLO_REQ must NOT
        // set 0x04 - that bit is the RESPONDER's (eMule SendMyDetails).
        let our_id = Kad128::from_words([7, 7, 7, 7]);
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x1111)
                .await
                .unwrap();
        node.set_public_ip(0x0A00_0001);

        let peer_id = Kad128::from_hash(&[0x55; 16]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let peer_issued_vk = 0xABCD_1234u32; // the key the peer hands us to echo

        #[allow(clippy::type_complexity)]
        let (tx, rx) = tokio::sync::oneshot::channel::<(Option<(u8, u32)>, Option<u8>)>();
        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 1) receive our HELLO_REQ, capture its misc options
            let (n, from) = peer.recv_from(&mut buf).await.unwrap();
            let dec = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)).unwrap();
            let (_rop, rpayload) = unpack_kad(&dec.payload).unwrap();
            let req = parse_hello(&rpayload).unwrap();
            // 2) send a HELLO_RES that REQUESTS an ACK (0x04). The RC4 key is the
            // sender key WE echo (dec.sender_vk = the key padMule issued us, which it
            // can reproduce to decrypt); peer_issued_vk rides the sender_vk FIELD as
            // the key padMule must echo back in its ACK.
            let (hop, hpayload) = build_hello_res(&peer_id, 4662, Some(4662), Some(0x04));
            let dg = kad_obfuscate_response(
                &pack_kad(hop, hpayload),
                0x2468,
                dec.sender_vk,
                peer_issued_vk,
                0x80,
            );
            peer.send_to(&dg, from).await.unwrap();
            // 3) receive the HELLO_RES_ACK (bounded, so a missing ACK fails cleanly)
            let ack = match timeout(Duration::from_millis(500), peer.recv_from(&mut buf)).await {
                Ok(Ok((n2, from2))) => {
                    let dec2 = kad_deobfuscate(&buf[..n2], &peer_id, 0, ip_u32(&from2)).unwrap();
                    let (aop, _ap) = unpack_kad(&dec2.payload).unwrap();
                    Some((aop, dec2.receiver_vk))
                }
                _ => None,
            };
            let _ = tx.send((ack, req.misc_options));
        });

        let contact = test_contact(peer_id, peer_addr);
        node.hello(&contact, Duration::from_secs(2)).await.unwrap();

        let (ack, req_misc) = rx.await.unwrap();
        let (ack_op, echoed) = ack.expect("we complete the handshake with a HELLO_RES_ACK");
        assert_eq!(
            ack_op, OP_HELLO_RES_ACK,
            "we complete the handshake with an ACK"
        );
        assert_eq!(
            echoed, peer_issued_vk,
            "the ACK echoes the peer's issued sender key"
        );
        assert!(
            req_misc.is_none_or(|m| m & 0x04 == 0),
            "our HELLO_REQ must not set the responder's 0x04 ack-request bit"
        );
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn hello_sends_no_ack_when_the_res_does_not_request_one() {
        // If the HELLO_RES does not set 0x04 (the peer already verified us, or does
        // not need an ACK), we must NOT send a HELLO_RES_ACK - a real node sends the
        // ACK only in response to the request, and an unsolicited ACK is noise.
        let our_id = Kad128::from_words([3, 3, 3, 3]);
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x2222)
                .await
                .unwrap();
        node.set_public_ip(0x0A00_0001);

        let peer_id = Kad128::from_hash(&[0x77; 16]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, from) = peer.recv_from(&mut buf).await.unwrap();
            let dec = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)).unwrap();
            // HELLO_RES with NO ack request (misc options absent); keyed on the
            // sender key padMule issued us so it can decrypt.
            let (hop, hpayload) = build_hello_res(&peer_id, 4662, Some(4662), None);
            let dg =
                kad_obfuscate_response(&pack_kad(hop, hpayload), 0x2468, dec.sender_vk, 0, 0x80);
            peer.send_to(&dg, from).await.unwrap();
            // A second packet (an ACK) would be a bug: expect a timeout.
            let got_ack = timeout(Duration::from_millis(400), peer.recv_from(&mut buf))
                .await
                .is_ok();
            let _ = tx.send(got_ack);
        });

        let contact = test_contact(peer_id, peer_addr);
        node.hello(&contact, Duration::from_secs(2)).await.unwrap();
        assert!(
            !rx.await.unwrap(),
            "no ACK must be sent when the HELLO_RES does not request one"
        );
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn add_contact_drops_ipfiltered_ranges() {
        use mule_files::{IpFilter, DEFAULT_IPFILTER_LEVEL};
        use std::sync::Arc;
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = KadNode::bind(bind, 4662).await.unwrap();
        node.set_ip_filter(Some(Arc::new(IpFilter::parse(
            "9.9.9.0 - 9.9.9.255 , 0 , blocked\n",
            DEFAULT_IPFILTER_LEVEL,
        ))));
        // A user-blocklisted public IP never enters the routing table...
        node.add_contact(
            Kad128::from_hash(&[1; 16]),
            0x0909_0909,
            4672,
            4662,
            8,
            false,
            /*proven_alive=*/ false,
        );
        assert_eq!(node.contacts_known(), 0, "blocklisted contact dropped");
        // ...but an allowed public IP does.
        node.add_contact(
            Kad128::from_hash(&[2; 16]),
            0x0808_0808,
            4672,
            4662,
            8,
            false,
            /*proven_alive=*/ false,
        );
        assert_eq!(node.contacts_known(), 1, "allowed contact kept");
    }

    #[tokio::test]
    async fn add_contact_version_gates_the_port_53_guard() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = KadNode::bind(bind, 4662).await.unwrap();
        // A LEGACY node (version <= 5) on DNS port 53 is dropped (anti-reflection)...
        node.add_contact(
            Kad128::from_hash(&[1; 16]),
            0x0808_0808,
            53,
            4662,
            5,
            false,
            /*proven_alive=*/ false,
        );
        assert_eq!(node.contacts_known(), 0, "legacy port-53 contact dropped");
        // ...but a MODERN node on 53 is KEPT - eMule keeps it, so we must not be
        // stricter (that would drop a peer eMule accepts).
        node.add_contact(
            Kad128::from_hash(&[2; 16]),
            0x0909_0909,
            53,
            4662,
            8,
            false,
            /*proven_alive=*/ false,
        );
        assert_eq!(
            node.contacts_known(),
            1,
            "modern port-53 contact kept (faithful)"
        );
    }

    #[tokio::test]
    async fn a_known_id_repointed_to_a_full_ip_is_refused() {
        // A known KadID re-pointed to a DIFFERENT ip is a hijack attempt and faces
        // the anti-sybil cap on the new ip - it is not a free refresh past the cap.
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = KadNode::bind(bind, 4662).await.unwrap();
        let id1 = Kad128::from_hash(&[1; 16]);
        node.add_contact(
            id1,
            0x0808_0808,
            4672,
            4662,
            8,
            false,
            /*proven_alive=*/ false,
        );
        node.add_contact(
            Kad128::from_hash(&[2; 16]),
            0x0808_0809,
            4672,
            4662,
            8,
            false,
            /*proven_alive=*/ false,
        );
        // The attacker's ip (0x0808_0809) is already at the 1-per-IP cap, so
        // re-pointing id1 onto it is refused; id1 stays at its original ip.
        node.add_contact(
            id1,
            0x0808_0809,
            4672,
            4662,
            8,
            false,
            /*proven_alive=*/ false,
        );
        assert_eq!(
            node.with_routing(|t| t.ip_of(&id1)),
            Some(0x0808_0808),
            "hijack to a full IP refused; id stays put"
        );
    }

    #[tokio::test]
    async fn add_contact_enforces_one_id_per_ip() {
        // eMule MAX_CONTACTS_IP = 1: a second KadID behind one IP is refused (the
        // cheapest sybil primitive).
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = KadNode::bind(bind, 4662).await.unwrap();
        node.add_contact(
            Kad128::from_hash(&[1; 16]),
            0x0808_0808,
            4672,
            4662,
            8,
            false,
            /*proven_alive=*/ false,
        );
        node.add_contact(
            Kad128::from_hash(&[2; 16]),
            0x0808_0808,
            4672,
            4662,
            8,
            false,
            /*proven_alive=*/ false,
        );
        assert_eq!(node.contacts_known(), 1, "second id on the same IP refused");
    }

    /// Send one obfuscated HELLO_REQ from a fresh mock peer to `ours` and
    /// return the parsed HELLO_RES. `echo_vk` is what the mock echoes as the
    /// packet's receiver key - the node's own verify key for 127.0.0.1 to play
    /// a sender whose IP is already proven, anything else to play an unproven
    /// one.
    async fn drive_hello(ours: SocketAddr, node_id: &Kad128, echo_vk: u32) -> Hello {
        drive_hello_within(ours, node_id, echo_vk, Duration::from_secs(3))
            .await
            .expect("the HELLO must be answered")
    }

    /// `drive_hello` that can report SILENCE instead of panicking on it, for the
    /// tests whose subject is a refusal. Same mock-peer role either way.
    async fn drive_hello_within(
        ours: SocketAddr,
        node_id: &Kad128,
        echo_vk: u32,
        wait: Duration,
    ) -> Option<Hello> {
        let peer_id = Kad128::from_hash(&[0x77; 16]);
        let peer_key = 0x5A5Au32;
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (op, payload) = build_hello_req(
            &peer_id,
            4662,
            Some(peer.local_addr().unwrap().port()),
            None,
        );
        // The sender key we hand the node is our verify key for ITS address, so
        // its receiver-keyed answer decrypts here - the same role a real v8
        // peer plays.
        let my_vk = udp_verify_key(peer_key, ip_u32(&ours));
        let dg = kad_obfuscate_request(
            &pack_kad(op, payload),
            node_id,
            0x3333,
            echo_vk,
            my_vk,
            0x40,
        );
        peer.send_to(&dg, ours).await.unwrap();
        let mut buf = vec![0u8; 8192];
        let (n, from) = timeout(wait, peer.recv_from(&mut buf)).await.ok()?.unwrap();
        let dec = kad_deobfuscate(&buf[..n], &peer_id, peer_key, ip_u32(&from)).unwrap();
        let (rop, rpayload) = unpack_kad(&dec.payload).unwrap();
        assert_eq!(rop, OP_HELLO_RES);
        Some(parse_hello(&rpayload).unwrap())
    }

    /// Send a KADEMLIA2_REQ (FIND_NODE) as a mock peer and return the contacts
    /// the node answered with. Same role as `drive_hello_within`.
    async fn drive_find(ours: SocketAddr, node_id: &Kad128, target: &Kad128) -> Vec<WireContact> {
        let peer_id = Kad128::from_hash(&[0x66; 16]);
        let peer_key = 0x6B6Bu32;
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (op, payload) = build_kad2_req(mule_kad::KAD_FIND_NODE, target, node_id);
        let my_vk = udp_verify_key(peer_key, ip_u32(&ours));
        let dg = kad_obfuscate_request(&pack_kad(op, payload), node_id, 0x3333, 0, my_vk, 0x40);
        peer.send_to(&dg, ours).await.unwrap();
        let mut buf = vec![0u8; 8192];
        let (n, from) = timeout(Duration::from_secs(3), peer.recv_from(&mut buf))
            .await
            .expect("a FIND must be answered - eMule sends the RES even when empty")
            .unwrap();
        let dec = kad_deobfuscate(&buf[..n], &peer_id, peer_key, ip_u32(&from)).unwrap();
        let (rop, rpayload) = unpack_kad(&dec.payload).unwrap();
        assert_eq!(rop, OP_KAD2_RES);
        mule_kad::parse_kad2_res(&rpayload).unwrap().contacts
    }

    /// THE SERVE GATE, AT THE CALLER. The pure rule is pinned in
    /// `mule_kad::routing`; what this proves is that the READ LOOP asks the
    /// narrow pool - a gate the wire path never consults is not a gate. (Both
    /// halves of this feature initially had pure tests only, and a mutant that
    /// pointed the read loop back at the wide pool sailed through the whole
    /// suite.)
    ///
    /// eMule answers KADEMLIA2_REQ from `GetClosestTo(2, ...)`
    /// (KademliaUDPListener.cpp:738): contacts it has itself had an answer from.
    /// A type-3 contact is one WE have never heard from, so passing it on spends
    /// the asker's dial on our guess.
    #[tokio::test]
    async fn an_inbound_find_is_answered_only_from_contacts_we_proved_ourselves() {
        let our_id = Kad128::from_words([5, 5, 5, 5]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x7171)
                .await
                .unwrap();
        let ours = node.local_addr();
        let target = Kad128::from_hash(&[0x31; 16]);
        let known = Kad128::from_hash(&[0x32; 16]);
        // A verified, routable contact - but one that has never answered US.
        node.with_routing(|t| {
            t.load_nodes(&[KadContact {
                id: known,
                ip: 0x0A0B_0C0D,
                udp_port: 4672,
                tcp_port: 4662,
                version: 8,
                udp_key: 0,
                udp_key_ip: 0,
                verified: true,
            }])
        });

        let answered = drive_find(ours, &our_id, &target).await;
        assert!(
            answered.is_empty(),
            "an unproven contact must not be passed to another node; got {answered:?}"
        );

        // Now it has proven itself alive to us - and only now may we vouch.
        node.with_routing(|t| t.set_alive(&known, 100));
        let answered = drive_find(ours, &our_id, &target).await;
        assert_eq!(
            answered.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![known],
            "a proven contact IS served"
        );
    }

    /// PROMOTION IS NOT "IT WAS MENTIONED". eMule renews a lease only on its
    /// `bUpdate = true` paths (an inbound HELLO_REQ :591, a HELLO_RES to our own
    /// request :672, the BOOTSTRAP_RES responder :567); a KADEMLIA2_RES adds its
    /// contacts `bUpdate = false` (:846) and does not re-add its responder at
    /// all. Drives the free function directly - it is the ONLY insert path, so
    /// this is the rule's one gate rather than a restatement of it.
    #[tokio::test]
    async fn only_a_proving_signal_renews_a_lease_never_hearsay() {
        let routing = Mutex::new(RoutingTable::new(Kad128::from_words([1, 2, 3, 4])));
        let filter: Mutex<Option<Arc<IpFilter>>> = Mutex::new(None);
        let c = WireContact {
            id: Kad128::from_hash(&[0x44; 16]),
            // A ROUTABLE PUBLIC address: `gated_add_contact` refuses private
            // ranges, so a 10.x contact never reaches the promotion rule at all.
            ip: 0x0808_0808,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
        };

        // A FIRST sighting is never a promotion, even from a proving signal:
        // eMule's new-contact branch inserts at type 3 with no SetAlive.
        gated_add_contact(&routing, &filter, &c, true, /*proven_alive=*/ true, 10);
        let t = |f: &dyn Fn(&RoutingTable) -> u8| f(&routing.lock().unwrap());
        assert_eq!(
            t(&|r| r.contacts()[0].kad_type),
            mule_kad::KAD_TYPE_NEW,
            "a first sighting is not yet a proof we can pass on"
        );

        // HEARSAY about a known contact: no lease.
        gated_add_contact(
            &routing, &filter, &c, true, /*proven_alive=*/ false, 20,
        );
        assert_eq!(
            t(&|r| r.contacts()[0].kad_type),
            mule_kad::KAD_TYPE_NEW,
            "being named by a third party is not evidence of life"
        );

        // It answered us: NOW the lease renews.
        gated_add_contact(&routing, &filter, &c, true, /*proven_alive=*/ true, 30);
        assert_eq!(t(&|r| r.contacts()[0].kad_type), mule_kad::KAD_TYPE_ALIVE);
        assert_eq!(
            routing.lock().unwrap().contacts()[0].expires,
            Some(30 + mule_kad::ALIVE_LEASE_SECS)
        );
    }

    /// THE INSTRUMENT MUST BE FED BY THE DRIVER. The sweep policy is unit-tested
    /// in `mule_kad::routing`; this proves `run_liveness_sweep` actually reports
    /// what it did. A panel that stays at zero while the feature works is the
    /// row-8by mistake (codecs with no driver), and on device these counters are
    /// the ONLY way to tell "the sweep never ran" from "the table is healthy".
    ///
    /// Deltas, never absolutes: stats are process-global and the suite is
    /// parallel.
    #[tokio::test]
    async fn the_liveness_sweep_feeds_the_probe_and_eviction_counters() {
        let mut node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([3, 1, 4, 1]),
            0x2727,
        )
        .await
        .unwrap();
        // A routable address with nothing behind it: its probe cannot be
        // answered, so it walks the full march to eviction.
        node.with_routing(|t| {
            t.load_nodes(&[KadContact {
                id: Kad128::from_hash(&[0x51; 16]),
                ip: 0x0808_0404,
                udp_port: 4672,
                tcp_port: 4662,
                version: 8,
                udp_key: 0,
                udp_key_ip: 0,
                verified: true,
            }])
        });

        // Held across the whole measurement: a concurrent `reset_kad_stats()`
        // would make the second read smaller than the first and no delta rule
        // survives that.
        let _stats = crate::stats::STATS_TEST_LOCK.lock();
        let (sent0, _, eviction0) = crate::stats::kad_liveness_counts();
        node.run_liveness_sweep(2).await; // stamps
        node.advance_aging_for_test(60);
        node.run_liveness_sweep(2).await; // probes (times out)
        node.advance_aging_for_test(200);
        node.run_liveness_sweep(2).await; // removes
        let (sent1, _, eviction1) = crate::stats::kad_liveness_counts();

        assert!(
            sent1 > sent0,
            "a probe went out but `probes sent` did not move - the panel would \
             read as 'the sweep never ran'"
        );
        assert!(
            eviction1 > eviction0,
            "a contact was evicted but `contacts evicted` did not move"
        );
        assert_eq!(node.contacts_known(), 0, "and it really is gone");
    }

    /// DROPPING THE NODE MUST STOP ITS READ LOOP, or `pause()` never releases
    /// the Kad port.
    ///
    /// The loop owns an `Arc<UdpSocket>`. If it outlives the node the socket
    /// stays bound, and the fresh loop a `resume()` spawns RACES the stale one
    /// for every inbound datagram - each is delivered to exactly one reader, so
    /// the loser silently loses replies. Clean pause/resume is a hard
    /// requirement here (docs/wiki/lifecycle-and-reactivation.md) and this is
    /// the half of it the read loop introduced.
    ///
    /// Watched through a `Weak` because the property is about a task we no
    /// longer hold: once the node is dropped there is nothing left to ask. The
    /// abort is asynchronous - it takes effect when the runtime next polls the
    /// task - so this yields rather than sleeping, and fails on a bounded wait
    /// instead of hanging.
    #[tokio::test]
    async fn dropping_the_node_stops_its_read_loop_and_releases_the_socket() {
        let node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([7, 7, 7, 7]),
            0x5150,
        )
        .await
        .unwrap();
        let socket = node.socket_weak();
        assert!(
            socket.upgrade().is_some(),
            "precondition: the socket is alive while the node is"
        );

        drop(node);

        for _ in 0..1000 {
            if socket.upgrade().is_none() {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "the read loop outlived its node and still holds the socket - the \
             Kad port would never be released on pause(), and a resumed node \
             would race the stale loop for datagrams"
        );
    }

    /// THE THREE-WAY HANDSHAKE, END TO END, THROUGH THE LOOP: a peer HELLOs,
    /// padMule asks for an ACK, the peer sends one, and the contact is MARKED
    /// VERIFIED. Without the last step the whole exchange is theatre - and it
    /// would be silent theatre, because `closest_to` hands out only verified
    /// contacts (row 8ao), so an unrecorded verification means that peer can
    /// never appear in any answer we give.
    #[tokio::test]
    async fn a_solicited_ack_marks_the_sender_verified_in_the_table() {
        let node_id = Kad128::from_words([0xA, 0xB, 0xC, 0xD]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, node_id, 0x9182)
                .await
                .unwrap();
        let ours = node.local_addr();
        let peer_id = Kad128::from_hash(&[0x77; 16]);
        let peer_key = 0x5A5Au32;
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let my_vk = udp_verify_key(peer_key, ip_u32(&ours));
        // SEED THE CONTACT EXPLICITLY. On loopback the HELLO's own contact-add
        // is refused by the routable-public gate (`is_acceptable_contact`), so
        // without this the table holds nothing for `verify_contact` to find and
        // the test would assert about a contact that never existed - the same
        // vacuity that made row 8cj's first listener test worthless. Seeding it
        // makes this test about the ACK PATH, which is its subject.
        node.with_routing(|t| t.add(peer_id, ip_u32(&ours), 4672, 4662, 8, false));

        // Leg 1: HELLO_REQ from an UNPROVEN sender (echo_vk 0), so the answer
        // must carry the ack request.
        let (op, payload) = build_hello_req(
            &peer_id,
            4662,
            Some(peer.local_addr().unwrap().port()),
            None,
        );
        let dg = kad_obfuscate_request(&pack_kad(op, payload), &node_id, 0x3333, 0, my_vk, 0x40);
        peer.send_to(&dg, ours).await.unwrap();

        // Leg 2: read the HELLO_RES and take the key it wants echoed back.
        let mut buf = vec![0u8; 8192];
        let (n, from) = timeout(Duration::from_secs(3), peer.recv_from(&mut buf))
            .await
            .expect("the HELLO must be answered")
            .unwrap();
        let dec = kad_deobfuscate(&buf[..n], &peer_id, peer_key, ip_u32(&from)).unwrap();
        let (rop, rpayload) = unpack_kad(&dec.payload).unwrap();
        assert_eq!(rop, OP_HELLO_RES);
        let hello = parse_hello(&rpayload).unwrap();
        assert!(
            hello.misc_options.is_some_and(|m| m & 0x04 != 0),
            "precondition: an unproven sender must be ASKED for an ack, or this \
             test proves nothing about what happens when it answers"
        );
        assert!(
            !node.with_routing(|t| t.contacts().iter().any(|c| c.id == peer_id && c.verified)),
            "precondition: not verified until the ack lands"
        );

        // Leg 3: the ACK, echoing the node's sender key so its bValidReceiverKey holds.
        let (ao, ap) = mule_kad::build_hello_res_ack(&peer_id);
        let ack = kad_obfuscate_request(
            &pack_kad(ao, ap),
            &node_id,
            0x4444,
            dec.sender_vk, // echo what the node asked us to echo
            my_vk,
            0x40,
        );
        peer.send_to(&ack, ours).await.unwrap();

        for _ in 0..200 {
            if node.with_routing(|t| t.contacts().iter().any(|c| c.id == peer_id && c.verified)) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the ack was accepted but the contact was never marked verified");
    }

    /// AN INBOUND HELLO'S VERIFY KEY IS STORED, so our next request to that
    /// peer echoes it and IT can verify US.
    ///
    /// Without this the verification is one-directional: the peer proves its IP
    /// to us and we stay unproven in ITS table - which is precisely the state
    /// that gets a contact evicted, so the serve loop would have solved half its
    /// own problem. An inbound HELLO is often the FIRST contact, making it the
    /// earliest moment the key exists at all.
    #[tokio::test]
    async fn an_inbound_hello_stores_the_senders_verify_key_for_the_echo() {
        let node_id = Kad128::from_words([0x1, 0x2, 0x3, 0x4]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, node_id, 0x7777)
                .await
                .unwrap();
        // A public ip must be set BEFORE the hello, because a key is minted
        // against it - and it is set after bind in production, which is exactly
        // what a captured value would get wrong.
        let our_public = 0x0B00_0007u32;
        node.set_public_ip(our_public);
        let ours = node.local_addr();

        let peer_id = Kad128::from_hash(&[0x44; 16]);
        let peer_ip = ip_u32(&ours);
        // Seeded for the same reason as the ACK test: on loopback the HELLO's
        // own contact-add is refused by the routable-public gate, so without
        // this there is no contact for the key to attach to.
        node.with_routing(|t| t.add(peer_id, peer_ip, 4672, 4662, 8, false));
        assert_eq!(
            node.with_routing(|t| t.verify_key_for(&peer_id, peer_ip, our_public)),
            0,
            "precondition: no key stored yet, so we would echo nothing"
        );

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_key = 0xBEEFu32;
        let its_vk = udp_verify_key(peer_key, our_public);
        let (op, payload) = build_hello_req(
            &peer_id,
            4662,
            Some(peer.local_addr().unwrap().port()),
            None,
        );
        let dg = kad_obfuscate_request(&pack_kad(op, payload), &node_id, 0x1212, 0, its_vk, 0x40);
        peer.send_to(&dg, ours).await.unwrap();

        // 6s, not 2s. The PROPERTY is "the inbound hello's sender key ends up
        // stored", not "within two seconds" - the wait is scaffolding, and a
        // scaffold that fails under load reports a defect that is not there.
        // This test and `request_reports_a_valid_receiver_key...` each flaked
        // roughly once in six FULL-SUITE runs on a loaded box while passing
        // 15-20/20 in isolation; a too-tight budget on a loopback datagram plus
        // a task wake is all that was ever wrong. Still bounded, so a genuinely
        // unstored key still fails - just not because the machine was busy.
        for _ in 0..600 {
            if node.with_routing(|t| t.verify_key_for(&peer_id, peer_ip, our_public)) == its_vk {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!(
            "the inbound hello's sender key was not stored - our next request \
             would echo nothing and the peer could never verify us"
        );
    }

    /// AN UNSOLICITED ACK CHANGES NOTHING. eMule drops an ACK from an IP it did
    /// not send a HELLO_RES to inside 180s (`IsOnOutTrackList`,
    /// PacketTracking.cpp:84-97) - the spec omitted this gate entirely. Without
    /// it anyone can name any KadID from any address and try to have that
    /// contact marked verified, which is exactly the spoof the handshake exists
    /// to prevent.
    #[tokio::test]
    async fn an_unsolicited_ack_verifies_nothing() {
        let node_id = Kad128::from_words([0xE, 0xE, 0xE, 0xE]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, node_id, 0x2718)
                .await
                .unwrap();
        let ours = node.local_addr();
        // A contact already in the table, unverified, at the address the ACK
        // will come from - so ONLY the solicitation gate can stop this.
        let peer_id = Kad128::from_hash(&[0x66; 16]);
        node.with_routing(|t| t.add(peer_id, ip_u32(&ours), 4672, 4662, 8, false));

        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_key = 0x1234u32;
        let (ao, ap) = mule_kad::build_hello_res_ack(&peer_id);
        let ack = kad_obfuscate_request(
            &pack_kad(ao, ap),
            &node_id,
            0x4444,
            udp_verify_key(0x2718, ip_u32(&peer.local_addr().unwrap())),
            udp_verify_key(peer_key, ip_u32(&ours)),
            0x40,
        );
        peer.send_to(&ack, ours).await.unwrap();

        // No HELLO_RES was ever sent to this address, so it must stay unverified.
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            !node.with_routing(|t| t.contacts().iter().any(|c| c.id == peer_id && c.verified)),
            "an ack nobody asked for verified a contact - any address could then \
             claim any KadID"
        );
    }

    /// THE FLOOD LIMITER'S FIRST PRODUCTION CALL SITE. eMule allows 2 PINGs per
    /// minute per IP (`InTrackListIsAllowedPacket`, PacketTracking.cpp:148-149)
    /// and IGNORES the rest. A serve loop without this answers every packet a
    /// stranger sends, which is both a CPU drain and, for BOOTSTRAP, an
    /// amplification arm.
    #[tokio::test]
    async fn a_flood_of_pings_from_one_ip_stops_being_answered() {
        let node_id = Kad128::from_words([0xF, 0xF, 0xF, 0xF]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, node_id, 0x3141)
                .await
                .unwrap();
        let ours = node.local_addr();
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_key = 0x8888u32;
        let my_vk = udp_verify_key(peer_key, ip_u32(&ours));

        let mut answered = 0;
        let mut buf = vec![0u8; 8192];
        for i in 0..6u16 {
            let (op, payload) = mule_kad::build_ping();
            let dg =
                kad_obfuscate_request(&pack_kad(op, payload), &node_id, 0x1000 + i, 0, my_vk, 0x40);
            peer.send_to(&dg, ours).await.unwrap();
            if timeout(Duration::from_millis(300), peer.recv_from(&mut buf))
                .await
                .is_ok()
            {
                answered += 1;
            }
        }
        // eMule's budget is 2/min; the exact tail is not the point, being
        // BOUNDED is. Asserting a literal rather than the constant, so raising
        // the budget cannot make this pass by definition.
        assert!(
            (1..=2).contains(&answered),
            "6 pings drew {answered} answers; eMule allows 2 per minute and \
             ignores the rest"
        );
    }

    /// THE REGRESSION ONE SHARED SOCKET MAKES POSSIBLE: an inbound request
    /// arriving while an outbound request is waiting for its reply. Before the
    /// owning loop, the only reader was the reply collector and it DISCARDED
    /// anything it was not waiting for - so a peer's PING was dropped on the
    /// floor and padMule aged out of every routing table that learned it. Both
    /// sides must work at once.
    #[tokio::test]
    async fn an_inbound_request_is_answered_while_a_reply_is_outstanding() {
        let our_id = Kad128::from_words([5, 5, 5, 5]);
        let mut node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x1234)
                .await
                .unwrap();
        let _ = node.local_addr(); // the accessor the loop's tests rely on

        // A peer that PINGS us while our own request to it is in flight.
        let peer_id = Kad128::from_hash(&[0x66; 16]);
        let peer_key = 0x9999u32;
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            // 1. our BOOTSTRAP_REQ arrives
            let (n, from) = peer.recv_from(&mut buf).await.unwrap();
            let dec = kad_deobfuscate(&buf[..n], &peer_id, peer_key, ip_u32(&from)).unwrap();
            // 2. before answering, PING the node - this is the interleaving
            let (po, pp) = mule_kad::build_ping();
            let my_vk = udp_verify_key(peer_key, ip_u32(&from));
            let dg = kad_obfuscate_request(
                &pack_kad(po, pp),
                &Kad128::from_words([5, 5, 5, 5]),
                0x1111,
                0,
                my_vk,
                0x40,
            );
            peer.send_to(&dg, from).await.unwrap();
            // 3. now answer the bootstrap
            let (ro, rp) = build_bootstrap_res(&peer_id, 4662, 8, &[]);
            let ack = kad_obfuscate_response(&pack_kad(ro, rp), 0x2468, dec.sender_vk, 0, 0x80);
            peer.send_to(&ack, from).await.unwrap();
            // 4. and read OUR pong - bounded, so an unanswered ping FAILS the
            // test instead of hanging it
            match timeout(Duration::from_secs(3), peer.recv_from(&mut buf)).await {
                Ok(Ok((n2, from2))) => {
                    let dec2 =
                        kad_deobfuscate(&buf[..n2], &peer_id, peer_key, ip_u32(&from2)).unwrap();
                    Some(unpack_kad(&dec2.payload).unwrap())
                }
                _ => None,
            }
        });

        let res = node
            .bootstrap_from(&test_contact(peer_id, peer_addr), Duration::from_secs(3))
            .await;
        assert!(
            res.is_ok(),
            "the reply must reach its waiter despite the interleaved request"
        );
        let (pong_op, pong_payload) = mock
            .await
            .unwrap()
            .expect("the inbound PING must have been answered");
        assert_eq!(pong_op, mule_kad::OP_PONG);
        assert_eq!(
            pong_payload,
            peer_addr.port().to_le_bytes().to_vec(),
            "the PONG carries the REQUESTER's port - how it learns its external port"
        );
    }

    /// AMENDMENT 2: `start_kad` configures the node AFTER binding it, and the
    /// read loop is spawned AT bind - so the loop must read its configuration
    /// through the SHARED handles the setters write. A loop that captured the
    /// advertised port at spawn would see `None` and answer with the BOUND
    /// port, putting us in peers' tables at a dead address behind a VPN
    /// remote-to-local forward. This test FAILS against that capture.
    #[tokio::test]
    async fn an_inbound_hello_is_answered_with_config_applied_after_bind() {
        let our_id = Kad128::from_words([8, 8, 8, 8]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x4242)
                .await
                .unwrap();
        let ours = node.local_addr();
        // AFTER bind, exactly as start_kad orders it.
        node.set_advertised_udp_port(Some(5999));

        let hello = drive_hello(ours, &our_id, 0).await;
        assert_eq!(hello.id, our_id);
        assert_eq!(
            hello.source_udp_port,
            Some(5999),
            "the HELLO_RES must advertise the port set AFTER bind, not the bound one - \
             a loop that captured config at spawn cannot see it"
        );
    }

    /// An inbound HELLO's sender is recorded through the SAME gated path as a
    /// wire-learned contact. Loopback is not a routable public address, so the
    /// gate must refuse it - a raw insert that bypassed `gated_add_contact`
    /// would put 127.0.0.1 in the table and fail this.
    #[tokio::test]
    async fn an_inbound_hello_sender_faces_the_add_contact_gates() {
        let our_id = Kad128::from_words([9, 9, 9, 9]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x5151)
                .await
                .unwrap();
        let ours = node.local_addr();
        let _ = drive_hello(ours, &our_id, 0).await; // answered...
        assert_eq!(
            node.contacts_known(),
            0,
            "...but a loopback sender must not enter the routing table"
        );
    }

    /// A BLOCKLISTED SOURCE GETS NO ANSWER - a deliberate divergence, and the
    /// only one on the serve path.
    ///
    /// eMule WOULD answer: `ProcessPacket` (KademliaUDPListener.cpp:236-256)
    /// gates an inbound datagram on the port-53 guard and
    /// `InTrackListIsAllowedPacket` alone, and reaches for the ipfilter only
    /// when INSERTING contacts (`:835`). padMule refuses, because a blocklist
    /// is an explicit "do not talk to these people" and an answer IS talking -
    /// it confirms we exist, at this address, running Kad. Interop-safe by
    /// construction: the only peers it can cut off are the ones the user chose
    /// to cut off.
    ///
    /// The test asserts SILENCE, so it must distinguish "refused" from "slow":
    /// it waits for a real timeout with the filter on, then proves the very
    /// same exchange succeeds with the filter off. Without that second half a
    /// broken read loop would pass just as happily.
    #[tokio::test]
    async fn a_blocklisted_source_is_not_answered_at_all() {
        use mule_files::{IpFilter, DEFAULT_IPFILTER_LEVEL};
        use std::sync::Arc;
        let our_id = Kad128::from_words([4, 4, 4, 4]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, 0x7373)
                .await
                .unwrap();
        let ours = node.local_addr();

        // Block the loopback the mock will dial us from.
        node.set_ip_filter(Some(Arc::new(IpFilter::parse(
            "127.0.0.0 - 127.255.255.255 , 0 , blocked\n",
            DEFAULT_IPFILTER_LEVEL,
        ))));
        assert!(
            drive_hello_within(ours, &our_id, 0, Duration::from_secs(1))
                .await
                .is_none(),
            "a blocklisted source must get SILENCE, not a HELLO_RES"
        );

        // THE CONTROL: same node, same exchange, filter cleared. If this also
        // came back empty the assertion above would be meaningless.
        node.set_ip_filter(None);
        assert!(
            drive_hello_within(ours, &our_id, 0, Duration::from_secs(3))
                .await
                .is_some(),
            "with no filter the identical exchange must still be answered - \
             otherwise the test above proves nothing"
        );
    }

    /// The ACK bit in our HELLO_RES must reflect the REAL receiver-key verdict:
    /// a sender that echoed the verify key we issue for its address has proved
    /// its IP and must NOT be asked to prove it again (eMule
    /// `bAddedOrUpdated && !bValidReceiverKey`, KademliaUDPListener.cpp:601).
    #[tokio::test]
    async fn a_verified_hello_sender_is_not_asked_for_an_ack() {
        let our_id = Kad128::from_words([6, 6, 6, 6]);
        let our_key = 0x7777u32;
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, our_key)
                .await
                .unwrap();
        let ours = node.local_addr();

        // The key we issue for the mock's address (loopback) - echoing it back
        // is the proof of IP the verdict is about.
        let proven_vk = udp_verify_key(our_key, ip_u32(&"127.0.0.1:1".parse().unwrap()));
        let proven = drive_hello(ours, &our_id, proven_vk).await;
        assert!(
            proven.misc_options.is_none_or(|m| m & 0x04 == 0),
            "a sender that proved its IP must not be asked for an ACK, got {:?}",
            proven.misc_options
        );

        let unproven = drive_hello(ours, &our_id, 0xBAD0_BEEF).await;
        assert_eq!(
            unproven.misc_options,
            Some(0x04),
            "an unproven sender must be asked for the verification ACK"
        );
    }

    /// The table is reachable from two places once the socket loop exists - the
    /// request handler reads it, lookups write it - so it lives behind a lock.
    /// This pins that the lock is taken per operation: a closure that takes it,
    /// does its work and drops the guard is the only allowed shape (never held
    /// across an await).
    #[tokio::test]
    async fn the_routing_table_is_shared_and_readable_while_a_lookup_holds_the_node() {
        let node = KadNode::bind_with_identity(
            "127.0.0.1:0".parse().unwrap(),
            4662,
            Kad128::from_words([2, 2, 2, 2]),
            0x4321,
        )
        .await
        .unwrap();
        node.with_routing(|t| {
            t.add(
                Kad128::from_hash(&[9; 16]),
                0x0A00_0001,
                4672,
                4662,
                8,
                true,
            )
        });
        assert_eq!(node.contacts_known(), 1);
        let closest = node.closest_wire_contacts(&Kad128::from_hash(&[9; 16]), 5);
        assert_eq!(closest.len(), 1);
    }

    #[tokio::test]
    async fn bind_with_identity_keeps_the_persisted_id_and_key() {
        // The engine passes NodeIdentity::{kad_id, kad_udp_key}; the node must
        // adopt them verbatim (a fresh random identity here would silently
        // re-key Kad on every app start - the bug this constructor fixes).
        let id = Kad128::from_words([1, 2, 3, 4]);
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let node = KadNode::bind_with_identity(bind, 4662, id, 0xDEAD_BEEF)
            .await
            .unwrap();
        assert_eq!(node.kad_id(), id);
        assert_eq!(node.udp_key, 0xDEAD_BEEF);
    }
}
