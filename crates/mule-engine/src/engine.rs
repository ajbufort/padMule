//! The Engine facade: the single object the native UI drives, and the seam Wave
//! 8's UniFFI layer wraps. It owns the persistent identity and config directory,
//! runs the foreground/background lifecycle state machine, and emits an event
//! stream the UI observes.
//!
//! The lifecycle is the biggest deviation from desktop aMule (see
//! docs/wiki/ipados-constraints.md): iPadOS suspends a backgrounded app and
//! reclaims its sockets, so the honest model is foreground-only -
//!   - `pause()` (app backgrounded): checkpoint to disk, pause the server link,
//!     drop the Kad socket, abort the listener. Idempotent.
//!   - `resume()` (app foregrounded): rebind the listener FIRST (the HighID
//!     ordering), reconnect the server, re-bootstrap Kad - emitting
//!     "Reconnecting..." then "Connected". Idempotent, correct across an IP
//!     change.
//!
//! Downloads ride the same lifecycle (the 8z readiness-audit fixes): `start()`
//! and `resume()` re-drive every incomplete download through `resume_fetches`,
//! and `pause()`/`shutdown()` flush gap progress to `.part.met` via
//! `persist_downloads`. The one DELIBERATE gap: pause() does not abort in-flight
//! fetch tasks (iPadOS suspends all threads anyway; resume() re-drives, and a
//! CancellationToken refactor was judged not worth it - see build-progress 8z).

use crate::bootstrap;
use crate::catalog::{catalog, tag_str, tag_u64, RankedFile};
use crate::connection::{ServerEvent, ServerState};
use crate::credit_store::{now_secs, CreditStore};
use crate::fetch::{download_file, ManagerConfig, PeerSource, SourceRegistry};
use crate::framed::FramedStream;
use crate::identity::NodeIdentity;
use crate::kad_live::KadNode;
use crate::known2_store::Known2Store;
use crate::link::ServerLink;
use crate::lock::LockRecover;
use crate::multi_source::{download_from_peer_at, resume_downloads, Download};
use crate::obf_handshake::{obf_accept, ObfDetect};
use crate::part_store::PartStore;
use crate::peer::HelloInfo;
use crate::peer_conn::peer_handshake_inbound;
use crate::search::{
    build_global_search_udp, parse_global_search_res, related_keyword, SearchParams,
    SearchResultFile, SearchResultPage, OP_GLOBSEARCHRES,
};
use crate::secure_ident::SecureIdentSession;
use crate::server_crawl::ServerCrawl;
use crate::server_messages::{
    desc_req_challenge, parse_serv_stat_res, parse_server_desc_res, parse_server_list,
    LoginRequest, OfferedFile, DEFAULT_SERVER_FLAGS, FILE_COMPLETE_ID, FILE_COMPLETE_PORT,
    OP_GLOBSERVSTATREQ, OP_GLOBSERVSTATRES, OP_SERVER_DESC_REQ, OP_SERVER_DESC_RES,
    OP_SERVER_LIST_REQ2, OP_SERVER_LIST_RES, SERV_STAT_CHALLENGE,
};
use crate::share::{
    classify_inbound, head_hash, serve_shared, InboundKind, ServeSec, SharedFile, UploadGate,
};
use crate::transfer::build_file_req_ans_no_fil;
use mule_files::{
    merge_server_met, read_nodes_dat, read_pins, read_server_met, write_nodes_dat, write_pins,
    write_server_met, IpFilter, KadContact, NodesDat, Server, ServerMet, DEFAULT_IPFILTER_LEVEL,
};
use mule_kad::{kad_keyword_target, KeywordEntry, RoutingTable, SourceEntry};
use mule_proto::{Kad128, Packet, Tag, TagName, TagValue, PROT_EDONKEY};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;

/// The ports padMule advertises and listens on (eD2k TCP, Kad UDP).
/// The eD2k defaults. Both are now overridable (see `Engine::set_ports`):
/// a VPN that forwards an ASSIGNED remote port is the case that needs it.
const TCP_PORT: u16 = 4662;
const KAD_UDP_PORT: u16 = 4672;

/// The nickname padMule announces when the user has not chosen one. It is what
/// every peer HELLO and every server login carried unconditionally until this
/// became a setting, so it stays the default: an install nobody touches behaves
/// exactly as before.
pub const DEFAULT_NICK: &str = "padMule";

/// The nickname length cap, in characters. eMule's own number, and BOTH
/// authorities agree on it: `CPreferences::GetMaxUserNickLength() {return 50;}`
/// (eMule 0.70b Preferences.h:690, eMule 0.50a Preferences.h:661). eMule applies
/// it at the edit control (`SetLimitText`, 0.70b PPgGeneral.cpp:115) and again
/// when a nickname arrives from elsewhere (AddFriend.cpp:143-144 truncates).
pub const MAX_NICK_LEN: usize = 50;

/// Clean a user-entered nickname into the string that may go on the wire.
///
/// eMule's rule, at `CPPgGeneral::OnApply` (0.70b PPgGeneral.cpp:187-191):
/// `GetDlgItemText(IDC_NICK, strNick); if (!IsValidEd2kString(strNick.Trim()) ||
/// strNick.IsEmpty()) strNick = DEFAULT_NICK;` - so it TRIMS (CString::Trim
/// mutates in place, which is why the emptiness test sees the trimmed value),
/// falls back to the default on empty, and caps the length at the control.
/// padMule keeps all three.
///
/// The one DELIBERATE divergence is `IsValidEd2kString` (StringConversion.h:21),
/// which rejects a nickname containing `?`. Its own comment says why: "'?' is the
/// character which is returned by windows if user entered a Unicode string into
/// an edit control when application runs in ANSI mode" - a Windows ANSI-mode
/// artifact. padMule has no ANSI mode; it writes UTF-8 bytes into a
/// length-prefixed string tag, where `?` is an ordinary character. Throwing away
/// the whole nickname because it contains a question mark would be a surprise
/// with no benefit here, so `?` is kept. What that check is FOR - keeping junk
/// off the wire - is honoured by the platform-appropriate rule instead: control
/// characters are stripped. A newline or a NUL in a nickname is never intended
/// from a single-line field, and both are the kind of thing that mangles another
/// client's log or C-string handling.
///
/// The length cap counts CHARACTERS, not bytes, like eMule's control does. At
/// most 50 chars is at most 200 UTF-8 bytes, far inside the u16 length prefix a
/// string tag carries, so no cap on bytes is needed.
///
/// The Swift Settings field applies the same rule so a rejected entry snaps
/// visibly (`SettingsView.sanitizedNickname`); THIS is the enforcing copy, since
/// the engine is what writes the bytes.
pub fn sanitize_nick(input: &str) -> String {
    let cleaned: String = input.chars().filter(|c| !c.is_control()).collect();
    let capped: String = cleaned.trim().chars().take(MAX_NICK_LEN).collect();
    let nick = capped.trim();
    if nick.is_empty() {
        DEFAULT_NICK.to_string()
    } else {
        nick.to_string()
    }
}

// `ip_from_met_u32` is now THE one definition in mule-files (2026-08-09); this
// crate re-imports it rather than keeping the copy that let three byte-order
// bugs breed at three different call sites.
use mule_files::ip_from_met_u32;

/// A routing table's live contacts in the on-disk `nodes.dat` shape. Taking the
/// table (not a `&[Contact]`) keeps mule-kad's contact type out of this signature.
fn routing_to_nodes(rt: &RoutingTable) -> Vec<KadContact> {
    rt.contacts()
        .into_iter()
        .map(|c| KadContact {
            id: c.id,
            ip: c.ip,
            udp_port: c.udp_port,
            tcp_port: c.tcp_port,
            version: c.version,
            // Persist the peer's verify key so we can echo it after a restart
            // (eMule persists m_uUDPKey + its IP; a stable key keeps us verified).
            udp_key: c.udp_key,
            udp_key_ip: c.udp_key_ip,
            // Persist the IP-verified bit so a contact stays verified across
            // restarts (eMule writes IsIpVerified() to nodes.dat, RoutingZone.cpp:332).
            verified: c.verified,
        })
        .collect()
}

/// The contacts a checkpoint should persist: the table we loaded at start PLUS
/// everything the LIVE Kad node has learned since.
///
/// `start_kad` folds the node's table into `self.routing` exactly ONCE, at the
/// end of bootstrap. After that the two diverge: every lookup answer adds
/// contacts to the LIVE table, and - the load-bearing part - `note_responder`
/// records each responder's UDP verify key there. Without this merge, `pause()`
/// dropped the node and `checkpoint()` wrote the stale bootstrap-time snapshot,
/// so every contact AND every verify key learned during the session was thrown
/// away. That defeats the point of persisting keys at all (see
/// `routing_to_nodes`: "so we can echo it after a restart"), and on iPadOS
/// pause/checkpoint is the ROUTINE path, not a rare one.
///
/// The live entry wins a collision: it is the fresher observation of the same
/// node, and it is the one carrying any key captured this session.
fn checkpoint_contacts(persisted: &RoutingTable, live: Option<&RoutingTable>) -> Vec<KadContact> {
    let mut by_id: std::collections::HashMap<[u8; 16], KadContact> =
        std::collections::HashMap::new();
    let mut order: Vec<[u8; 16]> = Vec::new();
    let mut fold = |c: KadContact| {
        let key = c.id.to_wire();
        if by_id.insert(key, c).is_none() {
            order.push(key);
        }
    };
    for c in routing_to_nodes(persisted) {
        fold(c);
    }
    if let Some(live) = live {
        for c in routing_to_nodes(live) {
            fold(c);
        }
    }
    order.into_iter().filter_map(|k| by_id.remove(&k)).collect()
}

/// Gate nodes.dat contacts at LOAD the way aMule does (RoutingZone.cpp:195-199):
/// Kad2-only (contactVersion > 1), routable public ip:port, the user's ipfilter,
/// and no legacy DNS-port contact. The file may have just been DOWNLOADED
/// (bootstrap::ensure), so an ungated load would let a hostile list seed the
/// routing table with unroutable or user-blocked contacts.
fn gate_loaded_nodes(contacts: &[KadContact], filter: Option<&IpFilter>) -> Vec<KadContact> {
    contacts
        .iter()
        .filter(|c| {
            c.version > 1
                && mule_kad::is_acceptable_contact(c.ip, c.udp_port, /*allow_private=*/ false)
                && !(c.udp_port == 53 && c.version <= 5)
                && filter.is_none_or(|f| !f.is_blocked_u32(c.ip))
        })
        .cloned()
        .collect()
}

/// Recursive-crawl bounds (see `Engine::crawl_servers`). Deliberately modest:
/// this is the one path that contacts hosts the user never chose, so each hop
/// is a paced trickle and the whole run is short enough to sit behind a button.
/// How often the Kad liveness sweep runs - eMule's `OnSmallTimer` cadence
/// (`Kademlia.cpp:274-278`, `MIN2S(1)`).
const KAD_SWEEP_EVERY: Duration = Duration::from_secs(60);
/// How often the publish scheduler runs ONE job. A drip, not a flood: the
/// republish clocks are 5h/24h, so there is never any hurry, and one job per
/// 10s keeps the per-beat lock hold rare. A file with W words takes W+1 jobs,
/// so a 20-file library republishes fully in a few minutes and then idles for
/// hours. `maintain_kad_publish`.
const KAD_PUBLISH_EVERY: Duration = Duration::from_secs(10);
/// Wall-clock cap on ONE publish job's FIND_NODE walk under the engine lock -
/// the same net `maintain_kad` uses (a publish is best-effort; storing to
/// fewer nodes inside the budget is fine, and the record republishes anyway).
const KAD_PUBLISH_BUDGET: Duration = Duration::from_secs(3);
/// The connect-options byte padMule publishes in a source record: crypt
/// SUPPORTED, never REQUIRED (bit 0x01), matching exactly what its HELLO
/// advertises ([[obfuscation-posture]] / [[security-model]]). A publisher that
/// claimed to REQUIRE crypt while accepting plaintext would misdescribe itself
/// to every searcher.
const KAD_PUBLISH_CRYPT_OPTIONS: u8 = 0x01;
/// Probes emitted per sweep. eMule probes one contact per LEAF ZONE per minute
/// and gets its stagger from per-zone timers (`RoutingZone.cpp:124`); padMule
/// sweeps the whole tree in one pass, so this cap is the stagger. Small because
/// the sweep runs under the engine lock: 2 x `KAD_PROBE_WAIT` bounds the hold.
const KAD_SWEEP_MAX_PROBES: usize = 2;
const MAX_CRAWL_ROUNDS: u32 = 3;
const CRAWL_ASKS_PER_ROUND: usize = 40;
const CRAWL_SEND_PACE: Duration = Duration::from_millis(40);
const CRAWL_ROUND_WAIT: Duration = Duration::from_secs(4);

/// How often a RUNNING engine re-checkpoints (see `Engine::maintain_checkpoint`).
/// Five minutes bounds what a suspend-kill can cost without writing often enough
/// to matter: the Kad table and credit ledger both move slowly, and the write is
/// a few small files.
const CHECKPOINT_EVERY: Duration = Duration::from_secs(300);

/// How often a RUNNING engine re-checks that its shared files are still on disk
/// (see `Engine::verify_shared_library`). The user can delete a finished file in
/// the Files app at any moment; a minute of staleness is invisible to them and
/// costs one stat per shared file.
const SHARE_VERIFY_EVERY: Duration = Duration::from_secs(60);

/// How long to wait for a server's search answer / source list. Servers reply in
/// well under this or not at all.
const SEARCH_WAIT: Duration = Duration::from_secs(20);
const SOURCES_WAIT: Duration = Duration::from_secs(10);

/// How long a Kad keyword lookup may run before we take whatever it has found.
/// Kad is the serverless half of search; bounded so a slow lookup never hangs
/// the box, and it runs concurrently with the server search so it is usually free.
///
/// IT USED TO BE THE COST, NOT THE BOUND. `resolve_keyword` awaited its
/// `ALPHA_QUERY` queries one at a time, so the lookup alone was structurally
/// 12 x 3 x `KAD_PER_QUERY` = 27s and every search ran until this cap cut it
/// off. That is the ~10s submit-to-results measured on device 2026-08-07, with
/// the server arm having answered in well under a second. Since 2026-08-08 the
/// lookup is EVENT-DRIVEN (eMule CSearch; `KadNode::drive_lookup`): its own
/// overall deadline is 16 x `KAD_PER_QUERY` = 12s, inside this cap, and a
/// normal lookup terminates on results or exhaustion long before either.
const KAD_SEARCH_WAIT: Duration = Duration::from_secs(15);
/// PER-REQUEST deadline during a Kad lookup - each request races its own
/// clock, so a silent peer costs itself, not a round (there are no rounds -
/// see `KadNode::drive_lookup`).
const KAD_PER_QUERY: Duration = Duration::from_millis(750);

/// How often a RUNNING engine refreshes its Kad routing table.
///
/// padMule had NO Kad maintenance at all before 2026-08-05 - see
/// `KadNode::refresh_routing`. Two minutes is a deliberate compromise: eMule
/// refreshes bins on an hourly cycle driven by a per-second timer, but it is an
/// always-on desktop client, whereas padMule only exists while it is on screen.
/// A foreground session is measured in minutes to hours, so the table has to be
/// built inside one rather than maintained across days.
const KAD_REFRESH_EVERY: Duration = Duration::from_secs(120);

/// Wall-clock cap on ONE `maintain_kad` pass.
///
/// `refresh_routing` carries its own deadline - `REFRESH_DEADLINE_QUERIES`
/// times `KAD_PER_QUERY` - but `heartbeat()` holds the engine lock across it,
/// so this outer timeout stays as the SAFETY NET rather than the thing that
/// ends every run. Pinned by `a_kad_maintenance_round_fits_inside_its_
/// deadline`, which fails if the refresh deadline grows past the budget.
const KAD_MAINTENANCE_BUDGET: Duration = Duration::from_secs(3);

/// Stop actively growing the table past this. Not a protocol rule - a battery
/// and bandwidth one: past a few hundred well-spread contacts a lookup already
/// converges, and a foreground-only client on a tablet should not keep paying
/// UDP for contacts it will never use.
///
/// NOTE, re-corrected 2026-08-09: the 2026-08-06 note here said the table
/// cannot shrink - `RoutingTable` had no removal path, so a table at this
/// ceiling kept its dead contacts for the session. TRUE THEN, FALSE SINCE
/// rows 8cw/8cx landed the `OnSmallTimer` half: `RoutingTable::remove` and
/// `sweep` exist, and `maintain_kad_liveness` probes-and-evicts every 60s.
/// "Refresh resumes if the table shrinks" is therefore real again: a live
/// table that loses contacts to the sweep drops below this target and
/// `maintain_kad` picks growth back up on its own. [[kad-routing-lifecycle]].
const KAD_TABLE_TARGET: usize = 600;

/// DIALABLE sources a server answer must carry before `find_sources` skips the
/// Kad arm entirely.
///
/// Tied to `fetch::parallel_for_priority`'s Normal width: below that the worker
/// pool is starved BY DEFINITION, so waiting for Kad costs nothing that was
/// going to be used, and skipping it forfeits the only other place sources come
/// from. Pinned to that constant by test rather than chosen by taste - a
/// threshold picked on feel is the mistake this file has already made twice.
const MIN_DIALABLE_TO_SKIP_KAD: usize = 4;

/// Minimum interval between SERVER searches - a client-side flood guard mirroring
/// aMule's silent 2 s (SearchDlg.cpp:277). padMule improves on aMule by surfacing
/// the remaining seconds instead of silently ignoring the click. Wire-neutral.
const SERVER_SEARCH_MIN_INTERVAL: Duration = Duration::from_secs(2);
/// eMule caps a search at 5 "load more" follow-up pages (opcodes.h:60).
const MAX_MORE_SEARCH_REQ: u8 = 5;

/// The result of a search: ranked files (with whether the server has more pages)
/// or a throttle notice. `Throttled` is a normal answer the UI reports, not an
/// error - the same "result, not error" shape as [`AddResult`].
pub enum SearchOutcome {
    Results {
        ranked: Vec<RankedFile>,
        more_available: bool,
    },
    Throttled {
        wait_secs: u32,
    },
}

/// The result of auto-updating the server list from a URL. A URL problem is a
/// normal outcome the UI reports, not an error it throws (mirrors [`AddResult`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerListUpdate {
    /// Merged `added` new servers; the file now holds `total`.
    Updated { added: u32, total: u32 },
    /// The URL was neither `http://` nor `https://`.
    BadUrl,
    /// Fetched, but the bytes were not a server.met (an HTML error page, or
    /// malformed data; gzip/zip-wrapped lists ARE unwrapped in the fetch path
    /// before this check, so this means genuinely-not-a-list).
    NotServerMet,
    /// The host could not be reached / the GET or the write failed.
    Unreachable,
}

/// The live server-search window, so "load more" continues the SAME query on the
/// SAME connection and folds new pages into the same dedupe. Ephemeral - rebuilt
/// on every [`Engine::search`]; guarded by `server_addr` so a reconnect voids it.
struct SearchSession {
    server_addr: SocketAddr,
    combined: Vec<SearchResultFile>,
    /// ORIGIN_* bits per entry of `combined`, so a page loaded later keeps
    /// saying where each hit came from.
    origins: Vec<u8>,
    filters: SearchFilters,
    server_more: bool,
    more_reqs: u8,
}

/// What the port-mapping maintenance triggers (a foreground resume, or a server
/// answering LowID) should actually DO.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingAction {
    /// We hold a mapping: verify it still exists and re-open only if it is gone
    /// (eMule's CheckAndRefresh).
    Refresh,
    /// We hold NO mapping and we are supposed to: try to make one.
    ///
    /// This is the case the first version got wrong. Both triggers early-returned
    /// when there was no mapping, on the reasoning that "there is nothing to
    /// refresh" - but the initial `map_port` at `start()` can simply have FAILED
    /// (a dropped SSDP answer, a gateway busy for a moment), and then the two
    /// triggers designed to recover a missing mapping were exactly the two that
    /// refused to run. The session stayed LowID with no retry short of a full
    /// Stop/Start, on the path padMule's whole HighID story runs through.
    Map,
    /// Do nothing: not running, offline, or deliberately stopped.
    None,
}

/// Decide the action from the facts. Pure, so the rule is testable without a
/// gateway - the live layer only performs what this returns.
pub fn port_mapping_action(running: bool, offline: bool, have_mapping: bool) -> MappingAction {
    if !running || offline {
        return MappingAction::None;
    }
    if have_mapping {
        MappingAction::Refresh
    } else {
        MappingAction::Map
    }
}

/// Seconds a caller must wait before the next server search, or `None` if it may
/// search now. Rounds UP so "wait 1s" never displays 0. Pure (takes `now`), so it
/// is unit-testable without a real clock.
fn throttle_wait_secs(last: Option<Instant>, now: Instant, interval: Duration) -> Option<u32> {
    let elapsed = now.saturating_duration_since(last?);
    let remaining = interval.checked_sub(elapsed)?;
    if remaining.is_zero() {
        return None;
    }
    Some(remaining.as_secs() as u32 + u32::from(remaining.subsec_nanos() > 0))
}

/// Apply the user's numeric filters to a ranked set (Kad hits are not filtered on
/// the wire, so the merged set must be re-filtered). Shared by search + load-more.
fn apply_search_filters(mut ranked: Vec<RankedFile>, filters: &SearchFilters) -> Vec<RankedFile> {
    ranked.retain(|r| {
        filters.min_sources.is_none_or(|m| r.sources >= m)
            && filters.min_size.is_none_or(|m| r.size >= m)
            && filters.max_size.is_none_or(|m| r.size <= m)
    });
    ranked
}

/// How long to wait for an inbound peer to speak first. A leecher sends
/// OP_REQUESTFILENAME within a round-trip; a called-back LowID source stays
/// silent, waiting for us to drive the download of one of OUR files. This
/// timeout is what routes each connection to the right half of the listener.
const SERVE_PEEK: Duration = Duration::from_secs(3);

/// The most simultaneous uploads we grant. Modest by desktop standards (aMule
/// floors at 20) because an iPad on a phone uplink is not a seedbox. A peer
/// that finds every slot taken is not refused: the `UploadGate` queues it by
/// credit score and answers OP_QUEUERANKING, exactly the standard wait-line
/// behaviour. The only true refusal is a FULL QUEUE (`UPLOAD_QUEUE_CAP`),
/// which is dropped silently - no packet - matching upstream.
const MAX_UPLOAD_SLOTS: usize = 8;
/// How many peers may wait for a slot before we decline further requests. A
/// small cap is honest for a foreground-only client (eMule's desktop default is
/// thousands, which assumes an always-on seedbox); a queued peer holds an open
/// connection here, so this also bounds fd/memory use.
const UPLOAD_QUEUE_CAP: usize = 32;
/// Cap on CONCURRENT inbound peer-connection tasks the listener will spawn. A
/// hostile peer opening thousands would otherwise exhaust file descriptors + task
/// memory; excess connections are dropped (the peer can retry).
const MAX_INBOUND_CONNS: usize = 200;
/// Cap on CONCURRENT inbound connections from a SINGLE IP, so one hostile source
/// cannot grab all `MAX_INBOUND_CONNS` permits and starve every other peer.
/// Generous on purpose: a NAT/CGNAT address legitimately fronts several peers, and
/// an honest peer opens only a handful of sockets to us, so this never cuts off a
/// real client - and a rejected connection is retryable.
const MAX_INBOUND_PER_IP: u32 = 16;

/// Which registry rows a called-back source may DRIVE: the one admission rule
/// (`multi_source::queued_flags`, same `(paused, complete, receiving)` rows
/// in add order) composed with the paused/complete skip the sweeps already
/// apply. The
/// listener's `InboundKind::Source` arm used to iterate every registered
/// download with neither check, so a row the UI reported as "Queued" (or
/// paused) transferred whenever a LowID source dialed back - the callback path
/// was a hole in the cap. Pinned by its own test because the listener seam
/// (a real silent inbound connection) is not exercised offline.
fn callback_drive_flags(cap: u32, rows: &[(bool, bool, bool)]) -> Vec<bool> {
    let queued = crate::multi_source::queued_flags(cap, rows);
    rows.iter()
        .zip(queued)
        .map(|(&(paused, complete, _receiving), q)| !paused && !complete && !q)
        .collect()
}
/// Total wall-clock budget for the resume-fetch pass in `start()`, and the
/// per-download cap on source-finding within it. Small so a batch of dead
/// downloads cannot stall startup (which holds the FFI engine lock).
/// How long one resume pass may spend re-driving downloads, and how long any
/// single download gets. The pass runs while the user waits on the foreground
/// return, so it stays short; downloads it does not reach are picked up by
/// `maintain_resume_fetches` rather than being stranded until the next launch.
const RESUME_BUDGET: Duration = Duration::from_secs(12);
const RESUME_PER_DL: Duration = Duration::from_secs(6);

/// The budget `add_download` gives source discovery. The user explicitly asked
/// for this file and is watching a spinner, so it gets the full wait.
const ADD_SOURCES_BUDGET: Duration = Duration::from_secs(15);

/// How often the heartbeat re-drives ONE download that has gone idle, and the
/// budget it gets. Before this existed there was NO retry anywhere: a download
/// that missed its resume window - or whose fetch task simply exhausted its
/// round budget - sat frozen until the app was relaunched, which is exactly
/// what "stuck at 34% forever" looked like.
///
/// [REVISED 2026-08-04 - the constraint this was sized for is GONE, and the old
/// sizing was the second half of Anthony's "downloads stall" report.]
///
/// It used to read: "deliberately small and infrequent: this runs on the 1s
/// heartbeat, which holds the engine lock, so the budget is the length of a UI
/// hitch... getting these calls off the one serial queue is the real fix". That
/// fix LANDED (row 8bq) - UI polls no longer take the engine lock - so the
/// budget no longer buys a frozen screen.
///
/// MEASURED, not guessed: with a 2s budget, 4 of 4 traced retries consumed the
/// ENTIRE budget and were cut off mid-discovery (`took=2.002s`, `2.001s`,
/// `2.001s`, `2.000s`), finding 0-6 sources and leaving 3-6 LowID peers
/// un-called-back. `add_download` gets 15s for identical work, and the Kad arm
/// carries a 15s budget of its own - so Kad could NEVER contribute to a retry.
/// A download whose sources dried up was getting a truncated 2s hunt.
///
/// 6s lets the server arm finish and gives Kad a real chance, while staying
/// under `ADD_SOURCES_BUDGET`. (This line said 8s while the constant shipped
/// at 6 - reconciled 2026-08-09 to the constant, whose value the
/// `RESUME_RETRY_DUTY` arithmetic below is derived from: a x4 floor is a 24s
/// gap, ~25% occupancy, and a ~3.6-minute rotation at a queue of 9.) It is
/// still bounded because `heartbeat()` does hold the engine lock, and
/// `pause()` waits behind it - which on iPadOS must stay prompt.
const RESUME_RETRY_BUDGET: Duration = Duration::from_secs(6);

/// Base cadence, DIVIDED by how many downloads are idle (clamped), so a big
/// queue rotates in bounded time instead of linearly worse.
///
/// The old fixed 45s meant one retry per 45s TOTAL: with 9 stalled downloads
/// each got rediscovery once every ~7 minutes, and with 30 queued, once every
/// 22. That is indistinguishable from "stopped". Dividing keeps the per-file
/// period roughly constant as the queue grows, with a floor so a huge queue
/// cannot turn the heartbeat into a source-discovery treadmill.
const RESUME_RETRY_EVERY: Duration = Duration::from_secs(45);
/// The gap is floored at this MULTIPLE of the budget, which bounds how much of
/// the time the retry holds the engine lock.
///
/// MEASURED THE HARD WAY: a first attempt paired an 8s budget with a 9s floor
/// and produced ~89% lock occupancy - `find_sources` joins the server and Kad
/// arms and WAITS FOR BOTH, and the Kad arm essentially always uses its whole
/// budget, so a retry always costs the full amount. At that duty cycle
/// `pause()` waits behind the lock, which on iPadOS risks losing the checkpoint
/// at suspension. A cure worse than the disease.
///
/// x4 caps occupancy at ~25%. With a queue of 9 that gives each file
/// rediscovery every ~3.6 minutes instead of the old ~7, without starving
/// pause. The REAL fix is getting `find_sources` off the engine lock (the same
/// ownership change row 8bq deliberately stopped short of); until then this
/// ratio is the honest limit.
const RESUME_RETRY_DUTY: u32 = 4;
const RESUME_RETRY_SPREAD: u32 = 5;

/// The next free `NNN.part` index in `dir`. aMule numbers part files this way and
/// `resume_downloads` finds them by that name, so a new download MUST NOT reuse
/// an index some existing `.part.met` already claims - that would silently
/// clobber a transfer in progress.
fn next_part_index(dir: &Path) -> u32 {
    let mut max = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for e in entries.flatten() {
            if let Some(n) = e
                .file_name()
                .to_string_lossy()
                .strip_suffix(".part.met")
                .and_then(|s| s.parse::<u32>().ok())
            {
                max = max.max(n);
            }
        }
    }
    max + 1
}

/// A filename safe to create in `downloads_dir`. P2P filenames are attacker
/// controlled: a name like `../../Library/Preferences/x` or one with a NUL
/// must not escape the directory we chose.
fn safe_filename(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    let cleaned = cleaned.trim().trim_matches('.').to_string();
    if cleaned.is_empty() {
        "download".to_string()
    } else {
        cleaned
    }
}

/// A destination that does not overwrite an existing file: `name`, `name (2)`,
/// `name (3)`... Finishing a download must never silently destroy a file the
/// user already has.
fn unique_dest(dest: PathBuf) -> PathBuf {
    if !dest.exists() {
        return dest;
    }
    let dir = dest.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let stem = dest
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "download".to_string());
    let ext = dest.extension().map(|e| e.to_string_lossy().into_owned());
    for n in 2..1000 {
        let fname = match &ext {
            Some(e) => format!("{stem} ({n}).{e}"),
            None => format!("{stem} ({n})"),
        };
        let cand = dir.join(fname);
        if !cand.exists() {
            return cand;
        }
    }
    dest
}

/// The persisted shared-library file (upstream-faithful `known.met`): the
/// complete files we will re-serve after a restart. Lives in the config dir
/// alongside the other `.met` files; the actual bytes are in the downloads dir.
const KNOWN_MET: &str = "known.met";
const CLIENTS_MET: &str = "clients.met";
const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_FILERATING: u8 = 0xF7;
const FT_FILECOMMENT: u8 = 0xF6;
/// The AICH master root as a base32 STRING tag - both authorities' known.met
/// form (eMule opcodes.h:373 + KnownFile.cpp:930; aMule KnownFile.cpp:833-836).
const FT_AICH_HASH: u8 = 0x27;

/// Load the IP blocklist from the config dir if present. Reads `ipfilter.dat`
/// then `.p2p`/`guarding.p2p` (both text line-forms parse the same), at the
/// default filter level. Returns `None` if no file exists or nothing blocks.
fn load_ip_filter(config_dir: &Path) -> Option<Arc<IpFilter>> {
    let candidates = ["ipfilter.dat", "ipfilter.p2p", "guarding.p2p"];
    let mut text = String::new();
    for name in candidates {
        // Read as bytes + lossy, NOT read_to_string: real community lists carry
        // Latin-1/Windows-1252 bytes in the description field, and strict UTF-8
        // would discard the whole file (fail-open). The parser ignores
        // descriptions, so a lossy decode loads identical ranges.
        if let Ok(bytes) = std::fs::read(config_dir.join(name)) {
            text.push_str(&String::from_utf8_lossy(&bytes));
            text.push('\n');
        }
    }
    if text.trim().is_empty() {
        return None;
    }
    let filter = IpFilter::parse(&text, DEFAULT_IPFILTER_LEVEL);
    if filter.is_empty() {
        None
    } else {
        Some(Arc::new(filter))
    }
}

/// Whether the user's blocklist forbids SENDING a datagram to this address -
/// THE one send gate for the server UDP fan-outs (status probe, global
/// search, crawl). Scoped to PUBLICLY ROUTABLE targets on purpose: a user
/// blocklisting a PUBLIC address is an unambiguous instruction not to talk to
/// it, while private/loopback entries in community lists are almost always
/// generic reserved-range boilerplate rather than a statement about the
/// user's own LAN - and a loopback or LAN server the user added themselves is
/// legitimate (padMule's own eserver oracle runs on 127.0.0.1,
/// scripts/eserver-oracle.sh). Ingestion vetting (`vet_downloaded_servers`)
/// still drops what a downloaded list tries to introduce; this closes the
/// residual gap of an entry that was in server.met before the blocklist
/// loaded, or was hand-added.
///
/// BYTE ORDER: takes an `Ipv4Addr`, so a met-order u32 cannot reach the
/// filter unconverted (the bug that shipped at three sites) - convert with
/// `ip_from_met_u32` at the call site; `IpFilter::is_blocked` does the
/// host-order `u32::from` itself.
fn blocklist_forbids_send(filter: Option<&IpFilter>, ip: Ipv4Addr) -> bool {
    crate::fetch::is_routable_public_v4(ip) && filter.is_some_and(|f| f.is_blocked(ip))
}

/// Rebuild the shared library from `known.met`: every complete file a prior
/// session saved that STILL exists on disk (a user can delete a file from the
/// Files app, and we must not advertise a source we can no longer serve). The
/// on-disk name is stored verbatim, so the path is `downloads_dir / name`.
fn load_shared_library(config_dir: &Path, downloads_dir: &Path) -> Vec<SharedFile> {
    let Ok(bytes) = std::fs::read(config_dir.join(KNOWN_MET)) else {
        return Vec::new();
    };
    let Ok(met) = mule_files::read_known_met(&bytes) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for e in met.entries {
        let (Some(name), Some(size)) =
            (tag_str(&e.tags, FT_FILENAME), tag_u64(&e.tags, FT_FILESIZE))
        else {
            continue;
        };
        let path = downloads_dir.join(&name);
        // Re-share only if the file is still there AND its size matches what we
        // hashed. The downloads dir is the user-visible Files folder, so a file
        // can be deleted and a DIFFERENT one saved under the same name; sharing
        // the old hash would then serve bytes that fail the peer's hash check. A
        // size mismatch reliably flags a replaced/truncated file (we do not
        // re-hash a possibly-huge file on every launch to catch a same-size
        // edit - that is aMule's date-triggered rehash, out of scope on iOS).
        match std::fs::metadata(&path) {
            Ok(m) if m.len() == size => {}
            _ => continue,
        }
        out.push(SharedFile {
            hash: e.file_hash,
            size,
            name: name.into_bytes(),
            part_hashes: e.part_hashes,
            path,
            // Our own rating/comment for this file, if we set one (persisted in
            // the known.met entry). Served to leechers via OP_FILEDESC.
            rating: tag_u64(&e.tags, FT_FILERATING).unwrap_or(0).min(5) as u8,
            comment: tag_str(&e.tags, FT_FILECOMMENT).unwrap_or_default(),
            aich_root: tag_str(&e.tags, FT_AICH_HASH)
                .and_then(|s| mule_proto::aich_from_base32(&s)),
        });
    }
    out
}

/// Append one finished file to `known.met` so it re-shares after a restart.
/// Idempotent by hash. Best-effort: a write failure just means it will not
/// persist, never a crash (the in-memory share still works this session).
fn persist_shared_file(config_dir: &Path, sf: &SharedFile) {
    let path = config_dir.join(KNOWN_MET);
    let mut met = std::fs::read(&path)
        .ok()
        .and_then(|b| mule_files::read_known_met(&b).ok())
        .unwrap_or(mule_files::KnownMet {
            header: mule_files::MET_HEADER,
            entries: Vec::new(),
        });
    if met.entries.iter().any(|e| e.file_hash == sf.hash) {
        return;
    }
    // A file past the 32-bit boundary needs the large-file header + a U64 size
    // tag; otherwise the 32-bit form (matches mule-files' own writer choice).
    let large = sf.size > mule_proto::OLD_MAX_FILE_SIZE;
    if large {
        met.header = mule_files::MET_HEADER_WITH_LARGEFILES;
    }
    let size_val = if large {
        TagValue::U64(sf.size)
    } else {
        TagValue::U32(sf.size as u32)
    };
    let date = std::fs::metadata(&sf.path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0);
    let mut tags = vec![
        Tag::id(FT_FILENAME, TagValue::Str(sf.name.clone())),
        Tag::id(FT_FILESIZE, size_val),
    ];
    // Persist our own rating/comment so it survives a restart and re-serves.
    if sf.rating != 0 {
        tags.push(Tag::id(FT_FILERATING, TagValue::U8(sf.rating)));
    }
    if !sf.comment.is_empty() {
        tags.push(Tag::id(
            FT_FILECOMMENT,
            TagValue::Str(sf.comment.clone().into_bytes()),
        ));
    }
    if let Some(root) = sf.aich_root {
        tags.push(Tag::id(
            FT_AICH_HASH,
            TagValue::Str(mule_proto::aich_base32(&root).into_bytes()),
        ));
    }
    met.entries.push(mule_files::KnownFileEntry {
        date,
        file_hash: sf.hash,
        part_hashes: sf.part_hashes.clone(),
        tags,
    });
    // Atomic: write a temp file then rename over known.met, so a crash mid-write
    // cannot leave a torn file that load_shared_library would read as empty and
    // silently reset the whole library.
    write_known_met_atomic(&path, &met);
}

/// Every AICH root the catalog (known.met) claims - the live set the startup
/// hashset prune keeps. Read from the FILE, not the loaded library, so an
/// entry whose file is momentarily missing from disk keeps its hashset.
fn known_met_aich_roots(config_dir: &Path) -> std::collections::HashSet<[u8; 20]> {
    std::fs::read(config_dir.join(KNOWN_MET))
        .ok()
        .and_then(|b| mule_files::read_known_met(&b).ok())
        .map(|met| {
            met.entries
                .iter()
                .filter_map(|e| tag_str(&e.tags, FT_AICH_HASH))
                .filter_map(|s| mule_proto::aich_from_base32(&s))
                .collect()
        })
        .unwrap_or_default()
}

/// Remove one file (by hash) from `known.met` so it is not re-shared on restart.
/// Caller must hold the known.met lock. A no-op if the file is absent.
fn forget_shared_file(config_dir: &Path, hash: [u8; 16]) {
    let path = config_dir.join(KNOWN_MET);
    let Some(mut met) = std::fs::read(&path)
        .ok()
        .and_then(|b| mule_files::read_known_met(&b).ok())
    else {
        return;
    };
    let before = met.entries.len();
    met.entries.retain(|e| e.file_hash != hash);
    if met.entries.len() != before {
        write_known_met_atomic(&path, &met);
    }
}

/// Update the rating/comment tags on an existing `known.met` entry, so the
/// local user's own rating survives a restart and re-serves via OP_FILEDESC.
/// Caller must hold the known.met lock. A no-op if the file is absent. Passing
/// rating 0 / an empty comment clears that field.
fn update_shared_file_meta(config_dir: &Path, hash: [u8; 16], rating: u8, comment: &str) {
    let path = config_dir.join(KNOWN_MET);
    let Some(mut met) = std::fs::read(&path)
        .ok()
        .and_then(|b| mule_files::read_known_met(&b).ok())
    else {
        return;
    };
    let Some(entry) = met.entries.iter_mut().find(|e| e.file_hash == hash) else {
        return;
    };
    entry.tags.retain(
        |t| !matches!(&t.name, TagName::Id(id) if *id == FT_FILERATING || *id == FT_FILECOMMENT),
    );
    if rating != 0 {
        entry
            .tags
            .push(Tag::id(FT_FILERATING, TagValue::U8(rating)));
    }
    if !comment.is_empty() {
        entry.tags.push(Tag::id(
            FT_FILECOMMENT,
            TagValue::Str(comment.as_bytes().to_vec()),
        ));
    }
    write_known_met_atomic(&path, &met);
}

/// Write `met` to `path` atomically (temp file + rename), so a crash mid-write
/// never leaves a torn known.met that would read back as an empty library.
fn write_known_met_atomic(path: &Path, met: &mule_files::KnownMet) {
    let _ = write_bytes_atomic(path, &mule_files::write_known_met(met));
}

/// Write `bytes` to `path` atomically (temp file + rename), so a crash mid-write
/// (routine on iOS, which suspends/terminates aggressively) never leaves a
/// truncated file that the next launch would choke on.
fn write_bytes_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

/// The engine-side handles a finished download needs, bundled so the completion
/// tail spawned in [`Engine::spawn_fetch`] can hand them off in one move.
struct FinishCtx {
    registry: Arc<Mutex<Vec<Arc<Download>>>>,
    shared: Arc<Mutex<Vec<SharedFile>>>,
    /// Raised once the finished file joins `shared`, so the poll re-offers it.
    shared_dirty: Arc<AtomicBool>,
    config_dir: PathBuf,
    /// Serializes the known.met read-modify-write across concurrently-finishing
    /// downloads (each runs in its own task) so no entry is lost to a race.
    known_met_lock: Arc<Mutex<()>>,
    /// The AICH hashset store: a finished file's tree (built in the verify
    /// pass) is appended here so recovery requests can be served.
    known2: Arc<Known2Store>,
    events: mpsc::UnboundedSender<EngineEvent>,
}

/// Clears a download's in-flight fetch flag on drop, so `try_begin_fetch`'s claim
/// is released no matter how the fetch task exits (cancel, completion, panic).
struct FetchGuard(Arc<Download>);
impl Drop for FetchGuard {
    fn drop(&mut self) {
        self.0.end_fetch();
    }
}

/// Per-IP inbound-connection counter shared by the listener.
///
/// POISON-TOLERANT ([`crate::lock::LockRecover`]): taken on every accepted
/// connection and released in `IpConnSlot::drop`, so a poisoned lock would both
/// close the listener's admission path and turn every later teardown into a
/// panic mid-unwind - a process ABORT. Recovery is safe because the map holds
/// nothing but per-IP counters: a torn update leaves one IP off by one, and the
/// entry is dropped entirely when it reaches zero.
type PerIpConns = Arc<std::sync::Mutex<std::collections::HashMap<Ipv4Addr, u32>>>;

/// RAII slot for one inbound connection from `ip`: decrements the per-IP count on
/// drop (i.e. when the connection task ends). `try_acquire` returns `None` when the
/// IP is already at [`MAX_INBOUND_PER_IP`].
struct IpConnSlot {
    map: PerIpConns,
    ip: Ipv4Addr,
}

impl IpConnSlot {
    fn try_acquire(map: &PerIpConns, ip: Ipv4Addr) -> Option<Self> {
        let mut m = map.lock_recover();
        let n = m.entry(ip).or_insert(0);
        if *n >= MAX_INBOUND_PER_IP {
            return None;
        }
        *n += 1;
        Some(IpConnSlot {
            map: Arc::clone(map),
            ip,
        })
    }
}

impl Drop for IpConnSlot {
    fn drop(&mut self) {
        let mut m = self.map.lock_recover();
        if let Some(n) = m.get_mut(&self.ip) {
            *n = n.saturating_sub(1);
            if *n == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

/// Verify a finished download and move it into place.
///
/// The whole-file ed2k hash is checked FIRST, and this is not belt-and-braces:
/// `download_file` never calls `verify_ready_parts`, and a file of one part has
/// no part hash to verify against at all, so this is the ONLY thing standing
/// between corrupt bytes and the user's Files app. We asked for hash X; we hand
/// over hash X or nothing. It is computed part-by-part so a large file is never
/// held in memory.
async fn finish_download(
    dl: Arc<Download>,
    ctx: FinishCtx,
    hash: [u8; 16],
    size: u64,
    dest: PathBuf,
) {
    let FinishCtx {
        registry,
        shared,
        shared_dirty,
        config_dir,
        known_met_lock,
        known2,
        events,
    } = ctx;
    let name = dl.name().await;
    // One streaming pass verifies the MD4 AND builds the AICH tree the shared
    // file will serve recovery data from.
    let (verified, aich_set) = dl.verify_whole_file_and_aich(size, hash).await;
    if !verified {
        // Blame the individual corrupt part(s) against the hashset and re-open only
        // those, so one bad source does not force re-downloading the WHOLE file
        // (localize_corruption hashes off the download lock, so it never stalls the
        // heartbeat). Fall back to a full re-open only when no part can be blamed
        // (a single-part file, or a spoofed hashset). Either way the download STAYS
        // registered and the next resume re-drives it - never stranded at 100%.
        if !dl.localize_corruption().await {
            dl.reset_all_gaps().await;
        }
        dl.reset_finalize();
        let _ = events.send(EngineEvent::Server(format!(
            "'{name}' failed verification - will re-fetch on the next resume"
        )));
        return;
    }
    // Cancelled during the (multi-second) verify window: do NOT save or share a
    // file the user just cancelled (it would land in Documents + re-seed to the
    // swarm on every start). finish_to re-checks under the lock to close the
    // remaining tiny window atomically.
    if dl.is_cancelled() {
        return;
    }
    // A finished file becomes a shared source, and answering OP_HASHSETREQUEST
    // needs these.
    let part_hashes = dl.part_hashes().await;
    // The download is complete: it leaves the active registry and (below) joins
    // the shared library.
    registry.lock().await.retain(|d| !Arc::ptr_eq(d, &dl));
    if let Some(parent) = dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let dest = unique_dest(dest);
    // finish_to moves the file THROUGH the download's lock (not via Arc::try_unwrap),
    // so a concurrent Arc holder - the 1s downloads() poll, cancel, or
    // set_download_priority - can no longer strand a byte-complete .part.
    match dl.finish_to(&dest).await {
        Ok(()) => {
            // A cancel that raced the move (landed after finish_to's under-lock
            // check but before we share) must NOT re-seed the file. It is already in
            // Documents; just skip adding it to the shared library / known.met, so a
            // cancelled file is never re-announced to the swarm on future starts.
            if dl.is_cancelled() {
                return;
            }
            // Seed it: a verified, complete file is a full source other peers can
            // pull. The listener only serves it while sharing is on. Use the
            // ACTUAL on-disk name (unique_dest may have renamed it), so the
            // persisted library can rebuild `path` as downloads_dir / name.
            let on_disk_name = dest
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or(name.clone());
            // Store the AICH hashset first, so the known.met root tag never
            // points at a hashset that failed to persist (append is
            // dedup + rollback-safe; a failure just leaves aich_root None and
            // recovery requests draw the honest refusal).
            let aich_root = match &aich_set {
                Some((root, leaves)) => known2.append(root, leaves).is_ok().then_some(*root),
                None => None,
            };
            let sf = SharedFile {
                hash,
                size,
                name: on_disk_name.into_bytes(),
                part_hashes,
                path: dest.clone(),
                rating: 0, // the user can rate it later
                comment: String::new(),
                aich_root,
            };
            {
                // Serialize the known.met read-modify-write against other
                // finishing downloads (re-share after a restart).
                let _g = known_met_lock.lock().await;
                persist_shared_file(&config_dir, &sf);
            }
            shared.lock().await.push(sf);
            // The library grew while we may be logged in: signal the poll to
            // re-announce it (OP_OFFERFILES) so the new file is findable without
            // waiting for a reconnect.
            shared_dirty.store(true, Ordering::Relaxed);
            let saved = dest
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let _ = events.send(EngineEvent::Server(format!("Saved '{saved}'")));
            let _ = events.send(EngineEvent::Finished { name: saved });
        }
        Err(e) => {
            let _ = events.send(EngineEvent::Server(format!("could not save '{name}': {e}")));
        }
    }
}

/// Serve one leecher: a peer that reached our listener and asked for a file
/// (`first` is the request packet the listener already read).
///
/// In Leech Mode (sharing off) we honestly decline with "no file" so the peer
/// moves on. Otherwise we serve, and [`serve_shared`] handles the slot: it
/// grants one immediately if free, or QUEUES the peer (OP_QUEUERANKING) and
/// grants a freed slot in place. The permit is held inside serve_shared for the
/// whole session.
#[allow(clippy::too_many_arguments)]
async fn serve_inbound<S>(
    fs: &mut FramedStream<S>,
    shared: &Arc<Mutex<Vec<SharedFile>>>,
    sharing: &Arc<AtomicBool>,
    gate: &Arc<UploadGate>,
    first: Packet,
    peer_accept_comment: u8,
    session: crate::share::ServeSession,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !sharing.load(Ordering::Relaxed) {
        // Leech Mode: we may hold the file, but we are not sharing - say so.
        if let Some(h) = head_hash(&first.payload) {
            let _ = fs.write_packet(&build_file_req_ans_no_fil(&h)).await;
        }
        return;
    }
    let library = shared.lock().await.clone();
    let _ = serve_shared(
        fs,
        &library,
        Some(first),
        Some(gate),
        peer_accept_comment,
        session,
    )
    .await;
}

/// What [`Engine::add_download`] did. Not an Error type: "no sources yet" is a
/// normal answer on a P2P network, not a failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddResult {
    /// Registered and the transfer is running.
    Started,
    /// This hash is already downloading.
    AlreadyAdded,
    /// Nobody we could ASK has this file. Only returned when we actually had a
    /// way to ask - see `NotConnected` for the other case.
    NoSources,
    /// We have no way to find sources at all: no server connected AND no Kad
    /// contacts. Distinct from `NoSources` on purpose. Reporting "nobody has this
    /// file" to a user who is simply not connected is a claim about the NETWORK
    /// when the truth is about them, and it sends them hunting for a different
    /// file instead of connecting. (Was `NoServer`, which was unreachable in the
    /// shipped app - it fired only under `offline`, which the FFI never exports,
    /// so this branch never once reached a user.)
    NotConnected,
    /// The request itself made no sense.
    BadRequest(&'static str),
    /// Could not create the part file.
    Failed(String),
}

/// Whether a search hit is something we already have, are fetching, or is new.
/// Mirrors eMule's colored result states. "Have" is best-effort: it knows files
/// finished this session (shared library) + complete downloads, not files sitting
/// in the downloads directory from a prior run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HitStatus {
    New,
    Downloading,
    Have,
}

/// A distilled Kad keyword result in the raw tagged shape the [`catalog`]
/// expects, so server and Kad hits for one hash dedupe and rank together. The id
/// tags mirror `catalog`'s: 0x01 filename, 0x02 filesize, 0x15 sources.
fn kad_to_search(f: &mule_kad::FileResult) -> SearchResultFile {
    SearchResultFile {
        hash: f.hash,
        id: 0,
        port: 0,
        tags: vec![
            Tag::id(0x01, TagValue::Str(f.name.as_bytes().to_vec())),
            Tag::id(0x02, TagValue::U64(f.size)),
            Tag::id(0x15, TagValue::U32(f.sources)),
        ],
    }
}

/// Global server UDP search (#9): send OP_GLOBSEARCHREQ to every server in
/// `server.met`'s UDP port (TCP port + 4), skipping `connected` (already queried
/// over TCP) and any entry the user's blocklist gates (`blocklist_forbids_send`,
/// publicly routable targets only), and collect OP_GLOBSEARCHRES replies for
/// `budget`. Best-effort: honors only replies from IPs we asked (anti-spoof),
/// dedupes by hash, and returns `[]` on any setup failure. Bounded to the first
/// `MAX_GLOBAL_SERVERS`.
async fn global_udp_search(
    config_dir: &Path,
    params: &SearchParams,
    connected: Option<SocketAddr>,
    filter: Option<&IpFilter>,
    budget: Duration,
) -> Vec<SearchResultFile> {
    const MAX_GLOBAL_SERVERS: usize = 40;
    // Cap collected hits so a flooding/malicious server cannot grow this
    // unbounded during the window (eMule caps a search at MAX_RESULTS too).
    const MAX_GLOBAL_HITS: usize = 300;
    let Some(met) = std::fs::read(config_dir.join("server.met"))
        .ok()
        .and_then(|b| read_server_met(&b).ok())
    else {
        return Vec::new();
    };
    let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0u16)).await else {
        return Vec::new();
    };
    let sock = Arc::new(sock);
    let pkt = build_global_search_udp(params);
    let mut req = vec![pkt.protocol, pkt.opcode];
    req.extend_from_slice(&pkt.payload);

    let asked: Arc<Mutex<std::collections::HashSet<Ipv4Addr>>> =
        Arc::new(Mutex::new(std::collections::HashSet::new()));
    let hits: Arc<Mutex<Vec<SearchResultFile>>> = Arc::new(Mutex::new(Vec::new()));

    let (rsock, rasked, rhits) = (Arc::clone(&sock), Arc::clone(&asked), Arc::clone(&hits));
    let recv = tokio::spawn(async move {
        let mut buf = [0u8; 16 * 1024];
        while let Ok((n, src)) = rsock.recv_from(&mut buf).await {
            if n < 2 {
                continue;
            }
            let IpAddr::V4(sip) = src.ip() else { continue };
            if !rasked.lock().await.contains(&sip) {
                continue; // anti-spoof: only a server we asked this search
            }
            if buf[0] == mule_proto::PROT_EDONKEY && buf[1] == OP_GLOBSEARCHRES {
                let files = parse_global_search_res(&buf[2..n]).unwrap_or_default();
                let mut h = rhits.lock().await;
                for f in files {
                    if h.len() >= MAX_GLOBAL_HITS {
                        break;
                    }
                    if !h.iter().any(|x| x.hash == f.hash) {
                        h.push(f);
                    }
                }
            }
        }
    });

    let deadline = tokio::time::Instant::now() + budget;
    for srv in met.servers.iter().take(MAX_GLOBAL_SERVERS) {
        if srv.ip == 0 || srv.port == 0 {
            continue;
        }
        let Some(udp_port) = srv.port.checked_add(4) else {
            continue;
        };
        let ip = ip_from_met_u32(srv.ip);
        if connected == Some(SocketAddr::new(IpAddr::V4(ip), srv.port)) {
            continue; // already queried over TCP
        }
        // THE BLOCKLIST GATES THIS SEND (2026-08-09), publicly routable targets
        // only - `blocklist_forbids_send` has the scoping rationale. `ip` is
        // the real address (converted from the met u32 just above), so the
        // filter sees host order. Skipped BEFORE `asked`, so a reply spoofed
        // from a gated address stays rejected, and before the pace sleep, so a
        // gated entry costs the fan-out no time.
        if blocklist_forbids_send(filter, ip) {
            continue;
        }
        asked.lock().await.insert(ip);
        let _ = sock
            .send_to(&req, SocketAddr::new(IpAddr::V4(ip), udp_port))
            .await;
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(deadline.saturating_duration_since(tokio::time::Instant::now())).await;
    recv.abort();
    let h = hits.lock().await;
    h.clone()
}

/// A privacy-safe label for a server state. NEVER Debug-format `ServerState`: its
/// `Connected.id` is our client id, which ENCODES our public IP on HighID, and
/// this string reaches the (screenshotted, public-repo) UI notice.
fn server_state_label(s: &ServerState) -> String {
    match s {
        ServerState::Disconnected => "Disconnected".into(),
        ServerState::Connecting => "Connecting".into(),
        ServerState::Connected { low_id, .. } => {
            format!("Connected ({})", if *low_id { "LowID" } else { "HighID" })
        }
        ServerState::PausedForBackground => "Paused".into(),
        ServerState::Rejected => "Rejected".into(),
    }
}

/// Flatten a server-link event into the UI's event stream.
fn map_server_event(e: ServerEvent) -> EngineEvent {
    match e {
        ServerEvent::State(s) => EngineEvent::Server(server_state_label(&s)),
        ServerEvent::Message(m) => {
            // Attribute + length-cap the server's MOTD, so a hostile server's text
            // (e.g. a fake "Your IP is x.x.x.x") is never shown as padMule's OWN
            // words, and a huge message cannot bloat the UI. char-safe truncation.
            let capped: String = m.chars().take(500).collect();
            EngineEvent::Server(format!("[server] {capped}"))
        }
        ServerEvent::Status { users, files } => {
            EngineEvent::Server(format!("{users} users, {files} files"))
        }
        ServerEvent::ServerList(l) => EngineEvent::Server(format!("{} servers known", l.len())),
    }
}

/// The coarse lifecycle state the UI shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EngineState {
    /// Not started (or shut down): no sockets, nothing running.
    Stopped,
    /// Foreground: sockets live, server/Kad connected, transfers active.
    Running,
    /// Backgrounded: sockets released, state checkpointed, transfers paused.
    Paused,
    /// Backgrounded but STILL SERVING: the inbound listener and the server
    /// login stay up so peers can keep downloading from us, while everything
    /// that initiates work - Kad, new fetches - is stopped.
    ///
    /// This state only means anything while an iOS audio keepalive is holding
    /// the app awake; without one the process is suspended moments later and
    /// this is indistinguishable from `Paused`. It is a SEPARATE state rather
    /// than a flag on `Running` because the honest-status rule
    /// (docs/wiki/lifecycle-and-reactivation.md) turns on the user being told
    /// which of these three things is true, and "Running" while backgrounded
    /// would be the dishonest-status failure that entry calls a hard
    /// requirement.
    Seeding,
}

/// An observable engine event. Kept simple (no lifetimes/generics) so the Wave-8
/// UniFFI layer can carry it to Swift directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineEvent {
    /// Our public address changed between two HighID logins - most importantly,
    /// a VPN tunnel that dropped. Carries NO payload: the address is exactly
    /// what must not reach the screen (see `connect_to_server`, which refuses to
    /// record the client id for the same reason). Sharing has already been
    /// paused by the time this is emitted.
    PublicAddressChanged,
    /// The coarse lifecycle state changed.
    State(EngineState),
    /// A human-readable status line ("Reconnecting...", "Connected", "Paused").
    Status(String),
    /// A server connection update.
    Server(String),
    /// The server we were connected to CLOSED the connection (a clean kick or a
    /// drop we did not request). The UI raises a prominent dialog so there is no
    /// mistaking what happened. `addr` is the server we lost.
    ServerDropped { addr: String },
    /// Kad status: the routing table now holds this many contacts.
    Kad { contacts: usize },
    /// Per-download progress.
    Progress {
        hash: [u8; 16],
        have: u64,
        total: u64,
    },
    /// A download COMPLETED: hash-verified and moved into the downloads folder.
    ///
    /// A typed event rather than leaving the UI to string-match the "Saved '..'"
    /// server line that accompanies it. That line is user-facing NEWS whose
    /// wording is free to change; a completion is a fact the UI acts on (the
    /// finish beep), and matching on prose would break silently the first time
    /// someone reworded it.
    Finished { name: String },
}

/// One row of the Servers screen: a server from `server.met`, enriched with a
/// live UDP status probe. `alive` servers are selectable; the rest are shown
/// greyed out. `users`/`files` are `None` until a probe answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerEntry {
    pub addr: SocketAddr,
    pub name: String,
    pub users: Option<u32>,
    pub files: Option<u32>,
    pub alive: bool,
    pub connected: bool,
    /// A user favorite: kept by `prune_dead_servers` even when down.
    pub pinned: bool,
    /// Silent so far, but not yet called DEAD: it has never answered us and has
    /// missed fewer than `PROBE_MISSES_BEFORE_DEAD` rounds.
    ///
    /// The third state exists because two were a lie. `alive: false` was being
    /// rendered as "no reply", which is a VERDICT, and on a cold start every
    /// server is in that bucket after ONE silent round - the probe's history map
    /// is in memory, so a fresh launch has nothing to vouch for anybody. That is
    /// the same "one datum is never a verdict" rule the miss counter already
    /// encodes for servers WITH history, missing from the branch for servers
    /// without. Proven on 2026-08-05: padMule showed `eMule Sunrise` as "no
    /// reply" and then logged into it with HighID moments later.
    pub checking: bool,
}

/// What the server told us at login. Kept because HighID-vs-LowID decides
/// whether peers can reach us at all, and on a sideloaded iPad there is no
/// debugger - this screen IS the diagnostic.
///
/// Deliberately does NOT carry the client id: a HighID id ENCODES our public
/// IP, and this struct exists to be rendered on a screen that gets
/// screenshotted. `low_id` is the whole answer; the id itself is not worth the
/// leak.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// The server we are logged into ("ip:port").
    pub addr: String,
    /// The server's display name (server.met tag 0x01), if known. Servers are
    /// public infrastructure, so this is safe to show - unlike our own client id.
    pub name: Option<String>,
    /// True when the server handed us a LowID (no reachable inbound port).
    pub low_id: bool,
    /// True when this server answers related-files searches (advertised
    /// SRV_TCPFLG_RELATEDSEARCH), so the UI can offer the true `related::`
    /// query instead of the filename-keyword fallback.
    pub related_search: bool,
}

/// Optional pre-search filters pushed onto the server query (and re-applied to
/// the merged result set so Kad hits obey them too). `None` = unfiltered.
#[derive(Debug, Clone, Copy, Default)]
pub struct SearchFilters {
    /// Minimum availability (source count). `Some(1)` = complete/live only.
    pub min_sources: Option<u32>,
    /// Minimum / maximum file size in BYTES.
    pub min_size: Option<u64>,
    pub max_size: Option<u64>,
    /// Also query the whole serverlist over UDP (global search), not just the
    /// connected server. Off by default (more traffic + noisier results).
    pub global: bool,
}

/// Status scalars PUBLISHED as atomics so a reader never takes the engine lock.
///
/// WHY: measured on device 2026-08-07, a "Refresh server list" tapped 1.9s into
/// a search took 20.62s against 7.5-9.3s idle - a user action waiting ~12s
/// behind another. Three of the four values the 1s UI poll reads are trivial
/// field reads (`state` is a Copy enum, `sharing_paused_for_ip_change` a bool,
/// `ip_filter_ranges` an `Arc::len`) and they were each taking a lock that a
/// search can hold for twenty seconds. Reading a bool must not queue behind
/// network I/O.
///
/// Same lock-free idea as `EngineHandles`' existing fields, extended to the
/// scalars. NOT a cache to be invalidated: every value has exactly one writer
/// inside the engine, which publishes on change.
#[derive(Clone, Default)]
pub struct StatusPub {
    state: Arc<AtomicU8>,
    ip_paused: Arc<AtomicBool>,
    ipfilter_ranges: Arc<AtomicUsize>,
    kad_contacts: Arc<AtomicUsize>,
    /// The live login. Not an atomic - it is a small struct - but a `std` mutex
    /// held only long enough to clone it, never across an await, exactly like
    /// `EngineHandles::public_ip`. That is what makes it lock-FREE in the sense
    /// that matters here: a reader cannot end up queued behind network I/O.
    server: Arc<std::sync::Mutex<Option<ServerInfo>>>,
}

impl StatusPub {
    fn set_state(&self, s: EngineState) {
        self.state.store(s as u8, Ordering::Relaxed);
    }
    fn state(&self) -> EngineState {
        match self.state.load(Ordering::Relaxed) {
            1 => EngineState::Running,
            2 => EngineState::Paused,
            3 => EngineState::Seeding,
            _ => EngineState::Stopped,
        }
    }
}

/// The parts of the engine a READ-ONLY caller can reach WITHOUT the engine lock.
///
/// Every FFI poll used to go through `Mutex<Engine>`, so a ~20s search or ~10s
/// crawl - which holds `&mut self` across its whole `tokio::join!` - blocked the
/// 1s UI poll behind it and the transfer numbers froze. But five of those polls
/// never needed engine STATE at all: the downloads list, the shared library, the
/// sharing switch and the public IP are already `Arc`s, and the byte totals are
/// process-global atomics. They took the lock purely because they were methods
/// on `Engine`.
///
/// Handing out clones is not a new pattern here - the engine already clones
/// these same `Arc`s into spawned tasks in seven places - and none of them is
/// ever REASSIGNED, so a handle taken once at construction stays valid for the
/// engine's life. That last property is what makes this safe; if any of these
/// fields were ever replaced rather than mutated in place, a handle would
/// silently go stale and the UI would read a dead copy forever.
#[derive(Clone)]
pub struct EngineHandles {
    downloads: Arc<Mutex<Vec<Arc<Download>>>>,
    shared: Arc<Mutex<Vec<SharedFile>>>,
    sharing: Arc<AtomicBool>,
    public_ip: Arc<std::sync::Mutex<Option<Ipv4Addr>>>,
    /// The engine's max-active cap, shared so the FFI's queued computation
    /// reads the SAME value the sweeps enforce.
    max_active: Arc<std::sync::atomic::AtomicU32>,
    status: StatusPub,
}

impl EngineHandles {
    /// The in-progress downloads. Clones `Arc`s, not files.
    pub async fn downloads(&self) -> Vec<Arc<Download>> {
        self.downloads.lock().await.clone()
    }

    /// The max-active cap (0 = unlimited) - lock-free, for the row builder.
    pub fn max_active(&self) -> u32 {
        self.max_active.load(Ordering::Relaxed)
    }

    /// The shared library, in the same shape `Engine::shared_files` returns.
    pub async fn shared_files(&self) -> Vec<([u8; 16], String, u64, u8, String)> {
        self.shared
            .lock()
            .await
            .iter()
            .map(|s| {
                (
                    s.hash,
                    String::from_utf8_lossy(&s.name).into_owned(),
                    s.size,
                    s.rating,
                    s.comment.clone(),
                )
            })
            .collect()
    }

    pub fn is_sharing(&self) -> bool {
        self.sharing.load(Ordering::Relaxed)
    }

    pub fn has_port_mapping(&self) -> bool {
        self.public_ip.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// Session byte totals - process-global atomics, never engine state.
    pub fn transfer_totals(&self) -> (u64, u64) {
        (crate::stats::downloaded(), crate::stats::uploaded())
    }

    /// The four status scalars the 1s UI poll reads, WITHOUT the engine lock.
    /// See [`StatusPub`] for why this exists.
    pub fn state(&self) -> EngineState {
        self.status.state()
    }
    pub fn kad_contacts(&self) -> usize {
        self.status.kad_contacts.load(Ordering::Relaxed)
    }
    pub fn ip_filter_ranges(&self) -> usize {
        self.status.ipfilter_ranges.load(Ordering::Relaxed)
    }
    pub fn sharing_paused_for_ip_change(&self) -> bool {
        self.status.ip_paused.load(Ordering::Relaxed)
    }
    /// The live login, or `None` when no server has us.
    ///
    /// This one was MISSED by the 2026-08-07 lock-free round: it moved onto the
    /// lock-free UI poll with the other four while the FFI method behind it still
    /// took the engine lock, so the whole "fast" poll - and, because it shares a
    /// queue with the event drain, the status banners too - still stalled for the
    /// length of every search. Found by the 2026-08-07 reanalysis.
    pub fn server_info(&self) -> Option<ServerInfo> {
        self.status.server.lock().ok().and_then(|g| g.clone())
    }
}

/// What the last successful status probe of a server said, and how many probes
/// have gone unanswered since. A server is only shown DEAD once it has missed
/// `PROBE_MISSES_BEFORE_DEAD` in a row.
#[derive(Clone, Copy)]
struct ProbeHealth {
    users: u32,
    files: u32,
    misses: u8,
    /// Has this server EVER answered a probe? Distinguishes "silent and known
    /// good" (keep showing its last counts) from "silent and unknown" (say so).
    answered: bool,
}

/// How many consecutive silent probes before a server is called dead. Three
/// rounds of UDP loss in a row is a real signal; one is just UDP.
const PROBE_MISSES_BEFORE_DEAD: u8 = 3;

/// Collection budget for the whole status fan-out. Was 3s, which is tight once
/// the path runs through a VPN (~200ms base RTT before the server even thinks)
/// and the fan-out is dozens of servers.
///
/// A CEILING, not the cost: see `PROBE_QUIET_PERIOD`.
const PROBE_COLLECT_BUDGET: Duration = Duration::from_secs(6);

/// How long the probe keeps listening after the LAST answer arrived.
///
/// The budget above used to be spent in full on every round, because the collect
/// loop had no reason to stop before the deadline - so a probe cost 6s whether
/// the servers answered in 200ms or not at all, and it costs that under the
/// engine lock, twice on every launch plus every Refresh and Prune. UDP answers
/// to a fan-out arrive in a burst about one round trip after the sends; two
/// seconds of complete silence after the last of them means the rest are not
/// coming this round.
///
/// Deliberately generous against the RTT it has to cover (~200ms through a
/// tunnel), because cutting a slow-but-live server short costs it a MISS, and
/// three consecutive misses is what greys a server out - the exact
/// one-datum-is-a-verdict failure `fold_probe_round` exists to prevent.
const PROBE_QUIET_PERIOD: Duration = Duration::from_secs(2);

/// What one probe round concluded about one server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProbeVerdict {
    alive: bool,
    checking: bool,
    users: u32,
    files: u32,
}

/// Fold ONE probe round for one server against what we remember of it, updating
/// that memory and returning what the row should say.
///
/// Extracted so the TEST drives the real rule instead of a copy of it. It used
/// to re-implement this fold, which meant it could go green while production
/// diverged - the exact shape [[interop-test-fidelity]] warns about, and it
/// mattered the moment the rule gained a third outcome.
///
/// The rule: an answer is always believed and resets the miss count. Silence is
/// only a VERDICT after `PROBE_MISSES_BEFORE_DEAD` rounds; before that a server
/// that has answered before keeps its last good numbers, and one that never has
/// is reported as still being CHECKED rather than as dead.
fn fold_probe_round(h: &mut ProbeHealth, answered: bool, users: u32, files: u32) -> ProbeVerdict {
    if answered {
        *h = ProbeHealth {
            users,
            files,
            misses: 0,
            answered: true,
        };
        return ProbeVerdict {
            alive: true,
            checking: false,
            users,
            files,
        };
    }
    h.misses = h.misses.saturating_add(1);
    if h.misses >= PROBE_MISSES_BEFORE_DEAD {
        return ProbeVerdict {
            alive: false,
            checking: false,
            users: 0,
            files: 0,
        };
    }
    ProbeVerdict {
        alive: h.answered,
        checking: !h.answered,
        users: h.users,
        files: h.files,
    }
}

/// The padMule engine. Create with [`Engine::new`], drive with the lifecycle
/// methods, observe via the returned event receiver.
pub struct Engine {
    identity: NodeIdentity,
    config_dir: PathBuf,
    state: EngineState,
    /// When the last periodic checkpoint ran (see `maintain_checkpoint`).
    last_checkpoint: Instant,
    last_share_verify: Instant,
    last_resume_retry: Instant,
    /// Max simultaneously-DRIVEN downloads (0 = unlimited); the rest report
    /// QUEUED and are admitted in add order as slots free, except that a row
    /// ACTIVELY RECEIVING keeps its slot first. Shared with
    /// `EngineHandles` so the FFI row builder reads the same value the sweeps
    /// enforce; the one admission rule is `multi_source::queued_flags`.
    max_active: Arc<std::sync::atomic::AtomicU32>,
    /// When `maintain_kad` last refreshed the routing table.
    last_kad_refresh: Instant,
    /// When the liveness sweep (`OnSmallTimer`) last ran.
    last_kad_sweep: Instant,
    /// When the publish scheduler last ran a job.
    last_kad_publish: Instant,
    /// The Kad publish SCHEDULE: which shared file / keyword is due to be
    /// (re)announced to the DHT, and when each was last done. Pure policy in
    /// [`crate::kad_publish`]; `maintain_kad_publish` drives the I/O.
    publish_schedule: crate::kad_publish::PublishSchedule,
    events: mpsc::UnboundedSender<EngineEvent>,
    /// Persisted Kad contacts (loaded from / saved to `nodes.dat`).
    routing: RoutingTable,
    /// In-progress downloads (resumed from disk on start). Shared with the
    /// listener task: a peer that connects to US (a LowID source we asked the
    /// server to call back) has to be routed into the download it is answering,
    /// and the listener cannot borrow `&self`.
    downloads: Arc<Mutex<Vec<Arc<Download>>>>,
    /// Where COMPLETED files are moved. Defaults to `config_dir/downloads`; on
    /// iOS the app passes its Documents dir so the Files app can see them - a
    /// finished file nobody can open is not a finished download.
    downloads_dir: PathBuf,
    /// Complete files we will serve to peers, populated as downloads finish.
    /// Shared with the listener, which serves them on request (the upload side).
    shared: Arc<Mutex<Vec<SharedFile>>>,
    /// Status scalars mirrored for lock-free reads - see [`StatusPub`].
    status: StatusPub,
    /// Set when the shared library grows mid-session (a download finishing), so
    /// the next heartbeat() re-announces it to the server (OP_OFFERFILES).
    /// Cloned into each download's completion task, which has no path to `server`.
    shared_dirty: Arc<AtomicBool>,
    /// Servers a connected server advertised via OP_SERVERLIST, awaiting merge
    /// into server.met on the 1s heartbeat. The heartbeat is the race-free spot:
    /// it runs on the same task as update_server_list, so there is never a
    /// concurrent server.met write. A std mutex, held only briefly, never across
    /// an await. This is the Server Hunter gossip crawl's first step.
    harvested_servers: Arc<std::sync::Mutex<Vec<(u32, u16)>>>,
    /// Ask a fresh login for the server's own server list (OP_GETSERVERLIST) -
    /// eMule's "update server list when connecting" pref (AddServersFromServer).
    /// BOTH authorities default it OFF (eMule 0.50a Preferences.cpp:2105, aMule
    /// 3.0.1 Preferences.cpp:1175); padMule defaults it ON as a DELIBERATE,
    /// documented policy deviation: the wire bytes and timing are identical,
    /// the harvest merge is already filtered + bounded, one bodiless packet per
    /// connect is negligible, and a default-off pref would leave the Server
    /// Hunter harvest inert on every fresh install - the exact inertness the
    /// 2026-08-03 device pass proved (docs/wiki/feature-server-hunter.md).
    add_servers_from_server: bool,
    /// The upload switch. `false` is "Leech Mode": we still download, but serve
    /// nothing. An atomic so the listener task reads it without taking a lock.
    sharing: Arc<AtomicBool>,
    /// Upload slots + wait queue (see `MAX_UPLOAD_SLOTS` / `UPLOAD_QUEUE_CAP`).
    /// Shared with the listener; serve_shared grants/queues against it.
    upload_gate: Arc<UploadGate>,
    /// Serializes known.met writes across concurrently-finishing downloads.
    known_met_lock: Arc<Mutex<()>>,
    /// The known2_64.met AICH hashset store (append on finish, serve on
    /// OP_AICHREQUEST, prune at start against the catalog).
    known2: Arc<Known2Store>,
    /// Per-peer credit history (bytes moved + verified key), keyed by userhash.
    /// Loaded from `clients.met` on `new`, written back on `pause`. Shared with
    /// the listener so it can accrue upload bytes + bind a verified leecher.
    credit_store: Arc<CreditStore>,
    /// The live eD2k server link, once logged in.
    server: Option<ServerLink>,
    /// What that login yielded (server address + HighID/LowID), for the UI.
    connection: Option<ServerInfo>,
    /// The live Kad node (owns the UDP socket), once bootstrapped.
    kad: Option<KadNode>,
    /// The last HighID client id we were assigned, which IS our public address.
    /// Kept ONLY to notice a change; never emitted, never rendered.
    last_public_id: Option<u32>,
    /// True while sharing is off BECAUSE the address changed, so the UI can keep
    /// saying why and `set_sharing(true)` can clear it. DURABLE: mirrored by a
    /// marker file (see `ip_pause_path`) that `new()` restores, so a relaunch
    /// comes back still paused - and still able to say why.
    sharing_paused_for_ip_change: bool,
    /// The port we BIND for inbound peer connections.
    listen_port: u16,
    /// The port we ADVERTISE to servers and peers. Differs from `listen_port`
    /// only when something OUTSIDE the app forwards a different external port
    /// to us - which is exactly what a VPN doing remote->local port forwarding
    /// does (AirVPN, for one, lets a remote port n reach a different local port
    /// x). Peers dial what the server hands out, so the advertised port must be
    /// the EXTERNAL one even though we listen on the local one.
    advertised_port: u16,
    /// The Kad UDP bind port.
    kad_port: u16,
    /// The Kad UDP port to ADVERTISE, when a VPN forwards a remote port to a
    /// DIFFERENT local one. `kad_port` is what we BIND (and must match what the
    /// provider forwards TO); this is what peers are told to dial.
    kad_advertised_port: u16,
    /// Whether to attempt UPnP at all. Pointless - and its failure line
    /// misleading - when a VPN tunnel is carrying the traffic, because the
    /// mapping would be made on the LAN router the tunnel bypasses.
    upnp_enabled: bool,
    /// The name we announce to peers (CT_NAME in the HELLO) and to servers
    /// (CT_NAME in the login). Always the sanitized form - `set_nickname` is the
    /// only writer and it never stores anything `sanitize_nick` would reject, so
    /// every reader gets a value that is safe to put on the wire as-is.
    nick: String,
    /// Our public IPv4, as UPnP/SSDP reported it (`theApp.GetPublicIP`). Learned
    /// in `map_port`, fed to the Kad node so it can echo a peer's UDP verify key
    /// (bound to THIS ip) and be verified faster. `None` until a mapping succeeds;
    /// a stale value only disables the echo (the key-echo gate is IP-equality),
    /// never mis-verifies. Host order (first octet = MSByte), matching
    /// `udp_verify_key`. Never emitted - it is our public IP verbatim.
    ///
    /// Shared so the spawned mapping-retry task can record a mapping it
    /// creates; a plain field could only ever be written on the engine task.
    public_ip: Arc<std::sync::Mutex<Option<Ipv4Addr>>>,
    /// The inbound peer listener's accept loop (dropping it frees port 4662).
    listener: Option<JoinHandle<()>>,
    /// Sender handed to each ServerLink; its forwarder task is spawned once.
    server_tx: Option<mpsc::Sender<ServerEvent>>,
    /// The IP blocklist (ipfilter.dat / .p2p), if the user placed one. Shared with
    /// the listener task so inbound peers are gated too. `None` = no filtering.
    ip_filter: Option<Arc<IpFilter>>,
    /// When we last issued a SERVER search, for the client-side flood guard
    /// ([`SERVER_SEARCH_MIN_INTERVAL`]). In-memory only; a fresh session may search
    /// at once. `None` = never searched this session.
    last_server_search: Option<Instant>,
    /// The live server-search window for "load more" (see [`SearchSession`]).
    search_session: Option<SearchSession>,
    /// Servers the user pinned (canonical `"ip:port"` keys), so `prune_dead_servers`
    /// keeps them even when down. Persisted to `config_dir/pinned.txt`.
    pinned: std::collections::HashSet<String>,
    /// Last GOOD probe answer per server, plus how many probes have missed since.
    ///
    /// A status probe is UDP, and UDP loses datagrams - more so through a VPN
    /// tunnel at ~200ms RTT. Treating one silent round as DEATH is the "an event
    /// is not state" bug again: it greyed out servers that were answering fine
    /// moments earlier, and that padMule had been connecting to. Observed
    /// directly - the same two servers read "no reply" and then 3,651 / 47,008
    /// users minutes apart, which no dead server does.
    server_health: Arc<std::sync::Mutex<HashMap<SocketAddr, ProbeHealth>>>,
    /// Suppress ALL network activity. Tests set this so the unit suite never
    /// touches the real network; the UI never does.
    offline: bool,
}

/// Path of the ip-change pause marker. Its EXISTENCE is the state: written the
/// moment `note_public_id` trips the guard, deleted when the user turns sharing
/// back on (`set_sharing(true)`), checked by `Engine::new` so a relaunch comes
/// back still paused. The pause must outlive the process, because the guard's
/// whole premise is that the USER decides when to resume - as an in-memory
/// latch it was the "an event is not state" defect again: the sharing
/// PREFERENCE stays ON and is pushed at every boot, so an app relaunch
/// silently resumed serving from the address the user did not choose (observed
/// on glass 2026-08-09, a VPN recycle then a relaunch). The file's content is
/// one explanatory line for a human reading the config dir; only existence is
/// consulted.
fn ip_pause_path(config_dir: &Path) -> PathBuf {
    config_dir.join("sharing_paused_for_ip_change.txt")
}

impl Engine {
    /// Load (or create) the identity in `config_dir` and return the engine plus
    /// the event stream the UI drains.
    pub fn new(
        config_dir: impl AsRef<Path>,
    ) -> io::Result<(Self, mpsc::UnboundedReceiver<EngineEvent>)> {
        let config_dir = config_dir.as_ref().to_path_buf();
        let identity = NodeIdentity::load_or_create(&config_dir)?;
        let (tx, rx) = mpsc::unbounded_channel();
        let routing = RoutingTable::new(identity.kad_id);
        // Load the credit history, pruning entries expired past the 150-day
        // window. We always hold a key pair, so the secure-ident gate is live.
        let credit_store = Arc::new(match std::fs::read(config_dir.join(CLIENTS_MET)) {
            Ok(bytes) => CreditStore::load(&bytes, now_secs(), true),
            Err(_) => CreditStore::empty(true),
        });
        // The AICH hashset store: index built in one scan, torn tail truncated.
        let known2 = Arc::new(Known2Store::load(&config_dir));
        // A pause the guard latched in a PREVIOUS launch: restore it before
        // anything can serve. Restoring HERE - not waiting for the UI to push
        // its stored preference - is what makes the upload listener and the
        // Kad publish gate read sharing OFF from the process's first instant,
        // and the status atomic is set too so the UI's first lock-free read
        // can already say WHY.
        let ip_paused = ip_pause_path(&config_dir).exists();
        let status = StatusPub::default();
        status.ip_paused.store(ip_paused, Ordering::Relaxed);
        let engine = Engine {
            status,
            identity,
            downloads_dir: config_dir.join("downloads"),
            config_dir,
            state: EngineState::Stopped,
            last_checkpoint: Instant::now(),
            last_share_verify: Instant::now(),
            last_resume_retry: Instant::now(),
            max_active: Arc::new(std::sync::atomic::AtomicU32::new(0)),
            last_kad_refresh: Instant::now(),
            last_kad_sweep: Instant::now(),
            last_kad_publish: Instant::now(),
            publish_schedule: crate::kad_publish::PublishSchedule::new(),
            events: tx,
            routing,
            downloads: Arc::new(Mutex::new(Vec::new())),
            shared: Arc::new(Mutex::new(Vec::new())),
            shared_dirty: Arc::new(AtomicBool::new(false)),
            harvested_servers: Arc::new(std::sync::Mutex::new(Vec::new())),
            add_servers_from_server: true,
            sharing: Arc::new(AtomicBool::new(!ip_paused)),
            upload_gate: Arc::new(UploadGate::new(MAX_UPLOAD_SLOTS, UPLOAD_QUEUE_CAP)),
            known_met_lock: Arc::new(Mutex::new(())),
            known2,
            credit_store,
            ip_filter: None,
            server: None,
            connection: None,
            kad: None,
            last_public_id: None,
            sharing_paused_for_ip_change: ip_paused,
            listen_port: TCP_PORT,
            advertised_port: TCP_PORT,
            kad_port: KAD_UDP_PORT,
            kad_advertised_port: KAD_UDP_PORT,
            upnp_enabled: true,
            nick: DEFAULT_NICK.to_string(),
            public_ip: Arc::new(std::sync::Mutex::new(None)),
            listener: None,
            server_tx: None,
            last_server_search: None,
            search_session: None,
            pinned: std::collections::HashSet::new(),
            server_health: Arc::new(std::sync::Mutex::new(HashMap::new())),
            offline: false,
        };
        Ok((engine, rx))
    }

    /// Suppress all network activity (tests only - the UI never calls this).
    /// Without it the unit suite would fetch lists and dial real servers.
    pub fn set_offline(&mut self, offline: bool) {
        self.offline = offline;
    }

    /// True once an eD2k server has accepted our login.
    pub fn is_online(&self) -> bool {
        self.server
            .as_ref()
            .map(|s| s.is_connected())
            .unwrap_or(false)
    }

    /// What our login yielded, once a server has accepted us.
    pub fn server_info(&self) -> Option<ServerInfo> {
        if self.is_online() {
            self.connection.clone()
        } else {
            None
        }
    }

    /// The display name of the server at `addr`, read from server.met (tag 0x01).
    /// None if the server is not in the list or has no name tag. Cheap and
    /// best-effort - called once per connect, not on the hot path.
    fn server_name_for(&self, addr: &SocketAddr) -> Option<String> {
        let bytes = std::fs::read(self.config_dir.join("server.met")).ok()?;
        let met = read_server_met(&bytes).ok()?;
        met.servers.iter().find_map(|s| {
            let saddr = SocketAddr::new(IpAddr::V4(ip_from_met_u32(s.ip)), s.port);
            (saddr == *addr)
                .then(|| tag_str(&s.tags, 0x01).filter(|n| !n.is_empty()))
                .flatten()
        })
    }

    /// An honest one-line status for the UI - never claims a connection we do
    /// not have. Names the connected server (address in parens); HighID/LowID
    /// is NOT repeated here since the Status screen gives it its own row.
    fn online_status(&self) -> String {
        if self.is_online() {
            match &self.connection {
                // Lead with the server's NAME, the address in parens after it -
                // a name is what the user recognises; the bare IP is not. HighID/
                // LowID is not repeated here: it has its own row on the Status
                // screen. Falls back to the address when no name is known.
                Some(c) => match &c.name {
                    Some(n) => format!("Connected to {n} ({})", c.addr),
                    None => format!("Connected to {}", c.addr),
                },
                None => "Connected".to_string(),
            }
        } else if self.offline {
            "Offline (network disabled)".to_string()
        } else {
            // We do NOT auto-connect (eMule behavior), so "no server accepted a
            // login" would be a lie - we simply have not been told to connect yet.
            "Not connected - pick a server".to_string()
        }
    }

    /// Publish the login for the lock-free readers, then emit the status line.
    ///
    /// The two say the same thing from the same two fields, so they are done
    /// together: every path that changes whether we are connected already emits
    /// this line, which makes it the one place that cannot be forgotten. Without
    /// the publish the UI would still be correct within one heartbeat - see
    /// `publish_status` - but the server row would lag a connect by up to a
    /// second, which is exactly when the user is watching it.
    fn emit_online_status(&self) {
        if let Ok(mut g) = self.status.server.lock() {
            *g = self.server_info();
        }
        self.emit(EngineEvent::Status(self.online_status()));
    }

    /// Have we any way to FIND sources right now - a connected server, or a Kad
    /// table with contacts in it?
    ///
    /// The two channels are genuinely independent: a serverless client downloads
    /// from HighID Kad sources, and a client with a server works with an empty Kad
    /// table. Only when BOTH are absent is a "nobody has this file" answer a guess
    /// about the network rather than a fact about us.
    pub fn can_discover(&self) -> bool {
        self.server.is_some() || self.kad_contacts() > 0
    }

    /// Do we currently hold a router port mapping?
    ///
    /// The UI must not claim to "hand the port back" to a user who never had a
    /// mapping - on cellular, behind CGNAT, or on any network whose router has no
    /// UPnP, the map simply never succeeded. `public_ip` is exactly that fact: it
    /// is set only on a successful map and cleared when the mapping is released.
    /// Exposed as a BOOLEAN on purpose - the address itself is our public IP and
    /// must never reach the screen.
    pub fn has_port_mapping(&self) -> bool {
        self.public_ip.lock().map(|g| g.is_some()).unwrap_or(false)
    }

    /// The number of Kad contacts currently held - the LIVE node's table
    /// whenever there is one, and the persisted table only when Kad is not
    /// running (before `start_kad`, or while paused).
    ///
    /// ONE FIELD, ONE MEASUREMENT. This used to return `self.routing.len()`
    /// unconditionally while `EngineEvent::Kad` carried the LIVE count from
    /// `start_kad` and `maintain_kad` - and the UI writes BOTH into the same
    /// `kadContacts` field, so the number on screen alternated between two
    /// different quantities at 1s resolution. Worse, `RoutingTable` has no
    /// removal path anywhere, so the persisted count is MONOTONIC: it cannot
    /// fall, which made it useless as evidence about anything and specifically
    /// useless as the verdict on Kad maintenance it had been nominated for.
    ///
    /// The live table is the honest answer because it is the only one
    /// `closest_to` reads, so it is the only one that describes whether a lookup
    /// can converge. [[kad-routing-lifecycle]], build-progress 8ce.
    pub fn kad_contacts(&self) -> usize {
        self.kad
            .as_ref()
            .map_or_else(|| self.routing.len(), |k| k.contacts_known())
    }

    /// Total file-data bytes moved this session as `(downloaded, uploaded)`. The
    /// UI samples these monotonic totals to draw the rate history + up:down ratio
    /// (see [`crate::stats`]). Process-global, so they survive a pause/resume.
    pub fn transfer_totals(&self) -> (u64, u64) {
        (crate::stats::downloaded(), crate::stats::uploaded())
    }

    /// Handles a reader can use WITHOUT holding the engine lock. Take this ONCE
    /// at construction; the underlying `Arc`s are never reassigned.
    pub fn handles(&self) -> EngineHandles {
        EngineHandles {
            status: self.status.clone(),
            downloads: Arc::clone(&self.downloads),
            shared: Arc::clone(&self.shared),
            sharing: Arc::clone(&self.sharing),
            public_ip: Arc::clone(&self.public_ip),
            max_active: Arc::clone(&self.max_active),
        }
    }

    /// The in-progress downloads. Cheap: clones `Arc`s, not files.
    pub async fn downloads(&self) -> Vec<Arc<Download>> {
        self.downloads.lock().await.clone()
    }

    /// The sources we have connected to for one download (for the per-source UI).
    /// Empty if no download with that hash is active.
    pub async fn download_sources(&self, hash: [u8; 16]) -> Vec<crate::multi_source::SourceInfo> {
        for dl in self.downloads.lock().await.iter() {
            if dl.hash().await == hash {
                return dl.sources().await;
            }
        }
        Vec::new()
    }

    /// How many IP-blocklist ranges are loaded (0 = no filter). For the UI.
    pub fn ip_filter_ranges(&self) -> usize {
        self.ip_filter.as_ref().map_or(0, |f| f.len())
    }

    /// The complete files we are currently serving to peers, as (hash, name,
    /// size). Reflects the persisted library plus anything finished this session;
    /// empty in Leech Mode is still what we HOLD, not what we serve.
    pub async fn shared_files(&self) -> Vec<([u8; 16], String, u64, u8, String)> {
        self.shared
            .lock()
            .await
            .iter()
            .map(|s| {
                (
                    s.hash,
                    String::from_utf8_lossy(&s.name).into_owned(),
                    s.size,
                    s.rating,
                    s.comment.clone(),
                )
            })
            .collect()
    }

    /// Where completed files land. The iOS app points this at its Documents dir
    /// so finished downloads show up in the Files app.
    /// Override the ports. Takes effect on the next `start()`.
    ///
    /// `advertised` is what we tell servers and peers; pass the same value as
    /// `listen` for the ordinary case (a home router forwarding port N to port
    /// N). They differ when an external forwarder maps one port to another -
    /// the VPN case - and getting this wrong is invisible locally but means
    /// every peer dials a port nothing is listening on.
    ///
    /// `kad_advertised` is the same split for Kad's UDP port. It used to be one
    /// value for both bind and advertise, which silently broke inbound Kad on a
    /// provider that remaps remote->local (padMule would bind the local port
    /// correctly and then tell every peer to dial it, while the forward only
    /// exists on the remote one). Pass the same value as `kad` for the ordinary
    /// same-port case.
    pub fn set_ports(&mut self, listen: u16, advertised: u16, kad: u16, kad_advertised: u16) {
        self.listen_port = listen;
        self.advertised_port = advertised;
        self.kad_port = kad;
        self.kad_advertised_port = kad_advertised;
    }

    /// Turn the UPnP attempt on or off. Takes effect on the next `start()` /
    /// mapping trigger. Off is correct on a VPN, where the forward is done by
    /// the provider and a LAN-router mapping accomplishes nothing.
    pub fn set_upnp_enabled(&mut self, on: bool) {
        self.upnp_enabled = on;
    }

    /// The name peers and servers are told. Always sanitized, never empty.
    pub fn nickname(&self) -> &str {
        &self.nick
    }

    /// Set the name peers and servers are told, applying eMule's nickname rules
    /// (see [`sanitize_nick`] - trimmed, no control characters, at most
    /// [`MAX_NICK_LEN`] characters, empty falls back to [`DEFAULT_NICK`]).
    ///
    /// WHEN IT REACHES THE WIRE, precisely: a server login builds its
    /// `LoginRequest` at connect time and a fetch builds its HELLO at fetch
    /// time, so both pick this up on the NEXT connection with no restart. The
    /// INBOUND listener is the exception - `start_listener` builds one
    /// `HelloInfo` and hands it to the accept task, so peers that dial US keep
    /// seeing the old name until the listener is rebuilt. VERIFIED, not assumed:
    /// `pause()` aborts the listener and `resume()` calls `start_listener()`
    /// again, so a plain background/foreground cycle picks the new name up too -
    /// but `pause_for_seeding` deliberately leaves the listener UP, so a user
    /// with background seeding on does not get that for free. Stop then Start is
    /// the one action that always works, which is what the Settings footer says.
    pub fn set_nickname(&mut self, nick: &str) {
        self.nick = sanitize_nick(nick);
    }

    /// The HELLO we present to a peer, before any per-site capability flags.
    /// ONE constructor for both HELLO sites (the inbound listener and an
    /// outbound fetch) so a peer can never be told a different name - or a
    /// different port - depending on who dialled whom.
    fn hello_baseline(&self) -> HelloInfo {
        HelloInfo::baseline(
            self.identity.userhash,
            0,
            self.advertised_port,
            self.kad_advertised_port,
            &self.nick,
        )
    }

    /// The login we present to an eD2k server. Same reason as
    /// [`Engine::hello_baseline`]: the nickname a server publishes about us and
    /// the one a peer sees must be the same string, so they come from one place.
    fn login_request(&self) -> LoginRequest {
        LoginRequest {
            user_hash: self.identity.userhash,
            client_id: 0,
            tcp_port: self.advertised_port,
            nick: self.nick.clone(),
            server_flags: DEFAULT_SERVER_FLAGS,
        }
    }

    pub fn set_downloads_dir(&mut self, dir: impl AsRef<Path>) {
        self.downloads_dir = dir.as_ref().to_path_buf();
    }

    /// Whether padMule serves files to peers. `false` is "Leech Mode":
    /// downloading still works, but we upload nothing.
    pub fn is_sharing(&self) -> bool {
        self.sharing.load(Ordering::Relaxed)
    }

    /// Turn uploading on or off. Off is the download-only "Leech Mode"; the
    /// listener consults this per connection, so it takes effect immediately.
    pub fn set_sharing(&mut self, on: bool) {
        self.sharing.store(on, Ordering::Relaxed);
        if on {
            // The user has decided; stop saying we paused for them. The
            // persisted marker goes too, so a LATER relaunch does not
            // re-pause - the OFF direction leaves it alone on purpose (a
            // metered auto-pause or a leech-mode preference is not the user
            // resolving the address change).
            self.sharing_paused_for_ip_change = false;
            self.status.ip_paused.store(false, Ordering::Relaxed);
            let _ = std::fs::remove_file(ip_pause_path(&self.config_dir));
        }
    }

    /// True while sharing is off because the public address changed under us.
    pub fn sharing_paused_for_ip_change(&self) -> bool {
        self.sharing_paused_for_ip_change
    }

    /// Note the client id from a login. A HighID id IS our public address, so a
    /// CHANGE between logins means our traffic is now leaving by a different
    /// route - on a VPN, that is the tunnel having dropped, and stock iOS has no
    /// kill switch to stop it. Pause sharing (uploads are what publish us most
    /// loudly) and warn.
    ///
    /// A LowID login carries no public address, so it neither trips the guard
    /// nor overwrites what we knew. The address itself is compared here and
    /// never leaves this function.
    pub fn note_public_id(&mut self, id: u32, low_id: bool) {
        if low_id {
            return;
        }
        match self.last_public_id {
            Some(prev) if prev != id => {
                self.sharing.store(false, Ordering::Relaxed);
                self.sharing_paused_for_ip_change = true;
                self.status.ip_paused.store(true, Ordering::Relaxed);
                // Persisted HERE, synchronously, not when the UI notices: the
                // process can die before any poll or event drain runs (jetsam
                // can end a background seed at any moment), and this pause
                // must outlive the process - `Engine::new` restores it.
                let _ = std::fs::write(
                    ip_pause_path(&self.config_dir),
                    b"sharing was paused because the public address changed;\nthe user has not turned it back on yet\n",
                );
                self.emit(EngineEvent::PublicAddressChanged);
            }
            _ => {}
        }
        self.last_public_id = Some(id);
    }

    /// The "update server list when connecting" pref (eMule AddServersFromServer;
    /// see the field doc for the citations and padMule's default-ON deviation).
    /// Takes effect on the NEXT connect/resume, like upstream's.
    pub fn set_add_servers_from_server(&mut self, on: bool) {
        self.add_servers_from_server = on;
    }

    pub fn state(&self) -> EngineState {
        self.state
    }
    pub fn userhash(&self) -> [u8; 16] {
        self.identity.userhash
    }
    pub fn kad_id(&self) -> Kad128 {
        self.identity.kad_id
    }
    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    fn emit(&self, e: EngineEvent) {
        let _ = self.events.send(e);
    }

    fn set_state(&mut self, s: EngineState) {
        // Published FIRST and unconditionally: a paused engine that still reads
        // "Running" to the UI is the dishonest-status failure this project
        // treats as a hard requirement ([[lifecycle-and-reactivation]]).
        self.status.set_state(s);
        if self.state != s {
            self.state = s;
            self.emit(EngineEvent::State(s));
        }
    }

    /// Start from `Stopped` -> `Running`. Idempotent (a no-op if already
    /// running). Loads the persisted Kad contacts and resumes in-progress
    /// downloads from disk, emitting an event for each. Phase 4 spins up the live
    /// server + Kad sockets on top.
    pub async fn start(&mut self) {
        if self.state == EngineState::Running {
            return;
        }
        let _ = std::fs::create_dir_all(&self.config_dir);
        // Restore the user's pinned servers (best-effort).
        self.load_pins();

        // Load the IP blocklist if the user placed one. Best-effort: absent or
        // unparseable means no filtering (never a startup failure).
        self.ip_filter = load_ip_filter(&self.config_dir);
        self.status.ipfilter_ranges.store(
            self.ip_filter.as_ref().map_or(0, |f| f.len()),
            Ordering::Relaxed,
        );
        if let Some(f) = &self.ip_filter {
            self.emit(EngineEvent::Server(format!(
                "IP filter: {} ranges blocked",
                f.len()
            )));
        }

        // A FRESH INSTALL HAS NEITHER LIST, so it knows no servers and no Kad
        // contacts and could reach nothing. Fetch them (best effort - a failure
        // must not stop the engine; we simply come up offline and can retry).
        if !self.offline {
            self.emit(EngineEvent::Status("Fetching network lists...".into()));
            // SAY what happened to the server list. `ensure` now re-fetches a
            // file that is present but unusable (see its docs - that is what
            // left the Servers tab empty), and the user has no other way to
            // tell an auto-load from a list that was simply already there.
            match bootstrap::ensure(
                &self.config_dir,
                "server.met",
                bootstrap::SERVER_MET_URL,
                bootstrap::looks_like_server_met,
            )
            .await
            {
                bootstrap::Fetched::Downloaded => {
                    self.emit(EngineEvent::Server("Server list downloaded".into()))
                }
                bootstrap::Fetched::Failed => self.emit(EngineEvent::Server(
                    "Server list unavailable - use Refresh on the Servers screen".into(),
                )),
                bootstrap::Fetched::AlreadyPresent => {}
            }
            bootstrap::ensure(
                &self.config_dir,
                "nodes.dat",
                bootstrap::NODES_DAT_URL,
                bootstrap::looks_like_nodes_dat,
            )
            .await;
        }

        // Persisted Kad contacts, gated like aMule's loader (the file may have
        // just been downloaded by bootstrap::ensure above).
        if let Ok(bytes) = std::fs::read(self.config_dir.join("nodes.dat")) {
            if let Ok(nd) = read_nodes_dat(&bytes) {
                self.routing
                    .load_nodes(&gate_loaded_nodes(&nd.contacts, self.ip_filter.as_deref()));
            }
        }
        // Through the accessor, not `self.routing.len()` directly: every emit
        // site of this event has to carry the SAME quantity as the poll, or the
        // one UI field they share means two things (see `kad_contacts`). Kad is
        // not up yet here, so this is still the persisted count - by the
        // accessor's own rule rather than by coincidence.
        self.emit(EngineEvent::Kad {
            contacts: self.kad_contacts(),
        });
        // In-progress downloads.
        let resumed = resume_downloads(&self.config_dir);
        for dl in &resumed {
            let total = dl.size().await;
            let have = total - dl.missing().await;
            let hash = dl.hash().await;
            self.emit(EngineEvent::Progress { hash, have, total });
        }
        *self.downloads.lock().await = resumed;

        // Complete files from prior sessions - re-share them (the list was
        // session-only before, so uploads forgot their library on every launch).
        let library = load_shared_library(&self.config_dir, &self.downloads_dir);
        *self.shared.lock().await = library;

        // STARTUP-ONLY orphan prune of the AICH hashset store, against the
        // CATALOG (known.met) rather than the loaded library, so a file that is
        // merely missing from disk right now does not lose its hashset. This is
        // aMule master's prune discipline (ThreadTasks.h:136-144) - 3.0.1 also
        // pruned after every mid-session hashing batch and raced its own
        // catalog registration, destroying fresh hashsets; running only here,
        // on the one engine task, that race class cannot exist.
        self.known2
            .prune_orphans(&known_met_aich_roots(&self.config_dir));

        // Go live. ORDER MATTERS: the inbound listener must exist BEFORE we log
        // in, because the server decides HighID vs LowID by connecting back to
        // the port we advertise. No listener = LowID = a second-class peer.
        if !self.offline {
            self.emit(EngineEvent::Status("Opening port...".into()));
            self.start_listener().await;
            self.map_port().await;
            // Do NOT auto-connect to a server (eMule does not either): the user
            // picks a live server from the Servers screen. Kad still bootstraps,
            // so search + downloads work serverless in the meantime.
            self.start_kad().await;
            // Report Running BEFORE the (time-bounded) resume pass, so the engine
            // is usable and the state is honest even while resume_fetches works.
            self.set_state(EngineState::Running);
            self.emit_online_status();
            // Downloads resumed from disk above were registered but have no
            // transfer task yet; now that the server + Kad are up, find sources
            // and drive them (otherwise they wait passively for a callback).
            self.resume_fetches().await;
            return;
        }

        self.set_state(EngineState::Running);
        self.emit_online_status();
    }

    /// Bind the inbound peer port and accept connections. This is what earns a
    /// HighID: the server's HighID test is a bare TCP connect+close (no eD2k
    /// HELLO), so simply ACCEPTING is enough to pass it. Real peers that follow
    /// get a proper hello handshake. Idempotent; a bind failure is survivable
    /// (we just stay LowID).
    ///
    /// An accepted peer plays one of two roles, told apart by who speaks first
    /// (see [`SERVE_PEEK`]): a LEECHER wants to download from us and sends
    /// OP_REQUESTFILENAME straight away, so we serve it from our shared files; a
    /// called-back LowID SOURCE for one of our downloads stays silent, so we
    /// drive the download instead.
    async fn start_listener(&mut self) {
        if self.listener.is_some() {
            return;
        }
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.listen_port);
        let Ok(listener) = TcpListener::bind(bind).await else {
            self.emit(EngineEvent::Server(format!(
                "port {} unavailable - expect LowID",
                self.listen_port
            )));
            return;
        };
        // Advertise crypt SUPPORTED so crypt-required peers can reach us, and
        // secure-ident so a leecher challenges us (the precondition for verifying
        // IT - the exchange is mutual). The accept loop wires the matching inbound
        // obf-accept and the secure-ident drain (all halves land together).
        let me = self.hello_baseline().with_crypt_supported().with_secident();
        let identity = Arc::clone(&self.identity.rsa);
        let credit_store = Arc::clone(&self.credit_store);
        let downloads = Arc::clone(&self.downloads);
        let max_active = Arc::clone(&self.max_active);
        let shared = Arc::clone(&self.shared);
        let sharing = Arc::clone(&self.sharing);
        let gate = Arc::clone(&self.upload_gate);
        let ip_filter = self.ip_filter.clone();
        let known2 = Arc::clone(&self.known2);
        let inbound = Arc::new(Semaphore::new(MAX_INBOUND_CONNS));
        let per_ip: PerIpConns = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let handle = tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(pair) => pair,
                    // On error (notably EMFILE when the fd table is exhausted) do
                    // NOT busy-loop - a bare `continue` spins accept() at 100% CPU.
                    // Back off so the box can recover a descriptor.
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                // Cap concurrent inbound connections: a hostile peer opening
                // thousands would exhaust fds/tasks. Reject the excess (it can
                // retry); the permit frees when the connection task ends.
                let Ok(permit) = Arc::clone(&inbound).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                // Per-IP cap: one IP must not hold all the permits (starving others).
                let ip_slot = match peer {
                    SocketAddr::V4(v4) => match IpConnSlot::try_acquire(&per_ip, *v4.ip()) {
                        Some(slot) => Some(slot),
                        None => {
                            drop(stream);
                            continue;
                        }
                    },
                    SocketAddr::V6(_) => None,
                };
                let me = me.clone();
                let identity = Arc::clone(&identity);
                let credit_store = Arc::clone(&credit_store);
                let downloads = Arc::clone(&downloads);
                let max_active = Arc::clone(&max_active);
                let shared = Arc::clone(&shared);
                let sharing = Arc::clone(&sharing);
                let gate = Arc::clone(&gate);
                let ip_filter = ip_filter.clone();
                let known2 = Arc::clone(&known2);
                tokio::spawn(async move {
                    let _permit = permit;
                    let _ip_slot = ip_slot;
                    let mut stream = stream;
                    // Auto-detect obfuscation on the first byte (eMule
                    // EncryptedStreamSocket.cpp:214): a plaintext eD2k marker stays
                    // plaintext (byte-identical to the old path); anything else runs
                    // the RC4 responder keyed on OUR userhash. This is what advertising
                    // crypt-SUPPORTED obligates. A bare connect+close (the server's
                    // HighID probe) reads no first byte, errors here, and bails - the
                    // accept already succeeded, so HighID is unaffected.
                    let detect = timeout(
                        Duration::from_secs(8),
                        obf_accept(&mut stream, &me.user_hash),
                    )
                    .await;
                    let peer_obf = matches!(detect, Ok(Ok(ObfDetect::Obfuscated(_))));
                    let mut fs = match detect {
                        Ok(Ok(ObfDetect::Obfuscated(c))) => FramedStream::obfuscated(stream, *c),
                        Ok(Ok(ObfDetect::Plaintext { first })) => {
                            FramedStream::plaintext_with_prefix(stream, &[first])
                        }
                        _ => return,
                    };
                    // A bare connect+close (the server's HighID probe) ends here:
                    // it never sends OP_HELLO, so the handshake errors and we bail.
                    let (
                        peer_hash,
                        peer_accept_comment,
                        peer_secident,
                        peer_crypt,
                        peer_sx1,
                        peer_aich,
                        peer_ext_requests,
                        peer_software,
                        peer_is_low_id,
                    ) = match timeout(Duration::from_secs(8), peer_handshake_inbound(&mut fs, &me))
                        .await
                    {
                        Ok(Ok(h)) => {
                            let (ac, si, crypt, sx1, aich, extreq) = h
                                .capabilities()
                                .map(|c| {
                                    // Re-encode the peer's crypt bits as the
                                    // connect-options byte source exchange
                                    // carries (SetConnectOptions layout), so a
                                    // peer we name to others can be dialed
                                    // obfuscated by them.
                                    let b = (c.supports_crypt as u8)
                                        | ((c.requests_crypt as u8) << 1)
                                        | ((c.requires_crypt as u8) << 2);
                                    (
                                        c.accept_comment,
                                        c.sec_ident,
                                        Some(b),
                                        c.source_exchange,
                                        c.aich,
                                        c.ext_requests,
                                    )
                                })
                                // No capabilities tag at all: assume the
                                // ExtReq-2 layout every AICH-era client sends
                                // (only read when the peer advertised AICH).
                                .unwrap_or((0, 0, None, 0, 0, 2));
                            (
                                h.user_hash,
                                ac,
                                si,
                                crypt,
                                sx1,
                                aich,
                                extreq,
                                h.client_software(),
                                h.client_id < 0x0100_0000,
                            )
                        }
                        _ => return,
                    };
                    // Record the contact so its credit record exists + last_seen is
                    // fresh (mirrors eMule's GetCredit at hello).
                    credit_store.touch(peer_hash, now_secs());
                    // Drop a blocklisted PEER now (after the handshake, so the
                    // server's bare-connect HighID probe - which never completes a
                    // handshake and already returned above - is never filtered and
                    // HighID is safe).
                    if let (Some(f), SocketAddr::V4(v4)) = (&ip_filter, peer) {
                        if f.is_blocked(*v4.ip()) {
                            return;
                        }
                    }
                    // Classify who this is, draining any secure-ident prefix along
                    // the way. Advertising secure-ident means a capable peer (a
                    // leecher OR a called-back source) may LEAD with OP_SECIDENTSTATE,
                    // so we can no longer classify on the first packet - the drain
                    // re-applies the leecher-vs-source discriminator on what follows.
                    // We run our half of the exchange only when the peer advertised
                    // support (mirrors eMule's m_bySupportSecIdent gate). Cancel-safe:
                    // classify_inbound times out per-read, never around a write.
                    let sec = (peer_secident > 0).then(|| {
                        let cs = Arc::clone(&credit_store);
                        ServeSec::new(
                            SecureIdentSession::new(&identity),
                            Arc::clone(&identity),
                            // On verification, bind the peer's key to its userhash
                            // (eMule Verified: first key-bind wipes prior credits).
                            Box::new(move |pubkey| cs.bind_verified(peer_hash, pubkey, now_secs())),
                        )
                    });
                    match classify_inbound(&mut fs, sec, SERVE_PEEK).await {
                        InboundKind::Leecher { first, sec } => {
                            serve_inbound(
                                &mut fs,
                                &shared,
                                &sharing,
                                &gate,
                                first,
                                peer_accept_comment,
                                crate::share::ServeSession {
                                    sec,
                                    credit: Some((Arc::clone(&credit_store), peer_hash)),
                                    peer: Some(peer),
                                    peer_crypt,
                                    peer_sx1,
                                    peer_aich,
                                    peer_ext_requests,
                                    aich: Some(Arc::clone(&known2)),
                                },
                            )
                            .await;
                        }
                        // Spoke, but not an upload request: nothing we can do.
                        InboundKind::Other => {}
                        // Silent: a called-back source. Offer it every unfinished
                        // download and let it serve whichever it actually has.
                        // Do NOT hold the lock across the transfer.
                        InboundKind::Source => {
                            let pending: Vec<Arc<Download>> = downloads.lock().await.clone();
                            // The one admission rule, applied HERE too: a row
                            // the UI reports as Queued (or paused) must not be
                            // driven by a dial-back. This arm used to skip only
                            // complete/banned rows, so a queued download
                            // transferred while its row said "Queued" - the
                            // callback path bypassed the max-active cap
                            // entirely (multi_source.rs's contract: queued rows
                            // are "NOT driven").
                            let now = u64::from(now_secs());
                            let mut rows = Vec::with_capacity(pending.len());
                            for d in &pending {
                                rows.push(d.admission_row(now).await);
                            }
                            let cap = max_active.load(Ordering::Relaxed);
                            let drive = callback_drive_flags(cap, &rows);
                            for (dl, may_drive) in pending.iter().zip(drive) {
                                // Skip a download this source is BANNED from (it
                                // fed us a corrupt part before). Without this a LowID
                                // poisoner - which only ever reaches us by callback -
                                // could re-poison indefinitely; the outbound sweep's
                                // guard alone never sees it.
                                if dl.is_complete().await || dl.is_banned(&peer) {
                                    continue;
                                }
                                // Queued/paused: not driven. (take_blocks would
                                // starve a paused row anyway, but skipping here
                                // is honest and saves the pointless session.)
                                if !may_drive {
                                    continue;
                                }
                                // RECORD IT. Only the outbound sweep called
                                // note_source, so a peer that reached us by
                                // CALLBACK delivered bytes while appearing in
                                // neither the per-source sheet nor the origin
                                // badge - a transfer visibly progressing with no
                                // source listed at all. Origin is Server because
                                // that is the only channel that can produce a
                                // callback here: `lowids` is built from the
                                // server's OP_FOUNDSOURCES list and the poke goes
                                // over the server link (find_sources /
                                // request_callbacks); padMule implements no
                                // Kad-mediated callback.
                                dl.note_source(
                                    peer_software.clone(),
                                    peer,
                                    peer_obf,
                                    peer_is_low_id,
                                    crate::fetch::SourceOrigin::Server,
                                )
                                .await;
                                // Credit this called-back source for what it gives us.
                                let session = crate::multi_source::PeerSession {
                                    credit: Some((Arc::clone(&credit_store), peer_hash)),
                                    // A called-back LowID peer reached US; asking
                                    // it for sources is free and it may know
                                    // others holding the file.
                                    ask_sources: dl.mark_asked_sources(peer.ip()),
                                    // ...and it can vote a root / serve AICH
                                    // recovery like any outbound source (eMule
                                    // considers LowID sources too, preferring
                                    // HighID, PartFile.cpp:6083-6133).
                                    peer_aich,
                                    ..Default::default()
                                };
                                // Count it as an INBOUND session. This peer
                                // dialed US, so it never passed through
                                // `fetch_one` and never bumped the dial stages -
                                // and one inbound connection is offered every
                                // unfinished download in turn, so it can make
                                // several sessions. Without this the funnel
                                // showed more file statuses than handshakes,
                                // which is impossible and made a correct set of
                                // counts unreadable.
                                crate::stats::note_inbound();
                                match timeout(
                                    Duration::from_secs(120),
                                    download_from_peer_at(&mut fs, dl, false, Some(peer), session),
                                )
                                .await
                                {
                                    // Delivered something - keep it on this
                                    // download rather than offering it others.
                                    Ok(Ok(n)) if n > 0 => break,
                                    // Connection is spent either way once it errors.
                                    Ok(Err(_)) | Err(_) => break,
                                    Ok(Ok(_)) => {}
                                }
                            }
                        }
                    }
                });
            }
        });
        self.listener = Some(handle);
    }

    /// Best-effort: ask the gateway (UPnP, multicast then unicast) to forward our
    /// port, so a real device with no hand-configured router rule can still earn a
    /// HighID. The RESULT is emitted either way - success or the failure reason -
    /// because on a debugger-less device this line is the only window into why the
    /// port did or did not open. Messages are prefixed "UPnP:" so the UI can pin
    /// them to a durable row instead of the transient notice.
    async fn map_port(&mut self) {
        if !self.upnp_enabled {
            // SAY SO. Returning silently left the UI's durable "Port mapping"
            // row showing whatever the last UPnP attempt said - which, after
            // switching to a VPN, was a stale failure naming the OLD port and
            // looked like the new settings had not taken.
            self.emit(EngineEvent::Server(
                "UPnP: off - port forwarding is handled outside padMule".to_string(),
            ));
            return;
        }
        let port = self.listen_port;
        match crate::upnp::map_port(port, "padMule", crate::upnp::PERMANENT_LEASE).await {
            Ok(ip) => {
                // The external IP the gateway reports is deliberately NOT emitted:
                // this reaches the UI, and that is our public IP verbatim. It IS
                // kept internally: the Kad node keys its UDP-verify-key echo on it
                // (see `public_ip`), which is how a peer verifies us faster.
                if let Ok(mut g) = self.public_ip.lock() {
                    *g = Some(ip);
                }
                self.emit(EngineEvent::Server(format!("UPnP: mapped port {port}")));
            }
            Err(e) => {
                self.emit(EngineEvent::Server(format!(
                    "UPnP: could not map port {port} ({e})"
                )));
            }
        }
    }

    /// The ServerEvent -> EngineEvent forwarder, spawned exactly once. Must be
    /// called from inside the runtime (start/resume), never from `new`.
    fn server_sender(&mut self) -> mpsc::Sender<ServerEvent> {
        if let Some(tx) = &self.server_tx {
            return tx.clone();
        }
        let (tx, mut rx) = mpsc::channel(64);
        let out = self.events.clone();
        let harvest = self.harvested_servers.clone();
        tokio::spawn(async move {
            // Rate-limit SERVER-DRIVEN events (Message/Status/ServerList): a hostile
            // server could otherwise flood them (e.g. OP_SERVERMESSAGE) into the
            // unbounded UI event channel and exhaust memory -> jetsam kill, with no
            // user action (it fires during automatic get_sources). A legitimate
            // connect emits only a handful, so a generous per-window cap is
            // invisible to real servers. Our OWN lifecycle State events are exempt -
            // dropping one would leave the UI's connection state stale.
            const WINDOW: Duration = Duration::from_secs(10);
            const PER_WINDOW: u32 = 30;
            let mut win_start = tokio::time::Instant::now();
            let mut count = 0u32;
            while let Some(e) = rx.recv().await {
                // Gossip crawl step 1: stash the servers this server advertised,
                // for the heartbeat to filter + merge into server.met. Bounded, so
                // a hostile server cannot grow it without limit; the public-IP
                // filter and dedup happen at merge time, on the engine task.
                // Stashed BEFORE the flood limiter below: the limiter protects
                // the unbounded UI channel, but the OP_SERVERLIST answer to our
                // own OP_GETSERVERLIST ask arrives inside the busy connect burst
                // - exactly when the window is most likely spent - and this
                // queue has its own bound, so the limiter must not eat it.
                if let ServerEvent::ServerList(list) = &e {
                    if let Ok(mut pend) = harvest.lock() {
                        const MAX_HARVEST_PENDING: usize = 2000;
                        let room = MAX_HARVEST_PENDING.saturating_sub(pend.len());
                        pend.extend(list.iter().copied().take(room));
                    }
                }
                if !matches!(e, ServerEvent::State(_)) {
                    let now = tokio::time::Instant::now();
                    if now.duration_since(win_start) >= WINDOW {
                        win_start = now;
                        count = 0;
                    }
                    count += 1;
                    if count > PER_WINDOW {
                        continue; // drop the flood (the harvest is already in)
                    }
                }
                let _ = out.send(map_server_event(e));
            }
        });
        self.server_tx = Some(tx.clone());
        tx
    }

    /// Connect to ONE specific server the user chose (eMule never auto-connects).
    /// Disconnects any current server first. Returns true on success. Records the
    /// connection + announces our shared library. Kad + downloads are untouched.
    pub async fn connect_to_server(&mut self, addr: SocketAddr) -> bool {
        if self.offline {
            return false;
        }
        if let Some(mut old) = self.server.take() {
            old.disconnect().await;
        }
        self.connection = None;
        // A new connection means the server no longer holds our last query, so any
        // "load more" session is stale even if we reconnect to the SAME address.
        self.search_session = None;
        let login = self.login_request();
        let tx = self.server_sender();
        let mut link = ServerLink::new(addr, login, tx);
        if let Ok(Ok(ServerState::Connected {
            id,
            low_id,
            related_search,
        })) = timeout(Duration::from_secs(12), link.connect()).await
        {
            // A HighID id IS our public address: notice if it changed under us
            // (a dropped VPN tunnel, a network switch) and pause sharing if so.
            // The value is compared internally and never recorded for display.
            self.note_public_id(id, low_id);
            // The client id is deliberately NOT recorded here: a HighID id encodes
            // our public IP and this text reaches the screen.
            let addr_str = addr.to_string();
            let name = self.server_name_for(&addr);
            self.connection = Some(ServerInfo {
                addr: addr_str.clone(),
                name: name.clone(),
                low_id,
                related_search,
            });
            let shown = name.as_deref().unwrap_or(&addr_str);
            self.emit(EngineEvent::Server(format!(
                "Connected to {shown} ({})",
                if low_id { "LowID" } else { "HighID" }
            )));
            // A LowID answer is the server telling us its connect-back failed, so
            // re-verify the port mapping - eMule does exactly this
            // (ServerSocket.cpp:334, "refresh the UPnP mappings once"). It is the
            // trigger that targets the real failure: a mapping that silently went
            // stale is INVISIBLE until a server refuses to reach us.
            if low_id {
                self.refresh_port_mapping();
            }
            Self::offer_shared_to(&self.shared, &mut link).await;
            // Ask for the server's own server list exactly where both
            // authorities do - right after the shares offer - and fire-and-
            // forget like theirs (eMule sockets.cpp:253-260, aMule
            // ServerConnect.cpp:289-296). The OP_SERVERLIST answer rides the
            // normal event path into the gossip harvest.
            if self.add_servers_from_server {
                let _ = link.request_server_list().await;
            }
            self.server = Some(link);
            // The DURABLE status line too, not only the notice above. The app
            // feeds its status row from `Status` events ALONE and routes `Server`
            // text to a transient banner, so without this the row keeps whatever
            // start() last said - it read "Not connected - pick a server" on a
            // screen that was simultaneously showing the server and "HighID"
            // (found on-device 2026-08-02). Emitted after `self.server` is set,
            // because `online_status` asks `is_online`.
            self.emit_online_status();
            true
        } else {
            self.emit(EngineEvent::Server(format!("could not connect to {addr}")));
            // A failed dial also DROPPED any previous link above, so the row must
            // stop claiming the connection we no longer have.
            self.emit_online_status();
            false
        }
    }

    /// Disconnect from the current server at the user's request. Kad and any
    /// in-progress downloads keep running (a download can proceed via Kad).
    pub async fn disconnect_server(&mut self) {
        if let Some(mut link) = self.server.take() {
            link.disconnect().await;
        }
        self.connection = None;
        self.search_session = None;
        self.emit(EngineEvent::Server("Disconnected from the server".into()));
        self.emit_online_status();
    }

    /// The Servers screen: read `server.met` and probe each server's UDP status
    /// port (TCP + 4), returning the list enriched with liveness + fresh
    /// user/file counts. A server that answers OP_GLOBSERVSTATRES within the
    /// budget is `alive` (selectable); the rest are shown greyed out. Best-effort:
    /// a missing/unreadable list yields an empty vec. A blocklisted publicly
    /// routable entry stays LISTED but is never pinged (`blocklist_forbids_send`),
    /// so it reads dead - and an unpinned Prune will then drop it, which is the
    /// blocklist's intent.
    pub async fn probe_server_list(&self) -> Vec<ServerEntry> {
        let connected = self.server.as_ref().map(|l| l.addr());
        let Ok(bytes) = std::fs::read(self.config_dir.join("server.met")) else {
            return Vec::new();
        };
        let Ok(met) = read_server_met(&bytes) else {
            return Vec::new();
        };
        let mut servers: Vec<ServerEntry> = met
            .servers
            .iter()
            .map(|s| {
                let addr = SocketAddr::new(IpAddr::V4(ip_from_met_u32(s.ip)), s.port);
                ServerEntry {
                    addr,
                    name: tag_str(&s.tags, 0x01).unwrap_or_default(),
                    users: None,
                    files: None,
                    alive: false,
                    connected: Some(addr) == connected,
                    pinned: self.pinned.contains(&addr.to_string()),
                    checking: false,
                }
            })
            .collect();
        if self.offline || servers.is_empty() {
            return servers;
        }
        // Fan the status ping out to each server's UDP port (TCP + 4).
        let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0u16)).await else {
            return servers;
        };
        // The request MUST carry a 4-byte challenge (a modern server ignores a
        // challenge-less ping); the server echoes it as the response's first u32.
        let ch = SERV_STAT_CHALLENGE.to_le_bytes();
        let req = [PROT_EDONKEY, OP_GLOBSERVSTATREQ, ch[0], ch[1], ch[2], ch[3]];
        // The description challenge varies per probe (its low half is fixed by
        // the protocol); names learned this round are collected then persisted.
        let desc_challenge = desc_req_challenge((std::process::id() as u16) ^ 0xA5C3);
        let mut learned: Vec<(SocketAddr, String)> = Vec::new();
        // THE BLOCKLIST GATES THESE SENDS (2026-08-09), publicly routable
        // targets only - `blocklist_forbids_send` has the scoping rationale
        // (the eserver oracle on 127.0.0.1 and any LAN server stay probeable).
        // Decided ONCE per entry and reused by the awaiting counters and the
        // answer matching below, so a gated server is neither pinged, nor
        // waited for, nor believed. `e.addr` was built with `ip_from_met_u32`
        // above, so this is the real address, not the met-order u32.
        let filter = self.ip_filter.as_deref();
        let sendable: Vec<bool> = servers
            .iter()
            .map(|e| match e.addr.ip() {
                IpAddr::V4(v4) => !blocklist_forbids_send(filter, v4),
                IpAddr::V6(_) => true,
            })
            .collect();
        for (e, &send) in servers.iter().zip(&sendable) {
            if !send {
                continue;
            }
            if let Some(udp) = e.addr.port().checked_add(4) {
                let target = SocketAddr::new(e.addr.ip(), udp);
                let _ = sock.send_to(&req, target).await;
                // Ask for the NAME too, exactly as both authorities do right
                // after a status answer (eMule UDPSocket.cpp:435, aMule
                // ServerUDPSocket.cpp:243). This is what gives a server found by
                // the crawl or the gossip harvest a name instead of a bare IP -
                // discovery yields only ip:port.
                let ch = desc_challenge.to_le_bytes();
                let dreq = [PROT_EDONKEY, OP_SERVER_DESC_REQ, ch[0], ch[1], ch[2], ch[3]];
                let _ = sock.send_to(&dreq, target).await;
            }
        }
        // Collect answers within a short budget; match each back by (ip, port-4).
        //
        // The budget is a CEILING and the round normally ends well inside it: it
        // stops as soon as every server has said everything we asked it for, and
        // failing that, `PROBE_QUIET_PERIOD` after the last answer. It used to run
        // to the deadline unconditionally, so a list that answered in 200ms still
        // cost six seconds under the engine lock.
        let hard_deadline = tokio::time::Instant::now() + PROBE_COLLECT_BUDGET;
        // What we are still waiting for: a status answer from everyone WE ASKED,
        // and a name from everyone asked who has none. A server whose name we
        // already have owes us nothing further, so its silence must not hold the
        // round open - and a blocklist-gated server was never asked at all, so
        // it owes nothing either.
        let mut awaiting_status = sendable.iter().filter(|&&s| s).count();
        let mut awaiting_name = servers
            .iter()
            .zip(&sendable)
            .filter(|&(e, &s)| s && e.name.is_empty())
            .count();
        // The quiet period only starts once answers are actually FLOWING. Before
        // the first one there is no burst to be at the end of, and cutting the
        // round short there would cost every server a miss on a cold start - when
        // the health map is empty and there is nothing to vouch for any of them.
        let mut heard_from_anyone = false;
        let mut buf = [0u8; 2048];
        while awaiting_status > 0 || awaiting_name > 0 {
            let now = tokio::time::Instant::now();
            let deadline = if heard_from_anyone {
                hard_deadline.min(now + PROBE_QUIET_PERIOD)
            } else {
                hard_deadline
            };
            let remaining = deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                break;
            }
            match timeout(remaining, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, src)))
                    if n >= 2 && buf[0] == PROT_EDONKEY && buf[1] == OP_GLOBSERVSTATRES =>
                {
                    // Verify the echoed challenge (anti-spoof) as well as the src.
                    // The zip re-checks the send gate: an answer "from" a gated
                    // server was never solicited (the fixed challenge is
                    // spoofable), and must not settle a debt it does not owe -
                    // the counters no longer include it.
                    if let Some((challenge, users, files)) = parse_serv_stat_res(&buf[2..n]) {
                        if challenge == SERV_STAT_CHALLENGE {
                            if let Some((e, _)) =
                                servers.iter_mut().zip(&sendable).find(|(e, &s)| {
                                    s && e.addr.ip() == src.ip()
                                        && e.addr.port().checked_add(4) == Some(src.port())
                                })
                            {
                                // Only the FIRST answer from a server settles its
                                // debt - a duplicate must not drive the counter
                                // below what is genuinely outstanding.
                                if !e.alive {
                                    awaiting_status -= 1;
                                }
                                e.alive = true;
                                e.users = Some(users);
                                e.files = Some(files);
                                heard_from_anyone = true;
                            }
                        }
                    }
                }
                Ok(Ok((n, src)))
                    if n >= 2 && buf[0] == PROT_EDONKEY && buf[1] == OP_SERVER_DESC_RES =>
                {
                    if let Some(desc) = parse_server_desc_res(&buf[2..n], desc_challenge) {
                        let name = desc.name.trim().to_string();
                        if !name.is_empty() {
                            // Same gate re-check as the status handler above.
                            if let Some((e, _)) =
                                servers.iter_mut().zip(&sendable).find(|(e, &s)| {
                                    s && e.addr.ip() == src.ip()
                                        && e.addr.port().checked_add(4) == Some(src.port())
                                })
                            {
                                // Only ADOPT a learned name; never overwrite one
                                // the user's own server.met already carries.
                                if e.name.is_empty() {
                                    e.name = name;
                                    learned.push((e.addr, e.name.clone()));
                                    awaiting_name -= 1;
                                }
                                heard_from_anyone = true;
                            }
                        }
                    }
                }
                Ok(Ok(_)) => {}
                // The DEADLINE elapsing is the normal end. A transient socket
                // error is not, and must not throw away every answer still in
                // flight for the servers we have not heard from yet.
                Err(_) => break,
                Ok(Err(_)) => continue,
            }
        }

        // Fold in what we remember. A server that answered THIS round resets its
        // miss counter; one that stayed silent keeps its last good answer until
        // it has missed PROBE_MISSES_BEFORE_DEAD in a row. Without this a single
        // dropped datagram - routine on UDP, more so through a tunnel - greys out
        // a server that is answering perfectly well, which is what Anthony saw.
        if let Ok(mut health) = self.server_health.lock() {
            for e in servers.iter_mut() {
                let h = health.entry(e.addr).or_insert(ProbeHealth {
                    users: 0,
                    files: 0,
                    misses: 0,
                    answered: false,
                });
                let seen = fold_probe_round(h, e.alive, e.users.unwrap_or(0), e.files.unwrap_or(0));
                e.alive = seen.alive;
                e.checking = seen.checking;
                if seen.alive {
                    e.users = Some(seen.users);
                    e.files = Some(seen.files);
                }
            }
            // Do not accumulate forever: forget servers no longer in the list.
            let live: std::collections::HashSet<SocketAddr> =
                servers.iter().map(|e| e.addr).collect();
            health.retain(|addr, _| live.contains(addr));
        }
        // Persist the names we just learned, so a crawled/harvested server stops
        // reading as a bare IP everywhere (the Servers table, and the connected
        // status line, which reads its name from server.met tag 0x01).
        if !learned.is_empty() {
            self.persist_server_names(&learned);
        }
        servers
    }

    /// Write newly learned server names into server.met as tag 0x01, leaving
    /// every other tag and the file's header untouched. Best-effort: a failure
    /// only means the name is relearned by the next probe.
    fn persist_server_names(&self, learned: &[(SocketAddr, String)]) {
        let path = self.config_dir.join("server.met");
        let Ok(bytes) = std::fs::read(&path) else {
            return;
        };
        let Ok(mut met) = read_server_met(&bytes) else {
            return;
        };
        let mut touched = false;
        for (addr, name) in learned {
            let IpAddr::V4(v4) = addr.ip() else { continue };
            let met_ip = u32::from_le_bytes(v4.octets());
            for s in met.servers.iter_mut() {
                if s.ip == met_ip && s.port == addr.port() && tag_str(&s.tags, 0x01).is_none() {
                    s.tags.push(mule_proto::Tag::id(
                        0x01,
                        mule_proto::TagValue::Str(name.as_bytes().to_vec()),
                    ));
                    touched = true;
                }
            }
        }
        if touched {
            let _ = write_bytes_atomic(&path, &write_server_met(&met));
        }
    }

    /// Path to the pin side store (padMule-specific; kept out of server.met).
    fn pins_path(&self) -> PathBuf {
        self.config_dir.join("pinned.txt")
    }

    /// Load pinned server keys from disk into memory (called on start).
    fn load_pins(&mut self) {
        if let Ok(text) = std::fs::read_to_string(self.pins_path()) {
            self.pinned = read_pins(&text).into_iter().collect();
        }
    }

    /// Persist the pin set (best-effort; a write failure just means it will not
    /// survive a restart, never a crash). Sorted, for a stable file.
    fn save_pins(&self) {
        let mut keys: Vec<String> = self.pinned.iter().cloned().collect();
        keys.sort();
        let _ = std::fs::write(self.pins_path(), write_pins(&keys));
    }

    /// Pin or unpin a server (canonical `"ip:port"`); persisted immediately.
    pub fn set_server_pinned(&mut self, addr: &str, pinned: bool) {
        if pinned {
            self.pinned.insert(addr.to_string());
        } else {
            self.pinned.remove(addr);
        }
        self.save_pins();
    }

    /// Fetch a server.met from `url` (`http://` or `https://`, unwrapped bytes)
    /// and MERGE its entries into `config_dir/server.met` - every existing entry
    /// (and its tags) is kept and only new `(ip, port)`s are appended. The fetched
    /// bytes are validated as a real server.met BEFORE writing, so a bad URL /
    /// HTML error page never corrupts the list.
    ///
    /// TLS IS TRANSPORT, NOT TRUST. An `https://` fetch proves only that the bytes
    /// came unmodified from the host the certificate names; it says nothing about
    /// what that host chose to put in the file. So `vet_downloaded_servers` below
    /// runs on the result exactly as it does for plaintext - same gate, same
    /// rules, no TLS shortcut.
    pub async fn update_server_list(&self, url: &str) -> ServerListUpdate {
        // Scheme gate. https was rejected here until 2026-08-10, so a user could
        // not use an https server list even deliberately - not eMule's design:
        // eMule sets INTERNET_FLAG_SECURE for AFX_INET_SERVICE_HTTPS
        // (refs/emule-0.70b/.../HttpDownloadDlg.cpp:461-463). The iOS Settings
        // screen has always ACCEPTED an https:// URL into the source list
        // (EngineModel.addServerListUrl), so this rejection was reachable from
        // ordinary use, not just from a hand-typed edge case.
        if !url.starts_with("http://") && !url.starts_with("https://") {
            return ServerListUpdate::BadUrl;
        }
        let Ok(body) = bootstrap::http_get_bytes(url).await else {
            return ServerListUpdate::Unreachable;
        };
        if !bootstrap::looks_like_server_met(&body) {
            return ServerListUpdate::NotServerMet;
        }
        let Ok(incoming) = read_server_met(&body) else {
            return ServerListUpdate::NotServerMet;
        };
        let path = self.config_dir.join("server.met");
        let base = std::fs::read(&path)
            .ok()
            .and_then(|b| read_server_met(&b).ok())
            .unwrap_or_else(|| ServerMet {
                header: incoming.header,
                servers: Vec::new(),
            });
        let before = base.servers.len() as u32;
        let incoming = Self::vet_downloaded_servers(incoming, self.ip_filter.as_deref());
        let merged = merge_server_met(&base, &incoming);
        let total = merged.servers.len() as u32;
        if write_bytes_atomic(&path, &write_server_met(&merged)).is_err() {
            return ServerListUpdate::Unreachable;
        }
        ServerListUpdate::Updated {
            added: total - before,
            total,
        }
    }

    /// Merge servers a connected server advertised (OP_SERVERLIST) into
    /// server.met. The first, non-abusive step of the Server Hunter gossip crawl
    /// (docs/wiki/feature-server-hunter.md part 3): eD2k servers VOLUNTEER their
    /// peer servers, so simply connecting teaches padMule about servers that are
    /// in no published list - no scanning, no extra sockets. Runs on the 1s
    /// heartbeat, the same task as update_server_list, so there is never a
    /// concurrent server.met write. Returns how many NEW servers were added.
    pub async fn maintain_server_harvest(&mut self) -> u32 {
        let pending: Vec<(u32, u16)> = {
            let Ok(mut h) = self.harvested_servers.lock() else {
                return 0;
            };
            if h.is_empty() {
                return 0;
            }
            std::mem::take(&mut *h)
        };
        self.merge_discovered_servers(pending).await
    }

    /// Filter a set of learned `(ip, port)`s and merge the survivors into
    /// server.met, returning how many were NEW. The ONE safety gate shared by
    /// both discovery channels - the connect-time gossip harvest and the
    /// recursive UDP crawl - so the rule cannot drift between them.
    ///
    /// Keeps only routable public ip:port, honoring the user ipfilter. A server
    /// advertising 127.0.0.1, a LAN address, or a blocked range is bogus or
    /// hostile, and adding it would later point the UDP status probe (and the
    /// crawl itself) at our own network - the SSRF posture from build-progress
    /// 8z/B8 applies to anything that becomes a datagram target.
    /// Drop entries a DOWNLOADED server list must never be able to introduce:
    /// unroutable/private/loopback addresses, port 0, and anything the user's
    /// blocklist covers.
    ///
    /// Same posture as [`Engine::merge_discovered_servers`] and for the same
    /// reason - "anything that becomes a datagram target" - but this is the
    /// path that actually needed it. A list is fetched from a user-configured
    /// URL, so the PUBLISHER chooses its contents (and over `http://`, so can
    /// any intermediary - `https://` removes the intermediary but not the
    /// publisher, which is why this gate is not conditional on the scheme);
    /// every entry then becomes a UDP target of the status probe and the
    /// global search. The crawl was gated from the start and this was not,
    /// which is the more dangerous way round: the crawl only ever learns
    /// addresses from servers, while this ingests a file wholesale.
    ///
    /// Vetting happens HERE, at ingestion, rather than at the fan-out on
    /// purpose: a LAN or loopback server the user added themselves is
    /// legitimate and stays usable (padMule's own eserver oracle runs on
    /// 127.0.0.1), so gating the send sites would have broken a supported setup
    /// while leaving the injection path open. (Since 2026-08-09 the send sites
    /// ARE gated too, but only for blocklisted PUBLICLY ROUTABLE targets -
    /// `blocklist_forbids_send` - so the oracle/LAN case still holds while the
    /// residual gap closes: an entry that predated the blocklist, or was
    /// hand-added, no longer receives probes or global searches.)
    fn vet_downloaded_servers(met: ServerMet, filter: Option<&IpFilter>) -> ServerMet {
        let servers = met
            .servers
            .into_iter()
            .filter(|s| {
                let ip = ip_from_met_u32(s.ip);
                s.port != 0
                    && crate::fetch::is_routable_public_v4(ip)
                    // HOST ORDER, not the met u32. `is_blocked_u32` compares
                    // against ranges parsed from dotted quads, so the met
                    // convention (low byte = first octet) is byte-REVERSED
                    // relative to it and silently matches the wrong ranges.
                    && filter.is_none_or(|f| !f.is_blocked_u32(u32::from(ip)))
            })
            .collect();
        ServerMet {
            header: met.header,
            servers,
        }
    }

    async fn merge_discovered_servers(&mut self, pending: Vec<(u32, u16)>) -> u32 {
        let filter = self.ip_filter.clone();
        let fresh: Vec<Server> = pending
            .into_iter()
            .filter(|&(ip, port)| {
                let addr = ip_from_met_u32(ip);
                port != 0
                    && crate::fetch::is_routable_public_v4(addr)
                    // HOST ORDER. This passed the raw met u32 until 2026-08-08,
                    // which is byte-REVERSED relative to the ranges
                    // `is_blocked_u32` holds - so the user's blocklist was
                    // consulted with a scrambled address and never actually
                    // filtered a discovered server. Verified empirically:
                    // 85.17.116.222 reads unblocked as the met u32 and blocked
                    // as the host-order one, against the same filter.
                    && filter
                        .as_deref()
                        .is_none_or(|f| !f.is_blocked_u32(u32::from(addr)))
            })
            .map(|(ip, port)| Server {
                ip,
                port,
                tags: Vec::new(),
            })
            .collect();
        if fresh.is_empty() {
            return 0;
        }

        let path = self.config_dir.join("server.met");
        let base = std::fs::read(&path)
            .ok()
            .and_then(|b| read_server_met(&b).ok())
            .unwrap_or_else(|| ServerMet {
                header: mule_files::server_met::SERVER_MET_HEADER,
                servers: Vec::new(),
            });
        let before = base.servers.len();
        let merged = merge_server_met(
            &base,
            &ServerMet {
                header: base.header,
                servers: fresh,
            },
        );
        let added = (merged.servers.len() - before) as u32;
        if added > 0 && write_bytes_atomic(&path, &write_server_met(&merged)).is_ok() {
            self.emit(EngineEvent::Server(format!(
                "Discovered {added} server(s) from the network"
            )));
            added
        } else {
            0
        }
    }

    /// The RECURSIVE UDP server crawl: ask servers we are NOT connected to for
    /// the servers THEY know, then ask the ones that come back, for `rounds`
    /// hops. The full Server Hunter discovery engine
    /// (docs/wiki/feature-server-hunter.md part 3), where the connect-time
    /// harvest only learns from the single server we logged into.
    ///
    /// Wire + the deliberate deviation: see `OP_SERVER_LIST_REQ2`. SILENCE IS
    /// THE COMMON ANSWER - most servers never implement it - so a non-answer is
    /// neither an error nor a liveness verdict, and the crawl simply moves on.
    ///
    /// Bounded on every axis, because this is the one feature that talks to
    /// hosts the user never chose: at most `MAX_CRAWL_ROUNDS` hops,
    /// `CRAWL_ASKS_PER_ROUND` asks per hop, paced `CRAWL_SEND_PACE` apart, a
    /// `CRAWL_ROUND_WAIT` collection budget, and `MAX_CRAWL_DISCOVERED` total.
    /// The abuse profile is deliberately no worse than the Servers screen's
    /// existing status probe, which already sends every known server a datagram.
    /// Whole-net scanning stays out of scope.
    ///
    /// Returns how many NEW servers were merged into server.met.
    pub async fn crawl_servers(&mut self, rounds: u32) -> u32 {
        if self.offline {
            return 0;
        }
        let Ok(bytes) = std::fs::read(self.config_dir.join("server.met")) else {
            return 0;
        };
        let Ok(met) = read_server_met(&bytes) else {
            return 0;
        };
        let mut crawl = ServerCrawl::new(met.servers.iter().map(|s| (s.ip, s.port)));
        let Ok(sock) = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0u16)).await else {
            return 0;
        };
        let filter = self.ip_filter.clone();
        let req = [PROT_EDONKEY, OP_SERVER_LIST_REQ2];
        let mut answered = 0u32;
        // What the progress line reports: datagrams actually SENT. The state
        // machine's `asked_count` includes addresses the ipfilter then
        // stopped, and a server the filter stopped was not asked.
        let mut sent = 0usize;

        for _ in 0..rounds.clamp(1, MAX_CRAWL_ROUNDS) {
            let asks = crawl.next_asks(CRAWL_ASKS_PER_ROUND);
            if asks.is_empty() {
                break;
            }
            // The ipfilter gates who we SEND to, not merely what we keep - a
            // blocked address gets no datagram from here. Since 2026-08-09 the
            // consult is THE shared send gate (`blocklist_forbids_send`, also
            // on the status probe and the global search fan-outs); its
            // public-only scoping is a no-op on this path, because
            // `is_crawlable` already admits only routable PUBLIC addresses to
            // the frontier. The met u32 is converted BEFORE the consult - the
            // raw form is byte-REVERSED relative to the ranges the filter
            // holds, and passing it straight through asked every blocklisted
            // server anyway (the same trap `merge_discovered_servers` carried
            // until 2026-08-08; this was the third site).
            let targets: Vec<SocketAddr> = asks
                .iter()
                .filter(|(ip, _)| !blocklist_forbids_send(filter.as_deref(), ip_from_met_u32(*ip)))
                .filter_map(|&(ip, port)| {
                    port.checked_add(4)
                        .map(|udp| SocketAddr::new(IpAddr::V4(ip_from_met_u32(ip)), udp))
                })
                .collect();
            if targets.is_empty() {
                continue;
            }
            // Paced, so a round is a trickle rather than a burst at the network.
            sent += targets.len();
            for t in &targets {
                let _ = sock.send_to(&req, t).await;
                tokio::time::sleep(CRAWL_SEND_PACE).await;
            }
            // Collect, accepting an answer ONLY from an address we just asked
            // (anti-spoof - the same rule the global UDP search applies).
            let expected: std::collections::HashSet<SocketAddr> = targets.into_iter().collect();
            let deadline = tokio::time::Instant::now() + CRAWL_ROUND_WAIT;
            let mut buf = [0u8; 2048];
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    break;
                }
                match timeout(remaining, sock.recv_from(&mut buf)).await {
                    Ok(Ok((n, src)))
                        if n >= 3
                            && buf[0] == PROT_EDONKEY
                            && buf[1] == OP_SERVER_LIST_RES
                            && expected.contains(&src) =>
                    {
                        if let Ok(list) = parse_server_list(&buf[2..n]) {
                            answered += 1;
                            crawl.on_answer(&list);
                        }
                    }
                    Ok(Ok(_)) => continue, // a stray or spoofed datagram
                    _ => break,
                }
            }
        }

        let found = crawl.discovered().to_vec();
        if found.is_empty() {
            // Say so honestly: asking is cheap and most servers do not answer.
            self.emit(EngineEvent::Server(format!(
                "Crawl asked {sent} server(s), {answered} answered - no new servers"
            )));
            return 0;
        }
        let added = self.merge_discovered_servers(found).await;
        self.emit(EngineEvent::Server(format!(
            "Crawl asked {sent} server(s), {answered} answered - {added} new"
        )));
        added
    }

    /// Drop shared files whose bytes are no longer on disk, correcting both the
    /// live library and known.met. Returns how many were dropped.
    ///
    /// The downloads directory is the user-visible Files folder and padMule has
    /// no in-app delete, so the ONLY way a finished file disappears is the user
    /// removing it - and before this existed, the library was verified just once
    /// at `start()`. For the rest of the session padMule kept announcing the
    /// dead hash to the server, told a requesting peer the file was COMPLETE,
    /// granted it an upload slot, and then dropped the connection when the read
    /// failed. Same rule as `load_shared_library`: present AND the right size,
    /// because a different file can be saved under the same name.
    pub async fn verify_shared_library(&mut self) -> u32 {
        let missing: Vec<(usize, [u8; 16])> = {
            let lib = self.shared.lock().await;
            lib.iter()
                .enumerate()
                .filter(|(_, f)| !matches!(std::fs::metadata(&f.path), Ok(m) if m.len() == f.size))
                .map(|(i, f)| (i, f.hash))
                .collect()
        };
        if missing.is_empty() {
            return 0;
        }
        let mut dropped_roots: Vec<[u8; 20]> = Vec::new();
        {
            let mut lib = self.shared.lock().await;
            // Remove back-to-front so the earlier indices stay valid.
            for (i, _) in missing.iter().rev() {
                if let Some(r) = lib.remove(*i).aich_root {
                    dropped_roots.push(r);
                }
            }
        }
        for (_, hash) in &missing {
            forget_shared_file(&self.config_dir, *hash);
        }
        // The catalog no longer claims these files, so their AICH hashsets go
        // with them (same rule as the startup prune, applied incrementally).
        for r in &dropped_roots {
            self.known2.remove(r);
        }
        // Re-announce the corrected library: the server still holds the old one.
        self.shared_dirty.store(true, Ordering::Relaxed);
        let n = missing.len() as u32;
        self.emit(EngineEvent::Server(format!(
            "{n} shared file(s) no longer on disk - stopped sharing them"
        )));
        n
    }

    /// Probe the server list and drop every server that is DEAD and not pinned,
    /// rewriting `config_dir/server.met`. Returns how many were removed.
    pub async fn prune_dead_servers(&mut self) -> u32 {
        // Keep a server if it answered the probe, is pinned, OR is the one we are
        // connected to right now. Many servers are TCP-reachable but do not answer
        // the UDP status ping, so `alive` alone would prune the server in active use
        // (eMule never removes the connected server on "remove dead servers").
        let keep: std::collections::HashSet<String> = self
            .probe_server_list()
            .await
            .iter()
            .filter(|e| e.alive || e.pinned || e.connected)
            .map(|e| e.addr.to_string())
            .collect();
        let path = self.config_dir.join("server.met");
        let Ok(bytes) = std::fs::read(&path) else {
            return 0;
        };
        let Ok(met) = read_server_met(&bytes) else {
            return 0;
        };
        let before = met.servers.len();
        let servers: Vec<_> = met
            .servers
            .into_iter()
            .filter(|s| {
                let addr = SocketAddr::new(IpAddr::V4(ip_from_met_u32(s.ip)), s.port);
                keep.contains(&addr.to_string())
            })
            .collect();
        let removed = (before - servers.len()) as u32;
        if removed > 0 {
            let out = ServerMet {
                header: met.header,
                servers,
            };
            let _ = write_bytes_atomic(&path, &write_server_met(&out));
        }
        removed
    }

    /// Drain buffered server packets (kick message / MOTD -> events) and detect a
    /// drop/kick between requests. Cancel-safe (FramedStream buffers), so this is
    /// safe to call from the 1s heartbeat. On EOF it clears the link + connection
    /// and emits `ServerDropped` (the UI raises a prominent dialog), returning the
    /// lost server's address.
    pub async fn poll_server_drop(&mut self) -> Option<String> {
        let dropped = match self.server.as_mut() {
            Some(l) => l.poll_incoming().await,
            None => return None,
        };
        if !dropped {
            return None;
        }
        let addr = self
            .server
            .as_ref()
            .map(|l| l.addr().to_string())
            .unwrap_or_default();
        if let Some(mut l) = self.server.take() {
            l.disconnect().await;
        }
        self.connection = None;
        self.emit(EngineEvent::ServerDropped { addr: addr.clone() });
        // The DURABLE status line too. The app feeds its status row from
        // `Status` events ALONE and routes `Server` text to a transient banner,
        // so without this the row keeps claiming the connection we just lost -
        // the same "an event is not state" bug fixed for connect/disconnect in
        // 8as, which missed this path. Emitted after `self.server` is cleared,
        // because `online_status` asks `is_online`.
        self.emit_online_status();
        Some(addr)
    }

    /// Announce our shared library to `link` via OP_OFFERFILES, so the server
    /// indexes it (findable by keyword search) and can source us. All our shares
    /// are COMPLETE, so each carries the FILE_COMPLETE_ID/PORT marker - faithful
    /// to aMule against a compression-advertising server (every live server), and
    /// it keeps a HighID's public IP out of the server's search index (the server
    /// sources us via our login id regardless). No-op with an empty library.
    async fn offer_shared_to(shared: &Mutex<Vec<SharedFile>>, link: &mut ServerLink) {
        // aMule caps each OFFERFILES burst at 200 files; we cap too (v1 does not
        // republish the remainder).
        const MAX_OFFER: usize = 200;
        // Snapshot what we need, then RELEASE the lock before the network write -
        // so a concurrent share change (a download finishing) never blocks on it.
        // Take the NEWEST 200 (finish_download appends to the tail): a just-
        // finished file - the very reason a re-offer fires - must always be in
        // the burst, never the one the cap drops.
        let snap: Vec<([u8; 16], String, u64)> = {
            let shared = shared.lock().await;
            shared
                .iter()
                .rev()
                .take(MAX_OFFER)
                .map(|s| {
                    (
                        s.hash,
                        String::from_utf8_lossy(&s.name).into_owned(),
                        s.size,
                    )
                })
                .collect()
        };
        if snap.is_empty() {
            return;
        }
        let offers: Vec<OfferedFile> = snap
            .iter()
            .map(|(h, n, sz)| OfferedFile {
                hash: *h,
                name: n,
                size: *sz,
            })
            .collect();
        // Bounded + best-effort: a stalled write must NOT hang connect/resume, and
        // a rejected offer is not fatal. 4s (not 10s) because this runs UNDER the
        // shared engine lock via the 1s heartbeat(), so it also caps how
        // long a re-offer can delay pause()'s socket teardown - iPadOS only grants
        // ~5s to background before it kills us.
        let _ = timeout(
            Duration::from_secs(4),
            link.offer_files(&offers, FILE_COMPLETE_ID, FILE_COMPLETE_PORT),
        )
        .await;
    }

    /// Re-announce the shared library to the server after a mid-session change.
    /// A download finishing sets `shared_dirty`; the 1s heartbeat() calls
    /// this, so a file that completes while we are connected becomes findable
    /// within about a second instead of only after the next reconnect.
    ///
    /// Cheap: a no-op unless the library actually changed. `swap` clears the flag
    /// up front, so a completion that lands DURING the offer re-arms it for the
    /// next beat (no lost update). While offline nothing is lost either: a
    /// reconnect re-offers the whole current library via `connect_server`.
    pub async fn maintain_shares(&mut self) {
        // Peek WITHOUT clearing: if we cannot actually offer (no server, or the
        // link is paused/disconnected) the flag must stay raised so a later
        // connected beat still announces the file. Clearing it here would strand
        // the file for the session - resume()'s success fast-path does not
        // re-offer, only a full connect_server does.
        if !self.shared_dirty.load(Ordering::Relaxed) {
            return;
        }
        // Disjoint field borrows: `server` mutably, `shared` immutably.
        let Some(link) = self.server.as_mut() else {
            return;
        };
        if !link.is_connected() {
            return;
        }
        // Committed to offering. Clear now (there is no await between the load
        // above and here, so nothing was missed); a completion that lands DURING
        // the offer re-arms the flag for the next poll - no lost update.
        self.shared_dirty.store(false, Ordering::Relaxed);
        Self::offer_shared_to(&self.shared, link).await;
    }

    /// Finalize any download that reached 100% OUTSIDE a fetch task - e.g. a LowID
    /// source that dialed our listener and served the last bytes, or a completion
    /// after the fetch sweep's round budget. Without this, such a download would
    /// sit complete-but-not-saved (never verified, moved, or shared). Idempotent
    /// via try_begin_finalize; runs each 1s heartbeat. Spawns finish_download
    /// (which verifies off-lock) rather than awaiting it, so the heartbeat - and
    /// thus the shared engine lock - is never held across the verify + file move.
    pub async fn finalize_completed(&self) {
        let pending: Vec<Arc<Download>> = self.downloads.lock().await.clone();
        for dl in pending {
            if !dl.is_complete().await || !dl.try_begin_finalize() {
                continue;
            }
            let hash = dl.hash().await;
            let size = dl.size().await;
            let dest = self.downloads_dir.join(safe_filename(&dl.name().await));
            let ctx = FinishCtx {
                registry: Arc::clone(&self.downloads),
                shared: Arc::clone(&self.shared),
                shared_dirty: Arc::clone(&self.shared_dirty),
                config_dir: self.config_dir.clone(),
                known_met_lock: Arc::clone(&self.known_met_lock),
                known2: Arc::clone(&self.known2),
                events: self.events.clone(),
            };
            tokio::spawn(finish_download(dl, ctx, hash, size, dest));
        }
    }

    /// Bind the Kad UDP socket and bootstrap off the persisted contacts.
    async fn start_kad(&mut self) {
        // BOTH sources, unioned - and the in-memory one FIRST, because it is the
        // fresher of the two and the one this used to ignore.
        //
        // `pause()` drops the live node via `set_kad(None)`, which folds
        // everything it learned into `self.routing`. Resume then came straight
        // back here and re-seeded from nodes.dat ON DISK, so every contact
        // learned since the last checkpoint was thrown away on each
        // background/foreground round trip. Caught live on 2026-08-05: the
        // Status screen read 138 contacts, Anthony opened a download in another
        // app and came back, and the engine logged `kad contacts: 21`.
        //
        // That is also why the table never seemed to grow across a session -
        // and it made the 2026-08-05 Kad maintenance (`maintain_kad`) rebuild
        // into a bucket with a hole in it. `load_nodes` merges, so the union
        // costs nothing when the two agree.
        let mut contacts: Vec<KadContact> = routing_to_nodes(&self.routing);
        let known: std::collections::HashSet<_> = contacts.iter().map(|c| c.id).collect();
        if let Ok(b) = std::fs::read(self.config_dir.join("nodes.dat")) {
            if let Ok(n) = read_nodes_dat(&b) {
                contacts.extend(n.contacts.into_iter().filter(|c| !known.contains(&c.id)));
            }
        }
        // The dial list gets the same gate as the table load: the ipfilter means
        // NO CONTACT, not merely no routing entry, and a poisoned nodes.dat must
        // not aim the bootstrap sweep at loopback/LAN/DNS-port/Kad1 addresses.
        let contacts = gate_loaded_nodes(&contacts, self.ip_filter.as_deref());
        if contacts.is_empty() {
            self.emit(EngineEvent::Server("no Kad contacts to bootstrap".into()));
            return;
        }
        let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), self.kad_port);
        // The PERSISTED identity, so our Kad ID and the UDP verify keys peers
        // stored for us survive a restart (identity.rs names re-keying Kad on
        // every start as the failure a stable identity exists to prevent).
        let Ok(mut node) = KadNode::bind_with_identity(
            bind,
            self.advertised_port,
            self.identity.kad_id,
            self.identity.kad_udp_key,
        )
        .await
        else {
            self.emit(EngineEvent::Server("Kad UDP port unavailable".into()));
            return;
        };
        // Tell peers the port the PROVIDER forwards, which is only the bound one
        // in the ordinary same-port case. Without this a remap means padMule
        // binds correctly and then advertises a port nothing forwards, so no
        // peer can ever reach it - inbound Kad silently dies while everything
        // outbound keeps working, which is the hardest shape to notice.
        node.set_advertised_udp_port(
            (self.kad_advertised_port != self.kad_port).then_some(self.kad_advertised_port),
        );
        // Thread the user blocklist into Kad so it gates routing inserts (eMule
        // filters every Kad contact, RoutingZone.cpp:477), matching the eD2k path.
        node.set_ip_filter(self.ip_filter.clone());
        // Feed our public IP (from the UPnP map above) so the node echoes a peer's
        // UDP verify key bound to THIS ip - the send-side of Kad hard-verify. `None`
        // (no mapping) leaves it 0, which disables the echo (the proven baseline).
        // On resume the last-learned value persists; a stale one only skips the
        // optimization (the echo gate is IP-equality), it never mis-verifies.
        let pub_ip = self.public_ip.lock().ok().and_then(|g| *g);
        node.set_public_ip(pub_ip.map_or(0, u32::from));
        // SEED THE TABLE LOOKUPS WILL ACTUALLY READ, before dialing anything.
        //
        // `contacts` above is the bootstrap DIAL LIST; this is the routing TABLE,
        // and they are not the same thing. A fresh node's table is empty and
        // `bootstrap_any` stops at the first answer, so without this every
        // start/resume left lookups running against one bootstrap response - the
        // "21" in the 2026-08-05 syslog - while `Engine::routing` held hundreds.
        // See `KadNode::seed_routing` for why the verified bit has to survive.
        //
        // BEFORE the bootstrap, deliberately: a bootstrap that fails entirely
        // then still leaves a usable table, which is also what keeps
        // `maintain_kad` (guarded on `contacts_known() > 0`) able to run at all
        // on a session whose bootstrap missed. `set_ip_filter` above has already
        // run, so the seeding is gated by the user's blocklist like any insert.
        node.seed_routing(&contacts);
        // Cap the OVERALL bootstrap: 40 contacts * 1200ms is ~48s worst case, and
        // start_kad runs while the single shared engine lock is held (start/resume
        // via the FFI), so an uncapped bootstrap would block pause()'s socket
        // teardown and every other FFI call for that whole window. The server path
        // is bounded the same way. Kad keeps working incrementally on its socket
        // after, so a timed-out-but-partial bootstrap is still useful.
        // NB: the wave-10 HELLO below adds its own 2s cap, so the lock-held
        // worst case for start_kad is ~7s total, not 5.
        let boot = timeout(
            Duration::from_secs(5),
            node.bootstrap_any(&contacts, Duration::from_millis(1200), 40),
        )
        .await;
        // The contact that answered, if any: we HELLO it next to complete the v8
        // three-way handshake so a real node marks us IP-verified (see below).
        let responder = match &boot {
            Ok(Ok((i, _))) => contacts.get(*i).cloned(),
            _ => None,
        };
        let bootstrapped = matches!(boot, Ok(Ok(_)));
        // Complete a verification handshake with our entry node: HELLO it so it sends
        // a HELLO_RES, then we ACK with its echoed key and it marks US IP-verified
        // (eMule Process2HelloResponseAck). Being verified keeps us a first-class
        // routing contact (returned in lookups, publishes accepted) instead of a
        // deprioritized unverified one. Best-effort + bounded: a miss just leaves us
        // unverified (the prior behavior), never blocks. Broader coverage (verifying
        // more nodes, e.g. publish targets) is a follow-on.
        if let Some(c) = responder {
            let _ = timeout(
                Duration::from_secs(2),
                node.hello(&c, Duration::from_millis(1500)),
            )
            .await;
        }
        // Fold whatever Kad learned into the persisted routing table (even a
        // timed-out bootstrap may have found contacts). Keep the node either way:
        // it owns a live UDP socket + our persisted identity, and downloads pull
        // Kad sources through it.
        self.routing
            .load_nodes(&node.with_routing(|t| routing_to_nodes(t)));
        self.emit(EngineEvent::Kad {
            contacts: node.contacts_known(),
        });
        if !bootstrapped {
            self.emit(EngineEvent::Server("Kad bootstrap incomplete".into()));
        }
        self.set_kad(Some(node));
    }

    /// Search BOTH the connected server AND the Kad network, deduped + ranked by
    /// [`catalog`]. Either half may be absent: a serverless client still gets Kad
    /// hits, a client with no Kad contacts still gets server hits, and a file on
    /// both merges by hash. Empty only when neither has anything (or we are
    /// offline) - not worth an error the UI would render as "no results" anyway.
    ///
    /// The two run concurrently, so the wait is the SLOWER of the two, not the
    /// sum - and in practice that was always the Kad arm, because its own
    /// queries were serial (see `KAD_SEARCH_WAIT`). Blocks up to `SEARCH_WAIT`;
    /// the FFI facade runs it off the UI thread.
    /// Filters (bounds in BYTES) are applied on the server wire query and to the
    /// merged set.
    pub async fn search(&mut self, keyword: &str, filters: SearchFilters) -> SearchOutcome {
        let keyword = keyword.trim();
        if self.offline || keyword.is_empty() {
            return SearchOutcome::Results {
                ranked: Vec::new(),
                more_available: false,
            };
        }
        // Client-side flood guard for the SERVER query only (aMule's 2 s): Kad and
        // global UDP are not the eserver's flood budget, so a serverless search is
        // never throttled. Stamp the time BEFORE issuing so bursts are caught.
        if self.server.is_some() {
            let now = Instant::now();
            if let Some(wait_secs) =
                throttle_wait_secs(self.last_server_search, now, SERVER_SEARCH_MIN_INTERVAL)
            {
                return SearchOutcome::Throttled { wait_secs };
            }
            self.last_server_search = Some(now);
        }
        let params = SearchParams {
            keyword: keyword.to_string(),
            file_type: None,
            // Push size + availability onto the server query so the ~200-result
            // cap fills with matches instead of junk. Min size clamps to 32-bit
            // (widening only); a max above 4 GiB is omitted from the wire and
            // enforced client-side below (see mule-cli fetch-complete).
            min_size: filters.min_size.map(|b| b.min(u32::MAX as u64) as u32),
            max_size: filters
                .max_size
                .and_then(|b| (b <= u32::MAX as u64).then_some(b as u32)),
            min_sources: filters.min_sources,
            // NOT the keyword: the search box means the word, not the file type
            // (mule-cli's fetch-complete pins an extension only because it hunts
            // for a ".pdf" when asked for "pdf").
            extension: None,
        };
        // Global UDP search (#9) reads server.met + the connected server's addr
        // (to skip it) + the blocklist (its send gate) before the &mut borrows
        // below; it runs concurrently.
        let config_dir = self.config_dir.clone();
        let connected = self.server.as_ref().map(|l| l.addr());
        let ip_filter = self.ip_filter.clone();
        let do_global = filters.global;
        // The server link and the Kad node are separate fields, so both can be
        // borrowed and driven at once.
        let server = self.server.as_mut();
        let kad = self.kad.as_mut();
        let (server_page, kad_files, global_files) = tokio::join!(
            async {
                match server {
                    Some(link) => link
                        .search_page(&params, SEARCH_WAIT)
                        .await
                        .unwrap_or_default(),
                    None => SearchResultPage::default(),
                }
            },
            async {
                match kad {
                    // Bounded so a slow lookup cannot hang the search; a lookup
                    // that misses the budget just contributes nothing this time.
                    Some(node) => timeout(
                        KAD_SEARCH_WAIT,
                        node.resolve_keyword(keyword, 50, KAD_PER_QUERY),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default(),
                    None => Vec::new(),
                }
            },
            async {
                if do_global {
                    global_udp_search(
                        &config_dir,
                        &params,
                        connected,
                        ip_filter.as_deref(),
                        SEARCH_WAIT,
                    )
                    .await
                } else {
                    Vec::new()
                }
            },
        );
        // Fold the Kad + global-UDP hits into the same shape the server hits
        // arrive in, so a single catalog pass dedupes across all three by hash.
        let server_more = server_page.more;
        let mut combined = server_page.files;
        // Track WHERE each row came from, in step with `combined`. The origin is
        // otherwise destroyed right here - three channels flattened into one
        // untagged vec before catalog() dedupes - so the UI could never say
        // whether a hit came from the server, from Kad, or from both.
        let mut origins: Vec<u8> = vec![crate::catalog::ORIGIN_SERVER; combined.len()];
        combined.extend(kad_files.iter().map(kad_to_search));
        origins.resize(combined.len(), crate::catalog::ORIGIN_KAD);
        combined.extend(global_files);
        origins.resize(combined.len(), crate::catalog::ORIGIN_GLOBAL);
        let ranked = apply_search_filters(
            crate::catalog::catalog_with_origins(&combined, &origins),
            &filters,
        );
        // Remember this window so "load more" can continue the SERVER query on the
        // same connection (server-only: Kad/global are one-shot). No server -> no
        // session and nothing more to fetch.
        let more_available = server_more && connected.is_some();
        self.search_session = connected.map(|server_addr| SearchSession {
            server_addr,
            combined,
            origins,
            filters,
            server_more,
            more_reqs: 0,
        });
        SearchOutcome::Results {
            ranked,
            more_available,
        }
    }

    /// Related-files search: ask the connected server for the files its index
    /// associates with `hash` - the ones clients who share this file also share
    /// (eMule's `related::` feature). SERVER-ONLY: Kad has no related index, and
    /// only a server advertising SRV_TCPFLG_RELATEDSEARCH answers it (else it
    /// would treat `related::<hash>` as a literal keyword and return nothing), so
    /// this returns empty when the server does not support it - the UI offers a
    /// filename keyword search instead (see `ServerInfo::related_search`). Ranked
    /// through the same [`catalog`] pass as a normal search, so results render
    /// identically.
    pub async fn related_search(&mut self, hash: [u8; 16]) -> SearchOutcome {
        let empty = || SearchOutcome::Results {
            ranked: Vec::new(),
            more_available: false,
        };
        if self.offline {
            return empty();
        }
        // A related search is a no-op unless a related-search-capable server is
        // connected, so check that BEFORE the flood guard - otherwise a related tap
        // within 2s of a normal search would falsely report "wait 2s" for something
        // that would do nothing, and the UI would not fall back to a keyword search.
        if !self
            .server
            .as_ref()
            .is_some_and(|l| l.related_search_supported())
        {
            return empty();
        }
        // Same flood guard as a normal search (it hits the same server); stamp only
        // when we actually issue.
        let now = Instant::now();
        if let Some(wait_secs) =
            throttle_wait_secs(self.last_server_search, now, SERVER_SEARCH_MIN_INTERVAL)
        {
            return SearchOutcome::Throttled { wait_secs };
        }
        self.last_server_search = Some(now);
        let params = SearchParams {
            keyword: related_keyword(&hash),
            file_type: None,
            min_size: None,
            max_size: None,
            min_sources: None,
            extension: None,
        };
        let link = self.server.as_mut().expect("checked supported just above");
        let files = link.search(&params, SEARCH_WAIT).await.unwrap_or_default();
        // THE PAGING CURSOR NOW BELONGS TO THIS QUERY, so the keyword session
        // that was using it is void. `OP_QUERY_MORE_RESULT` is bodiless - it
        // continues whatever query the SERVER last received - and the line above
        // just made that this related search. Leaving the old session in place
        // let a later `search_more()` pass its own staleness check (same server,
        // still `server_more`, under the page cap) and splice page 2 of the
        // RELATED query into the KEYWORD result set, silently and with no error
        // anywhere. Dropping it turns "Load more" off instead, which is honest:
        // the related result itself already reports `more_available: false`.
        //
        // NOT UNIT-TESTED: the seam needs a connected, related-search-capable
        // server link, so no test in this file can reach it - the eserver oracle
        // is where it would be provable. Said plainly rather than implied.
        self.search_session = None;
        SearchOutcome::Results {
            ranked: catalog(&files),
            more_available: false,
        }
    }

    /// Fetch the next page of the last SERVER search and merge it into the same
    /// ranked view - eMule's "Load more results" (server-only, bodiless
    /// OP_QUERY_MORE_RESULT, up to [`MAX_MORE_SEARCH_REQ`] pages). Returns the
    /// current ranked view with the button OFF when there is nothing more, the
    /// session is stale (a reconnect voids it), or the page cap is reached.
    pub async fn search_more(&mut self) -> SearchOutcome {
        let connected = self.server.as_ref().map(|l| l.addr());
        let can_page = !self.offline
            && matches!(&self.search_session, Some(s)
                if connected == Some(s.server_addr)
                    && s.server_more
                    && s.more_reqs < MAX_MORE_SEARCH_REQ);
        if !can_page {
            let ranked = self
                .search_session
                .as_ref()
                .map(|s| {
                    apply_search_filters(
                        crate::catalog::catalog_with_origins(&s.combined, &s.origins),
                        &s.filters,
                    )
                })
                .unwrap_or_default();
            return SearchOutcome::Results {
                ranked,
                more_available: false,
            };
        }
        // Continue the query on the SAME link; the server holds it in session state.
        let page = match self.server.as_mut() {
            Some(link) => link.search_more(SEARCH_WAIT).await.unwrap_or_default(),
            None => SearchResultPage::default(),
        };
        let session = self
            .search_session
            .as_mut()
            .expect("can_page implies a session");
        session.combined.extend(page.files);
        session.server_more = page.more;
        session.more_reqs += 1;
        let ranked = apply_search_filters(
            crate::catalog::catalog_with_origins(&session.combined, &session.origins),
            &session.filters,
        );
        let more_available = session.server_more && session.more_reqs < MAX_MORE_SEARCH_REQ;
        SearchOutcome::Results {
            ranked,
            more_available,
        }
    }

    /// Classify a search hit's hash against our downloads + shared files, so the
    /// UI can show an already-have / fetching / new indicator per result.
    pub async fn hit_status(&self, hash: [u8; 16]) -> HitStatus {
        for dl in self.downloads.lock().await.iter() {
            if dl.hash().await == hash {
                return if dl.is_complete().await {
                    HitStatus::Have
                } else {
                    HitStatus::Downloading
                };
            }
        }
        if self.shared.lock().await.iter().any(|s| s.hash == hash) {
            return HitStatus::Have;
        }
        HitStatus::New
    }

    /// Start downloading `hash`. Asks the server AND Kad who has it (see
    /// [`Engine::find_sources`]), creates the part file, registers the download,
    /// and spawns the transfer - returning as soon as it is registered, NOT when
    /// the file lands. Progress is observed via [`Engine::downloads`]; the
    /// finished file is moved to `downloads_dir`.
    ///
    /// Idempotent: asking twice for the same hash is a no-op, not a second
    /// part file racing the first.
    pub async fn add_download(&mut self, hash: [u8; 16], size: u64, name: &str) -> AddResult {
        if size == 0 {
            return AddResult::BadRequest("file size is unknown");
        }
        for dl in self.downloads.lock().await.iter() {
            if dl.hash().await == hash {
                return AddResult::AlreadyAdded;
            }
        }
        if self.offline || !self.can_discover() {
            // Bail BEFORE the source lookup: with no channel there is nobody to
            // ask, so spending the 10s budget would only delay an answer we
            // already know - and the honest answer is about our connection, not
            // about the file.
            return AddResult::NotConnected;
        }
        // No server gate: find_sources queries the connected server AND Kad, so a
        // SERVERLESS client still downloads from HighID Kad sources (a LowID Kad
        // source needs a server callback, so it is simply skipped without one).
        // A hands-on simulation caught the old gate: with every server down but
        // Kad up, search returned real hits yet every download was refused
        // "NoServer" - even though Kad had the sources.
        // `true` - return the moment the server yields sources. Get used to cost
        // a FLAT ~15s (see find_sources): the joined path waits for the slower
        // arm, and a Kad lookup essentially always burns its whole budget, so
        // the user paid ~14.8s of Kad timeout after the server had already
        // answered in ~200ms - while holding the engine lock, so queueing four
        // files cost a minute.
        //
        // Nothing is lost in the case that matters: with no server, or a server
        // that knows nothing, this falls through to the SAME joined Kad path as
        // before (see `add_download_without_a_server_still_tries_kad`). Kad
        // sources simply arrive via the retry sweep and source exchange instead
        // of at the instant of the tap.
        let (reg, lowids) = self
            .find_sources(hash, size, ADD_SOURCES_BUDGET, true)
            .await;
        // A LowID source can only reach us via a SERVER callback, so without a
        // server only directly-connectable (HighID) sources are usable - otherwise
        // a Kad-only client would register a download that can never progress.
        let has_usable_source = !reg.is_empty() || (self.server.is_some() && !lowids.is_empty());
        if !has_usable_source {
            return AddResult::NoSources;
        }

        // aMule numbers part files NNN.part in one directory and
        // resume_downloads finds them by that name, so take the next free index.
        let index = next_part_index(&self.config_dir);
        let store = match PartStore::create(&self.config_dir, index, hash, size, name.as_bytes()) {
            Ok(s) => s,
            Err(e) => return AddResult::Failed(e.to_string()),
        };
        let dl = Download::new(store);
        let queued = {
            let mut guard = self.downloads.lock().await;
            guard.push(Arc::clone(&dl));
            // Admission for the NEW row, by the one rule. Registered either
            // way - a queued download is a real entry that the sweep drives
            // the moment a slot frees.
            let now = u64::from(now_secs());
            let mut rows = Vec::with_capacity(guard.len());
            for d in guard.iter() {
                rows.push(d.admission_row(now).await);
            }
            let cap = self.max_active.load(Ordering::Relaxed);
            *crate::multi_source::queued_flags(cap, &rows)
                .last()
                .unwrap_or(&false)
        };

        // Keep what the lookup produced. Both numbers are right here and were
        // discarded; without them a row with no bytes cannot say whether nothing
        // was found or plenty was found and none of it was reachable.
        dl.note_source_pool(reg.sources().len(), lowids.len());
        if queued {
            // Deliberately NO request_callbacks here: a callback poked now
            // solicits LowID dial-backs for a row the listener will refuse to
            // drive (callback_drive_flags), so it would only spend the
            // server's goodwill and the peers' dials. The retry sweep re-runs
            // source discovery - callbacks included - when a slot frees.
            let _ = self.events.send(EngineEvent::Status(format!(
                "'{name}' queued - at the max-active download cap"
            )));
            return AddResult::Started;
        }
        self.request_callbacks(&lowids).await;
        self.spawn_fetch(dl, hash, size, name, reg.sources().to_vec());
        AddResult::Started
    }

    /// Pause ONE download (eMule 0.70b `PauseFile`): its workers stop within a
    /// block, the entry and its bytes stay, and FT_STATUS persists the flag so
    /// a restart comes back paused. Returns false if no active download
    /// carries that hash.
    pub async fn pause_download(&mut self, hash: [u8; 16]) -> bool {
        let dl = {
            let guard = self.downloads.lock().await;
            let mut found = None;
            for d in guard.iter() {
                if d.hash().await == hash {
                    found = Some(Arc::clone(d));
                    break;
                }
            }
            found
        };
        match dl {
            Some(dl) => {
                dl.set_paused(true).await;
                true
            }
            None => false,
        }
    }

    /// Resume ONE download (eMule 0.70b `ResumeFile`): flag off; the next
    /// resume sweep re-drives the fetch, subject to the max-active admission.
    /// Deliberately not an immediate spawn - the sweep already owns admission
    /// and source-finding, and a second spawn path would drift from it.
    pub async fn resume_download(&mut self, hash: [u8; 16]) -> bool {
        let dl = {
            let guard = self.downloads.lock().await;
            let mut found = None;
            for d in guard.iter() {
                if d.hash().await == hash {
                    found = Some(Arc::clone(d));
                    break;
                }
            }
            found
        };
        match dl {
            Some(dl) => {
                dl.set_paused(false).await;
                true
            }
            None => false,
        }
    }

    /// Set the max-active download cap (0 = unlimited). Takes effect on the
    /// next sweep: rows past the cap stop being driven and report QUEUED;
    /// raising it admits queued rows in add order. See
    /// `multi_source::queued_flags` - the one admission rule.
    pub fn set_max_active_downloads(&mut self, n: u32) {
        self.max_active.store(n, Ordering::Relaxed);
    }

    /// Discover who has `hash`: the connected server (get_sources) AND Kad
    /// (resolve_sources) CONCURRENTLY, folding both into one registry so a
    /// serverless client still gets Kad sources and vice versa. Returns the
    /// registry plus the LowID source IPs worth a server callback (empty unless
    /// WE are HighID - a LowID cannot receive a callback).
    /// Find sources for `hash`, spending at most `budget` on it.
    ///
    /// The budget bounds EACH arm rather than the whole call, which is the
    /// difference between "best effort" and "all or nothing". The old shape
    /// wrapped this function in an outer `timeout` at the call site: since the
    /// two arms are joined (the wait is the SLOWER of the two, not the sum), a
    /// slow Kad lookup made the outer timeout fire and threw away the server's
    /// answer - which had arrived in well under a second. Resume therefore only
    /// worked when Kad was BROKEN. Bounding per-arm means whatever arrived in
    /// time is always used, and the caller never has to discard a good result.
    /// `stop_when_server_answers` makes the budget a CEILING instead of a fixed
    /// cost. `join!` waits for BOTH arms, and a Kad lookup essentially always
    /// uses its whole budget, so every call cost the full amount even when the
    /// server had already answered in under a second - traced live as
    /// `found=1 ... took=6.001s`. That is what made the retry sweep expensive
    /// enough to need a duty-cycle cap, since it runs under the engine lock.
    ///
    /// ALL THREE production callers now pass `true` (`add_download`,
    /// `resume_fetches`, `maintain_resume_fetches`). The two resume paths always
    /// did - getting SOME sources now beats getting more in six seconds.
    ///
    /// KNOWN COST, not yet measured: the fast path returns on the first NON-EMPTY
    /// server answer, so Kad is skipped entirely whenever the server names even
    /// one source. The latency win is measured (~200ms vs ~15s); the narrower
    /// source pool is not, and it sits directly against the open question of why
    /// downloads run short of live sources. A count threshold, or letting the Kad
    /// arm land into the mid-sweep source channel `take_sx_sources` already
    /// provides, would keep both - see the handoff.
    ///
    /// `add_download` passed `false` until 2026-08-04, justified as "the user is
    /// watching a spinner for that one file and wants the widest net". That was
    /// REASONING, not measurement, and Anthony reported the consequence: every
    /// Get cost a flat ~15s. The measurement had already been taken on the retry
    /// path and pointed the other way - 195ms instead of 6.001s, 16 of 16
    /// retries sub-second. The widest net is worth little if it is cast 15
    /// seconds late, under the engine lock, once per queued file.
    async fn find_sources(
        &mut self,
        hash: [u8; 16],
        size: u64,
        budget: Duration,
        stop_when_server_answers: bool,
    ) -> (SourceRegistry, Vec<u32>) {
        let low_id = self.connection.as_ref().map(|c| c.low_id).unwrap_or(true);
        // The two lookups touch disjoint fields (server link vs Kad node), so
        // run them together; the wait is the slower of the two, not the sum.
        // FAST PATH: ask the server alone first. It answers in well under a
        // second when it answers at all, so a retry that gets what it needs
        // returns immediately instead of waiting out Kad.
        if stop_when_server_answers {
            let found = match self.server.as_mut() {
                Some(link) => link
                    .get_sources(&hash, size, budget.min(SOURCES_WAIT))
                    .await
                    .unwrap_or_default(),
                None => Vec::new(),
            };
            // NOT `!found.is_empty()`. The gate has to be on sources we can
            // actually DIAL, because a server answer is not the same thing as a
            // usable one: `PeerSource::from_found` drops every LowID source (it
            // cannot accept our connection), so a hash whose swarm is mostly
            // LowID answers with a healthy-looking count and yields almost
            // nothing to dial. Observed live 2026-08-05 - a file whose search row
            // read "15 srcs (14 full)" sat at Zero KB while five siblings ran at
            // hundreds of KB/s, and Kad was skipped for it on the strength of
            // that non-empty answer.
            let dialable = found
                .iter()
                .filter(|s| crate::fetch::PeerSource::from_found(s).is_some())
                .count();
            if dialable >= MIN_DIALABLE_TO_SKIP_KAD {
                return self.registry_from(found, low_id, &[]);
            }
            // Too thin to fill even one download's worker pool, so the Kad wait
            // costs nothing we would have been using. Keep the server's answer
            // and ADD Kad to it rather than falling through, which would re-ask
            // the server for something we are already holding.
            let kad_sources = match self.kad.as_mut() {
                Some(node) => timeout(
                    budget.min(KAD_SEARCH_WAIT),
                    node.resolve_sources(&Kad128::from_hash(&hash), size, 20, KAD_PER_QUERY),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .map(|o| o.sources)
                .unwrap_or_default(),
                None => Vec::new(),
            };
            return self.registry_from(found, low_id, &kad_sources);
        }
        let server = self.server.as_mut();
        let kad = self.kad.as_mut();
        let (found, kad_sources) = tokio::join!(
            async {
                match server {
                    Some(link) => link
                        .get_sources(&hash, size, budget.min(SOURCES_WAIT))
                        .await
                        .unwrap_or_default(),
                    None => Vec::new(),
                }
            },
            async {
                match kad {
                    // Bounded like the search path: a slow lookup contributes
                    // nothing rather than hanging the Get.
                    Some(node) => timeout(
                        budget.min(KAD_SEARCH_WAIT),
                        node.resolve_sources(&Kad128::from_hash(&hash), size, 20, KAD_PER_QUERY),
                    )
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .map(|o| o.sources)
                    .unwrap_or_default(),
                    None => Vec::new(),
                }
            }
        );
        self.registry_from(found, low_id, &kad_sources)
    }

    /// Build the registry + LowID callback list from raw arm results. Shared by
    /// the full path and the server-first fast path so the ipfilter gate and the
    /// LowID rule cannot drift apart between them.
    fn registry_from(
        &self,
        found: Vec<crate::FoundSource>,
        low_id: bool,
        kad_sources: &[mule_kad::Source],
    ) -> (SourceRegistry, Vec<u32>) {
        let mut reg = SourceRegistry::new();
        reg.add_found(&found);
        reg.add_kad(kad_sources);
        // Never dial a blocklisted peer. LowID callback sources are gated on the
        // inbound side instead (they dial US), so only direct sources are dropped
        // here.
        if let Some(filter) = &self.ip_filter {
            reg.drop_blocked(|addr| match addr {
                SocketAddr::V4(v4) => filter.is_blocked(*v4.ip()),
                SocketAddr::V6(_) => false,
            });
        }
        // A LowID source cannot accept our connection; the server has to poke it
        // for us. Only worth asking if WE are reachable - a LowID asking a LowID
        // to call back is the one case eD2k simply cannot route.
        let lowids: Vec<u32> = if low_id {
            Vec::new()
        } else {
            found
                .iter()
                .filter(|s| s.ip != 0 && s.ip < 0x0100_0000 && s.port != 0)
                .map(|s| s.ip)
                .collect()
        };
        (reg, lowids)
    }

    /// Ask the server to poke each LowID source so it dials our listener.
    async fn request_callbacks(&mut self, lowids: &[u32]) {
        for id in lowids {
            if let Some(link) = self.server.as_mut() {
                let _ = link.request_callback(*id).await;
            }
        }
    }

    /// Spawn the transfer task for an already-registered download: pull from
    /// `sources`, then verify + save on completion (or bail if cancelled).
    fn spawn_fetch(
        &self,
        dl: Arc<Download>,
        hash: [u8; 16],
        size: u64,
        name: &str,
        sources: Vec<PeerSource>,
    ) {
        // One live fetch task per download: skip if one is already running. pause()
        // does not abort in-flight tasks, so without this resume()/resume_fetches
        // would stack a duplicate download_file every background/foreground cycle,
        // multiplying outbound peer connections.
        if !dl.try_begin_fetch() {
            // Counted: a `fetching` flag that never clears makes the retry sweep
            // skip this download for the rest of the process, which is one of
            // the two in-memory gates that a restart silently repairs.
            crate::stats::note_fetch_busy();
            return;
        }
        // Advertise SecureIdent v1 in the fetch HELLO so a source will initiate
        // the exchange toward us; pass our RSA identity so we can respond + verify.
        let me = self.hello_baseline().with_secident();
        let identity = Arc::clone(&self.identity.rsa);
        let credit_store = Arc::clone(&self.credit_store);
        // Sources learned mid-sweep via source exchange are filtered too.
        let ip_filter = self.ip_filter.clone();
        let dest = self.downloads_dir.join(safe_filename(name));
        let events = self.events.clone();
        let ctx = FinishCtx {
            registry: Arc::clone(&self.downloads),
            shared: Arc::clone(&self.shared),
            shared_dirty: Arc::clone(&self.shared_dirty),
            config_dir: self.config_dir.clone(),
            known_met_lock: Arc::clone(&self.known_met_lock),
            known2: Arc::clone(&self.known2),
            events: events.clone(),
        };
        let dl_task = dl;
        tokio::spawn(async move {
            // Release the in-flight fetch slot however this task exits.
            let _fetch_guard = FetchGuard(Arc::clone(&dl_task));
            // ByPriority: the sweep reads dl.priority() live each round, so a
            // priority change on this download while it is fetching takes effect.
            let cfg = ManagerConfig::ByPriority {
                per_peer: Duration::from_secs(45),
            };
            download_file(
                &dl_task,
                &sources,
                &me,
                cfg,
                Some(identity),
                Some(credit_store),
                ip_filter,
            )
            .await;
            // Cancelled while in flight: the engine already removed it and deleted
            // the .part. Do NOT finish or emit - there is nothing to save.
            if dl_task.is_cancelled() {
                return;
            }
            let total = dl_task.size().await;
            let have = total - dl_task.missing().await;
            let _ = events.send(EngineEvent::Progress { hash, have, total });
            if dl_task.is_complete().await && dl_task.try_begin_finalize() {
                finish_download(dl_task, ctx, hash, size, dest).await;
            }
        });
    }

    /// Re-drive downloads resumed from disk by `start()`. Each was registered but
    /// had NO transfer task, so it progressed only if a called-back peer happened
    /// to dial our listener; this finds fresh sources and spawns the fetch, the
    /// same pipeline `add_download` uses. Best-effort: a resumed download with no
    /// sources right now stays registered and idle (a later run may find some).
    async fn resume_fetches(&mut self) {
        let cap = self.max_active.load(Ordering::Relaxed);
        let pending: Vec<Arc<Download>> = {
            let guard = self.downloads.lock().await;
            // The ONE admission rule (multi_source::queued_flags): user-paused
            // rows are never driven, and past the max-active cap the rest are
            // QUEUED - reported, not driven; a freed slot admits the next in
            // add order on this very sweep, no event needed (a row actively
            // receiving keeps its slot first).
            let now = u64::from(now_secs());
            let mut rows = Vec::with_capacity(guard.len());
            for dl in guard.iter() {
                rows.push(dl.admission_row(now).await);
            }
            let queued = crate::multi_source::queued_flags(cap, &rows);
            let mut v = Vec::new();
            for (i, dl) in guard.iter().enumerate() {
                let (paused, complete, _receiving) = rows[i];
                // Skip ones already being fetched: pause() does not abort in-flight
                // tasks, so a still-running fetch must not be re-driven (spawn_fetch
                // would bail anyway, but this also avoids wasted source-finding under
                // the engine lock).
                if !complete && !paused && !queued[i] && !dl.is_cancelled() && !dl.is_fetching() {
                    v.push(Arc::clone(dl));
                }
            }
            // High priority first, so under the resume budget the downloads the
            // user cares most about get their sources found before it runs out.
            v.sort_by_key(|dl| std::cmp::Reverse(dl.priority()));
            v
        };
        // Bound the whole pass: start() holds the FFI engine lock for its whole
        // duration, so a batch of dead downloads (each up to KAD_SEARCH_WAIT in
        // find_sources) must not stall startup and delay pause(). Downloads not
        // reached stay registered + idle (best-effort, as documented) and fetch
        // via an inbound callback or the next start.
        let deadline = tokio::time::Instant::now() + RESUME_BUDGET;
        for dl in pending {
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            let hash = dl.hash().await;
            let size = dl.size().await;
            let name = dl.name().await;
            // Bounded INSIDE find_sources, so a slow Kad arm no longer throws
            // away the server sources that already arrived.
            let (reg, lowids) = self.find_sources(hash, size, RESUME_PER_DL, true).await;
            if reg.is_empty() && lowids.is_empty() {
                continue;
            }
            dl.note_source_pool(reg.sources().len(), lowids.len());
            self.request_callbacks(&lowids).await;
            self.spawn_fetch(dl, hash, size, &name, reg.sources().to_vec());
        }
    }

    /// Cancel and remove an in-progress download, deleting its `.part` files.
    /// Returns false if no download with that hash is active (already finished,
    /// or never started). The fetch workers stop within a block of `cancel()`,
    /// and the outer task then bails without saving.
    pub async fn cancel_download(&mut self, hash: [u8; 16]) -> bool {
        let mut guard = self.downloads.lock().await;
        let mut found = None;
        for (i, dl) in guard.iter().enumerate() {
            if dl.hash().await == hash {
                found = Some(i);
                break;
            }
        }
        let Some(i) = found else {
            return false;
        };
        let dl = guard.remove(i);
        drop(guard);
        dl.cancel();
        dl.discard_files().await;
        let name = dl.name().await;
        self.emit(EngineEvent::Server(format!("Removed '{name}'")));
        true
    }

    /// Stop serving one shared file, keeping the file itself on disk. Removes it
    /// from the live library AND from `known.met`, so it does not re-share on the
    /// next start. Returns false if we were not sharing that hash.
    pub async fn unshare_file(&mut self, hash: [u8; 16]) -> bool {
        let removed_root = {
            let mut guard = self.shared.lock().await;
            let before = guard.len();
            let root = guard
                .iter()
                .find(|s| s.hash == hash)
                .and_then(|s| s.aich_root);
            guard.retain(|s| s.hash != hash);
            (before != guard.len()).then_some(root)
        };
        let removed = removed_root.is_some();
        if let Some(root) = removed_root {
            let _g = self.known_met_lock.lock().await;
            forget_shared_file(&self.config_dir, hash);
            // An unshared file's AICH hashset leaves the store with it.
            if let Some(r) = root {
                self.known2.remove(&r);
            }
            self.emit(EngineEvent::Server("Stopped sharing a file".into()));
        }
        removed
    }

    /// Set a download's priority (Low/Normal/High). Persisted to part.met and
    /// read live by the running fetch sweep, so a higher priority contacts more
    /// sources at once (and, after a restart, is re-driven first). An unknown
    /// value is clamped to Normal. Returns false if we hold no such download.
    pub async fn set_download_priority(&mut self, hash: [u8; 16], priority: u8) -> bool {
        let priority = match priority {
            crate::part_store::PR_LOW | crate::part_store::PR_HIGH => priority,
            _ => crate::part_store::PR_NORMAL,
        };
        let dl = {
            let guard = self.downloads.lock().await;
            let mut found = None;
            for d in guard.iter() {
                if d.hash().await == hash {
                    found = Some(Arc::clone(d));
                    break;
                }
            }
            found
        };
        match dl {
            // A complete download is a no-op: its priority is moot, and skipping
            // the persist keeps set_priority's blocking save_met from racing
            // finish_download's Arc::try_unwrap (which would strand the finished
            // file until the next start).
            Some(d) if !d.is_complete().await => {
                d.set_priority(priority).await;
                true
            }
            Some(_) => true,
            None => false,
        }
    }

    /// Find an active download by hash (clones the Arc).
    async fn find_download(&self, hash: [u8; 16]) -> Option<Arc<Download>> {
        let guard = self.downloads.lock().await;
        for d in guard.iter() {
            if d.hash().await == hash {
                return Some(Arc::clone(d));
            }
        }
        None
    }

    /// Turn preview mode on/off for the download with `hash`: first+last-then-
    /// sequential block bias, so the file grows contiguously from the start and
    /// can be played while still incomplete. False if no active download matches.
    pub async fn set_preview(&mut self, hash: [u8; 16], on: bool) -> bool {
        match self.find_download(hash).await {
            Some(d) => {
                d.set_preview(on);
                true
            }
            None => false,
        }
    }

    /// The `(part_path, contiguous_prefix)` a preview snapshot needs for `hash`, or
    /// None if there is no such active download or nothing contiguous is available
    /// yet. The caller copies the prefix OUTSIDE the engine lock (see the FFI), so
    /// a large copy never stalls the 1s heartbeat or the download.
    pub async fn preview_target(&self, hash: [u8; 16]) -> Option<(std::path::PathBuf, u64)> {
        self.find_download(hash).await?.preview_target().await
    }

    /// Set the local user's own rating (0-5, 0 = none) and comment on a file we
    /// share. Updates the live library AND `known.met`, so it survives a restart
    /// and is served to downloaders via OP_FILEDESC (when they accept comments).
    /// Rating is clamped to 5 and the comment to MAX_FILE_COMMENT_LEN chars, so
    /// what we store is exactly what goes on the wire. Returns false if we do not
    /// share that hash.
    pub async fn set_file_rating(&mut self, hash: [u8; 16], rating: u8, comment: String) -> bool {
        let rating = rating.min(5);
        let comment: String = comment
            .chars()
            .take(crate::transfer::MAX_FILE_COMMENT_LEN)
            .collect();
        let updated = {
            let mut guard = self.shared.lock().await;
            match guard.iter_mut().find(|s| s.hash == hash) {
                Some(sf) => {
                    sf.rating = rating;
                    sf.comment = comment.clone();
                    true
                }
                None => false,
            }
        };
        if updated {
            let _g = self.known_met_lock.lock().await;
            update_shared_file_meta(&self.config_dir, hash, rating, &comment);
            self.emit(EngineEvent::Server("Updated a file rating".into()));
        }
        updated
    }

    /// App backgrounded: checkpoint to disk and release sockets. Idempotent - a
    /// no-op unless currently `Running`. `Running` -> `Paused`.
    pub async fn pause(&mut self) {
        if self.state != EngineState::Running {
            return;
        }
        // Release the sockets ourselves rather than let iPadOS reclaim them
        // out from under us - that is what makes resume predictable.
        if let Some(s) = &mut self.server {
            s.pause().await;
        }
        // `set_kad` folds the live table into the persisted one before dropping
        // the node - load-bearing, because `checkpoint()` below runs AFTER this
        // and would otherwise write the stale bootstrap-time snapshot, losing
        // every contact and verify key the session learned. Socket release still
        // happens first, as the comment above intends.
        self.set_kad(None);
        if let Some(h) = self.listener.take() {
            h.abort(); // release TCP 4662; resume() rebinds it
        }
        // Flush download progress to disk BEFORE we may be suspended/killed: the
        // hot receive path only fills the in-memory gap list, so without this a
        // background-kill would lose all session progress and re-download from
        // scratch. iPadOS calls pause() on .background, so this is the boundary.
        self.persist_downloads().await;
        self.checkpoint();
        self.emit(EngineEvent::Status("Paused".into()));
        self.set_state(EngineState::Paused);
    }

    /// Background WITHOUT going quiet: keep serving what we already have.
    ///
    /// The difference from [`pause`](Self::pause), which is the whole feature:
    /// the inbound listener and the server login STAY UP, so peers can keep
    /// downloading from us and the server keeps handing us out as a source.
    /// Everything that INITIATES user-facing work stops -
    /// `maintain_resume_fetches` / `maintain_kad` / `maintain_share_verify`
    /// gate on `Running`, so they fall silent for free.
    ///
    /// WHY SEEDING IS THE PART WORTH KEEPING ALIVE. It is the cheapest thing
    /// the engine does - no source hunting, no lookups, no block scheduling -
    /// and on eD2k it is what earns standing: the credit system rewards upload,
    /// so a client that only ever takes is one every queue puts last.
    ///
    /// KAD STAYS UP (DECIDED 2026-08-09, reversing the launch behaviour that
    /// dropped it here). Since publishing shipped (row 8de) a seeding session
    /// has real Kad duties: `maintain_kad_publish` admits Seeding and keeps
    /// the 5h/24h source/keyword records fresh at the storing nodes, and the
    /// node's read loop keeps answering the network, so we are not aged out
    /// of other nodes' routing tables and a resume no longer rebuilds the
    /// live table from one bootstrap response. The same audio keepalive that
    /// keeps the TCP listener and the server login alive (row 8cj) keeps this
    /// UDP socket schedulable - suspension is what kills sockets, and the
    /// keepalive's whole job is preventing it. What `set_kad(None)` was ALSO
    /// doing here - folding the live table into the persisted one - is kept
    /// below, without the teardown. The maintenance split while seeding
    /// (liveness sweep on, growth refresh off) is decided and argued at the
    /// `maintain_kad_liveness` / `maintain_kad` gates.
    ///
    /// THIS ONLY MEANS ANYTHING UNDER AN AUDIO KEEPALIVE. Without one iOS
    /// suspends the process seconds later and every socket here dies with it -
    /// so the caller must have the keepalive running BEFORE calling this, and
    /// must fall back to `pause()` when it cannot. Being jetsam-killed remains
    /// possible at any moment, which is why this still persists and checkpoints
    /// on the way in.
    pub async fn pause_for_seeding(&mut self) {
        if self.state != EngineState::Running {
            return;
        }
        // Fold the live table into the persisted one WITHOUT dropping the node
        // - the same discipline `set_kad` makes unforgettable, minus the
        // teardown. `checkpoint` below unions the live table into nodes.dat by
        // itself, but `self.routing` must be current too or a later
        // node-dropping path would write a stale union.
        self.absorb_kad_routing();
        // Persist NOW rather than trusting the background to last: jetsam can
        // take the process at any moment and gives no warning.
        self.persist_downloads().await;
        self.checkpoint();
        self.emit(EngineEvent::Status("Sharing in the background".into()));
        self.set_state(EngineState::Seeding);
    }

    /// Come back to the foreground from [`pause_for_seeding`].
    ///
    /// Much smaller than `resume()` because almost nothing was torn down: the
    /// listener, the server link AND (since 2026-08-09) the Kad node all
    /// survive a seed. Calling the full `resume()` here would abort a LIVE
    /// listener and re-dial a server we are still logged into - and an
    /// unconditional `start_kad` would bind a second UDP socket, or replace a
    /// live table with a bootstrap-sized one. Kad is rebuilt only when the
    /// seed was entered without a node (offline, or a failed bind).
    async fn resume_from_seeding(&mut self) {
        self.set_state(EngineState::Running);
        if !self.offline && self.kad.is_none() {
            self.start_kad().await;
        }
        self.emit_online_status();
    }

    /// App foregrounded: rebuild sockets, reconnect, re-bootstrap. Idempotent - a
    /// no-op unless currently `Paused`. `Paused` -> `Running`. The real reconnect
    /// (listener rebind, server link, Kad) runs between the two status lines.
    pub async fn resume(&mut self) {
        // Coming back from a background SEED is a different, much smaller job -
        // see `resume_from_seeding`. Routed here so callers keep one entry point.
        if self.state == EngineState::Seeding {
            self.resume_from_seeding().await;
            return;
        }
        if self.state != EngineState::Paused {
            return;
        }
        // The banner goes up BEFORE the work, so the UI is honest while we wait.
        self.emit(EngineEvent::Status("Reconnecting...".into()));
        self.set_state(EngineState::Running);

        if !self.offline {
            // Rebind the inbound port first - same HighID reason as start().
            self.start_listener().await;
            // Re-run the handshake on the existing link, or find a new server if
            // we never had one (or the old one is gone). Correct across an IP
            // change, which is the whole point on a mobile device.
            // Captured inside the &mut self.server borrow, applied after it ends.
            let mut new_public_id: Option<(u32, bool)> = None;
            let resumed = match &mut self.server {
                Some(s) => match timeout(Duration::from_secs(12), s.resume()).await {
                    Ok(Ok(ServerState::Connected {
                        id,
                        low_id,
                        related_search,
                    })) => {
                        new_public_id = Some((id, low_id));
                        // Re-record: the ID can flip across an IP change, which
                        // is exactly what resume() exists to survive. The server's
                        // related-search capability comes back on the fresh
                        // IDCHANGE too.
                        if let Some(c) = &mut self.connection {
                            c.low_id = low_id;
                            c.related_search = related_search;
                        }
                        // A resume is a FRESH login, and the ask lives in the
                        // authorities' ConnectionEstablished - which runs on
                        // every reconnect. Re-ask here too.
                        if self.add_servers_from_server {
                            let _ = s.request_server_list().await;
                        }
                        true
                    }
                    _ => false,
                },
                None => false,
            };
            if let Some((id, low_id)) = new_public_id {
                // Same guard as connect_to_server: a resume is a FRESH login, and
                // a resume is exactly when a tunnel is most likely to have gone.
                self.note_public_id(id, low_id);
            }
            if !resumed {
                // The server we were on did not come back. Do NOT auto-pick
                // another (eMule does not either); drop it and let the user
                // reconnect from the Servers screen. If we had no server, this is
                // a no-op - resume stays serverless.
                self.server = None;
                self.connection = None;
                self.search_session = None;
            }
            self.start_kad().await;
            // Re-drive in-progress downloads: while suspended, iPadOS reclaimed the
            // peer sockets, so the one-shot fetch tasks ended. Without this a
            // download is byte-frozen after any background/foreground cycle. start()
            // does the same via resume_fetches (this closes the start()-vs-resume()
            // asymmetry the audit found).
            self.resume_fetches().await;
            // Re-announce our shared library on the fresh login: the server dropped
            // our offers when the old connection died.
            if resumed {
                self.shared_dirty.store(true, Ordering::Relaxed);
            }
            self.refresh_port_mapping();
        }

        self.emit_online_status();
    }

    /// Re-verify the UPnP port mapping after a foreground return, eMule's
    /// `CheckAndRefresh` (see `upnp::refresh_mapping` for the citations - eMule
    /// runs it on resume from system suspend, among other triggers).
    ///
    /// padMule mapped the port ONCE per launch and never looked again, so a
    /// mapping lost while suspended - router reboot, lease change, or our own DHCP
    /// address moving - left it silently LowID for the whole session with the
    /// Status row still reading "mapped".
    ///
    /// SPAWNED, not awaited: discovery plus SOAP costs seconds, and resume() is on
    /// the path the user waits behind every time they switch back to the app. The
    /// result reaches the UI as the same durable "UPnP:" row that start() writes,
    /// so a change still surfaces - just a moment later.
    fn refresh_port_mapping(&self) {
        let action = port_mapping_action(
            self.state == EngineState::Running && self.upnp_enabled,
            self.offline,
            self.has_port_mapping(),
        );
        if action == MappingAction::None {
            return;
        }
        let events = self.events.clone();
        let public_ip = self.public_ip.clone();
        let port = self.listen_port;
        tokio::spawn(async move {
            let msg = match action {
                MappingAction::Refresh => {
                    match crate::upnp::refresh_and_remap(port, "padMule").await {
                        // Silent on the common case: saying "still mapped" every
                        // time the user switches apps is noise, and the row
                        // already says it.
                        Ok(crate::upnp::RefreshOutcome::Intact) => return,
                        Ok(crate::upnp::RefreshOutcome::Remapped) => {
                            format!("UPnP: re-mapped port {port} after resume")
                        }
                        Err(e) => {
                            // STOP CLAIMING A MAPPING WE JUST FAILED TO CONFIRM.
                            // `public_ip` is documented as "set only on a
                            // successful map and cleared when the mapping is
                            // released", and `has_port_mapping()` is exactly
                            // that Option being Some - so leaving it set after a
                            // failed refresh makes the Status row keep saying
                            // "mapped" for a port that may no longer be
                            // forwarded, which is the very failure the doc above
                            // this function describes. It also stops the Kad
                            // verify-key echo minting keys against an address
                            // we can no longer vouch for. Clearing is
                            // self-healing rather than pessimistic: the next
                            // trigger sees no mapping and takes the Map retry
                            // arm below.
                            if let Ok(mut g) = public_ip.lock() {
                                *g = None;
                            }
                            format!("UPnP: could not refresh port {port} ({e})")
                        }
                    }
                }
                // The RETRY: start()'s attempt failed, so try again on the very
                // triggers that exist to recover a missing mapping. Silent on a
                // repeated failure - a user with no UPnP gateway would otherwise
                // get the same line on every foreground return.
                MappingAction::Map => {
                    match crate::upnp::map_port(port, "padMule", crate::upnp::PERMANENT_LEASE).await
                    {
                        Ok(ip) => {
                            if let Ok(mut g) = public_ip.lock() {
                                *g = Some(ip);
                            }
                            format!("UPnP: mapped port {port} on retry")
                        }
                        Err(_) => return,
                    }
                }
                MappingAction::None => return,
            };
            let _ = events.send(EngineEvent::Server(msg));
        });
    }

    /// A DELIBERATE stop: disconnect, release every socket, flush, give the port
    /// back to the gateway, and land in `Stopped`. Safe from any state, and
    /// restartable in place with `start()`.
    ///
    /// This is the closest honest analogue of eMule's Exit. iOS has no app-quit
    /// the app may invoke, so the user still closes padMule from the app
    /// switcher - but doing it AFTER this leaves nothing behind.
    ///
    /// It used to checkpoint and set the state while leaving TCP 4662 bound, the
    /// Kad UDP socket open and the port mapping in place, which is not a stop in
    /// any sense the user would recognise.
    pub async fn shutdown(&mut self) {
        if let Some(mut link) = self.server.take() {
            link.disconnect().await;
        }
        self.connection = None;
        self.search_session = None;
        // Same ordering rule as pause(): fold the live table in BEFORE the node
        // is dropped, or the checkpoint below writes a stale snapshot.
        self.set_kad(None);
        if let Some(h) = self.listener.take() {
            h.abort();
        }
        self.persist_downloads().await;
        self.checkpoint();
        self.release_port_mapping().await;
        self.emit(EngineEvent::Status("Stopped".into()));
        self.set_state(EngineState::Stopped);
    }

    /// Hand the forwarded port back on a deliberate stop.
    ///
    /// BOTH authorities do this and padMule never did: eMule deletes its ports on
    /// exit when `CloseUPnPOnExit` is set, which DEFAULTS TO TRUE
    /// (`Preferences.cpp:2501`, `emuleDlg.cpp:1817-1819`), and aMule deletes
    /// unconditionally (`amule.cpp:1747-1751`). Leaving a PERMANENT mapping behind
    /// is exactly how one outlived this device's DHCP address and stranded the
    /// port until a human cleared it by hand - a mapping can only be deleted by
    /// the address that owns it, so the moment our address changes it is too late.
    ///
    /// Awaited rather than spawned: the user asked to stop, so it is honest to
    /// finish the work (and report a failure) before saying we did.
    async fn release_port_mapping(&mut self) {
        if self.offline || !self.has_port_mapping() {
            return;
        }
        let port = self.listen_port;
        match crate::upnp::unmap_port(port).await {
            Ok(()) => {
                if let Ok(mut g) = self.public_ip.lock() {
                    *g = None;
                }
                self.emit(EngineEvent::Server(format!("UPnP: released port {port}")));
            }
            // Non-fatal: the stop itself still succeeded, and saying so is more
            // useful than silence - a mapping left behind is what strands a port.
            Err(e) => self.emit(EngineEvent::Server(format!(
                "UPnP: could not release port {port} ({e})"
            ))),
        }
    }

    /// Flush every active download's `.part.met` (its gap list) so the progress
    /// made this session survives a suspend-kill. The hot receive path (`commit`)
    /// only fills the IN-MEMORY gaps, so this durability-boundary flush is what
    /// makes resume-from-disk actually resume instead of restarting at 0%.
    async fn persist_downloads(&self) {
        // Snapshot the Arcs, then drop the registry lock BEFORE the blocking
        // per-download writes, matching downloads()/finalize_completed - so pause()
        // does not hold the registry lock across every .part.met flush.
        let dls: Vec<Arc<Download>> = self.downloads.lock().await.clone();
        for dl in dls {
            dl.persist().await;
        }
    }

    /// Re-drive ONE download that has gone idle. The missing retry: `spawn_fetch`
    /// is otherwise only ever called from `start()`, `resume()` and
    /// `add_download`, and a fetch task that exhausts its round budget without
    /// finishing simply ends - so a download could be registered, incomplete,
    /// and permanently doing nothing while the UI showed it as a transfer.
    ///
    /// One per tick keeps the cost bounded; the oldest-idle-first ordering means
    /// a set of stalled downloads is worked through round-robin rather than the
    /// first one hogging every retry.
    pub async fn maintain_resume_fetches(&mut self) -> bool {
        if self.state != EngineState::Running || self.offline {
            return false;
        }
        // Cadence scales with the QUEUE: one retry per 45s total meant a file in
        // a queue of 9 waited ~7 minutes for rediscovery, and one in a queue of
        // 30 waited 22. Dividing by the idle count keeps the PER-FILE period
        // roughly constant as the queue grows, with a floor so a large queue
        // cannot turn the heartbeat into a discovery treadmill.
        let idle_count = {
            let guard = self.downloads.lock().await;
            guard
                .iter()
                .filter(|dl| !dl.is_cancelled() && !dl.is_fetching() && !dl.is_paused())
                .count() as u32
        };
        if idle_count == 0 {
            return false;
        }
        let gap = (RESUME_RETRY_EVERY / idle_count.clamp(1, RESUME_RETRY_SPREAD))
            .max(RESUME_RETRY_BUDGET * RESUME_RETRY_DUTY);
        if self.last_resume_retry.elapsed() < gap {
            return false;
        }
        // Nothing to do is the common case - check before paying for anything.
        // FAIR ROTATION, and this is a bug fix rather than a refinement. The old
        // selection sorted by priority and took `.first()`; Rust's sort is
        // STABLE, so with every download at the same (Normal) priority it
        // returned the SAME download on every sweep and every other one was
        // never retried at all. With dozens queued that is not "slow", it is
        // "never" - which is exactly the "downloads stop or crawl" report.
        //
        // Now: highest priority first, and WITHIN a priority tier the one
        // retried longest ago. Priority still wins, but it can no longer starve
        // its own tier.
        let now = u64::from(now_secs());
        let cap = self.max_active.load(Ordering::Relaxed);
        let candidate: Option<Arc<Download>> = {
            let guard = self.downloads.lock().await;
            // Same admission rule as resume_fetches: paused and past-the-cap
            // rows are not retried (a queued row's turn comes when a slot
            // frees and queued_flags recomputes).
            let mut rows = Vec::with_capacity(guard.len());
            for dl in guard.iter() {
                rows.push(dl.admission_row(now).await);
            }
            let queued = crate::multi_source::queued_flags(cap, &rows);
            guard
                .iter()
                .enumerate()
                .filter(|(i, dl)| {
                    !rows[*i].0 && !queued[*i] && !dl.is_cancelled() && !dl.is_fetching()
                })
                .map(|(_, dl)| dl)
                .min_by_key(|dl| (std::cmp::Reverse(dl.priority()), dl.last_retry_at()))
                .map(Arc::clone)
        };
        self.last_resume_retry = Instant::now();
        if let Some(dl) = candidate.as_ref() {
            // Stamp on SELECTION, not on success: a download whose retry finds
            // no sources must still yield its turn, or it becomes the new
            // permanent winner and we are back to the same starvation.
            dl.mark_retried(now);
        }
        let Some(dl) = candidate else {
            return false;
        };
        if dl.is_complete().await {
            return false;
        }
        let hash = dl.hash().await;
        let size = dl.size().await;
        let name = dl.name().await;
        let (reg, lowids) = self
            .find_sources(hash, size, RESUME_RETRY_BUDGET, true)
            .await;
        if reg.is_empty() && lowids.is_empty() {
            return false;
        }
        dl.note_source_pool(reg.sources().len(), lowids.len());
        self.request_callbacks(&lowids).await;
        self.spawn_fetch(dl, hash, size, &name, reg.sources().to_vec());
        true
    }

    /// THE `OnSmallTimer` HALF of Kad maintenance, which padMule did not have
    /// until 2026-08-08: age contacts, probe the oldest due one in each bin,
    /// and REMOVE whoever failed to answer. `maintain_kad` below is the
    /// `OnBigTimer` half (a random-target lookup that GROWS the table); this is
    /// the half that shrinks it, and without it nothing was ever removed - a
    /// contact whose IP changed stayed as a lookup seed for the node's life and
    /// held its stale address against every other Kad ID under
    /// `MAX_CONTACTS_PER_IP`.
    ///
    /// Returns (probes sent, contacts removed).
    ///
    /// RUNS WHILE SEEDING TOO (decided 2026-08-09, when `pause_for_seeding`
    /// stopped dropping the node). A background seed keeps the node serving
    /// and publishing for hours, which is exactly when contacts die around
    /// it - and without the sweep nothing is EVER removed (a contact's type
    /// moves only here and in `set_alive`), so the serve pool
    /// (`closest_to_serving`, the contacts we hand OTHER nodes) fills with
    /// peers that answered once and died, and every publish walk seeds from
    /// them. The cost is small and bounded: at most KAD_SWEEP_MAX_PROBES (2)
    /// HELLOs per 60s pass, ~1.2s worst-case each under the engine lock. The
    /// GROWTH half (`maintain_kad`) deliberately stays Running-only - see its
    /// doc for the other side of the split. Flip the state predicate below if
    /// the device soak says otherwise.
    pub async fn maintain_kad_liveness(&mut self) -> (usize, usize) {
        if !matches!(self.state, EngineState::Running | EngineState::Seeding) || self.offline {
            return (0, 0);
        }
        if self.last_kad_sweep.elapsed() < KAD_SWEEP_EVERY {
            return (0, 0);
        }
        self.last_kad_sweep = Instant::now();
        let Some(kad) = self.kad.as_mut() else {
            return (0, 0);
        };
        let (sent, removed) = kad.run_liveness_sweep(KAD_SWEEP_MAX_PROBES).await;
        // PROPAGATE THE EVICTION INTO THE PERSISTED TABLE. `Engine::routing` is
        // monotonic and `checkpoint_contacts` folds it with the live one, so
        // without this the contact the sweep just killed is written back to
        // nodes.dat, re-imported next launch, re-blackholes its IP under
        // MAX_CONTACTS_PER_IP = 1, and restarts its 3-4 minute march every
        // session. No tombstone SET is needed and none is wanted: eMule's
        // routing zone is its only contact store and `WriteFile` samples it
        // directly, so a contact `OnSmallTimer` deleted cannot reach its
        // nodes.dat at all. Deleting from both stores reproduces that
        // structurally - and it keeps the inverse case working for free: a peer
        // that returns at a NEW address is re-learned by the ordinary gated
        // insert and persisted again, with no tombstone to outlive it.
        for id in &removed {
            self.routing.remove(id);
        }
        let removed = removed.len();
        // DELIBERATELY NO `EngineEvent::Kad` HERE. That variant carries a
        // CONTACT COUNT, and the KB's most expensive Kad bug was one UI field
        // written by two different measurements (build-progress 8ce: a live
        // count landing on top of a persisted one, diagnosed as a table being
        // thrown away and "fixed" as such). `Engine::kad_contacts()` already
        // polls the live table once a second, so an eviction shows up there on
        // its own - one field, one measurement. See the `an-event-is-not-state`
        // memory before adding a second writer.
        (sent, removed)
    }

    /// PUBLISH one due shared file / keyword to the Kad DHT (eMule's STORE half
    /// of Kad, which padMule never had - its shares were findable only through
    /// a connected server's index and source exchange). One job per pass, hours
    /// between republishes; see [`crate::kad_publish`] for the schedule and the
    /// decision to build a foreground-only publisher (records age out when we
    /// stop, so a publisher that vanishes leaves nothing stale for long).
    ///
    /// Runs while RUNNING or SEEDING and only while SHARING is on. The
    /// Seeding arm is LIVE since 2026-08-09: `pause_for_seeding` keeps the
    /// Kad node up, so a background seed keeps republishing on the 5h/24h
    /// clocks instead of letting its records age out at the storing nodes -
    /// which is the point of seeding Kad-visibly. (Before that date the node
    /// was dropped on the way in and this arm idled at the availability
    /// guard below.) SOURCE records need a reachable address, so they are
    /// gated on a known public identity (HighID); KEYWORD records make no
    /// reachability claim and publish either way.
    ///
    /// Returns how many nodes stored this job's record (0 when nothing was due).
    pub async fn maintain_kad_publish(&mut self) -> usize {
        if !matches!(self.state, EngineState::Running | EngineState::Seeding) || self.offline {
            return 0;
        }
        if !self.is_sharing() {
            return 0;
        }
        if self.last_kad_publish.elapsed() < KAD_PUBLISH_EVERY {
            return 0;
        }
        // KAD AVAILABILITY, checked BEFORE the cadence stamp and the refill.
        // `refill` stamps the republish clocks AT ENQUEUE, so a pass that
        // cannot publish must consume nothing: with these guards after the
        // stamp/refill/pop (as first shipped), a seeding session - which,
        // until the node started surviving `pause_for_seeding` (2026-08-09),
        // always had `kad: None` - burned its whole due set at one job per
        // 10s, marked "published", and nothing republished for up to 5h/24h
        // after returning to Running. Still reachable without seeding: any
        // Running pass before `start_kad`, or after a failed bind.
        if self.kad.as_ref().is_none_or(|k| k.contacts_known() == 0) {
            return 0; // no node, or nothing to walk from - bootstrap first
        }
        self.last_kad_publish = Instant::now();

        // Refill the schedule from the current library when it is idle. A
        // firewalled node (no public id) publishes keywords but not sources.
        let can_publish_source = self.last_public_id.is_some();
        let now = u64::from(now_secs());
        // (hash, size, name, keywords) for each shared file.
        let files: Vec<([u8; 16], u64, String, Vec<String>)> = {
            let shared = self.shared.lock().await;
            shared
                .iter()
                .map(|s| {
                    let name = String::from_utf8_lossy(&s.name).into_owned();
                    let words = mule_kad::kad_keywords(&name);
                    (s.hash, s.size, name, words)
                })
                .collect()
        };
        let schedule_input: Vec<([u8; 16], Vec<String>)> = files
            .iter()
            .map(|(h, _, _, words)| (*h, words.clone()))
            .collect();
        self.publish_schedule
            .refill(now, &schedule_input, can_publish_source);
        let Some(job) = self.publish_schedule.take_next() else {
            return 0;
        };
        // A job is popped - schedule state is consumed whatever happens next -
        // so THIS is the point that counts as a publish JOB on the Stats
        // panel. The gated and idle passes above count nothing, so the panel's
        // "0 jobs" reads "the duty never ran a job", which is the truth.
        crate::stats::note_kad_publish_job();

        let our_kad_id = self.identity.kad_id;
        let tcp_port = self.advertised_port;
        let udp_port = self.kad_advertised_port;
        // Availability was checked before the stamp; this re-borrow is only
        // for the &mut the publish calls need (nothing between can drop it).
        let Some(kad) = self.kad.as_mut() else {
            return 0;
        };

        let stored = match job {
            crate::kad_publish::PublishJob::Source(hash) => {
                let Some((_, size, _, _)) = files.iter().find(|(h, ..)| *h == hash) else {
                    return 0; // unshared between refill and now
                };
                let target = Kad128::from_hash(&hash);
                let entry = SourceEntry {
                    size: *size,
                    tcp_port,
                    udp_port: Some(udp_port),
                    crypt: KAD_PUBLISH_CRYPT_OPTIONS,
                };
                timeout(
                    KAD_PUBLISH_BUDGET,
                    kad.publish_source(&target, our_kad_id, entry, KAD_PER_QUERY),
                )
                .await
            }
            crate::kad_publish::PublishJob::Keyword { file, word } => {
                let Some((_, size, name, _)) = files.iter().find(|(h, ..)| *h == file) else {
                    return 0;
                };
                let target = kad_keyword_target(&word);
                let entry = KeywordEntry {
                    file_id: Kad128::from_hash(&file),
                    name: name.clone(),
                    size: *size,
                    // We are one complete source of our own shared file.
                    complete_sources: 1,
                    // eD2k file-type search term is optional; padMule does not
                    // publish it (the type is derivable from the extension in
                    // the filename, which IS published). Faithful to eMule's
                    // note that the format tag is no longer sent (Search.cpp).
                    file_type: String::new(),
                };
                timeout(
                    KAD_PUBLISH_BUDGET,
                    kad.publish_keyword(&target, &[entry], KAD_PER_QUERY),
                )
                .await
            }
        };
        // A timed-out publish is best-effort partial work, not an error; the
        // record republishes on its clock regardless.
        let stored = stored.unwrap_or(Ok(0)).unwrap_or(0);
        crate::stats::note_kad_publish_stored(stored as u64);
        stored
    }

    /// Refresh the Kad routing table: one bounded lookup toward a RANDOM target,
    /// which pulls in every contact the answering nodes name (the `OnBigTimer`
    /// half; `maintain_kad_liveness` above is the half that shrinks).
    ///
    /// This is the maintenance padMule never had. Without it the table was fed
    /// only by the bootstrap and by whatever a source lookup or keyword search
    /// happened to walk past, so it neither grew on purpose nor shed the dead -
    /// and Kad keyword search, whose quality is a direct function of how broad
    /// and well-spread that table is, stayed correspondingly thin. Both
    /// authorities run the equivalent on a timer (eMule
    /// `CRoutingZone::OnBigTimer`, aMule RoutingZone.cpp).
    ///
    /// A RANDOM target rather than our own ID on purpose: a self-lookup only
    /// ever deepens the region we already know best, while the keyspace a
    /// keyword search lands in is uniform. Successive random targets walk the
    /// whole space, which is the same effect eMule gets by refreshing each bin
    /// in turn.
    ///
    /// DELIBERATELY NOT RUN WHILE SEEDING, unlike the liveness sweep and the
    /// publisher (both admit Seeding since 2026-08-09, when the node started
    /// surviving `pause_for_seeding`). Growth buys search breadth -
    /// KAD_TABLE_TARGET exists for keyword-search quality - and a seeding
    /// session never searches; meanwhile this is the most expensive periodic
    /// Kad duty (a full iterative lookup, up to KAD_MAINTENANCE_BUDGET under
    /// the engine lock, every KAD_REFRESH_EVERY) in the one mode where
    /// battery is the open question (row 8cj's unexplained CPU split). The
    /// table still learns while seeding without it: every publish answer is
    /// absorbed (`absorb_find_answer`) and every inbound HELLO_REQ is a
    /// proven-alive insert. Flip the state predicate below if the device
    /// soak says otherwise.
    ///
    /// Returns contacts gained, for the caller's log and for tests.
    pub async fn maintain_kad(&mut self) -> usize {
        if self.state != EngineState::Running || self.offline {
            return 0;
        }
        if self.last_kad_refresh.elapsed() < KAD_REFRESH_EVERY {
            return 0;
        }
        self.last_kad_refresh = Instant::now();
        let Some(kad) = self.kad.as_mut() else {
            return 0;
        };
        // Nothing to walk from - the bootstrap has to land first.
        if kad.contacts_known() == 0 || kad.contacts_known() >= KAD_TABLE_TARGET {
            return 0;
        }
        let mut bytes = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
        let target = Kad128::from_hash(&bytes);
        let before = kad.contacts_known();
        // AN OUTER DEADLINE on top of the refresh's own. `refresh_routing`
        // runs its event-driven lookup to a deadline of
        // REFRESH_DEADLINE_QUERIES x KAD_PER_QUERY, and this runs under the
        // engine lock via `heartbeat()`. Every OTHER Kad call site already
        // wraps in a timeout (search, find_sources); this one did not, and it
        // was the only periodic one. Row 8bx treated a 15s lock hold as a real
        // defect. The refresh normally finishes inside its own deadline, so
        // this is the net and not the knife.
        //
        // Partial work is KEPT: `add_contact` mutates the table as answers
        // arrive, so a cancelled pass still leaves everything it learned. The
        // gain is measured from the table itself rather than taken from the
        // return value, which a timed-out pass never produces.
        let _ = timeout(
            KAD_MAINTENANCE_BUDGET,
            kad.refresh_routing(&target, KAD_PER_QUERY),
        )
        .await;
        let total = kad.contacts_known();
        let gained = total.saturating_sub(before);
        if gained > 0 {
            let _ = self.events.send(EngineEvent::Kad { contacts: total });
        }
        gained
    }

    /// Periodically drop shared files the user deleted (see
    /// `verify_shared_library`). Runs off the same 1s heartbeat as the other
    /// maintainers, gated to `SHARE_VERIFY_EVERY`.
    pub async fn maintain_share_verify(&mut self) -> u32 {
        if self.state != EngineState::Running
            || self.last_share_verify.elapsed() < SHARE_VERIFY_EVERY
        {
            return 0;
        }
        self.last_share_verify = Instant::now();
        self.verify_shared_library().await
    }

    /// Re-checkpoint periodically while RUNNING, so a kill that never reaches
    /// `pause()` does not cost the whole session.
    ///
    /// A DELIBERATE DEVIATION from both authorities, flagged as such: eMule and
    /// aMule each write `nodes.dat` only from `CRoutingZone`'s DESTRUCTOR
    /// (RoutingZone.cpp:137-142 and :118-123 respectively) - i.e. on a clean
    /// exit, never on a timer. That is sound for a desktop app that gets to run
    /// its destructors. iPadOS does not offer that: the app is killed at
    /// suspension as ROUTINE behavior, and `pause()` only runs if `.background`
    /// is actually delivered first. So the platform, not the protocol, is the
    /// reason - and nothing here touches the wire or the file FORMAT.
    ///
    /// Driven by the same 1s `heartbeat()` as the other background
    /// duties, and gated on elapsed time so all but one call in 300 is a clock
    /// comparison.
    pub async fn maintain_checkpoint(&mut self) {
        if self.state != EngineState::Running || self.last_checkpoint.elapsed() < CHECKPOINT_EVERY {
            return;
        }
        // Progress first: a half-finished download is the costliest thing to lose
        // and the hot receive path only updates the IN-MEMORY gap list.
        self.persist_downloads().await;
        self.checkpoint();
        self.last_checkpoint = Instant::now();
    }

    /// Refresh the status values that are DERIVED rather than set once.
    ///
    /// `kad_contacts` walks a routing table and the login is a function of TWO
    /// fields (`server`'s connected state and `connection`), so unlike the flags
    /// neither can simply be published at one write site. Driven from the
    /// heartbeat, which already holds the lock, so the published value is at most
    /// one beat stale and costs no extra locking - and every connect / disconnect
    /// / drop / pause path calls this directly, so the common cases are exact
    /// rather than merely eventual.
    pub fn publish_status(&self) {
        self.status
            .kad_contacts
            .store(self.kad_contacts(), Ordering::Relaxed);
        if let Ok(mut g) = self.status.server.lock() {
            *g = self.server_info();
        }
    }

    /// Install or clear the live Kad node, absorbing whatever the OUTGOING node
    /// learned first.
    ///
    /// EVERY assignment to `self.kad` goes through here on purpose. The rule
    /// "fold the live table in before you drop the node" was previously a thing
    /// each call site had to remember, and `pause()` did not - it dropped the
    /// node and then checkpointed, silently discarding every contact and verify
    /// key of the session. A rule that cannot be forgotten is worth more than a
    /// comment asking callers to remember it.
    fn set_kad(&mut self, node: Option<KadNode>) {
        self.absorb_kad_routing();
        self.kad = node;
        // Immediate, not left to the next heartbeat: pause/resume swaps the live
        // table wholesale and a stale count across that boundary is exactly the
        // "138 -> 21" confusion of row 8cd.
        self.publish_status();
    }

    /// Copy the LIVE Kad node's table into the persisted one.
    ///
    /// Must run before any path that drops the node and then checkpoints -
    /// `checkpoint_contacts` can only union in a node that still exists. Cheap
    /// and idempotent: `load_nodes` merges, so calling it twice changes nothing.
    fn absorb_kad_routing(&mut self) {
        // Bind the conversion first so the borrow of `self.kad` ends before
        // `self.routing` is borrowed mutably.
        let learned = self
            .kad
            .as_ref()
            .map(|n| n.with_routing(|t| routing_to_nodes(t)));
        if let Some(learned) = learned {
            self.routing.load_nodes(&learned);
        }
    }

    /// Persist durable state: the identity and the Kad routing table
    /// (`nodes.dat`). Download `.part.met` progress is flushed separately on the
    /// pause/shutdown boundary by `persist_downloads` (the hot path only updates
    /// the in-memory gaps, so this is NOT already durable per-block).
    fn checkpoint(&self) {
        let _ = self.identity.save(&self.config_dir);
        // Include what the LIVE node learned this session, not just the snapshot
        // taken at the end of bootstrap - see `checkpoint_contacts`. This catches
        // any caller that checkpoints while the node is still alive; the callers
        // that DROP it first are covered by `set_kad`, which absorbs the table on
        // the way out. Both are needed: this one alone silently missed pause().
        // Folded UNDER the live node's routing lock: `with_routing` hands out a
        // borrow, never the table itself, so the union happens inside the
        // closure (the lock is held for this one call, no await in sight).
        let contacts = match self.kad.as_ref() {
            Some(k) => k.with_routing(|live| checkpoint_contacts(&self.routing, Some(live))),
            None => checkpoint_contacts(&self.routing, None),
        };
        let nd = NodesDat {
            version: 2,
            contacts,
        };
        let _ = std::fs::write(self.config_dir.join("nodes.dat"), write_nodes_dat(&nd));
        // Persist the credit history (clients.met). pause() is the only reliable
        // iPadOS checkpoint, so credit deltas since the last pause are lost on a
        // hard kill - acceptable for foreground-only v1, and eMule keeps its own
        // wait-clock in RAM too.
        let _ = std::fs::write(self.config_dir.join(CLIENTS_MET), self.credit_store.save());
    }

    /// Seed the routing table with Kad contacts (e.g. from a fresh nodes.dat or a
    /// live bootstrap), so the next checkpoint persists them.
    pub fn add_kad_contacts(&mut self, contacts: &[KadContact]) {
        self.routing.load_nodes(contacts);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MUTEX POISONING (handoff #35a). The per-IP inbound cap is taken on EVERY
    /// accepted connection and released in `IpConnSlot::drop`, so poisoning it
    /// would both close the listener's admission path and turn every later
    /// connection teardown into a panic mid-unwind - a process ABORT. Recovery
    /// is safe: the map holds per-IP counters that a torn update can only leave
    /// off by one, and each entry is removed when it reaches zero.
    #[test]
    fn a_panic_under_the_per_ip_lock_leaves_admission_working() {
        let per_ip: PerIpConns = Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));
        let ip = Ipv4Addr::new(203, 0, 113, 7);
        let first = IpConnSlot::try_acquire(&per_ip, ip).expect("the control acquire");
        crate::lock::poison_for_test(&per_ip);

        // Admission still counts up to the cap, and still refuses past it.
        let mut held = vec![first];
        while let Some(s) = IpConnSlot::try_acquire(&per_ip, ip) {
            held.push(s);
            assert!(
                held.len() <= MAX_INBOUND_PER_IP as usize,
                "the cap still holds"
            );
        }
        assert_eq!(held.len(), MAX_INBOUND_PER_IP as usize);
        // And the Drop path - the abort path - still gives the slots back.
        held.clear();
        // Read the map back WITHOUT the production helper, so this assertion is
        // an independent witness rather than a restatement of the fix.
        let seen = per_ip.lock().unwrap_or_else(|e| e.into_inner()).clone();
        assert!(seen.is_empty(), "the entry was cleaned up");
        assert!(IpConnSlot::try_acquire(&per_ip, ip).is_some());
    }

    #[test]
    fn gate_loaded_nodes_applies_the_amule_load_gate() {
        // aMule filters nodes.dat contacts at LOAD (RoutingZone.cpp:195-199):
        // Kad2-only, routable ip:port, user ipfilter, no legacy DNS-port node.
        // A DOWNLOADED nodes.dat must not seed the table unfiltered.
        let mk = |ip: u32, udp: u16, ver: u8| KadContact {
            id: Kad128::from_hash(&[ver; 16]),
            ip,
            udp_port: udp,
            tcp_port: 4662,
            version: ver,
            udp_key: 0,
            udp_key_ip: 0,
            verified: false,
        };
        let contacts = vec![
            mk(0xC0A8_0105, 4672, 8), // 192.168.1.5 - private, dropped
            mk(0x0808_0808, 53, 5),   // legacy node on the DNS port - dropped
            mk(0x0808_0404, 53, 8),   // MODERN node on port 53 - kept (version-gated)
            mk(0x0505_0505, 4672, 1), // Kad1 - dropped (aMule: contactVersion > 1)
            mk(0x0102_0300, 4672, 8), // 1.2.3.0 - blocked by the user filter below
            mk(0x2596_24FA, 4672, 8), // routable public v8 - kept
        ];
        let filter = mule_files::IpFilter::parse(
            "001.002.003.000 - 001.002.003.255 , 000 , blocked range",
            127,
        );
        let gated = gate_loaded_nodes(&contacts, Some(&filter));
        let ips: Vec<u32> = gated.iter().map(|c| c.ip).collect();
        assert_eq!(ips, vec![0x0808_0404, 0x2596_24FA]);
    }

    /// THE send gate for the server UDP fan-outs: forbids a blocklisted PUBLIC
    /// target, allows a blocklisted loopback/LAN one (the eserver-oracle case),
    /// and allows anything the filter does not cover.
    #[test]
    fn blocklist_forbids_send_is_public_only_and_host_order() {
        let filter = IpFilter::parse(
            "198.18.0.0 - 198.18.255.255 , 0 , blocked\n\
             127.0.0.0 - 127.255.255.255 , 0 , reserved-range boilerplate\n",
            DEFAULT_IPFILTER_LEVEL,
        );
        let f = Some(&filter);
        // A blocklisted PUBLIC address: an unambiguous "do not talk to it".
        assert!(blocklist_forbids_send(f, Ipv4Addr::new(198, 18, 0, 1)));
        // A blocklisted LOOPBACK address: still sendable - community lists
        // blanket the reserved ranges, and the user's own oracle lives there.
        assert!(!blocklist_forbids_send(f, Ipv4Addr::new(127, 0, 0, 1)));
        // Public but not blocklisted, and no filter at all: sendable.
        assert!(!blocklist_forbids_send(f, Ipv4Addr::new(85, 17, 116, 222)));
        assert!(!blocklist_forbids_send(None, Ipv4Addr::new(198, 18, 0, 1)));
        // THE BYTE-ORDER PIN: the helper takes an `Ipv4Addr`, so a met-order
        // u32 cannot reach the filter unconverted. The met spelling of
        // 198.18.0.1 misread as host order is 1.0.18.198 - a public address
        // the ranges above do NOT cover - so the raw u32 would sail through,
        // which is exactly the three-times-shipped bug this shape prevents.
        assert!(!blocklist_forbids_send(
            f,
            Ipv4Addr::from(u32::from_le_bytes([198, 18, 0, 1]))
        ));
    }

    /// A REAL file on disk for a `SharedFile` fixture. The serve path verifies a
    /// shared file still exists at the size we hashed before claiming we have it
    /// (so a file the user deleted is never advertised), which means a fixture
    /// path must be real - and makes these tests faithful to a live serve.
    fn fixture_file(tag: &str, size: usize) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "padmule-engine-{tag}-{}-{:?}.bin",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&p, vec![0u8; size]).unwrap();
        p
    }

    fn tmp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("padmule-engine-{tag}-{}", std::process::id()))
    }

    async fn drain(rx: &mut mpsc::UnboundedReceiver<EngineEvent>) -> Vec<EngineEvent> {
        let mut out = Vec::new();
        while let Ok(e) = rx.try_recv() {
            out.push(e);
        }
        out
    }

    /// `start_kad` hands the RAW nodes.dat contacts to `bootstrap_any`, bypassing
    /// the same load gate `start()` applies to the routing-table load. A poisoned
    /// nodes.dat (ipfilter-blocked, unroutable, or Kad1 contacts) must not aim the
    /// bootstrap dial sweep at them - it must gate to empty and say so, not dial.
    /// Resume must seed Kad from the IN-MEMORY table, not only from disk.
    ///
    /// `pause()` drops the live node and folds everything it learned into
    /// `self.routing`; `start_kad` then used to re-read nodes.dat and ignore
    /// that, so every contact learned since the last checkpoint was discarded on
    /// each background/foreground round trip. Caught live 2026-08-05 - Status
    /// showed 138 contacts, Anthony opened a download in another app and came
    /// back, and the engine logged `kad contacts: 21`.
    ///
    /// Driven with NO nodes.dat at all, so the only way to reach a non-empty
    /// dial list is through the in-memory table: if the union regresses, the
    /// engine emits "no Kad contacts to bootstrap" and this fails.
    #[tokio::test]
    async fn resume_seeds_kad_from_the_in_memory_table_not_only_from_disk() {
        let dir = tmp("kad-reseed");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(
            !dir.join("nodes.dat").exists(),
            "no disk contacts on purpose"
        );

        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        // What a live session would have folded in on pause: routable, Kad2.
        engine.routing.load_nodes(&[KadContact {
            id: Kad128::from_hash(&[0x5A; 16]),
            ip: 0x0808_0404, // 8.8.4.4 - routable and acceptable
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            verified: false,
        }]);

        engine.start_kad().await;

        let evs = drain(&mut rx).await;
        assert!(
            !evs.iter().any(
                |e| matches!(e, EngineEvent::Server(s) if s == "no Kad contacts to bootstrap")
            ),
            "the in-memory table was ignored, so a resume threw away everything \
             learned since the last checkpoint; got {evs:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A maintenance pass must FIT INSIDE its deadline, so the timeout is a
    /// safety net rather than the thing that ends every run.
    ///
    /// THIS RELATIONSHIP INVERTED on 2026-08-07 and the inversion is the point.
    /// `refresh_routing` used to issue its `ALPHA_QUERY` queries one after
    /// another, so a pass cost 4 rounds x 3 x `KAD_PER_QUERY` = 9s against a 3s
    /// deadline: the deadline always fired, and maintenance got through about
    /// four of its twelve queries before being cut off. The refresh is now an
    /// event-driven lookup whose own deadline is `REFRESH_DEADLINE_QUERIES *
    /// KAD_PER_QUERY`, and that deadline must stay inside the heartbeat's
    /// budget or the budget silently becomes the thing that ends every pass
    /// again - cancelling `refresh_routing` mid-flight instead of letting it
    /// finish.
    #[test]
    fn a_kad_maintenance_round_fits_inside_its_deadline() {
        let structural = KAD_PER_QUERY * crate::kad_live::REFRESH_DEADLINE_QUERIES;
        assert!(
            structural <= KAD_MAINTENANCE_BUDGET,
            "a refresh pass can cost {structural:?} against a {KAD_MAINTENANCE_BUDGET:?} \
             deadline, so the heartbeat cuts maintenance off part-way every time - \
             REFRESH_DEADLINE_QUERIES / KAD_PER_QUERY grew past the budget"
        );
    }

    /// The publish twin of the pin above, for the same inversion: the publish
    /// walks shipped with `LOOKUP_DEADLINE_QUERIES` (16 x 750ms = 12s
    /// structural) inside a 3s `KAD_PUBLISH_BUDGET`, so every publish ran to
    /// the OUTER cancellation under the engine lock instead of terminating on
    /// its own deadline. The walk's deadline must stay inside the budget.
    #[test]
    fn a_kad_publish_walk_fits_inside_its_budget() {
        let structural = KAD_PER_QUERY * crate::kad_live::PUBLISH_DEADLINE_QUERIES;
        assert!(
            structural <= KAD_PUBLISH_BUDGET,
            "a publish walk can cost {structural:?} against a {KAD_PUBLISH_BUDGET:?} \
             budget, so the outer timeout cancels every publish part-way - \
             PUBLISH_DEADLINE_QUERIES / KAD_PER_QUERY grew past the budget"
        );
    }

    /// Seeding must not be a way around the contact rules - a nodes.dat is a
    /// DOWNLOADABLE file, so a poisoned one arriving by this path has to be held
    /// to what a wire-learned contact is held to.
    ///
    /// Driven through `start_kad` rather than by calling `seed_routing` directly,
    /// because the guarantee is a COMPOSITION and testing either half alone
    /// overstates it: `gate_loaded_nodes` (engine layer) rejects Kad1 and
    /// ipfilter-blocked contacts, while `KadNode::add_contact` (live layer)
    /// rejects unroutable addresses, legacy DNS-port contacts and anti-sybil
    /// floods. The first version of this test asserted the combined result
    /// against `seed_routing` alone and failed on the Kad1 entry - correctly, as
    /// it happens: `add_contact` has no version gate of its own.
    ///
    /// THE FIXTURE MUST EXERCISE BOTH LAYERS, or it silently tests only one. The
    /// four poisoned contacts are all caught by `gate_loaded_nodes` BEFORE the
    /// live layer ever sees them, so with only those the test passed even with
    /// `add_contact` bypassed entirely - proving nothing about seeding. The three
    /// contacts sharing ONE IP are what close that: `gate_loaded_nodes` has no
    /// per-IP cap and passes all three, and only the live layer's anti-sybil
    /// `MAX_CONTACTS_PER_IP` cuts them to one.
    /// A DOWNLOADED server list cannot point padMule at private space.
    ///
    /// `update_server_list` fetches from a user-configured URL, so the publisher
    /// chooses the bytes (and over `http://`, so can anyone in between), and
    /// every entry that lands in server.met becomes a UDP target for the status
    /// probe and the global search. TLS does not retire this gate: it
    /// authenticates the HOST, not the host's intentions. The crawl path was
    /// gated from the beginning; this one was not, which is the wrong way round,
    /// because the crawl only learns addresses one at a time from servers while
    /// this ingests a whole file.
    ///
    /// The vetting sits at INGESTION, not at the send sites, so a loopback or
    /// LAN server the USER added stays usable - padMule's own eserver oracle
    /// runs on 127.0.0.1, and gating the fan-out would have broken it while
    /// leaving this hole open.
    ///
    /// It is deliberately NOT conditional on the scheme. See
    /// `the_scheme_gate_admits_https_and_nothing_else` for the other half.
    #[test]
    fn a_downloaded_server_list_cannot_smuggle_in_private_space() {
        let met_ip = |a: u8, b: u8, c: u8, d: u8| u32::from_le_bytes([a, b, c, d]);
        let srv = |ip: u32, port: u16| Server {
            ip,
            port,
            tags: Vec::new(),
        };
        let hostile = ServerMet {
            header: 0xE0,
            servers: vec![
                srv(met_ip(85, 17, 116, 222), 4242), // routable - kept
                srv(met_ip(127, 0, 0, 1), 4242),     // loopback - our own machine
                srv(met_ip(192, 168, 0, 5), 4242),   // the user's LAN
                srv(met_ip(10, 1, 2, 3), 4242),      // private
                srv(met_ip(169, 254, 1, 1), 4242),   // link-local
                srv(met_ip(77, 42, 68, 79), 0),      // port 0
                srv(met_ip(77, 42, 68, 80), 5000),   // routable - kept
            ],
        };

        let vetted = Engine::vet_downloaded_servers(hostile, None);
        assert_eq!(
            vetted.servers.len(),
            2,
            "only the two routable public entries may survive"
        );
        assert!(
            vetted
                .servers
                .iter()
                .all(|s| crate::fetch::is_routable_public_v4(ip_from_met_u32(s.ip))),
            "no unroutable address may reach server.met"
        );

        // The user's blocklist applies to a downloaded list as well - it gates
        // sources and Kad contacts, so a server list must not be the way around it.
        let filter = IpFilter::parse("85.17.116.0 - 85.17.116.255 , 0 , blocked\n", 127);
        let vetted = Engine::vet_downloaded_servers(
            ServerMet {
                header: 0xE0,
                servers: vec![
                    srv(met_ip(85, 17, 116, 222), 4242),
                    srv(met_ip(77, 42, 68, 80), 5000),
                ],
            },
            Some(&filter),
        );
        assert_eq!(vetted.servers.len(), 1, "a blocklisted server is dropped");
        assert_eq!(vetted.servers[0].port, 5000);
    }

    /// The scheme gate must ADMIT https and reject everything else.
    ///
    /// Until 2026-08-10 `https://` was answered with `BadUrl`, so an https server
    /// list could not be used even deliberately - while the iOS Settings screen
    /// happily ACCEPTED one into the source list (`EngineModel.addServerListUrl`
    /// takes `http://` or `https://`), so the dead end was reachable from ordinary
    /// use. That is padMule's own limitation, not the authority's: eMule sets
    /// INTERNET_FLAG_SECURE for AFX_INET_SERVICE_HTTPS
    /// (refs/emule-0.70b/eMule0.70b-Sources/srchybrid/HttpDownloadDlg.cpp:461-463).
    ///
    /// The distinction the assertions turn on is WHICH failure comes back.
    /// `Unreachable` means the URL got as far as a socket (loopback port 1
    /// refuses instantly, so this stays offline); `BadUrl` means the gate turned
    /// it away. Asserting merely "it fails" would pass on the buggy code too.
    #[tokio::test]
    async fn the_scheme_gate_admits_https_and_nothing_else() {
        let dir = tmp("server-list-scheme");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (engine, _rx) = Engine::new(&dir).unwrap();

        assert_eq!(
            engine
                .update_server_list("https://127.0.0.1:1/list.met")
                .await,
            ServerListUpdate::Unreachable,
            "an https URL must be FETCHED (and here fail to connect), not refused"
        );
        assert_eq!(
            engine
                .update_server_list("http://127.0.0.1:1/list.met")
                .await,
            ServerListUpdate::Unreachable,
            "plaintext must be unchanged"
        );
        // Widened by exactly one scheme, not opened. `file://` matters most: it
        // is the one that would turn a server-list URL into a local-file read.
        for bad in [
            "ftp://example.org/list.met",
            "file:///etc/passwd",
            "upd.example.org/server.met",
            "",
        ] {
            assert_eq!(
                engine.update_server_list(bad).await,
                ServerListUpdate::BadUrl,
                "{bad:?} must not be fetched"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn seeding_the_live_table_applies_the_same_gates_as_the_wire() {
        let dir = tmp("kad-seed-gates");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mk = |ip: u32, udp: u16, ver: u8, seed: u8| KadContact {
            id: Kad128::from_hash(&[seed; 16]),
            ip,
            udp_port: udp,
            tcp_port: 4662,
            version: ver,
            udp_key: 0,
            udp_key_ip: 0,
            verified: true,
        };
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.routing.load_nodes(&[
            // Caught by the ENGINE layer (gate_loaded_nodes).
            mk(0x7F00_0001, 4672, 8, 1), // loopback
            mk(0xC0A8_0105, 4672, 8, 2), // private LAN
            mk(0x0909_0909, 53, 5, 4),   // legacy node on the DNS port
            // Caught EARLIER, by the routing table itself: a Kad1 contact never
            // enters ANY routing table, because eMule runs its whole insert
            // inside `uVersion > 1` (RoutingZone.cpp:494) and aMule applies the
            // same filter when loading nodes.dat (RoutingZone.cpp:192-203).
            // This is why the fixture count below is 6 and not 7 - the entry is
            // refused before `Engine::routing` ever holds it, so it cannot
            // reach the engine gate that used to catch it.
            mk(0x0808_0808, 4672, 1, 3), // Kad1 - the protocol cannot talk to it
            // Pass the engine layer; only the LIVE layer's per-IP cap cuts these
            // three down to one.
            mk(0x0101_0101, 4672, 8, 5),
            mk(0x0101_0101, 4672, 8, 6),
            mk(0x0101_0101, 4672, 8, 7),
        ]);
        assert_eq!(
            engine.routing.len(),
            6,
            "the fixture must survive intact EXCEPT the Kad1 contact, which the \
             table refuses outright"
        );

        engine.start_kad().await;

        assert_eq!(
            engine.kad.as_ref().unwrap().contacts_known(),
            1,
            "seeding let a poisoned contact or an anti-sybil flood into the live table"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Five routable, mutually /24-distinct contacts, so none is dropped by the
    /// live layer's anti-sybil per-IP//24 caps.
    fn seed_contacts() -> Vec<KadContact> {
        [
            (0x0808_0404u32, 0x11u8), // 8.8.4.4
            (0x0909_0909, 0x22),      // 9.9.9.9
            (0x0101_0101, 0x33),      // 1.1.1.1
            (0xD043_DEDE, 0x44),      // 208.67.222.222
            (0x4006_4006, 0x55),      // 64.6.64.6
        ]
        .into_iter()
        .map(|(ip, seed)| KadContact {
            id: Kad128::from_hash(&[seed; 16]),
            ip,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            // VERIFIED, as a contact reloaded from nodes.dat or folded in by
            // `absorb_kad_routing` would be - and the bit is load-bearing:
            // `closest_to` is verified-only, so an unverified seed populates
            // `len()` while remaining invisible to every lookup.
            verified: true,
        })
        .collect()
    }

    /// The live `KadNode` must START from what we already know, not from one
    /// bootstrap response.
    ///
    /// `bind_with_identity` constructs an EMPTY `RoutingTable`, `bootstrap_any`
    /// returns on the FIRST success, and `bootstrap_from` adds only the responder
    /// plus the ~20 contacts it names - so every `start_kad`, on START and on
    /// every RESUME, left the table that lookups actually read at about 21
    /// entries no matter how many `Engine::routing` held. That is the real
    /// content of the 2026-08-05 "138 -> 21" report: not a table being discarded,
    /// but a fresh one being built. The 8cd union fixed the bootstrap DIAL LIST
    /// and did not touch this ([[kad-routing-lifecycle]], build-progress 8ce).
    ///
    /// Driven with NO nodes.dat and an unreachable seed set, so the bootstrap
    /// CANNOT contribute a single contact: anything in the live table came from
    /// the seeding this test exists to pin.
    #[tokio::test]
    async fn start_kad_seeds_the_live_node_from_what_we_already_know() {
        let dir = tmp("kad-seed-live");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        let seeds = seed_contacts();
        engine.routing.load_nodes(&seeds);
        engine.start_kad().await;

        let live = engine
            .kad
            .as_ref()
            .expect("the node is kept even when the bootstrap fails");
        assert_eq!(
            live.contacts_known(),
            seeds.len(),
            "the live table starts EMPTY and only the bootstrap fills it, so every \
             lookup after a resume runs against one bootstrap response"
        );
        // The bit has to survive the seeding or the contacts are invisible to
        // every lookup while still counting toward `len()`.
        assert_eq!(
            live.closest_wire_contacts(&engine.identity.kad_id, 50)
                .len(),
            seeds.len(),
            "seeded contacts lost their verified bit, so closest_to hands out none"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ONE FIELD, ONE MEASUREMENT.
    ///
    /// `Engine::kad_contacts()` (polled every second) returned the PERSISTED
    /// table while `EngineEvent::Kad` carried the LIVE node's count from
    /// `start_kad` and `maintain_kad` - two different quantities written to the
    /// same `kadContacts` field in the UI. That is what made the on-screen number
    /// monotonic (nothing ever removes a contact from `Engine::routing`) and
    /// therefore useless as the verdict on Kad maintenance.
    ///
    /// THE TWO TABLES ARE FORCED TO DIVERGE HERE, and that is the whole design of
    /// the test. Once seeding works the live and persisted counts normally AGREE,
    /// which makes the assertion vacuous - the first version of this test passed
    /// with `kad_contacts` reverted to `self.routing.len()`, i.e. it could not see
    /// the bug it was written for. So the fixture loads three contacts sharing ONE
    /// IP: `RoutingTable::add` (the persisted path) has no per-IP cap and keeps
    /// all three, while the live layer's anti-sybil `MAX_CONTACTS_PER_IP` keeps
    /// exactly one. 3 against 1, deterministically, every run.
    #[tokio::test]
    async fn the_polled_kad_count_and_the_kad_event_report_the_same_thing() {
        let dir = tmp("kad-one-measurement");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        let crowded: Vec<KadContact> = [0x11u8, 0x22, 0x33]
            .into_iter()
            .map(|seed| KadContact {
                id: Kad128::from_hash(&[seed; 16]),
                ip: 0x0808_0404, // all three at 8.8.4.4 - one IP, three IDs
                udp_port: 4672,
                tcp_port: 4662,
                version: 8,
                udp_key: 0,
                udp_key_ip: 0,
                verified: true,
            })
            .collect();
        engine.routing.load_nodes(&crowded);
        assert_eq!(
            engine.routing.len(),
            3,
            "the fixture must actually divide the two tables, or this proves nothing"
        );

        engine.start_kad().await;

        let live = engine.kad.as_ref().unwrap().contacts_known();
        assert_eq!(live, 1, "the anti-sybil per-IP cap should keep exactly one");
        assert_eq!(
            engine.kad_contacts(),
            live,
            "the polled count must describe the table lookups actually use, not the \
             monotonic persisted one"
        );
        let emitted: Vec<usize> = drain(&mut rx)
            .await
            .into_iter()
            .filter_map(|e| match e {
                EngineEvent::Kad { contacts } => Some(contacts),
                _ => None,
            })
            .collect();
        assert!(
            emitted.iter().all(|&n| n == live),
            "the Kad event carried a different quantity than the poll: {emitted:?} vs {live}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_kad_gates_the_dial_list_not_just_the_routing_table_load() {
        let dir = tmp("start-kad-gate");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mk = |ip: u32, udp: u16, ver: u8| KadContact {
            id: Kad128::from_hash(&[ver; 16]),
            ip,
            udp_port: udp,
            tcp_port: 4662,
            version: ver,
            udp_key: 0,
            udp_key_ip: 0,
            verified: false,
        };
        let contacts = vec![
            mk(0x7F00_0001, 4672, 8), // 127.0.0.1 - loopback, unroutable
            mk(0xC0A8_0105, 4672, 8), // 192.168.1.5 - private LAN
            mk(0x0808_0808, 4672, 1), // Kad1 - the protocol can't even talk to it
        ];
        std::fs::write(
            dir.join("nodes.dat"),
            write_nodes_dat(&NodesDat {
                version: 2,
                contacts,
            }),
        )
        .unwrap();

        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.start_kad().await;

        let evs = drain(&mut rx).await;
        assert!(
            evs.iter().any(
                |e| matches!(e, EngineEvent::Server(s) if s == "no Kad contacts to bootstrap")
            ),
            "an all-unacceptable nodes.dat must gate the dial list to empty, not dial it; got {evs:?}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A checkpoint must persist what the LIVE Kad node learned this session, not
    /// only the snapshot `start_kad` took at the end of bootstrap. Reported by the
    /// 2026-08-02 reanalysis: `pause()` drops the node and then checkpoints, so
    /// every contact and - worse - every per-peer UDP verify key captured by
    /// `note_responder` was silently discarded, defeating the wave-10 goal of
    /// echoing a peer's key after a restart.
    #[test]
    fn a_checkpoint_keeps_contacts_and_verify_keys_learned_this_session() {
        let me = Kad128::from_hash(&[0x11; 16]);
        let seen_at_boot = KadContact {
            id: Kad128::from_hash(&[0xAA; 16]),
            ip: 0x0808_0808,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            verified: false,
        };
        // The SAME node, re-observed live: it answered us, so we now hold its
        // verify key and it is IP-verified.
        let with_key = KadContact {
            udp_key: 0xDEAD_BEEF,
            udp_key_ip: 0x0101_0101,
            verified: true,
            ..seen_at_boot
        };
        // ...plus a node discovered by a lookup AFTER bootstrap.
        let found_later = KadContact {
            id: Kad128::from_hash(&[0xBB; 16]),
            ip: 0x0909_0909,
            ..with_key
        };

        let mut persisted = RoutingTable::new(me);
        persisted.load_nodes(&[seen_at_boot]);
        let mut live = RoutingTable::new(me);
        live.load_nodes(&[with_key.clone(), found_later.clone()]);

        let out = checkpoint_contacts(&persisted, Some(&live));
        assert_eq!(out.len(), 2, "the union, not a replacement: {out:?}");

        let a = out.iter().find(|c| c.id == with_key.id).expect("boot node");
        assert_eq!(a.udp_key, 0xDEAD_BEEF, "the key learned live must survive");
        assert!(a.verified, "the verified bit learned live must survive");
        assert!(
            out.iter().any(|c| c.id == found_later.id),
            "a contact discovered after bootstrap must be persisted"
        );

        // With no live node (never started, or already dropped) it is a pass-through.
        let only = checkpoint_contacts(&persisted, None);
        assert_eq!(only.len(), 1);
        assert_eq!(only[0].udp_key, 0, "no live node, no invented state");
    }

    /// A deliberate STOP must actually stop: release the sockets (the old
    /// `shutdown` checkpointed and set the state while leaving TCP 4662 bound and
    /// Kad's UDP socket open), persist what the session learned, and leave the
    /// engine restartable without relaunching the app.
    /// THE PERSISTENCE HALF of contact expiry, driven through the REAL caller
    /// chain (`maintain_kad_liveness` -> `checkpoint`), not by calling
    /// `RoutingTable::remove` directly - the whole defect was that the sweep
    /// removed from the LIVE table while `checkpoint_contacts` re-folded the
    /// monotonic `Engine::routing` on top, so a test that skipped the engine
    /// would prove nothing about it.
    ///
    /// The second half is the one a naive tombstone SET would fail: a peer that
    /// comes back at a NEW address must be persisted again. There is no
    /// tombstone to outlive the re-observation because the eviction is a
    /// deletion, exactly as it is in eMule's single store.
    #[tokio::test]
    async fn an_evicted_contact_is_dropped_from_nodes_dat_and_a_reborn_one_returns() {
        use crate::kad_live::KadNode;
        use mule_files::read_nodes_dat;

        let dir = tmp("kad-evict-persist");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(false);

        // X is silent (nothing is bound at its address, so its probe times out).
        // Y is the control: it must survive, or the test proves only that
        // checkpointing can lose contacts.
        let dead = KadContact {
            id: Kad128::from_hash(&[0xA1; 16]),
            ip: 0x0101_0101,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            verified: true,
        };
        let control = KadContact {
            id: Kad128::from_hash(&[0xB2; 16]),
            ip: 0x0202_0202,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            verified: true,
        };
        // ONLY the dead contact goes into the LIVE table. The control lives in
        // the persisted table alone, so the sweep never touches it - which is
        // what makes it a control. An unreachable contact placed in the live
        // table beside the victim is not a control, it is a second victim: the
        // first sweep STAMPS and then ROTATES the bin front, so whichever
        // contact ends up second is the one probed first. The first version of
        // this test put both in the live table and evicted the "control".
        let node = KadNode::bind("127.0.0.1:0".parse().unwrap(), 4662)
            .await
            .unwrap();
        node.with_routing(|t| t.load_nodes(std::slice::from_ref(&dead)));
        engine.routing.load_nodes(&[dead.clone(), control.clone()]);
        engine.kad = Some(node);
        engine.state = EngineState::Running;

        // Walk the death march: stamp, probe (X's HELLO times out), remove.
        // The aging clock is advanced rather than slept on - the arms are gated
        // on eMule's real 10s/120s intervals.
        for step in 0..3 {
            engine.last_kad_sweep = Instant::now() - KAD_SWEEP_EVERY;
            engine.maintain_kad_liveness().await;
            if let Some(k) = engine.kad.as_ref() {
                k.advance_aging_for_test(if step == 0 { 60 } else { 200 });
            }
        }

        engine.checkpoint();
        let nd = read_nodes_dat(&std::fs::read(dir.join("nodes.dat")).unwrap()).unwrap();
        assert!(
            !nd.contacts.iter().any(|c| c.id == dead.id),
            "an evicted contact must NOT be written back - it would be \
             re-imported next launch and re-blackhole its IP"
        );
        assert!(
            nd.contacts.iter().any(|c| c.id == control.id),
            "the control must survive - this asserts an EVICTION happened, not \
             a checkpoint that loses contacts"
        );

        // REBORN at a new address: re-learned by the live table, so the next
        // checkpoint persists it again. A never-cleared tombstone set fails here.
        let reborn = KadContact {
            ip: 0x0505_0505,
            ..dead.clone()
        };
        engine
            .kad
            .as_ref()
            .unwrap()
            .with_routing(|t| t.load_nodes(std::slice::from_ref(&reborn)));
        engine.checkpoint();
        let nd = read_nodes_dat(&std::fs::read(dir.join("nodes.dat")).unwrap()).unwrap();
        assert!(
            nd.contacts
                .iter()
                .any(|c| c.id == reborn.id && c.ip == 0x0505_0505),
            "a peer that comes back at a new address must be persisted again"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn stop_releases_sockets_persists_and_can_restart() {
        use crate::kad_live::KadNode;
        use mule_files::read_nodes_dat;

        let dir = tmp("stop-clean");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        let learned = KadContact {
            id: Kad128::from_hash(&[0xD4; 16]),
            ip: 0x0C0C_0C0C,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0xFEED_FACE,
            udp_key_ip: 0x0303_0303,
            verified: true,
        };
        let node = KadNode::bind("127.0.0.1:0".parse().unwrap(), 4662)
            .await
            .unwrap();
        node.with_routing(|t| t.load_nodes(std::slice::from_ref(&learned)));
        engine.kad = Some(node);
        engine.state = EngineState::Running;

        engine.shutdown().await;

        assert_eq!(engine.state(), EngineState::Stopped);
        assert!(engine.kad.is_none(), "the Kad socket must be released");
        assert!(engine.listener.is_none(), "TCP 4662 must be released");
        assert!(engine.server.is_none(), "the server link must be dropped");

        // What the session learned still reached disk.
        let nd = read_nodes_dat(&std::fs::read(dir.join("nodes.dat")).unwrap()).unwrap();
        assert!(
            nd.contacts.iter().any(|c| c.id == learned.id),
            "a stop must still persist the session's Kad contacts"
        );

        // The user is told, in a line the UI can show verbatim.
        let evs = drain(&mut rx).await;
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::Status(s) if s == "Stopped")),
            "stop must announce itself; got {evs:?}"
        );

        // ...and it is restartable in-place, so a deliberate stop does not brick
        // the app until it is relaunched.
        engine.start().await;
        assert_eq!(engine.state(), EngineState::Running);
        engine.shutdown().await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The connected-line resolves the server's NAME from server.met and shows
    /// it with the address in parens - the user asked for the name, not a bare IP.
    #[tokio::test]
    async fn the_connected_line_shows_the_server_name() {
        use mule_files::{write_server_met, Server, ServerMet};
        use mule_proto::{Tag, TagName, TagValue};

        let dir = tmp("server-name");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (engine, _rx) = Engine::new(&dir).unwrap();

        // A server.met with one named server at 85.17.116.222:6082 (met u32 is
        // little-endian: low byte first).
        let ip = u32::from_le_bytes([85, 17, 116, 222]);
        let met = write_server_met(&ServerMet {
            header: 0xE0,
            servers: vec![Server {
                ip,
                port: 6082,
                tags: vec![Tag {
                    name: TagName::Id(0x01),
                    value: TagValue::Str(b"ed2k-rust".to_vec()),
                }],
            }],
        });
        std::fs::write(dir.join("server.met"), met).unwrap();

        let addr: SocketAddr = "85.17.116.222:6082".parse().unwrap();
        assert_eq!(
            engine.server_name_for(&addr).as_deref(),
            Some("ed2k-rust"),
            "the name must resolve from server.met"
        );
        // A server not in the list has no name (the line falls back to the addr).
        let other: SocketAddr = "1.2.3.4:4242".parse().unwrap();
        assert_eq!(engine.server_name_for(&other), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The gossip crawl merges advertised servers into server.met, and filters
    /// out the bogus/hostile ones a server must never be able to inject.
    #[tokio::test]
    async fn harvested_servers_are_filtered_and_merged() {
        let dir = tmp("harvest");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        // ip_from_met_u32 reads the u32 little-endian (low byte = first octet), so
        // build the met-u32 for each address that way.
        let met_ip = |a: u8, b: u8, c: u8, d: u8| u32::from_le_bytes([a, b, c, d]);
        // NB use genuinely routable public IPs, not the 203.0.113/198.51.100
        // TEST-NET documentation ranges - is_routable_public_v4 rejects those.
        {
            let mut h = engine.harvested_servers.lock().unwrap();
            h.push((met_ip(85, 17, 116, 222), 4242)); // public - kept
            h.push((met_ip(77, 42, 68, 79), 5000)); // public - kept
            h.push((met_ip(192, 168, 0, 5), 4242)); // LAN - dropped
            h.push((met_ip(127, 0, 0, 1), 4242)); // loopback - dropped
            h.push((met_ip(8, 8, 8, 8), 0)); // port 0 - dropped
            h.push((met_ip(91, 200, 13, 76), 4242)); // blocklisted below - dropped
        }
        // THE USER'S BLOCKLIST MUST REACH THIS PATH, and it did not: the filter
        // was consulted with the raw met u32, which is byte-REVERSED relative to
        // the ranges `is_blocked_u32` holds, so a blocked address read as some
        // unrelated one and sailed through. The address below is only ever
        // dropped if the conversion is right.
        engine.ip_filter = Some(std::sync::Arc::new(IpFilter::parse(
            "91.200.13.0 - 91.200.13.255 , 0 , blocked\n",
            DEFAULT_IPFILTER_LEVEL,
        )));

        let added = engine.maintain_server_harvest().await;
        assert_eq!(
            added, 2,
            "only the two routable, non-blocklisted servers are added"
        );

        // Persisted, and re-harvesting the SAME set adds nothing (dedup).
        let bytes = std::fs::read(dir.join("server.met")).unwrap();
        let met = read_server_met(&bytes).unwrap();
        assert_eq!(met.servers.len(), 2);
        {
            let mut h = engine.harvested_servers.lock().unwrap();
            h.push((met_ip(85, 17, 116, 222), 4242)); // already present
        }
        assert_eq!(
            engine.maintain_server_harvest().await,
            0,
            "dedup on re-harvest"
        );

        // An empty queue is a cheap no-op.
        assert_eq!(engine.maintain_server_harvest().await, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The crawl is the one path that sends datagrams to hosts the user never
    /// chose, so its SSRF posture is asserted on the production entry point, not
    /// on the helper: a server.met full of LAN/loopback entries must produce
    /// ZERO asks. (Testing `is_crawlable` alone would not prove `crawl_servers`
    /// consults it - the 8ae/8au lesson.)
    #[tokio::test]
    async fn a_crawl_never_targets_lan_or_loopback_servers() {
        let dir = tmp("crawl-ssrf");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let met_ip = |a: u8, b: u8, c: u8, d: u8| u32::from_le_bytes([a, b, c, d]);
        let servers = vec![
            Server {
                ip: met_ip(127, 0, 0, 1),
                port: 4661,
                tags: Vec::new(),
            },
            Server {
                ip: met_ip(192, 168, 0, 5),
                port: 4661,
                tags: Vec::new(),
            },
            Server {
                ip: met_ip(10, 0, 0, 7),
                port: 4661,
                tags: Vec::new(),
            },
        ];
        std::fs::write(
            dir.join("server.met"),
            write_server_met(&ServerMet {
                header: mule_files::server_met::SERVER_MET_HEADER,
                servers,
            }),
        )
        .unwrap();

        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        let added = engine.crawl_servers(2).await;
        assert_eq!(added, 0);

        let evs = drain(&mut rx).await;
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::Server(s) if s.contains("asked 0 server"))),
            "a LAN/loopback-only list must yield ZERO asks; got {evs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ipfilter must gate who the crawl SENDS to, in HOST order. The
    /// filter was consulted with the raw met u32 - byte-REVERSED relative to
    /// the ranges `is_blocked_u32` holds - so a blocklisted server read as
    /// some unrelated address and was asked anyway: the same defect
    /// `merge_discovered_servers` carried until 2026-08-08, surviving at a
    /// third site. Asserted on the production entry point, like the SSRF test
    /// above: the progress line must report ZERO asks. The seed is in
    /// 198.18.0.0/15 (benchmarking): `is_routable_public_v4` accepts it, so
    /// it reaches the send gate, but the range is not routed on the real
    /// internet - a regression leaks a datagram into a black hole, not at a
    /// real host.
    #[tokio::test]
    async fn the_crawl_never_sends_to_a_blocklisted_server() {
        let dir = tmp("crawl-blocklist");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let met_ip = |a: u8, b: u8, c: u8, d: u8| u32::from_le_bytes([a, b, c, d]);
        std::fs::write(
            dir.join("server.met"),
            write_server_met(&ServerMet {
                header: mule_files::server_met::SERVER_MET_HEADER,
                servers: vec![Server {
                    ip: met_ip(198, 18, 0, 1),
                    port: 4661,
                    tags: Vec::new(),
                }],
            }),
        )
        .unwrap();

        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.ip_filter = Some(std::sync::Arc::new(IpFilter::parse(
            "198.18.0.0 - 198.18.255.255 , 0 , blocked\n",
            DEFAULT_IPFILTER_LEVEL,
        )));
        assert_eq!(engine.crawl_servers(1).await, 0);

        let evs = drain(&mut rx).await;
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::Server(s) if s.contains("asked 0 server"))),
            "a blocklisted server must not be sent a crawl ask; got {evs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The Servers-screen status probe must not ping a blocklisted PUBLIC
    /// server (the residual 8cq gap: an entry that predated the blocklist, or
    /// was hand-added, kept receiving probes). Same 198.18.0.0/15 benchmarking
    /// seed as the crawl test above: `is_routable_public_v4` accepts it, so it
    /// reaches the send gate, but a regression leaks the datagram into a black
    /// hole, not at a real host. Observable by TIMING, the same instrument as
    /// `the_probe_stops_as_soon_as_every_server_has_answered`: a gated server
    /// is neither pinged nor WAITED for, so the round returns at once - while
    /// an ungated, silent 198.18 target holds the round open for the full
    /// `PROBE_COLLECT_BUDGET`. The entry must still be LISTED (greyed out):
    /// gating the send must not hide the user's own server.met contents.
    #[tokio::test]
    async fn the_probe_never_pings_a_blocklisted_public_server() {
        let dir = tmp("probe-blocklist-public");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("server.met"),
            write_server_met(&ServerMet {
                header: mule_files::server_met::SERVER_MET_HEADER,
                servers: vec![Server {
                    ip: u32::from_le_bytes([198, 18, 0, 1]),
                    port: 4661,
                    tags: Vec::new(),
                }],
            }),
        )
        .unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.ip_filter = Some(std::sync::Arc::new(IpFilter::parse(
            "198.18.0.0 - 198.18.255.255 , 0 , blocked\n",
            DEFAULT_IPFILTER_LEVEL,
        )));

        let t0 = std::time::Instant::now();
        let rows = engine.probe_server_list().await;
        let elapsed = t0.elapsed();

        assert_eq!(rows.len(), 1, "the entry stays listed, just never pinged");
        assert!(!rows[0].alive);
        assert!(
            elapsed < PROBE_COLLECT_BUDGET / 3,
            "the probe took {elapsed:?} for a list that owes it nothing - it \
             is waiting on (so it must have pinged) a blocklisted public server"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The oracle case the public-only scoping exists for: a LOOPBACK server
    /// the user's community blocklist happens to cover (reserved-range
    /// boilerplate) must STILL be probed - scripts/eserver-oracle.sh and any
    /// LAN server the user added by hand live on exactly such addresses.
    /// Mutation check: drop the `is_routable_public_v4` qualifier from
    /// `blocklist_forbids_send` and this fails on the `alive` assertion.
    #[tokio::test]
    async fn the_probe_still_pings_a_blocklisted_loopback_server() {
        let dir = tmp("probe-blocklist-loopback");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // A mock server on loopback (probe pings TCP port + 4).
        let mock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
        let udp_port = mock.local_addr().unwrap().port();
        let tcp_port = udp_port - 4;
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, src)) = mock.recv_from(&mut buf).await else {
                    return;
                };
                if n < 2 || buf[1] != OP_GLOBSERVSTATREQ {
                    continue;
                }
                let mut res = vec![PROT_EDONKEY, OP_GLOBSERVSTATRES];
                res.extend_from_slice(&SERV_STAT_CHALLENGE.to_le_bytes());
                res.extend_from_slice(&7u32.to_le_bytes()); // users
                res.extend_from_slice(&9u32.to_le_bytes()); // files
                let _ = mock.send_to(&res, src).await;
            }
        });

        std::fs::write(
            dir.join("server.met"),
            write_server_met(&ServerMet {
                header: mule_files::server_met::SERVER_MET_HEADER,
                servers: vec![Server {
                    ip: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                    port: tcp_port,
                    // A name on file, so the round owes only the status answer.
                    tags: vec![mule_proto::Tag::id(
                        0x01,
                        mule_proto::TagValue::Str(b"oracle".to_vec()),
                    )],
                }],
            }),
        )
        .unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.ip_filter = Some(std::sync::Arc::new(IpFilter::parse(
            "127.0.0.0 - 127.255.255.255 , 0 , reserved-range boilerplate\n",
            DEFAULT_IPFILTER_LEVEL,
        )));

        let rows = engine.probe_server_list().await;
        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].alive,
            "a blocklisted LOOPBACK server must still be probed - the \
             blocklist send gate is scoped to publicly routable targets"
        );
        assert_eq!(rows[0].users, Some(7));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A mock global-search server on loopback: answers OP_GLOBSEARCHREQ with
    /// one OP_GLOBSEARCHRES record (`hash` repeated 16x, tagcount 0). Returns
    /// the TCP port to write into server.met (the fan-out sends to TCP + 4).
    async fn spawn_global_search_mock(hash: u8) -> u16 {
        let mock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
        let tcp_port = mock.local_addr().unwrap().port() - 4;
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                let Ok((n, src)) = mock.recv_from(&mut buf).await else {
                    return;
                };
                if n < 2 || buf[0] != PROT_EDONKEY || buf[1] != crate::search::OP_GLOBSEARCHREQ {
                    continue;
                }
                let mut res = vec![PROT_EDONKEY, OP_GLOBSEARCHRES];
                res.extend_from_slice(&[hash; 16]);
                res.extend_from_slice(&1u32.to_le_bytes()); // client id
                res.extend_from_slice(&4662u16.to_le_bytes()); // client port
                res.extend_from_slice(&0u32.to_le_bytes()); // tagcount
                let _ = mock.send_to(&res, src).await;
            }
        });
        tcp_port
    }

    /// The oracle case for the GLOBAL SEARCH fan-out: a loopback server the
    /// community blocklist happens to cover must still be queried - the send
    /// gate is scoped to publicly routable targets. Mutation check: drop the
    /// `is_routable_public_v4` qualifier from `blocklist_forbids_send` and the
    /// hit disappears.
    #[tokio::test]
    async fn a_global_search_still_queries_a_blocklisted_loopback_server() {
        let dir = tmp("global-blocklist-loopback");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tcp_port = spawn_global_search_mock(0x5A).await;
        std::fs::write(
            dir.join("server.met"),
            write_server_met(&ServerMet {
                header: mule_files::server_met::SERVER_MET_HEADER,
                servers: vec![Server {
                    ip: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                    port: tcp_port,
                    tags: Vec::new(),
                }],
            }),
        )
        .unwrap();
        let filter = IpFilter::parse(
            "127.0.0.0 - 127.255.255.255 , 0 , reserved-range boilerplate\n",
            DEFAULT_IPFILTER_LEVEL,
        );
        let params = SearchParams {
            keyword: "x".into(),
            ..Default::default()
        };
        let out = global_udp_search(
            &dir,
            &params,
            None,
            Some(&filter),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(
            out.len(),
            1,
            "the blocklisted LOOPBACK server must still be asked and answer"
        );
        assert_eq!(out[0].hash, [0x5A; 16]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A blocklisted PUBLIC server gets NO global-search datagram. Proven
    /// through the fan-out's own pacing: five blocklisted 198.18.x entries sit
    /// AHEAD of a loopback mock in server.met. Gated, they cost nothing and
    /// the mock is asked at once (its hit arrives inside the 500ms budget);
    /// ungated, each costs a 200ms pace sleep - a full second for five - so
    /// the send loop hits its deadline before ever reaching the mock and the
    /// hit vanishes. (Under a regression the leaked datagrams go to
    /// 198.18.0.0/15, the unrouted benchmarking range - the same black-hole
    /// convention as the crawl's blocklist test.)
    #[tokio::test]
    async fn a_global_search_never_sends_to_a_blocklisted_public_server() {
        let dir = tmp("global-blocklist-public");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let tcp_port = spawn_global_search_mock(0x6B).await;
        let mut servers: Vec<Server> = (1..=5u8)
            .map(|d| Server {
                ip: u32::from_le_bytes([198, 18, 0, d]),
                port: 4661,
                tags: Vec::new(),
            })
            .collect();
        servers.push(Server {
            ip: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
            port: tcp_port,
            tags: Vec::new(),
        });
        std::fs::write(
            dir.join("server.met"),
            write_server_met(&ServerMet {
                header: mule_files::server_met::SERVER_MET_HEADER,
                servers,
            }),
        )
        .unwrap();
        let filter = IpFilter::parse(
            "198.18.0.0 - 198.18.255.255 , 0 , blocked\n",
            DEFAULT_IPFILTER_LEVEL,
        );
        let params = SearchParams {
            keyword: "x".into(),
            ..Default::default()
        };
        let out = global_udp_search(
            &dir,
            &params,
            None,
            Some(&filter),
            Duration::from_millis(500),
        )
        .await;
        assert_eq!(
            out.len(),
            1,
            "five gated entries must cost the fan-out nothing - a paced send \
             to any of them starves the un-blocklisted mock past the budget"
        );
        assert_eq!(out[0].hash, [0x6B; 16]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Offline means offline: no socket, no datagrams, no crawl.
    #[tokio::test]
    async fn a_crawl_is_a_no_op_when_offline() {
        let dir = tmp("crawl-offline");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("server.met"),
            write_server_met(&ServerMet {
                header: mule_files::server_met::SERVER_MET_HEADER,
                servers: vec![Server {
                    ip: u32::from_le_bytes([85, 17, 116, 222]),
                    port: 4242,
                    tags: Vec::new(),
                }],
            }),
        )
        .unwrap();
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        assert_eq!(engine.crawl_servers(2).await, 0);
        let evs = drain(&mut rx).await;
        assert!(
            !evs.iter()
                .any(|e| matches!(e, EngineEvent::Server(s) if s.contains("Crawl"))),
            "an offline crawl must not even report; got {evs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The forwarder's flood limiter protects the unbounded UI channel; it must
    /// NOT discard the gossip payload. Once padMule ASKS for the list
    /// (OP_GETSERVERLIST), the OP_SERVERLIST answer arrives inside the busy
    /// connect burst - exactly when the window is most likely to be spent - and
    /// dropping it there silently re-inerts the whole harvest.
    #[tokio::test]
    async fn a_flooded_event_window_does_not_drop_the_harvest() {
        let dir = tmp("harvest-flood");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        let tx = engine.server_sender();
        // Spend the whole 30-events/10s window on message spam...
        for i in 0..40u32 {
            tx.send(ServerEvent::Message(format!("spam {i}")))
                .await
                .unwrap();
        }
        // ...then deliver the gossip. The UI event may be dropped; the stash
        // must not be.
        tx.send(ServerEvent::ServerList(vec![(
            u32::from_le_bytes([85, 17, 116, 222]),
            4242,
        )]))
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(
            !engine.harvested_servers.lock().unwrap().is_empty(),
            "the ServerList payload must be stashed even while the UI flood \
             limiter is dropping events"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A user with no server and no Kad must be told THEY are not connected, not
    /// that the file is unavailable. The old code could only ever say the latter:
    /// `NoServer` fired solely under `offline`, which the FFI never exports, so
    /// every disconnected user was told "No one online has X right now" and sent
    /// hunting for a different file.
    #[tokio::test]
    async fn a_disconnected_client_is_told_it_is_disconnected_not_that_the_file_is_gone() {
        let dir = tmp("not-connected");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        // No server, no Kad contacts - and NOT the offline test flag, because that
        // is the path the shipped app can never take.
        assert!(!engine.can_discover());
        assert!(
            matches!(
                engine.add_download([0x11; 16], 1024, "whatever.bin").await,
                AddResult::NotConnected
            ),
            "with no discovery channel the answer must be about US, not the file"
        );

        // With a channel, the same call is free to report a genuine NoSources -
        // asserted here only as far as it does NOT claim we are disconnected.
        engine.routing.load_nodes(&[KadContact {
            id: Kad128::from_hash(&[0x77; 16]),
            ip: 0x0808_0808,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            verified: true,
        }]);
        assert!(
            engine.can_discover(),
            "a Kad contact IS a discovery channel"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The UI asks this before telling the user their port was handed back, so it
    /// must be false for everyone who never had a mapping - cellular, CGNAT, or a
    /// router without UPnP. Claiming otherwise would be the UI lying about work
    /// that never happened.
    #[test]
    fn has_port_mapping_reports_whether_one_is_actually_held() {
        let dir = tmp("has-mapping");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (engine, _rx) = Engine::new(&dir).unwrap();

        assert!(
            !engine.has_port_mapping(),
            "a client that never mapped a port must not be told one was released"
        );
        *engine.public_ip.lock().unwrap() = Some(std::net::Ipv4Addr::new(203, 0, 113, 5));
        assert!(engine.has_port_mapping());
        *engine.public_ip.lock().unwrap() = None; // what release does on success
        assert!(!engine.has_port_mapping());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The periodic checkpoint must fire when it is DUE and stay quiet when it is
    /// not - an unconditional write on the 1s heartbeat would hammer the disk.
    #[tokio::test]
    async fn the_periodic_checkpoint_fires_only_when_due() {
        let dir = tmp("periodic-ckpt");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        engine.state = EngineState::Running;

        let nodes = dir.join("nodes.dat");
        let _ = std::fs::remove_file(&nodes);

        // Just started: not due, so nothing is written.
        engine.maintain_checkpoint().await;
        assert!(
            !nodes.exists(),
            "a fresh engine must not checkpoint on every heartbeat"
        );

        // Due: it writes.
        engine.last_checkpoint = Instant::now() - CHECKPOINT_EVERY - Duration::from_secs(1);
        engine.maintain_checkpoint().await;
        assert!(nodes.exists(), "an overdue checkpoint must write");

        // ...and the timer resets, so the next heartbeat is quiet again.
        std::fs::remove_file(&nodes).unwrap();
        engine.maintain_checkpoint().await;
        assert!(!nodes.exists(), "the timer must reset after a checkpoint");

        // It is also inert unless RUNNING - pause/shutdown own those boundaries.
        engine.state = EngineState::Paused;
        engine.last_checkpoint = Instant::now() - CHECKPOINT_EVERY - Duration::from_secs(1);
        engine.maintain_checkpoint().await;
        assert!(!nodes.exists(), "a paused engine must not checkpoint again");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// REPLACING the live node must not throw away what the outgoing one learned.
    ///
    /// No caller does this today (both `start_kad` callers run with `self.kad`
    /// already None), so this pins the INVARIANT rather than a live bug: the rule
    /// is now enforced by `set_kad` instead of remembered at each call site,
    /// because forgetting it at exactly one site is what silently lost a whole
    /// session's contacts and verify keys.
    #[tokio::test]
    async fn replacing_the_kad_node_keeps_what_the_outgoing_one_learned() {
        use crate::kad_live::KadNode;

        let dir = tmp("kad-replace");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        let learned = KadContact {
            id: Kad128::from_hash(&[0xE5; 16]),
            ip: 0x0D0D_0D0D,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0xABCD_1234,
            udp_key_ip: 0x0404_0404,
            verified: true,
        };
        let outgoing = KadNode::bind("127.0.0.1:0".parse().unwrap(), 4662)
            .await
            .unwrap();
        outgoing.with_routing(|t| t.load_nodes(std::slice::from_ref(&learned)));
        engine.set_kad(Some(outgoing));

        // A fresh node replaces it, as a re-bootstrap would.
        let replacement = KadNode::bind("127.0.0.1:0".parse().unwrap(), 4662)
            .await
            .unwrap();
        engine.set_kad(Some(replacement));

        let kept = routing_to_nodes(&engine.routing)
            .into_iter()
            .find(|c| c.id == learned.id)
            .expect("the outgoing node's contact must have been absorbed");
        assert_eq!(kept.udp_key, 0xABCD_1234, "and its verify key with it");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The REAL `pause()` path must persist what the live Kad node learned.
    ///
    /// The first version of this fix added the union inside `checkpoint_contacts`
    /// and was proven only by calling that helper directly - which MISSED that
    /// `pause()` sets `self.kad = None` BEFORE it calls `checkpoint()`, so on the
    /// one path that matters most on iPadOS the helper was handed `None` and the
    /// stale snapshot was written anyway. This test drives `pause()` itself and
    /// reads the nodes.dat that lands on disk, so it cannot be fooled the same way.
    #[tokio::test]
    async fn pause_persists_what_the_live_kad_node_learned() {
        use crate::kad_live::KadNode;
        use mule_files::read_nodes_dat;

        let dir = tmp("pause-kad-persist");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        // A live node holding a contact the persisted table has never seen, with
        // the verify key a real session would have captured from its response.
        let learned = KadContact {
            id: Kad128::from_hash(&[0xC3; 16]),
            ip: 0x0B0B_0B0B,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0x1234_5678,
            udp_key_ip: 0x0202_0202,
            verified: true,
        };
        let node = KadNode::bind("127.0.0.1:0".parse().unwrap(), 4662)
            .await
            .unwrap();
        node.with_routing(|t| t.load_nodes(std::slice::from_ref(&learned)));
        engine.kad = Some(node);
        engine.state = EngineState::Running;

        engine.pause().await;

        let bytes = std::fs::read(dir.join("nodes.dat")).expect("pause must write nodes.dat");
        let nd = read_nodes_dat(&bytes).expect("valid nodes.dat");
        let got = nd
            .contacts
            .iter()
            .find(|c| c.id == learned.id)
            .unwrap_or_else(|| {
                panic!(
                    "the contact learned this session is missing from nodes.dat: {:?}",
                    nd.contacts
                )
            });
        assert_eq!(got.udp_key, 0x1234_5678, "its verify key must persist too");
        assert!(got.verified, "its verified bit must persist too");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A local mock eD2k server that answers a login with a HighID IDCHANGE
    /// (same shape as the one in link.rs, kept local to this test module).
    async fn spawn_mock_login_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut sfs = crate::framed::FramedStream::new(sock);
                    if sfs.read_packet().await.is_err() {
                        return;
                    }
                    let _ = sfs
                        .write_packet(&mule_proto::Packet::new(
                            mule_proto::PROT_EDONKEY,
                            crate::server_messages::OP_IDCHANGE,
                            0x0A00_0001u32.to_le_bytes().to_vec(),
                        ))
                        .await;
                    let _ = sfs.read_packet().await;
                });
            }
        });
        addr
    }

    /// ...and the split must be asserted ON THE WIRE, not just on the struct.
    /// A mutation that made the login advertise the BIND port instead of the
    /// ADVERTISED one passed the whole suite: everything still binds and
    /// connects locally, while every real peer would dial a port nothing is
    /// listening on. The login request carries it at a fixed offset
    /// (userhash 16 | client_id 4 | tcp_port 2), so read it back.
    #[tokio::test]
    async fn the_login_tells_the_server_our_advertised_port() {
        let dir = tmp("advertised-port");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        // The VPN shape: bind locally on 4662, but the provider forwards 51234.
        engine.set_ports(4662, 51234, 4672, 4672);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<std::sync::Mutex<Option<u16>>> = Arc::new(std::sync::Mutex::new(None));
        let rec = seen.clone();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                let mut sfs = crate::framed::FramedStream::new(sock);
                if let Ok(p) = sfs.read_packet().await {
                    if p.payload.len() >= 22 {
                        *rec.lock().unwrap() =
                            Some(u16::from_le_bytes([p.payload[20], p.payload[21]]));
                    }
                }
                let _ = sfs
                    .write_packet(&mule_proto::Packet::new(
                        mule_proto::PROT_EDONKEY,
                        crate::server_messages::OP_IDCHANGE,
                        0x0A00_0001u32.to_le_bytes().to_vec(),
                    ))
                    .await;
                while sfs.read_packet().await.is_ok() {}
            }
        });

        assert!(
            engine.connect_to_server(addr).await,
            "mock login should win"
        );
        let port = seen.lock().unwrap().expect("the server saw a login");
        assert_eq!(
            port, 51234,
            "the server must be told the port the PROVIDER forwards, not the one we bind"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A HighID client id IS our public address, so a CHANGE in it between two
    /// logins means our traffic is leaving by a different route than before -
    /// most importantly, a VPN tunnel that dropped. Stock iOS has no kill
    /// switch, so padMule would otherwise keep seeding from the real address
    /// with nothing on screen to say so. Sharing is therefore paused and the
    /// user is warned LOUDLY.
    ///
    /// PRIVACY: the address is compared internally and NEVER emitted - the
    /// event carries no payload at all, for the same reason `connect_to_server`
    /// refuses to record the client id in any user-visible text.
    /// The publish duty is GATED: it runs nothing while stopped, while paused,
    /// or while sharing is off - the same "only when we mean it" discipline the
    /// seeding/VPN work follows. The open arms give the engine a real (loopback)
    /// Kad node holding one seeded contact, because Kad availability now gates
    /// BEFORE the cadence stamp; with no shared files the duty then stamps,
    /// finds nothing due and returns 0 without any I/O. The gate is proven by
    /// watching `last_kad_publish` NOT advance when gated and advance when open.
    #[tokio::test]
    async fn the_publish_duty_runs_only_while_running_or_seeding_and_sharing() {
        let dir = tmp("kad-publish-gate");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        // Every pass below is gated or idle (nothing is ever shared), so the
        // publish JOBS counter must not move across the whole test - a job is
        // counted only when one is actually popped. Held across the
        // measurement per STATS_TEST_LOCK's rule.
        let _stats = crate::stats::STATS_TEST_LOCK.lock();
        let (jobs0, _) = crate::stats::kad_publish_counts();

        // Stopped: gated. Back-date the cadence so only the STATE gate can stop
        // it, and confirm the clock did not advance (the duty returned early).
        let old = Instant::now() - KAD_PUBLISH_EVERY * 2;
        engine.last_kad_publish = old;
        engine.maintain_kad_publish().await;
        assert_eq!(
            engine.last_kad_publish, old,
            "a stopped engine does not even reach the cadence stamp"
        );

        // Running but sharing OFF: still gated.
        engine.state = EngineState::Running;
        engine.set_sharing(false);
        engine.last_kad_publish = old;
        engine.maintain_kad_publish().await;
        assert_eq!(engine.last_kad_publish, old, "Leech Mode publishes nothing");

        // A live node with one contact, so the availability guard passes and
        // the open arms reach the cadence stamp. No shared files, so no job is
        // ever built and nothing goes out the socket.
        let mut node = KadNode::bind("127.0.0.1:0".parse().unwrap(), 4662)
            .await
            .unwrap();
        node.seed_routing(&[KadContact {
            id: Kad128::from_hash(&[0x42; 16]),
            ip: 0x0808_0404, // routable public, so the gated insert keeps it
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            verified: true,
        }]);
        engine.kad = Some(node);

        // Running AND sharing: the gate opens (the cadence stamp advances even
        // though nothing is shared, so no actual store happens).
        engine.set_sharing(true);
        engine.last_kad_publish = old;
        engine.maintain_kad_publish().await;
        assert!(
            engine.last_kad_publish > old,
            "running + sharing reaches the scheduler"
        );

        // Seeding is ADMITTED by the state gate - and LIVE in production
        // since 2026-08-09, when `pause_for_seeding` stopped dropping the
        // node. This arm pins only the admission; the real-work half (a job
        // popped through a node that survived the seeding boundary) is
        // `kad_publishing_pops_a_real_job_while_seeding`.
        engine.state = EngineState::Seeding;
        engine.last_kad_publish = old;
        engine.maintain_kad_publish().await;
        assert!(
            engine.last_kad_publish > old,
            "the state gate must admit Seeding - background seeds republish now"
        );

        let (jobs1, _) = crate::stats::kad_publish_counts();
        assert_eq!(
            jobs0, jobs1,
            "an idle pass (nothing due) counted a publish job - the panel \
             would claim publish traffic that never existed"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A pass that CANNOT publish must CONSUME nothing. `refill` stamps the
    /// 5h/24h republish clocks AT ENQUEUE (kad_publish.rs), so a pass that
    /// refilled, popped a job and only then noticed there was no Kad node had
    /// marked work "published" that never left the box - a seeding session
    /// (which, until the node started surviving `pause_for_seeding` on
    /// 2026-08-09, always had `kad: None`) burned its whole due set at one
    /// job per 10s and nothing republished for up to 5h/24h after returning
    /// to Running. Kad-less passes still happen (before `start_kad`, after a
    /// failed bind), so the Kad-availability guards must keep running BEFORE
    /// the cadence stamp and the refill.
    #[tokio::test]
    async fn a_publish_pass_without_kad_consumes_no_schedule_state() {
        let dir = tmp("kad-publish-no-kad");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.state = EngineState::Running;
        engine.set_sharing(true);
        // A shared file whose name yields several keywords, so a burning pass
        // (refill all, pop one) would leave pending() > 0 - discriminating.
        engine.shared.lock().await.push(SharedFile {
            hash: [0xAA; 16],
            size: 10,
            name: b"ubuntu iso image.bin".to_vec(),
            part_hashes: vec![],
            path: dir.join("ubuntu iso image.bin"),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        });
        let old = Instant::now() - KAD_PUBLISH_EVERY * 2;
        engine.last_kad_publish = old;
        assert!(engine.kad.is_none(), "precondition: no Kad node");
        // The publish JOBS counter must not move either: this pass has DUE
        // work but is gated, and counting a job here would let the Stats
        // panel claim publish traffic that never left the box. Held across
        // the measurement per STATS_TEST_LOCK's rule.
        let _stats = crate::stats::STATS_TEST_LOCK.lock();
        let (jobs0, _) = crate::stats::kad_publish_counts();
        engine.maintain_kad_publish().await;
        let (jobs1, _) = crate::stats::kad_publish_counts();
        assert_eq!(
            jobs0, jobs1,
            "a gated pass (no Kad node) counted a publish job"
        );
        assert_eq!(
            engine.last_kad_publish, old,
            "no Kad node: the pass did nothing, so the cadence must not stamp"
        );
        assert_eq!(
            engine.publish_schedule.pending(),
            0,
            "no Kad node: nothing may be enqueued (refill stamps the clocks)"
        );
        // And the republish clocks really were untouched: a refill NOW must
        // still consider every keyword job due. A burned pass fails this
        // either way - the queue still holds the un-popped jobs (refill is a
        // no-op on a non-empty queue), and its clocks read freshly stamped.
        let words = mule_kad::kad_keywords("ubuntu iso image.bin");
        engine.publish_schedule.refill(
            u64::from(now_secs()),
            &[([0xAA; 16], words.clone())],
            false,
        );
        assert_eq!(
            engine.publish_schedule.pending(),
            words.len(),
            "the clocks were stamped by a pass that published nothing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A called-back source must not drive a row the UI reports as Queued or
    /// Paused - the admission decision the listener's `InboundKind::Source`
    /// arm feeds. DISCLOSED LIMIT: the listener seam itself (a real silent
    /// inbound connection classified as Source) is not driven offline; this
    /// pins the decision function, and the arm's use of it is by reading.
    /// The fixtures discriminate ORDER deliberately (the project's tautology
    /// lesson): a paused first row must not consume the one slot.
    #[test]
    fn a_called_back_source_may_not_drive_queued_or_paused_rows() {
        // cap 1, add order: active, active, paused, complete. Only the first
        // active row is admitted; the second is queued and NOT driven.
        assert_eq!(
            callback_drive_flags(
                1,
                &[
                    (false, false, false),
                    (false, false, false),
                    (true, false, false),
                    (false, true, false)
                ]
            ),
            vec![true, false, false, false],
            "the second active row is past the cap and must not be driven"
        );
        // Ordering discriminator: a PAUSED first row consumes no slot, so the
        // SECOND row is the admitted one. An implementation that just took
        // the first row - or ignored the queued flags - fails here.
        assert_eq!(
            callback_drive_flags(
                1,
                &[
                    (true, false, false),
                    (false, false, false),
                    (false, false, false)
                ]
            ),
            vec![false, true, false],
            "a paused row must neither be driven nor consume the slot"
        );
        // RECEIVING discriminator (the 2026-08-09 rule): the younger row that
        // is pulling bytes holds the one slot, so a dial-back may drive IT
        // and not the older idle row - under plain add order this inverts.
        assert_eq!(
            callback_drive_flags(1, &[(false, false, false), (false, false, true)]),
            vec![false, true],
            "the receiving row keeps the slot; the older idle row is queued"
        );
        // cap 0 = unlimited: every active row may be driven.
        assert_eq!(
            callback_drive_flags(0, &[(false, false, false), (false, false, false)]),
            vec![true, true]
        );
    }

    /// eMule 0.70b `PauseFile`/`ResumeFile` through the ENGINE API: the flag
    /// flips, persists via FT_STATUS, and a store re-opened from disk comes
    /// back paused - the restart behaviour a 0.70b user expects.
    #[tokio::test]
    async fn pause_download_persists_and_a_reopened_store_comes_back_paused() {
        let dir = tmp("pause-persist");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        let hash = [0x42u8; 16];
        let store = crate::part_store::PartStore::create(&dir, 1, hash, 500, b"x.bin").unwrap();
        let dl = Download::new(store);
        engine.downloads.lock().await.push(Arc::clone(&dl));

        assert!(engine.pause_download(hash).await, "the download is found");
        assert!(dl.is_paused());
        let reopened = crate::part_store::PartStore::open(&dir, 1).unwrap();
        assert!(reopened.paused, "FT_STATUS persisted the pause");
        assert!(
            Download::new(reopened).is_paused(),
            "a restart's Download comes back paused"
        );
        assert!(engine.resume_download(hash).await);
        assert!(!dl.is_paused());
        assert!(
            !engine.pause_download([0xEE; 16]).await,
            "an unknown hash reports false"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The max-active cap through the PRODUCTION retry sweep: with cap 1 and
    /// two registered downloads, the sweep picks only the FIRST (stamps its
    /// retry clock); pausing the first ADMITS the second on the next pass.
    /// Promotion is a recompute, not an event - `queued_flags` in add order.
    #[tokio::test]
    async fn the_max_active_cap_gates_the_retry_sweep_and_pausing_promotes() {
        let dir = tmp("max-active");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.state = EngineState::Running;
        let d1 = Download::new(
            crate::part_store::PartStore::create(&dir, 1, [1; 16], 500, b"a.bin").unwrap(),
        );
        let d2 = Download::new(
            crate::part_store::PartStore::create(&dir, 2, [2; 16], 500, b"b.bin").unwrap(),
        );
        engine.downloads.lock().await.push(Arc::clone(&d1));
        engine.downloads.lock().await.push(Arc::clone(&d2));
        engine.set_max_active_downloads(1);

        // Back-date the cadence gate. The monotonic clock cannot be
        // back-dated on a host up under a minute - PANIC rather than let the
        // gate false-pass the test silently (that would be a fake green).
        let back_dated = || {
            Instant::now()
                .checked_sub(Duration::from_secs(60))
                .expect("host uptime under 60s - rerun this test")
        };
        engine.last_resume_retry = back_dated();
        engine.maintain_resume_fetches().await;
        assert!(d1.last_retry_at() > 0, "the first drivable row is retried");
        assert_eq!(d2.last_retry_at(), 0, "past the cap: queued, not retried");

        // The SECOND sweep is the discriminating one, and the first draft of
        // this test did not have it: sweep 1 picks d1 by the fair-rotation
        // order whether or not the cap gate exists, so a mutant that ignored
        // `queued` still passed. Rotation now WANTS d2 (least recently
        // retried); only the cap gate keeps refusing it.
        engine.last_resume_retry = back_dated();
        engine.maintain_resume_fetches().await;
        assert_eq!(
            d2.last_retry_at(),
            0,
            "rotation would pick d2 next - only the cap gate refuses it"
        );

        d1.set_paused(true).await;
        engine.last_resume_retry = back_dated();
        engine.maintain_resume_fetches().await;
        assert!(
            d2.last_retry_at() > 0,
            "pausing the first admits the second - promotion by recompute"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE 2026-08-09 ON-GLASS DEFECT through the production retry sweep:
    /// cap 1, the OLDER row (d1) resumed from pause must not preempt the
    /// YOUNGER row (d2) that is actively receiving; once d2 goes STALE its
    /// slot releases and d1 is admitted on the next recompute.
    ///
    /// Ordering trap, named: in BOTH discriminating sweeps the fair rotation
    /// (least recently retried) AND plain add order want d1 - its retry
    /// clock is 0 and it is first in the registry - so no assertion here can
    /// go green by rotation or add order alone. A mutant that ignores
    /// `receiving` hands d1 the slot in sweep 1 (first assertion red); a
    /// mutant that ignores the STALENESS WINDOW (receiving = "ever received")
    /// keeps d2 protected forever and refuses d1 in sweep 2 (last assertion
    /// red).
    #[tokio::test]
    async fn a_receiving_row_keeps_its_slot_and_releases_it_when_stale() {
        let dir = tmp("keep-slot");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.state = EngineState::Running;
        let d1 = Download::new(
            crate::part_store::PartStore::create(&dir, 1, [1; 16], 500, b"a.bin").unwrap(),
        );
        let d2 = Download::new(
            crate::part_store::PartStore::create(&dir, 2, [2; 16], 500, b"b.bin").unwrap(),
        );
        engine.downloads.lock().await.push(Arc::clone(&d1));
        engine.downloads.lock().await.push(Arc::clone(&d2));
        engine.set_max_active_downloads(1);
        // d1 (older) paused by the user; d2 promoted into the slot and
        // RECEIVING - the stamp comes from the production commit path.
        d1.set_paused(true).await;
        d2.commit(0, &[0xAB; 8], None).await.unwrap();

        let back_dated = || {
            Instant::now()
                .checked_sub(Duration::from_secs(60))
                .expect("host uptime under 60s - rerun this test")
        };
        // RESUME the older row: it must NOT take the slot back.
        d1.set_paused(false).await;
        engine.last_resume_retry = back_dated();
        engine.maintain_resume_fetches().await;
        assert_eq!(
            d1.last_retry_at(),
            0,
            "the resumed OLDER row must not preempt the receiving one"
        );
        assert!(
            d2.last_retry_at() > 0,
            "the receiving row holds the slot (and is the only retry candidate)"
        );

        // d2 goes STALE: no bytes for the whole window. Its slot releases on
        // the next recompute and add order admits the older waiter.
        d2.set_last_byte_at(
            u64::from(now_secs()).saturating_sub(crate::multi_source::SLOT_KEEP_WINDOW_SECS + 1),
        );
        engine.last_resume_retry = back_dated();
        engine.maintain_resume_fetches().await;
        assert!(
            d1.last_retry_at() > 0,
            "a stale row releases its slot - the waiting row is admitted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_changed_public_address_pauses_sharing_and_warns() {
        let dir = tmp("ip-change");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        assert!(engine.is_sharing(), "sharing is on by default");

        // First HighID login: nothing to compare against yet.
        engine.note_public_id(0x0102_0304, false);
        assert!(
            engine.is_sharing(),
            "the first login must not trip the guard"
        );
        assert!(!engine.sharing_paused_for_ip_change());

        // Same address again (a reconnect to the same server): still fine.
        engine.note_public_id(0x0102_0304, false);
        assert!(engine.is_sharing(), "an unchanged address is not a leak");

        // A LowID login tells us nothing about our public address, so it must
        // neither trip the guard nor overwrite what we knew.
        engine.note_public_id(7, true);
        assert!(engine.is_sharing(), "LowID carries no public address");

        // The address changed -> the tunnel may have dropped.
        engine.note_public_id(0x0506_0708, false);
        assert!(!engine.is_sharing(), "sharing must be paused");
        assert!(engine.sharing_paused_for_ip_change());

        let evs = drain_sync(&mut rx);
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::PublicAddressChanged)),
            "a loud, payload-free warning must reach the UI; got {evs:?}"
        );
        for e in &evs {
            if let EngineEvent::Server(t) | EngineEvent::Status(t) = e {
                assert!(
                    !t.contains("1.2.3.4") && !t.contains("5.6.7.8"),
                    "the address must never reach a user-visible string: {t}"
                );
            }
        }

        // The user turning sharing back on clears the latch - otherwise the
        // warning state would be permanent for the session.
        engine.set_sharing(true);
        assert!(!engine.sharing_paused_for_ip_change());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...and the guard must run on the REAL login path, not merely as a helper.
    /// A mock server that hands out a DIFFERENT HighID on the second connect is
    /// the exact shape of a tunnel dropping between sessions.
    #[tokio::test]
    async fn a_reconnect_with_a_different_high_id_pauses_sharing() {
        let dir = tmp("ip-change-live");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();

        // Hands out id 0x0A000001 first, then 0x0B000002 - two different public
        // addresses, as a dropped tunnel would produce.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let ids = [0x0A00_0001u32, 0x0B00_0002u32];
            let mut n = 0usize;
            while let Ok((sock, _)) = listener.accept().await {
                let id = ids[n.min(ids.len() - 1)];
                n += 1;
                tokio::spawn(async move {
                    let mut sfs = crate::framed::FramedStream::new(sock);
                    if sfs.read_packet().await.is_err() {
                        return;
                    }
                    let _ = sfs
                        .write_packet(&mule_proto::Packet::new(
                            mule_proto::PROT_EDONKEY,
                            crate::server_messages::OP_IDCHANGE,
                            id.to_le_bytes().to_vec(),
                        ))
                        .await;
                    while sfs.read_packet().await.is_ok() {}
                });
            }
        });

        assert!(engine.connect_to_server(addr).await);
        assert!(engine.is_sharing(), "first login: nothing to compare");
        let _ = drain(&mut rx).await;

        assert!(engine.connect_to_server(addr).await);
        assert!(
            !engine.is_sharing(),
            "a different public address on reconnect must pause sharing"
        );
        assert!(engine.sharing_paused_for_ip_change());
        let evs = drain(&mut rx).await;
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::PublicAddressChanged)),
            "and warn; got {evs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...and THE PAUSE SURVIVES A RELAUNCH. The guard's whole premise is that
    /// the USER decides when to resume - but the pause was an in-memory latch
    /// while the sharing preference (UserDefaults, pushed at every boot) stays
    /// ON, so process death dropped the latch and the next launch silently
    /// resumed serving from the address the user did not choose. Observed on
    /// glass 2026-08-09 (a VPN recycle, then an app relaunch). This is the
    /// "an event is not state" family again, in its worst placement.
    ///
    /// Four launches: trip the guard; relaunch (still paused, still says WHY,
    /// through the lock-free handle the UI polls); an unrelated OFF push (the
    /// metered pause) must not eat the persisted reason; the user resumes;
    /// a later relaunch comes back sharing normally (not sticky-forever).
    #[test]
    fn the_ip_change_pause_survives_a_relaunch_until_the_user_resumes() {
        let dir = tmp("ip-pause-relaunch");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Launch 1: the guard fires.
        let (mut e1, _rx1) = Engine::new(&dir).unwrap();
        e1.note_public_id(0x0102_0304, false);
        e1.note_public_id(0x0506_0708, false);
        assert!(!e1.is_sharing(), "precondition: the guard paused sharing");
        drop(e1);

        // Launch 2: the pause is back BEFORE any preference push. is_sharing()
        // is the very atomic the upload listener and the Kad publish gate
        // read, so this is the "correct from the first moment" property.
        let (mut e2, _rx2) = Engine::new(&dir).unwrap();
        assert!(
            !e2.is_sharing(),
            "a relaunch after the guard fired must come back with sharing OFF"
        );
        assert!(
            e2.sharing_paused_for_ip_change(),
            "...and still able to say WHY"
        );
        assert!(
            e2.handles().sharing_paused_for_ip_change(),
            "the lock-free handle the UI boot-reads and polls must agree"
        );
        // An OFF push (the metered auto-pause, or a leech-mode preference) is
        // NOT the user resuming: it must not clear the persisted pause.
        e2.set_sharing(false);
        drop(e2);
        let (mut e3, _rx3) = Engine::new(&dir).unwrap();
        assert!(
            e3.sharing_paused_for_ip_change(),
            "an unrelated OFF push must not clear the persisted pause"
        );

        // The user resumes: the persisted pause goes with the latch...
        e3.set_sharing(true);
        assert!(e3.is_sharing());
        assert!(!e3.sharing_paused_for_ip_change());
        drop(e3);

        // ...so a later, unrelated relaunch does NOT re-pause.
        let (e4, _rx4) = Engine::new(&dir).unwrap();
        assert!(
            e4.is_sharing(),
            "after the user resumes, a relaunch must not re-pause"
        );
        assert!(!e4.sharing_paused_for_ip_change());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Drain without awaiting (the sender is synchronous here).
    fn drain_sync(rx: &mut mpsc::UnboundedReceiver<EngineEvent>) -> Vec<EngineEvent> {
        let mut out = Vec::new();
        while let Ok(e) = rx.try_recv() {
            out.push(e);
        }
        out
    }

    /// VPN readiness: the port we ADVERTISE and the port we BIND are different
    /// facts. A provider that forwards an assigned remote port to a different
    /// local one (AirVPN allows exactly that) means peers must be told the
    /// EXTERNAL port while we listen on the local one - and getting it wrong is
    /// invisible on this box, because everything still binds and connects
    /// locally while every real peer dials a port nothing is listening on.
    #[test]
    fn ports_default_to_ed2k_and_can_be_split_for_a_vpn() {
        let dir = tmp("ports");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        // Untouched, padMule is a stock eD2k client.
        assert_eq!(engine.listen_port, 4662);
        assert_eq!(engine.advertised_port, 4662);
        assert_eq!(engine.kad_port, 4672);
        assert_eq!(engine.kad_advertised_port, 4672, "same-port by default");
        assert!(engine.upnp_enabled, "UPnP is on by default (home router)");

        // The VPN shape: the provider forwards remote 51234 to our local 4662.
        // Kad gets the SAME split - it used to be one value for both bind and
        // advertise, so a remap left padMule binding the local port correctly
        // and then telling every peer to dial it, while the forward only existed
        // on the remote one. Inbound Kad died silently while everything outbound
        // kept working, which is the hardest shape to notice.
        engine.set_ports(4662, 51234, 4672, 51235);
        assert_eq!(engine.listen_port, 4662, "we still BIND the local port");
        assert_eq!(
            engine.advertised_port, 51234,
            "but peers must be told the port the PROVIDER forwards"
        );
        assert_eq!(engine.kad_port, 4672, "Kad BINDS the local UDP port");
        assert_eq!(
            engine.kad_advertised_port, 51235,
            "and Kad peers must be told the forwarded UDP port, not the bound one"
        );

        // On a VPN the LAN router mapping accomplishes nothing, so it must be
        // possible to switch it off rather than emit a misleading failure.
        engine.set_upnp_enabled(false);
        assert!(!engine.upnp_enabled);
        assert_eq!(
            port_mapping_action(true, false, false),
            MappingAction::Map,
            "the policy itself is unchanged - the engine gates on the toggle"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two triggers that exist to RECOVER a missing port mapping both used
    /// to early-return when there was no mapping - so a start() map that simply
    /// failed (a dropped SSDP answer, a momentarily busy gateway) left the
    /// session LowID with no retry short of a full Stop/Start, on the path
    /// padMule's whole HighID story runs through.
    #[test]
    fn a_missing_mapping_is_retried_not_ignored() {
        // Running, online, no mapping yet -> TRY, do not shrug.
        assert_eq!(
            port_mapping_action(true, false, false),
            MappingAction::Map,
            "a failed initial map must be retried on resume / on a LowID answer"
        );
        // Running, online, mapping held -> verify it, do not blindly re-add.
        assert_eq!(
            port_mapping_action(true, false, true),
            MappingAction::Refresh
        );
        // Never touch the gateway when stopped or offline, either way round.
        assert_eq!(
            port_mapping_action(false, false, false),
            MappingAction::None
        );
        assert_eq!(port_mapping_action(false, false, true), MappingAction::None);
        assert_eq!(port_mapping_action(true, true, false), MappingAction::None);
        assert_eq!(port_mapping_action(true, true, true), MappingAction::None);
    }

    /// THE missing retry. Before this, `spawn_fetch` was only ever reached from
    /// `start()`, `resume()` and `add_download`, so a download that missed its
    /// resume window - or whose fetch task simply ran out of rounds - sat
    /// registered, incomplete and permanently idle while the UI still showed it
    /// as a transfer. That is what "stuck at 34% forever" was.
    #[tokio::test]
    async fn the_idle_download_retry_fires_only_when_due_and_only_when_idle() {
        use crate::part_store::PartStore;
        let dir = tmp("resume-retry");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(false);
        engine.state = EngineState::Running;

        let store = PartStore::create(&dir, 7, [0x33; 16], 5000, b"idle.bin").unwrap();
        engine.downloads.lock().await.push(Download::new(store));

        // NOT due: it must early-return BEFORE doing any work. The observable
        // that distinguishes "early-returned" from "ran and found nothing" is
        // the interval stamp, which only a tick that actually runs updates.
        // (Asserting the RETURN VALUE would not bite: with no server and no Kad
        // the answer is false either way - the first version of this test passed
        // happily with the interval check deleted.)
        let not_due = Instant::now();
        engine.last_resume_retry = not_due;
        let _ = engine.maintain_resume_fetches().await;
        assert_eq!(
            engine.last_resume_retry, not_due,
            "an early return must not consume the interval - it never ran"
        );

        // Due: it runs, which the refreshed stamp proves, so a tick cannot spin
        // every second once it has looked.
        engine.last_resume_retry = Instant::now() - RESUME_RETRY_EVERY - Duration::from_secs(1);
        let due = engine.last_resume_retry;
        let _ = engine.maintain_resume_fetches().await;
        assert!(
            engine.last_resume_retry > due,
            "a due tick must run and consume the interval"
        );
        let dls = engine.downloads().await;
        assert_eq!(dls.len(), 1, "the download is still registered");
        assert!(
            !dls[0].is_complete().await,
            "still incomplete, still resumable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A server that logs in and then NEVER answers a source request, holding
    /// the connection open - the shape that made the old code burn its whole
    /// SOURCES_WAIT.
    async fn spawn_silent_source_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut sfs = crate::framed::FramedStream::new(sock);
                    if sfs.read_packet().await.is_err() {
                        return;
                    }
                    let _ = sfs
                        .write_packet(&mule_proto::Packet::new(
                            mule_proto::PROT_EDONKEY,
                            crate::server_messages::OP_IDCHANGE,
                            0x0A00_0001u32.to_le_bytes().to_vec(),
                        ))
                        .await;
                    // Read forever, answer nothing, keep the socket OPEN.
                    while sfs.read_packet().await.is_ok() {}
                });
            }
        });
        addr
    }

    /// Kad maintenance must be RATE-LIMITED and must never fire on a stopped or
    /// offline engine. It runs from the heartbeat, i.e. once a second, and it
    /// does real UDP work under the engine lock - so the guard is the whole
    /// reason the call is safe to make that often.
    #[tokio::test]
    async fn kad_maintenance_is_rate_limited_and_never_runs_offline() {
        let dir = tmp("kadmaint");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        // Stopped: nothing, whatever the clock says.
        engine.last_kad_refresh = Instant::now() - KAD_REFRESH_EVERY - Duration::from_secs(1);
        assert_eq!(engine.maintain_kad().await, 0, "a stopped engine is silent");

        // Running but OFFLINE: still nothing. Offline means no packets, and
        // maintenance is packets.
        engine.state = EngineState::Running;
        engine.last_kad_refresh = Instant::now() - KAD_REFRESH_EVERY - Duration::from_secs(1);
        assert_eq!(engine.maintain_kad().await, 0, "offline means no UDP");

        // Due-ness is checked BEFORE the offline short-circuit consumes it, so a
        // freshly-stamped engine stays quiet on the next heartbeat too.
        engine.last_kad_refresh = Instant::now();
        assert_eq!(engine.maintain_kad().await, 0, "not due yet");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The Kad-skip threshold is TIED to the worker pool, not chosen by feel.
    ///
    /// The rule it encodes: skipping Kad is only safe when the server alone
    /// produced enough DIALABLE sources to keep the pool busy. Below that the
    /// pool is starved by definition, so the Kad wait costs nothing that was
    /// going to be used. If the Normal pool width ever changes, this assert
    /// fails and the threshold gets revisited deliberately - which is the whole
    /// point, since a threshold tuned on one network and then forgotten is
    /// exactly how the 5s connect cap nearly shipped.
    #[test]
    fn the_kad_skip_threshold_matches_the_default_worker_pool() {
        assert_eq!(
            MIN_DIALABLE_TO_SKIP_KAD,
            crate::fetch::parallel_for_priority(crate::part_store::PR_NORMAL),
            "the Kad-skip threshold and the Normal worker pool have drifted apart"
        );
    }

    /// Source discovery must honour the budget it is GIVEN, so the caller never
    /// has to wrap it in a timeout that throws away a good answer. Driven
    /// against a server that stays connected and never replies: the old code
    /// spent the full SOURCES_WAIT (10s) here regardless of what the caller
    /// could afford.
    #[tokio::test]
    async fn find_sources_honours_a_short_budget_against_a_silent_server() {
        let dir = tmp("find-budget");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        let addr = spawn_silent_source_server().await;
        assert!(
            engine.connect_to_server(addr).await,
            "mock login should win"
        );

        let t0 = tokio::time::Instant::now();
        let (reg, lowids) = engine
            .find_sources([0x44; 16], 1000, Duration::from_millis(600), false)
            .await;
        let elapsed = t0.elapsed();
        assert!(
            reg.is_empty() && lowids.is_empty(),
            "the server said nothing"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "must return inside the 600ms budget, not the 10s SOURCES_WAIT; took {elapsed:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A finished file the user DELETED (in the Files app - the downloads dir is
    /// user-visible, and padMule offers no in-app delete) must stop being
    /// advertised. Before this fix the library was verified only at `start()`,
    /// so for the rest of the session padMule kept announcing the dead hash via
    /// OP_OFFERFILES, told a requesting peer the file was COMPLETE, granted it
    /// an upload slot, and then died silently when the read failed - the worst
    /// shape, since the peer had every reason to believe us.
    #[tokio::test]
    async fn a_deleted_finished_file_is_dropped_from_the_shared_library() {
        let dir = tmp("phantom-share");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let downloads = dir.join("dl");
        std::fs::create_dir_all(&downloads).unwrap();

        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_downloads_dir(&downloads);

        // Two shared files, both really on disk.
        let keep = downloads.join("keep.bin");
        let gone = downloads.join("gone.bin");
        std::fs::write(&keep, vec![1u8; 64]).unwrap();
        std::fs::write(&gone, vec![2u8; 64]).unwrap();
        {
            let mut lib = engine.shared.lock().await;
            for (h, p) in [([0xAAu8; 16], &keep), ([0xBBu8; 16], &gone)] {
                let sf = SharedFile {
                    hash: h,
                    size: 64,
                    name: p
                        .file_name()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                        .into_bytes(),
                    part_hashes: Vec::new(),
                    path: p.clone(),
                    rating: 0,
                    comment: String::new(),
                    aich_root: None,
                };
                persist_shared_file(&engine.config_dir, &sf);
                lib.push(sf);
            }
        }
        assert_eq!(engine.shared_files().await.len(), 2);

        // The user deletes one in the Files app.
        std::fs::remove_file(&gone).unwrap();

        let dropped = engine.verify_shared_library().await;
        assert_eq!(dropped, 1, "the deleted file must be dropped");

        let left = engine.shared_files().await;
        assert_eq!(left.len(), 1, "only the surviving file is still shared");
        assert_eq!(left[0].1, "keep.bin");
        assert!(
            engine.shared_dirty.load(Ordering::Relaxed),
            "the server must be re-offered the corrected library"
        );
        // ...and it must not come back from known.met on the next load.
        let reloaded = load_shared_library(&engine.config_dir, &downloads);
        assert_eq!(reloaded.len(), 1, "known.met was corrected too");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A mock server that accepts a login, answers the IDCHANGE, then CLOSES -
    /// a kick. Used to drive the drop path end to end.
    async fn spawn_kicking_login_server() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut sfs = crate::framed::FramedStream::new(sock);
                    if sfs.read_packet().await.is_err() {
                        return;
                    }
                    let _ = sfs
                        .write_packet(&mule_proto::Packet::new(
                            mule_proto::PROT_EDONKEY,
                            crate::server_messages::OP_IDCHANGE,
                            0x0A00_0001u32.to_le_bytes().to_vec(),
                        ))
                        .await;
                    // ...and hang up. The socket drops at the end of this task.
                });
            }
        });
        addr
    }

    /// A server DROP must refresh the durable Status line, not only raise the
    /// kick alert. This is the exact mirror of the 2026-08-02 on-device bug
    /// (build-progress 8as, "an event is not state"): that fix taught
    /// connect/disconnect/failed-dial to emit Status, but the DROP path was
    /// missed, so after a kick the Status row kept reading "Connected to ..."
    /// forever while the Server and ID rows correctly vanished.
    #[tokio::test]
    async fn a_server_drop_refreshes_the_status_line() {
        let dir = tmp("drop-status");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();

        let addr = spawn_kicking_login_server().await;
        assert!(
            engine.connect_to_server(addr).await,
            "mock login should win"
        );
        let _ = drain(&mut rx).await; // clear the connect events

        // Give the server's close a moment to land, then poll as the heartbeat does.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            engine.poll_server_drop().await.is_some(),
            "the closed connection must be detected as a drop"
        );

        let evs = drain(&mut rx).await;
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::ServerDropped { .. })),
            "the kick alert must still fire; got {evs:?}"
        );
        assert!(
            evs.iter().any(
                |e| matches!(e, EngineEvent::Status(s) if s == "Not connected - pick a server")
            ),
            "the DURABLE status line must stop claiming a connection; got {evs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Like `spawn_mock_login_server`, but RECORDS the opcode of every packet
    /// the client sends after its login, so a test can assert what the connect
    /// burst contains (the shares offer, the OP_GETSERVERLIST ask, ...).
    async fn spawn_recording_login_server() -> (SocketAddr, Arc<std::sync::Mutex<Vec<u8>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen: Arc<std::sync::Mutex<Vec<u8>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
        let record = seen.clone();
        tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let record = record.clone();
                tokio::spawn(async move {
                    let mut sfs = crate::framed::FramedStream::new(sock);
                    if sfs.read_packet().await.is_err() {
                        return; // the login request
                    }
                    let _ = sfs
                        .write_packet(&mule_proto::Packet::new(
                            mule_proto::PROT_EDONKEY,
                            crate::server_messages::OP_IDCHANGE,
                            0x0A00_0001u32.to_le_bytes().to_vec(),
                        ))
                        .await;
                    while let Ok(p) = sfs.read_packet().await {
                        record.lock().unwrap().push(p.opcode);
                    }
                });
            }
        });
        (addr, seen)
    }

    /// Both authorities ask a fresh login for the server's own list - a bodiless
    /// OP_GETSERVERLIST right after the shares offer (eMule 0.50a
    /// sockets.cpp:253-260, aMule ServerConnect.cpp:289-296) - and the
    /// 2026-08-03 device pass proved modern servers do NOT volunteer
    /// OP_SERVERLIST unasked, so this send is what makes the gossip harvest
    /// live. padMule defaults the pref ON (a documented deviation - field doc).
    #[tokio::test]
    async fn connecting_asks_the_server_for_its_server_list() {
        let dir = tmp("ask-serverlist");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        let (addr, seen) = spawn_recording_login_server().await;
        assert!(
            engine.connect_to_server(addr).await,
            "mock login should win"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;

        let ops = seen.lock().unwrap().clone();
        assert!(
            ops.contains(&crate::server_messages::OP_GETSERVERLIST),
            "the connect burst must include the OP_GETSERVERLIST ask; got {ops:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ask honors the pref, exactly as both authorities gate theirs on
    /// AddServersFromServer.
    #[tokio::test]
    async fn the_server_list_ask_honors_the_pref() {
        let dir = tmp("ask-serverlist-off");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_add_servers_from_server(false);

        let (addr, seen) = spawn_recording_login_server().await;
        assert!(
            engine.connect_to_server(addr).await,
            "mock login should win"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;

        let ops = seen.lock().unwrap().clone();
        assert!(
            !ops.contains(&crate::server_messages::OP_GETSERVERLIST),
            "with the pref off, no ask may be sent; got {ops:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// resume() is a FRESH login (the old socket died with the suspension), and
    /// eMule's ConnectionEstablished - where the ask lives - runs on every
    /// reconnect. So a resumed session re-asks too.
    #[tokio::test]
    async fn resuming_re_asks_for_the_server_list() {
        let dir = tmp("ask-serverlist-resume");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        let (addr, seen) = spawn_recording_login_server().await;
        assert!(
            engine.connect_to_server(addr).await,
            "mock login should win"
        );

        // pause() requires Running; connect alone does not set it.
        engine.state = EngineState::Running;
        engine.pause().await;
        engine.resume().await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        let asks = seen
            .lock()
            .unwrap()
            .iter()
            .filter(|o| **o == crate::server_messages::OP_GETSERVERLIST)
            .count();
        assert!(
            asks >= 2,
            "the fresh post-resume login must re-ask (want >= 2 asks, got {asks})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Connecting to a server must refresh the STATUS line, not only raise a
    /// transient notice. Found on-device 2026-08-02: the Status screen kept
    /// reading "Not connected - pick a server" while the very same screen showed
    /// the server address and "HighID", because `connect_to_server` emitted only
    /// `Server(..)` (which the app routes to its transient notice banner) and the
    /// durable `status` field is fed ONLY by `Status(..)` events.
    #[tokio::test]
    async fn connecting_to_a_server_refreshes_the_status_line() {
        let dir = tmp("status-on-connect");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();

        let addr = spawn_mock_login_server().await;
        assert!(
            engine.connect_to_server(addr).await,
            "mock login should win"
        );

        let evs = drain(&mut rx).await;
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::Status(s) if s.contains("Connected to"))),
            "connect must emit a Status line; got {evs:?}"
        );

        // ... and disconnecting must take it back to the honest resting text.
        engine.disconnect_server().await;
        let evs = drain(&mut rx).await;
        assert!(
            evs.iter().any(
                |e| matches!(e, EngineEvent::Status(s) if s == "Not connected - pick a server")
            ),
            "disconnect must emit a Status line; got {evs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cancel_download_removes_it_and_deletes_the_part_files() {
        let dir = tmp("cancel");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        // Register an in-progress download backed by a real .part in config_dir.
        let store = PartStore::create(&dir, 1, [0xAB; 16], 1000, b"x.bin").unwrap();
        engine.downloads.lock().await.push(Download::new(store));
        assert!(dir.join("001.part").exists());
        assert!(dir.join("001.part.met").exists());

        // Cancelling it removes it from the list and deletes both files.
        assert!(engine.cancel_download([0xAB; 16]).await, "should cancel");
        assert!(engine.downloads().await.is_empty());
        assert!(!dir.join("001.part").exists());
        assert!(!dir.join("001.part.met").exists());

        // Cancelling a hash we are not downloading is a no-op, not a lie.
        assert!(!engine.cancel_download([0x00; 16]).await);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn kad_hits_flow_through_the_catalog_and_merge_with_server_hits() {
        // A Kad result and a server result for the SAME hash must collapse to one
        // ranked file with the better availability - the whole point of merging
        // the two discovery paths into one search.
        let h = [0x42; 16];
        let server = SearchResultFile {
            hash: h,
            id: 0,
            port: 0,
            tags: vec![
                Tag::id(0x01, TagValue::Str(b"clip.mp4".to_vec())),
                Tag::id(0x02, TagValue::U32(1000)),
                Tag::id(0x15, TagValue::U32(4)),
            ],
        };
        let kad = mule_kad::FileResult {
            hash: h,
            name: "clip.mp4".into(),
            size: 1000,
            sources: 30,
        };
        let combined = vec![server, kad_to_search(&kad)];
        let cat = catalog(&combined);
        assert_eq!(cat.len(), 1, "same hash from both sources merges to one");
        assert_eq!(cat[0].sources, 30, "the better availability wins");
        assert_eq!(cat[0].size, 1000);
        assert_eq!(cat[0].name, "clip.mp4");
        assert!(cat[0].is_trusted());
    }

    #[tokio::test]
    async fn hit_status_reports_downloading_have_and_new() {
        let dir = tmp("hitstatus");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (engine, _rx) = Engine::new(&dir).unwrap();

        // An in-progress (incomplete) download -> Downloading.
        let store = PartStore::create(&dir, 1, [0xAA; 16], 1000, b"a.bin").unwrap();
        engine.downloads.lock().await.push(Download::new(store));
        assert_eq!(engine.hit_status([0xAA; 16]).await, HitStatus::Downloading);

        // A shared (finished) file -> Have.
        engine.shared.lock().await.push(SharedFile {
            hash: [0xBB; 16],
            size: 10,
            name: b"b.bin".to_vec(),
            part_hashes: vec![],
            path: dir.join("b.bin"),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        });
        assert_eq!(engine.hit_status([0xBB; 16]).await, HitStatus::Have);

        // Anything else -> New.
        assert_eq!(engine.hit_status([0xCC; 16]).await, HitStatus::New);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn leech_mode_refuses_a_file_we_actually_hold() {
        use crate::transfer::{build_request_filename_ext, OP_FILEREQANSNOFIL};
        // We DO hold this hash, but sharing is off - so the honest answer to a
        // leecher is "no file", not a transfer.
        let hash = [0x5A; 16];
        let shared = Arc::new(Mutex::new(vec![SharedFile {
            hash,
            size: 100,
            name: b"held.bin".to_vec(),
            part_hashes: vec![],
            path: fixture_file("held", 100),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        }]));
        let sharing = Arc::new(AtomicBool::new(false)); // Leech Mode
        let gate = Arc::new(UploadGate::new(MAX_UPLOAD_SLOTS, UPLOAD_QUEUE_CAP));

        let (client, server) = tokio::io::duplex(8192);
        let mut server_fs = FramedStream::new(server);
        let mut client_fs = FramedStream::new(client);

        let first = build_request_filename_ext(&hash);
        let srv = tokio::spawn(async move {
            serve_inbound(
                &mut server_fs,
                &shared,
                &sharing,
                &gate,
                first,
                0,
                Default::default(),
            )
            .await
        });

        let reply = client_fs.read_packet_unpacked().await.unwrap();
        assert_eq!(
            reply.opcode, OP_FILEREQANSNOFIL,
            "Leech Mode must decline, not serve"
        );
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn a_full_queue_ranks_the_peer_then_grants_when_a_slot_frees() {
        use crate::transfer::{
            build_request_filename_ext, build_start_upload_req, parse_queue_ranking,
            OP_ACCEPTUPLOADREQ, OP_QUEUERANKING,
        };
        // One slot, already occupied by a held grant, so the next requester must
        // queue instead of being served or refused.
        let gate = Arc::new(UploadGate::new(1, UPLOAD_QUEUE_CAP));
        let held = gate.try_grant().unwrap();

        let hash = [0x7C; 16];
        let shared = vec![SharedFile {
            hash,
            size: 100,
            name: b"q.bin".to_vec(),
            part_hashes: vec![],
            path: fixture_file("queue", 100),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        }];

        let (client, server) = tokio::io::duplex(8192);
        let mut server_fs = FramedStream::new(server);
        let mut client_fs = FramedStream::new(client);

        let gate2 = Arc::clone(&gate);
        let srv = tokio::spawn(async move {
            let _ = serve_shared(
                &mut server_fs,
                &shared,
                None,
                Some(&gate2),
                0,
                Default::default(),
            )
            .await;
        });

        // Name the file, then ask to upload - the slot is taken, so we are queued.
        client_fs
            .write_packet(&build_request_filename_ext(&hash))
            .await
            .unwrap();
        let _ = client_fs.read_packet_unpacked().await.unwrap(); // filename answer
        client_fs
            .write_packet(&build_start_upload_req(&hash))
            .await
            .unwrap();
        let ranked = client_fs.read_packet_unpacked().await.unwrap();
        assert_eq!(ranked.opcode, OP_QUEUERANKING, "at capacity -> a rank");
        assert_eq!(
            parse_queue_ranking(&ranked.payload).unwrap(),
            1,
            "first in line"
        );
        assert_eq!(gate.waiting(), 1);

        // Free the slot -> the queued peer is granted IN PLACE (no reconnect).
        drop(held);
        let accepted = client_fs.read_packet_unpacked().await.unwrap();
        assert_eq!(
            accepted.opcode, OP_ACCEPTUPLOADREQ,
            "the freed slot is granted"
        );

        drop(client_fs);
        srv.await.unwrap();
    }

    #[tokio::test]
    async fn a_gated_peer_that_skips_startupload_gets_no_data() {
        // A peer that names a file then jumps straight to OP_REQUESTPARTS - never
        // asking for a slot - must NOT be served, or it would bypass the cap and
        // the queue. It should get the filename answer and then nothing.
        use crate::transfer::{build_request_filename_ext, build_request_parts, OP_SENDINGPART};
        let hash = [0x3A; 16];
        let shared = vec![SharedFile {
            hash,
            size: 300,
            name: b"g.bin".to_vec(),
            part_hashes: vec![],
            path: fixture_file("gated", 300),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        }];
        let gate = Arc::new(UploadGate::new(MAX_UPLOAD_SLOTS, UPLOAD_QUEUE_CAP));

        let (client, server) = tokio::io::duplex(8192);
        let mut server_fs = FramedStream::new(server);
        let mut client_fs = FramedStream::new(client);

        let gate2 = Arc::clone(&gate);
        let srv = tokio::spawn(async move {
            let _ = serve_shared(
                &mut server_fs,
                &shared,
                None,
                Some(&gate2),
                0,
                Default::default(),
            )
            .await;
        });

        client_fs
            .write_packet(&build_request_filename_ext(&hash))
            .await
            .unwrap();
        let ans = client_fs.read_packet_unpacked().await.unwrap(); // filename answer
        assert_ne!(ans.opcode, OP_SENDINGPART);
        // Ask for bytes WITHOUT a slot grant.
        client_fs
            .write_packet(&build_request_parts(&hash, &[(0, 300)]))
            .await
            .unwrap();
        // No data should come back; a short wait must time out, not yield a part.
        let got = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            client_fs.read_packet_unpacked(),
        )
        .await;
        assert!(
            got.is_err(),
            "an ungranted peer must receive no OP_SENDINGPART"
        );
        drop(client_fs);
        let _ = srv.await;
    }

    #[tokio::test]
    async fn sharing_on_serves_a_held_file_to_a_leecher() {
        let dir = tmp("serve-inbound");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data: Vec<u8> = (0..300_000u32)
            .map(|i| (i.wrapping_mul(29)) as u8)
            .collect();
        let hash = mule_proto::ed2k_hash(&data);
        let path = dir.join("f.bin");
        std::fs::write(&path, &data).unwrap();
        let shared = Arc::new(Mutex::new(vec![SharedFile {
            hash,
            size: data.len() as u64,
            name: b"f.bin".to_vec(),
            part_hashes: vec![],
            path,
            rating: 0,
            comment: String::new(),
            aich_root: None,
        }]));
        let sharing = Arc::new(AtomicBool::new(true));
        let gate = Arc::new(UploadGate::new(MAX_UPLOAD_SLOTS, UPLOAD_QUEUE_CAP));

        let (client, server) = tokio::io::duplex(128 * 1024);
        let mut server_fs = FramedStream::new(server);
        let mut client_fs = FramedStream::new(client);

        let srv = tokio::spawn(async move {
            // The listener peeks the first packet before deciding; do the same.
            let first = server_fs.read_packet_unpacked().await.unwrap();
            serve_inbound(
                &mut server_fs,
                &shared,
                &sharing,
                &gate,
                first,
                0,
                Default::default(),
            )
            .await;
        });

        let got = crate::transfer_session::download_file(&mut client_fs, &hash, data.len() as u64)
            .await
            .unwrap();
        assert_eq!(got, data);
        assert_eq!(mule_proto::ed2k_hash(&got), hash);

        drop(client_fs);
        srv.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn new_loads_identity_and_starts_stopped() {
        let dir = tmp("new");
        let _ = std::fs::remove_dir_all(&dir);
        let (engine, _rx) = Engine::new(&dir).unwrap();
        assert_eq!(engine.state(), EngineState::Stopped);
        assert_eq!(engine.userhash()[5], 14, "identity loaded");
        assert!(dir.join("preferences.dat").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A P2P filename comes from a stranger. It must never steer a write out of
    /// the directory we chose.
    #[test]
    fn filenames_from_the_network_cannot_escape_the_downloads_dir() {
        for (raw, want) in [
            // Separators become underscores; the leading dots are then stripped,
            // so a traversal attempt collapses to an inert single name.
            (
                "../../Library/Preferences/evil",
                "_.._Library_Preferences_evil",
            ),
            ("/etc/passwd", "_etc_passwd"),
            ("..\\..\\windows\\system32", "_.._windows_system32"),
            ("nul\0byte.txt", "nul_byte.txt"),
            ("line\nbreak.txt", "line_break.txt"),
            // Names that are nothing but dots/space have no content to keep.
            ("..", "download"),
            (".", "download"),
            ("   ", "download"),
            ("", "download"),
            // An ordinary name is left completely alone.
            ("ordinary file.pdf", "ordinary file.pdf"),
        ] {
            let got = safe_filename(raw);
            assert_eq!(got, want, "safe_filename({raw:?})");
            // The real invariant: whatever comes out is ONE path component that
            // joins inside the parent.
            let joined = Path::new("/downloads").join(&got);
            assert_eq!(
                joined.parent(),
                Some(Path::new("/downloads")),
                "{raw:?} escaped to {joined:?}"
            );
        }
    }

    /// Finishing a download must never destroy a file the user already has.
    #[test]
    fn a_finished_file_never_overwrites_an_existing_one() {
        let dir = tmp("uniq");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let first = dir.join("a.pdf");
        assert_eq!(unique_dest(first.clone()), first, "free name is used as-is");

        std::fs::write(&first, b"original").unwrap();
        let second = unique_dest(first.clone());
        assert_eq!(second.file_name().unwrap(), "a (2).pdf");

        std::fs::write(&second, b"second").unwrap();
        assert_eq!(unique_dest(first).file_name().unwrap(), "a (3).pdf");
        // The original is untouched.
        assert_eq!(std::fs::read(dir.join("a.pdf")).unwrap(), b"original");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A new download must not claim an index an existing .part.met already uses
    /// - that would clobber a transfer in progress.
    #[test]
    fn a_new_part_index_never_collides_with_an_existing_one() {
        let dir = tmp("idx");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(next_part_index(&dir), 1, "empty dir starts at 1");

        std::fs::write(dir.join("1.part.met"), b"x").unwrap();
        std::fs::write(dir.join("2.part.met"), b"x").unwrap();
        assert_eq!(next_part_index(&dir), 3);

        // A gap must NOT be reused while a higher index is live: 7 exists, so
        // the next is 8, not the free 3.
        std::fs::write(dir.join("7.part.met"), b"x").unwrap();
        assert_eq!(next_part_index(&dir), 8);

        // Unrelated files are ignored.
        std::fs::write(dir.join("preferences.dat"), b"x").unwrap();
        std::fs::write(dir.join("notanumber.part.met"), b"x").unwrap();
        assert_eq!(next_part_index(&dir), 8);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn add_download_refuses_what_it_cannot_do_instead_of_pretending() {
        let dir = tmp("add");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        // A zero size means we do not know the file - a part store cannot even
        // be sized. Refuse rather than create a broken download.
        assert_eq!(
            engine.add_download([1; 16], 0, "x.pdf").await,
            AddResult::BadRequest("file size is unknown")
        );
        // No server -> say so; do not silently create a download nothing feeds.
        assert_eq!(
            engine.add_download([1; 16], 1000, "x.pdf").await,
            AddResult::NotConnected
        );
        assert!(
            engine.downloads().await.is_empty(),
            "nothing was registered"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// With NO server (but not `offline`), a download must fall through to Kad
    /// source-finding rather than being refused outright: the old code returned
    /// NoServer before ever trying Kad, so a Kad-only client (all servers down,
    /// Kad up) could search but never download. Caught by the hands-on FFI
    /// simulation, row 8w.
    ///
    /// The 2026-08-03 honesty change added a bail for having NO channel at all,
    /// which could reintroduce exactly that bug if it were keyed on the server
    /// alone - so this test now pins BOTH halves: bail when there is nothing to
    /// ask, and DO NOT bail when Kad alone could answer.
    #[tokio::test]
    async fn add_download_without_a_server_still_tries_kad() {
        let dir = tmp("kadonly");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        // Neither channel: refusing is right, and the reason is about US.
        assert_eq!(
            engine.add_download([2; 16], 1000, "x.bin").await,
            AddResult::NotConnected
        );
        assert!(engine.downloads().await.is_empty());

        // THE 8w REGRESSION GUARD: a populated Kad table alone is a channel, so
        // the same call must get PAST the bail and actually look. It reports
        // NoSources here only because no live Kad node is attached, which is what
        // keeps this test offline.
        engine.routing.load_nodes(&[KadContact {
            id: Kad128::from_hash(&[0x5A; 16]),
            ip: 0x0808_0808,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            verified: true,
        }]);
        assert_eq!(
            engine.add_download([2; 16], 1000, "x.bin").await,
            AddResult::NoSources,
            "a Kad-only client must still TRY - never refused for lacking a server"
        );
        assert!(engine.downloads().await.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn ranked_of(o: SearchOutcome) -> Vec<RankedFile> {
        match o {
            SearchOutcome::Results { ranked, .. } => ranked,
            SearchOutcome::Throttled { wait_secs } => panic!("unexpected throttle ({wait_secs}s)"),
        }
    }

    #[tokio::test]
    async fn search_is_empty_rather_than_erroring_when_no_server_has_us() {
        let dir = tmp("search");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        let f = SearchFilters::default();
        assert!(ranked_of(engine.search("anything", f).await).is_empty());
        assert!(
            ranked_of(engine.search("", f).await).is_empty(),
            "empty keyword is a no-op"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn throttle_wait_secs_guards_the_min_interval() {
        let interval = Duration::from_secs(2);
        let base = Instant::now();
        // Never searched -> may search now.
        assert_eq!(throttle_wait_secs(None, base, interval), None);
        // 0.5s after the last search -> must wait, rounded UP to 2s.
        assert_eq!(
            throttle_wait_secs(Some(base), base + Duration::from_millis(500), interval),
            Some(2)
        );
        // 1.2s after -> 0.8s left, rounds up to 1s.
        assert_eq!(
            throttle_wait_secs(Some(base), base + Duration::from_millis(1200), interval),
            Some(1)
        );
        // Exactly the interval later -> may search (no wait).
        assert_eq!(
            throttle_wait_secs(Some(base), base + interval, interval),
            None
        );
        // Well past -> may search.
        assert_eq!(
            throttle_wait_secs(Some(base), base + Duration::from_secs(10), interval),
            None
        );
    }

    /// The device screen is our only diagnostic, so the ID type must reach it.
    /// This pins the honesty gate: no server, no claim.
    #[tokio::test]
    async fn server_info_is_none_until_a_server_accepts_us() {
        let dir = tmp("srvinfo");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        assert_eq!(engine.server_info(), None, "no login yet");
        engine.start().await;
        assert_eq!(
            engine.server_info(),
            None,
            "offline start logs into nothing"
        );
        assert!(
            !engine.online_status().contains("HighID") && !engine.online_status().contains("LowID"),
            "must not invent an ID we were never given: {}",
            engine.online_status()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `maintain_shares` re-announces the library after a mid-session change, but
    /// must only CONSUME the `shared_dirty` flag once it can actually offer. With
    /// no server connected the flag has to survive - the next connected poll (or
    /// reconnect) is what announces the file; clearing it early would strand the
    /// file for the session, since resume()'s success path does not re-offer.
    #[tokio::test]
    async fn maintain_shares_keeps_the_flag_until_it_can_offer() {
        let dir = tmp("maintshare");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        // Nothing changed -> no work, and the flag stays clear.
        assert!(!engine.shared_dirty.load(Ordering::Relaxed));
        engine.maintain_shares().await;
        assert!(!engine.shared_dirty.load(Ordering::Relaxed));

        // A completion raised the flag but no server is connected: it must be
        // KEPT, not consumed, so a later connected poll still announces the file.
        engine.shared_dirty.store(true, Ordering::Relaxed);
        engine.maintain_shares().await;
        assert!(
            engine.shared_dirty.load(Ordering::Relaxed),
            "maintain_shares must NOT consume the dirty flag when it cannot offer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A remembered login must not survive losing the server: `server_info` is
    /// gated on `is_online`, which pause() falsifies by design.
    #[tokio::test]
    async fn server_info_reports_the_id_type_and_clears_when_offline() {
        let dir = tmp("srvid");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        // Stand in for a real login (no server needed to pin the reporting).
        engine.connection = Some(ServerInfo {
            addr: "192.0.2.1:4242".to_string(),
            name: None,
            low_id: true,
            related_search: false,
        });
        // Still not online -> still no claim, remembered or not.
        assert_eq!(engine.server_info(), None, "is_online gates the claim");
        assert!(!engine.online_status().contains("LowID"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn lifecycle_transitions_and_events() {
        let dir = tmp("life");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        engine.start().await;
        assert_eq!(engine.state(), EngineState::Running);
        engine.pause().await;
        assert_eq!(engine.state(), EngineState::Paused);
        engine.resume().await;
        assert_eq!(engine.state(), EngineState::Running);
        engine.shutdown().await;
        assert_eq!(engine.state(), EngineState::Stopped);

        let evs = drain(&mut rx).await;
        // The key state changes are all present and ordered.
        let states: Vec<EngineState> = evs
            .iter()
            .filter_map(|e| match e {
                EngineEvent::State(s) => Some(*s),
                _ => None,
            })
            .collect();
        assert_eq!(
            states,
            vec![
                EngineState::Running,
                EngineState::Paused,
                EngineState::Running,
                EngineState::Stopped
            ]
        );
        // The reconnect banner is emitted on resume.
        assert!(evs.contains(&EngineEvent::Status("Reconnecting...".into())));
        // The status after the banner must be HONEST: offline here, because the
        // test suppresses the network. It must never claim a connection we lack.
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::Status(s) if s.starts_with("Offline"))),
            "resume must report real connectivity, not a hardcoded 'Connected'"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn lifecycle_methods_are_idempotent() {
        let dir = tmp("idem");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);

        // pause/resume before start are no-ops.
        engine.pause().await;
        engine.resume().await;
        assert_eq!(engine.state(), EngineState::Stopped);

        engine.start().await;
        engine.start().await; // second start is a no-op
        engine.pause().await;
        engine.pause().await; // second pause is a no-op
        engine.resume().await;
        engine.resume().await; // second resume is a no-op

        let evs = drain(&mut rx).await;
        let n_running = evs
            .iter()
            .filter(|e| matches!(e, EngineEvent::State(EngineState::Running)))
            .count();
        // Running was entered exactly twice (start, resume) - not on the repeats.
        assert_eq!(n_running, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn kad_contacts_persist_through_checkpoint_and_reload() {
        use mule_files::KadContact;
        use mule_proto::Kad128;
        let dir = tmp("kad");
        let _ = std::fs::remove_dir_all(&dir);
        // Routable public IPs: the reload path applies the aMule load gate, so
        // private/unroutable fixture addresses would (correctly) be dropped.
        let contacts: Vec<KadContact> = (1..=3u8)
            .map(|i| KadContact {
                id: Kad128::from_hash(&[i; 16]),
                ip: 0x0808_0800 | i as u32,
                udp_port: 4000 + i as u16,
                tcp_port: 5000 + i as u16,
                version: 8,
                udp_key: 0,
                udp_key_ip: 0,
                verified: false,
            })
            .collect();
        {
            let (mut engine, _rx) = Engine::new(&dir).unwrap();
            engine.set_offline(true);
            engine.add_kad_contacts(&contacts);
            engine.start().await;
            engine.pause().await; // checkpoint writes nodes.dat
            assert!(dir.join("nodes.dat").exists());
        }
        // A fresh engine on the same dir loads them on start.
        let (mut engine2, mut rx) = Engine::new(&dir).unwrap();
        engine2.set_offline(true);
        engine2.start().await;
        assert_eq!(engine2.kad_contacts(), 3);
        let evs = drain(&mut rx).await;
        assert!(evs.contains(&EngineEvent::Kad { contacts: 3 }));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_resumes_an_in_progress_download() {
        use crate::part_store::PartStore;
        use mule_proto::ed2k_hash;
        let dir = tmp("resume");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Lay down a part file for a 5000-byte download (nothing written yet).
        let data = vec![9u8; 5000];
        let hash = ed2k_hash(&data);
        let store = PartStore::create(&dir, 1, hash, 5000, b"resume.bin").unwrap();
        drop(store); // leaves 001.part + 001.part.met on disk

        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        engine.start().await;
        assert_eq!(engine.downloads().await.len(), 1, "the .part is resumed");
        let evs = drain(&mut rx).await;
        assert!(evs.iter().any(|e| matches!(
            e,
            EngineEvent::Progress { total, have, .. } if *total == 5000 && *have == 0
        )));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_download_priority_updates_the_live_download_and_part_met() {
        use crate::part_store::{PartStore, PR_HIGH, PR_NORMAL};
        use mule_proto::ed2k_hash;
        let dir = tmp("dl-priority");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let data = vec![7u8; 5000];
        let hash = ed2k_hash(&data);
        let store = PartStore::create(&dir, 1, hash, 5000, b"prio.bin").unwrap();
        drop(store);

        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        engine.start().await; // resumes the .part (Normal by default)
        assert_eq!(engine.downloads().await[0].priority(), PR_NORMAL);

        assert!(
            engine.set_download_priority(hash, PR_HIGH).await,
            "a known hash is updated"
        );
        assert!(
            !engine.set_download_priority([0xEE; 16], PR_HIGH).await,
            "an unknown hash returns false"
        );
        // Live download reflects it...
        assert_eq!(engine.downloads().await[0].priority(), PR_HIGH);
        // ...and it persisted to part.met (a fresh open reads it back).
        assert_eq!(PartStore::open(&dir, 1).unwrap().priority, PR_HIGH);

        // An out-of-range value clamps to Normal.
        assert!(engine.set_download_priority(hash, 9).await);
        assert_eq!(engine.downloads().await[0].priority(), PR_NORMAL);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn shared_library_persists_reloads_and_skips_deleted() {
        let dir = tmp("known-met-roundtrip");
        let _ = std::fs::remove_dir_all(&dir);
        let downloads = dir.join("downloads");
        std::fs::create_dir_all(&downloads).unwrap();
        // One file still on disk, one the user later deleted from Files.
        std::fs::write(downloads.join("kept.bin"), b"hello").unwrap();
        let kept = SharedFile {
            hash: [0x11; 16],
            size: 5,
            name: b"kept.bin".to_vec(),
            part_hashes: vec![],
            path: downloads.join("kept.bin"),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        };
        let gone = SharedFile {
            hash: [0x22; 16],
            size: 9,
            name: b"gone.bin".to_vec(),
            part_hashes: vec![[0xAB; 16], [0xCD; 16]],
            path: downloads.join("gone.bin"), // never written to disk
            rating: 0,
            comment: String::new(),
            aich_root: None,
        };
        persist_shared_file(&dir, &kept);
        persist_shared_file(&dir, &gone);
        persist_shared_file(&dir, &kept); // idempotent by hash

        // known.met stayed byte-valid and holds both entries once each.
        let met =
            mule_files::read_known_met(&std::fs::read(dir.join("known.met")).unwrap()).unwrap();
        assert_eq!(met.entries.len(), 2, "each hash persisted exactly once");

        // Reload only re-shares the file that still exists on disk.
        let lib = load_shared_library(&dir, &downloads);
        assert_eq!(lib.len(), 1);
        assert_eq!(lib[0].hash, [0x11; 16]);
        assert_eq!(lib[0].size, 5);
        assert_eq!(lib[0].name, b"kept.bin");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn start_loads_an_ip_filter_when_present() {
        let dir = tmp("ipfilter-load");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A Latin-1 byte (0xE9) in the description, as real community lists have:
        // the file must still load (bytes + lossy, not strict UTF-8).
        std::fs::write(
            dir.join("ipfilter.dat"),
            b"# test list\n10.0.0.0 - 10.0.0.255 , 0 , R\xE9seau bad range\n",
        )
        .unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        assert_eq!(engine.ip_filter_ranges(), 0, "not loaded until start");
        engine.start().await;
        assert_eq!(
            engine.ip_filter_ranges(),
            1,
            "start() loads ipfilter.dat despite a non-UTF-8 description byte"
        );
        assert!(engine
            .ip_filter
            .as_ref()
            .unwrap()
            .is_blocked("10.0.0.9".parse().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn aich_root_round_trips_through_known_met() {
        let dir = tmp("aichtag");
        let _ = std::fs::remove_dir_all(&dir);
        let downloads = dir.join("downloads");
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::write(downloads.join("a.bin"), b"abc").unwrap();
        let root = [0x5A; 20];
        let sf = SharedFile {
            hash: [0xAB; 16],
            size: 3,
            name: b"a.bin".to_vec(),
            part_hashes: vec![],
            path: downloads.join("a.bin"),
            rating: 0,
            comment: String::new(),
            aich_root: Some(root),
        };
        persist_shared_file(&dir, &sf);
        // The tag written is the base32 STRING form both authorities use, so
        // a reload recovers the exact root - and the catalog root set (which
        // drives the startup hashset prune) contains it.
        let lib = load_shared_library(&dir, &downloads);
        assert_eq!(lib.len(), 1);
        assert_eq!(lib[0].aich_root, Some(root));
        assert!(known_met_aich_roots(&dir).contains(&root));
        // An entry saved WITHOUT a root loads as None (pre-AICH library).
        let sf2 = SharedFile {
            hash: [0xCD; 16],
            size: 3,
            name: b"b.bin".to_vec(),
            part_hashes: vec![],
            path: downloads.join("b.bin"),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        };
        std::fs::write(downloads.join("b.bin"), b"xyz").unwrap();
        persist_shared_file(&dir, &sf2);
        let lib = load_shared_library(&dir, &downloads);
        assert_eq!(
            lib.iter().find(|f| f.hash == [0xCD; 16]).unwrap().aich_root,
            None
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn unshare_removes_from_the_library_and_known_met() {
        let dir = tmp("unshare");
        let _ = std::fs::remove_dir_all(&dir);
        let downloads = dir.join("downloads");
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::write(downloads.join("keep.bin"), b"a").unwrap();
        std::fs::write(downloads.join("drop.bin"), b"bb").unwrap();
        let keep = SharedFile {
            hash: [0xAA; 16],
            size: 1,
            name: b"keep.bin".to_vec(),
            part_hashes: vec![],
            path: downloads.join("keep.bin"),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        };
        let drop = SharedFile {
            hash: [0xBB; 16],
            size: 2,
            name: b"drop.bin".to_vec(),
            part_hashes: vec![],
            path: downloads.join("drop.bin"),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        };
        persist_shared_file(&dir, &keep);
        persist_shared_file(&dir, &drop);

        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        engine.shared.lock().await.push(keep);
        engine.shared.lock().await.push(drop);

        assert!(engine.unshare_file([0xBB; 16]).await, "found and removed");
        assert!(
            !engine.unshare_file([0xCC; 16]).await,
            "unknown hash is false"
        );
        // Gone from the live library...
        assert_eq!(engine.shared.lock().await.len(), 1);
        assert_eq!(engine.shared.lock().await[0].hash, [0xAA; 16]);
        // ...and from known.met, so a reload does not re-share it (the file is
        // still on disk).
        let lib = load_shared_library(&dir, &downloads);
        assert_eq!(lib.len(), 1);
        assert_eq!(lib[0].hash, [0xAA; 16]);
        assert!(
            downloads.join("drop.bin").exists(),
            "the file itself is kept"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn set_file_rating_updates_the_library_and_survives_a_reload() {
        let dir = tmp("set-rating");
        let _ = std::fs::remove_dir_all(&dir);
        let downloads = dir.join("downloads");
        std::fs::create_dir_all(&downloads).unwrap();
        std::fs::write(downloads.join("rate.bin"), b"hello").unwrap();
        let sf = SharedFile {
            hash: [0xAA; 16],
            size: 5,
            name: b"rate.bin".to_vec(),
            part_hashes: vec![],
            path: downloads.join("rate.bin"),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        };
        persist_shared_file(&dir, &sf);

        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        engine.shared.lock().await.push(sf);

        assert!(
            engine
                .set_file_rating([0xAA; 16], 4, "solid rip".to_string())
                .await,
            "known hash is rated"
        );
        assert!(
            !engine
                .set_file_rating([0xCC; 16], 5, "nope".to_string())
                .await,
            "an unknown hash returns false"
        );
        // Live library reflects it.
        {
            let lib = engine.shared.lock().await;
            assert_eq!(lib[0].rating, 4);
            assert_eq!(lib[0].comment, "solid rip");
        }
        // And it survived to known.met: a reload reads it back (the entry was
        // UPDATED in place, not duplicated - persist_shared_file skips by hash).
        let lib = load_shared_library(&dir, &downloads);
        assert_eq!(lib.len(), 1, "still exactly one entry");
        assert_eq!(lib[0].rating, 4);
        assert_eq!(lib[0].comment, "solid rip");

        // Clearing the rating removes the tags again.
        assert!(engine.set_file_rating([0xAA; 16], 0, String::new()).await);
        let lib = load_shared_library(&dir, &downloads);
        assert_eq!(lib[0].rating, 0);
        assert!(lib[0].comment.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn global_udp_search_with_no_server_met_returns_empty() {
        // No server.met in the config dir -> the global fan-out is a graceful
        // no-op (empty, no hang, no panic), so a global search on a fresh install
        // just contributes nothing.
        let dir = tmp("global-no-met");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let params = SearchParams {
            keyword: "x".into(),
            ..Default::default()
        };
        let out = global_udp_search(&dir, &params, None, None, Duration::from_millis(200)).await;
        assert!(out.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn resume_fetches_with_no_sources_leaves_the_download_resumable() {
        // resume_fetches finds fresh sources for each resumed .part and spawns a
        // transfer. With no server and no Kad node (nothing to find), it must be
        // a safe no-op: the download stays registered and incomplete, so a later
        // run (or an inbound callback) can still complete it. It must NOT drop,
        // complete, or panic on it.
        use crate::part_store::PartStore;
        let dir = tmp("resume-fetch-noop");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let store = PartStore::create(&dir, 1, [0x11; 16], 5000, b"r.bin").unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.downloads.lock().await.push(Download::new(store));

        engine.resume_fetches().await; // no server, no kad -> no sources found

        let dls = engine.downloads().await;
        assert_eq!(dls.len(), 1, "the download is still registered");
        assert!(
            !dls[0].is_complete().await,
            "still incomplete, still resumable"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE PROBE ENDS WHEN THE ANSWERS ARE IN, not when its budget runs out.
    ///
    /// The collect loop had no early exit, so a server list that answered in a
    /// couple of hundred milliseconds still cost `PROBE_COLLECT_BUDGET` - six
    /// seconds, under the engine lock, twice on every launch plus every Refresh
    /// and Prune, with every user action queued behind it.
    ///
    /// One server, whose name server.met already carries, so the only thing owed
    /// is its status answer. It fails by TIMING: restore the unconditional
    /// deadline and this takes the full six seconds.
    #[tokio::test]
    async fn the_probe_stops_as_soon_as_every_server_has_answered() {
        let dir = tmp("probe-early-exit");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // A mock server on loopback. The probe pings TCP port + 4, so the entry
        // written into server.met is the mock's port minus four.
        let mock = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0u16)).await.unwrap();
        let udp_port = mock.local_addr().unwrap().port();
        let tcp_port = udp_port - 4;
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                let Ok((n, src)) = mock.recv_from(&mut buf).await else {
                    return;
                };
                if n < 2 || buf[1] != OP_GLOBSERVSTATREQ {
                    continue; // the description ask - this server does not answer it
                }
                let mut res = vec![PROT_EDONKEY, OP_GLOBSERVSTATRES];
                res.extend_from_slice(&SERV_STAT_CHALLENGE.to_le_bytes()); // echoed
                res.extend_from_slice(&3_651u32.to_le_bytes()); // users
                res.extend_from_slice(&47_008u32.to_le_bytes()); // files
                let _ = mock.send_to(&res, src).await;
            }
        });

        let met = ServerMet {
            header: mule_files::server_met::SERVER_MET_HEADER,
            servers: vec![Server {
                ip: u32::from_le_bytes(Ipv4Addr::LOCALHOST.octets()),
                port: tcp_port,
                // A NAME already on file, so the round owes only a status answer.
                tags: vec![mule_proto::Tag::id(
                    0x01,
                    mule_proto::TagValue::Str(b"mock".to_vec()),
                )],
            }],
        };
        std::fs::write(dir.join("server.met"), write_server_met(&met)).unwrap();

        let (engine, _rx) = Engine::new(&dir).unwrap();
        let t0 = std::time::Instant::now();
        let rows = engine.probe_server_list().await;
        let elapsed = t0.elapsed();

        assert_eq!(rows.len(), 1);
        assert!(
            rows[0].alive,
            "the mock answered, so the row must read alive"
        );
        assert_eq!(rows[0].users, Some(3_651));
        assert!(
            elapsed < PROBE_COLLECT_BUDGET / 3,
            "the probe took {elapsed:?} for one server that answered at once - it \
             is running to its {PROBE_COLLECT_BUDGET:?} budget again, and it holds \
             the engine lock for all of it"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE WHOLE POINT OF SEEDING: the listener and the server login SURVIVE
    /// backgrounding, where `pause()` tears both down. If either stopped, peers
    /// could not reach us and the mode would be an expensive way to do nothing.
    ///
    /// Mutation check: make `pause_for_seeding` call `pause()` and this fails on
    /// the listener assertion - which is the only difference that matters.
    #[tokio::test]
    async fn seeding_keeps_the_listener_up_where_pause_tears_it_down() {
        let dir = tmp("seed-keeps-listener");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        // Offline so no server is dialled; the listener is what this is about.
        // `start()` skips the listener entirely when offline, so bind it
        // explicitly - otherwise the assertion below passes on a listener that
        // was never there, which is the first thing this test did wrong.
        engine.set_offline(true);
        // AN EPHEMERAL PORT, not the 4662 default. Two tests in this module bind
        // a listener, cargo runs them on separate threads, and `start_listener`
        // treats a bind failure as survivable (it stays LowID and returns) - so
        // whichever lost the race left `listener: None` and tripped its own
        // precondition. That is a FLAKE, not a finding: it passed alone and
        // failed in the full suite, which is the worst way for a gate to fail.
        engine.set_ports(0, 4662, 0, 4672);
        engine.start().await;
        engine.start_listener().await;
        assert_eq!(engine.state(), EngineState::Running);
        assert!(
            engine.listener.is_some(),
            "precondition: there must BE a listener for the test to be about \
             whether seeding keeps it"
        );

        engine.pause_for_seeding().await;
        assert_eq!(engine.state(), EngineState::Seeding);
        assert!(
            engine.listener.is_some(),
            "seeding dropped the inbound listener - peers cannot reach us, so \
             there is nothing to seed WITH"
        );
        // Kad now SURVIVES seeding (decided 2026-08-09). Not asserted here,
        // where the offline start never built a node and `kad.is_some()`
        // could only fail vacuously - the keep is pinned with a REAL node by
        // `pause_for_seeding_keeps_the_kad_node_and_still_persists_its_table`.

        // Coming back is the small path, not the full resume: still one listener.
        engine.resume().await;
        assert_eq!(engine.state(), EngineState::Running);
        assert!(engine.listener.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `pause()` remains the honest fallback, and must still tear everything
    /// down - the seeding path must not have weakened it.
    #[tokio::test]
    async fn a_plain_pause_still_releases_the_listener() {
        let dir = tmp("pause-releases-listener");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        // Ephemeral, for the same reason as the seeding test above: these two
        // both bind a listener and would otherwise race for the 4662 default.
        engine.set_ports(0, 4662, 0, 4672);
        engine.start().await;
        engine.start_listener().await;
        assert!(engine.listener.is_some(), "precondition: a listener exists");
        engine.pause().await;
        assert_eq!(engine.state(), EngineState::Paused);
        assert!(
            engine.listener.is_none(),
            "pause must release the port - iPadOS reclaims it anyway, and doing \
             it explicitly is what makes resume honest"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Seeding is only reachable from Running. A second call, or a call while
    /// paused, must not resurrect anything.
    #[tokio::test]
    async fn seeding_is_only_reachable_from_running() {
        let dir = tmp("seed-guard");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        // Stopped -> no-op.
        engine.pause_for_seeding().await;
        assert_eq!(engine.state(), EngineState::Stopped);
        engine.start().await;
        engine.pause().await;
        // Paused -> no-op; a paused engine must not silently start serving.
        engine.pause_for_seeding().await;
        assert_eq!(engine.state(), EngineState::Paused);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE 2026-08-09 REVERSAL, decided by Anthony: `pause_for_seeding` KEEPS
    /// the Kad node instead of dropping it. Since publishing shipped (row 8de)
    /// a seeding session has real Kad work - republishing on the 5h/24h clocks
    /// and answering the network so we are not aged out of its routing tables.
    /// What `set_kad(None)` was ALSO doing - folding the live table into the
    /// persisted one before jetsam can strike - must survive the reversal, so
    /// BOTH halves are pinned: the node lives on, AND the routing state was
    /// still absorbed and checkpointed.
    ///
    /// Mutation checks: restore `set_kad(None)` and the `is_some` assertion
    /// fails; drop the `absorb_kad_routing` call and the `engine.routing`
    /// assertion fails (the nodes.dat read-back alone cannot catch that -
    /// `checkpoint` unions the live table itself, which is why both seams are
    /// asserted).
    #[tokio::test]
    async fn pause_for_seeding_keeps_the_kad_node_and_still_persists_its_table() {
        let dir = tmp("seed-keeps-kad");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.state = EngineState::Running;

        // A live node holding one contact the persisted table has never seen.
        let learned = KadContact {
            id: Kad128::from_hash(&[0x6B; 16]),
            ip: 0x0808_0404,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
            udp_key: 0,
            udp_key_ip: 0,
            verified: true,
        };
        let node = KadNode::bind("127.0.0.1:0".parse().unwrap(), 4662)
            .await
            .unwrap();
        node.with_routing(|t| t.load_nodes(std::slice::from_ref(&learned)));
        engine.kad = Some(node);
        assert!(
            !engine.routing.contains(&learned.id),
            "precondition: the contact is live-table-only"
        );

        engine.pause_for_seeding().await;
        assert_eq!(engine.state(), EngineState::Seeding);
        assert!(
            engine.kad.is_some(),
            "seeding dropped the Kad node - publishing idles for the whole \
             session and the serve loop stops answering (decided 2026-08-09: \
             keep it)"
        );
        assert!(
            engine.routing.contains(&learned.id),
            "the live table was not absorbed on the way in - a jetsam kill \
             would forget what the session learned"
        );
        let nd = read_nodes_dat(&std::fs::read(dir.join("nodes.dat")).unwrap()).unwrap();
        assert!(
            nd.contacts.iter().any(|c| c.id == learned.id),
            "the seeding boundary must still checkpoint nodes.dat - jetsam \
             gives no warning"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Coming back from a seed whose Kad node SURVIVED must not start a second
    /// one: `start_kad` binds a fresh socket and reseeds from one bootstrap, so
    /// an unconditional call would either fail its bind (a spurious error
    /// event) or replace a live table with a bootstrap-sized one. The engine
    /// holds no routable contact here, so a `start_kad` that runs at all
    /// announces itself with "no Kad contacts to bootstrap" - the seam both
    /// arms assert on. Arm 2 proves the guard is `is_none`, not `state`: a
    /// seed ENTERED without a node must still get one back on resume.
    ///
    /// Mutation checks: make `resume_from_seeding` call `start_kad`
    /// unconditionally and arm 1 fails on the event; make it never call
    /// `start_kad` and arm 2 fails.
    #[tokio::test]
    async fn resume_from_seeding_rebuilds_kad_only_when_the_node_is_gone() {
        let dir = tmp("seed-resume-kad");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        engine.state = EngineState::Running;
        let node = KadNode::bind("127.0.0.1:0".parse().unwrap(), 4662)
            .await
            .unwrap();
        engine.kad = Some(node);

        engine.pause_for_seeding().await;
        assert!(
            engine.kad.is_some(),
            "precondition: the node survived the seed"
        );
        let _ = drain(&mut rx).await;

        engine.resume().await;
        assert_eq!(engine.state(), EngineState::Running);
        assert!(engine.kad.is_some(), "resume must keep the surviving node");
        let evs = drain(&mut rx).await;
        assert!(
            !evs.iter().any(
                |e| matches!(e, EngineEvent::Server(s) if s == "no Kad contacts to bootstrap")
            ),
            "resume ran start_kad against a LIVE node - that rebinds or \
             replaces the socket; got {evs:?}"
        );

        // Arm 2: a seed entered WITHOUT a node still gets one back on resume.
        engine.pause_for_seeding().await;
        engine.kad = None; // as after a failed bind, or an offline entry
        let _ = drain(&mut rx).await;
        engine.resume().await;
        let evs = drain(&mut rx).await;
        assert!(
            evs.iter().any(
                |e| matches!(e, EngineEvent::Server(s) if s == "no Kad contacts to bootstrap")
            ),
            "with the node gone, resume must run start_kad (its empty-table \
             complaint is the proof it ran); got {evs:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Kad publishing ACTUALLY RUNS while seeding, now that the node survives
    /// (the gate test above pins only admission). Reached through the REAL
    /// boundary - `pause_for_seeding` - with a shared file due, a live node
    /// holding one silent loopback contact, and the cadence back-dated: the
    /// duty must get past the state gate, the sharing gate AND the
    /// Kad-availability guard, and POP a real job. The popped job is observed
    /// on the stats counter, which by its own rule advances only when a job
    /// is consumed. The walk then sends one FIND_NODE at the silent peer and
    /// gives up at its per-query deadline - offline, bounded, no egress.
    ///
    /// Mutation check: restore `set_kad(None)` in `pause_for_seeding` and this
    /// fails on the jobs count (the availability guard idles the pass).
    #[tokio::test]
    async fn kad_publishing_pops_a_real_job_while_seeding() {
        let dir = tmp("seed-publishes");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.state = EngineState::Running;
        engine.set_sharing(true);
        engine.shared.lock().await.push(SharedFile {
            hash: [0xC4; 16],
            size: 10,
            name: b"ubuntu iso image.bin".to_vec(),
            part_hashes: vec![],
            path: dir.join("ubuntu iso image.bin"),
            rating: 0,
            comment: String::new(),
            aich_root: None,
        });
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let peer_ip = match peer_addr.ip() {
            IpAddr::V4(v) => u32::from(v),
            IpAddr::V6(_) => unreachable!("bound v4 above"),
        };
        let node = KadNode::bind("127.0.0.1:0".parse().unwrap(), 4662)
            .await
            .unwrap();
        node.with_routing(|t| {
            t.add(
                Kad128::from_hash(&[0x21; 16]),
                peer_ip,
                peer_addr.port(),
                4662,
                8,
                true,
            )
        });
        engine.kad = Some(node);

        engine.pause_for_seeding().await;
        assert_eq!(engine.state(), EngineState::Seeding);

        // Held across the measurement per STATS_TEST_LOCK's rule.
        let _stats = crate::stats::STATS_TEST_LOCK.lock();
        let (jobs0, _) = crate::stats::kad_publish_counts();
        engine.last_kad_publish = Instant::now() - KAD_PUBLISH_EVERY * 2;
        engine.maintain_kad_publish().await;
        let (jobs1, _) = crate::stats::kad_publish_counts();
        assert_eq!(
            jobs1,
            jobs0 + 1,
            "while Seeding with a live node and due work, the duty must pop a \
             real publish job - not idle at the availability guard"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE MAINTENANCE SPLIT WHILE SEEDING (decided 2026-08-09, reasoning at
    /// the two gates): the liveness sweep KEEPS running - a node that serves
    /// and publishes for hours is exactly the one that accumulates dead
    /// contacts, and the sweep is the only thing that removes them - while
    /// the growth refresh stays Running-only, because it buys search breadth
    /// a seeding session never uses at the largest lock+battery cost of the
    /// Kad duties. Both stamps sit past their state gates, so each arm is a
    /// direct read on its gate.
    ///
    /// Mutation checks: make the sweep's gate Running-only again and arm 1
    /// fails; admit Seeding in `maintain_kad`'s gate and arm 2 fails.
    #[tokio::test]
    async fn while_seeding_the_liveness_sweep_runs_and_the_growth_refresh_does_not() {
        let dir = tmp("seed-maint-split");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.state = EngineState::Seeding;

        let old = Instant::now() - KAD_SWEEP_EVERY * 2;
        engine.last_kad_sweep = old;
        engine.maintain_kad_liveness().await;
        assert!(
            engine.last_kad_sweep > old,
            "the liveness sweep must keep running while Seeding - a node that \
             serves and publishes for hours most needs to shed its dead"
        );

        let old = Instant::now() - KAD_REFRESH_EVERY * 2;
        engine.last_kad_refresh = old;
        engine.maintain_kad().await;
        assert_eq!(
            engine.last_kad_refresh, old,
            "the growth refresh is Running-only on purpose: it buys search \
             breadth a seeding session never uses, at the largest lock+battery \
             cost of the Kad duties"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_single_silent_probe_does_not_kill_a_server() {
        // UDP loses datagrams - more so through a VPN at ~200ms RTT. One silent
        // round greyed out servers that were answering moments earlier and that
        // padMule had been connecting to. Observed live: the same two servers
        // read "no reply", then 3,651 / 47,008 users minutes later.
        //
        // Drives the REAL fold, not a copy of it (see fold_probe_round).
        let mut h = ProbeHealth {
            users: 0,
            files: 0,
            misses: 0,
            answered: false,
        };

        // It answers once: alive, with its numbers.
        let v = fold_probe_round(&mut h, true, 3_651, 9);
        assert!(v.alive && !v.checking);
        assert_eq!(v.users, 3_651);

        // Two silent rounds: still believed live, still showing what it said.
        for round in 1..PROBE_MISSES_BEFORE_DEAD {
            let v = fold_probe_round(&mut h, false, 0, 0);
            assert!(v.alive, "one lost datagram is not a death (round {round})");
            assert_eq!(v.users, 3_651, "keeps its last good numbers");
        }
        // The third consecutive miss is a real signal.
        let v = fold_probe_round(&mut h, false, 0, 0);
        assert!(!v.alive && !v.checking, "three misses in a row IS dead");
    }

    /// A COLD START must not call every server dead. The probe's history lives
    /// in memory, so on a fresh launch nothing has ever answered - and the old
    /// rule skipped those servers entirely, leaving `alive: false`, which the
    /// screen printed as "no reply". That is a verdict from one datum, and it is
    /// wrong: on 2026-08-05 padMule showed `eMule Sunrise` as "no reply" and
    /// then logged into it with HighID moments later.
    #[test]
    fn a_never_answered_server_reads_as_checking_not_dead() {
        let mut h = ProbeHealth {
            users: 0,
            files: 0,
            misses: 0,
            answered: false,
        };
        for round in 1..PROBE_MISSES_BEFORE_DEAD {
            let v = fold_probe_round(&mut h, false, 0, 0);
            assert!(
                v.checking && !v.alive,
                "round {round}: unknown is not dead, and must not be shown as dead"
            );
        }
        // ...but silence is not indefinitely excusable either.
        let v = fold_probe_round(&mut h, false, 0, 0);
        assert!(
            !v.checking && !v.alive,
            "after {PROBE_MISSES_BEFORE_DEAD} silent rounds it really is dead"
        );

        // And a late first answer clears everything.
        let v = fold_probe_round(&mut h, true, 42, 7);
        assert!(v.alive && !v.checking);
        assert_eq!((v.users, v.files), (42, 7));
    }

    #[tokio::test]
    async fn checkpoint_persists_identity_on_pause() {
        let dir = tmp("ckpt");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_offline(true);
        let uh = engine.userhash();
        std::fs::remove_file(dir.join("preferences.dat")).unwrap();
        engine.start().await;
        engine.pause().await; // checkpoint re-writes identity + the credit store
        assert!(dir.join("preferences.dat").exists());
        // The credit store is checkpointed alongside (clients.met, valid on read).
        assert!(dir.join("clients.met").exists());
        assert!(
            mule_files::read_clients_met(&std::fs::read(dir.join("clients.met")).unwrap()).is_ok()
        );
        let re =
            mule_files::read_preferences_dat(&std::fs::read(dir.join("preferences.dat")).unwrap())
                .unwrap();
        assert_eq!(re, uh);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- nickname -------------------------------------------------------

    /// CT_NAME, the tag both wire paths carry the nickname in. Declared here
    /// rather than imported because `peer.rs` and `server_messages.rs` each keep
    /// their own private copy of the number (eD2k CT_NAME = 0x01); a test that
    /// re-derived it from one of them would prove less, not more.
    const CT_NAME_TAG: u8 = 0x01;

    /// Pull the CT_NAME string out of a parsed HELLO.
    fn hello_nick(p: &crate::peer::ParsedHello) -> Option<String> {
        p.tags.iter().find_map(|t| match (&t.name, &t.value) {
            (TagName::Id(i), TagValue::Str(v)) if *i == CT_NAME_TAG => {
                Some(String::from_utf8_lossy(v).into_owned())
            }
            _ => None,
        })
    }

    /// The CT_NAME tag as it appears in a login packet's payload: tag header
    /// (type 0x02 = string, name length 1, name byte CT_NAME), then the u16
    /// length and the bytes. Same encoding the golden login test pins
    /// (`server_messages::tests::login_request_golden_payload`).
    fn ct_name_tag_bytes(nick: &str) -> Vec<u8> {
        let mut v = vec![0x02, 0x01, 0x00, CT_NAME_TAG];
        v.extend_from_slice(&(nick.len() as u16).to_le_bytes());
        v.extend_from_slice(nick.as_bytes());
        v
    }

    /// AN UNTOUCHED INSTALL STILL SAYS "padMule". The nickname became a setting;
    /// the DEFAULT is the behaviour every build before it had, so a user who
    /// never opens Settings must be indistinguishable from one running the old
    /// build.
    #[test]
    fn the_default_nickname_is_padmule() {
        let dir = tmp("nick-default");
        let _ = std::fs::remove_dir_all(&dir);
        let (engine, _rx) = Engine::new(&dir).unwrap();
        assert_eq!(engine.nickname(), "padMule");
        assert_eq!(DEFAULT_NICK, "padMule");
        // And it is what both wire paths would carry, not merely what the
        // getter reports.
        assert_eq!(engine.hello_baseline().nick, "padMule");
        assert_eq!(engine.login_request().nick, "padMule");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE SET NAME REACHES BOTH WIRE PATHS, AS BYTES.
    ///
    /// Not "the field round-trips" - that would pass with the HELLO and the
    /// login still holding their old literals. This builds the actual packets
    /// the peer path and the server path send and reads CT_NAME back out of
    /// each, which is the only claim that matters: a peer and a server see the
    /// same name, and it is the one the user chose.
    #[test]
    fn a_set_nickname_reaches_the_peer_hello_and_the_server_login() {
        let dir = tmp("nick-wire");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();
        engine.set_nickname("Tony's iPad");

        // The peer HELLO. `hello_baseline` is the ONE constructor both the
        // inbound listener and an outbound fetch use, so proving it here proves
        // both sites; the flags they add (.with_secident, .with_crypt_supported)
        // do not touch the name.
        let hello = crate::peer::build_hello(&engine.hello_baseline());
        let parsed = crate::peer::parse_hello(&hello.payload, true).unwrap();
        assert_eq!(
            hello_nick(&parsed).as_deref(),
            Some("Tony's iPad"),
            "the peer HELLO must carry the user's name in CT_NAME"
        );

        // The server login, the same name, as bytes inside the packet.
        let login = crate::server_messages::build_login_request(&engine.login_request());
        let want = ct_name_tag_bytes("Tony's iPad");
        assert!(
            login.payload.windows(want.len()).any(|w| w == want),
            "the server login must carry the SAME name in CT_NAME"
        );
        // Nothing anywhere still announces the hardcoded default.
        assert!(
            !login.payload.windows(7).any(|w| w == b"padMule".as_slice()),
            "the old hardcoded nickname must be gone from the login"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// EMPTY FALLS BACK, LONG IS CUT, JUNK IS STRIPPED - eMule's rules.
    ///
    /// eMule 0.70b `CPPgGeneral::OnApply` (PPgGeneral.cpp:187-191) trims, then
    /// substitutes the default for an empty nickname; the 50-character cap is
    /// `GetMaxUserNickLength()` (Preferences.h:690, and 0.50a Preferences.h:661
    /// agrees). The control-character strip is padMule's stated divergence from
    /// `IsValidEd2kString`, whose '?' rule is a Windows ANSI artifact - see
    /// `sanitize_nick`. Asserted through the ENGINE, so it pins what goes on the
    /// wire and not merely the helper.
    #[test]
    fn an_empty_or_oversized_or_control_laden_nickname_is_repaired() {
        let dir = tmp("nick-sanitize");
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, _rx) = Engine::new(&dir).unwrap();

        // Empty, and whitespace-only, both fall back to the default rather than
        // announcing a nameless client.
        engine.set_nickname("");
        assert_eq!(engine.nickname(), DEFAULT_NICK);
        engine.set_nickname("Tony");
        engine.set_nickname("   \t  ");
        assert_eq!(
            engine.nickname(),
            DEFAULT_NICK,
            "whitespace-only is empty once trimmed, like CString::Trim makes it"
        );

        // Trimmed, not rejected.
        engine.set_nickname("  Tony  ");
        assert_eq!(engine.nickname(), "Tony");

        // Capped at eMule's 50 CHARACTERS. The LITERAL 50 leads on purpose:
        // `chars().count() == MAX_NICK_LEN` moves with the constant and so
        // cannot catch the constant changing, which is the regression that
        // matters (verified - a 50 -> 60 mutant survives that line and dies on
        // these two).
        let long = "N".repeat(120);
        engine.set_nickname(&long);
        assert_eq!(engine.nickname(), "N".repeat(50));
        assert_eq!(MAX_NICK_LEN, 50, "eMule's GetMaxUserNickLength");
        assert_eq!(engine.nickname().chars().count(), MAX_NICK_LEN);

        // Control characters never reach the wire. A newline is the realistic
        // one (paste from a text field) and is exactly what mangles another
        // client's log line.
        engine.set_nickname("Tony\r\n\u{0}iPad");
        assert_eq!(engine.nickname(), "TonyiPad");
        // Scan the NICK, not the whole packet. The login embeds a RANDOMLY
        // GENERATED 16-byte userhash (identity.rs:33), so a byte-scan of the
        // whole payload fails on ~5% of runs when the random bytes happen to
        // contain a 0x0A - a flake with nothing to do with nicknames, found by
        // the 35a agent hitting it live. Assert the two things actually
        // claimed: the sanitized name REACHED the wire, and it carries no
        // control byte.
        let login = crate::server_messages::build_login_request(&engine.login_request());
        assert!(
            login.payload.windows(8).any(|w| w == b"TonyiPad"),
            "the sanitized nickname must reach the login packet"
        );
        assert!(
            !engine.nickname().bytes().any(|b| b.is_ascii_control()),
            "no control character may survive sanitization"
        );

        // '?' is KEPT - the deliberate divergence from IsValidEd2kString, whose
        // own comment says the character is a Windows ANSI-mode artifact. On a
        // UTF-8 client it is an ordinary character, and discarding the whole
        // nickname over it would be a surprise with no benefit.
        engine.set_nickname("who? me");
        assert_eq!(engine.nickname(), "who? me");

        // Multi-byte input is counted in characters, not bytes, so a name in a
        // non-Latin script gets the same 50 as an ASCII one.
        let cyrillic = "\u{044f}".repeat(60);
        engine.set_nickname(&cyrillic);
        assert_eq!(engine.nickname().chars().count(), MAX_NICK_LEN);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod live {
    use super::*;

    /// The real thing, exactly as a FRESH iPad install experiences it: an empty
    /// config dir with no server.met and no nodes.dat -> fetch both and
    /// bootstrap Kad. Deliberately does NOT expect a server login: start() has
    /// not auto-connected since the Servers screen landed (row 8x) - the user
    /// picks a live server, like eMule. Ignored by default (needs the network);
    /// run with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn fresh_install_fetches_bootstrap_data_and_joins_kad() {
        let dir = std::env::temp_dir().join(format!("padmule-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (mut engine, mut rx) = Engine::new(&dir).unwrap();
        assert!(!dir.join("server.met").exists(), "fresh: no server list");
        assert!(!dir.join("nodes.dat").exists(), "fresh: no Kad contacts");

        engine.start().await;

        // It fetched the bootstrap data it had none of.
        assert!(dir.join("server.met").exists(), "server.met was fetched");
        assert!(dir.join("nodes.dat").exists(), "nodes.dat was fetched");
        // No auto-connect: the server link waits for the user's pick.
        assert!(!engine.is_online(), "start() must not auto-connect");
        // But Kad joined on its own.
        assert!(engine.kad_contacts() > 0, "Kad routing table is populated");

        let mut evs = Vec::new();
        while let Ok(e) = rx.try_recv() {
            evs.push(e);
        }
        println!("--- engine events on a fresh start ---");
        for e in &evs {
            println!("{e:?}");
        }
        assert!(
            evs.iter()
                .any(|e| matches!(e, EngineEvent::Kad { contacts } if *contacts > 0)),
            "a Kad event reported the populated table"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
