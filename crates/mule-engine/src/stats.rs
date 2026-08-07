//! Process-session transfer counters: total file-data bytes moved over the wire
//! this run (download + upload).
//!
//! These are GLOBAL, not per-`Engine`, on purpose. There is one `Engine` per
//! process (session = process launch), and threading two counters through the
//! whole transfer call chain (`download_file` -> `fetch_from_sources` ->
//! `download_from_peer`, plus `serve_shared`) would touch a dozen signatures and
//! their test call sites for no added fidelity. Counting at the two byte points
//! is one line each and gives LIVE, incremental totals.
//!
//! The engine only counts bytes; the UI derives rate history and the up:down
//! ratio by SAMPLING these monotonic totals (see the stats screen). Only file
//! DATA is counted - handshake/control packets are protocol overhead, excluded,
//! matching how eMule reports "session down/up".

use std::sync::atomic::{AtomicU64, Ordering};

static BYTES_DOWN: AtomicU64 = AtomicU64::new(0);
static BYTES_UP: AtomicU64 = AtomicU64::new(0);

/// Count `n` bytes of file data RECEIVED from a peer (download).
pub fn add_downloaded(n: u64) {
    BYTES_DOWN.fetch_add(n, Ordering::Relaxed);
}

/// Count `n` bytes of file data SENT to a peer (upload).
pub fn add_uploaded(n: u64) {
    BYTES_UP.fetch_add(n, Ordering::Relaxed);
}

/// Total bytes downloaded this process-session.
pub fn downloaded() -> u64 {
    BYTES_DOWN.load(Ordering::Relaxed)
}

/// Total bytes uploaded this process-session.
pub fn uploaded() -> u64 {
    BYTES_UP.load(Ordering::Relaxed)
}

// ---------------------------------------------------------------------------
// THE FETCH FUNNEL
// ---------------------------------------------------------------------------
//
// Why this exists: the 2026-08-04 stress runs measured that 15 of 17 source
// lookups found 2-7 usable sources, yet only ~5 of 20 downloads ever received a
// byte. Sources are found; data does not follow - and NOBODY had looked inside
// that gap. Every theory about it (the queue-bail "root cause") was written down
// before it was tested, and measurement then said four times worse.
//
// So: count, per PEER SESSION, how far down the eD2k request sequence it got.
// These are CUMULATIVE stage counters, not a per-attempt verdict, which is why
// they need no per-attempt state at all - one line at each transition. The DROP
// between two adjacent stages IS the loss at that stage, including a loss to the
// outer per-peer timeout, which no error value can report.
//
// Global for the same reason the byte counters are (see the module header):
// threading a tracker through `download_file` -> `fetch_one` ->
// `download_from_peer_at` -> `run_peer` would touch every call site in the CLI
// and a dozen tests for no added fidelity.

macro_rules! funnel {
    ($($id:ident => $note:ident / $get:ident, $label:literal;)*) => {
        $(
            static $id: AtomicU64 = AtomicU64::new(0);
            /// Count one peer session reaching this stage.
            pub fn $note() { $id.fetch_add(1, Ordering::Relaxed); }
            /// How many peer sessions reached this stage this run.
            pub fn $get() -> u64 { $id.load(Ordering::Relaxed) }
        )*
        /// The funnel as ordered `(label, count)` pairs, widest stage first.
        pub fn fetch_funnel() -> Vec<(&'static str, u64)> {
            vec![$(($label, $get())),*]
        }
        /// Every funnel counter, so `reset_fetch_stats` cannot miss one when a
        /// new stage is added - the macro is the single place stages are listed.
        static FUNNEL_REFS: &[&AtomicU64] = &[$(&$id),*];
    };
}

// TWO ENTRY PATHS, and conflating them made the first device report IMPOSSIBLE:
// `got filestatus` read 396 against `connected` 315. A session cannot read a
// file status without connecting first - unless it never dialed at all.
//
// It did not. A called-back source DIALS US (engine.rs `InboundKind::Source`),
// so it enters `download_from_peer_at` directly, never through `fetch_one`, and
// bumps every stage EXCEPT the two dial stages. Worse, one inbound connection is
// offered EVERY unfinished download in turn, so a single callback can produce
// several sessions. With a HighID user and LowID peers calling back, that was
// ~160 phantom sessions in an outbound funnel.
//
// So the report is now three labelled groups instead of one column: what WE
// dialed, what dialed US, and the per-session stages both paths share. The stage
// counts were never wrong - only the story the layout told about them.
funnel! {
    F_DIAL      => note_dial / dials,             "outbound dials";
    F_CONN      => note_connected / connected,    "  handshaked";
    F_INBOUND   => note_inbound / inbound,        "inbound sessions (they dialed us)";
    F_STATUS    => note_status / got_status,      "got filestatus";
    // NOT a subset of the line above: the NOFILE arm returns BEFORE the
    // filestatus counter, so these are disjoint. The old indentation implied
    // otherwise and made the totals look broken.
    F_NOFILE    => note_nofile / nofile,          "peer said NOFILE instead";
    F_NONEEDED  => note_no_needed_parts / no_needed_parts, "holds nothing we need";
    F_HS_NEED   => note_hashset_need / hashset_need, "needed hashset";
    F_HS_GOT    => note_hashset_got / hashset_got,   "  got hashset";
    F_SLOT_ASK  => note_slot_ask / slot_asked,    "asked for a slot";
    F_ACCEPT    => note_accepted / accepted,      "  slot ACCEPTED";
    F_QUEUED    => note_queued / queued,          "  queued (bailed)";
    F_NOBLOCK   => note_no_blocks / no_blocks,    "accepted, no block to take";
    F_REQ       => note_requested / requested,    "requested blocks";
    F_DELIVERED => note_delivered / delivered,    "DELIVERED bytes";
    F_REVOKED   => note_revoked / revoked,        "  slot REVOKED (0x57)";
    // WHY A RESTART UNSTICKS A STALLED DOWNLOAD. Anthony's observation: a file
    // sat at 85% for a long time, the app was restarted, and it finished. That
    // narrows the blocker to in-memory state a restart clears, and there are
    // exactly two such gates on the dial path - both counted here so the next
    // stall says which, instead of being argued about.
    //
    // `skipped BANNED`: the per-download corruption ban set is a plain
    // in-memory HashSet, never persisted, and `is_banned` is consulted BEFORE
    // dialing - so a download whose handful of sources all got banned makes ZERO
    // dials while still listing them, until a restart forgets the bans.
    //
    // `fetch already running`: see the correction below - this counter does NOT
    // observe a stuck flag, and `fetches in flight` is what does.
    F_BANSKIP   => note_skipped_banned / skipped_banned, "skipped: source BANNED";
    F_FETCHBUSY => note_fetch_busy / fetch_busy,  "spawn raced a live fetch";
}

/// How many downloads hold the in-flight fetch claim RIGHT NOW.
///
/// CORRECTION (2026-08-05) to the pair above. `skipped: fetch already running`
/// was added to catch the second restart-clearable gate - a `fetching` flag that
/// never clears - and it CANNOT: `note_fetch_busy` sits on `spawn_fetch`'s
/// refusal branch, but every caller already filters `!is_fetching()` before it
/// gets there (`resume_fetches` engine.rs:3641, `maintain_resume_fetches`
/// :4133, and `add_download` only ever spawns a brand-new download). A download
/// whose flag is stuck is EXCLUDED by those filters and never reaches the
/// counter, so the line reads 0 in exactly the case it was built to name. What
/// it does count is the rare genuine race between the filter and the spawn,
/// which is why it is now labelled as that.
///
/// THIS IS THE FIX, and it is the shape of the mistake as much as the mistake:
/// a stuck flag is durable STATE, and it was being chased with a momentary
/// EVENT. So this is a GAUGE - claimed up, released down, never reset by
/// `reset_fetch_stats`, because zeroing it would erase the fetches that are
/// genuinely running. Read it as state: a number that stays put while nothing
/// moves on the Transfers screen is the stuck flag, visible at last.
///
/// Note the standing expectation this is meant to TEST rather than assume:
/// `FetchGuard` (engine.rs:716) releases the claim on any task exit including
/// unwind, and `download_file` is bounded on every axis, so a stuck flag should
/// be unreachable. That is an argument, not a measurement, and this is the
/// measurement.
static FETCH_INFLIGHT: AtomicU64 = AtomicU64::new(0);

/// One download just claimed its fetch slot.
pub fn note_fetch_claimed() {
    FETCH_INFLIGHT.fetch_add(1, Ordering::Relaxed);
}

/// One download just released it. Saturating: a gauge that underflows to
/// u64::MAX would be worse than useless in the report.
pub fn note_fetch_released() {
    let _ = FETCH_INFLIGHT.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_sub(1))
    });
}

/// Downloads holding a fetch claim right now.
pub fn fetches_in_flight() -> u64 {
    FETCH_INFLIGHT.load(Ordering::Relaxed)
}

/// Opcodes a wait loop read while it was waiting for something else, tallied by
/// opcode. A stage that loses sessions is only half the answer; this says WHAT
/// the peer sent instead, by number, so the diagnosis is not a guess about which
/// packet padMule failed to act on.
///
/// A fixed 256-entry array rather than a map: this is on the packet-read path,
/// so it must be lock-free, and 2KB of statics is cheaper than the `HashMap`
/// entry it replaces.
static UNEXPECTED: [AtomicU64; 256] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; 256]
};

/// Record that `opcode` arrived while a loop was waiting for a different packet.
pub fn note_unexpected(opcode: u8) {
    UNEXPECTED[opcode as usize].fetch_add(1, Ordering::Relaxed);
}

/// How long dials take, bucketed, split by whether they SUCCEEDED.
///
/// This exists to answer one question with data instead of taste: padMule gives
/// a peer session 45s, and the connect shares that budget, so a black-holed
/// address costs one of only FOUR workers for that download a full 45 seconds.
/// Both authorities do use CONNECTION_TIMEOUT = 40s (eMule opcodes.h:62, aMule
/// Constants.h:33-35), but eMule multiplexes hundreds of sockets, so a stalled
/// one costs it nothing; padMule's worker pool makes the same number a
/// throughput cap.
///
/// A shorter CONNECT deadline is only free if slow-but-alive peers do not exist.
/// The SUCCEEDED row settles that: if successful handshakes all land in the
/// first seconds, everything past that is dead air and can be cut. If they are
/// spread out, cutting would throw away real sources - and the honest answer is
/// to leave the timeout alone and widen the worker pool instead.
///
/// IT ANSWERED THAT, AND IS NOW CENSORED BY ITS OWN ANSWER. The device reading
/// (313 of 315 successful handshakes under 10s, one at 5-10s, two at 20-45s) set
/// `fetch::CONNECT_TIMEOUT` to 10s - so no dial can now last longer than that,
/// and every bucket above 10s is structurally dead. A future "20-45s: 0" is NOT
/// evidence that a network has no slow tail; it is the cap talking. Re-measuring
/// on a different path (another VPN exit, cellular) means raising the cap first.
const DIAL_BUCKET_MS: [u64; 6] = [1_000, 2_000, 5_000, 10_000, 20_000, 45_000];
static DIAL_OK: [AtomicU64; 7] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; 7]
};
static DIAL_FAIL: [AtomicU64; 7] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const Z: AtomicU64 = AtomicU64::new(0);
    [Z; 7]
};

/// Record a finished dial: how long it took, and whether it handshaked.
pub fn note_dial_time(elapsed_ms: u64, ok: bool) {
    let i = DIAL_BUCKET_MS
        .iter()
        .position(|&b| elapsed_ms < b)
        .unwrap_or(DIAL_BUCKET_MS.len());
    let row = if ok { &DIAL_OK } else { &DIAL_FAIL };
    row[i].fetch_add(1, Ordering::Relaxed);
}

/// Dial-duration buckets as `(label, connected, failed)`.
pub fn dial_times() -> Vec<(String, u64, u64)> {
    let mut out = Vec::with_capacity(7);
    let mut lo = 0u64;
    for (i, &hi) in DIAL_BUCKET_MS.iter().enumerate() {
        out.push((
            format!("{}-{}s", lo / 1000, hi / 1000),
            DIAL_OK[i].load(Ordering::Relaxed),
            DIAL_FAIL[i].load(Ordering::Relaxed),
        ));
        lo = hi;
    }
    out.push((
        ">=45s (timeout)".to_string(),
        DIAL_OK[6].load(Ordering::Relaxed),
        DIAL_FAIL[6].load(Ordering::Relaxed),
    ));
    out
}

/// Every opcode seen out of turn, as `(opcode, count)`, most frequent first.
pub fn unexpected_opcodes() -> Vec<(u8, u64)> {
    let mut v: Vec<(u8, u64)> = (0..256usize)
        .filter_map(|i| {
            let n = UNEXPECTED[i].load(Ordering::Relaxed);
            (n > 0).then_some((i as u8, n))
        })
        .collect();
    v.sort_by_key(|&(_, n)| std::cmp::Reverse(n));
    v
}

/// Zero every fetch counter.
///
/// Needed because the counters are cumulative since LAUNCH, so by the time a
/// download stalls they are dominated by the healthy minutes before it. The
/// diagnostic workflow is reset -> reproduce -> read, and without this the
/// numbers cannot be attributed to the thing being investigated. Byte totals
/// are deliberately NOT reset - those are the user's session stats, not a
/// diagnostic.
pub fn reset_fetch_stats() {
    for c in FUNNEL_REFS {
        c.store(0, Ordering::Relaxed);
    }
    for c in UNEXPECTED.iter() {
        c.store(0, Ordering::Relaxed);
    }
    for c in DIAL_OK.iter().chain(DIAL_FAIL.iter()) {
        c.store(0, Ordering::Relaxed);
    }
}

/// The funnel and the out-of-turn opcodes as a printable block.
pub fn fetch_report() -> String {
    // Three groups, because the two entry paths do not share the dial stages -
    // see the `funnel!` block. Printing them as one column made a correct set of
    // counts look impossible.
    let mut s = String::from("  HOW SESSIONS START\n");
    for (label, n) in fetch_funnel() {
        if label == "got filestatus" {
            s.push_str("  THEN, PER SESSION (both paths)\n");
        }
        s.push_str(&format!("    {label:<34} {n:>6}\n"));
    }
    // STATE, not a count - printed apart from the funnel and unaffected by
    // Reset, because it describes what is happening NOW rather than what has
    // happened since. See `FETCH_INFLIGHT`.
    s.push_str(&format!(
        "  STATE (not reset)\n    {:<34} {:>6}\n",
        "fetches in flight",
        fetches_in_flight()
    ));
    s.push_str("  DIAL TIME - OUTBOUND ONLY (bucket: connected / failed)\n");
    for (label, ok, fail) in dial_times() {
        if ok + fail > 0 {
            s.push_str(&format!("    {label:<18} {ok:>6} / {fail:<6}\n"));
        }
    }
    let un = unexpected_opcodes();
    if !un.is_empty() {
        s.push_str("  OPCODES READ OUT OF TURN (opcode: count)\n    ");
        for (op, n) in un {
            s.push_str(&format!("0x{op:02X}:{n}  "));
        }
        s.push('\n');
    }
    s
}

// ---------------------------------------------------------------------------
// THE KAD LOOKUP PROFILE
// ---------------------------------------------------------------------------
//
// ONE QUESTION, and the answer decides whether a rewrite is worth doing.
//
// Since 2026-08-07 a lookup round sends its ALPHA_QUERY requests together and
// waits ONE window for them (`KadNode::request_batch`). That window ends when
// the last member answers - or, if any member never does, at the full
// `KAD_PER_QUERY` deadline. So a round costs either "the slowest RTT" or "the
// whole timeout", and which one dominates in practice is the difference between:
//
//   - most rounds have a silent member -> the BARRIER is the cost, and eMule's
//     event-driven CSearch (no rounds at all; a response immediately fires the
//     next request, and keyword requests interleave with the lookup) would be a
//     large win;
//   - rounds rarely have a silent member -> the cost is genuine lookup DEPTH in
//     round trips, which no amount of restructuring removes, and the rewrite
//     would buy almost nothing.
//
// Measured A/B on 2026-08-07 put the batching win at about -25% median, well
// short of the 3x the worst-case arithmetic implies - which says most queried
// nodes DO answer. That is an inference from an aggregate; this counts it
// directly. `rounds with a silent peer` against `rounds run` is the whole
// reading.
//
// Global, lock-free, and reset with the fetch funnel, for the reasons in the
// module header - and because a diagnostic that queued behind the engine lock
// would be unreadable exactly when it is needed.

static K_LOOKUPS: AtomicU64 = AtomicU64::new(0);
static K_ROUNDS: AtomicU64 = AtomicU64::new(0);
static K_ROUNDS_SILENT: AtomicU64 = AtomicU64::new(0);
static K_SENT: AtomicU64 = AtomicU64::new(0);
static K_ANSWERED: AtomicU64 = AtomicU64::new(0);
static K_ROUND_MS: AtomicU64 = AtomicU64::new(0);
static K_WINDOWS: AtomicU64 = AtomicU64::new(0);
static K_WINDOWS_SILENT: AtomicU64 = AtomicU64::new(0);
static K_WIN_SENT: AtomicU64 = AtomicU64::new(0);
static K_WIN_ANSWERED: AtomicU64 = AtomicU64::new(0);
static K_WINDOW_MS: AtomicU64 = AtomicU64::new(0);

static KAD_REFS: &[&AtomicU64] = &[
    &K_LOOKUPS,
    &K_ROUNDS,
    &K_ROUNDS_SILENT,
    &K_SENT,
    &K_ANSWERED,
    &K_ROUND_MS,
    &K_WINDOWS,
    &K_WINDOWS_SILENT,
    &K_WIN_SENT,
    &K_WIN_ANSWERED,
    &K_WINDOW_MS,
];

/// One `resolve_keyword` / `resolve_sources` / `refresh_routing` call started.
pub fn note_kad_lookup() {
    K_LOOKUPS.fetch_add(1, Ordering::Relaxed);
}

/// One FIND_NODE round finished: `sent` requests went out, `answered` came back,
/// and the batch window took `elapsed_ms`.
pub fn note_kad_round(sent: usize, answered: usize, elapsed_ms: u64) {
    K_ROUNDS.fetch_add(1, Ordering::Relaxed);
    K_SENT.fetch_add(sent as u64, Ordering::Relaxed);
    K_ANSWERED.fetch_add(answered as u64, Ordering::Relaxed);
    K_ROUND_MS.fetch_add(elapsed_ms, Ordering::Relaxed);
    if answered < sent {
        K_ROUNDS_SILENT.fetch_add(1, Ordering::Relaxed);
    }
}

/// One VALUE window finished - the keyword or source request that follows the
/// lookup. Same shape as a round, counted apart because it is the phase eMule
/// interleaves rather than defers.
pub fn note_kad_value_window(sent: usize, answered: usize, elapsed_ms: u64) {
    K_WINDOWS.fetch_add(1, Ordering::Relaxed);
    K_WIN_SENT.fetch_add(sent as u64, Ordering::Relaxed);
    K_WIN_ANSWERED.fetch_add(answered as u64, Ordering::Relaxed);
    K_WINDOW_MS.fetch_add(elapsed_ms, Ordering::Relaxed);
    if answered < sent {
        K_WINDOWS_SILENT.fetch_add(1, Ordering::Relaxed);
    }
}

/// Zero the Kad lookup profile (same reset button as the fetch funnel).
pub fn reset_kad_stats() {
    for c in KAD_REFS {
        c.store(0, Ordering::Relaxed);
    }
}

/// `n` as a percentage of `d`, or `-` when there is nothing to divide. A fresh
/// launch has every denominator at zero, and "0%" there would read as a measured
/// result rather than as no measurement.
fn pct(n: u64, d: u64) -> String {
    n.saturating_mul(100)
        .checked_div(d)
        .map_or_else(|| "-".to_string(), |v| format!("{v}%"))
}

/// `n` per `d`, or `-` when nothing has been measured yet.
fn per(n: u64, d: u64) -> String {
    n.checked_div(d)
        .map_or_else(|| "-".to_string(), |v| v.to_string())
}

/// The Kad lookup profile as a printable block.
pub fn kad_report() -> String {
    let (rounds, silent) = (
        K_ROUNDS.load(Ordering::Relaxed),
        K_ROUNDS_SILENT.load(Ordering::Relaxed),
    );
    let (wins, wsilent) = (
        K_WINDOWS.load(Ordering::Relaxed),
        K_WINDOWS_SILENT.load(Ordering::Relaxed),
    );
    let mut s = String::new();
    s.push_str(&format!(
        "    {:<32} {:>6}\n",
        "lookups run",
        K_LOOKUPS.load(Ordering::Relaxed)
    ));
    s.push_str("  FIND_NODE ROUNDS\n");
    s.push_str(&format!("    {:<32} {rounds:>6}\n", "rounds run"));
    // THE READING. A high share here means the batch window is being held open
    // by a peer that never answers, so the round costs the full KAD_PER_QUERY
    // and removing the barrier (eMule's event-driven CSearch) is worth doing. A
    // low share means the cost is lookup DEPTH, which a rewrite cannot remove.
    s.push_str(&format!(
        "    {:<32} {silent:>6}  ({})\n",
        "  with a SILENT peer",
        pct(silent, rounds)
    ));
    s.push_str(&format!(
        "    {:<32} {:>6} / {}\n",
        "  requests sent / answered",
        K_SENT.load(Ordering::Relaxed),
        K_ANSWERED.load(Ordering::Relaxed)
    ));
    s.push_str(&format!(
        "    {:<32} {:>6} ms\n",
        "  avg round",
        per(K_ROUND_MS.load(Ordering::Relaxed), rounds)
    ));
    s.push_str("  VALUE WINDOWS (keyword / source)\n");
    s.push_str(&format!("    {:<32} {wins:>6}\n", "windows run"));
    s.push_str(&format!(
        "    {:<32} {wsilent:>6}  ({})\n",
        "  with a SILENT peer",
        pct(wsilent, wins)
    ));
    s.push_str(&format!(
        "    {:<32} {:>6} / {}\n",
        "  requests sent / answered",
        K_WIN_SENT.load(Ordering::Relaxed),
        K_WIN_ANSWERED.load(Ordering::Relaxed)
    ));
    s.push_str(&format!(
        "    {:<32} {:>6} ms\n",
        "  avg window",
        per(K_WINDOW_MS.load(Ordering::Relaxed), wins)
    ));
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The reading this instrument exists for must actually MOVE with the thing
    /// it measures - a round where somebody stayed silent has to be counted as
    /// one, and a fully-answered round must not be.
    ///
    /// Asserted as DELTAS, because these are process-global and other tests bump
    /// them concurrently.
    #[test]
    fn a_silent_peer_in_a_round_is_what_the_silent_counter_counts() {
        let (r0, s0) = (
            K_ROUNDS.load(Ordering::Relaxed),
            K_ROUNDS_SILENT.load(Ordering::Relaxed),
        );
        note_kad_round(3, 3, 120); // everyone answered
        assert_eq!(
            K_ROUNDS_SILENT.load(Ordering::Relaxed),
            s0,
            "a fully-answered round must not count as silent - it cost one RTT, \
             not the timeout"
        );
        note_kad_round(3, 2, 750); // one never answered: the window ran to the deadline
        assert_eq!(K_ROUNDS_SILENT.load(Ordering::Relaxed), s0 + 1);
        assert_eq!(K_ROUNDS.load(Ordering::Relaxed), r0 + 2);
    }

    /// Every Kad counter must be in the reset list, or a stale value survives a
    /// reset -> reproduce -> read cycle and is read as fresh. Same guarantee the
    /// funnel gets from its macro, made explicit here because these are declared
    /// by hand.
    #[test]
    fn the_kad_reset_covers_every_kad_counter() {
        assert_eq!(
            KAD_REFS.len(),
            11,
            "a Kad counter was added or removed without updating KAD_REFS, so \
             reset_kad_stats no longer clears all of them"
        );
    }

    /// A report that divides by a zero denominator must not panic - it is read
    /// on a fresh launch, when every denominator IS zero.
    #[test]
    fn the_kad_report_survives_having_measured_nothing() {
        reset_kad_stats();
        let s = kad_report();
        assert!(s.contains("rounds run"));
        assert!(s.contains('-'), "an empty ratio should read as '-', not 0%");
    }

    /// `reset_fetch_stats` must clear EVERY funnel stage, and the only way to
    /// guarantee that as stages are added is for the reset to iterate the same
    /// list the macro generates. Asserting the two agree is race-free, unlike
    /// asserting a counter reads zero - these are process-global and other
    /// tests bump them concurrently.
    #[test]
    fn the_reset_covers_every_funnel_stage() {
        assert_eq!(
            FUNNEL_REFS.len(),
            fetch_funnel().len(),
            "a stage was added to the funnel that reset_fetch_stats would miss"
        );
        // The report must name every stage too, or a counter is invisible.
        for (label, _) in fetch_funnel() {
            assert!(
                fetch_report().contains(label.trim()),
                "stage {label:?} is counted but never printed"
            );
        }
    }

    /// The in-flight GAUGE must survive `reset_fetch_stats`. This is the whole
    /// reason it lives outside the `funnel!` macro: Reset is for cumulative
    /// history, and zeroing a gauge would report "no fetches running" while
    /// downloads were running - stating the opposite of the truth at exactly the
    /// moment somebody is trying to diagnose a stall.
    ///
    /// Asserted one-directionally (`>= 1` while WE hold a claim) rather than as
    /// an exact value, because the gauge is process-global and other tests claim
    /// and release concurrently.
    #[test]
    fn the_reset_does_not_erase_a_live_fetch_claim() {
        note_fetch_claimed();
        assert!(fetches_in_flight() >= 1);
        reset_fetch_stats();
        assert!(
            fetches_in_flight() >= 1,
            "reset erased a fetch that is still running"
        );
        note_fetch_released();
    }

    /// The counters only ever grow, so a delta assertion is race-safe even though
    /// other tests share the same process-global counter and may add concurrently.
    #[test]
    fn counters_are_monotonic_and_additive() {
        let d0 = downloaded();
        add_downloaded(100);
        assert!(downloaded() >= d0 + 100);

        let u0 = uploaded();
        add_uploaded(50);
        assert!(uploaded() >= u0 + 50);
    }
}
