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
    };
}

funnel! {
    F_DIAL      => note_dial / dials,             "dialed";
    F_CONN      => note_connected / connected,    "connected";
    F_STATUS    => note_status / got_status,      "got filestatus";
    F_NOFILE    => note_nofile / nofile,          "  (peer said NOFILE)";
    F_NONEEDED  => note_no_needed_parts / no_needed_parts, "  (holds nothing we need)";
    F_HS_NEED   => note_hashset_need / hashset_need, "needed hashset";
    F_HS_GOT    => note_hashset_got / hashset_got,   "  got hashset";
    F_SLOT_ASK  => note_slot_ask / slot_asked,    "asked for a slot";
    F_ACCEPT    => note_accepted / accepted,      "  slot ACCEPTED";
    F_QUEUED    => note_queued / queued,          "  queued (bailed)";
    F_NOBLOCK   => note_no_blocks / no_blocks,    "accepted, no block to take";
    F_REQ       => note_requested / requested,    "requested blocks";
    F_DELIVERED => note_delivered / delivered,    "DELIVERED bytes";
    F_REVOKED   => note_revoked / revoked,        "  slot REVOKED (0x57)";
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

/// The funnel and the out-of-turn opcodes as a printable block.
pub fn fetch_report() -> String {
    let mut s = String::from("  FETCH FUNNEL (peer sessions reaching each stage)\n");
    for (label, n) in fetch_funnel() {
        s.push_str(&format!("    {label:<28} {n:>6}\n"));
    }
    s.push_str("  DIAL TIME (bucket: connected / failed)\n");
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

#[cfg(test)]
mod tests {
    use super::*;

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
