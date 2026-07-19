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
