//! Poison-tolerant locking for the engine's `std::sync::Mutex` state.
//!
//! THE RISK THIS CLOSES (padMule-specific; eMule/aMule have no analogue because
//! C++ mutexes have no poisoning). In Rust a panic while a `std::sync::Mutex`
//! guard is alive marks that mutex POISONED, and every later `.lock().unwrap()`
//! on it panics too. So ONE panic escalates from "this peer/datagram is
//! dropped" to "this subsystem is dead until the app is restarted".
//!
//! It escalates because the process SURVIVES the first panic, which was checked
//! rather than assumed:
//!
//!   1. Nothing in the workspace sets `panic = "abort"` (no profile override in
//!      the root `Cargo.toml`, no `.cargo/config.toml`), so both debug and
//!      release UNWIND - poisoning is live on device, not just in tests.
//!   2. UniFFI wraps every FFI entry point in `panic::catch_unwind`
//!      (uniffi_core-0.28.3, `ffi/rustcalls.rs:177`), turning a panic into an
//!      `UnexpectedError` returned to Swift. The app keeps running - with a
//!      permanently poisoned lock.
//!   3. A panicking tokio task likewise only fails its own `JoinHandle`.
//!
//! And it can escalate FURTHER than a dead subsystem: several of these mutexes
//! are taken inside a `Drop` impl (`share::SlotGuard`, `share::QueueWaiter`,
//! `engine::IpConnSlot`, `kad_live::SlotGuard`, `multi_source::HeldBlocks`).
//! A poisoned lock makes that `Drop` panic, and a panic during unwinding is a
//! double panic - which ABORTS the process.
//!
//! WHY RECOVERING THE GUARD IS SOUND HERE. Poisoning is a warning that a
//! critical section may have been left half-applied. It is only worth heeding
//! where a torn update could break an invariant the code cannot re-derive.
//! Every mutex converted here guards SELF-HEALING BOOKKEEPING - counters,
//! caches, evidence maps, reservation lists, a routing table that ages and
//! re-probes - never a durability or correctness invariant. The invariants that
//! DO matter (the gap list never claims bytes the disk lacks; a hashset is
//! validated against its own root before it is served; a completed file is
//! verified by whole-file MD4) live outside these locks and are re-checked from
//! the artifact, not from in-memory state. The per-mutex argument is written at
//! each mutex's own field declaration, which is where the guarded data is
//! defined.
//!
//! NOT CONVERTED, deliberately:
//!
//!   - `tokio::sync::Mutex` (most of `engine.rs`, `fetch.rs`, `mule-ffi`,
//!     `mule-cli`) has no poisoning concept at all.
//!   - `engine.rs`'s `server` / `public_ip` / `harvested_servers` /
//!     `server_health` already handle `PoisonError` by hand (`if let Ok(..)`,
//!     `.lock().ok()`), so they cannot cascade. Left alone: changing them would
//!     alter their fail-quiet behaviour, which is a separate question.
//!   - `#[cfg(test)]` locks (`stats::STATS_TEST_LOCK`, the harness mutexes in
//!     `upnp.rs` and the per-module test bodies). In a test a poisoned lock IS
//!     the signal you want - it should fail loudly.

use std::sync::{Mutex, MutexGuard};

/// Take a `std::sync::Mutex` guard, RECOVERING it if a previous holder panicked.
pub(crate) trait LockRecover<T> {
    /// Like `lock().unwrap()`, except a poisoned lock hands back the guard
    /// instead of panicking. Identical behaviour on an unpoisoned lock, which is
    /// every lock in every run that has not already panicked.
    fn lock_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> LockRecover<T> for Mutex<T> {
    fn lock_recover(&self) -> MutexGuard<'_, T> {
        // `into_inner` on the PoisonError is the guard the panicking holder
        // dropped mid-unwind - the data is there, just possibly half-updated.
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Poison `m` for real, the way production does it: panic with the guard alive
/// inside a `catch_unwind`, exactly as UniFFI's FFI boundary catches a panic
/// raised under one of these locks. Asserts the poisoning actually happened, so
/// a test built on it can never pass vacuously.
#[cfg(test)]
pub(crate) fn poison_for_test<T>(m: &Mutex<T>) {
    let hit = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _held = m.lock().expect("not poisoned yet");
        panic!("deliberate panic under the lock (poison-recovery test)");
    }));
    assert!(hit.is_err(), "the deliberate panic must have unwound");
    assert!(
        m.is_poisoned(),
        "the lock must really be poisoned, or the test proves nothing"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_recovered_guard_still_sees_the_data() {
        let m = Mutex::new(vec![1u32, 2, 3]);
        poison_for_test(&m);
        assert!(m.lock().is_err(), "std still refuses the poisoned lock");
        assert_eq!(*m.lock_recover(), vec![1, 2, 3]);
        m.lock_recover().push(4);
        assert_eq!(*m.lock_recover(), vec![1, 2, 3, 4]);
    }
}
