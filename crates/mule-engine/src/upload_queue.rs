//! The upload queue: who waits, in what order, and who gets a slot.
//! See docs/raw/wave4d-upstream-research-2026-07-14.md section 2
//! (UploadQueue.cpp:304-333 slots, UploadClient.cpp:75-148 scoring).
//!
//! This is local policy, not wire format. NOTE: the live serve path does not
//! use this queue yet - `share.rs` grants slots from a Semaphore and REFUSES
//! at capacity with OP_FILEREQANSNOFIL, so padMule never sends the
//! OP_QUEUERANKING this module can rank for. Wiring real queueing into serve
//! is an open candidate feature (stock clients queue waiting peers).
//!
//! The wait clock is deliberately keyed to a peer's PERSISTED wait-start (which
//! upstream stores in clients.met), so a peer that reconnects does not lose its
//! place in the queue.

use crate::credits::score_ratio;
use std::cmp::Reverse;

/// A friend holding a friend slot jumps the entire queue.
pub const FRIEND_SLOT_SCORE: u32 = 0x0FFF_FFFF;

/// Slot-count bounds. Upstream allows far more slots than eMule (250 vs 100).
pub const MIN_UP_CLIENTS_ALLOWED: u32 = 2;
pub const MAX_UP_CLIENTS_ALLOWED: u32 = 250;
/// With an unlimited upload rate, never open fewer than this many slots.
pub const SLOT_N_FLOOR: u32 = 20;
/// Default kB/s of upload budgeted per slot.
pub const DEFAULT_SLOT_ALLOCATION_KBPS: u32 = 10;

/// Beyond this many waiting peers, new requests are dropped SILENTLY (upstream
/// sends no packet at all on the TCP path).
pub const MAX_QUEUE_SIZE: usize = 5000;

/// A peer loses its slot after this long...
pub const SESSION_MAX_SECS: u32 = 3600;
/// ...or after this many bytes, whichever comes first.
pub const SESSION_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Share priority of the file being requested.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FilePriority {
    VeryLow,
    Low,
    #[default]
    Normal,
    High,
    VeryHigh,
    /// aMule-only "release" priority; dominates the queue by design.
    PowerShare,
}

impl FilePriority {
    /// The multiplier this priority applies to a waiting peer's score.
    pub fn multiplier(self) -> f32 {
        match self {
            FilePriority::VeryLow => 0.2,
            FilePriority::Low => 0.6,
            FilePriority::Normal => 0.7,
            FilePriority::High => 0.9,
            FilePriority::VeryHigh => 1.8,
            FilePriority::PowerShare => 250.0,
        }
    }
}

/// A peer waiting for (or holding) an upload slot.
#[derive(Debug, Clone)]
pub struct QueuedPeer {
    pub user_hash: [u8; 16],
    /// Unix seconds when this peer first asked. Persisted across reconnects.
    pub wait_start_secs: u32,
    pub priority: FilePriority,
    /// Credit totals: what we have sent to / received from this peer.
    pub uploaded: u64,
    pub downloaded: u64,
    pub friend_slot: bool,
    pub low_id: bool,
    pub banned: bool,
    /// A pre-0x19 eMule; upstream halves its score.
    pub old_emule: bool,
    /// True while this peer holds a slot.
    pub uploading: bool,
}

impl QueuedPeer {
    /// A plain peer with no credit history, asking right now.
    pub fn new(user_hash: [u8; 16], now_secs: u32) -> Self {
        QueuedPeer {
            user_hash,
            wait_start_secs: now_secs,
            priority: FilePriority::Normal,
            uploaded: 0,
            downloaded: 0,
            friend_slot: false,
            low_id: false,
            banned: false,
            old_emule: false,
            uploading: false,
        }
    }
}

/// A waiting peer's queue score. Higher wins.
///
/// The short-circuit ORDER is load-bearing and matches upstream: a friend with a
/// friend slot wins even if it is banned or already downloading, because that
/// check comes first.
pub fn peer_score(p: &QueuedPeer, now_secs: u32) -> u32 {
    if p.friend_slot && !p.low_id {
        return FRIEND_SLOT_SCORE;
    }
    if p.banned || p.uploading {
        return 0;
    }
    let waited = now_secs.saturating_sub(p.wait_start_secs) as f32;
    let mut base = waited * score_ratio(p.uploaded, p.downloaded) * p.priority.multiplier();
    if p.old_emule {
        base *= 0.5;
    }
    base as u32
}

/// How many upload slots to run.
///
/// `max_upload_kbps == 0` means unlimited, in which case the slot count follows
/// the MEASURED rate but never drops below `SLOT_N_FLOOR`.
pub fn max_slots(max_upload_kbps: u32, measured_up_kbps: u32, slot_allocation_kbps: u32) -> u32 {
    let per_slot = slot_allocation_kbps.max(1);
    let slots = if max_upload_kbps == 0 {
        (measured_up_kbps / per_slot + 2).max(SLOT_N_FLOOR)
    } else if max_upload_kbps >= 10 {
        // Upstream rounds rather than truncates.
        let n = (max_upload_kbps as f32 / per_slot as f32 + 0.5) as u32;
        n.max(MIN_UP_CLIENTS_ALLOWED)
    } else {
        MIN_UP_CLIENTS_ALLOWED
    };
    slots.min(MAX_UP_CLIENTS_ALLOWED)
}

/// Whether a peer holding a slot has used it up. Friends are never kicked.
pub fn should_kick(upload_secs: u32, session_bytes: u64, friend_slot: bool) -> bool {
    if friend_slot {
        return false;
    }
    upload_secs > SESSION_MAX_SECS || session_bytes > SESSION_MAX_BYTES
}

/// The waiting queue, ordered by score.
#[derive(Debug, Clone, Default)]
pub struct UploadQueue {
    waiting: Vec<QueuedPeer>,
}

impl UploadQueue {
    pub fn new() -> Self {
        UploadQueue::default()
    }

    pub fn len(&self) -> usize {
        self.waiting.len()
    }

    pub fn is_empty(&self) -> bool {
        self.waiting.is_empty()
    }

    /// Add a peer. Returns false if it is already queued or the queue is full
    /// (upstream drops a full-queue request silently - no packet is sent).
    pub fn add(&mut self, peer: QueuedPeer) -> bool {
        if self.waiting.len() >= MAX_QUEUE_SIZE
            || self.waiting.iter().any(|p| p.user_hash == peer.user_hash)
        {
            return false;
        }
        self.waiting.push(peer);
        true
    }

    pub fn remove(&mut self, user_hash: &[u8; 16]) -> Option<QueuedPeer> {
        let i = self
            .waiting
            .iter()
            .position(|p| &p.user_hash == user_hash)?;
        Some(self.waiting.remove(i))
    }

    /// Re-sort by score, best first. Upstream does this every 2 minutes rather
    /// than on every change.
    pub fn sort(&mut self, now_secs: u32) {
        self.waiting
            .sort_by_key(|p| Reverse(peer_score(p, now_secs)));
    }

    /// A peer's 1-BASED rank, as sent in OP_QUEUERANKING. `None` means it is not
    /// queued, which upstream reports as rank 0 and never transmits.
    ///
    /// Call `sort` first; the rank is the position in the sorted list.
    pub fn rank_of(&self, user_hash: &[u8; 16]) -> Option<u16> {
        self.waiting
            .iter()
            .position(|p| &p.user_hash == user_hash)
            .map(|i| (i + 1) as u16)
    }

    /// The best waiting peer - the one to hand the next free slot to.
    pub fn next_client(&self) -> Option<&QueuedPeer> {
        self.waiting.first()
    }

    pub fn peers(&self) -> &[QueuedPeer] {
        &self.waiting
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_rises_with_waiting_time() {
        let p = QueuedPeer::new([1; 16], 1000);
        let early = peer_score(&p, 1010);
        let late = peer_score(&p, 2000);
        assert!(late > early, "{late} !> {early}");
    }

    #[test]
    fn credits_multiply_the_score() {
        let mut generous = QueuedPeer::new([1; 16], 0);
        // Gave us 2 MiB, took nothing: ratio 2.0.
        generous.downloaded = 2 * 1_048_576;
        let plain = QueuedPeer::new([2; 16], 0);

        let now = 100;
        assert_eq!(peer_score(&plain, now), (100.0 * 1.0 * 0.7) as u32);
        assert_eq!(peer_score(&generous, now), (100.0 * 2.0 * 0.7) as u32);
        assert!(peer_score(&generous, now) > peer_score(&plain, now));
    }

    #[test]
    fn priority_multipliers_match_upstream() {
        assert_eq!(FilePriority::VeryLow.multiplier(), 0.2);
        assert_eq!(FilePriority::Low.multiplier(), 0.6);
        assert_eq!(FilePriority::Normal.multiplier(), 0.7);
        assert_eq!(FilePriority::High.multiplier(), 0.9);
        assert_eq!(FilePriority::VeryHigh.multiplier(), 1.8);
        assert_eq!(FilePriority::PowerShare.multiplier(), 250.0);
    }

    #[test]
    fn a_friend_slot_beats_everything_including_bans() {
        // The friend check short-circuits BEFORE the banned/uploading checks -
        // this ordering is upstream's, and it is easy to get backwards.
        let mut f = QueuedPeer::new([1; 16], 0);
        f.friend_slot = true;
        f.banned = true;
        f.uploading = true;
        assert_eq!(peer_score(&f, 10), FRIEND_SLOT_SCORE);
    }

    #[test]
    fn a_lowid_friend_gets_no_friend_bonus() {
        let mut f = QueuedPeer::new([1; 16], 0);
        f.friend_slot = true;
        f.low_id = true;
        assert_ne!(peer_score(&f, 10), FRIEND_SLOT_SCORE);
    }

    #[test]
    fn banned_and_uploading_peers_score_zero() {
        let mut b = QueuedPeer::new([1; 16], 0);
        b.banned = true;
        assert_eq!(peer_score(&b, 10_000), 0);

        let mut u = QueuedPeer::new([2; 16], 0);
        u.uploading = true;
        assert_eq!(peer_score(&u, 10_000), 0);
    }

    #[test]
    fn an_old_emule_is_halved() {
        let mut old = QueuedPeer::new([1; 16], 0);
        old.old_emule = true;
        let new = QueuedPeer::new([2; 16], 0);
        assert_eq!(peer_score(&old, 100) * 2, peer_score(&new, 100));
    }

    #[test]
    fn unlimited_upload_never_opens_fewer_than_the_floor() {
        // No measured traffic at all still yields N_FLOOR, not 2.
        assert_eq!(max_slots(0, 0, DEFAULT_SLOT_ALLOCATION_KBPS), SLOT_N_FLOOR);
        // A fast measured rate scales past it: 500/10 + 2 = 52.
        assert_eq!(max_slots(0, 500, DEFAULT_SLOT_ALLOCATION_KBPS), 52);
    }

    #[test]
    fn a_limited_upload_divides_the_budget_into_slots() {
        // 100 kB/s at 10 kB/s per slot -> 10 slots.
        assert_eq!(max_slots(100, 0, DEFAULT_SLOT_ALLOCATION_KBPS), 10);
        // Below 10 kB/s upstream falls back to the minimum.
        assert_eq!(
            max_slots(5, 0, DEFAULT_SLOT_ALLOCATION_KBPS),
            MIN_UP_CLIENTS_ALLOWED
        );
    }

    #[test]
    fn slot_count_is_capped() {
        assert_eq!(max_slots(0, 1_000_000, 1), MAX_UP_CLIENTS_ALLOWED);
    }

    #[test]
    fn a_slot_expires_on_time_or_volume_but_never_for_a_friend() {
        assert!(!should_kick(10, 1024, false));
        assert!(should_kick(SESSION_MAX_SECS + 1, 0, false));
        assert!(should_kick(0, SESSION_MAX_BYTES + 1, false));
        // Friends are exempt from both limits.
        assert!(!should_kick(
            SESSION_MAX_SECS + 1,
            SESSION_MAX_BYTES + 1,
            true
        ));
    }

    #[test]
    fn rank_is_one_based_and_sorted_by_score() {
        let mut q = UploadQueue::new();
        // The peer that has waited far longer should outrank the fresh one.
        let fresh = QueuedPeer::new([0x0F; 16], 990);
        let waited = QueuedPeer::new([0xAA; 16], 0);
        q.add(fresh);
        q.add(waited);
        q.sort(1000);

        assert_eq!(q.rank_of(&[0xAA; 16]), Some(1));
        assert_eq!(q.rank_of(&[0x0F; 16]), Some(2));
        assert_eq!(q.next_client().unwrap().user_hash, [0xAA; 16]);
        // A peer that is not queued has no rank (upstream: rank 0, never sent).
        assert_eq!(q.rank_of(&[0x99; 16]), None);
    }

    #[test]
    fn a_peer_cannot_queue_twice() {
        let mut q = UploadQueue::new();
        assert!(q.add(QueuedPeer::new([1; 16], 0)));
        assert!(!q.add(QueuedPeer::new([1; 16], 0)));
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn a_full_queue_rejects_new_peers() {
        let mut q = UploadQueue::new();
        for i in 0..MAX_QUEUE_SIZE {
            let mut h = [0u8; 16];
            h[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            assert!(q.add(QueuedPeer::new(h, 0)));
        }
        assert_eq!(q.len(), MAX_QUEUE_SIZE);
        assert!(!q.add(QueuedPeer::new([0xFF; 16], 0)));
    }

    #[test]
    fn removing_a_peer_closes_the_rank_gap() {
        let mut q = UploadQueue::new();
        q.add(QueuedPeer::new([1; 16], 0));
        q.add(QueuedPeer::new([2; 16], 0));
        q.add(QueuedPeer::new([3; 16], 0));
        q.sort(100);
        assert!(q.remove(&[1; 16]).is_some());
        q.sort(100);
        // Whoever is now first is rank 1 - ranks are always contiguous from 1.
        let first = q.next_client().unwrap().user_hash;
        assert_eq!(q.rank_of(&first), Some(1));
        assert_eq!(q.len(), 2);
        assert!(q.remove(&[1; 16]).is_none()); // already gone
    }
}
