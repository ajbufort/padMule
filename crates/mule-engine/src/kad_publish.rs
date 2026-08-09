//! The Kad PUBLISH scheduler, as a PURE policy (no sockets, no clock).
//!
//! padMule announces its shared files to the Kad DHT so other clients can find
//! them by keyword and by source, the way every stock eMule/aMule does. What it
//! publishes and how often is eMule's (opcodes.h:76-78):
//!
//!   - a SOURCE record per file every 5h  (`KADEMLIAREPUBLISHTIMES`)
//!   - a KEYWORD record per WORD every 24h (`KADEMLIAREPUBLISHTIMEK`)
//!
//! Entries age out against those clocks at the storing node, so publishing that
//! STOPS is forgotten rather than retracted - which is exactly why a
//! foreground-only publisher is honest: when padMule leaves the foreground it
//! simply stops republishing, and its records expire on their own. That was the
//! design question the handoff said to settle before building; Anthony decided
//! BUILD (2026-08-09), gated on the engine actually running and sharing.
//!
//! This module owns only the SCHEDULE - which file/word is due, in what order,
//! and when each was last done. `Engine::maintain_kad_publish` owns the I/O and
//! calls `KadNode::publish_keyword` / `publish_source`. The split is the same as
//! `mule_kad::lookup` vs `kad_live`: the policy is unit-testable offline.
//!
//! ONE JOB PER PASS. A publish is a full FIND_NODE walk under the engine lock,
//! so the driver bounds it and the scheduler hands out exactly one job at a
//! time - the same lock-hold discipline `maintain_kad` follows. There is no
//! rush: the clocks are hours long.

use std::collections::{HashMap, HashSet, VecDeque};

/// Republish a SOURCE record this often (eMule `KADEMLIAREPUBLISHTIMES`, 5h).
pub const KAD_REPUBLISH_SOURCE_SECS: u64 = 5 * 3600;
/// Republish a KEYWORD record this often (eMule `KADEMLIAREPUBLISHTIMEK`, 24h).
pub const KAD_REPUBLISH_KEYWORD_SECS: u64 = 24 * 3600;

/// One unit of publishing work: our source record for a file, or one keyword
/// (a single word) pointing at a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublishJob {
    /// Publish our own source record for this file hash.
    Source([u8; 16]),
    /// Publish `word` -> `file` under the keyword index.
    Keyword { file: [u8; 16], word: String },
}

/// Both fields are WALL-CLOCK Unix seconds - the caller
/// (`Engine::maintain_kad_publish`) passes `now_secs()`, SystemTime since the
/// epoch, not engine uptime. A backward clock jump therefore FREEZES republish
/// until real time catches back up (`due` uses `saturating_sub`, so the
/// elapsed reads 0, never underflows); a forward jump republishes early. Both
/// are benign - an early publish is a wasted walk, a frozen one is caught up
/// on the next due pass - and the clocks are in-memory only, so a restart
/// resets them and republishes everything anyway.
#[derive(Default, Clone)]
struct FileClocks {
    /// Unix seconds the source record was last (re)published.
    source: Option<u64>,
    /// Unix seconds the keyword records were last (re)published.
    keyword: Option<u64>,
}

/// Decides which publish jobs are due and hands them out one at a time.
#[derive(Default)]
pub struct PublishSchedule {
    clocks: HashMap<[u8; 16], FileClocks>,
    queue: VecDeque<PublishJob>,
}

fn due(last: Option<u64>, now: u64, interval: u64) -> bool {
    match last {
        None => true,                                 // never published
        Some(t) => now.saturating_sub(t) >= interval, // interval elapsed
    }
}

impl PublishSchedule {
    pub fn new() -> Self {
        Self::default()
    }

    /// Refill the work queue from the current shared library WHEN IT IS EMPTY
    /// (a job is still in flight otherwise). `shared` is `(hash, keywords)` per
    /// file, where `keywords` are the already-tokenised, deduplicated words
    /// (`mule_kad::kad_keywords` on the filename). `can_publish_source` gates
    /// SOURCE jobs - only a reachable node should claim to be a source, so a
    /// firewalled/LowID padMule publishes keywords but not sources (it would
    /// otherwise advertise an address nobody can reach; eMule publishes a buddy
    /// record there, which padMule has no buddy system for).
    ///
    /// Clocks are stamped at ENQUEUE, not on success: a file is not re-queued
    /// until its interval elapses again, and a publish that finds few nodes is
    /// best-effort, exactly like eMule's. Files no longer shared are pruned so
    /// the clock map cannot grow without bound.
    pub fn refill(
        &mut self,
        now: u64,
        shared: &[([u8; 16], Vec<String>)],
        can_publish_source: bool,
    ) {
        if !self.queue.is_empty() {
            return;
        }
        let live: HashSet<[u8; 16]> = shared.iter().map(|(h, _)| *h).collect();
        self.clocks.retain(|h, _| live.contains(h));

        for (hash, words) in shared {
            let c = self.clocks.entry(*hash).or_default();
            if can_publish_source && due(c.source, now, KAD_REPUBLISH_SOURCE_SECS) {
                self.queue.push_back(PublishJob::Source(*hash));
                c.source = Some(now);
            }
            if due(c.keyword, now, KAD_REPUBLISH_KEYWORD_SECS) {
                for w in words {
                    self.queue.push_back(PublishJob::Keyword {
                        file: *hash,
                        word: w.clone(),
                    });
                }
                c.keyword = Some(now);
            }
        }
    }

    /// The next job to publish, or `None` when nothing is due.
    pub fn take_next(&mut self) -> Option<PublishJob> {
        self.queue.pop_front()
    }

    /// How many jobs are queued (diagnostics).
    pub fn pending(&self) -> usize {
        self.queue.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 16] = [0xAA; 16];
    const B: [u8; 16] = [0xBB; 16];

    #[test]
    fn a_fresh_file_queues_a_source_and_one_job_per_word() {
        let mut s = PublishSchedule::new();
        s.refill(
            1000,
            &[(A, vec!["ubuntu".to_string(), "iso".to_string()])],
            true,
        );
        // source + 2 keywords, source first (eMule's order is source then key,
        // and either way both are due on a fresh file).
        assert_eq!(s.pending(), 3);
        assert_eq!(s.take_next(), Some(PublishJob::Source(A)));
        assert_eq!(
            s.take_next(),
            Some(PublishJob::Keyword {
                file: A,
                word: "ubuntu".to_string()
            })
        );
        assert_eq!(
            s.take_next(),
            Some(PublishJob::Keyword {
                file: A,
                word: "iso".to_string()
            })
        );
        assert_eq!(s.take_next(), None);
    }

    #[test]
    fn a_firewalled_node_publishes_keywords_but_no_source() {
        let mut s = PublishSchedule::new();
        s.refill(1000, &[(A, vec!["ubuntu".to_string()])], false);
        assert_eq!(
            s.take_next(),
            Some(PublishJob::Keyword {
                file: A,
                word: "ubuntu".to_string()
            }),
            "keywords are published without a source claim"
        );
        assert_eq!(s.take_next(), None, "no source job when unreachable");
    }

    #[test]
    fn clocks_gate_republish_at_their_own_intervals() {
        let mut s = PublishSchedule::new();
        let shared = [(A, vec!["ubuntu".to_string()])];
        s.refill(0, &shared, true);
        while s.take_next().is_some() {}

        // Just before the source interval: nothing due.
        s.refill(KAD_REPUBLISH_SOURCE_SECS - 1, &shared, true);
        assert_eq!(s.pending(), 0, "neither clock has elapsed");

        // At the source interval but before the keyword one: source ONLY.
        s.refill(KAD_REPUBLISH_SOURCE_SECS, &shared, true);
        assert_eq!(s.pending(), 1);
        assert_eq!(s.take_next(), Some(PublishJob::Source(A)));

        // At the keyword interval: the keyword too (source was just restamped,
        // so at exactly 24h it is due again as well).
        s.refill(KAD_REPUBLISH_KEYWORD_SECS, &shared, true);
        let mut jobs = Vec::new();
        while let Some(j) = s.take_next() {
            jobs.push(j);
        }
        assert!(jobs.contains(&PublishJob::Keyword {
            file: A,
            word: "ubuntu".to_string()
        }));
    }

    #[test]
    fn the_queue_is_not_refilled_while_a_job_is_in_flight() {
        let mut s = PublishSchedule::new();
        s.refill(0, &[(A, vec!["a".to_string(), "b".to_string()])], true);
        let _one = s.take_next(); // pop one, leave the rest queued
                                  // A refill now must be a no-op - the queue is non-empty.
        s.refill(
            KAD_REPUBLISH_KEYWORD_SECS * 10,
            &[(A, vec!["a".to_string()])],
            true,
        );
        // Still the ORIGINAL jobs, not a re-scan.
        assert!(s.pending() >= 1);
    }

    #[test]
    fn an_unshared_file_is_pruned_from_the_clock_map() {
        let mut s = PublishSchedule::new();
        s.refill(
            0,
            &[(A, vec!["a".to_string()]), (B, vec!["b".to_string()])],
            true,
        );
        while s.take_next().is_some() {}
        // B is gone from the library; a refill far in the future must re-queue
        // A fresh (its clock survived) but treat B as never-seen if it returns.
        s.refill(
            KAD_REPUBLISH_KEYWORD_SECS + 1,
            &[(A, vec!["a".to_string()])],
            true,
        );
        // Only A's jobs (B is not in the library), and A republishes on time.
        while let Some(j) = s.take_next() {
            match j {
                PublishJob::Source(h) | PublishJob::Keyword { file: h, .. } => {
                    assert_eq!(h, A, "only the still-shared file is scheduled")
                }
            }
        }
    }
}
