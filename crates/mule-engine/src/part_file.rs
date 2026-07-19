//! The in-progress download: which bytes we still need, which blocks to ask for
//! next, and whether a finished part actually verifies. See
//! docs/raw/wave4d-upstream-research-2026-07-14.md section 4.
//!
//! # Gap convention
//!
//! A "gap" is a range we still NEED. Here (and in `mule_files::part_met`) gaps
//! are `[start, end)` - end EXCLUSIVE - which is both the on-disk convention and
//! the natural Rust one. Upstream keeps them end-INCLUSIVE in memory and converts
//! at the file boundary; we simply do not have the inclusive form anywhere, which
//! removes a whole class of off-by-one.
//!
//! # Part counts: there are TWO of them
//!
//! `mule_proto::part_count` is the ED2K part count (`floor(size/PARTSIZE) + 1`),
//! which counts the trailing sentinel part that an exact-multiple file carries in
//! its hashset. The DATA part count - how many parts actually hold bytes - is
//! `ceil(size/PARTSIZE)`, one smaller for exact multiples. Confusing them is how
//! upstream ended up with the bug below.
//!
//! # Deliberate divergence: the exactly-PARTSIZE bug
//!
//! aMule verifies a single-part file against the FILE hash. For a file of exactly
//! 9,728,000 bytes that is wrong: the hashset holds two entries (the real part
//! hash plus the empty-MD4 sentinel), so the file hash is `MD4(h0 || h_empty)`,
//! which never equals `h0`. Such a file is reported corrupt forever, on every
//! retry. eMule guards it with `part_count > 1 || size == PARTSIZE`; we use
//! eMule's condition. See `verify_part`.

use mule_files::Gap;
use mule_proto::{md4, PARTSIZE};

use crate::transfer::EMBLOCKSIZE;

/// Number of parts that actually hold data: `ceil(size / PARTSIZE)`.
///
/// This is upstream's `m_iPartCount`, NOT `mule_proto::part_count` (which is the
/// ED2K/hashset count and is one larger for exact multiples).
pub fn data_part_count(size: u64) -> u64 {
    size.div_ceil(PARTSIZE)
}

/// Size of part `part`, which is short for the final part unless the file is an
/// exact multiple of PARTSIZE.
pub fn part_size(part: u64, size: u64) -> u64 {
    let start = part * PARTSIZE;
    (size - start).min(PARTSIZE)
}

/// A download in progress.
#[derive(Debug, Clone)]
pub struct PartFile {
    pub hash: [u8; 16],
    pub size: u64,
    /// Per-part MD4s from OP_HASHSETANSWER. Empty until the hashset arrives; a
    /// single-part file never needs one.
    pub part_hashes: Vec<[u8; 16]>,
    /// Ranges still missing, sorted, non-overlapping, end-EXCLUSIVE.
    gaps: Vec<Gap>,
    /// Parts that failed verification. Upstream persists this in part.met as
    /// FT_CORRUPTEDPARTS; the invariant is "a part is verified iff it is
    /// gap-complete AND not in this list".
    corrupted: Vec<u64>,
}

impl PartFile {
    /// A fresh download: one gap covering the whole file.
    pub fn new(hash: [u8; 16], size: u64) -> Self {
        PartFile {
            hash,
            size,
            part_hashes: Vec::new(),
            gaps: if size == 0 {
                Vec::new()
            } else {
                vec![Gap {
                    start: 0,
                    end: size,
                }]
            },
            corrupted: Vec::new(),
        }
    }

    /// Resume a download from a part.met gap list.
    pub fn resume(hash: [u8; 16], size: u64, gaps: Vec<Gap>, corrupted: Vec<u64>) -> Self {
        let mut pf = PartFile {
            hash,
            size,
            part_hashes: Vec::new(),
            gaps,
            corrupted,
        };
        pf.normalize();
        pf
    }

    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    pub fn corrupted(&self) -> &[u64] {
        &self.corrupted
    }

    /// Bytes still missing.
    pub fn missing(&self) -> u64 {
        self.gaps.iter().map(|g| g.end - g.start).sum()
    }

    /// Bytes available CONTIGUOUSLY from offset 0 (up to the first gap). This is
    /// the leading prefix a media player can read straight off the raw `.part`:
    /// 0 when byte 0 is still missing, the full `size` when complete. `gaps` is
    /// kept sorted by start, so the first gap's start is the prefix length.
    pub fn contiguous_prefix(&self) -> u64 {
        self.gaps.first().map(|g| g.start).unwrap_or(self.size)
    }

    /// Every byte has arrived. (Verification is separate - see `verify_part`.)
    pub fn is_complete(&self) -> bool {
        self.gaps.is_empty()
    }

    /// All of part `part` has arrived.
    pub fn is_part_complete(&self, part: u64) -> bool {
        let start = part * PARTSIZE;
        let end = start + part_size(part, self.size);
        !self.gaps.iter().any(|g| g.start < end && g.end > start)
    }

    /// Sort and merge the gap list so the allocator can assume it is tidy.
    fn normalize(&mut self) {
        self.gaps.retain(|g| g.start < g.end);
        self.gaps.sort_by_key(|g| g.start);
        let mut merged: Vec<Gap> = Vec::with_capacity(self.gaps.len());
        for g in self.gaps.drain(..) {
            match merged.last_mut() {
                Some(prev) if g.start <= prev.end => prev.end = prev.end.max(g.end),
                _ => merged.push(g),
            }
        }
        self.gaps = merged;
    }

    /// Mark `[start, end)` as received, closing that much of the gap list.
    ///
    /// Upstream calls this the moment the bytes land in the write buffer, BEFORE
    /// they reach disk - which is why a crash mid-flush can lose data that the
    /// gap list already claims we have. eMule compensates by persisting still-
    /// buffered ranges as extra gaps. That matters more for padMule than for a
    /// desktop client, because iPadOS can suspend us mid-write; the caller is
    /// therefore expected to flush before persisting the gap list.
    pub fn fill_gap(&mut self, start: u64, end: u64) {
        if start >= end {
            return;
        }
        let mut out = Vec::with_capacity(self.gaps.len() + 1);
        for g in self.gaps.drain(..) {
            // No overlap: keep as-is.
            if g.end <= start || g.start >= end {
                out.push(g);
                continue;
            }
            // Left remainder.
            if g.start < start {
                out.push(Gap {
                    start: g.start,
                    end: start,
                });
            }
            // Right remainder.
            if g.end > end {
                out.push(Gap {
                    start: end,
                    end: g.end,
                });
            }
        }
        self.gaps = out;
        self.normalize();
    }

    /// Re-open an entire part as missing, and remember that it went bad.
    ///
    /// Upstream re-gaps the WHOLE part on a hash mismatch - without AICH there is
    /// no way to know which of its ~53 blocks was the bad one. (AICH narrows this
    /// to the offending ~180 KiB block; it needs the SHA-1 tree from Wave 1c.)
    pub fn mark_corrupt(&mut self, part: u64) {
        let start = part * PARTSIZE;
        let end = start + part_size(part, self.size);
        self.gaps.push(Gap { start, end });
        self.normalize();
        if !self.corrupted.contains(&part) {
            self.corrupted.push(part);
        }
    }

    /// Verify a completed part's bytes against the hashset.
    ///
    /// The single-part case is where aMule has a real bug: it compares against
    /// the FILE hash whenever there is one part, but a file of exactly PARTSIZE
    /// has a two-entry hashset (real part + empty sentinel), so its file hash is
    /// `MD4(h0 || h_empty)` and can never equal the part's MD4. We use eMule's
    /// condition instead, so an exactly-9,728,000-byte file verifies.
    ///
    /// Returns `None` when we have no hash to check against yet (the hashset has
    /// not arrived); upstream treats that as "assume good, fetch the hashset".
    pub fn verify_part(&self, part: u64, data: &[u8]) -> Option<bool> {
        let use_part_hash = data_part_count(self.size) > 1 || self.size == PARTSIZE;
        let expected = if use_part_hash {
            *self.part_hashes.get(part as usize)?
        } else {
            self.hash
        };
        Some(md4(data) == expected)
    }

    /// Accept a verified part: clear it from the corrupted list.
    pub fn clear_corrupt(&mut self, part: u64) {
        self.corrupted.retain(|&p| p != part);
    }

    /// The next block to request from within `part`, skipping anything already
    /// reserved by another source.
    ///
    /// A block is bounded by BOTH the gap and the `part_start + k*EMBLOCKSIZE`
    /// lattice, so it can come back SHORTER than EMBLOCKSIZE - a caller that
    /// assumes a fixed block size will corrupt the file.
    pub fn next_block_in_part(&self, part: u64, reserved: &[(u64, u64)]) -> Option<(u64, u64)> {
        let part_start = part * PARTSIZE;
        let part_end = part_start + part_size(part, self.size);
        let mut cursor = part_start;

        while cursor < part_end {
            // First gap that still intersects [cursor, part_end).
            let g = self
                .gaps
                .iter()
                .find(|g| g.start < part_end && g.end > cursor)?;
            let start = cursor.max(g.start);
            // Clamp to the end of this lattice cell, the gap, and the part.
            let cell_end = part_start + EMBLOCKSIZE * ((start - part_start) / EMBLOCKSIZE + 1);
            let end = g.end.min(cell_end).min(part_end);
            if start >= end {
                return None;
            }
            if !reserved.iter().any(|&(rs, re)| rs < end && re > start) {
                return Some((start, end));
            }
            cursor = end; // this block is spoken for; try the next one
        }
        None
    }

    /// Allocate up to `max` blocks to request from one source.
    ///
    /// Upstream picks ONE part per source and drains it before moving on, which
    /// is what keeps parts finishing (and therefore verifiable and shareable)
    /// instead of leaving every part half-done. `available` says which parts the
    /// source actually holds.
    /// Pick up to `max` blocks to request from a peer that holds the parts for
    /// which `available(part)` is true.
    ///
    /// `rarity(part)` is the swarm availability of a part (how many peers hold
    /// it); parts are requested RAREST-FIRST so the least-available data enters
    /// our copy soonest (it may vanish from the swarm), tie-broken by the usual
    /// "finish nearly-complete parts first" order. In `endgame` the `reserved`
    /// list is ignored, so several peers can race the final blocks - a slow or
    /// queuing peer then can't stall the last block.
    pub fn next_blocks(
        &self,
        available: &dyn Fn(u64) -> bool,
        reserved: &[(u64, u64)],
        max: usize,
        rarity: &dyn Fn(u64) -> u32,
        endgame: bool,
        preview: bool,
    ) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut taken: Vec<(u64, u64)> = if endgame {
            Vec::new()
        } else {
            reserved.to_vec()
        };

        // `wanted_parts()` is already ordered by (missing, part); a stable sort
        // preserves that tie-break under the chosen ordering.
        let mut parts = self.wanted_parts();
        if preview {
            // Preview bias: strictly forward-sequential (part 0, 1, 2, ...), so the
            // file grows CONTIGUOUSLY from offset 0 and a player can read/play the
            // leading run straight off the raw `.part`. We do NOT fetch the last
            // part early: the snapshot the player gets is only the contiguous head,
            // so a disconnected tail island would not help it - a moov-at-end
            // (non-faststart) file simply is not previewable until near-complete
            // (a future AVAssetResourceLoader serving ranges would lift that).
            parts.sort_by_key(|&p| p);
        } else {
            // Rarest-first: the least-available data enters our copy soonest.
            parts.sort_by_key(|&p| rarity(p));
        }

        for part in parts {
            if !available(part) {
                continue;
            }
            while out.len() < max {
                match self.next_block_in_part(part, &taken) {
                    Some(b) => {
                        out.push(b);
                        taken.push(b);
                    }
                    None => break,
                }
            }
            if out.len() >= max {
                break;
            }
        }
        out
    }

    /// Parts that still have missing bytes, most-complete-first.
    ///
    /// Upstream ranks these by a 4-criteria formula (rarity, preview, already-
    /// requested, completion) with a random tie-break. Here the ordering stays
    /// simple - most-complete-first, so parts finish and become shareable.
    /// Rarity IS tracked and applied one level up: `multi_source` folds each
    /// peer's OP_FILESTATUS into per-part availability and `take_blocks`
    /// selects rarest-first over this list.
    pub fn wanted_parts(&self) -> Vec<u64> {
        let n = data_part_count(self.size);
        let mut parts: Vec<(u64, u64)> = (0..n)
            .filter(|&p| !self.is_part_complete(p))
            .map(|p| (p, self.part_missing(p)))
            .collect();
        parts.sort_by_key(|&(p, missing)| (missing, p));
        parts.into_iter().map(|(p, _)| p).collect()
    }

    /// Bytes still missing from `part`.
    fn part_missing(&self, part: u64) -> u64 {
        let start = part * PARTSIZE;
        let end = start + part_size(part, self.size);
        self.gaps
            .iter()
            .filter(|g| g.start < end && g.end > start)
            .map(|g| g.end.min(end) - g.start.max(start))
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::ed2k_hash;

    const H: [u8; 16] = [0xAB; 16];

    #[test]
    fn data_part_count_differs_from_the_ed2k_part_count_on_exact_multiples() {
        // The whole point of keeping the two separate.
        assert_eq!(data_part_count(1), 1);
        assert_eq!(data_part_count(PARTSIZE - 1), 1);
        assert_eq!(data_part_count(PARTSIZE), 1);
        assert_eq!(data_part_count(PARTSIZE + 1), 2);
        assert_eq!(data_part_count(2 * PARTSIZE), 2);
        // ...whereas the ED2K count carries the sentinel part.
        assert_eq!(mule_proto::part_count(PARTSIZE), 2);
        assert_eq!(mule_proto::part_count(2 * PARTSIZE), 3);
    }

    #[test]
    fn part_size_is_short_only_for_a_ragged_last_part() {
        assert_eq!(part_size(0, PARTSIZE), PARTSIZE);
        assert_eq!(part_size(0, 500), 500);
        assert_eq!(part_size(0, PARTSIZE + 10), PARTSIZE);
        assert_eq!(part_size(1, PARTSIZE + 10), 10);
    }

    #[test]
    fn a_fresh_download_wants_the_whole_file() {
        let pf = PartFile::new(H, 1000);
        assert_eq!(pf.missing(), 1000);
        assert_eq!(
            pf.gaps(),
            &[Gap {
                start: 0,
                end: 1000
            }]
        );
        assert!(!pf.is_complete());
    }

    #[test]
    fn filling_gaps_closes_them_and_merges() {
        let mut pf = PartFile::new(H, 1000);
        pf.fill_gap(200, 400);
        assert_eq!(
            pf.gaps(),
            &[
                Gap { start: 0, end: 200 },
                Gap {
                    start: 400,
                    end: 1000
                }
            ]
        );
        assert_eq!(pf.missing(), 800);

        // A range spanning the hole in the middle collapses both.
        pf.fill_gap(0, 1000);
        assert!(pf.is_complete());
        assert_eq!(pf.missing(), 0);
    }

    #[test]
    fn filling_the_same_range_twice_is_harmless() {
        let mut pf = PartFile::new(H, 1000);
        pf.fill_gap(100, 200);
        pf.fill_gap(100, 200);
        pf.fill_gap(150, 175); // inside an already-filled range
        assert_eq!(pf.missing(), 900);
    }

    #[test]
    fn blocks_are_bounded_by_the_lattice_not_just_the_gap() {
        // A 400 KB file: block 0 must stop at EMBLOCKSIZE, not run to EOF.
        let pf = PartFile::new(H, 400_000);
        let b = pf.next_block_in_part(0, &[]).unwrap();
        assert_eq!(b, (0, EMBLOCKSIZE));
    }

    #[test]
    fn a_block_can_be_shorter_than_emblocksize() {
        let pf = PartFile::new(H, 400_000);
        // Third block is the ragged tail: 400000 - 2*184320 = 31360 bytes.
        let mut pf2 = pf.clone();
        pf2.fill_gap(0, 2 * EMBLOCKSIZE);
        let b = pf2.next_block_in_part(0, &[]).unwrap();
        assert_eq!(b, (2 * EMBLOCKSIZE, 400_000));
        assert!(b.1 - b.0 < EMBLOCKSIZE, "tail block must be short");
    }

    #[test]
    fn a_block_never_crosses_a_part_boundary() {
        let size = PARTSIZE + 1000;
        let pf = PartFile::new(H, size);
        // The final block of part 0 must stop exactly at PARTSIZE.
        let mut pf2 = pf.clone();
        pf2.fill_gap(0, 52 * EMBLOCKSIZE); // 52 full blocks = 9_584_640
        let b = pf2.next_block_in_part(0, &[]).unwrap();
        assert_eq!(b, (52 * EMBLOCKSIZE, PARTSIZE));
        assert_eq!(b.1 - b.0, 143_360, "the documented short tail block");

        // Part 1 starts at PARTSIZE and is only 1000 bytes.
        let b1 = pf.next_block_in_part(1, &[]).unwrap();
        assert_eq!(b1, (PARTSIZE, PARTSIZE + 1000));
    }

    #[test]
    fn reserved_blocks_are_skipped_so_two_sources_do_not_collide() {
        let pf = PartFile::new(H, 400_000);
        let first = pf.next_block_in_part(0, &[]).unwrap();
        // With the first block reserved, we must be handed the SECOND one.
        let second = pf.next_block_in_part(0, &[first]).unwrap();
        assert_eq!(second, (EMBLOCKSIZE, 2 * EMBLOCKSIZE));
        assert_ne!(first, second);

        // Reserve everything -> nothing left to hand out.
        let third = pf.next_block_in_part(0, &[first, second]).unwrap();
        assert!(pf.next_block_in_part(0, &[first, second, third]).is_none());
    }

    #[test]
    fn next_blocks_hands_out_three_distinct_blocks() {
        let pf = PartFile::new(H, 400_000);
        let blocks = pf.next_blocks(&|_| true, &[], 3, &|_| 0, false, false);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0], (0, EMBLOCKSIZE));
        assert_eq!(blocks[1], (EMBLOCKSIZE, 2 * EMBLOCKSIZE));
        assert_eq!(blocks[2], (2 * EMBLOCKSIZE, 400_000));
        // No overlaps.
        assert!(blocks[0].1 <= blocks[1].0 && blocks[1].1 <= blocks[2].0);
    }

    #[test]
    fn contiguous_prefix_stops_at_the_first_gap() {
        let mut pf = PartFile::new(H, 1_000_000);
        assert_eq!(pf.contiguous_prefix(), 0, "byte 0 is still missing");
        pf.fill_gap(0, 300_000);
        assert_eq!(
            pf.contiguous_prefix(),
            300_000,
            "prefix reaches the first gap"
        );
        // A disconnected island does NOT extend the contiguous-from-0 prefix.
        pf.fill_gap(500_000, 600_000);
        assert_eq!(pf.contiguous_prefix(), 300_000);
        pf.fill_gap(300_000, 500_000);
        assert_eq!(pf.contiguous_prefix(), 600_000, "the island now joins on");
        pf.fill_gap(0, 1_000_000);
        assert_eq!(pf.contiguous_prefix(), 1_000_000, "complete -> whole file");
    }

    #[test]
    fn preview_is_sequential_ignoring_rarity() {
        // 3 parts, with the LAST part made the rarest so rarest-first would start
        // there. Preview must ignore rarity and go strictly front-to-back.
        let pf = PartFile::new(H, 3 * PARTSIZE);
        let rarity = |p: u64| if p == 2 { 0 } else { 9 }; // part 2 is rarest

        // Non-preview: rarest-first starts in the rarest part (2).
        let rare = pf.next_blocks(&|_| true, &[], 1, &rarity, false, false);
        assert!(
            rare[0].0 >= 2 * PARTSIZE,
            "rarest-first starts in the rarest part"
        );

        // Preview: sequential from part 0, and it continues to part 1 (NOT the rare
        // last part), so the contiguous-from-start prefix grows.
        let prev = pf.next_blocks(&|_| true, &[], 10_000, &rarity, false, true);
        assert_eq!(
            prev[0],
            (0, EMBLOCKSIZE),
            "preview starts at the first block"
        );
        let after_part0 = prev.iter().take_while(|(s, _)| *s < PARTSIZE).count();
        assert_eq!(
            prev[after_part0].0, PARTSIZE,
            "preview continues to part 1, in order"
        );
    }

    #[test]
    fn we_never_request_a_part_the_source_lacks() {
        let pf = PartFile::new(H, 3 * PARTSIZE);
        // Source has ONLY part 2.
        let blocks = pf.next_blocks(&|p| p == 2, &[], 3, &|_| 0, false, false);
        assert!(!blocks.is_empty());
        for (s, _) in blocks {
            assert!(s >= 2 * PARTSIZE, "requested outside part 2: {s}");
        }
        // A source with nothing gives us nothing.
        assert!(pf
            .next_blocks(&|_| false, &[], 3, &|_| 0, false, false)
            .is_empty());
    }

    #[test]
    fn a_completed_file_yields_no_more_blocks() {
        let mut pf = PartFile::new(H, 400_000);
        pf.fill_gap(0, 400_000);
        assert!(pf.is_complete());
        assert!(pf
            .next_blocks(&|_| true, &[], 3, &|_| 0, false, false)
            .is_empty());
        assert!(pf.next_block_in_part(0, &[]).is_none());
    }

    #[test]
    fn part_completion_tracks_the_gap_list() {
        let mut pf = PartFile::new(H, PARTSIZE + 1000);
        assert!(!pf.is_part_complete(0));
        pf.fill_gap(0, PARTSIZE);
        assert!(pf.is_part_complete(0));
        assert!(!pf.is_part_complete(1));
        assert!(!pf.is_complete());
    }

    #[test]
    fn a_small_single_part_file_verifies_against_the_file_hash() {
        let data = vec![7u8; 5000];
        let hash = ed2k_hash(&data);
        let pf = PartFile::new(hash, data.len() as u64);
        // No hashset at all, and none needed.
        assert_eq!(pf.verify_part(0, &data), Some(true));
        assert_eq!(pf.verify_part(0, &vec![8u8; 5000]), Some(false));
    }

    #[test]
    fn an_exactly_partsize_file_verifies_against_the_part_hash() {
        // THE aMULE BUG. A file of exactly PARTSIZE has a 2-entry hashset, so
        // its file hash is MD4(h0 || h_empty) and can never equal h0. aMule
        // compares against the file hash here and calls the part corrupt
        // forever; we compare against the part hash, as eMule does.
        let data = vec![3u8; PARTSIZE as usize];
        let file_hash = ed2k_hash(&data);
        let part_hash = md4(&data);
        assert_ne!(
            file_hash, part_hash,
            "precondition: the two genuinely differ for an exact-multiple file"
        );

        let mut pf = PartFile::new(file_hash, PARTSIZE);
        assert_eq!(data_part_count(PARTSIZE), 1, "still a single DATA part");
        pf.part_hashes = vec![part_hash, md4(b"")];

        // This is the assertion aMule fails.
        assert_eq!(
            pf.verify_part(0, &data),
            Some(true),
            "an exactly-PARTSIZE file must verify"
        );
    }

    #[test]
    fn a_multipart_file_verifies_each_part_against_its_own_hash() {
        let size = PARTSIZE + 1000;
        let p0 = vec![1u8; PARTSIZE as usize];
        let p1 = vec![2u8; 1000];
        let mut pf = PartFile::new(H, size);
        pf.part_hashes = vec![md4(&p0), md4(&p1)];

        assert_eq!(pf.verify_part(0, &p0), Some(true));
        assert_eq!(pf.verify_part(1, &p1), Some(true));
        assert_eq!(pf.verify_part(1, &p0), Some(false));
    }

    #[test]
    fn verification_without_a_hashset_is_unknown_not_false() {
        let pf = PartFile::new(H, 2 * PARTSIZE); // multipart, no hashes yet
        assert_eq!(pf.verify_part(0, b"whatever"), None);
    }

    #[test]
    fn a_corrupt_part_is_fully_reopened_and_remembered() {
        let size = PARTSIZE + 1000;
        let mut pf = PartFile::new(H, size);
        pf.fill_gap(0, size);
        assert!(pf.is_complete());

        pf.mark_corrupt(0);
        // The WHOLE part comes back, not just a block - without AICH we cannot
        // know which block was bad.
        assert!(!pf.is_complete());
        assert!(!pf.is_part_complete(0));
        assert!(pf.is_part_complete(1), "part 1 must be untouched");
        assert_eq!(pf.missing(), PARTSIZE);
        assert_eq!(pf.corrupted(), &[0]);

        // Re-downloading and clearing restores the invariant.
        pf.fill_gap(0, PARTSIZE);
        pf.clear_corrupt(0);
        assert!(pf.is_complete());
        assert!(pf.corrupted().is_empty());
    }

    #[test]
    fn marking_the_same_part_corrupt_twice_does_not_duplicate_it() {
        let mut pf = PartFile::new(H, PARTSIZE + 1000);
        pf.fill_gap(0, PARTSIZE + 1000);
        pf.mark_corrupt(0);
        pf.mark_corrupt(0);
        assert_eq!(pf.corrupted(), &[0]);
        assert_eq!(pf.missing(), PARTSIZE);
    }

    #[test]
    fn resume_tidies_a_messy_gap_list() {
        // Overlapping, unsorted, and one empty gap - all of which a hand-edited
        // or half-written part.met could contain.
        let pf = PartFile::resume(
            H,
            1000,
            vec![
                Gap {
                    start: 500,
                    end: 700,
                },
                Gap {
                    start: 100,
                    end: 200,
                },
                Gap {
                    start: 650,
                    end: 800,
                },
                Gap {
                    start: 900,
                    end: 900,
                },
            ],
            vec![],
        );
        assert_eq!(
            pf.gaps(),
            &[
                Gap {
                    start: 100,
                    end: 200
                },
                Gap {
                    start: 500,
                    end: 800
                },
            ]
        );
        assert_eq!(pf.missing(), 100 + 300);
    }

    #[test]
    fn next_blocks_prefers_the_rarest_part() {
        // Three full parts, all equally incomplete, so the (missing, part)
        // tie-break alone would pick part 0. Making part 2 the rarest must flip
        // it to the front.
        let pf = PartFile::new(H, 3 * PARTSIZE);
        let rarity = |p: u64| if p == 2 { 0 } else { 9 };
        let blocks = pf.next_blocks(&|_| true, &[], 1, &rarity, false, false);
        assert_eq!(blocks.len(), 1);
        assert!(
            blocks[0].0 >= 2 * PARTSIZE,
            "the rarest part (2) is requested first, got {:?}",
            blocks[0]
        );
        // With uniform rarity, order falls back to the part index (part 0).
        let flat = pf.next_blocks(&|_| true, &[], 1, &|_| 0, false, false);
        assert!(flat[0].0 < PARTSIZE, "uniform rarity -> part 0 first");
    }

    #[test]
    fn endgame_re_offers_reserved_blocks() {
        // A one-block file. Normally a reserved block is skipped; in endgame it
        // is re-offered so several peers can race the final block.
        let pf = PartFile::new(H, 100_000); // < EMBLOCKSIZE -> one block
        let b = pf.next_blocks(&|_| true, &[], 1, &|_| 0, false, false)[0];
        assert!(pf
            .next_blocks(&|_| true, &[b], 1, &|_| 0, false, false)
            .is_empty());
        assert_eq!(
            pf.next_blocks(&|_| true, &[b], 1, &|_| 0, true, false),
            vec![b]
        );
    }
}
