//! known2_64.met: the AICH full-hashset store - every shared file's SHA-1 leaf
//! hashes, keyed by the AICH master root, so OP_AICHREQUEST recovery data can
//! be served without rehashing the file.
//!
//! WIRE/FORMAT AUTHORITY eMule 0.50a `SHAHashSet.cpp` (aMule 3.0.1 identical):
//! `<version u8 = 0x02>` then per hashset `<master root 20><count u32>
//! <count * leaf hash 20>` - the count EXCLUDES the root (`SaveHashSet`
//! :796-807), leaves are the EMBLOCKSIZE lowest level, left to right, no
//! identifiers (`WriteLowestLevelHashs` with `bNoIdent`). The u32 count is the
//! 64-bit-file upgrade over the old known2.met's u16 (aMule ThreadTasks.cpp
//! :454-509 converter).
//!
//! This module is the pure byte codec; file I/O, the append-with-rollback
//! discipline and pruning policy live in the engine. `scan_known2_met` is the
//! root->offset index aMule master added (`SHAHashSet.h:307-327`,
//! `s_rootHashCache` - "making the AICH request path O(1) and closing the DoS
//! amplification"): one walk at load, then every lookup seeks directly.
//! A torn final entry (a crash mid-append) is EXCLUDED and reported via
//! `valid_len` so the caller can truncate it off, exactly as both authorities'
//! sync passes do (eMule AICHSyncThread.cpp:113, aMule ThreadTasks.cpp:403-407).

use mule_proto::IoError;
use std::collections::HashMap;

/// known2_64.met version byte (KNOWN2_MET_VERSION, eMule SHAHashSet.h:72).
pub const KNOWN2_MET_VERSION: u8 = 0x02;

const HASHSIZE: usize = 20;
const ENTRY_HEADER: usize = HASHSIZE + 4; // root + count

/// One stored hashset: the master root plus the left-to-right leaf hashes.
#[derive(Debug, Clone, PartialEq)]
pub struct Known2Entry {
    pub root: [u8; 20],
    pub leaves: Vec<[u8; 20]>,
}

/// An empty store: just the version byte.
pub fn empty_known2_met() -> Vec<u8> {
    vec![KNOWN2_MET_VERSION]
}

/// Serialize one hashset entry (the bytes appended to the store).
pub fn known2_entry_bytes(root: &[u8; 20], leaves: &[[u8; 20]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ENTRY_HEADER + leaves.len() * HASHSIZE);
    out.extend_from_slice(root);
    out.extend_from_slice(&(leaves.len() as u32).to_le_bytes());
    for l in leaves {
        out.extend_from_slice(l);
    }
    out
}

/// The scan result: the root->offset index plus how much of the file is whole
/// entries (`valid_len < bytes.len()` means a torn tail to truncate off).
#[derive(Debug, Clone, PartialEq)]
pub struct Known2Index {
    /// Master root -> byte offset of the entry (its root hash) in the store.
    /// First occurrence wins, matching the authorities' linear scan.
    pub by_root: HashMap<[u8; 20], u64>,
    /// Length of the whole-entry prefix (everything past it is torn).
    pub valid_len: u64,
}

/// One walk over the store building the offset index. Errors only on a bad
/// version byte or an empty input; a torn tail is not an error (see module doc).
pub fn scan_known2_met(bytes: &[u8]) -> Result<Known2Index, IoError> {
    if bytes.is_empty() {
        return Err(IoError::UnexpectedEof);
    }
    if bytes[0] != KNOWN2_MET_VERSION {
        return Err(IoError::BadTag(bytes[0]));
    }
    let mut by_root = HashMap::new();
    let mut pos = 1u64;
    let len = bytes.len() as u64;
    while pos < len {
        if len - pos < ENTRY_HEADER as u64 {
            break; // torn tail
        }
        let at = pos as usize;
        let count = u32::from_le_bytes([
            bytes[at + HASHSIZE],
            bytes[at + HASHSIZE + 1],
            bytes[at + HASHSIZE + 2],
            bytes[at + HASHSIZE + 3],
        ]);
        let entry_len = ENTRY_HEADER as u64 + u64::from(count) * HASHSIZE as u64;
        if len - pos < entry_len {
            break; // torn tail
        }
        let mut root = [0u8; 20];
        root.copy_from_slice(&bytes[at..at + HASHSIZE]);
        by_root.entry(root).or_insert(pos);
        pos += entry_len;
    }
    Ok(Known2Index {
        by_root,
        valid_len: pos,
    })
}

/// Parse the entry at `offset` (an offset produced by [`scan_known2_met`]).
/// The leaf vec grows incrementally - an untrusted count cannot force an
/// allocation larger than the store itself.
pub fn read_known2_entry(bytes: &[u8], offset: u64) -> Result<Known2Entry, IoError> {
    let at = offset as usize;
    if bytes.len() < at + ENTRY_HEADER {
        return Err(IoError::UnexpectedEof);
    }
    let mut root = [0u8; 20];
    root.copy_from_slice(&bytes[at..at + HASHSIZE]);
    let count = u32::from_le_bytes([
        bytes[at + HASHSIZE],
        bytes[at + HASHSIZE + 1],
        bytes[at + HASHSIZE + 2],
        bytes[at + HASHSIZE + 3],
    ]) as usize;
    let mut leaves = Vec::new();
    let mut pos = at + ENTRY_HEADER;
    for _ in 0..count {
        if bytes.len() < pos + HASHSIZE {
            return Err(IoError::UnexpectedEof);
        }
        let mut leaf = [0u8; 20];
        leaf.copy_from_slice(&bytes[pos..pos + HASHSIZE]);
        leaves.push(leaf);
        pos += HASHSIZE;
    }
    Ok(Known2Entry { root, leaves })
}

/// Full parse of a store (tools/tests; the engine uses the index + per-entry
/// reads). A torn tail is silently dropped, like the scan.
pub fn read_known2_met(bytes: &[u8]) -> Result<Vec<Known2Entry>, IoError> {
    let idx = scan_known2_met(bytes)?;
    let mut offsets: Vec<u64> = idx.by_root.values().copied().collect();
    offsets.sort_unstable();
    offsets
        .into_iter()
        .map(|off| read_known2_entry(bytes, off))
        .collect()
}

/// Rewrite the store without the entry for `root` (pure transform; the engine
/// wraps it in an atomic tmp+rename). Returns `None` when `root` is absent -
/// callers then skip the rewrite entirely. Other entries are preserved
/// byte-verbatim; a torn tail is dropped.
pub fn remove_known2_entry(bytes: &[u8], root: &[u8; 20]) -> Option<Vec<u8>> {
    let idx = scan_known2_met(bytes).ok()?;
    idx.by_root.get(root)?;
    let mut out = Vec::with_capacity(bytes.len());
    out.push(KNOWN2_MET_VERSION);
    let mut offsets: Vec<(u64, [u8; 20])> = idx.by_root.iter().map(|(r, o)| (*o, *r)).collect();
    offsets.sort_unstable();
    for (off, r) in offsets {
        if r == *root {
            continue;
        }
        let at = off as usize;
        let count = u32::from_le_bytes([
            bytes[at + HASHSIZE],
            bytes[at + HASHSIZE + 1],
            bytes[at + HASHSIZE + 2],
            bytes[at + HASHSIZE + 3],
        ]);
        let entry_len = ENTRY_HEADER + count as usize * HASHSIZE;
        out.extend_from_slice(&bytes[at..at + entry_len]);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(b: u8) -> [u8; 20] {
        [b; 20]
    }

    fn store_of(entries: &[(&[u8; 20], &[[u8; 20]])]) -> Vec<u8> {
        let mut s = empty_known2_met();
        for (root, leaves) in entries {
            s.extend_from_slice(&known2_entry_bytes(root, leaves));
        }
        s
    }

    #[test]
    fn golden_layout_is_version_root_count_leaves() {
        // <0x02><root 20><count u32 LE = 2><leaf><leaf>
        let s = store_of(&[(&leaf(0xAA), &[leaf(1), leaf(2)])]);
        assert_eq!(s[0], 0x02);
        assert_eq!(&s[1..21], &[0xAA; 20]);
        assert_eq!(&s[21..25], &[2, 0, 0, 0]);
        assert_eq!(&s[25..45], &[1u8; 20]);
        assert_eq!(&s[45..65], &[2u8; 20]);
        assert_eq!(s.len(), 65);
    }

    #[test]
    fn scan_indexes_offsets_and_reads_back() {
        let s = store_of(&[
            (&leaf(0xAA), &[leaf(1), leaf(2)]),
            (&leaf(0xBB), &[leaf(3)]),
        ]);
        let idx = scan_known2_met(&s).unwrap();
        assert_eq!(idx.valid_len, s.len() as u64);
        assert_eq!(idx.by_root[&leaf(0xAA)], 1);
        assert_eq!(idx.by_root[&leaf(0xBB)], 1 + 24 + 40);
        let e = read_known2_entry(&s, idx.by_root[&leaf(0xBB)]).unwrap();
        assert_eq!(
            e,
            Known2Entry {
                root: leaf(0xBB),
                leaves: vec![leaf(3)],
            }
        );
        assert_eq!(read_known2_met(&s).unwrap().len(), 2);
    }

    #[test]
    fn torn_tail_is_excluded_not_fatal() {
        // a crash mid-append leaves a partial entry; the scan reports the
        // whole-entry prefix so the caller can truncate (aMule
        // ThreadTasks.cpp:403-407).
        let whole = store_of(&[(&leaf(0xAA), &[leaf(1)])]);
        let mut torn = whole.clone();
        torn.extend_from_slice(&[0xCC; 30]); // root + partial count/leaves
        let idx = scan_known2_met(&torn).unwrap();
        assert_eq!(idx.valid_len, whole.len() as u64);
        assert_eq!(idx.by_root.len(), 1);
        // a torn ENTRY HEADER with a count promising more than the file holds
        let mut lying = whole.clone();
        lying.extend_from_slice(&known2_entry_bytes(&leaf(0xDD), &[leaf(9); 4])[..30]);
        let idx = scan_known2_met(&lying).unwrap();
        assert_eq!(idx.valid_len, whole.len() as u64);
    }

    #[test]
    fn huge_count_cannot_force_a_huge_allocation() {
        // count u32::MAX with a tiny store: scan excludes it as torn, and a
        // direct entry read errors incrementally instead of preallocating.
        let mut s = empty_known2_met();
        s.extend_from_slice(&leaf(0xEE));
        s.extend_from_slice(&u32::MAX.to_le_bytes());
        s.extend_from_slice(&[0u8; 40]);
        let idx = scan_known2_met(&s).unwrap();
        assert_eq!(idx.valid_len, 1);
        assert!(read_known2_entry(&s, 1).is_err());
    }

    #[test]
    fn remove_entry_preserves_others_verbatim() {
        let s = store_of(&[
            (&leaf(0xAA), &[leaf(1), leaf(2)]),
            (&leaf(0xBB), &[leaf(3)]),
            (&leaf(0xCC), &[leaf(4), leaf(5), leaf(6)]),
        ]);
        let out = remove_known2_entry(&s, &leaf(0xBB)).unwrap();
        assert_eq!(
            out,
            store_of(&[
                (&leaf(0xAA), &[leaf(1), leaf(2)]),
                (&leaf(0xCC), &[leaf(4), leaf(5), leaf(6)]),
            ])
        );
        // absent root: no rewrite signalled
        assert!(remove_known2_entry(&out, &leaf(0xBB)).is_none());
    }

    #[test]
    fn empty_store_and_bad_version() {
        let idx = scan_known2_met(&empty_known2_met()).unwrap();
        assert!(idx.by_root.is_empty());
        assert_eq!(idx.valid_len, 1);
        assert_eq!(scan_known2_met(&[]), Err(IoError::UnexpectedEof));
        assert_eq!(scan_known2_met(&[0x01]), Err(IoError::BadTag(0x01)));
    }

    #[test]
    fn duplicate_root_first_occurrence_wins() {
        // dedup normally prevents this, but a store that HAS a duplicate must
        // resolve like the authorities' linear scan: first match.
        let mut s = store_of(&[(&leaf(0xAA), &[leaf(1)])]);
        s.extend_from_slice(&known2_entry_bytes(&leaf(0xAA), &[leaf(2)]));
        let idx = scan_known2_met(&s).unwrap();
        assert_eq!(idx.by_root[&leaf(0xAA)], 1);
        assert_eq!(
            read_known2_entry(&s, 1).unwrap().leaves,
            vec![leaf(1)],
            "first entry wins"
        );
    }
}
