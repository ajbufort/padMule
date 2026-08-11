//! Known2Store: the file-backed known2_64.met AICH hashset store, with the
//! root->offset index that keeps the serve path O(1) (aMule master's
//! s_rootHashCache design, SHAHashSet.h:307-327 - one scan at load, direct
//! seeks after; eMule 0.50a still walks the whole file per request, which is
//! the DoS amplification the aMule comment cites closing).
//!
//! Concurrency/pruning discipline: aMule 3.0.1's post-hashing orphan prune
//! raced the main-thread catalog registration and destroyed freshly written
//! hashsets (fixed in master by gating the prune to STARTUP only,
//! ThreadTasks.h:136-144). padMule takes master's discipline structurally:
//! `prune_orphans` is called exactly once, from `start()`, after the catalog
//! (known.met) is loaded - and every mutation goes through `&self` methods
//! whose index lock serializes them, so the race class cannot exist.
//!
//! Crash safety follows the authorities: appends are rolled back by
//! truncation on any failure (eMule SHAHashSet.cpp:803/:809), a torn tail
//! from a hard crash is truncated off at load (eMule AICHSyncThread.cpp:113,
//! aMule ThreadTasks.cpp:403-407), and rewrites (remove/prune) go through a
//! temp file + atomic rename like every other padMule .met writer.

use mule_files::{empty_known2_met, known2_entry_bytes, remove_known2_entry, scan_known2_met};
use mule_proto::AichTree;
use std::collections::{HashMap, HashSet};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex as StdMutex;

use crate::lock::LockRecover;

/// The store filename (eMule KNOWN2_MET_FILENAME).
pub const KNOWN2_MET: &str = "known2_64.met";

pub struct Known2Store {
    path: PathBuf,
    /// Master root -> byte offset of the entry in the file.
    ///
    /// POISON-TOLERANT ([`crate::lock::LockRecover`]), and the site with the
    /// most exposure: `remove`/`prune_orphans` hold this lock across
    /// `scan_known2_met` and `remove_known2_entry`, i.e. across PARSING the
    /// whole store file - whose contents include hashsets learned from peers.
    /// Recovery is safe because this is a pure CACHE that `lookup` re-validates
    /// from the artifact: it re-reads the root at the offset and rebuilds the
    /// tree, refusing anything that does not reproduce the root. A torn index
    /// can therefore cost a miss (we re-ask), never a wrong answer.
    index: StdMutex<HashMap<[u8; 20], u64>>,
}

impl Known2Store {
    /// Open the store at `dir/known2_64.met`, creating an empty one if absent,
    /// building the index, and truncating a torn tail. A file with a FOREIGN
    /// version byte is left untouched (we just cannot serve from it) - never
    /// overwritten, matching both authorities' abort-on-bad-header.
    pub fn load(dir: &Path) -> Known2Store {
        let path = dir.join(KNOWN2_MET);
        let bytes = std::fs::read(&path).unwrap_or_default();
        let mut index = HashMap::new();
        if bytes.is_empty() {
            let _ = std::fs::write(&path, empty_known2_met());
        } else if let Ok(ix) = scan_known2_met(&bytes) {
            if ix.valid_len < bytes.len() as u64 {
                if let Ok(f) = std::fs::OpenOptions::new().write(true).open(&path) {
                    let _ = f.set_len(ix.valid_len);
                }
            }
            index = ix.by_root;
        }
        Known2Store {
            path,
            index: StdMutex::new(index),
        }
    }

    /// Whether a hashset for `root` is stored.
    pub fn has(&self, root: &[u8; 20]) -> bool {
        self.index.lock_recover().contains_key(root)
    }

    /// Append one hashset. Deduplicated by root (eMule SHAHashSet.cpp:770-776);
    /// any write failure or length mismatch rolls the file back to its prior
    /// length so a partial entry never survives (eMule :803/:809).
    pub fn append(&self, root: &[u8; 20], leaves: &[[u8; 20]]) -> std::io::Result<()> {
        let mut ix = self.index.lock_recover();
        if ix.contains_key(root) {
            return Ok(());
        }
        let mut f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&self.path)?;
        let mut existing = f.metadata()?.len();
        if existing == 0 {
            f.write_all(&empty_known2_met())?;
            existing = 1;
        } else {
            let mut hdr = [0u8; 1];
            f.read_exact(&mut hdr)?;
            if hdr[0] != mule_files::KNOWN2_MET_VERSION {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "known2_64.met has a foreign version byte",
                ));
            }
        }
        f.seek(SeekFrom::End(0))?;
        let entry = known2_entry_bytes(root, leaves);
        if let Err(e) = f.write_all(&entry).and_then(|()| f.flush()) {
            let _ = f.set_len(existing);
            return Err(e);
        }
        if f.metadata()?.len() != existing + entry.len() as u64 {
            let _ = f.set_len(existing);
            return Err(std::io::Error::other(
                "calculated and real size of hashset differ",
            ));
        }
        ix.insert(*root, existing);
        Ok(())
    }

    /// The rebuilt tree for `root`, VALIDATED the way eMule's LoadHashSet is
    /// (SHAHashSet.cpp:872-893): the stored count must match what `file_size`
    /// demands, and the tree recomputed from the leaves must reproduce `root` -
    /// a corrupted store serves nothing rather than serving lies. The count
    /// check precedes the allocation, so a corrupt count cannot balloon it.
    ///
    /// Returns the TREE, not the leaves: validating already builds one, and
    /// the serve path needs exactly that - handing back leaves made the
    /// caller rebuild an identical tree, doubling the CPU of the single most
    /// expensive answer we serve.
    pub fn lookup(&self, root: &[u8; 20], file_size: u64) -> Option<AichTree> {
        let off = *self.index.lock_recover().get(root)?;
        let mut f = std::fs::File::open(&self.path).ok()?;
        f.seek(SeekFrom::Start(off)).ok()?;
        let mut hdr = [0u8; 24];
        f.read_exact(&mut hdr).ok()?;
        if hdr[..20] != root[..] {
            return None; // stale index
        }
        let count = u32::from_le_bytes([hdr[20], hdr[21], hdr[22], hdr[23]]);
        if u64::from(count) != AichTree::leaf_count(file_size) {
            return None;
        }
        let mut buf = vec![0u8; count as usize * 20];
        f.read_exact(&mut buf).ok()?;
        let leaves: Vec<[u8; 20]> = buf
            .chunks_exact(20)
            .map(|c| {
                let mut h = [0u8; 20];
                h.copy_from_slice(c);
                h
            })
            .collect();
        let tree = AichTree::from_leaves(file_size, &leaves)?;
        (tree.master_hash()? == *root).then_some(tree)
    }

    /// Remove the hashset for `root` (a file was unshared). Atomic rewrite;
    /// the index is rebuilt from the rewritten bytes.
    pub fn remove(&self, root: &[u8; 20]) {
        let mut ix = self.index.lock_recover();
        if !ix.contains_key(root) {
            return;
        }
        let Ok(bytes) = std::fs::read(&self.path) else {
            return;
        };
        let Some(out) = remove_known2_entry(&bytes, root) else {
            return;
        };
        if Self::write_atomic(&self.path, &out) {
            *ix = scan_known2_met(&out).map(|i| i.by_root).unwrap_or_default();
        }
    }

    /// STARTUP-ONLY (see module doc): drop hashsets whose root no longer
    /// appears in the catalog. Rewrites atomically only when something is
    /// actually dropped.
    pub fn prune_orphans(&self, live: &HashSet<[u8; 20]>) {
        let mut ix = self.index.lock_recover();
        let orphans: Vec<[u8; 20]> = ix.keys().filter(|r| !live.contains(*r)).copied().collect();
        if orphans.is_empty() {
            return;
        }
        let Ok(mut bytes) = std::fs::read(&self.path) else {
            return;
        };
        for root in &orphans {
            if let Some(out) = remove_known2_entry(&bytes, root) {
                bytes = out;
            }
        }
        if Self::write_atomic(&self.path, &bytes) {
            *ix = scan_known2_met(&bytes)
                .map(|i| i.by_root)
                .unwrap_or_default();
        }
    }

    fn write_atomic(path: &Path, bytes: &[u8]) -> bool {
        let tmp = path.with_extension("met.tmp");
        if std::fs::write(&tmp, bytes).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return false;
        }
        std::fs::rename(&tmp, path).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::AichTree;

    const EMBLOCKSIZE_B: u64 = mule_proto::EMBLOCKSIZE;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("padmule-k2-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A real tree for a small multi-block file, so lookups validate honestly.
    fn real_set(seed: u8, blocks: usize) -> (u64, [u8; 20], Vec<[u8; 20]>) {
        let size = blocks * mule_proto::EMBLOCKSIZE as usize - 7;
        let data: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_add(seed)).collect();
        let t = AichTree::from_file_data(&data).unwrap();
        (size as u64, t.master_hash().unwrap(), t.leaves().unwrap())
    }

    /// MUTEX POISONING (handoff #35a). This index lock is the one held across
    /// PARSING: `remove`/`prune_orphans` run `scan_known2_met` and
    /// `remove_known2_entry` over the whole store file while holding it, and
    /// that file's contents include hashsets learned from peers. A panic there
    /// would end AICH serving for the app's life. Recovery is safe because the
    /// index is a pure root->offset CACHE that `lookup` re-validates: it
    /// re-reads the root at the offset and rebuilds the tree, refusing anything
    /// that does not reproduce the root, so a stale entry can only cost a miss.
    #[test]
    fn a_panic_under_the_index_lock_leaves_the_store_working() {
        let dir = tmpdir("poison");
        let store = Known2Store::load(&dir);
        let (sa, ra, la) = real_set(8, 2);
        let (sb, rb, lb) = real_set(9, 3);
        store.append(&ra, &la).unwrap();
        crate::lock::poison_for_test(&store.index);

        // Reads, appends, removals and the startup prune all still work.
        assert!(store.has(&ra));
        assert_eq!(store.lookup(&ra, sa).unwrap().leaves().unwrap(), la);
        store.append(&rb, &lb).unwrap();
        assert_eq!(store.lookup(&rb, sb).unwrap().leaves().unwrap(), lb);
        store.remove(&ra);
        assert!(!store.has(&ra), "the removal took effect");
        store.prune_orphans(&HashSet::new());
        assert!(!store.has(&rb), "the prune took effect");
    }

    #[test]
    fn append_lookup_round_trip_and_dedup() {
        let dir = tmpdir("roundtrip");
        let store = Known2Store::load(&dir);
        let (size, root, leaves) = real_set(1, 3);
        store.append(&root, &leaves).unwrap();
        store.append(&root, &leaves).unwrap(); // dedup: no duplicate entry
        assert_eq!(store.lookup(&root, size).unwrap().leaves().unwrap(), leaves);
        // exactly one entry on disk
        let bytes = std::fs::read(dir.join(KNOWN2_MET)).unwrap();
        assert_eq!(bytes.len(), 1 + 24 + leaves.len() * 20);
        // A size demanding a different leaf count refuses (eMule's own check
        // is count-based, LoadHashSet :872-879 - a size within the same count
        // legitimately passes, just as it does upstream).
        assert!(store.lookup(&root, size + EMBLOCKSIZE_B).is_none());
        // survives a reload (index rebuilt from disk)
        let store2 = Known2Store::load(&dir);
        assert_eq!(
            store2.lookup(&root, size).unwrap().leaves().unwrap(),
            leaves
        );
    }

    #[test]
    fn lookup_refuses_a_corrupted_entry() {
        let dir = tmpdir("corrupt");
        let store = Known2Store::load(&dir);
        let (size, root, leaves) = real_set(2, 3);
        store.append(&root, &leaves).unwrap();
        // flip one leaf byte on disk: recomputed root no longer matches
        let p = dir.join(KNOWN2_MET);
        let mut bytes = std::fs::read(&p).unwrap();
        let n = bytes.len() - 1;
        bytes[n] ^= 0xFF;
        std::fs::write(&p, &bytes).unwrap();
        assert!(store.lookup(&root, size).is_none());
    }

    #[test]
    fn torn_tail_is_truncated_at_load() {
        let dir = tmpdir("torn");
        {
            let store = Known2Store::load(&dir);
            let (_, root, leaves) = real_set(3, 2);
            store.append(&root, &leaves).unwrap();
        }
        let p = dir.join(KNOWN2_MET);
        let whole = std::fs::read(&p).unwrap();
        let mut torn = whole.clone();
        torn.extend_from_slice(&[0xAB; 33]); // partial next entry
        std::fs::write(&p, &torn).unwrap();
        let store = Known2Store::load(&dir);
        assert_eq!(std::fs::read(&p).unwrap(), whole, "tail truncated off");
        assert_eq!(store.index.lock().unwrap().len(), 1);
    }

    #[test]
    fn remove_and_prune_keep_the_rest() {
        let dir = tmpdir("prune");
        let store = Known2Store::load(&dir);
        let (sa, ra, la) = real_set(4, 2);
        let (_sb, rb, lb) = real_set(5, 3);
        let (sc, rc, lc) = real_set(6, 4);
        store.append(&ra, &la).unwrap();
        store.append(&rb, &lb).unwrap();
        store.append(&rc, &lc).unwrap();
        store.remove(&rb);
        assert!(!store.has(&rb));
        assert_eq!(store.lookup(&ra, sa).unwrap().leaves().unwrap(), la);
        assert_eq!(store.lookup(&rc, sc).unwrap().leaves().unwrap(), lc);
        // prune down to only rc
        let live: HashSet<[u8; 20]> = [rc].into_iter().collect();
        store.prune_orphans(&live);
        assert!(!store.has(&ra));
        assert_eq!(store.lookup(&rc, sc).unwrap().leaves().unwrap(), lc);
    }

    #[test]
    fn foreign_version_byte_is_left_untouched() {
        let dir = tmpdir("foreign");
        let p = dir.join(KNOWN2_MET);
        std::fs::write(&p, [0x09, 1, 2, 3]).unwrap();
        let store = Known2Store::load(&dir);
        assert_eq!(std::fs::read(&p).unwrap(), [0x09, 1, 2, 3], "not clobbered");
        let (_, root, leaves) = real_set(7, 2);
        assert!(store.append(&root, &leaves).is_err(), "no append into it");
    }
}
