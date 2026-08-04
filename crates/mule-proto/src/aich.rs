//! AICH - the eD2k "Advanced Intelligent Corruption Handling" SHA-1 hash tree
//! (Wave 1c master hash; Wave 11 full tree + recovery data). A file's AICH
//! *master hash* is the root of a binary tree of SHA-1 hashes: each leaf is
//! `SHA1` of one 184320-byte block (EMBLOCKSIZE), each internal node is
//! `SHA1(leftHash || rightHash)`. It lets a downloader verify and re-fetch a
//! single corrupt ~180KB block instead of a whole 9.28 MB part.
//!
//! WIRE AUTHORITY: eMule 0.50a `SHAHashSet.cpp/.h` (per the project authority
//! rule); aMule 3.0.1 `SHAHashSet.cpp` is byte-identical on everything below.
//! The tree is NOT a uniform binary hash tree: the PARTSIZE boundary is a
//! forced level (`SHAHashSet.h:19-65`), so it is one tree over parts plus one
//! subtree per part over that part's 180KB blocks. The root counts as a LEFT
//! branch (`SHAHashSet.cpp:538-539`), and a node's split is
//! `blocks = ceil(n/base); left = ((isLeft ? blocks+1 : blocks)/2)*base`
//! (`SHAHashSet.cpp:120-122`) - the odd child goes LEFT under a left branch,
//! RIGHT under a right branch. BaseSize is PARTSIZE above the part level and
//! EMBLOCKSIZE below, chosen at child creation by `childSize <= PARTSIZE`
//! (`SHAHashSet.cpp:128-129,141-142`); a file `<= PARTSIZE` starts at
//! EMBLOCKSIZE (`SetFileSize`, `SHAHashSet.cpp:950-953`).
//!
//! A hash's wire identifier is its root path, MSB-first, 1 = left / 0 = right,
//! with the root's own left-bit doubling as the start marker - so the master
//! root's ident is exactly 1 and idents grow one bit per level
//! (`SHAHashSet.h:46-63`; encode `WriteHash` :365-376, decode `SetHash`
//! :439-494). Files over OLD_MAX_FILE_SIZE use 32-bit idents on the wire,
//! everything else 16-bit (`CreatePartRecoveryData`, `SHAHashSet.cpp:617`).
//!
//! DELIBERATE non-transcriptions, both latent 0.50a bugs with no wire effect:
//! the duplicate-hash skip statement `CAICHHash(file);` is a most-vexing-parse
//! no-op that desyncs the read (`SHAHashSet.cpp:456-459`; eMule 0.70b fixed it
//! to a real skip) - we implement the INTENDED skip; and `SetHash`'s
//! `bAllowOverwrite=false` is silently lost after one recursion level because
//! the recursive calls omit the argument whose default is `true`
//! (`SHAHashSet.h:156`, calls :483/:491) - we thread the flag through. Both
//! are safe either way because `VerifyHashTree(true)` re-derives everything
//! from the trusted root afterwards.

use crate::hash::{OLD_MAX_FILE_SIZE, PARTSIZE};
use sha1::{Digest, Sha1};

/// AICH leaf block size (eMule `EMBLOCKSIZE`, opcodes.h:134).
pub const EMBLOCKSIZE: u64 = 184_320;

const HASHSIZE: usize = 20;

/// Recursion sanity cap, eMule `SHAHashSet.cpp:97` (and the matching wire
/// ident bound 0x400000 = 2^22 at :698).
const MAX_LEVEL: u8 = 22;

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

fn sha1_pair(l: &[u8; 20], r: &[u8; 20]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(l);
    h.update(r);
    h.finalize().into()
}

fn base_for(size: u64) -> u64 {
    if size <= PARTSIZE {
        EMBLOCKSIZE
    } else {
        PARTSIZE
    }
}

fn ceil_div(n: u64, d: u64) -> u64 {
    n / d + u64::from(!n.is_multiple_of(d))
}

/// One tree node (eMule `CAICHHashTree`). `hash: Some(..)` is
/// `m_bHashValid + m_Hash` combined; children are created lazily.
struct Node {
    hash: Option<[u8; 20]>,
    data_size: u64,
    is_left: bool,
    base: u64,
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
}

impl Node {
    fn new(data_size: u64, is_left: bool, base: u64) -> Self {
        Node {
            hash: None,
            data_size,
            is_left,
            base,
            left: None,
            right: None,
        }
    }

    /// The split sizes of this interior node (`SHAHashSet.cpp:120-122`).
    fn split(&self) -> (u64, u64) {
        let blocks = ceil_div(self.data_size, self.base);
        let left = ((if self.is_left { blocks + 1 } else { blocks }) / 2) * self.base;
        (left, self.data_size - left)
    }

    fn ensure_left(&mut self, size: u64) -> &mut Node {
        self.left
            .get_or_insert_with(|| Box::new(Node::new(size, true, base_for(size))))
    }

    fn ensure_right(&mut self, size: u64) -> &mut Node {
        self.right
            .get_or_insert_with(|| Box::new(Node::new(size, false, base_for(size))))
    }

    /// `FindHash` (`SHAHashSet.cpp:95-149`): locate (creating children) the
    /// node covering exactly `[start, start+size)`, counting levels visited.
    fn find_mut(&mut self, start: u64, size: u64, level: &mut u8) -> Option<&mut Node> {
        *level += 1;
        if *level > MAX_LEVEL || start + size > self.data_size {
            return None;
        }
        if start == 0 && size == self.data_size {
            return Some(self);
        }
        if self.data_size <= self.base {
            return None; // already the last level
        }
        let (nleft, _nright) = self.split();
        if start < nleft {
            if start + size > nleft {
                return None;
            }
            self.ensure_left(nleft).find_mut(start, size, level)
        } else {
            let (_, nright) = self.split();
            self.ensure_right(nright)
                .find_mut(start - nleft, size, level)
        }
    }

    /// Non-creating lookup. (eMule's `FindExistingHash` const method actually
    /// calls the creating `FindHash` on its child pointers - a const-correctness
    /// slip with no wire effect; we do the honest read-only walk.)
    fn find(&self, start: u64, size: u64, level: &mut u8) -> Option<&Node> {
        *level += 1;
        if *level > MAX_LEVEL || start + size > self.data_size {
            return None;
        }
        if start == 0 && size == self.data_size {
            return Some(self);
        }
        if self.data_size <= self.base {
            return None;
        }
        let (nleft, _) = self.split();
        if start < nleft {
            if start + size > nleft {
                return None;
            }
            self.left.as_ref()?.find(start, size, level)
        } else {
            self.right.as_ref()?.find(start - nleft, size, level)
        }
    }

    /// `ReCalculateHash` (`SHAHashSet.cpp:213-233`): fill in missing interior
    /// hashes bottom-up from valid children; with `dont_replace`, keep any
    /// hash already present.
    fn recalculate(&mut self, dont_replace: bool) -> bool {
        if let (Some(l), Some(r)) = (self.left.as_mut(), self.right.as_mut()) {
            if !l.recalculate(dont_replace) || !r.recalculate(dont_replace) {
                return false;
            }
            if dont_replace && self.hash.is_some() {
                return true;
            }
            match (
                self.left.as_ref().unwrap().hash,
                self.right.as_ref().unwrap().hash,
            ) {
                (Some(lh), Some(rh)) => {
                    self.hash = Some(sha1_pair(&lh, &rh));
                    true
                }
                _ => self.hash.is_some(),
            }
        } else {
            true
        }
    }

    /// `VerifyHashTree` (`SHAHashSet.cpp:235-289`): starting from a node whose
    /// own hash is set, check each child pair against its parent, deleting any
    /// subtree that fails or is half-populated when `delete_bad`.
    fn verify(&mut self, delete_bad: bool) -> bool {
        if self.hash.is_none() {
            if delete_bad {
                self.left = None;
                self.right = None;
            }
            return false;
        }
        if let Some(l) = self.left.as_mut() {
            if l.hash.is_none() {
                l.recalculate(true);
            }
        }
        if let Some(r) = self.right.as_mut() {
            if r.hash.is_none() {
                r.recalculate(true);
            }
        }
        let left_valid = self.left.as_ref().is_some_and(|n| n.hash.is_some());
        let right_valid = self.right.as_ref().is_some_and(|n| n.hash.is_some());
        if left_valid ^ right_valid {
            // one branch can never be verified
            if delete_bad {
                self.left = None;
                self.right = None;
            }
            return false;
        }
        if left_valid && right_valid {
            let lh = self.left.as_ref().unwrap().hash.unwrap();
            let rh = self.right.as_ref().unwrap().hash.unwrap();
            if sha1_pair(&lh, &rh) != self.hash.unwrap() {
                if delete_bad {
                    self.left = None;
                    self.right = None;
                }
                return false;
            }
            self.left.as_mut().unwrap().verify(delete_bad)
                && self.right.as_mut().unwrap().verify(delete_bad)
        } else {
            // last hash in branch - nothing below to verify
            true
        }
    }

    /// `SetHash` descent (`SHAHashSet.cpp:439-494`), on a pre-decoded ident:
    /// `path` has the marker bit already shifted to bit 31 and `level` levels
    /// remaining. Unlike eMule we thread `allow_overwrite` through recursion
    /// (see the module doc) and never let a blocked overwrite desync anything.
    fn set_hash(&mut self, path: u32, level: u8, hash: [u8; 20], allow_overwrite: bool) -> bool {
        if level == 0 {
            if self.hash.is_some() && !allow_overwrite {
                // intended semantics of the 0.50a skip branch: keep ours
                return true;
            }
            self.hash = Some(hash);
            return true;
        }
        if self.data_size <= self.base {
            return false; // path goes below the last level
        }
        let (nleft, nright) = self.split();
        let path = path << 1;
        if path & 0x8000_0000 != 0 {
            self.ensure_left(nleft)
                .set_hash(path, level - 1, hash, allow_overwrite)
        } else {
            self.ensure_right(nright)
                .set_hash(path, level - 1, hash, allow_overwrite)
        }
    }

    /// `WriteHash` (`SHAHashSet.cpp:365-376`): append this node's record,
    /// its own branch bit having been folded into `ident` by the caller.
    fn write_hash(&self, out: &mut Vec<u8>, ident: u32, ident32: bool) -> bool {
        let ident = (ident << 1) | u32::from(self.is_left);
        let Some(hash) = self.hash else { return false };
        if !write_ident(out, ident, ident32) {
            return false;
        }
        out.extend_from_slice(&hash);
        true
    }

    /// `WriteLowestLevelHashs` (`SHAHashSet.cpp:379-407`): every leaf below
    /// this node, left to right, optionally with idents.
    fn write_lowest_level(
        &self,
        out: &mut Vec<u8>,
        ident: u32,
        no_ident: bool,
        ident32: bool,
    ) -> bool {
        let ident = (ident << 1) | u32::from(self.is_left);
        match (self.left.as_ref(), self.right.as_ref()) {
            (None, None) => {
                let Some(hash) = self.hash else { return false };
                if self.data_size > self.base {
                    return false; // an unexpanded interior node is not a leaf
                }
                if !no_ident && !write_ident(out, ident, ident32) {
                    return false;
                }
                out.extend_from_slice(&hash);
                true
            }
            (Some(l), Some(r)) => {
                l.write_lowest_level(out, ident, no_ident, ident32)
                    && r.write_lowest_level(out, ident, no_ident, ident32)
            }
            _ => false,
        }
    }

    /// `LoadLowestLevelHashs` (`SHAHashSet.cpp:410-435`): plant leaves from a
    /// left-to-right list (no idents), expanding the tree structurally.
    fn load_lowest_level(&mut self, leaves: &mut std::slice::Iter<'_, [u8; 20]>) -> bool {
        if self.data_size <= self.base {
            match leaves.next() {
                Some(h) => {
                    self.hash = Some(*h);
                    true
                }
                None => false,
            }
        } else {
            let (nleft, nright) = self.split();
            self.ensure_left(nleft);
            if !self.left.as_mut().unwrap().load_lowest_level(leaves) {
                return false;
            }
            self.ensure_right(nright);
            self.right.as_mut().unwrap().load_lowest_level(leaves)
        }
    }

    /// Tree half of `CreatePartRecoveryData` (`SHAHashSet.cpp:313-363`):
    /// descending toward the part, write the SIBLING hash at each level, then
    /// all block hashes of the part itself.
    fn create_part_recovery(
        &self,
        start: u64,
        size: u64,
        out: &mut Vec<u8>,
        ident: u32,
        ident32: bool,
    ) -> bool {
        if start + size > self.data_size {
            return false;
        }
        if start == 0 && size == self.data_size {
            return self.write_lowest_level(out, ident, false, ident32);
        }
        if self.data_size <= self.base {
            return false;
        }
        let ident = (ident << 1) | u32::from(self.is_left);
        let (nleft, _) = self.split();
        let (Some(l), Some(r)) = (self.left.as_ref(), self.right.as_ref()) else {
            return false;
        };
        if start < nleft {
            if start + size > nleft || r.hash.is_none() {
                return false;
            }
            r.write_hash(out, ident, ident32)
                && l.create_part_recovery(start, size, out, ident, ident32)
        } else {
            if l.hash.is_none() {
                return false;
            }
            l.write_hash(out, ident, ident32)
                && r.create_part_recovery(start - nleft, size, out, ident, ident32)
        }
    }
}

fn write_ident(out: &mut Vec<u8>, ident: u32, ident32: bool) -> bool {
    if ident32 {
        out.extend_from_slice(&ident.to_le_bytes());
        true
    } else {
        // eMule ASSERTs and truncates here (`SHAHashSet.cpp:370`); we refuse.
        if ident > 0xFFFF {
            return false;
        }
        out.extend_from_slice(&(ident as u16).to_le_bytes());
        true
    }
}

/// Decode a wire ident (`SetHash` first call, `SHAHashSet.cpp:440-453`):
/// shift the marker bit up to bit 31; the remaining level count is the number
/// of edges to descend. Returns `(path, level)`; `None` for ident 0.
fn decode_ident(ident: u32) -> Option<(u32, u8)> {
    if ident == 0 {
        return None;
    }
    let lead = ident.leading_zeros() as u8;
    Some((ident << lead, 31 - lead))
}

/// The AICH hash tree of one file (eMule `CAICHRecoveryHashSet`, minus the
/// trust status - trust is engine policy, not codec). Wraps the root node;
/// `data_size` of the root is the file size.
pub struct AichTree {
    root: Node,
}

impl AichTree {
    /// An empty tree for a file of `file_size` bytes (`SetFileSize`,
    /// `SHAHashSet.cpp:950-953`). `None` for an empty file.
    pub fn new_for_size(file_size: u64) -> Option<AichTree> {
        if file_size == 0 {
            return None;
        }
        Some(AichTree {
            root: Node::new(file_size, true, base_for(file_size)),
        })
    }

    /// An empty tree whose master root is already known and trusted
    /// (`SetMasterHash`, `SHAHashSet.cpp:926-930`) - the receiving shape for
    /// recovery data.
    pub fn with_master(file_size: u64, master: [u8; 20]) -> Option<AichTree> {
        let mut t = Self::new_for_size(file_size)?;
        t.root.hash = Some(master);
        Some(t)
    }

    /// Rebuild the full tree from the left-to-right leaf list (the
    /// known2_64.met payload): `LoadLowestLevelHashs` + `ReCalculateHash`
    /// (`LoadHashSet`, `SHAHashSet.cpp:868-894`, minus the file scan).
    /// `None` when the count does not match the file size or the rebuild fails.
    pub fn from_leaves(file_size: u64, leaves: &[[u8; 20]]) -> Option<AichTree> {
        if leaves.len() as u64 != Self::leaf_count(file_size) {
            return None;
        }
        let mut t = Self::new_for_size(file_size)?;
        let mut it = leaves.iter();
        if !t.root.load_lowest_level(&mut it) || it.next().is_some() {
            return None;
        }
        if !t.root.recalculate(false) || t.root.hash.is_none() {
            return None;
        }
        Some(t)
    }

    /// Build the complete tree from in-memory file bytes (test/small-file
    /// convenience; production streams via [`AichLeafHasher`]).
    pub fn from_file_data(data: &[u8]) -> Option<AichTree> {
        let n = data.len() as u64;
        let leaves: Vec<[u8; 20]> = leaf_spans(n)
            .map(|(start, len)| sha1(&data[start as usize..(start + len) as usize]))
            .collect();
        Self::from_leaves(n, &leaves)
    }

    pub fn file_size(&self) -> u64 {
        self.root.data_size
    }

    pub fn master_hash(&self) -> Option<[u8; 20]> {
        self.root.hash
    }

    /// Leaf-hash count for a file (the `SaveHashSet` formula,
    /// `SHAHashSet.cpp:797-799`): 53 per full part + the tail part's blocks.
    pub fn leaf_count(file_size: u64) -> u64 {
        let full = ceil_div(PARTSIZE, EMBLOCKSIZE) * (file_size / PARTSIZE);
        let tail = file_size % PARTSIZE;
        full + if tail != 0 {
            ceil_div(tail, EMBLOCKSIZE)
        } else {
            0
        }
    }

    /// All leaf hashes, left to right (the known2_64.met entry body,
    /// `WriteLowestLevelHashs` with `bNoIdent`). `None` unless complete.
    pub fn leaves(&self) -> Option<Vec<[u8; 20]>> {
        let mut out = Vec::with_capacity(Self::leaf_count(self.file_size()) as usize * HASHSIZE);
        if !self.root.write_lowest_level(&mut out, 0, true, true) {
            return None;
        }
        Some(
            out.chunks_exact(HASHSIZE)
                .map(|c| {
                    let mut h = [0u8; 20];
                    h.copy_from_slice(c);
                    h
                })
                .collect(),
        )
    }

    /// The OP_AICHANSWER recovery payload for the part at `part_start`
    /// (`CAICHRecoveryHashSet::CreatePartRecoveryData`, `SHAHashSet.cpp:595-645`):
    /// one sibling hash per level above the part, then the part's block
    /// hashes, each with its wire ident; framed as the V2 dual-count layout
    /// (16-bit idents for normal files, 32-bit past OLD_MAX_FILE_SIZE).
    /// Requires a complete tree. `None` on any inconsistency.
    pub fn create_part_recovery_data(&mut self, part_start: u64) -> Option<Vec<u8>> {
        let file_size = self.file_size();
        if file_size <= EMBLOCKSIZE
            || part_start >= file_size
            || !part_start.is_multiple_of(PARTSIZE)
        {
            return None;
        }
        let part_size = PARTSIZE.min(file_size - part_start);
        let mut level = 0u8;
        self.root.find_mut(part_start, part_size, &mut level)?;
        let hash_count = u64::from(level) - 1 + ceil_div(part_size, EMBLOCKSIZE);
        let ident32 = file_size > OLD_MAX_FILE_SIZE;
        if hash_count > u64::from(u16::MAX) {
            return None;
        }
        let mut out = Vec::new();
        if ident32 {
            out.extend_from_slice(&0u16.to_le_bytes()); // no 16-bit hashes
        }
        out.extend_from_slice(&(hash_count as u16).to_le_bytes());
        let body_start = out.len();
        if !self
            .root
            .create_part_recovery(part_start, part_size, &mut out, 0, ident32)
        {
            return None;
        }
        let rec = HASHSIZE + if ident32 { 4 } else { 2 };
        if out.len() - body_start != hash_count as usize * rec {
            return None; // eMule's length self-check (`SHAHashSet.cpp:624`)
        }
        if !ident32 {
            out.extend_from_slice(&0u16.to_le_bytes()); // no 32-bit hashes
        }
        Some(out)
    }

    /// Verify + absorb a received recovery payload for the part at
    /// `part_start` (`ReadRecoveryData`, `SHAHashSet.cpp:647-730`). The tree's
    /// master root must already be set from a TRUSTED/VERIFIED source (that
    /// gate lives in the engine). On success every EMBLOCKSIZE leaf of the
    /// part is present and verified against the root; on failure any planted
    /// hashes that do not derive from the root have been stripped.
    pub fn read_recovery_data(&mut self, part_start: u64, payload: &[u8]) -> bool {
        if self.root.hash.is_none()
            || part_start >= self.file_size()
            || !part_start.is_multiple_of(PARTSIZE)
        {
            return false;
        }
        let part_size = PARTSIZE.min(self.file_size() - part_start);
        let mut level = 0u8;
        if self
            .root
            .find_mut(part_start, part_size, &mut level)
            .is_none()
        {
            return false;
        }
        let to_read = u64::from(level) - 1 + ceil_div(part_size, EMBLOCKSIZE);

        let mut cur = payload;
        let Some(mut avail) = read_u16(&mut cur) else {
            return false;
        };
        // eMule's dual length/count guard (`SHAHashSet.cpp:669`)
        if (cur.len() as u64) < to_read * (HASHSIZE as u64 + 2)
            || (u64::from(avail) != to_read && avail != 0)
        {
            return false;
        }
        for _ in 0..avail {
            let Some(ident) = read_u16(&mut cur) else {
                return false;
            };
            if !self.plant(u32::from(ident), &mut cur) {
                self.root.verify(true); // strip what was already written
                return false;
            }
        }

        // 32-bit ident section (`SHAHashSet.cpp:687-706`)
        if avail == 0 && cur.len() >= 2 {
            avail = read_u16(&mut cur).unwrap();
            if (cur.len() as u64) < to_read * (HASHSIZE as u64 + 4)
                || (u64::from(avail) != to_read && avail != 0)
            {
                return false;
            }
            // eMule iterates to_read here, not avail (`SHAHashSet.cpp:695`);
            // the guard above forces them equal unless avail == 0, which the
            // "no hashes" check below rejects - iterate to_read faithfully.
            if avail != 0 {
                for _ in 0..to_read {
                    let Some(ident) = read_u32(&mut cur) else {
                        return false;
                    };
                    if ident > 0x40_0000 || !self.plant(ident, &mut cur) {
                        self.root.verify(true);
                        return false;
                    }
                }
            }
        }
        if avail == 0 {
            return false; // packet contained no hashes
        }

        if !self.root.verify(true) {
            return false;
        }
        // completeness sweep of the part's lowest-level hashes
        // (`SHAHashSet.cpp:716-722`)
        let mut pos = 0u64;
        while pos < part_size {
            let len = EMBLOCKSIZE.min(part_size - pos);
            let mut lvl = 0u8;
            match self.root.find(part_start + pos, len, &mut lvl) {
                Some(n) if n.hash.is_some() => {}
                _ => return false,
            }
            pos += EMBLOCKSIZE;
        }
        true
    }

    /// One record: reject the master ident, then plant hash bytes from `cur`.
    fn plant(&mut self, ident: u32, cur: &mut &[u8]) -> bool {
        if ident == 1 {
            return false; // never allow the masterhash to be overwritten
        }
        let Some((path, lvl)) = decode_ident(ident) else {
            return false;
        };
        if cur.len() < HASHSIZE {
            return false;
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&cur[..HASHSIZE]);
        *cur = &cur[HASHSIZE..];
        // the marker bit itself addresses the root; descend past it
        self.root.set_hash(path, lvl, hash, false)
    }

    /// The verified block hashes of the part at `part_start` as
    /// `(absolute_start, len, hash)`, for comparing against locally hashed
    /// disk blocks (`AICHRecoveryDataAvailable`, eMule `PartFile.cpp:6179-6199`).
    /// `None` unless every block hash of that part is present.
    pub fn part_block_hashes(&self, part_start: u64) -> Option<Vec<(u64, u64, [u8; 20])>> {
        if part_start >= self.file_size() || !part_start.is_multiple_of(PARTSIZE) {
            return None;
        }
        let part_size = PARTSIZE.min(self.file_size() - part_start);
        let mut out = Vec::new();
        let mut pos = 0u64;
        while pos < part_size {
            let len = EMBLOCKSIZE.min(part_size - pos);
            let mut lvl = 0u8;
            let node = self.root.find(part_start + pos, len, &mut lvl)?;
            out.push((part_start + pos, len, node.hash?));
            pos += EMBLOCKSIZE;
        }
        Some(out)
    }
}

fn read_u16(cur: &mut &[u8]) -> Option<u16> {
    if cur.len() < 2 {
        return None;
    }
    let v = u16::from_le_bytes([cur[0], cur[1]]);
    *cur = &cur[2..];
    Some(v)
}

fn read_u32(cur: &mut &[u8]) -> Option<u32> {
    if cur.len() < 4 {
        return None;
    }
    let v = u32::from_le_bytes([cur[0], cur[1], cur[2], cur[3]]);
    *cur = &cur[4..];
    Some(v)
}

/// The AICH leaf lattice of a file: `(start, len)` of every EMBLOCKSIZE block,
/// in file order - blocks restart at each PARTSIZE boundary, so each part ends
/// with a short block (`SHAHashSet.h:42` diagram).
pub fn leaf_spans(file_size: u64) -> impl Iterator<Item = (u64, u64)> {
    let mut part_start = 0u64;
    let mut off = 0u64;
    std::iter::from_fn(move || {
        if part_start >= file_size {
            return None;
        }
        let part_len = PARTSIZE.min(file_size - part_start);
        let len = EMBLOCKSIZE.min(part_len - off);
        let span = (part_start + off, len);
        off += EMBLOCKSIZE;
        if off >= part_len {
            part_start += PARTSIZE;
            off = 0;
        }
        Some(span)
    })
}

/// Streaming AICH leaf hasher: feed the file's bytes in order (any chunking),
/// get the complete [`AichTree`] - so the engine computes AICH in the same
/// disk pass as the eD2k hash instead of holding the file in memory (eMule
/// hashes both in one pass too, `KnownFile.cpp:1053-1137`).
pub struct AichLeafHasher {
    file_size: u64,
    pos: u64,
    cur: Sha1,
    leaves: Vec<[u8; 20]>,
}

impl AichLeafHasher {
    /// `None` for an empty file.
    pub fn new(file_size: u64) -> Option<AichLeafHasher> {
        if file_size == 0 {
            return None;
        }
        Some(AichLeafHasher {
            file_size,
            pos: 0,
            cur: Sha1::new(),
            leaves: Vec::with_capacity(AichTree::leaf_count(file_size) as usize),
        })
    }

    /// The end offset of the leaf containing `pos`.
    fn leaf_end(&self) -> u64 {
        let part_start = self.pos - self.pos % PARTSIZE;
        let part_len = PARTSIZE.min(self.file_size - part_start);
        let block = (self.pos - part_start) / EMBLOCKSIZE;
        part_start + part_len.min((block + 1) * EMBLOCKSIZE)
    }

    /// Feed the next `data` bytes; returns false if fed past `file_size`.
    pub fn update(&mut self, mut data: &[u8]) -> bool {
        if self.pos + data.len() as u64 > self.file_size {
            return false;
        }
        while !data.is_empty() {
            let end = self.leaf_end();
            let take = ((end - self.pos) as usize).min(data.len());
            self.cur.update(&data[..take]);
            self.pos += take as u64;
            data = &data[take..];
            if self.pos == end {
                self.leaves.push(
                    std::mem::replace(&mut self.cur, Sha1::new())
                        .finalize()
                        .into(),
                );
            }
        }
        true
    }

    /// The completed tree; `None` unless exactly `file_size` bytes were fed.
    pub fn finish(self) -> Option<AichTree> {
        if self.pos != self.file_size {
            return None;
        }
        AichTree::from_leaves(self.file_size, &self.leaves)
    }
}

/// The AICH master hash (20-byte SHA-1 tree root) of a file's bytes. Returns
/// `None` for an empty file or one past the eD2k size ceiling.
pub fn aich_master_hash(data: &[u8]) -> Option<[u8; 20]> {
    let n = data.len() as u64;
    if n == 0 || n > OLD_MAX_FILE_SIZE {
        return None;
    }
    AichTree::from_file_data(data)?.master_hash()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ORIGINAL Wave-1c one-shot recursive fold, kept as an independent
    /// reference implementation: `from_leaves` + `recalculate` must agree with
    /// it for every shape (it was itself byte-validated vs real amuled).
    fn tree_hash_reference(data: &[u8], is_left: bool, base: u64) -> [u8; 20] {
        let n = data.len() as u64;
        if n <= base {
            return sha1(data);
        }
        let blocks = n / base + u64::from(!n.is_multiple_of(base));
        let left = ((if is_left { blocks + 1 } else { blocks }) / 2) * base;
        let (l, r) = data.split_at(left as usize);
        let lh = tree_hash_reference(l, true, base_for(left));
        let rh = tree_hash_reference(r, false, base_for(n - left));
        sha1_pair(&lh, &rh)
    }

    fn ref_master(data: &[u8]) -> [u8; 20] {
        tree_hash_reference(data, true, base_for(data.len() as u64))
    }

    fn patterned(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i.wrapping_mul(31) >> 3) as u8).collect()
    }

    #[test]
    fn small_file_master_is_sha1_of_the_whole_file() {
        // <= EMBLOCKSIZE -> the root is a single leaf, so master == SHA1(file).
        let data = vec![0xABu8; 1000];
        assert_eq!(aich_master_hash(&data).unwrap(), sha1(&data));
    }

    #[test]
    fn exactly_one_block_is_a_leaf() {
        let data = vec![7u8; EMBLOCKSIZE as usize];
        assert_eq!(aich_master_hash(&data).unwrap(), sha1(&data));
    }

    #[test]
    fn two_block_file_combines_two_leaf_hashes() {
        // EMBLOCKSIZE < n <= 2*EMBLOCKSIZE: root base EMBLOCKSIZE, blocks=2,
        // left branch -> left = (3/2)*B = B, right = n-B. Master = SHA1(H0||H1).
        let n = EMBLOCKSIZE as usize + 500;
        let data: Vec<u8> = (0..n).map(|i| (i * 31) as u8).collect();
        let h0 = sha1(&data[..EMBLOCKSIZE as usize]);
        let h1 = sha1(&data[EMBLOCKSIZE as usize..]);
        assert_eq!(aich_master_hash(&data).unwrap(), sha1_pair(&h0, &h1));
    }

    #[test]
    fn tree_master_matches_reference_fold_across_shapes() {
        // one leaf / odd splits / exact block multiple / exact part multiple /
        // multi-part with tail - every branch parity the split rule has.
        for n in [
            1usize,
            1000,
            EMBLOCKSIZE as usize,
            EMBLOCKSIZE as usize + 1,
            3 * EMBLOCKSIZE as usize + 7,
            PARTSIZE as usize,
            PARTSIZE as usize + 1,
            PARTSIZE as usize + EMBLOCKSIZE as usize + 123,
            2 * PARTSIZE as usize,
            2 * PARTSIZE as usize + 5 * EMBLOCKSIZE as usize + 999,
        ] {
            let data = patterned(n);
            assert_eq!(
                AichTree::from_file_data(&data)
                    .unwrap()
                    .master_hash()
                    .unwrap(),
                ref_master(&data),
                "size {n}"
            );
        }
    }

    #[test]
    fn streaming_hasher_matches_from_file_data_for_any_chunking() {
        let data = patterned(PARTSIZE as usize + 2 * EMBLOCKSIZE as usize + 4321);
        let expect = AichTree::from_file_data(&data)
            .unwrap()
            .master_hash()
            .unwrap();
        for chunk in [1usize, 7, 4096, EMBLOCKSIZE as usize, data.len()] {
            let mut h = AichLeafHasher::new(data.len() as u64).unwrap();
            for c in data.chunks(chunk) {
                assert!(h.update(c));
            }
            assert_eq!(
                h.finish().unwrap().master_hash().unwrap(),
                expect,
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn leaf_count_matches_leaf_spans() {
        for n in [
            1u64,
            EMBLOCKSIZE,
            EMBLOCKSIZE + 1,
            PARTSIZE - 1,
            PARTSIZE,
            PARTSIZE + 1,
            2 * PARTSIZE,
            2 * PARTSIZE + EMBLOCKSIZE + 3,
            10_000_000,
        ] {
            assert_eq!(
                AichTree::leaf_count(n),
                leaf_spans(n).count() as u64,
                "size {n}"
            );
            let total: u64 = leaf_spans(n).map(|(_, len)| len).sum();
            assert_eq!(total, n, "spans must cover the file, size {n}");
        }
        // 10 MB: the golden fixture's documented 55 blocks
        assert_eq!(AichTree::leaf_count(10_000_000), 55);
        // one full part is 53 blocks (52 full + one 140KB tail)
        assert_eq!(AichTree::leaf_count(PARTSIZE), 53);
    }

    #[test]
    fn from_leaves_roundtrips_leaves() {
        let data = patterned(PARTSIZE as usize + 3 * EMBLOCKSIZE as usize + 17);
        let t = AichTree::from_file_data(&data).unwrap();
        let leaves = t.leaves().unwrap();
        let t2 = AichTree::from_leaves(data.len() as u64, &leaves).unwrap();
        assert_eq!(t2.master_hash(), t.master_hash());
        assert_eq!(t2.leaves().unwrap(), leaves);
        // wrong count refused
        assert!(AichTree::from_leaves(data.len() as u64, &leaves[1..]).is_none());
    }

    #[test]
    fn recovery_data_roundtrip_repairs_receiver_tree() {
        // serve side: full tree; download side: only the trusted master root.
        let size = 2 * PARTSIZE as usize + 3 * EMBLOCKSIZE as usize + 4242;
        let data = patterned(size);
        let mut full = AichTree::from_file_data(&data).unwrap();
        let master = full.master_hash().unwrap();
        for part in 0..3u64 {
            let part_start = part * PARTSIZE;
            let payload = full.create_part_recovery_data(part_start).unwrap();
            let mut rx = AichTree::with_master(size as u64, master).unwrap();
            assert!(
                rx.read_recovery_data(part_start, &payload),
                "part {part} must verify"
            );
            // the receiver now holds exactly the part's block hashes
            let got = rx.part_block_hashes(part_start).unwrap();
            let want = full.part_block_hashes(part_start).unwrap();
            assert_eq!(got, want, "part {part}");
        }
    }

    #[test]
    fn recovery_data_wire_layout_is_emule_v2() {
        // normal file: <count16 u16><records><u16 0>; record = <ident u16><20B>
        let size = PARTSIZE as usize + EMBLOCKSIZE as usize + 100;
        let data = patterned(size);
        let mut full = AichTree::from_file_data(&data).unwrap();
        let payload = full.create_part_recovery_data(0).unwrap();
        let count = u16::from_le_bytes([payload[0], payload[1]]) as usize;
        // part 0 of a 2-part file: 1 sibling + 53 blocks
        assert_eq!(count, 54);
        assert_eq!(payload.len(), 2 + count * 22 + 2);
        assert_eq!(
            &payload[payload.len() - 2..],
            &[0, 0],
            "trailing 32-bit count 0"
        );
        // first record is the SIBLING (the other part's subtree root):
        // root ident 1 -> its right child = 0b10 = 2
        let first_ident = u16::from_le_bytes([payload[2], payload[3]]);
        assert_eq!(first_ident, 2);
    }

    #[test]
    fn recovery_data_rejects_master_ident_and_tampering() {
        let size = PARTSIZE as usize + EMBLOCKSIZE as usize + 100;
        let data = patterned(size);
        let mut full = AichTree::from_file_data(&data).unwrap();
        let master = full.master_hash().unwrap();
        let good = full.create_part_recovery_data(0).unwrap();

        // ident 1 (the master) smuggled into a record is refused
        let mut evil = good.clone();
        evil[2] = 1;
        evil[3] = 0;
        let mut rx = AichTree::with_master(size as u64, master).unwrap();
        assert!(!rx.read_recovery_data(0, &evil));

        // a flipped hash byte cannot survive the root verification
        let mut tampered = good.clone();
        let last = tampered.len() - 3;
        tampered[last] ^= 0xFF;
        let mut rx = AichTree::with_master(size as u64, master).unwrap();
        assert!(!rx.read_recovery_data(0, &tampered));

        // truncated payload is refused
        let mut rx = AichTree::with_master(size as u64, master).unwrap();
        assert!(!rx.read_recovery_data(0, &good[..good.len() / 2]));

        // empty payload ("no hashes") is refused
        let mut rx = AichTree::with_master(size as u64, master).unwrap();
        assert!(!rx.read_recovery_data(0, &[0, 0, 0, 0]));

        // and the honest payload still passes after all that
        let mut rx = AichTree::with_master(size as u64, master).unwrap();
        assert!(rx.read_recovery_data(0, &good));
    }

    #[test]
    fn recovery_data_against_wrong_master_fails() {
        let size = PARTSIZE as usize + EMBLOCKSIZE as usize + 100;
        let data = patterned(size);
        let mut full = AichTree::from_file_data(&data).unwrap();
        let payload = full.create_part_recovery_data(0).unwrap();
        let mut rx = AichTree::with_master(size as u64, [0xEE; 20]).unwrap();
        assert!(
            !rx.read_recovery_data(0, &payload),
            "recovery data must not verify against a different root"
        );
    }

    #[test]
    fn single_part_file_recovery_covers_whole_file() {
        // file <= PARTSIZE: the part node IS the root; recovery = all blocks,
        // zero siblings.
        let size = 3 * EMBLOCKSIZE as usize + 55;
        let data = patterned(size);
        let mut full = AichTree::from_file_data(&data).unwrap();
        let master = full.master_hash().unwrap();
        let payload = full.create_part_recovery_data(0).unwrap();
        let count = u16::from_le_bytes([payload[0], payload[1]]) as u64;
        assert_eq!(count, 4, "0 siblings + 4 blocks");
        let mut rx = AichTree::with_master(size as u64, master).unwrap();
        assert!(rx.read_recovery_data(0, &payload));
    }

    #[test]
    fn empty_and_oversize_are_none() {
        assert!(aich_master_hash(&[]).is_none());
        assert!(AichTree::new_for_size(0).is_none());
        assert!(AichLeafHasher::new(0).is_none());
    }

    /// Byte-validation against the REAL amuled AICH, not a self-consistent
    /// reconstruction (the [[interop-test-fidelity]] lesson: a reference that is
    /// wrong the SAME way gives false confidence). A deterministic 10 MB file -
    /// over PARTSIZE (9,728,000), so the MULTI-PART tree branch is exercised, and
    /// exactly ceil(10_000_000 / 184320) = 55 AICH blocks - hashed by amuled 3.0.1
    /// yields this master root, read from its `known2_64.met` AICH hashset backup
    /// (`version(1) | root(20) | count(u32) | count*hash(20)`). Regenerate with
    /// `scripts/aich-golden.sh`. The file bytes follow a fixed LCG so we rebuild
    /// them here byte-for-byte (i < 2^34, so the product never overflows u64).
    #[test]
    fn aich_master_matches_real_amuled_for_a_multipart_file() {
        let n = 10_000_000usize;
        let mut data = vec![0u8; n];
        for (i, b) in data.iter_mut().enumerate() {
            *b = ((i as u64).wrapping_mul(1_103_515_245).wrapping_add(12_345) >> 16) as u8;
        }
        let golden: [u8; 20] = [
            0xbc, 0x30, 0x1c, 0x26, 0xff, 0x3c, 0xc6, 0xd9, 0x8e, 0x80, 0x49, 0x01, 0x60, 0x3a,
            0x0a, 0x32, 0x88, 0x35, 0x11, 0x00,
        ];
        assert_eq!(
            aich_master_hash(&data).unwrap(),
            golden,
            "padMule AICH master must match real amuled"
        );
    }
}
