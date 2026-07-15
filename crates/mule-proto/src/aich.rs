//! AICH - the eD2k "Advanced Intelligent Corruption Handling" SHA-1 hash tree
//! (Wave 1c). A file's AICH *master hash* is the root of a binary tree of SHA-1
//! hashes: each leaf is `SHA1` of one 184320-byte block (EMBLOCKSIZE), each
//! internal node is `SHA1(leftHash || rightHash)`. It lets a downloader verify
//! and re-fetch a single corrupt block instead of a whole 9.28 MB part.
//!
//! The tree shape is transcribed verbatim from aMule `SHAHashSet.cpp`
//! (`CAICHHashTree` ctor + recursive split, `CAICHHashSet::SetFileSize`). The
//! root is a left branch covering the whole file, with base size EMBLOCKSIZE
//! when the file is `<= PARTSIZE` else PARTSIZE. A node covering `n` bytes with
//! base `b` is a LEAF (`SHA1` of its `n` data bytes) when `n <= b`; otherwise it
//! splits into `blocks = ceil(n/b)`, `left = ((isLeft ? blocks+1 : blocks) / 2)
//! * b`, `right = n - left`, each child's base being EMBLOCKSIZE when its size
//! is `<= PARTSIZE` else PARTSIZE, and hashes to `SHA1(leftHash || rightHash)`.

use crate::hash::{OLD_MAX_FILE_SIZE, PARTSIZE};
use sha1::{Digest, Sha1};

/// AICH leaf block size (eMule `EMBLOCKSIZE`).
pub const EMBLOCKSIZE: u64 = 184_320;

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

fn base_for(size: u64) -> u64 {
    if size <= PARTSIZE {
        EMBLOCKSIZE
    } else {
        PARTSIZE
    }
}

/// Hash one subtree covering `data` (`is_left` = a left branch, `base` = this
/// node's base size).
fn tree_hash(data: &[u8], is_left: bool, base: u64) -> [u8; 20] {
    let n = data.len() as u64;
    if n <= base {
        return sha1(data); // leaf
    }
    let blocks = n / base + u64::from(!n.is_multiple_of(base));
    let left = ((if is_left { blocks + 1 } else { blocks }) / 2) * base;
    let (l, r) = data.split_at(left as usize);
    let lh = tree_hash(l, true, base_for(left));
    let rh = tree_hash(r, false, base_for(n - left));
    let mut combined = [0u8; 40];
    combined[..20].copy_from_slice(&lh);
    combined[20..].copy_from_slice(&rh);
    sha1(&combined)
}

/// The AICH master hash (20-byte SHA-1 tree root) of a file's bytes. Returns
/// `None` for an empty file or one past the eD2k size ceiling.
pub fn aich_master_hash(data: &[u8]) -> Option<[u8; 20]> {
    let n = data.len() as u64;
    if n == 0 || n > OLD_MAX_FILE_SIZE {
        return None;
    }
    Some(tree_hash(data, true, base_for(n)))
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut combined = [0u8; 40];
        combined[..20].copy_from_slice(&h0);
        combined[20..].copy_from_slice(&h1);
        assert_eq!(aich_master_hash(&data).unwrap(), sha1(&combined));
    }

    #[test]
    fn three_block_file_is_deterministic_and_differs_from_two() {
        let two: Vec<u8> = (0..(EMBLOCKSIZE as usize + 10)).map(|i| i as u8).collect();
        let three: Vec<u8> = (0..(2 * EMBLOCKSIZE as usize + 10))
            .map(|i| i as u8)
            .collect();
        let a = aich_master_hash(&three).unwrap();
        assert_eq!(a, aich_master_hash(&three).unwrap(), "deterministic");
        assert_ne!(a, aich_master_hash(&two).unwrap());
    }

    #[test]
    fn empty_and_oversize_are_none() {
        assert!(aich_master_hash(&[]).is_none());
    }
}
