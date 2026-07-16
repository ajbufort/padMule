//! eD2k/MD4 file hashing. See docs/wiki/protocol-reference.md.

use md4::{Digest, Md4};

/// Raw MD4 digest of `data`.
pub fn md4(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md4::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// eD2k part size in bytes (aMule PARTSIZE).
pub const PARTSIZE: u64 = 9_728_000;

/// The largest file the OLD 32-bit eD2k protocol could address. A file STRICTLY
/// larger than this is a "large file" (`IsLargeFile()` upstream, Constants.h:77
/// OLD_MAX_FILE_SIZE) and must use the 64-bit-size wire and .met encodings.
///
/// Note this is 4,290,048,000 - a good 4.9 million bytes BELOW `u32::MAX`
/// (4,294,967,295). Using `u32::MAX` as the boundary would mis-encode files in
/// that band, so the two must not be confused.
pub const OLD_MAX_FILE_SIZE: u64 = 4_290_048_000;

/// eD2k part count for a file of `size` bytes: floor(size/PARTSIZE) + 1.
///
/// This is aMule's `m_iED2KPartCount` (used in OP_FILESTATUS and the part-status
/// bitfield) and also the number of MD4 part hashes `ed2k_hash` combines,
/// because an exact-multiple file carries a trailing empty (sentinel) part.
/// It is NOT the data-part count (`m_iPartCount = ceil(size/PARTSIZE)`), which
/// is one smaller for exact multiples. Do not confuse the two in the engine.
///
/// Degenerate case: this returns 1 for `size == 0`, which is what `ed2k_hash`
/// needs (an empty file hashes to `md4(b"")`). aMule instead special-cases a
/// 0-byte file to `m_iED2KPartCount == 0` (KnownFile.cpp SetFileSize), but it
/// never shares or hashes 0-byte files, so no OP_FILESTATUS is ever emitted for
/// one. If the engine reuses this for the OP_FILESTATUS/part-status count, it
/// must special-case `size == 0` to 0 there.
pub fn part_count(size: u64) -> u64 {
    size / PARTSIZE + 1
}

/// eD2k file hash of an in-memory file `data`, per the aMule rule.
///
/// - Split into PARTSIZE-byte parts; if `data.len()` is an exact multiple of
///   PARTSIZE (including 0), a trailing empty part is appended, so part count
///   is always floor(len/PARTSIZE)+1.
/// - Each part is MD4-hashed.
/// - If there is exactly one part, the file hash is that part's MD4.
/// - Otherwise the file hash is MD4 of the concatenated 16-byte part hashes.
pub fn ed2k_hash(data: &[u8]) -> [u8; 16] {
    let n = part_count(data.len() as u64) as usize;
    if n == 1 {
        return md4(data);
    }
    let mut concat = Vec::with_capacity(n * 16);
    for i in 0..n {
        let start = i * PARTSIZE as usize;
        let end = core::cmp::min(start + PARTSIZE as usize, data.len());
        // For the trailing empty part on an exact multiple, start == end == len.
        concat.extend_from_slice(&md4(&data[start..end]));
    }
    md4(&concat)
}

/// eD2k file hash of a file supplied one part at a time, so a large file is
/// never held in memory whole. Same rule as [`ed2k_hash`] - and pinned to it by
/// test for every awkward size - but the caller streams the parts in.
///
/// `read_part(i)` must return DATA part `i` (`PARTSIZE` bytes, short on the
/// last). It is NEVER called for the trailing empty sentinel part that an
/// exact-multiple file carries: that part has no data to read, and asking a
/// `PartStore` for it would be an out-of-range read. This is the
/// `part_count`-vs-`data_part_count` landmine from `part_count`'s docs, handled
/// here once so callers cannot get it wrong.
pub fn ed2k_hash_parts<E>(
    size: u64,
    mut read_part: impl FnMut(u64) -> Result<Vec<u8>, E>,
) -> Result<[u8; 16], E> {
    let n = part_count(size);
    // One part: the file hash IS that part's MD4. `size == 0` lands here too,
    // and reads nothing - md4(b"") is exactly right.
    if n == 1 {
        let data = if size == 0 { Vec::new() } else { read_part(0)? };
        return Ok(md4(&data));
    }
    let mut concat = Vec::with_capacity(n as usize * 16);
    for i in 0..n {
        // The sentinel part exists only when size is an exact multiple, and it
        // is always the last one. It has no bytes on disk.
        let start = i * PARTSIZE;
        let data = if start >= size {
            Vec::new()
        } else {
            read_part(i)?
        };
        concat.extend_from_slice(&md4(&data));
    }
    Ok(md4(&concat))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1320 MD4 test vectors.
    #[test]
    fn md4_rfc1320_vectors() {
        assert_eq!(hex::encode(md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        assert_eq!(hex::encode(md4(b"a")), "bde52cb31de33e46245e05fbdbd6fb24");
        assert_eq!(hex::encode(md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
        assert_eq!(
            hex::encode(md4(b"message digest")),
            "d9130a8164549fe818874806e1c7014b"
        );
    }

    #[test]
    fn part_count_rule() {
        // aMule: part count = floor(size / PARTSIZE) + 1. An exact multiple
        // gets a trailing (empty) part. See protocol-reference.md.
        assert_eq!(part_count(0), 1);
        assert_eq!(part_count(1), 1);
        assert_eq!(part_count(PARTSIZE - 1), 1);
        assert_eq!(part_count(PARTSIZE), 2);
        assert_eq!(part_count(PARTSIZE + 1), 2);
        assert_eq!(part_count(2 * PARTSIZE), 3);
        assert_eq!(part_count(2 * PARTSIZE + 1), 3);
    }

    #[test]
    fn partsize_value() {
        assert_eq!(PARTSIZE, 9_728_000);
    }

    #[test]
    fn ed2k_empty_file_is_md4_empty() {
        // One (empty) part -> hash is that part's MD4 directly.
        assert_eq!(
            hex::encode(ed2k_hash(b"")),
            "31d6cfe0d16ae931b73c59d7e0c089c0"
        );
    }

    #[test]
    fn ed2k_single_part_is_md4_of_contents() {
        // Sub-PARTSIZE file: single part, file hash IS the part MD4.
        let data = b"abc";
        assert_eq!(ed2k_hash(data), md4(data));
        assert_eq!(
            hex::encode(ed2k_hash(data)),
            "a448017aaf21d8525fc10ae87aa6729d"
        );
    }

    #[test]
    fn ed2k_two_parts_hashes_concat_of_part_hashes() {
        // Slightly over one part -> 2 parts: [PARTSIZE bytes][remainder].
        // Expected = MD4( MD4(part0) || MD4(part1) ), built from the
        // RFC-verified md4() primitive.
        let mut data = vec![0xABu8; PARTSIZE as usize];
        data.extend_from_slice(b"tail");
        let part0 = md4(&data[..PARTSIZE as usize]);
        let part1 = md4(&data[PARTSIZE as usize..]);
        let mut concat = Vec::new();
        concat.extend_from_slice(&part0);
        concat.extend_from_slice(&part1);
        let expected = md4(&concat);
        assert_eq!(ed2k_hash(&data), expected);
    }

    #[test]
    fn ed2k_exact_multiple_appends_empty_trailing_part() {
        // Exactly PARTSIZE bytes -> 2 parts: [PARTSIZE bytes][empty].
        // aMule includes the trailing empty part's MD4 in the combination.
        let data = vec![0xCDu8; PARTSIZE as usize];
        let part0 = md4(&data);
        let part1 = md4(b""); // trailing empty part
        let mut concat = Vec::new();
        concat.extend_from_slice(&part0);
        concat.extend_from_slice(&part1);
        let expected = md4(&concat);
        assert_eq!(ed2k_hash(&data), expected);
        // And it must NOT equal the naive single-part MD4 of the whole file.
        assert_ne!(ed2k_hash(&data), md4(&data));
    }

    /// The streaming hash must agree with the in-memory one at EVERY awkward
    /// size - especially the exact multiples, where a trailing empty sentinel
    /// part changes the answer and there is no such part to read from disk.
    #[test]
    fn streaming_hash_matches_the_in_memory_hash_at_every_boundary() {
        let ps = PARTSIZE;
        for size in [
            0u64,
            1,
            1000,
            ps - 1,
            ps, // exact multiple: sentinel part appears
            ps + 1,
            2 * ps, // exact multiple again
            2 * ps + 1,
        ] {
            // Cheap deterministic filler; content does not matter, length does.
            let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
            let streamed = ed2k_hash_parts(size, |i| {
                let start = (i * ps) as usize;
                let end = core::cmp::min(start + ps as usize, data.len());
                Ok::<_, ()>(data[start..end].to_vec())
            })
            .unwrap();
            assert_eq!(
                streamed,
                ed2k_hash(&data),
                "streaming != in-memory at size {size}"
            );
        }
    }

    /// The sentinel part must never be read from disk - a PartStore has no such
    /// part and would error. Pin that we only ask for real data parts.
    #[test]
    fn streaming_hash_never_reads_the_sentinel_part() {
        let size = 2 * PARTSIZE; // exact multiple -> 3 hash parts, 2 data parts
        assert_eq!(part_count(size), 3);
        let mut asked = Vec::new();
        let _ = ed2k_hash_parts(size, |i| {
            asked.push(i);
            Ok::<_, ()>(vec![0u8; PARTSIZE as usize])
        })
        .unwrap();
        assert_eq!(asked, vec![0, 1], "only the two DATA parts were read");
    }
}
