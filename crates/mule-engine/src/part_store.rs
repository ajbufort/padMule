//! The `.part` file on disk: sparse data file plus its `.part.met` sidecar.
//!
//! Naming follows upstream: `NNN.part` holds the bytes, `NNN.part.met` holds the
//! hash, the gap list, and the corrupted-part list. A read-then-write of the met
//! is byte-compatible (`mule_files::part_met`), so an aMule install can pick up a
//! padMule download and vice versa.
//!
//! # Durability: we deliberately invert upstream's write order
//!
//! aMule calls `FillGap` the moment bytes land in its write BUFFER - before they
//! reach disk. A crash between the two loses data the gap list already claims we
//! have, and the file then fails its hash check for no visible reason. eMule
//! papers over this by persisting still-buffered ranges as extra gaps.
//!
//! padMule writes to disk and syncs BEFORE closing the gap, so the gap list can
//! never claim more than the disk actually holds. The failure mode becomes
//! re-downloading a block we already had (harmless) instead of silently
//! corrupting a part (not harmless). This matters more here than on a desktop:
//! iPadOS can suspend and kill us mid-write at any moment.
//!
//! I/O here is blocking. The driver calls it under a lock; an iOS build should
//! wrap these in `spawn_blocking`.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use mule_files::part_met::{
    gap_tags, gaps as met_gaps, read_part_met, write_part_met, PartMet, PARTFILE_VERSION,
    PARTFILE_VERSION_LARGEFILE,
};
use mule_proto::{Tag, TagValue, OLD_MAX_FILE_SIZE, PARTSIZE};

use crate::part_file::{part_size, PartFile};

/// Tag ids used in part.met beyond the gap pair.
pub const FT_FILENAME: u8 = 0x01;
pub const FT_FILESIZE: u8 = 0x02;
/// Comma-separated decimal part numbers that failed verification.
pub const FT_CORRUPTEDPARTS: u8 = 0x24;

/// A download backed by a real `.part` file.
pub struct PartStore {
    part_path: PathBuf,
    met_path: PathBuf,
    file: File,
    pub pf: PartFile,
    pub name: Vec<u8>,
}

impl PartStore {
    /// Start a new download as `NNN.part` in `dir`.
    ///
    /// The data file is created sparse at full length, so block writes can land
    /// at any offset without the file having to grow in order.
    pub fn create(
        dir: &Path,
        index: u32,
        hash: [u8; 16],
        size: u64,
        name: &[u8],
    ) -> io::Result<Self> {
        let (part_path, met_path) = paths(dir, index);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&part_path)?;
        file.set_len(size)?;
        let mut s = PartStore {
            part_path,
            met_path,
            file,
            pf: PartFile::new(hash, size),
            name: name.to_vec(),
        };
        s.save_met()?;
        Ok(s)
    }

    /// Resume `NNN.part` from its `.part.met`.
    pub fn open(dir: &Path, index: u32) -> io::Result<Self> {
        let (part_path, met_path) = paths(dir, index);
        let met = read_part_met(&fs::read(&met_path)?)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?;

        let size = met
            .tags
            .iter()
            .find(|t| t.name == mule_proto::TagName::Id(FT_FILESIZE))
            .and_then(|t| match &t.value {
                TagValue::U32(v) => Some(*v as u64),
                TagValue::U64(v) => Some(*v),
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "part.met has no filesize")
            })?;

        let name = met
            .tags
            .iter()
            .find(|t| t.name == mule_proto::TagName::Id(FT_FILENAME))
            .and_then(|t| match &t.value {
                TagValue::Str(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_default();

        let corrupted = met
            .tags
            .iter()
            .find(|t| t.name == mule_proto::TagName::Id(FT_CORRUPTEDPARTS))
            .and_then(|t| match &t.value {
                TagValue::Str(s) => Some(parse_corrupted(s)),
                _ => None,
            })
            .unwrap_or_default();

        let mut pf = PartFile::resume(met.file_hash, size, met_gaps(&met), corrupted);
        pf.part_hashes = met.part_hashes.clone();

        let file = OpenOptions::new().read(true).write(true).open(&part_path)?;
        Ok(PartStore {
            part_path,
            met_path,
            file,
            pf,
            name,
        })
    }

    /// Write a received block, then close its gap.
    ///
    /// The order is the point: the bytes are on disk and synced before the gap
    /// list stops asking for them. See the module docs.
    pub fn write_block(&mut self, start: u64, data: &[u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let end = start + data.len() as u64;
        if end > self.pf.size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "block runs past the end of the file",
            ));
        }
        self.file.seek(SeekFrom::Start(start))?;
        self.file.write_all(data)?;
        self.file.sync_data()?;
        self.pf.fill_gap(start, end);
        Ok(())
    }

    /// Read a whole part back off disk (for verification).
    pub fn read_part(&mut self, part: u64) -> io::Result<Vec<u8>> {
        let start = part * PARTSIZE;
        let len = part_size(part, self.pf.size) as usize;
        let mut buf = vec![0u8; len];
        self.file.seek(SeekFrom::Start(start))?;
        self.file.read_exact(&mut buf)?;
        Ok(buf)
    }

    /// Verify a completed part against the hashset, re-opening it if it is bad.
    ///
    /// Returns `Some(true)` if it verified, `Some(false)` if it was corrupt (and
    /// has been re-gapped for re-download), or `None` if we cannot tell yet
    /// because the hashset has not arrived.
    pub fn verify_part(&mut self, part: u64) -> io::Result<Option<bool>> {
        let data = self.read_part(part)?;
        match self.pf.verify_part(part, &data) {
            Some(true) => {
                self.pf.clear_corrupt(part);
                Ok(Some(true))
            }
            Some(false) => {
                self.pf.mark_corrupt(part);
                Ok(Some(false))
            }
            None => Ok(None),
        }
    }

    /// Persist the gap list and corrupted-part list.
    ///
    /// Written to a temp file and renamed, so an interrupted save cannot leave a
    /// half-written met behind.
    pub fn save_met(&mut self) -> io::Result<()> {
        // Boundary is OLD_MAX_FILE_SIZE, not u32::MAX: aMule gates the 0xE2
        // version + 64-bit filesize/gap tags on IsLargeFile(), so a file in the
        // (OLD_MAX_FILE_SIZE, u32::MAX] band must use the large encoding too or
        // the .met is not byte-identical to aMule's.
        let large = self.pf.size > OLD_MAX_FILE_SIZE;
        let mut tags = vec![
            Tag::id(FT_FILENAME, TagValue::Str(self.name.clone())),
            Tag::id(
                FT_FILESIZE,
                if large {
                    TagValue::U64(self.pf.size)
                } else {
                    TagValue::U32(self.pf.size as u32)
                },
            ),
        ];
        if !self.pf.corrupted().is_empty() {
            tags.push(Tag::id(
                FT_CORRUPTEDPARTS,
                TagValue::Str(format_corrupted(self.pf.corrupted())),
            ));
        }
        tags.extend(gap_tags(self.pf.gaps(), large));

        let met = PartMet {
            version: if large {
                PARTFILE_VERSION_LARGEFILE
            } else {
                PARTFILE_VERSION
            },
            date: 0,
            file_hash: self.pf.hash,
            part_hashes: self.pf.part_hashes.clone(),
            tags,
        };

        let tmp = self.met_path.with_extension("met.tmp");
        fs::write(&tmp, write_part_met(&met))?;
        fs::rename(&tmp, &self.met_path)?;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.pf.is_complete()
    }

    /// Move the finished file to `dest` and drop the `.part.met`.
    pub fn finish(self, dest: &Path) -> io::Result<()> {
        drop(self.file);
        fs::rename(&self.part_path, dest)?;
        let _ = fs::remove_file(&self.met_path);
        Ok(())
    }
}

fn paths(dir: &Path, index: u32) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("{index:03}.part")),
        dir.join(format!("{index:03}.part.met")),
    )
}

fn format_corrupted(parts: &[u64]) -> Vec<u8> {
    parts
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(",")
        .into_bytes()
}

fn parse_corrupted(s: &[u8]) -> Vec<u64> {
    String::from_utf8_lossy(s)
        .split(',')
        .filter_map(|p| p.trim().parse().ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::{ed2k_hash, md4};

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("padmule-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn the_large_file_met_boundary_is_old_max_not_u32_max() {
        // Review finding 6: a file in (OLD_MAX_FILE_SIZE, u32::MAX] must be written
        // with the 0xE2 large version + 64-bit tags, matching aMule/eMule's
        // IsLargeFile gate. The sparse data file is never populated, so this costs
        // no real disk. Skip gracefully if the filesystem refuses the sparse size.
        let dir = tmpdir("large-met");
        let size = OLD_MAX_FILE_SIZE + 1; // one byte into the "large" band
        let s = match PartStore::create(&dir, 1, [0xCD; 16], size, b"huge.bin") {
            Ok(s) => s,
            Err(_) => {
                std::fs::remove_dir_all(&dir).ok();
                return; // filesystem won't hold a >4GiB sparse file; not our bug
            }
        };
        drop(s);
        let met = fs::read(dir.join("001.part.met")).unwrap();
        assert_eq!(
            met[0], PARTFILE_VERSION_LARGEFILE,
            "a file just over OLD_MAX_FILE_SIZE must use the 0xE2 large-file met"
        );
        // And it must round-trip that size back.
        let reopened = PartStore::open(&dir, 1).unwrap();
        assert_eq!(reopened.pf.size, size);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writes_land_at_the_right_offsets_and_close_their_gaps() {
        let dir = tmpdir("offsets");
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let hash = ed2k_hash(&data);
        let mut s = PartStore::create(&dir, 1, hash, data.len() as u64, b"x.bin").unwrap();

        // Write the file back-to-front to prove offsets are honoured.
        s.write_block(2000, &data[2000..5000]).unwrap();
        assert_eq!(s.pf.missing(), 2000);
        s.write_block(0, &data[0..2000]).unwrap();
        assert!(s.is_complete());

        assert_eq!(s.read_part(0).unwrap(), data);
        assert_eq!(s.verify_part(0).unwrap(), Some(true));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_block_past_the_end_is_refused() {
        let dir = tmpdir("oob");
        let mut s = PartStore::create(&dir, 1, [0; 16], 100, b"x").unwrap();
        assert!(s.write_block(50, &[0u8; 100]).is_err());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_download_resumes_from_disk_with_its_gaps_intact() {
        let dir = tmpdir("resume");
        let data: Vec<u8> = (0..9000u32).map(|i| (i * 7) as u8).collect();
        let hash = ed2k_hash(&data);

        {
            let mut s = PartStore::create(&dir, 1, hash, 9000, b"resume.bin").unwrap();
            s.write_block(0, &data[0..3000]).unwrap();
            s.write_block(6000, &data[6000..9000]).unwrap();
            s.save_met().unwrap();
        } // dropped: simulates the app being killed

        let mut s = PartStore::open(&dir, 1).unwrap();
        assert_eq!(s.pf.hash, hash);
        assert_eq!(s.pf.size, 9000);
        assert_eq!(s.name, b"resume.bin");
        // Exactly the middle third is still missing.
        assert_eq!(
            s.pf.gaps(),
            &[mule_files::Gap {
                start: 3000,
                end: 6000
            }]
        );
        assert_eq!(s.pf.missing(), 3000);

        // Finish it and the bytes are whole.
        s.write_block(3000, &data[3000..6000]).unwrap();
        assert!(s.is_complete());
        assert_eq!(s.read_part(0).unwrap(), data);
        assert_eq!(s.verify_part(0).unwrap(), Some(true));

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_part_is_re_gapped_and_survives_a_restart() {
        let dir = tmpdir("corrupt");
        let size = PARTSIZE + 1000;
        let good0 = vec![1u8; PARTSIZE as usize];
        let p1 = vec![2u8; 1000];

        let mut s = PartStore::create(&dir, 1, [0xAB; 16], size, b"c.bin").unwrap();
        s.pf.part_hashes = vec![md4(&good0), md4(&p1)];
        // Write GARBAGE for part 0.
        s.write_block(0, &vec![9u8; PARTSIZE as usize]).unwrap();
        s.write_block(PARTSIZE, &p1).unwrap();
        assert!(s.is_complete());

        assert_eq!(s.verify_part(0).unwrap(), Some(false));
        assert_eq!(s.verify_part(1).unwrap(), Some(true));
        // Part 0 is fully re-opened; part 1 is untouched.
        assert!(!s.is_complete());
        assert_eq!(s.pf.missing(), PARTSIZE);
        assert_eq!(s.pf.corrupted(), &[0]);
        s.save_met().unwrap();
        drop(s);

        // The corrupted list persists, so a restart does not "forget" and call
        // the part good just because its bytes are all present.
        let mut s = PartStore::open(&dir, 1).unwrap();
        assert_eq!(s.pf.corrupted(), &[0]);
        assert_eq!(s.pf.missing(), PARTSIZE);

        // Re-download it correctly and it now verifies.
        s.pf.part_hashes = vec![md4(&good0), md4(&p1)];
        s.write_block(0, &good0).unwrap();
        assert_eq!(s.verify_part(0).unwrap(), Some(true));
        assert!(s.pf.corrupted().is_empty());
        assert!(s.is_complete());

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn finishing_moves_the_file_and_removes_the_met() {
        let dir = tmpdir("finish");
        let data = vec![42u8; 500];
        let mut s = PartStore::create(&dir, 1, ed2k_hash(&data), 500, b"done.bin").unwrap();
        s.write_block(0, &data).unwrap();
        let dest = dir.join("done.bin");
        s.finish(&dest).unwrap();

        assert_eq!(fs::read(&dest).unwrap(), data);
        assert!(!dir.join("001.part").exists());
        assert!(!dir.join("001.part.met").exists());

        fs::remove_dir_all(&dir).ok();
    }
}
