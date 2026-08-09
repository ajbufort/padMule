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
/// Download priority (eMule `m_iDownPriority`). aMule writes BOTH the modern
/// 0x18 and the legacy 0x13, same value, always, as UINT32 (PartFile.cpp:928-933
/// -> CFileDataIO::WriteTag). We match that.
pub const FT_DLPRIORITY: u8 = 0x18;
pub const FT_OLDDLPRIORITY: u8 = 0x13;
/// Paused flag (eMule `FT_STATUS`, opcodes.h:354, `<uint32>`). The FORMAT
/// authority writes it ONLY while paused (0.50a PartFile.cpp:1435-1439:
/// `if (paused) CTag(FT_STATUS, 1)`); aMule always writes `m_paused?1:0`
/// (PartFile.cpp:926) - a known divergence padMule does not copy. Read side:
/// any nonzero int means paused; absent or zero means not (both authorities
/// read it that way).
pub const FT_STATUS: u8 = 0x14;

/// Priority levels (eMule `Constants.h`): the three padMule honors, plus the
/// AUTO sentinel it maps in. padMule does not implement Auto tuning, so on read
/// it collapses AUTO to HIGH exactly as aMule does when it cannot auto-tune
/// (PartFile.cpp:506-509); genuinely unknown values (PR_VERYHIGH 3, PR_VERY_LOW
/// 4, PR_POWERSHARE 6) clamp to Normal like aMule's later branch (:512-515).
pub const PR_LOW: u8 = 0;
pub const PR_NORMAL: u8 = 1;
pub const PR_HIGH: u8 = 2;
pub const PR_AUTO: u8 = 5;

/// A download backed by a real `.part` file.
pub struct PartStore {
    part_path: PathBuf,
    met_path: PathBuf,
    file: File,
    pub pf: PartFile,
    pub name: Vec<u8>,
    /// The user's download priority (PR_LOW/PR_NORMAL/PR_HIGH). Persisted in
    /// part.met, read on resume; biases source-finding effort (see fetch.rs).
    pub priority: u8,
    /// USER-paused (eMule `m_paused`, persisted as FT_STATUS). A paused
    /// download keeps its entry and bytes and is skipped by every fetch path
    /// until the user resumes it - across restarts, like eMule 0.70b.
    pub paused: bool,
}

/// The previous generation of a `.part.met`, kept so a lost or unreadable live
/// met never strands a download (eMule `PARTMET_BAK_EXT`).
fn met_bak_path(met_path: &Path) -> PathBuf {
    let mut p = met_path.as_os_str().to_owned();
    p.push(".bak");
    PathBuf::from(p)
}

/// Free space we refuse to consume when preallocating, so a download can never
/// fill the device to zero - iPadOS degrades badly there (and the user still has
/// to be able to save the finished file out of Documents).
pub const MIN_FREE_MARGIN: u64 = 256 * 1024 * 1024;

/// Bytes currently available on the volume holding `dir`, or `None` if it cannot
/// be determined (an unreadable path, an exotic filesystem).
pub fn available_space(dir: &Path) -> Option<u64> {
    let c_path = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).ok()?;
    // SAFETY: c_path is a valid NUL-terminated string for the duration of the
    // call, and statvfs only writes into the zeroed struct we hand it.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c_path.as_ptr(), &mut st) != 0 {
            return None;
        }
        // f_bavail is the count available to a NON-root user, which is what an
        // app actually gets; f_bfree would overstate it by the reserved blocks.
        (st.f_bavail as u64).checked_mul(st.f_frsize as u64)
    }
}

/// Would preallocating `size` bytes leave less than [`MIN_FREE_MARGIN`] free?
///
/// FAILS OPEN on unknown availability: if the volume cannot be read we allow the
/// download rather than block one the device may well have room for.
pub fn would_exhaust_space(size: u64, available: Option<u64>) -> bool {
    match available {
        // A size that OVERFLOWS when the margin is added is absurd and cannot
        // fit anything - refuse it. (saturating_add would silently stop
        // enforcing the margin at the top of the range.)
        Some(free) => match size.checked_add(MIN_FREE_MARGIN) {
            Some(needed) => needed > free,
            None => true,
        },
        None => false,
    }
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
        // Guard the volume BEFORE creating anything: a sparse `set_len` succeeds
        // instantly even when the file cannot possibly fit, so without this the
        // failure surfaces mid-transfer instead of at the click
        // (docs/wiki/ipados-constraints.md requires this check).
        if would_exhaust_space(size, available_space(dir)) {
            return Err(io::Error::other(format!(
                "not enough free space for {size} bytes (keeping {MIN_FREE_MARGIN} bytes free)"
            )));
        }
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
            priority: PR_NORMAL,
            paused: false,
        };
        s.save_met()?;
        Ok(s)
    }

    /// Resume `NNN.part` from its `.part.met`.
    pub fn open(dir: &Path, index: u32) -> io::Result<Self> {
        let (part_path, met_path) = paths(dir, index);
        // Prefer the live met; fall back to the previous generation if it is
        // missing or unreadable, so one bad save (or a suspension kill mid-write
        // on a filesystem that reorders) never strands a download. eMule does the
        // same (DownloadQueue.cpp:103 loads PARTMET_BAK_EXT on failure).
        let met = match fs::read(&met_path)
            .ok()
            .and_then(|b| read_part_met(&b).ok())
        {
            Some(m) => m,
            None => read_part_met(&fs::read(met_bak_path(&met_path))?)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("{e:?}")))?,
        };

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

        // Priority: prefer the modern tag, fall back to the legacy one. Read as
        // any int width (mule-proto preserves the on-disk width; an old eMule may
        // have written it narrow). AUTO collapses to HIGH (aMule's own AUTO->HIGH,
        // since padMule has no Auto tuning); other unknown values clamp to Normal.
        let priority = met
            .tags
            .iter()
            .find(|t| {
                t.name == mule_proto::TagName::Id(FT_DLPRIORITY)
                    || t.name == mule_proto::TagName::Id(FT_OLDDLPRIORITY)
            })
            .and_then(|t| match &t.value {
                TagValue::U8(v) => Some(*v as u64),
                TagValue::U16(v) => Some(*v as u64),
                TagValue::U32(v) => Some(*v as u64),
                _ => None,
            })
            .map(|v| match v as u8 {
                PR_LOW => PR_LOW,
                PR_HIGH | PR_AUTO => PR_HIGH,
                _ => PR_NORMAL,
            })
            .unwrap_or(PR_NORMAL);

        // Paused (FT_STATUS): nonzero = the user paused this download. Absent
        // is eMule's unpaused write shape; zero is aMule's.
        let paused = met
            .tags
            .iter()
            .find(|t| t.name == mule_proto::TagName::Id(FT_STATUS))
            .and_then(|t| match &t.value {
                TagValue::U8(v) => Some(*v as u64),
                TagValue::U16(v) => Some(*v as u64),
                TagValue::U32(v) => Some(*v as u64),
                _ => None,
            })
            .map(|v| v != 0)
            .unwrap_or(false);

        let mut pf = PartFile::resume(met.file_hash, size, met_gaps(&met), corrupted);
        pf.part_hashes = met.part_hashes.clone();

        let file = OpenOptions::new().read(true).write(true).open(&part_path)?;
        Ok(PartStore {
            part_path,
            met_path,
            file,
            pf,
            name,
            priority,
            paused,
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

    /// The backing `.part` data file's path, so a preview snapshot can open its
    /// OWN read handle and copy without holding the download lock.
    pub fn part_path(&self) -> &Path {
        &self.part_path
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
        // Priority: both tags, same value, UINT32 - exactly as aMule writes them
        // (PartFile.cpp:928-933), so the .met stays readable by a desktop client.
        tags.push(Tag::id(FT_DLPRIORITY, TagValue::U32(self.priority as u32)));
        tags.push(Tag::id(
            FT_OLDDLPRIORITY,
            TagValue::U32(self.priority as u32),
        ));
        // FT_STATUS only while paused - the format authority's write shape
        // (eMule 0.50a PartFile.cpp:1435-1439); aMule tolerates the absence.
        if self.paused {
            tags.push(Tag::id(FT_STATUS, TagValue::U32(1)));
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

        // Write new content aside, promote the PREVIOUS met to .bak, then
        // atomically install - aMule's own save order (PartFile.cpp:855-865):
        // one content write plus two metadata renames, and the live .part.met is
        // never absent or partial at any observable moment. The .bak is not
        // decorative: `open` recovers from it, exactly as eMule does when the
        // live met fails to load (DownloadQueue.cpp:103).
        let tmp = self.met_path.with_extension("met.tmp");
        fs::write(&tmp, write_part_met(&met))?;
        // Best-effort: a first save has nothing to promote, and a failure here
        // must not cost us the new content.
        let _ = fs::rename(&self.met_path, met_bak_path(&self.met_path));
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

    /// Move the finished `.part` into place WITHOUT consuming the store, so the
    /// caller need not be the sole owner of the enclosing `Arc<Download>`. Unix
    /// (iPadOS + Linux, the only targets) renames an open file fine; the still-open
    /// handle keeps pointing at the moved inode until the Download is dropped. The
    /// `.part`/`.met` paths are now stale, so this must be the store's last write.
    pub fn finish_in_place(&mut self, dest: &Path) -> io::Result<()> {
        fs::rename(&self.part_path, dest)?;
        let _ = fs::remove_file(&self.met_path);
        Ok(())
    }

    /// Delete the backing `.part` and `.part.met` (best effort). Used when a
    /// download is cancelled. Any open handle keeps the bytes readable until it
    /// drops, but the paths leave disk at once so a restart will not resume them.
    pub fn remove_backing_files(&self) {
        let _ = fs::remove_file(&self.part_path);
        let _ = fs::remove_file(&self.met_path);
    }
}

fn paths(dir: &Path, index: u32) -> (PathBuf, PathBuf) {
    (
        dir.join(format!("{index:03}.part")),
        dir.join(format!("{index:03}.part.met")),
    )
}

/// Copy the first `len` bytes of the `.part` at `src` to `dest`, so the UI can
/// hand a contiguous media prefix to a player. Opens its OWN read handle (NOT the
/// download's), so the caller can run it WITHOUT holding the download lock - safe
/// because `[0, len)` is completed contiguous data the block writer never rewrites
/// (writes only fill gaps at or past `len`). Chunked (a large video is never held
/// in memory); returns the bytes written (short if the file ends early). 0 for an
/// empty prefix, leaving no stray file behind.
pub fn copy_file_prefix(src: &Path, dest: &Path, len: u64) -> io::Result<u64> {
    if len == 0 {
        return Ok(0);
    }
    let mut input = File::open(src)?;
    let mut out = File::create(dest)?;
    let mut remaining = len;
    let mut buf = vec![0u8; 256 * 1024];
    while remaining > 0 {
        let want = remaining.min(buf.len() as u64) as usize;
        let n = input.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        out.write_all(&buf[..n])?;
        remaining -= n as u64;
    }
    out.sync_data()?;
    Ok(len - remaining)
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
    #[test]
    fn saving_promotes_the_previous_met_to_a_bak_and_open_recovers_from_it() {
        // Upstream keeps a previous generation of the part.met and RECOVERS from
        // it: eMule 0.50a loads `<name>.part.met.bak` when the live file fails
        // (DownloadQueue.cpp:103), and aMule installs it by renaming the old met
        // aside before the atomic install (PartFile.cpp:855-865). padMule's
        // tmp+rename already made a TORN write impossible, but a lost or
        // unreadable met still stranded a download - which matters more here
        // than on desktop, since iPadOS kills the app on suspension as routine.
        use super::*;
        let dir = std::env::temp_dir().join(format!("padmule-bak-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // create() writes the first met itself, so there is nothing to promote
        // until a SUBSEQUENT save.
        let mut st = PartStore::create(&dir, 1, [0x5A; 16], 40_000, b"first.bin").unwrap();
        let bak = dir.join("001.part.met.bak");
        assert!(!bak.exists(), "nothing to back up until a second save");

        // The next save promotes the PREVIOUS content to .bak - so the backup
        // must hold the OLD name, not the new one.
        st.name = b"second.bin".to_vec();
        st.save_met().unwrap();
        assert!(bak.exists(), "the previous met must be kept as .bak");
        let old = read_part_met(&std::fs::read(&bak).unwrap()).unwrap();
        let old_name = old.tags.iter().find_map(|t| match (&t.name, &t.value) {
            (mule_proto::TagName::Id(FT_FILENAME), TagValue::Str(v)) => Some(v.clone()),
            _ => None,
        });
        assert_eq!(old_name.as_deref(), Some(&b"first.bin"[..]));

        // The recovery path: a destroyed live met must not strand the download.
        drop(st);
        std::fs::write(dir.join("001.part.met"), b"garbage not a met").unwrap();
        let recovered = PartStore::open(&dir, 1).expect("open must fall back to the .bak");
        assert_eq!(recovered.name, b"first.bin".to_vec());
        // A missing (not merely corrupt) met recovers too.
        drop(recovered);
        std::fs::remove_file(dir.join("001.part.met")).unwrap();
        let recovered = PartStore::open(&dir, 1).expect("a MISSING met must also fall back");
        assert_eq!(recovered.name, b"first.bin".to_vec());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_space_guard_refuses_only_what_would_exhaust_the_volume() {
        // Pure predicate, so the policy is testable without a full disk.
        // Unknown availability must FAIL OPEN: if we cannot read the volume we
        // must not block a download the device may well have room for.
        assert!(!would_exhaust_space(1_000, None));
        // Comfortably fits.
        assert!(!would_exhaust_space(1_000, Some(10 * MIN_FREE_MARGIN)));
        // Fits on paper but would eat the safety margin - iPadOS misbehaves badly
        // at zero free space, so leave headroom rather than fill the device.
        assert!(would_exhaust_space(
            MIN_FREE_MARGIN,
            Some(MIN_FREE_MARGIN + 1_000)
        ));
        // Plainly larger than the volume.
        assert!(would_exhaust_space(u64::MAX / 2, Some(1_000_000)));
        // No overflow panic on a preposterous size.
        assert!(would_exhaust_space(u64::MAX, Some(u64::MAX)));
    }

    #[test]
    fn create_refuses_a_file_the_volume_cannot_hold() {
        // The live path: a sparse set_len would SUCCEED instantly for a size the
        // volume cannot hold, and the download would then die mid-transfer.
        // docs/wiki/ipados-constraints.md requires guarding this.
        let dir = std::env::temp_dir().join(format!("padmule-space-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let err = match PartStore::create(&dir, 1, [0xAB; 16], u64::MAX / 2, b"huge.bin") {
            Err(e) => e,
            Ok(_) => panic!("a file larger than the volume must be refused up front"),
        };
        assert!(
            err.to_string().contains("free space"),
            "the refusal must say WHY: {err}"
        );
        // ...and it must not leave a stray part file behind.
        assert!(!dir.join("001.part").exists());
        // A normal-sized file is unaffected.
        PartStore::create(&dir, 2, [0xCD; 16], 4096, b"ok.bin").unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

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
    fn paused_persists_via_ft_status_and_only_when_paused() {
        let dir = tmpdir("paused");
        let mut s = PartStore::create(&dir, 1, [0x5A; 16], 500, b"p.bin").unwrap();
        assert!(!s.paused, "new downloads are not paused");
        // eMule's write shape: NO FT_STATUS tag at all while unpaused (0.50a
        // PartFile.cpp:1435-1439 writes it only inside `if (paused)`); aMule
        // always writes it, a divergence deliberately not copied.
        let tag = [0x03u8, 0x01, 0x00, FT_STATUS, 0x01, 0x00, 0x00, 0x00];
        let met = fs::read(dir.join("001.part.met")).unwrap();
        assert!(
            !met.windows(8).any(|w| w == tag),
            "an unpaused met carries no FT_STATUS tag"
        );

        s.paused = true;
        s.save_met().unwrap();
        let met = fs::read(dir.join("001.part.met")).unwrap();
        assert!(
            met.windows(8).any(|w| w == tag),
            "paused writes FT_STATUS(0x14) as UINT32 = 1"
        );
        let reopened = PartStore::open(&dir, 1).unwrap();
        assert!(reopened.paused, "the pause survives a restart");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn priority_persists_byte_faithfully_and_reads_back() {
        let dir = tmpdir("priority");
        let mut s = PartStore::create(&dir, 1, [0x5A; 16], 500, b"p.bin").unwrap();
        assert_eq!(s.priority, PR_NORMAL, "new downloads default to Normal");

        s.priority = PR_HIGH;
        s.save_met().unwrap();

        // Assert the ACTUAL on-disk bytes, not just a round-trip: aMule writes
        // each priority tag as <type=UINT32(0x03)><nameLen u16 LE = 1><id byte>
        // <value u32 LE>. For PR_HIGH=2 that is exactly these 8 bytes, once for
        // 0x18 and once for 0x13.
        let met = fs::read(dir.join("001.part.met")).unwrap();
        let dl = [0x03u8, 0x01, 0x00, FT_DLPRIORITY, 0x02, 0x00, 0x00, 0x00];
        let old = [0x03u8, 0x01, 0x00, FT_OLDDLPRIORITY, 0x02, 0x00, 0x00, 0x00];
        assert!(
            met.windows(8).any(|w| w == dl),
            "FT_DLPRIORITY(0x18) must be a UINT32 tag = 2"
        );
        assert!(
            met.windows(8).any(|w| w == old),
            "FT_OLDDLPRIORITY(0x13) must be a UINT32 tag = 2"
        );

        // ...and it reads back on resume.
        let reopened = PartStore::open(&dir, 1).unwrap();
        assert_eq!(reopened.priority, PR_HIGH);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn auto_reads_as_high_and_other_unknowns_read_as_normal() {
        // aMule collapses PR_AUTO(5) -> HIGH; padMule mirrors that (no Auto tuning).
        let dir = tmpdir("priority-auto");
        let mut s = PartStore::create(&dir, 1, [0x11; 16], 500, b"a.bin").unwrap();
        s.priority = PR_AUTO;
        s.save_met().unwrap();
        assert_eq!(PartStore::open(&dir, 1).unwrap().priority, PR_HIGH);

        // A genuinely-unknown value (PR_VERYHIGH 3) clamps to Normal, like aMule.
        s.priority = 3;
        s.save_met().unwrap();
        assert_eq!(PartStore::open(&dir, 1).unwrap().priority, PR_NORMAL);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn copy_prefix_snapshots_the_contiguous_leading_bytes() {
        let dir = tmpdir("prefix");
        let data: Vec<u8> = (0..5000u32).map(|i| i as u8).collect();
        let mut s =
            PartStore::create(&dir, 1, ed2k_hash(&data), data.len() as u64, b"m.bin").unwrap();
        // A leading run [0, 3000) plus a DISCONNECTED island [4000, 5000).
        s.write_block(0, &data[0..3000]).unwrap();
        s.write_block(4000, &data[4000..5000]).unwrap();
        assert_eq!(
            s.pf.contiguous_prefix(),
            3000,
            "only the leading run counts, not the island"
        );
        let dest = dir.join("snapshot.bin");
        let prefix = s.pf.contiguous_prefix();
        let n = copy_file_prefix(s.part_path(), &dest, prefix).unwrap();
        assert_eq!(n, 3000);
        assert_eq!(
            fs::read(&dest).unwrap(),
            data[0..3000],
            "the snapshot is exactly the leading bytes"
        );
        std::fs::remove_dir_all(&dir).ok();
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
