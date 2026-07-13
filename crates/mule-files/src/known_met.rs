//! known.met: the known/shared-files database. See docs/raw reference section 3
//! (KnownFile.cpp:723-858, KnownFileList.cpp).
//!
//! Layout: `u8` header (0x0E, or 0x0F when any record holds a large file),
//! `u32` record count, then per record: `u32` date, `16B` file MD4 hash,
//! `u16` part-hash count + that many `16B` part hashes, `u32` tag count + that
//! many MET-format tags. Every field is preserved as read so a read-then-write
//! round-trips bit-for-bit; the 0x0E and 0x0F headers are handled uniformly
//! because tag values (including UINT64 sizes) are preserved verbatim.

use mule_proto::{read_tag, write_tag, IoError, Reader, Tag, Writer};

/// known.met header (MET_HEADER).
pub const MET_HEADER: u8 = 0x0E;
/// known.met header when any record holds a large file (MET_HEADER_WITH_LARGEFILES).
pub const MET_HEADER_WITH_LARGEFILES: u8 = 0x0F;

/// One known-file record.
#[derive(Debug, Clone, PartialEq)]
pub struct KnownFileEntry {
    /// mtime (epoch seconds) of the shared file at hashing time.
    pub date: u32,
    /// eD2k file MD4 hash.
    pub file_hash: [u8; 16],
    /// Part MD4 hashes (ED2KPartHashCount; includes the sentinel for exact
    /// multiples, empty for sub-part files).
    pub part_hashes: Vec<[u8; 16]>,
    pub tags: Vec<Tag>,
}

/// A parsed known.met.
#[derive(Debug, Clone, PartialEq)]
pub struct KnownMet {
    /// Header byte as read (preserved for byte-identical round-trip).
    pub header: u8,
    pub entries: Vec<KnownFileEntry>,
}

fn read_hash16(r: &mut Reader) -> Result<[u8; 16], IoError> {
    let mut h = [0u8; 16];
    h.copy_from_slice(&r.read_bytes(16)?);
    Ok(h)
}

/// Parse a known.met.
pub fn read_known_met(bytes: &[u8]) -> Result<KnownMet, IoError> {
    let mut r = Reader::new(bytes);
    let header = r.read_u8()?;
    if header != MET_HEADER && header != MET_HEADER_WITH_LARGEFILES {
        return Err(IoError::BadTag(header));
    }
    let count = r.read_u32()?;
    let mut entries = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let date = r.read_u32()?;
        let file_hash = read_hash16(&mut r)?;
        let phcount = r.read_u16()?;
        let mut part_hashes = Vec::with_capacity(phcount as usize);
        for _ in 0..phcount {
            part_hashes.push(read_hash16(&mut r)?);
        }
        let tagcount = r.read_u32()?;
        let mut tags = Vec::with_capacity(tagcount as usize);
        for _ in 0..tagcount {
            tags.push(read_tag(&mut r)?);
        }
        entries.push(KnownFileEntry {
            date,
            file_hash,
            part_hashes,
            tags,
        });
    }
    Ok(KnownMet { header, entries })
}

/// Serialize a known.met, reproducing aMule's byte layout.
pub fn write_known_met(m: &KnownMet) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u8(m.header);
    w.write_u32(m.entries.len() as u32);
    for e in &m.entries {
        w.write_u32(e.date);
        w.write_bytes(&e.file_hash);
        w.write_u16(e.part_hashes.len() as u16);
        for ph in &e.part_hashes {
            w.write_bytes(ph);
        }
        w.write_u32(e.tags.len() as u32);
        for t in &e.tags {
            write_tag(&mut w, t);
        }
    }
    w.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::TagValue;

    const GOLDEN: &[u8] = &[
        0x0E, // header
        0x01, 0x00, 0x00, 0x00, // record count = 1
        0x00, 0x00, 0x00, 0x5F, // date = 0x5F000000
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // file hash (16B)
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, //
        0x00, 0x00, // part-hash count = 0
        0x01, 0x00, 0x00, 0x00, // tag count = 1
        // tag UINT32 id=0x02 (FT_FILESIZE) = 3
        0x03, 0x01, 0x00, 0x02, 0x03, 0x00, 0x00, 0x00,
    ];

    fn golden_parsed() -> KnownMet {
        KnownMet {
            header: 0x0E,
            entries: vec![KnownFileEntry {
                date: 0x5F00_0000,
                file_hash: [
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
                    0x0D, 0x0E, 0x0F,
                ],
                part_hashes: vec![],
                tags: vec![Tag::id(0x02, TagValue::U32(3))],
            }],
        }
    }

    #[test]
    fn reads_golden() {
        assert_eq!(read_known_met(GOLDEN).unwrap(), golden_parsed());
    }

    #[test]
    fn writes_golden_byte_identical() {
        assert_eq!(write_known_met(&golden_parsed()), GOLDEN);
    }

    #[test]
    fn rejects_bad_header() {
        let bytes = [0x99u8, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_known_met(&bytes), Err(IoError::BadTag(0x99)));
    }

    #[test]
    fn round_trips_multi_entry_with_part_hashes_and_large_header() {
        let m = KnownMet {
            header: MET_HEADER_WITH_LARGEFILES, // 0x0F
            entries: vec![
                KnownFileEntry {
                    date: 1_600_000_000,
                    file_hash: [0xAA; 16],
                    part_hashes: vec![[0x11; 16], [0x22; 16]],
                    tags: vec![
                        Tag::id(0x01, TagValue::Str(b"movie.avi".to_vec())),
                        Tag::id(0x02, TagValue::U64(5_000_000_000)), // large FT_FILESIZE
                    ],
                },
                KnownFileEntry {
                    date: 42,
                    file_hash: [0xBB; 16],
                    part_hashes: vec![],
                    tags: vec![],
                },
            ],
        };
        let bytes = write_known_met(&m);
        assert_eq!(read_known_met(&bytes).unwrap(), m);
        assert_eq!(bytes[0], 0x0F); // large-file header preserved
    }

    #[test]
    fn round_trips_empty() {
        let empty = KnownMet {
            header: MET_HEADER,
            entries: vec![],
        };
        let b = write_known_met(&empty);
        assert_eq!(b, vec![0x0E, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(read_known_met(&b).unwrap(), empty);
    }
}
