//! part.met: metadata for one partial download. See docs/raw reference
//! section 4 (PartFile.cpp:820-1053 save, 384-817 load).
//!
//! Layout: `u8` version (0xE0, or 0xE2 for a large file), `u32` date, `16B` file
//! hash, `u16` part-hash count + part hashes, `u32` tag count + MET tags. The
//! tag list carries the fixed metadata, the gap list, and any extras, all flat.
//! Fields are preserved verbatim so a read-then-write round-trips bit-for-bit.
//!
//! THE 0xE1 "SPLITTED" LAYOUT IS DIFFERENT, and read-only. eDonkey's import
//! format puts a selector `u32` at offset 1 and then either the hashset with NO
//! date, or a date at offset 2 with NO part-hash count (aMule
//! PartFile.cpp:432-461). An 0xE0 file can ALSO be in that layout, flagged only
//! by `00 00 02 01` at offset 24. `read_part_met` handles all of it;
//! `write_part_met` emits ONLY the default layout above, so writing a parsed
//! splitted file would produce bytes that contradict its own version byte. The
//! engine never does: `part_store` sets 0xE0/0xE2 explicitly rather than
//! preserving what it read. The bit-for-bit round-trip claim therefore covers
//! the DEFAULT layout, which is the only one padMule writes.
//!
//! The gap list (still-missing byte ranges) is encoded as ordinary tags whose
//! string name is a GAPSTART (0x09) or GAPEND (0x0A) byte followed by the
//! ASCII-decimal gap index. GAPSTART is the first missing byte (inclusive);
//! GAPEND is the first byte NOT missing (exclusive). `gaps` / `gap_tags`
//! translate between the tag encoding and `(start, end)` ranges.

use mule_proto::{read_tag, write_tag, IoError, Reader, Tag, TagName, TagValue, Writer};
use std::collections::BTreeMap;

/// part.met version for a normal file.
pub const PARTFILE_VERSION: u8 = 0xE0;
/// part.met version for a large file (> OLD_MAX_FILE_SIZE).
pub const PARTFILE_VERSION_LARGEFILE: u8 = 0xE2;
/// edonkey-import version, accepted on read only.
pub const PARTFILE_VERSION_EDONKEY: u8 = 0xE1;

/// Gap-tag name prefixes (FileTags.h): first missing byte / first present byte.
pub const FT_GAPSTART: u8 = 0x09;
pub const FT_GAPEND: u8 = 0x0A;

/// Metadata for one partial download.
#[derive(Debug, Clone, PartialEq)]
pub struct PartMet {
    /// Version byte as read (preserved for byte-identical round-trip).
    pub version: u8,
    /// mtime (epoch seconds) of the .part data file.
    pub date: u32,
    pub file_hash: [u8; 16],
    pub part_hashes: Vec<[u8; 16]>,
    pub tags: Vec<Tag>,
}

/// A still-missing byte range. `end` is EXCLUSIVE (the on-disk GAPEND value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Gap {
    pub start: u64,
    pub end: u64,
}

fn read_hash16(r: &mut Reader) -> Result<[u8; 16], IoError> {
    let mut h = [0u8; 16];
    h.copy_from_slice(&r.read_bytes(16)?);
    Ok(h)
}

/// Parse a part.met.
pub fn read_part_met(bytes: &[u8]) -> Result<PartMet, IoError> {
    let mut r = Reader::new(bytes);
    let version = r.read_u8()?;
    if version != PARTFILE_VERSION
        && version != PARTFILE_VERSION_LARGEFILE
        && version != PARTFILE_VERSION_EDONKEY
    {
        return Err(IoError::BadTag(version));
    }
    // WHICH LAYOUT? aMule decides with `isnewstyle` (PartFile.cpp:432-461) and
    // the two layouts are NOT interchangeable - reading one as the other yields
    // a plausible-looking but wrong hash and gap set, i.e. a silently corrupt
    // import rather than an error. padMule read EVERY version with the
    // old-style layout until 2026-08-08.
    //
    //   isnewstyle = (version == 0xE1)                          // "splitted"
    //   plus, for 0xE0 only, a sniff of the 4 bytes at offset 24 for
    //   `00 00 02 01`, which marks eDonkey's "old part style" (PMT_NEWOLD).
    let splitted = version == PARTFILE_VERSION_EDONKEY
        || (version == PARTFILE_VERSION && bytes.get(24..28) == Some(&[0, 0, 2, 1]));

    let (date, file_hash, part_hashes);
    if splitted {
        // `temp` is read at offset 1. Its VALUE selects the sub-layout, and in
        // the non-zero arm aMule seeks BACK to offset 2 - so the date overlaps
        // the bytes just examined. Transcribed rather than tidied, because the
        // overlap IS the format.
        let temp = r.read_u32()?;
        if temp == 0 {
            // 0.48-era: hashset immediately, no date field.
            date = 0;
            file_hash = read_hash16(&mut r)?;
            let phcount = r.read_u16()?;
            let mut hs = Vec::new();
            for _ in 0..phcount {
                hs.push(read_hash16(&mut r)?);
            }
            part_hashes = hs;
        } else {
            // eDonkey "old part style": date at offset 2, hash, and NO
            // part-hash count at all - the tag count follows the hash.
            let mut r2 = Reader::new(bytes.get(2..).ok_or(IoError::UnexpectedEof)?);
            date = r2.read_u32()?;
            file_hash = read_hash16(&mut r2)?;
            part_hashes = Vec::new();
            r = r2;
        }
    } else {
        date = r.read_u32()?;
        file_hash = read_hash16(&mut r)?;
        let phcount = r.read_u16()?;
        let mut hs = Vec::new();
        for _ in 0..phcount {
            hs.push(read_hash16(&mut r)?);
        }
        part_hashes = hs;
    }
    let tagcount = r.read_u32()?;
    let mut tags = Vec::new();
    for _ in 0..tagcount {
        tags.push(read_tag(&mut r)?);
    }
    Ok(PartMet {
        version,
        date,
        file_hash,
        part_hashes,
        tags,
    })
}

/// Serialize a part.met, reproducing aMule's DEFAULT byte layout (the one
/// `PARTFILE_VERSION` / `PARTFILE_VERSION_LARGEFILE` describe).
///
/// It does NOT emit the 0xE1 "splitted" layout - see the module doc. Hand it a
/// `PartMet` parsed from a splitted file and it will write the default shape
/// under whatever version byte that file carried, which no reader would then
/// parse correctly. Callers set the version deliberately (`part_store` writes
/// 0xE0/0xE2); this is a read-side import format, not a write target.
pub fn write_part_met(pm: &PartMet) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u8(pm.version);
    w.write_u32(pm.date);
    w.write_bytes(&pm.file_hash);
    w.write_u16(pm.part_hashes.len() as u16);
    for ph in &pm.part_hashes {
        w.write_bytes(ph);
    }
    w.write_u32(pm.tags.len() as u32);
    for t in &pm.tags {
        write_tag(&mut w, t);
    }
    w.into_inner()
}

/// A gap tag's value as a u64 (UINT32 or UINT64 on disk; other types ignored).
fn tag_u64(v: &TagValue) -> Option<u64> {
    match v {
        TagValue::U32(x) => Some(*x as u64),
        TagValue::U64(x) => Some(*x),
        _ => None,
    }
}

/// A gap tag's index parsed from the ASCII-decimal suffix of its name, plus
/// which end it is. Returns None if the tag is not a gap tag.
fn gap_key(name: &TagName) -> Option<(u8, u64)> {
    let bytes = match name {
        TagName::Str(b) => b,
        TagName::Id(_) => return None,
    };
    if bytes.len() < 2 || (bytes[0] != FT_GAPSTART && bytes[0] != FT_GAPEND) {
        return None;
    }
    let idx: u64 = std::str::from_utf8(&bytes[1..]).ok()?.parse().ok()?;
    Some((bytes[0], idx))
}

/// Extract the missing byte ranges from a part.met's tags. Ranges are sorted by
/// `start`; `end` is exclusive. Gap tags are paired by their decimal index, so
/// out-of-order or duplicated tags are tolerated (matching aMule's loader).
pub fn gaps(pm: &PartMet) -> Vec<Gap> {
    let mut starts: BTreeMap<u64, u64> = BTreeMap::new();
    let mut ends: BTreeMap<u64, u64> = BTreeMap::new();
    for t in &pm.tags {
        if let (Some((kind, idx)), Some(val)) = (gap_key(&t.name), tag_u64(&t.value)) {
            if kind == FT_GAPSTART {
                starts.insert(idx, val);
            } else {
                ends.insert(idx, val);
            }
        }
    }
    let mut out: Vec<Gap> = starts
        .iter()
        .filter_map(|(idx, &start)| ends.get(idx).map(|&end| Gap { start, end }))
        .collect();
    out.sort_by_key(|g| g.start);
    out
}

/// Build the gap-list tags for `gaps`. Values are UINT64 if `large`, else
/// UINT32. Gaps are emitted in the given order with indices 0..n.
pub fn gap_tags(gaps: &[Gap], large: bool) -> Vec<Tag> {
    let mut tags = Vec::with_capacity(gaps.len() * 2);
    let val = |v: u64| {
        if large {
            TagValue::U64(v)
        } else {
            TagValue::U32(v as u32)
        }
    };
    for (i, g) in gaps.iter().enumerate() {
        let suffix = i.to_string();
        let mut start_name = vec![FT_GAPSTART];
        start_name.extend_from_slice(suffix.as_bytes());
        let mut end_name = vec![FT_GAPEND];
        end_name.extend_from_slice(suffix.as_bytes());
        tags.push(Tag {
            name: TagName::Str(start_name),
            value: val(g.start),
        });
        tags.push(Tag {
            name: TagName::Str(end_name),
            value: val(g.end),
        });
    }
    tags
}

#[cfg(test)]
mod tests {
    use super::*;

    // Fresh 500-byte download: FT_FILESIZE=500 and one gap [0, 500).
    const GOLDEN: &[u8] = &[
        0xE0, // version
        0x11, 0x22, 0x33, 0x44, // date
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // file hash (16B)
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, //
        0x00, 0x00, // part-hash count = 0
        0x03, 0x00, 0x00, 0x00, // tag count = 3
        // FT_FILESIZE(0x02) UINT32 = 500
        0x03, 0x01, 0x00, 0x02, 0xF4, 0x01, 0x00, 0x00,
        // GAPSTART gap0: string name [0x09,'0'], UINT32 = 0
        0x03, 0x02, 0x00, 0x09, 0x30, 0x00, 0x00, 0x00, 0x00,
        // GAPEND gap0: string name [0x0A,'0'], UINT32 = 500
        0x03, 0x02, 0x00, 0x0A, 0x30, 0xF4, 0x01, 0x00, 0x00,
    ];

    fn golden_parsed() -> PartMet {
        PartMet {
            version: 0xE0,
            date: 0x4433_2211,
            file_hash: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ],
            part_hashes: vec![],
            tags: vec![
                Tag::id(0x02, TagValue::U32(500)),
                Tag {
                    name: TagName::Str(vec![FT_GAPSTART, b'0']),
                    value: TagValue::U32(0),
                },
                Tag {
                    name: TagName::Str(vec![FT_GAPEND, b'0']),
                    value: TagValue::U32(500),
                },
            ],
        }
    }

    #[test]
    fn reads_golden() {
        assert_eq!(read_part_met(GOLDEN).unwrap(), golden_parsed());
    }

    #[test]
    fn writes_golden_byte_identical() {
        assert_eq!(write_part_met(&golden_parsed()), GOLDEN);
    }

    /// THE 0xE1 "SPLITTED" LAYOUT IS NOT THE 0xE0 ONE, and reading one as the
    /// other does not error - it yields a plausible, wrong hash and gap set,
    /// which is a silently corrupt import.
    ///
    /// aMule (PartFile.cpp:432-461): `isnewstyle = (version == 0xE1)`, and then
    /// a `temp = ReadUInt32()` at offset 1 selects between two sub-layouts -
    /// `temp == 0` means the hashset follows immediately with NO date field,
    /// anything else means seek BACK to offset 2, read the date there, read the
    /// hash, and read NO part-hash count at all.
    ///
    /// THIS TEST REPLACES A TAUTOLOGICAL ONE that flipped the version byte on an
    /// 0xE0-layout golden and asserted it round-tripped. Of course it did: both
    /// sides used the same wrong layout, so the assertion compared padMule with
    /// itself and could never fail. Fixtures here are built from the SOURCE
    /// layout instead. **Validated by transcription, not against a real eDonkey
    /// part.met - no such file was available.** Said plainly so the next reader
    /// knows what this does and does not prove.
    #[test]
    fn the_splitted_layout_reads_its_own_shape_not_the_default_one() {
        // temp == 0: version, 0u32, hash, u16 count, hashes, tagcount.
        let mut b = vec![PARTFILE_VERSION_EDONKEY];
        b.extend_from_slice(&0u32.to_le_bytes());
        b.extend_from_slice(&[0xAB; 16]);
        b.extend_from_slice(&1u16.to_le_bytes());
        b.extend_from_slice(&[0xCD; 16]);
        b.extend_from_slice(&0u32.to_le_bytes()); // tagcount
        let p = read_part_met(&b).unwrap();
        assert_eq!(p.version, PARTFILE_VERSION_EDONKEY);
        assert_eq!(p.file_hash, [0xAB; 16], "the hash must come from offset 5");
        assert_eq!(p.part_hashes, vec![[0xCD; 16]]);
        assert_eq!(p.date, 0, "this sub-layout has no date field at all");

        // temp != 0: version, <1 byte>, date@2, hash, tagcount. No part count.
        let mut b = vec![PARTFILE_VERSION_EDONKEY, 0x77];
        b.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // date at offset 2
        b.extend_from_slice(&[0xEE; 16]);
        b.extend_from_slice(&0u32.to_le_bytes()); // tagcount
        let p = read_part_met(&b).unwrap();
        assert_eq!(p.date, 0x1234_5678, "the date is read from offset 2");
        assert_eq!(p.file_hash, [0xEE; 16]);
        assert!(
            p.part_hashes.is_empty(),
            "this sub-layout carries no part-hash count"
        );
    }

    /// The 0xE0 SNIFF: eDonkey's "old part style" wears the ordinary version
    /// byte and is identified only by `00 00 02 01` at offset 24
    /// (PartFile.cpp:435-445). Without the sniff it parses as a normal 0xE0 and
    /// the difference is silent.
    #[test]
    fn an_0xe0_file_marked_old_part_style_takes_the_splitted_path() {
        // Build a temp != 0 splitted body under an 0xE0 version byte, with the
        // marker bytes landing at offset 24.
        let mut b = vec![PARTFILE_VERSION, 0x77];
        b.extend_from_slice(&0x0BAD_F00Du32.to_le_bytes()); // date at 2..6
        b.extend_from_slice(&[0x11; 16]); // hash at 6..22
        b.extend_from_slice(&0u32.to_le_bytes()); // tagcount at 22..26
        assert_eq!(&b[24..26], &[0, 0], "fixture places the marker at 24");
        b[24] = 0;
        b[25] = 0;
        b.push(2);
        b.push(1);
        // Bytes 24..28 are now 00 00 02 01 - the marker - so this 0xE0 file must
        // be read with the SPLITTED layout, i.e. the date comes from offset 2.
        let p = read_part_met(&b).unwrap();
        assert_eq!(
            p.date, 0x0BAD_F00D,
            "the marker must switch this 0xE0 file onto the splitted layout"
        );
        assert_eq!(p.file_hash, [0x11; 16]);
    }

    #[test]
    fn rejects_bad_version() {
        let bytes = [0x99u8, 0, 0, 0, 0];
        assert_eq!(read_part_met(&bytes), Err(IoError::BadTag(0x99)));
    }

    #[test]
    fn fresh_download_is_one_gap_end_exclusive() {
        // The golden part.met's single gap is [0, 500): start inclusive, end
        // exclusive == file size.
        let g = gaps(&golden_parsed());
        assert_eq!(g, vec![Gap { start: 0, end: 500 }]);
    }

    #[test]
    fn gap_tags_then_gaps_round_trips() {
        let want = vec![
            Gap { start: 0, end: 100 },
            Gap {
                start: 200,
                end: 300,
            },
        ];
        let pm = PartMet {
            version: 0xE0,
            date: 1,
            file_hash: [0; 16],
            part_hashes: vec![],
            tags: gap_tags(&want, false),
        };
        assert_eq!(gaps(&pm), want);
    }

    #[test]
    fn large_file_gaps_use_uint64_and_round_trip() {
        let want = vec![Gap {
            start: 5_000_000_000,
            end: 9_000_000_000,
        }];
        let tags = gap_tags(&want, true);
        // Confirm the values were emitted as UINT64.
        assert!(matches!(tags[0].value, TagValue::U64(5_000_000_000)));
        let pm = PartMet {
            version: PARTFILE_VERSION_LARGEFILE,
            date: 1,
            file_hash: [0; 16],
            part_hashes: vec![],
            tags,
        };
        // Full byte round-trip too.
        let bytes = write_part_met(&pm);
        assert_eq!(read_part_met(&bytes).unwrap(), pm);
        assert_eq!(gaps(&pm), want);
    }

    #[test]
    fn out_of_order_and_duplicate_gap_tags_pair_by_index() {
        // Deliberately shuffled: end0, start1, end1, start0. Pairs by index.
        let tags = vec![
            Tag {
                name: TagName::Str(vec![FT_GAPEND, b'0']),
                value: TagValue::U32(100),
            },
            Tag {
                name: TagName::Str(vec![FT_GAPSTART, b'1']),
                value: TagValue::U32(200),
            },
            Tag {
                name: TagName::Str(vec![FT_GAPEND, b'1']),
                value: TagValue::U32(300),
            },
            Tag {
                name: TagName::Str(vec![FT_GAPSTART, b'0']),
                value: TagValue::U32(0),
            },
        ];
        let pm = PartMet {
            version: 0xE0,
            date: 1,
            file_hash: [0; 16],
            part_hashes: vec![],
            tags,
        };
        assert_eq!(
            gaps(&pm),
            vec![
                Gap { start: 0, end: 100 },
                Gap {
                    start: 200,
                    end: 300
                }
            ]
        );
    }
}
