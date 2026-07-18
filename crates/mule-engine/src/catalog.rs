//! Search-result intelligence (client-side, zero wire): fold raw search hits
//! into a ranked catalog of unique files. Dedups by ed2k hash across a server
//! (and later Kad) response, aggregates availability and the filenames seen,
//! flags suspect entries, and ranks so the best/most-available file surfaces
//! first. None of this touches the wire - it is purely how we present and choose.

use crate::search::SearchResultFile;
use mule_proto::{TagName, TagValue};
use std::collections::BTreeMap;

const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
const FT_SOURCES: u8 = 0x15;
const FT_COMPLETE_SOURCES: u8 = 0x30;
// Type + media tags (IDs from refs/emule-0.50a/.../opcodes.h).
const FT_FILETYPE: u8 = 0x03;
const FT_MEDIA_ARTIST: u8 = 0xD0;
const FT_MEDIA_ALBUM: u8 = 0xD1;
const FT_MEDIA_TITLE: u8 = 0xD2;
const FT_MEDIA_LENGTH: u8 = 0xD3;
const FT_MEDIA_BITRATE: u8 = 0xD4;
const FT_MEDIA_CODEC: u8 = 0xD5;
const FT_FILERATING: u8 = 0xF7;

/// Decode a server search-result FT_FILERATING tag to a 0-5 rating. The tag is a
/// masked field, NOT a plain 0-5: aMule reads `(value & 0xF) / 3`
/// (SearchFile.cpp:77). 0 = not rated, 1 = Fake/Invalid, 2 = Poor, 3 = Fair,
/// 4 = Good, 5 = Excellent. Clamped to 5.
fn decode_rating(tag_value: u64) -> u8 {
    (((tag_value & 0xF) / 3) as u8).min(5)
}

pub(crate) fn tag_str(tags: &[mule_proto::Tag], id: u8) -> Option<String> {
    tags.iter().find_map(|t| match (&t.name, &t.value) {
        (TagName::Id(n), TagValue::Str(s)) if *n == id => {
            Some(String::from_utf8_lossy(s).into_owned())
        }
        _ => None,
    })
}

pub(crate) fn tag_u64(tags: &[mule_proto::Tag], id: u8) -> Option<u64> {
    // Match every integer width, including U8: aMule's CTag::GetInt normalizes
    // all of them (Tag.cpp:128-131), and the compact "new ed2k tag" encoding
    // writes any value <= 0xFF as TAGTYPE_UINT8 - so a small FT_FILERATING /
    // FT_SOURCES / bitrate arrives as U8. Omitting it silently dropped those.
    tags.iter().find_map(|t| match (&t.name, &t.value) {
        (TagName::Id(n), TagValue::U8(v)) if *n == id => Some(*v as u64),
        (TagName::Id(n), TagValue::U16(v)) if *n == id => Some(*v as u64),
        (TagName::Id(n), TagValue::U32(v)) if *n == id => Some(*v as u64),
        (TagName::Id(n), TagValue::U64(v)) if *n == id => Some(*v),
        _ => None,
    })
}

/// A confidence flag on a cataloged file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trust {
    /// Nothing suspicious.
    Ok,
    /// Something is off - carries a short reason (shown to the user / used to
    /// deprioritize). A hash uniquely determines the content, so e.g. two sizes
    /// for one hash means the metadata is lying or corrupt.
    Suspect(&'static str),
}

/// One unique file in the catalog (deduped by hash).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RankedFile {
    pub hash: [u8; 16],
    /// The agreed file size (0 if none was advertised).
    pub size: u64,
    /// The most-seen filename.
    pub name: String,
    /// Best advertised availability across the results.
    pub sources: u32,
    /// How many DISTINCT names were advertised for this one hash (a high count
    /// on a lone-source file is a mild fake signal).
    pub name_variants: usize,
    pub trust: Trust,
    /// Full-file copies advertised (FT_COMPLETE_SOURCES); 0 if none advertised.
    pub complete_sources: u32,
    /// Display category (from FT_FILETYPE, else inferred from the extension).
    pub file_type: String,
    /// Media metadata, empty/0 when the result did not carry the tag.
    pub artist: String,
    pub album: String,
    pub title: String,
    pub length_secs: u32,
    pub bitrate: u32,
    pub codec: String,
    /// Server-advertised rating 0-5 (0 = none/not rated, 1 = Fake, ... 5 =
    /// Excellent). Sparse - most server results carry no rating.
    pub rating: u8,
}

#[derive(Default)]
struct Group {
    sizes: BTreeMap<u64, u32>, // size -> times seen (nonzero only)
    names: BTreeMap<String, u32>,
    sources: u32,
    complete: u32,
    types: BTreeMap<String, u32>, // FT_FILETYPE values seen
    artist: String,
    album: String,
    title: String,
    length: u32,
    bitrate: u32,
    codec: String,
    // Sum + count of RATED rows (rating != 0), for aMule's average aggregation.
    rating_sum: u32,
    rating_count: u32,
}

/// Map a filename extension to a display category. eMule's FT_FILETYPE tag is
/// preferred when present; this is the fallback.
fn infer_type(name: &str) -> &'static str {
    let ext = name.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    match ext.as_str() {
        "avi" | "mkv" | "mp4" | "mov" | "mpg" | "mpeg" | "wmv" | "flv" | "m4v" | "webm" | "vob"
        | "ogm" | "rm" | "rmvb" => "Video",
        "mp3" | "flac" | "wav" | "aac" | "ogg" | "m4a" | "wma" | "ac3" | "ape" | "mpc" => "Audio",
        "zip" | "rar" | "7z" | "gz" | "tar" | "bz2" | "iso" | "img" | "nrg" => "Archive",
        "pdf" | "doc" | "docx" | "txt" | "epub" | "rtf" | "odt" | "chm" => "Document",
        "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "tif" | "tiff" => "Image",
        "exe" | "msi" | "dmg" | "apk" | "deb" | "rpm" => "Program",
        _ => "Other",
    }
}

/// eMule sends FT_FILETYPE as short codes ("Audio","Video","Pro","Doc","Image",
/// "Arc","Iso"). Normalize to our display categories; unknown values pass through.
fn normalize_type(tag: &str) -> String {
    match tag {
        "Audio" => "Audio",
        "Video" => "Video",
        "Pro" => "Program",
        "Doc" => "Document",
        "Image" => "Image",
        "Arc" | "Iso" => "Archive",
        other => other,
    }
    .to_string()
}

/// Fold raw search results into a ranked, deduped catalog. Ranks Ok-trust files
/// above suspect ones, then by availability (descending).
pub fn catalog(files: &[SearchResultFile]) -> Vec<RankedFile> {
    let mut groups: BTreeMap<[u8; 16], Group> = BTreeMap::new();
    for f in files {
        let g = groups.entry(f.hash).or_default();
        if let Some(sz) = tag_u64(&f.tags, FT_FILESIZE) {
            if sz > 0 {
                *g.sizes.entry(sz).or_default() += 1;
            }
        }
        if let Some(n) = tag_str(&f.tags, FT_FILENAME) {
            *g.names.entry(n).or_default() += 1;
        }
        let src = tag_u64(&f.tags, FT_SOURCES)
            .or_else(|| tag_u64(&f.tags, FT_COMPLETE_SOURCES))
            .unwrap_or(0) as u32;
        g.sources = g.sources.max(src);
        g.complete = g
            .complete
            .max(tag_u64(&f.tags, FT_COMPLETE_SOURCES).unwrap_or(0) as u32);
        if let Some(t) = tag_str(&f.tags, FT_FILETYPE) {
            if !t.is_empty() {
                *g.types.entry(t).or_default() += 1;
            }
        }
        // First non-empty media value wins (duplicates agree, or the tag is absent).
        let set_if_empty = |dst: &mut String, v: Option<String>| {
            if dst.is_empty() {
                if let Some(v) = v {
                    if !v.is_empty() {
                        *dst = v;
                    }
                }
            }
        };
        set_if_empty(&mut g.artist, tag_str(&f.tags, FT_MEDIA_ARTIST));
        set_if_empty(&mut g.album, tag_str(&f.tags, FT_MEDIA_ALBUM));
        set_if_empty(&mut g.title, tag_str(&f.tags, FT_MEDIA_TITLE));
        set_if_empty(&mut g.codec, tag_str(&f.tags, FT_MEDIA_CODEC));
        if g.length == 0 {
            g.length = tag_u64(&f.tags, FT_MEDIA_LENGTH).unwrap_or(0) as u32;
        }
        if g.bitrate == 0 {
            g.bitrate = tag_u64(&f.tags, FT_MEDIA_BITRATE).unwrap_or(0) as u32;
        }
        // Server rating (sparse; most servers do not populate it). aMule averages
        // the ratings across a hash's rated rows (SearchFile.cpp:299-300), so a
        // lone spoofed "Excellent" cannot bury a chorus of "Fake" - accumulate
        // sum + count of the RATED rows and divide at the end.
        if let Some(r) = tag_u64(&f.tags, FT_FILERATING) {
            let decoded = decode_rating(r);
            if decoded > 0 {
                g.rating_sum += decoded as u32;
                g.rating_count += 1;
            }
        }
    }

    let mut out: Vec<RankedFile> = groups
        .into_iter()
        .map(|(hash, g)| {
            // Most-common size and name win.
            let (size, _) = g
                .sizes
                .iter()
                .max_by_key(|(_, c)| **c)
                .map(|(s, c)| (*s, *c))
                .unwrap_or((0, 0));
            let name = g
                .names
                .iter()
                .max_by_key(|(_, c)| **c)
                .map(|(n, _)| n.clone())
                .unwrap_or_default();
            let name_variants = g.names.len();
            // Average rating over rated rows (integer, aMule-style); 0 = unrated.
            let rating = g.rating_sum.checked_div(g.rating_count).unwrap_or(0) as u8;
            let trust = if g.sizes.len() > 1 {
                Trust::Suspect("sources disagree on size for this hash")
            } else if size == 0 {
                Trust::Suspect("no advertised size")
            } else if rating == 1 {
                // eMule rating 1 = Invalid/Corrupt/Fake.
                Trust::Suspect("rated fake")
            } else if g.sources == 0 && name_variants > 3 {
                Trust::Suspect("many names, no sources")
            } else {
                Trust::Ok
            };
            let file_type = g
                .types
                .iter()
                .max_by_key(|(_, c)| **c)
                .map(|(t, _)| normalize_type(t))
                .unwrap_or_else(|| infer_type(&name).to_string());
            RankedFile {
                hash,
                size,
                name,
                sources: g.sources,
                name_variants,
                trust,
                complete_sources: g.complete,
                file_type,
                artist: g.artist,
                album: g.album,
                title: g.title,
                length_secs: g.length,
                bitrate: g.bitrate,
                codec: g.codec,
                rating,
            }
        })
        .collect();

    // Ok before Suspect, then most available first, then a stable name order.
    out.sort_by(|a, b| {
        let ta = matches!(a.trust, Trust::Ok);
        let tb = matches!(b.trust, Trust::Ok);
        tb.cmp(&ta)
            .then(b.sources.cmp(&a.sources))
            .then(a.name.cmp(&b.name))
    });
    out
}

impl RankedFile {
    /// True if this file looks safe enough to auto-download.
    pub fn is_trusted(&self) -> bool {
        matches!(self.trust, Trust::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::Tag;

    #[test]
    fn rating_tag_decodes_and_a_fake_is_flagged() {
        // FT_FILERATING is masked: aMule reads (value & 0xF) / 3. So a raw 15
        // decodes to 5 (Excellent) and a raw 3 decodes to 1 (Fake).
        assert_eq!(decode_rating(15), 5);
        assert_eq!(decode_rating(12), 4);
        assert_eq!(decode_rating(3), 1);
        assert_eq!(decode_rating(0), 0);
        assert_eq!(decode_rating(0xFF), 5); // high bits ignored, clamped

        // Build the rating tag as UINT8 - the natural wire encoding for a value
        // <= 0xFF. tag_u64 MUST read it (a U8-only reader once dropped it, so a
        // fake was silently shown Trusted).
        let rated = |hash: [u8; 16], raw: u8| SearchResultFile {
            hash,
            id: 0,
            port: 0,
            tags: vec![
                Tag {
                    name: TagName::Id(FT_FILENAME),
                    value: TagValue::Str(b"f.bin".to_vec()),
                },
                Tag {
                    name: TagName::Id(FT_FILESIZE),
                    value: TagValue::U32(100),
                },
                Tag {
                    name: TagName::Id(FT_SOURCES),
                    value: TagValue::U32(5),
                },
                Tag {
                    name: TagName::Id(FT_FILERATING),
                    value: TagValue::U8(raw),
                },
            ],
        };
        // Excellent (raw 15 -> 5): trusted, rating carried (via the U8 path).
        let good = catalog(&[rated([0x01; 16], 15)]);
        assert_eq!(good[0].rating, 5);
        assert!(good[0].is_trusted());
        // Fake (raw 3 -> 1): flagged suspect and not trusted.
        let fake = catalog(&[rated([0x02; 16], 3)]);
        assert_eq!(fake[0].rating, 1);
        assert!(!fake[0].is_trusted());
        assert!(matches!(fake[0].trust, Trust::Suspect(_)));

        // AVERAGE, not max (aMule SearchFile.cpp:299): three Fake rows and one
        // Fair row average to 1 (Fake), so a lone dissenting rating cannot bury
        // the chorus - the file is still flagged.
        let mixed = catalog(&[
            rated([0x03; 16], 3),  // 1 (Fake)
            rated([0x03; 16], 3),  // 1
            rated([0x03; 16], 3),  // 1
            rated([0x03; 16], 12), // 4 (Good)
        ]);
        assert_eq!(mixed[0].rating, 1, "avg (1+1+1+4)/4 = 1, not max 4");
        assert!(!mixed[0].is_trusted());
    }

    fn result(hash: [u8; 16], name: &str, size: u64, sources: u32) -> SearchResultFile {
        SearchResultFile {
            hash,
            id: 0,
            port: 0,
            tags: vec![
                Tag {
                    name: TagName::Id(FT_FILENAME),
                    value: TagValue::Str(name.as_bytes().to_vec()),
                },
                Tag {
                    name: TagName::Id(FT_FILESIZE),
                    value: TagValue::U32(size as u32),
                },
                Tag {
                    name: TagName::Id(FT_SOURCES),
                    value: TagValue::U32(sources),
                },
            ],
        }
    }

    fn media_result(hash: [u8; 16], name: &str, size: u64, sources: u32) -> SearchResultFile {
        SearchResultFile {
            hash,
            id: 0,
            port: 0,
            tags: vec![
                Tag {
                    name: TagName::Id(FT_FILENAME),
                    value: TagValue::Str(name.as_bytes().to_vec()),
                },
                Tag {
                    name: TagName::Id(FT_FILESIZE),
                    value: TagValue::U32(size as u32),
                },
                Tag {
                    name: TagName::Id(FT_SOURCES),
                    value: TagValue::U32(sources),
                },
                Tag {
                    name: TagName::Id(FT_COMPLETE_SOURCES),
                    value: TagValue::U32(7),
                },
                Tag {
                    name: TagName::Id(FT_FILETYPE),
                    value: TagValue::Str(b"Audio".to_vec()),
                },
                Tag {
                    name: TagName::Id(FT_MEDIA_ARTIST),
                    value: TagValue::Str(b"Some Artist".to_vec()),
                },
                Tag {
                    name: TagName::Id(FT_MEDIA_ALBUM),
                    value: TagValue::Str(b"Some Album".to_vec()),
                },
                Tag {
                    name: TagName::Id(FT_MEDIA_TITLE),
                    value: TagValue::Str(b"Some Title".to_vec()),
                },
                Tag {
                    name: TagName::Id(FT_MEDIA_LENGTH),
                    value: TagValue::U32(225),
                },
                Tag {
                    name: TagName::Id(FT_MEDIA_BITRATE),
                    value: TagValue::U32(192),
                },
                Tag {
                    name: TagName::Id(FT_MEDIA_CODEC),
                    value: TagValue::Str(b"mp3".to_vec()),
                },
            ],
        }
    }

    #[test]
    fn catalog_surfaces_type_media_and_complete_sources() {
        let cat = catalog(&[media_result([9u8; 16], "song.mp3", 5_000_000, 40)]);
        assert_eq!(cat.len(), 1);
        let f = &cat[0];
        assert_eq!(f.complete_sources, 7);
        assert_eq!(f.file_type, "Audio");
        assert_eq!(f.artist, "Some Artist");
        assert_eq!(f.album, "Some Album");
        assert_eq!(f.title, "Some Title");
        assert_eq!(f.length_secs, 225);
        assert_eq!(f.bitrate, 192);
        assert_eq!(f.codec, "mp3");
    }

    #[test]
    fn file_type_is_inferred_from_extension_when_no_tag() {
        // No FT_FILETYPE tag -> inferred from ".avi"; no complete-sources -> 0.
        let cat = catalog(&[result([1u8; 16], "movie.avi", 700_000_000, 3)]);
        assert_eq!(cat[0].file_type, "Video");
        assert_eq!(cat[0].complete_sources, 0);
    }

    #[test]
    fn dedups_by_hash_and_aggregates_sources() {
        let h = [1u8; 16];
        let files = vec![
            result(h, "movie.avi", 1000, 5),
            result(h, "movie.avi", 1000, 12), // same file, higher availability
            result([2u8; 16], "other.avi", 2000, 3),
        ];
        let cat = catalog(&files);
        assert_eq!(cat.len(), 2, "the duplicate hash collapses to one entry");
        let m = cat.iter().find(|r| r.hash == h).unwrap();
        assert_eq!(m.sources, 12, "best availability is kept");
        assert_eq!(m.size, 1000);
        assert!(m.is_trusted());
    }

    #[test]
    fn ranks_more_available_first() {
        let cat = catalog(&[
            result([1u8; 16], "a", 10, 2),
            result([2u8; 16], "b", 10, 50),
            result([3u8; 16], "c", 10, 9),
        ]);
        let by_src: Vec<u32> = cat.iter().map(|r| r.sources).collect();
        assert_eq!(by_src, vec![50, 9, 2], "descending availability");
    }

    #[test]
    fn size_disagreement_for_one_hash_is_suspect() {
        let h = [7u8; 16];
        // A hash uniquely determines content, so two sizes = lying metadata.
        let cat = catalog(&[
            result(h, "real.pdf", 1000, 8),
            result(h, "fake.pdf", 9999, 8),
        ]);
        assert_eq!(cat.len(), 1);
        assert_eq!(
            cat[0].trust,
            Trust::Suspect("sources disagree on size for this hash")
        );
        assert!(!cat[0].is_trusted());
        assert_eq!(cat[0].name_variants, 2);
    }

    #[test]
    fn suspect_files_rank_below_trusted() {
        let good = result([1u8; 16], "good", 100, 1);
        let bad_a = result([2u8; 16], "x", 100, 99);
        let bad_b = result([2u8; 16], "y", 200, 99); // size disagreement -> suspect
        let cat = catalog(&[good, bad_a, bad_b]);
        // The suspect file has WAY more sources, but trust wins the sort.
        assert!(cat[0].is_trusted());
        assert_eq!(cat[0].hash, [1u8; 16]);
    }
}
