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

fn tag_str(tags: &[mule_proto::Tag], id: u8) -> Option<String> {
    tags.iter().find_map(|t| match (&t.name, &t.value) {
        (TagName::Id(n), TagValue::Str(s)) if *n == id => {
            Some(String::from_utf8_lossy(s).into_owned())
        }
        _ => None,
    })
}

fn tag_u64(tags: &[mule_proto::Tag], id: u8) -> Option<u64> {
    tags.iter().find_map(|t| match (&t.name, &t.value) {
        (TagName::Id(n), TagValue::U32(v)) if *n == id => Some(*v as u64),
        (TagName::Id(n), TagValue::U64(v)) if *n == id => Some(*v),
        (TagName::Id(n), TagValue::U16(v)) if *n == id => Some(*v as u64),
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
}

#[derive(Default)]
struct Group {
    sizes: BTreeMap<u64, u32>, // size -> times seen (nonzero only)
    names: BTreeMap<String, u32>,
    sources: u32,
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
            let trust = if g.sizes.len() > 1 {
                Trust::Suspect("sources disagree on size for this hash")
            } else if size == 0 {
                Trust::Suspect("no advertised size")
            } else if g.sources == 0 && name_variants > 3 {
                Trust::Suspect("many names, no sources")
            } else {
                Trust::Ok
            };
            RankedFile {
                hash,
                size,
                name,
                sources: g.sources,
                name_variants,
                trust,
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
