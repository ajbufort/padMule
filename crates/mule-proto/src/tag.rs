//! eD2k MET-format tags: `u8` type, a name (numeric id or byte string), and a
//! typed value. Values preserve their on-disk width and bytes so writing a
//! parsed tag reproduces the input bit-for-bit. See
//! docs/wiki/protocol-reference.md.
//!
//! Divergences from a fully general eD2k tag codec, matching aMule's MET file
//! writers: `write_tag` never emits the compact `(type | 0x80)` short form or
//! the inline STR1..STR16 types; those are accepted on read only.
//!
//! Deliberate choices (not bugs):
//! - UINT8/UINT16 values are PRESERVED at their on-disk width. aMule's reader
//!   promotes them to UINT32 (Tag.cpp:123-131), so aMule re-writes them wider;
//!   preserving is strictly more faithful to the source file for a byte-exact
//!   round-trip, and aMule reads UINT8/UINT16 back with no trouble.
//! - BOOL (0x05) and BOOLARRAY (0x06) are accepted for robustness (aMule reads
//!   and skips them, Tag.cpp:142-155); no aMule .met writer emits them. We
//!   preserve their raw bytes so they still round-trip. BOOLARRAY keeps aMule's
//!   `(bit_len/8)+1` payload-length quirk verbatim.
//! - A `TagName::Str` of exactly one byte is NOT representable: the format
//!   reserves name-length==1 for a numeric id, so such a name reads back as
//!   `TagName::Id`. This ambiguity is inherent to eD2k, not specific to us.

use crate::io::{IoError, Reader, Writer};

// Tag type bytes (src/include/tags/TagTypes.h).
const TAGTYPE_HASH16: u8 = 0x01;
const TAGTYPE_STRING: u8 = 0x02;
const TAGTYPE_UINT32: u8 = 0x03;
const TAGTYPE_FLOAT32: u8 = 0x04;
const TAGTYPE_BOOL: u8 = 0x05;
const TAGTYPE_BOOLARRAY: u8 = 0x06;
const TAGTYPE_BLOB: u8 = 0x07;
const TAGTYPE_UINT16: u8 = 0x08;
const TAGTYPE_UINT8: u8 = 0x09;
const TAGTYPE_BSOB: u8 = 0x0A;
const TAGTYPE_UINT64: u8 = 0x0B;
const TAGTYPE_STR1: u8 = 0x11;
const TAGTYPE_STR16: u8 = 0x20;

/// A tag's name: either a single-byte numeric id (the common eD2k case) or a
/// byte string (Latin-1 on disk).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TagName {
    Id(u8),
    Str(Vec<u8>),
}

/// A tag's typed value, preserving the on-disk representation.
#[derive(Debug, Clone, PartialEq)]
pub enum TagValue {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    F32(f32),
    Hash([u8; 16]),
    /// Raw string bytes (usually UTF-8; may carry a leading BOM from eMule).
    Str(Vec<u8>),
    /// uint32-length blob.
    Blob(Vec<u8>),
    /// uint8-length blob (aMule BSOB, e.g. legacy 8-byte filesize).
    Bsob(Vec<u8>),
    /// A single boolean byte (TAGTYPE_BOOL). aMule reads and discards these; we
    /// keep the byte so the tag round-trips.
    Bool(u8),
    /// A bit array (TAGTYPE_BOOLARRAY): `bit_len` bits stored in `data`, whose
    /// length is aMule's `(bit_len / 8) + 1` bytes (the quirk is preserved).
    BoolArray {
        bit_len: u16,
        data: Vec<u8>,
    },
}

/// One eD2k tag.
#[derive(Debug, Clone, PartialEq)]
pub struct Tag {
    pub name: TagName,
    pub value: TagValue,
}

impl Tag {
    /// Convenience constructor for a numeric-id tag.
    pub fn id(id: u8, value: TagValue) -> Self {
        Tag {
            name: TagName::Id(id),
            value,
        }
    }
}

/// Read one MET-format tag.
pub fn read_tag(r: &mut Reader) -> Result<Tag, IoError> {
    let raw_type = r.read_u8()?;
    let (tagtype, name) = if raw_type & 0x80 != 0 {
        // Compact short form: high bit set, single-byte id, no length prefix.
        (raw_type & 0x7f, TagName::Id(r.read_u8()?))
    } else {
        let namelen = r.read_u16()?;
        let name = if namelen == 1 {
            TagName::Id(r.read_u8()?)
        } else {
            TagName::Str(r.read_bytes(namelen as usize)?)
        };
        (raw_type, name)
    };

    let value = read_value(r, tagtype)?;
    Ok(Tag { name, value })
}

fn read_value(r: &mut Reader, tagtype: u8) -> Result<TagValue, IoError> {
    let value = match tagtype {
        TAGTYPE_HASH16 => {
            let mut h = [0u8; 16];
            h.copy_from_slice(&r.read_bytes(16)?);
            TagValue::Hash(h)
        }
        TAGTYPE_STRING => TagValue::Str(r.read_string_u16()?),
        TAGTYPE_UINT32 => TagValue::U32(r.read_u32()?),
        TAGTYPE_FLOAT32 => TagValue::F32(f32::from_le_bytes(
            r.read_bytes(4)?.try_into().expect("4 bytes"),
        )),
        TAGTYPE_BOOL => TagValue::Bool(r.read_u8()?),
        TAGTYPE_BOOLARRAY => {
            let bit_len = r.read_u16()?;
            // aMule reads (bit_len/8)+1 bytes here (SafeFile/Tag.cpp:147-154);
            // the off-by-one is intentional compat, kept verbatim.
            let nbytes = (bit_len / 8) as usize + 1;
            TagValue::BoolArray {
                bit_len,
                data: r.read_bytes(nbytes)?,
            }
        }
        TAGTYPE_BLOB => {
            let len = r.read_u32()? as usize;
            TagValue::Blob(r.read_bytes(len)?)
        }
        TAGTYPE_UINT16 => TagValue::U16(r.read_u16()?),
        TAGTYPE_UINT8 => TagValue::U8(r.read_u8()?),
        TAGTYPE_BSOB => {
            let len = r.read_u8()? as usize;
            TagValue::Bsob(r.read_bytes(len)?)
        }
        TAGTYPE_UINT64 => TagValue::U64(r.read_u64()?),
        // Inline fixed-length strings STR1..STR16 (read only).
        t if (TAGTYPE_STR1..=TAGTYPE_STR16).contains(&t) => {
            let len = (t - TAGTYPE_STR1 + 1) as usize;
            TagValue::Str(r.read_bytes(len)?)
        }
        other => return Err(IoError::BadTag(other)),
    };
    Ok(value)
}

/// Write one MET-format tag (non-compact form, matching aMule file writers).
pub fn write_tag(w: &mut Writer, tag: &Tag) {
    w.write_u8(value_type(&tag.value));
    match &tag.name {
        TagName::Id(id) => {
            w.write_u16(1);
            w.write_u8(*id);
        }
        // write_string_u16 caps at u16::MAX so the length prefix and byte count
        // stay consistent. (A 1-byte string name is unrepresentable and reads
        // back as TagName::Id; see the module docs.)
        TagName::Str(bytes) => w.write_string_u16(bytes),
    }
    write_value(w, &tag.value);
}

fn value_type(v: &TagValue) -> u8 {
    match v {
        TagValue::U8(_) => TAGTYPE_UINT8,
        TagValue::U16(_) => TAGTYPE_UINT16,
        TagValue::U32(_) => TAGTYPE_UINT32,
        TagValue::U64(_) => TAGTYPE_UINT64,
        TagValue::F32(_) => TAGTYPE_FLOAT32,
        TagValue::Hash(_) => TAGTYPE_HASH16,
        TagValue::Str(_) => TAGTYPE_STRING,
        TagValue::Blob(_) => TAGTYPE_BLOB,
        TagValue::Bsob(_) => TAGTYPE_BSOB,
        TagValue::Bool(_) => TAGTYPE_BOOL,
        TagValue::BoolArray { .. } => TAGTYPE_BOOLARRAY,
    }
}

fn write_value(w: &mut Writer, v: &TagValue) {
    match v {
        TagValue::U8(x) => w.write_u8(*x),
        TagValue::U16(x) => w.write_u16(*x),
        TagValue::U32(x) => w.write_u32(*x),
        TagValue::U64(x) => w.write_u64(*x),
        TagValue::F32(x) => w.write_bytes(&x.to_le_bytes()),
        TagValue::Hash(h) => w.write_bytes(h),
        TagValue::Str(b) => w.write_string_u16(b),
        TagValue::Blob(b) => {
            // Cap the length so the u32 prefix and payload stay consistent.
            let n = b.len().min(u32::MAX as usize);
            w.write_u32(n as u32);
            w.write_bytes(&b[..n]);
        }
        TagValue::Bsob(b) => {
            // BSOB length is a single byte; cap so prefix and payload agree.
            let n = b.len().min(u8::MAX as usize);
            w.write_u8(n as u8);
            w.write_bytes(&b[..n]);
        }
        TagValue::Bool(x) => w.write_u8(*x),
        TagValue::BoolArray { bit_len, data } => {
            w.write_u16(*bit_len);
            w.write_bytes(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_uint32_id_tag() {
        // FT_FILESIZE-style: type UINT32, numeric id 0x01, value 0x12345678.
        let bytes = vec![0x03, 0x01, 0x00, 0x01, 0x78, 0x56, 0x34, 0x12];
        let mut r = Reader::new(&bytes);
        let tag = read_tag(&mut r).unwrap();
        assert_eq!(tag, Tag::id(0x01, TagValue::U32(0x12345678)));
        assert_eq!(r.remaining(), 0);

        let mut w = Writer::new();
        write_tag(&mut w, &tag);
        assert_eq!(w.into_inner(), bytes);
    }

    #[test]
    fn golden_string_id_tag() {
        // type STRING, numeric id 0x01, value "abc".
        let bytes = vec![0x02, 0x01, 0x00, 0x01, 0x03, 0x00, b'a', b'b', b'c'];
        let mut r = Reader::new(&bytes);
        let tag = read_tag(&mut r).unwrap();
        assert_eq!(tag, Tag::id(0x01, TagValue::Str(b"abc".to_vec())));

        let mut w = Writer::new();
        write_tag(&mut w, &tag);
        assert_eq!(w.into_inner(), bytes);
    }

    #[test]
    fn hash16_and_string_named_tag_round_trip() {
        let tags = vec![
            Tag::id(0x02, TagValue::Hash([0xAB; 16])),
            Tag {
                name: TagName::Str(b"emVersion".to_vec()),
                value: TagValue::U64(0x0102030405060708),
            },
        ];
        for t in tags {
            let mut w = Writer::new();
            write_tag(&mut w, &t);
            let bytes = w.into_inner();
            let mut r = Reader::new(&bytes);
            assert_eq!(read_tag(&mut r).unwrap(), t);
            assert_eq!(r.remaining(), 0);
        }
    }

    #[test]
    fn compact_form_reads_but_writes_noncompact() {
        // Compact: (UINT32 | 0x80), id 0x10, then 4 LE bytes.
        let bytes = vec![0x83, 0x10, 0x21, 0x43, 0x65, 0x87];
        let mut r = Reader::new(&bytes);
        let tag = read_tag(&mut r).unwrap();
        assert_eq!(tag, Tag::id(0x10, TagValue::U32(0x87654321)));

        // Re-writing yields the non-compact MET form, per aMule file writers.
        let mut w = Writer::new();
        write_tag(&mut w, &tag);
        assert_eq!(
            w.into_inner(),
            vec![0x03, 0x01, 0x00, 0x10, 0x21, 0x43, 0x65, 0x87]
        );
    }

    #[test]
    fn inline_str3_reads_as_string() {
        // STR3 (0x13), numeric id 0x01, 3 inline bytes "xyz".
        let bytes = vec![0x13, 0x01, 0x00, 0x01, b'x', b'y', b'z'];
        let mut r = Reader::new(&bytes);
        let tag = read_tag(&mut r).unwrap();
        assert_eq!(tag, Tag::id(0x01, TagValue::Str(b"xyz".to_vec())));
    }

    #[test]
    fn unknown_type_errors() {
        let bytes = vec![0x7f, 0x01, 0x00, 0x01];
        let mut r = Reader::new(&bytes);
        assert_eq!(read_tag(&mut r), Err(IoError::BadTag(0x7f)));
    }

    #[test]
    fn bool_tag_round_trips() {
        // aMule tolerates BOOL (0x05); we preserve the byte. id 0x01, value 0x2A.
        let bytes = vec![0x05, 0x01, 0x00, 0x01, 0x2A];
        let mut r = Reader::new(&bytes);
        let tag = read_tag(&mut r).unwrap();
        assert_eq!(tag, Tag::id(0x01, TagValue::Bool(0x2A)));
        let mut w = Writer::new();
        write_tag(&mut w, &tag);
        assert_eq!(w.into_inner(), bytes);
    }

    #[test]
    fn boolarray_tag_round_trips_with_amule_length_quirk() {
        // BOOLARRAY (0x06), id 0x01, bit_len=16 -> (16/8)+1 = 3 payload bytes.
        let bytes = vec![0x06, 0x01, 0x00, 0x01, 0x10, 0x00, 0xAA, 0xBB, 0xCC];
        let mut r = Reader::new(&bytes);
        let tag = read_tag(&mut r).unwrap();
        assert_eq!(
            tag,
            Tag::id(
                0x01,
                TagValue::BoolArray {
                    bit_len: 16,
                    data: vec![0xAA, 0xBB, 0xCC],
                }
            )
        );
        assert_eq!(r.remaining(), 0);
        let mut w = Writer::new();
        write_tag(&mut w, &tag);
        assert_eq!(w.into_inner(), bytes);
    }
}
