//! mule-proto: pure eD2k/Kad codec and crypto primitives for padMule.
//! No I/O. See docs/wiki/protocol-reference.md.

pub mod hash;
pub mod io;
pub mod tag;

pub use hash::{ed2k_hash, md4, part_count, PARTSIZE};
pub use io::{IoError, Reader, Writer};
pub use tag::{read_tag, write_tag, Tag, TagName, TagValue};
