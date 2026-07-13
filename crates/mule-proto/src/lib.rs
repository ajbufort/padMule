//! mule-proto: pure eD2k/Kad codec and crypto primitives for padMule.
//! No I/O. See docs/wiki/protocol-reference.md.

pub mod hash;

pub use hash::{ed2k_hash, md4, part_count, PARTSIZE};
