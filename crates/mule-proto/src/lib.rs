//! mule-proto: pure eD2k/Kad codec and crypto primitives for padMule.
//! No I/O. See docs/wiki/protocol-reference.md.

pub mod hash;
pub mod io;
pub mod packet;
pub mod tag;

pub use hash::{ed2k_hash, md4, part_count, OLD_MAX_FILE_SIZE, PARTSIZE};
pub use io::{IoError, Reader, Writer};
pub use packet::{
    compress, decompress, read_packet, write_packet, Packet, MAX_PACKET_SIZE, PROT_EDONKEY,
    PROT_EMULE, PROT_KAD, PROT_KAD_PACKED, PROT_PACKED,
};
pub use tag::{read_tag, write_tag, Tag, TagName, TagValue};
