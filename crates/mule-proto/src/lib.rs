//! mule-proto: pure eD2k/Kad codec and crypto primitives for padMule.
//! No I/O. See docs/wiki/protocol-reference.md.

pub mod aich;
pub mod hash;
pub mod io;
pub mod kad_id;
pub mod link;
pub mod obf;
pub mod packet;
pub mod rc4;
pub mod tag;

pub use aich::{aich_master_hash, EMBLOCKSIZE};
pub use hash::{ed2k_hash, md4, part_count, OLD_MAX_FILE_SIZE, PARTSIZE};
pub use io::{IoError, Reader, Writer};
pub use kad_id::Kad128;
pub use link::{parse_link, Ed2kLink, FileLink};
pub use obf::{
    build_initiator_handshake, is_plaintext_marker, semi_random_marker, tcp_cipher, StreamCiphers,
    MAGICVALUE_REQUESTER, MAGICVALUE_SERVER, MAGICVALUE_SYNC, TCP_RC4_DISCARD,
};
pub use packet::{
    compress, decompress, read_packet, write_packet, Packet, MAX_PACKET_SIZE, PROT_EDONKEY,
    PROT_EMULE, PROT_KAD, PROT_KAD_PACKED, PROT_PACKED,
};
pub use rc4::Rc4;
pub use tag::{read_tag, write_tag, Tag, TagName, TagValue};
