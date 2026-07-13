//! mule-files: byte-compatible readers/writers for aMule/eMule on-disk formats
//! (server.met, known.met, part.met, nodes.dat, ...). Built on `mule-proto`.
//! See docs/wiki/protocol-reference.md.

pub mod known_met;
pub mod part_met;
pub mod server_met;

pub use known_met::{read_known_met, write_known_met, KnownFileEntry, KnownMet};
pub use part_met::{gap_tags, gaps, read_part_met, write_part_met, Gap, PartMet};
pub use server_met::{read_server_met, write_server_met, Server, ServerMet};
