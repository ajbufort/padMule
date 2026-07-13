//! mule-files: byte-compatible readers/writers for aMule/eMule on-disk formats
//! (server.met, known.met, part.met, nodes.dat, ...). Built on `mule-proto`.
//! See docs/wiki/protocol-reference.md.

pub mod server_met;

pub use server_met::{read_server_met, write_server_met, Server, ServerMet};
