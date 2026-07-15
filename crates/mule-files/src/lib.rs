//! mule-files: byte-compatible readers/writers for aMule/eMule on-disk formats
//! (server.met, known.met, part.met, nodes.dat, ...). Built on `mule-proto`.
//! See docs/wiki/protocol-reference.md.

pub mod clients_met;
pub mod known_met;
pub mod nodes_dat;
pub mod part_met;
pub mod preferences;
pub mod server_met;

pub use clients_met::{
    read_clients_met, write_clients_met, ClientsMet, CreditEntry, CREDIT_EXPIRE_SECS,
    CREDIT_FILE_VERSION,
};
pub use known_met::{read_known_met, write_known_met, KnownFileEntry, KnownMet};
pub use nodes_dat::{read_nodes_dat, write_nodes_dat, KadContact, NodesDat};
pub use part_met::{gap_tags, gaps, read_part_met, write_part_met, Gap, PartMet};
pub use preferences::{
    read_kad_prefs, read_preferences_dat, write_kad_prefs, write_preferences_dat, KadPrefs,
    PREFFILE_VERSION,
};
pub use server_met::{read_server_met, write_server_met, Server, ServerMet};
