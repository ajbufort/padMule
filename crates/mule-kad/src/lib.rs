//! mule-kad: the Kademlia DHT for padMule (routing table, node IDs, and - in
//! later slices - the UDP protocol, lookups, and source/keyword search).
//! See docs/raw/wave6-kad-research-2026-07-14.md.

pub mod routing;

pub use routing::{Contact, RoutingTable, K, KBASE, KK, MAXLEVELS};
