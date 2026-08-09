//! mule-files: byte-compatible readers/writers for aMule/eMule on-disk formats
//! (server.met, known.met, part.met, nodes.dat, ...). Built on `mule-proto`.
//! See docs/wiki/protocol-reference.md.

pub mod clients_met;
pub mod ipfilter;
pub mod known2_met;
pub mod known_met;
pub mod nodes_dat;
pub mod part_met;
pub mod pins;
pub mod preferences;
pub mod server_met;

pub use clients_met::{
    read_clients_met, write_clients_met, ClientsMet, CreditEntry, CREDIT_EXPIRE_SECS,
    CREDIT_FILE_VERSION,
};
pub use ipfilter::{IpFilter, DEFAULT_IPFILTER_LEVEL};
pub use known2_met::{
    empty_known2_met, known2_entry_bytes, read_known2_entry, read_known2_met, remove_known2_entry,
    scan_known2_met, Known2Entry, Known2Index, KNOWN2_MET_VERSION,
};
pub use known_met::{
    read_known_met, write_known_met, KnownFileEntry, KnownMet, MET_HEADER,
    MET_HEADER_WITH_LARGEFILES,
};
pub use nodes_dat::{read_nodes_dat, write_nodes_dat, KadContact, NodesDat};
pub use part_met::{gap_tags, gaps, read_part_met, write_part_met, Gap, PartMet};
pub use pins::{read_pins, write_pins};
pub use preferences::{
    read_kad_prefs, read_preferences_dat, write_kad_prefs, write_preferences_dat, KadPrefs,
    PREFFILE_VERSION,
};
pub use server_met::{merge_server_met, read_server_met, write_server_met, Server, ServerMet};

/// Decode an eD2k `.met`-convention IP `u32` (read little-endian, so the FIRST
/// dotted-quad octet sits in the LOW byte) into a host-order `Ipv4Addr`.
///
/// THE ONE CONVERSION, defined once. Four private copies of this function used
/// to exist (`engine`, `mule-cli`, `fetch::ed2k_ip`, `server_crawl`'s inline
/// spelling) while the byte-order confusion around it produced a real bug three
/// times over - the user's IP blocklist consulted with a byte-reversed address
/// at three separate sites (rows 8cq/8ct). One definition, one doc, one test.
///
/// NEVER hand the raw met u32 to a HOST-order consumer such as
/// `IpFilter::is_blocked_u32`; convert first: `u32::from(ip_from_met_u32(x))`.
/// And do NOT apply this to a Kad contact's `ip` (`KadContact` /
/// `mule_kad::WireContact`) - those are ALREADY host order (first octet in the
/// HIGH byte); "met-converting" one is the same bug in the other direction.
///
/// Spelled with `to_le_bytes` rather than a byte-shift chain or `to_be()`, so
/// it stays correct on a big-endian target.
pub fn ip_from_met_u32(ip: u32) -> std::net::Ipv4Addr {
    std::net::Ipv4Addr::from(ip.to_le_bytes())
}

#[cfg(test)]
mod tests {
    #[test]
    fn met_u32_low_byte_is_the_first_octet() {
        // The server.met golden convention: 127.0.0.1 stores as 0x0100007F.
        assert_eq!(
            super::ip_from_met_u32(0x0100_007F),
            std::net::Ipv4Addr::new(127, 0, 0, 1)
        );
        // CONTRAST with the Kad-contact convention on the SAME u32: a Kad
        // contact holding 0x050607FA means 5.6.7.250 (host order - first
        // octet in the HIGH byte), while the met reading of that value is the
        // reversed 250.7.6.5. Applying this function to a Kad ip - or
        // skipping it on a met ip - swaps every address end for end, which is
        // precisely the three-times-fixed blocklist bug.
        assert_eq!(
            super::ip_from_met_u32(0x0506_07FA),
            std::net::Ipv4Addr::new(250, 7, 6, 5)
        );
    }
}
