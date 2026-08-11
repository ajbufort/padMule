//! The on-disk `.met` / `.dat` readers (`mule_files`).
//!
//! Attacker input, in descending order of exposure:
//!   - `server.met` is DOWNLOADED from a user-configured URL, so it is a remote
//!     byte stream that merely happens to be spelled as a file format;
//!   - `nodes.dat` likewise (bootstrap lists are fetched);
//!   - `part.met` / `known.met` / `known2_64.met` / `clients.met` are local, but
//!     their contents are built from what peers told us, and a sideloaded app's
//!     config directory is not a trust boundary worth betting on.
//!
//! One target multiplexed by a leading selector byte: these readers share the
//! MET header/count/taglist shape, so a corpus entry that is interesting for
//! one is frequently interesting for another.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mule_files::{
    gaps, read_clients_met, read_kad_prefs, read_known2_entry, read_known2_met, read_known_met,
    read_nodes_dat, read_part_met, read_preferences_dat, read_server_met, remove_known2_entry,
    scan_known2_met, write_part_met,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    match selector % 7 {
        0 => {
            let _ = read_server_met(body);
        }
        1 => {
            let _ = read_known_met(body);
        }
        2 => {
            if let Ok(pm) = read_part_met(body) {
                // The gap derivation and the writer both consume the parsed
                // (attacker-shaped) tag set, so they are on the same path.
                let _ = gaps(&pm);
                let _ = write_part_met(&pm);
            }
        }
        3 => {
            let _ = read_nodes_dat(body);
        }
        4 => {
            let _ = read_clients_met(body);
        }
        5 => {
            if let Ok(idx) = scan_known2_met(body) {
                for (root, &off) in idx.by_root.iter() {
                    // Offsets come from the scan, which is the real caller's
                    // contract; the reader must still hold for a torn store.
                    let _ = read_known2_entry(body, off);
                    let _ = remove_known2_entry(body, root);
                }
            }
            let _ = read_known2_met(body);
        }
        _ => {
            let _ = read_preferences_dat(body);
            let _ = read_kad_prefs(body);
        }
    }
});
