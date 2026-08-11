//! ipfilter.dat / .p2p blocklist parsing (`mule_files::ipfilter`).
//!
//! Attacker input: the blocklist is downloaded from a user-supplied URL, so the
//! whole file is remote text. It is also security-load-bearing - this is the
//! filter that decides which peers padMule will talk to - which makes a parse
//! panic here worse than a nuisance.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mule_files::{IpFilter, DEFAULT_IPFILTER_LEVEL};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // The level gate changes which lines survive, so fuzz two of them: the
    // shipped default and the permissive extreme.
    for level in [DEFAULT_IPFILTER_LEVEL, 0] {
        let f = IpFilter::parse(&text, level);
        let _ = f.len();
        // Exercise the range lookup on the parsed table, including the
        // boundaries a merged range is most likely to get wrong.
        for ip in [0u32, 1, 0x0A00_0001, 0x7F00_0001, 0xC0A8_0001, u32::MAX] {
            let _ = f.is_blocked_u32(ip);
        }
    }
});
