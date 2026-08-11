//! The whole Kad UDP receive path: obfuscation, framing, message decoding
//! (`mule_kad::udp_obf`, `::frame`, `::message`).
//!
//! Attacker input: a raw datagram from any host on the internet. This is
//! padMule's most exposed surface - no handshake, no connection, no source
//! check. `kad_live` runs exactly this sequence: try to deobfuscate, then
//! `unpack_kad`, then dispatch on the opcode byte.
//!
//! The keys are FIXED constants so the target stays deterministic (libFuzzer
//! requires that a crashing input reproduce). A fuzzed datagram will not
//! decrypt to the sync sentinel, so the obfuscation call mostly exercises the
//! reject paths; the plaintext dispatch below is where the message decoders
//! actually get their bytes.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mule_kad::{
    kad_deobfuscate, kad_filename_matches, kad_keyword_target, kad_keywords, kad_primary_keyword,
    parse_bootstrap_res, parse_hello, parse_hello_res_ack, parse_kad2_req, parse_kad2_res,
    parse_publish_res, parse_search_res, unpack_kad, OP_BOOTSTRAP_RES, OP_HELLO_REQ, OP_HELLO_RES,
    OP_HELLO_RES_ACK, OP_KAD2_REQ, OP_KAD2_RES, OP_PUBLISH_RES, OP_SEARCH_RES,
};
use mule_proto::Kad128;

fuzz_target!(|data: &[u8]| {
    let our_id = Kad128::from_hash(&[0x11; 16]);
    // Stage 1: the first code a hostile datagram meets.
    let _ = kad_deobfuscate(data, &our_id, 0xDEAD_BEEF, 0x0A00_0001);

    // Stage 2: the plaintext frame (0xE4 raw, or 0xE5 zlib-packed - unpack_kad
    // bounds the inflation itself at len*10+300).
    let Ok((opcode, payload)) = unpack_kad(data) else {
        return;
    };

    // Stage 3: opcode dispatch, mirroring kad_live's match.
    match opcode {
        OP_BOOTSTRAP_RES => {
            let _ = parse_bootstrap_res(&payload);
        }
        OP_HELLO_REQ | OP_HELLO_RES => {
            let _ = parse_hello(&payload);
        }
        OP_HELLO_RES_ACK => {
            let _ = parse_hello_res_ack(&payload);
        }
        OP_KAD2_REQ => {
            let _ = parse_kad2_req(&payload);
        }
        OP_KAD2_RES => {
            let _ = parse_kad2_res(&payload);
        }
        OP_PUBLISH_RES => {
            let _ = parse_publish_res(&payload);
        }
        OP_SEARCH_RES => {
            let Ok(res) = parse_search_res(&payload) else {
                return;
            };
            for r in &res.results {
                let _ = r.as_source();
                // A keyword hit's filename is attacker text that then goes
                // through the keyword splitter and the hash target - the same
                // string handling a search reply drives in production.
                if let Some(f) = r.as_file() {
                    let _ = kad_keywords(&f.name);
                    let _ = kad_filename_matches(&f.name, "padmule");
                    if let Some(k) = kad_primary_keyword(&f.name) {
                        let _ = kad_keyword_target(&k);
                    }
                }
            }
        }
        _ => {}
    }
});
