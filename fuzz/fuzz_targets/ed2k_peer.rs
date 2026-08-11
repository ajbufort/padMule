//! Peer-to-peer eD2k message payloads (`mule_engine::transfer`,
//! `mule_engine::peer`).
//!
//! Attacker input: the body of every packet a remote client sends us after the
//! TCP frame is stripped. Any peer in the swarm can send any of these at any
//! time, in any order - the funnel work of 2026-08-04 showed peers really do
//! send opcodes out of turn - so each decoder has to hold on arbitrary bytes.
//!
//! Multiplexed by a leading selector byte. The `i64` flavors (the >4GB variants
//! that swap u32 offsets for u64) get their own arms because the two lengths
//! are separate bounds arithmetic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mule_engine::peer::parse_hello;
use mule_engine::transfer::{
    parse_aich_answer, parse_aich_file_hash_ans, parse_aich_file_hash_req, parse_aich_request,
    parse_file_desc, parse_file_status, parse_hashset_answer, parse_multipacket_hash,
    parse_queue_ranking, parse_req_filename_answer, parse_request_parts, parse_sending_part,
};

fuzz_target!(|data: &[u8]| {
    let Some((&selector, p)) = data.split_first() else {
        return;
    };
    match selector % 14 {
        0 => {
            let _ = parse_hello(p, true);
        }
        1 => {
            let _ = parse_hello(p, false);
        }
        2 => {
            let _ = parse_file_desc(p);
        }
        3 => {
            let _ = parse_req_filename_answer(p);
        }
        4 => {
            let _ = parse_queue_ranking(p);
        }
        5 => {
            let _ = parse_file_status(p);
        }
        6 => {
            let _ = parse_sending_part(p, false);
        }
        7 => {
            let _ = parse_sending_part(p, true);
        }
        8 => {
            let _ = parse_multipacket_hash(p);
        }
        9 => {
            let _ = parse_request_parts(p, false);
        }
        10 => {
            let _ = parse_request_parts(p, true);
        }
        11 => {
            let _ = parse_hashset_answer(p);
        }
        12 => {
            let _ = parse_aich_file_hash_req(p);
            let _ = parse_aich_file_hash_ans(p);
        }
        _ => {
            let _ = parse_aich_request(p);
            let _ = parse_aich_answer(p);
        }
    }
});
