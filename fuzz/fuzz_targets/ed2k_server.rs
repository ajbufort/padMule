//! Server-side and source-exchange eD2k payloads, plus the two decoders that
//! read text off a remote device (`mule_engine::server_messages`, `::search`,
//! `::sources`, `::secure_ident`, `::portmap`, `::upnp`).
//!
//! Attacker input: everything an eD2k server sends (search results, server
//! lists, ident, MOTD), everything a peer sends over source exchange, the
//! secure-identification blobs that feed the RSA verifier, the NAT-PMP reply
//! from whatever answers on the LAN gateway, and the IGD description XML
//! fetched over plain HTTP.
//!
//! Multiplexed by a leading selector byte.

#![no_main]

use libfuzzer_sys::fuzz_target;
use mule_engine::catalog::catalog;
use mule_engine::portmap::{parse_map_response, Proto};
use mule_engine::search::{parse_global_search_res, parse_search_result_page};
use mule_engine::secure_ident::{parse_public_key, parse_sec_ident_state, parse_signature};
use mule_engine::server_messages::{
    parse_id_change, parse_serv_stat_res, parse_server_desc_res, parse_server_ident,
    parse_server_list, parse_server_message, parse_server_status,
};
use mule_engine::sources::{
    parse_answer_sources, parse_callback_requested, parse_found_sources, parse_request_sources,
    parse_request_sources2,
};
use mule_engine::upnp::parse_wan_service;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, p)) = data.split_first() else {
        return;
    };
    match selector % 13 {
        0 => {
            if let Ok(page) = parse_search_result_page(p) {
                // Ranking consumes the attacker's filenames and sizes.
                let _ = catalog(&page.files);
            }
        }
        1 => {
            let _ = parse_global_search_res(p);
        }
        2 => {
            let _ = parse_id_change(p);
            let _ = parse_server_status(p);
            let _ = parse_serv_stat_res(p);
        }
        3 => {
            let _ = parse_server_message(p);
        }
        4 => {
            let _ = parse_server_list(p);
        }
        5 => {
            let _ = parse_server_ident(p);
        }
        6 => {
            // Both branches of the two-form OP_SERVER_DESC_RES. Echoing the
            // payload's own leading u32 back as the expected challenge forces
            // the NEW (tagged) form, which a fixed challenge would never reach;
            // it stays deterministic because it is derived from the input.
            let echoed = if p.len() >= 4 {
                u32::from_le_bytes([p[0], p[1], p[2], p[3]])
            } else {
                0
            };
            let _ = parse_server_desc_res(p, echoed);
            let _ = parse_server_desc_res(p, 0);
        }
        7 => {
            let _ = parse_found_sources(p, false);
            let _ = parse_found_sources(p, true);
        }
        8 => {
            // SX1 announced versions 1..=3 pick different record layouts, and
            // SX2 carries its own version byte.
            let _ = parse_answer_sources(p, true, 0);
            for v in 1..=3u8 {
                let _ = parse_answer_sources(p, false, v);
            }
        }
        9 => {
            let _ = parse_callback_requested(p);
            let _ = parse_request_sources(p);
            let _ = parse_request_sources2(p);
        }
        10 => {
            let _ = parse_public_key(p);
            let _ = parse_sec_ident_state(p);
            let _ = parse_signature(p);
        }
        11 => {
            let _ = parse_map_response(Proto::Udp, p);
            let _ = parse_map_response(Proto::Tcp, p);
        }
        _ => {
            let xml = String::from_utf8_lossy(p);
            let _ = parse_wan_service(&xml, "http://192.168.0.1:1900/desc.xml");
        }
    }
});
