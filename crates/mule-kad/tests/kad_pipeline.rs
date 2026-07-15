//! End-to-end Kad UDP codec pipeline: build a message, frame it, obfuscate it,
//! then (as the peer) deobfuscate, deframe, and parse it back. This exercises
//! the full send/receive path offline before the live bootstrap gate.

use mule_kad::{
    build_bootstrap_res, build_hello_req, kad_deobfuscate, kad_obfuscate_request,
    kad_obfuscate_response, pack_kad, parse_bootstrap_res, parse_hello, udp_verify_key, unpack_kad,
    WireContact, OP_BOOTSTRAP_RES, OP_HELLO_REQ,
};
use mule_proto::Kad128;

#[test]
fn hello_request_survives_frame_obfuscate_deobfuscate_deframe_parse() {
    // We (requester) send a HELLO_REQ to a server whose Kad ID we know.
    let server_id = Kad128::from_hash(&[0x5c; 16]);
    let our_id = Kad128::from_hash(&[0x01; 16]);
    let server_ip = 0x0A00_0021u32; // 10.0.0.33
    let server_udp_key = 0xDEAD_BEEFu32; // the server's own install key

    // The verify key WE issue for the server (want it echoed back to prove IP).
    let our_udp_key = 0x1122_3344u32;
    let sender_vk = udp_verify_key(our_udp_key, server_ip);

    let (op, payload) = build_hello_req(&our_id, 4662, Some(4672), Some(0x04));
    assert_eq!(op, OP_HELLO_REQ);
    let frame = pack_kad(op, payload);
    // NodeID-keyed on the server's id; no receiver key yet (first contact).
    let datagram = kad_obfuscate_request(&frame, &server_id, 0x1234, 0, sender_vk, 0x40);

    // Server side: it decrypts with its own id (NodeID key path).
    let dec = kad_deobfuscate(
        &datagram,
        &server_id,
        server_udp_key,
        /*our ip*/ 0x0A00_0001,
    )
    .expect("server decrypts the request");
    assert!(!dec.used_receiver_key);
    assert_eq!(dec.sender_vk, sender_vk, "server learns the key to echo");

    let (op2, payload2) = unpack_kad(&dec.payload).unwrap();
    assert_eq!(op2, OP_HELLO_REQ);
    let hello = parse_hello(&payload2).unwrap();
    assert_eq!(hello.id, our_id);
    assert_eq!(hello.tcp_port, 4662);
    assert_eq!(hello.source_udp_port, Some(4672));
    assert_eq!(hello.misc_options, Some(0x04));
}

#[test]
fn bootstrap_response_survives_the_receiver_key_path() {
    // The server replies BOOTSTRAP_RES, ReceiverKey-encrypted with the verify
    // key we issued for it; we decrypt with the same value.
    let server_id = Kad128::from_hash(&[0x22; 16]);
    let our_id = Kad128::from_hash(&[0x99; 16]);
    let server_ip = 0x4552_3039u32;
    let our_udp_key = 0xA1B2_C3D4u32;
    let echoed = udp_verify_key(our_udp_key, server_ip); // what the server echoes

    let contacts = vec![WireContact {
        id: Kad128::from_hash(&[0x33; 16]),
        ip: 0x0102_0304,
        udp_port: 4672,
        tcp_port: 4662,
        version: 8,
    }];
    let (op, payload) = build_bootstrap_res(&server_id, 4662, 8, &contacts);
    let frame = pack_kad(op, payload);
    let datagram = kad_obfuscate_response(&frame, 0x9ABC, echoed, 0, 0x80);

    let dec = kad_deobfuscate(&datagram, &our_id, our_udp_key, server_ip)
        .expect("we decrypt the response via our issued key");
    assert!(dec.used_receiver_key);

    let (op2, payload2) = unpack_kad(&dec.payload).unwrap();
    assert_eq!(op2, OP_BOOTSTRAP_RES);
    let res = parse_bootstrap_res(&payload2).unwrap();
    assert_eq!(res.id, server_id);
    assert_eq!(res.contacts, contacts);
}

#[test]
fn a_large_bootstrap_response_packs_and_still_round_trips() {
    // 20 contacts -> 16+2+1+2+20*25 = 521-byte payload, over the 200-byte pack
    // threshold, so the frame is 0xE5-compressed inside the obfuscation layer.
    let server_id = Kad128::from_hash(&[0x44; 16]);
    let our_id = Kad128::from_hash(&[0x55; 16]);
    let server_ip = 0x0808_0808u32;
    let our_udp_key = 0x5566_7788u32;
    let echoed = udp_verify_key(our_udp_key, server_ip);

    let contacts: Vec<WireContact> = (0..20u8)
        .map(|i| WireContact {
            id: Kad128::from_hash(&[i; 16]),
            ip: 0x0A00_0000 | i as u32,
            udp_port: 4000 + i as u16,
            tcp_port: 5000 + i as u16,
            version: 8,
        })
        .collect();
    let (op, payload) = build_bootstrap_res(&server_id, 4662, 8, &contacts);
    let frame = pack_kad(op, payload);
    assert_eq!(frame[0], 0xE5, "the 521-byte frame must be zlib-packed");

    let datagram = kad_obfuscate_response(&frame, 0x0F0F, echoed, 0, 0x02);
    let dec = kad_deobfuscate(&datagram, &our_id, our_udp_key, server_ip).unwrap();
    let (_, payload2) = unpack_kad(&dec.payload).unwrap();
    let res = parse_bootstrap_res(&payload2).unwrap();
    assert_eq!(res.contacts.len(), 20);
    assert_eq!(res.contacts, contacts);
}
