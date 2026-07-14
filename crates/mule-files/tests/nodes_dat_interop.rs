//! Interop test: parse a REAL nodes.dat (downloaded by amuled from
//! upd.emule-security.org) and round-trip it. This is the differential check that
//! our Kad-contact byte layout + the CUInt128 wire encoding match the real
//! network's file. Fixture: crates/mule-files/tests/fixtures/nodes.dat (6098 B,
//! v2, 179 contacts).

use mule_files::nodes_dat::{read_nodes_dat, write_nodes_dat};

const NODES: &[u8] = include_bytes!("fixtures/nodes.dat");

#[test]
fn parses_the_real_fixture() {
    let n = read_nodes_dat(NODES).expect("must parse a real nodes.dat");
    assert_eq!(n.version, 2);
    assert_eq!(n.contacts.len(), 179);

    // The first contact, decoded in the research spec.
    let c = &n.contacts[0];
    // Canonical Kad ID 8fb8d05c9334b727eeb1ef09e86ef928.
    assert_eq!(
        c.id.to_hash(),
        [
            0x8f, 0xb8, 0xd0, 0x5c, 0x93, 0x34, 0xb7, 0x27, 0xee, 0xb1, 0xef, 0x09, 0xe8, 0x6e,
            0xf9, 0x28
        ]
    );
    assert_eq!(c.udp_port, 4672);
    assert_eq!(c.tcp_port, 4662);
    assert_eq!(c.version, 8);
    assert!(c.verified);
    // IP 226.80.49.93 stored network-order (first octet in the low byte here is
    // 226 because the file stores it as the raw u32 our reader read LE).
    let octets = c.ip.to_le_bytes();
    assert_eq!(octets, [226, 80, 49, 93]);
}

#[test]
fn round_trips_the_v2_records_byte_for_byte() {
    let n = read_nodes_dat(NODES).unwrap();
    // The fixture is already the modern v2 form, so a re-write must reproduce the
    // exact bytes (same 0/version/count header, same 34-byte records, same order).
    let out = write_nodes_dat(&n);
    assert_eq!(out, NODES, "re-serialized nodes.dat must be byte-identical");
}
