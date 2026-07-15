//! mule-kad: the Kademlia DHT for padMule. Wave 6a: node IDs (in mule-proto) and
//! the routing table. Wave 6b: the UDP wire - framing, obfuscation, and the
//! bootstrap/hello handshake. Later slices add iterative lookups and
//! source/keyword search. See docs/raw/wave6-kad-research-2026-07-14.md.

pub mod frame;
pub mod message;
pub mod routing;
pub mod udp_obf;

pub use frame::{pack_kad, unpack_kad, KAD_PACK_THRESHOLD};
pub use message::{
    build_bootstrap_req, build_bootstrap_res, build_hello_req, build_hello_res,
    build_hello_res_ack, parse_bootstrap_res, parse_hello, parse_hello_res_ack, BootstrapRes,
    Hello, KadTag, KadTagValue, WireContact, KADEMLIA_VERSION, KADEMLIA_VERSION_AMULE,
    KADEMLIA_VERSION_EMULE, OP_BOOTSTRAP_REQ, OP_BOOTSTRAP_RES, OP_HELLO_REQ, OP_HELLO_RES,
    OP_HELLO_RES_ACK, OP_KAD2_REQ, OP_KAD2_RES, OP_PING, OP_PONG, TAG_KADMISCOPTIONS,
    TAG_SOURCEUPORT,
};
pub use routing::{Contact, RoutingTable, K, KBASE, KK, MAXLEVELS};
pub use udp_obf::{
    kad_deobfuscate, kad_obfuscate_request, kad_obfuscate_response, udp_verify_key, KadDecrypted,
    MAGICVALUE_UDP_SYNC_CLIENT,
};
