//! mule-kad: the Kademlia DHT for padMule - node IDs (in mule-proto), the
//! routing table, the UDP wire (framing, obfuscation, bootstrap/hello), the
//! pure iterative lookup, source/keyword search codecs, and anti-abuse
//! hardening. All offline-testable; `mule_engine::kad_live` drives it over
//! real sockets. See docs/raw/wave6-kad-research-2026-07-14.md.

pub mod frame;
pub mod hardening;
pub mod lookup;
pub mod message;
pub mod routing;
pub mod udp_obf;

pub use frame::{pack_kad, unpack_kad, KAD_PACK_THRESHOLD};
pub use hardening::{is_acceptable_contact, is_acceptable_contact_ip, FloodTracker, FloodVerdict};
pub use lookup::{Lookup, ALPHA_QUERY};
pub use message::{
    build_bootstrap_req, build_bootstrap_res, build_hello_req, build_hello_res,
    build_hello_res_ack, build_kad2_req, build_kad2_res, build_search_key_req, build_search_res,
    build_search_source_req, kad_keyword_target, parse_bootstrap_res, parse_hello,
    parse_hello_res_ack, parse_kad2_req, parse_kad2_res, parse_search_res, BootstrapRes,
    FileResult, Hello, Kad2Req, Kad2Res, KadTag, KadTagValue, SearchRes, SearchResult, Source,
    WireContact, KADEMLIA_VERSION, KADEMLIA_VERSION_AMULE, KADEMLIA_VERSION_EMULE, KAD_FIND_NODE,
    KAD_FIND_VALUE, KAD_FIND_VALUE_MORE, KAD_STORE, OP_BOOTSTRAP_REQ, OP_BOOTSTRAP_RES,
    OP_HELLO_REQ, OP_HELLO_RES, OP_HELLO_RES_ACK, OP_KAD2_REQ, OP_KAD2_RES, OP_PING, OP_PONG,
    OP_SEARCH_KEY_REQ, OP_SEARCH_RES, OP_SEARCH_SOURCE_REQ, TAG_FILENAME, TAG_FILESIZE,
    TAG_KADMISCOPTIONS, TAG_SOURCEIP, TAG_SOURCEPORT, TAG_SOURCES, TAG_SOURCETYPE, TAG_SOURCEUPORT,
};
pub use routing::{Contact, RoutingTable, K, KBASE, KK, MAXLEVELS};
pub use udp_obf::{
    kad_deobfuscate, kad_obfuscate_request, kad_obfuscate_response, udp_verify_key, KadDecrypted,
    MAGICVALUE_UDP_SYNC_CLIENT,
};
