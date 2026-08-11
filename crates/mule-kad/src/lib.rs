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
pub use hardening::{
    is_acceptable_contact, is_acceptable_contact_ip, FloodTracker, FloodVerdict, MAX_TRACKED_IPS,
};
pub use lookup::{CSearch, ALPHA_QUERY};
pub use message::{
    build_bootstrap_req, build_bootstrap_res, build_hello_req, build_hello_res,
    build_hello_res_ack, build_kad2_req, build_kad2_res, build_ping, build_pong,
    build_publish_key_req, build_publish_source_req, build_search_expression_and,
    build_search_key_req, build_search_key_req_restrictive, build_search_res,
    build_search_source_req, kad_filename_matches, kad_keyword_target, kad_keywords,
    kad_primary_keyword, parse_bootstrap_res, parse_hello, parse_hello_res_ack, parse_kad2_req,
    parse_kad2_res, parse_publish_res, parse_search_res, BootstrapRes, FileResult, Hello, Kad2Req,
    Kad2Res, KadTag, KadTagValue, KeywordEntry, PublishRes, SearchRes, SearchResult, Source,
    SourceEntry, WireContact, EXPR_MAX_DEPTH, KADEMLIA_VERSION, KADEMLIA_VERSION_AMULE,
    KADEMLIA_VERSION_EMULE, KAD_FIND_NODE, KAD_FIND_VALUE, KAD_FIND_VALUE_MORE, KAD_STORE,
    OP_BOOTSTRAP_REQ, OP_BOOTSTRAP_RES, OP_HELLO_REQ, OP_HELLO_RES, OP_HELLO_RES_ACK, OP_KAD2_REQ,
    OP_KAD2_RES, OP_PING, OP_PONG, OP_PUBLISH_KEY_REQ, OP_PUBLISH_RES, OP_PUBLISH_RES_ACK,
    OP_PUBLISH_SOURCE_REQ, OP_SEARCH_KEY_REQ, OP_SEARCH_RES, OP_SEARCH_SOURCE_REQ,
    PUBLISH_KEY_FILES_PER_PACKET, SEARCH_KEY_RESTRICTIVE, TAG_FILENAME, TAG_FILESIZE, TAG_FILETYPE,
    TAG_KADMISCOPTIONS, TAG_SOURCEIP, TAG_SOURCEPORT, TAG_SOURCES, TAG_SOURCETYPE, TAG_SOURCEUPORT,
};
pub use routing::{
    Contact, RoutingTable, SweepOutcome, ALIVE_LEASE_SECS, DIVERSITY_STARVED_BELOW, K,
    KAD_TYPE_ALIVE, KAD_TYPE_NEW, KAD_TYPE_PROBED, KBASE, KK, MAXLEVELS, MAX_CONTACTS_PER_IP,
    MAX_CONTACTS_PER_SLASH16, MAX_CONTACTS_PER_SUBNET, MAX_SAME_SUBNET_PER_BIN, PROBE_WINDOW_SECS,
};
pub use udp_obf::{
    kad_deobfuscate, kad_obfuscate_request, kad_obfuscate_response, udp_verify_key, KadDecrypted,
    MAGICVALUE_UDP_SYNC_CLIENT,
};
