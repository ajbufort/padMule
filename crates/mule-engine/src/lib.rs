//! mule-engine: the live eD2k/Kad engine for padMule - pure message codecs
//! plus the tokio networking that drives them (server link, peer transfer,
//! obfuscation, secure ident, Kad node, fetch/search, share/upload, UPnP) and
//! the `Engine` lifecycle facade the FFI wraps.
//! See docs/wiki/protocol-understanding.md.

pub mod bootstrap;
pub mod catalog;
pub mod connection;
pub mod credits;
pub mod crypt_policy;
pub mod engine;
pub mod fetch;
pub mod framed;
pub mod identity;
pub mod kad_live;
pub mod link;
pub mod multi_source;
pub mod obf_handshake;
pub mod part_file;
pub mod part_store;
pub mod peer;
pub mod peer_conn;
pub mod portmap;
pub mod search;
pub mod secure_ident;
pub mod server_messages;
pub mod share;
pub mod sources;
pub mod stats;
pub mod transfer;
pub mod transfer_session;
pub mod upload_queue;
pub mod upnp;

pub use catalog::{catalog, RankedFile, Trust};
pub use connection::{connect_server, login_handshake, ServerEvent, ServerState};
pub use credits::{resolve_ident_state, score_ratio, score_ratio_ident, IdentState};
pub use crypt_policy::{should_obfuscate_outbound, should_reject, CryptPrefs};
pub use engine::{
    AddResult, Engine, EngineEvent, EngineState, HitStatus, SearchFilters, SearchOutcome,
    ServerInfo, ServerListUpdate,
};
pub use fetch::{
    download_file, fetch_from_sources, FetchOutcome, ManagerConfig, PeerScoreboard, PeerSource,
    SourceOrigin, SourceRegistry,
};
pub use framed::{FrameError, FramedStream};
pub use identity::NodeIdentity;
pub use kad_live::{KadError, KadNode, ResolveOutcome};
pub use link::ServerLink;
pub use multi_source::{download_from_peer, download_from_peer_at, Download, SecIdentCtx};
pub use obf_handshake::{obf_accept, obf_initiate, ObfDetect};
pub use part_file::{data_part_count, part_size, PartFile};
pub use part_store::{copy_file_prefix, PartStore};
pub use peer::{
    build_hello, build_hello_answer, parse_hello, Capabilities, HelloInfo, PadMuleInfo,
    ParsedHello, PADMULE_CHANNEL_VERSION,
};
pub use peer_conn::{
    accept_peer, connect_peer, connect_peer_obf, peer_handshake_inbound, peer_handshake_outbound,
};
pub use portmap::{map_port, MapResponse, PortMapError, Proto};
pub use search::{
    build_search_request, choose_search_method, parse_search_result, SearchMethod, SearchParams,
    SearchResultFile,
};
pub use secure_ident::{run_secure_ident, verify_v1, Identity, SecureIdentSession};
pub use server_messages::{
    build_login_request, is_low_id, parse_id_change, parse_server_ident, parse_server_list,
    parse_server_message, parse_server_status, IdChange, LoginRequest, ServerIdent,
    DEFAULT_SERVER_FLAGS, EMULE_VERSION_TAG,
};
pub use share::{serve_shared, SharedFile};
pub use sources::{
    build_answer_sources, build_callback_request, build_get_sources, build_request_sources,
    build_request_sources2, parse_answer_sources, parse_callback_requested, parse_found_sources,
    parse_request_sources, parse_request_sources2, CallbackRequested, FoundSource, Source,
    SOURCE_EXCHANGE_VERSION,
};
pub use transfer_session::{serve, serve_file, ServedFile};
pub use upload_queue::{
    max_slots, peer_score, should_kick, FilePriority, QueuedPeer, UploadQueue, FRIEND_SLOT_SCORE,
};
