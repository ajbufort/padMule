//! mule-engine: the eD2k/Kad engine for padMule. This wave adds the pure
//! server-message codecs (no networking yet; tokio arrives in a later wave).
//! See docs/wiki/protocol-understanding.md.

pub mod connection;
pub mod framed;
pub mod link;
pub mod peer;
pub mod peer_conn;
pub mod search;
pub mod server_messages;
pub mod transfer;
pub mod transfer_session;

pub use connection::{connect_server, login_handshake, ServerEvent, ServerState};
pub use framed::{FrameError, FramedStream};
pub use link::ServerLink;
pub use peer::{
    build_hello, build_hello_answer, parse_hello, Capabilities, HelloInfo, ParsedHello,
};
pub use peer_conn::{accept_peer, connect_peer, peer_handshake_inbound, peer_handshake_outbound};
pub use search::{build_search_request, parse_search_result, SearchParams, SearchResultFile};
pub use server_messages::{
    build_login_request, is_low_id, parse_id_change, parse_server_ident, parse_server_list,
    parse_server_message, parse_server_status, IdChange, LoginRequest, ServerIdent,
    DEFAULT_SERVER_FLAGS, EMULE_VERSION_TAG,
};
