//! mule-engine: the eD2k/Kad engine for padMule. This wave adds the pure
//! server-message codecs (no networking yet; tokio arrives in a later wave).
//! See docs/wiki/protocol-understanding.md.

pub mod server_messages;

pub use server_messages::{
    build_login_request, is_low_id, parse_id_change, parse_server_message, parse_server_status,
    IdChange, LoginRequest, DEFAULT_SERVER_FLAGS, EMULE_VERSION_TAG,
};
