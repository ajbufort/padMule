//! eD2k server login-handshake message codecs (pure; no I/O). See
//! ServerConnect.cpp:210-259 (login), ServerSocket.cpp:228-320 (IDCHANGE), and
//! docs/wiki/protocol-understanding.md Part 1.

use mule_proto::{write_tag, IoError, Packet, Reader, Tag, TagValue, Writer, PROT_EDONKEY};

// Opcodes (protocol 0xE3).
pub const OP_LOGINREQUEST: u8 = 0x01;
pub const OP_SERVERSTATUS: u8 = 0x34;
pub const OP_SERVERMESSAGE: u8 = 0x38;
pub const OP_IDCHANGE: u8 = 0x40;

// Login tag ids (ClientTags.h).
const CT_NAME: u8 = 0x01;
const CT_VERSION: u8 = 0x11;
const CT_SERVER_FLAGS: u8 = 0x20;
const CT_EMULE_VERSION: u8 = 0xFB;

/// eDonkey protocol version advertised in CT_VERSION (ClientVersion.h).
pub const EDONKEYVERSION: u32 = 0x3C;

// Server capability flags (ClientTags.h SRVCAP_*).
pub const SRVCAP_ZLIB: u32 = 0x0001;
pub const SRVCAP_AUXPORT: u32 = 0x0004;
pub const SRVCAP_NEWTAGS: u32 = 0x0008;
pub const SRVCAP_UNICODE: u32 = 0x0010;
pub const SRVCAP_LARGEFILES: u32 = 0x0100;
pub const SRVCAP_SUPPORTCRYPT: u32 = 0x0200;
pub const SRVCAP_REQUESTCRYPT: u32 = 0x0400;
pub const SRVCAP_REQUIRECRYPT: u32 = 0x0800;

/// The v1 baseline capability set: zlib, aux port, new tags, unicode, large
/// files. Crypt is OFF until obfuscation lands (Wave 5). Value 0x011D.
pub const DEFAULT_SERVER_FLAGS: u32 =
    SRVCAP_ZLIB | SRVCAP_AUXPORT | SRVCAP_NEWTAGS | SRVCAP_UNICODE | SRVCAP_LARGEFILES;

/// aMule software id in CT_EMULE_VERSION (ClientSoftware.h SO_AMULE).
const SO_AMULE: u32 = 3;

/// aMule 3.0.1 pack: `(a<<17)|(b<<10)|(c<<7)` (OtherFunctions.h make_full_ed2k_version).
const fn make_full_ed2k_version(a: u32, b: u32, c: u32) -> u32 {
    (a << 17) | (b << 10) | (c << 7)
}

/// The CT_EMULE_VERSION value padMule advertises: aMule 3.0.1. Equals 0x03060080.
pub const EMULE_VERSION_TAG: u32 = (SO_AMULE << 24) | make_full_ed2k_version(3, 0, 1);

/// IDs below this are LowIDs (server-local, not reachable directly).
pub const HIGHEST_LOWID: u32 = 16_777_216;

/// True if `id` is a LowID.
pub fn is_low_id(id: u32) -> bool {
    id < HIGHEST_LOWID
}

/// Parameters for a login request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginRequest {
    pub user_hash: [u8; 16],
    /// Our client ID; 0 on first connect.
    pub client_id: u32,
    pub tcp_port: u16,
    pub nick: String,
    /// CT_SERVER_FLAGS capability bitmask (use DEFAULT_SERVER_FLAGS for v1).
    pub server_flags: u32,
}

/// Build an OP_LOGINREQUEST packet. Tags are written in the verbose form aMule
/// uses at login (it does not yet know the server's capabilities).
pub fn build_login_request(req: &LoginRequest) -> Packet {
    let mut w = Writer::new();
    w.write_bytes(&req.user_hash);
    w.write_u32(req.client_id);
    w.write_u16(req.tcp_port);
    w.write_u32(4); // tag count
    write_tag(
        &mut w,
        &Tag::id(CT_NAME, TagValue::Str(req.nick.as_bytes().to_vec())),
    );
    write_tag(&mut w, &Tag::id(CT_VERSION, TagValue::U32(EDONKEYVERSION)));
    write_tag(
        &mut w,
        &Tag::id(CT_SERVER_FLAGS, TagValue::U32(req.server_flags)),
    );
    write_tag(
        &mut w,
        &Tag::id(CT_EMULE_VERSION, TagValue::U32(EMULE_VERSION_TAG)),
    );
    Packet::new(PROT_EDONKEY, OP_LOGINREQUEST, w.into_inner())
}

/// The server's login answer: our assigned ID plus optional session details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdChange {
    /// Our assigned client ID (a HighID == our public IPv4; a LowID < 16M; 0 =
    /// rejected).
    pub new_id: u32,
    pub tcp_flags: Option<u32>,
    /// The "standard" port to advertise when we logged in on an aux port.
    pub standard_port: Option<u32>,
    pub reported_ip: Option<u32>,
    pub obfuscation_tcp_port: Option<u32>,
}

impl IdChange {
    /// True if the server refused to assign an ID (login rejected).
    pub fn is_rejected(&self) -> bool {
        self.new_id == 0
    }

    /// True if we were assigned a LowID.
    pub fn is_low_id(&self) -> bool {
        is_low_id(self.new_id)
    }
}

/// Parse an OP_IDCHANGE payload (fields are optional by length tier).
pub fn parse_id_change(payload: &[u8]) -> Result<IdChange, IoError> {
    let mut r = Reader::new(payload);
    let new_id = r.read_u32()?;
    let mut ic = IdChange {
        new_id,
        tcp_flags: None,
        standard_port: None,
        reported_ip: None,
        obfuscation_tcp_port: None,
    };
    if r.remaining() >= 4 {
        ic.tcp_flags = Some(r.read_u32()?);
    }
    if r.remaining() >= 4 {
        ic.standard_port = Some(r.read_u32()?);
    }
    if r.remaining() >= 8 {
        ic.reported_ip = Some(r.read_u32()?);
        ic.obfuscation_tcp_port = Some(r.read_u32()?);
    }
    Ok(ic)
}

/// Parse an OP_SERVERMESSAGE payload (u16 length + text).
pub fn parse_server_message(payload: &[u8]) -> Result<String, IoError> {
    let mut r = Reader::new(payload);
    let bytes = r.read_string_u16()?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Parse an OP_SERVERSTATUS payload: (user count, file count).
pub fn parse_server_status(payload: &[u8]) -> Result<(u32, u32), IoError> {
    let mut r = Reader::new(payload);
    let users = r.read_u32()?;
    let files = r.read_u32()?;
    Ok((users, files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::{read_packet, write_packet};

    fn sample_login() -> LoginRequest {
        LoginRequest {
            user_hash: [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
                0x0E, 0x0F,
            ],
            client_id: 0,
            tcp_port: 4662,
            nick: "a".to_string(),
            server_flags: DEFAULT_SERVER_FLAGS,
        }
    }

    #[test]
    fn constants_match_amule() {
        assert_eq!(DEFAULT_SERVER_FLAGS, 0x011D);
        assert_eq!(EMULE_VERSION_TAG, 0x0306_0080);
        assert_eq!(EDONKEYVERSION, 0x3C);
    }

    #[test]
    fn login_request_golden_payload() {
        let p = build_login_request(&sample_login());
        assert_eq!(p.protocol, PROT_EDONKEY);
        assert_eq!(p.opcode, OP_LOGINREQUEST);
        let expected: Vec<u8> = vec![
            // userhash
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, //
            0x00, 0x00, 0x00, 0x00, // client_id = 0
            0x36, 0x12, // tcp_port = 4662
            0x04, 0x00, 0x00, 0x00, // tag count = 4
            0x02, 0x01, 0x00, 0x01, 0x01, 0x00, b'a', // CT_NAME "a"
            0x03, 0x01, 0x00, 0x11, 0x3C, 0x00, 0x00, 0x00, // CT_VERSION 0x3C
            0x03, 0x01, 0x00, 0x20, 0x1D, 0x01, 0x00, 0x00, // CT_SERVER_FLAGS 0x011D
            0x03, 0x01, 0x00, 0xFB, 0x80, 0x00, 0x06, 0x03, // CT_EMULE_VERSION 0x03060080
        ];
        assert_eq!(p.payload, expected);
    }

    #[test]
    fn login_request_round_trips_through_framing() {
        let p = build_login_request(&sample_login());
        let wire = write_packet(&p);
        let (parsed, consumed) = read_packet(&wire).unwrap().unwrap();
        assert_eq!(parsed, p);
        assert_eq!(consumed, wire.len());
    }

    #[test]
    fn id_change_minimal_only_new_id() {
        let ic = parse_id_change(&[0x01, 0x00, 0x00, 0x00]).unwrap();
        assert_eq!(
            ic,
            IdChange {
                new_id: 1,
                tcp_flags: None,
                standard_port: None,
                reported_ip: None,
                obfuscation_tcp_port: None,
            }
        );
        assert!(ic.is_low_id());
    }

    #[test]
    fn id_change_full_20_bytes() {
        // new_id=0x0A000001 (HighID), flags=0x40, stdport=4661, ip=0x0A000001, obfport=1234
        let payload = vec![
            0x01, 0x00, 0x00, 0x0A, // new_id = 0x0A000001
            0x40, 0x00, 0x00, 0x00, // tcp_flags = 0x40
            0x35, 0x12, 0x00, 0x00, // standard_port = 4661
            0x01, 0x00, 0x00, 0x0A, // reported_ip = 0x0A000001
            0xD2, 0x04, 0x00, 0x00, // obfuscation_tcp_port = 1234
        ];
        let ic = parse_id_change(&payload).unwrap();
        assert_eq!(ic.new_id, 0x0A00_0001);
        assert_eq!(ic.tcp_flags, Some(0x40));
        assert_eq!(ic.standard_port, Some(4661));
        assert_eq!(ic.reported_ip, Some(0x0A00_0001));
        assert_eq!(ic.obfuscation_tcp_port, Some(1234));
        assert!(!ic.is_low_id()); // 0x0A000001 = 167772161 >= 16777216
    }

    #[test]
    fn id_change_rejected_and_lowid_boundary() {
        assert!(parse_id_change(&[0, 0, 0, 0]).unwrap().is_rejected());
        // Exactly HIGHEST_LOWID is a HighID; one below is a LowID.
        assert!(!parse_id_change(&16_777_216u32.to_le_bytes())
            .unwrap()
            .is_low_id());
        assert!(parse_id_change(&16_777_215u32.to_le_bytes())
            .unwrap()
            .is_low_id());
    }

    #[test]
    fn id_change_truncated_errors() {
        assert_eq!(parse_id_change(&[0x01, 0x02]), Err(IoError::UnexpectedEof));
    }

    #[test]
    fn server_message_and_status() {
        // "hi" = u16 len 2 + bytes.
        assert_eq!(
            parse_server_message(&[0x02, 0x00, b'h', b'i']).unwrap(),
            "hi"
        );
        // users = 100, files = 5000
        let status = [0x64, 0x00, 0x00, 0x00, 0x88, 0x13, 0x00, 0x00];
        assert_eq!(parse_server_status(&status).unwrap(), (100, 5000));
    }
}
