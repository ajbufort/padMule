//! eD2k server login-handshake message codecs (pure; no I/O). See
//! ServerConnect.cpp:210-259 (login), ServerSocket.cpp:228-320 (IDCHANGE), and
//! docs/wiki/protocol-understanding.md Part 1.

use mule_proto::{
    read_tag, write_tag, IoError, Packet, Reader, Tag, TagValue, Writer, PROT_EDONKEY,
};

// Opcodes (protocol 0xE3).
pub const OP_LOGINREQUEST: u8 = 0x01;
pub const OP_SERVERLIST: u8 = 0x32;
pub const OP_SERVERSTATUS: u8 = 0x34;
pub const OP_SERVERMESSAGE: u8 = 0x38;
pub const OP_IDCHANGE: u8 = 0x40;
pub const OP_SERVERIDENT: u8 = 0x41;
/// Announce our shared files to the server (`<count 4>(<HASH 16><ID 4><PORT 2>
/// <tagset>)[count]`, opcodes.h:161) so it indexes them for keyword search and
/// can hand us out as a source.
pub const OP_OFFERFILES: u8 = 0x15;

/// Server TCP-capability bit (in the OP_IDCHANGE flags word) meaning the server
/// answers "related files" searches - a keyword query whose string is
/// `related::<HEXHASH>`. eMule `server.h:39` SRV_TCPFLG_RELATEDSEARCH; gates
/// `CSearchResultsWnd::CanSearchRelatedFiles`.
pub const SRV_TCPFLG_RELATEDSEARCH: u32 = 0x0000_0040;

// File-tag ids for an offered file (opcodes.h:322,324,328).
const FT_FILENAME: u8 = 0x01;
const FT_FILESIZE: u8 = 0x02;
/// High 32 bits of a 64-bit file size, TO A SERVER (opcodes.h FT_FILESIZE_HI).
/// A server offer for a large file uses FT_FILESIZE (low) + FT_FILESIZE_HI (high)
/// as TWO 32-bit tags, NOT one 64-bit FT_FILESIZE (KnownFile.cpp:1222-1223).
const FT_FILESIZE_HI: u8 = 0x3A;
/// The marker client-id/port an offered COMPLETE file carries (aMule
/// `KnownFile.cpp:1173-1174`). aMule sends it for a complete file whenever the
/// server advertises compression (`KnownFile.cpp:1172`) - i.e. every live server;
/// padMule uses it for ALL its (complete) shares, which is faithful for that
/// common case and keeps a HighID's public IP out of the server's search index
/// (the server still sources us via our login id).
pub const FILE_COMPLETE_ID: u32 = 0xFBFB_FBFB;
pub const FILE_COMPLETE_PORT: u16 = 0xFBFB;

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

/// One shared file to announce via OP_OFFERFILES.
pub struct OfferedFile<'a> {
    pub hash: [u8; 16],
    pub name: &'a str,
    pub size: u64,
}

/// Build an OP_OFFERFILES packet announcing `files` to the server. `client_id` /
/// `client_port` identify the source (padMule passes FILE_COMPLETE_ID/PORT for
/// its complete shares). Each record carries FT_FILENAME + FT_FILESIZE (plus
/// FT_FILESIZE_HI for a >4-GiB file - the TWO-32-bit-tag SERVER form, not a
/// single 64-bit tag). Faithful to aMule `CKnownFile::CreateOfferedFilePacket`.
pub fn build_offer_files(files: &[OfferedFile], client_id: u32, client_port: u16) -> Packet {
    let mut w = Writer::new();
    w.write_u32(files.len() as u32);
    for f in files {
        w.write_bytes(&f.hash);
        w.write_u32(client_id);
        w.write_u16(client_port);
        let large = f.size > mule_proto::OLD_MAX_FILE_SIZE;
        w.write_u32(if large { 3 } else { 2 }); // name + size (+ size-hi if large)
        write_tag(
            &mut w,
            &Tag::id(FT_FILENAME, TagValue::Str(f.name.as_bytes().to_vec())),
        );
        // To a SERVER, a large file is FT_FILESIZE(low 32) + FT_FILESIZE_HI(high
        // 32) - NOT a single u64 tag (KnownFile.cpp:1222-1223).
        write_tag(&mut w, &Tag::id(FT_FILESIZE, TagValue::U32(f.size as u32)));
        if large {
            write_tag(
                &mut w,
                &Tag::id(FT_FILESIZE_HI, TagValue::U32((f.size >> 32) as u32)),
            );
        }
    }
    Packet::new(PROT_EDONKEY, OP_OFFERFILES, w.into_inner())
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

/// UDP server-status ping opcodes (protocol 0xE3, sent to the server's UDP port =
/// TCP + 4). `OP_GLOBSERVSTATREQ` is a bare `[0xE3][0x96]` datagram; a server that
/// answers `OP_GLOBSERVSTATRES` `<users u32><files u32>` (opcodes.h:192-193) is
/// ALIVE and reports fresh counts. Newer servers append maxusers/soft/hard/version
/// - ignored here.
pub const OP_GLOBSERVSTATREQ: u8 = 0x96;
pub const OP_GLOBSERVSTATRES: u8 = 0x97;

/// Parse an OP_GLOBSERVSTATRES payload into `(users, files)`, or None if it is too
/// short. Only the leading two u32s are read; any trailing extension is ignored.
pub fn parse_serv_stat_res(payload: &[u8]) -> Option<(u32, u32)> {
    if payload.len() < 8 {
        return None;
    }
    let users = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let files = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    Some((users, files))
}

/// Parse an OP_SERVERLIST payload: `u8 count` then `count * (u32 IP, u16 port)`.
/// Peer-server gossip used to grow the local server list.
pub fn parse_server_list(payload: &[u8]) -> Result<Vec<(u32, u16)>, IoError> {
    let mut r = Reader::new(payload);
    let count = r.read_u8()?;
    let mut out = Vec::with_capacity(count as usize); // count is a u8, bounded
    for _ in 0..count {
        let ip = r.read_u32()?;
        let port = r.read_u16()?;
        out.push((ip, port));
    }
    Ok(out)
}

/// A server's self-identification (OP_SERVERIDENT).
#[derive(Debug, Clone, PartialEq)]
pub struct ServerIdent {
    pub hash: [u8; 16],
    pub ip: u32,
    pub port: u16,
    pub tags: Vec<Tag>,
}

/// Parse an OP_SERVERIDENT payload: `hash(16)`, `IP(u32)`, `port(u16)`, tags.
pub fn parse_server_ident(payload: &[u8]) -> Result<ServerIdent, IoError> {
    let mut r = Reader::new(payload);
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&r.read_bytes(16)?);
    let ip = r.read_u32()?;
    let port = r.read_u16()?;
    let tagcount = r.read_u32()?;
    // Untrusted count: grow as we read rather than pre-allocating.
    let mut tags = Vec::new();
    for _ in 0..tagcount {
        tags.push(read_tag(&mut r)?);
    }
    Ok(ServerIdent {
        hash,
        ip,
        port,
        tags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_proto::{read_packet, write_packet};

    #[test]
    fn offer_files_round_trips_via_the_shared_result_record() {
        // OP_OFFERFILES carries the SAME <count>(<hash><id><port><tagset>)[count]
        // record as a search result, so parse it back with parse_search_result to
        // prove the record format is byte-correct.
        let files = vec![OfferedFile {
            hash: [0xAA; 16],
            name: "linux mint.iso",
            size: 2_000_000,
        }];
        let pkt = build_offer_files(&files, FILE_COMPLETE_ID, FILE_COMPLETE_PORT);
        assert_eq!(pkt.protocol, PROT_EDONKEY);
        assert_eq!(pkt.opcode, OP_OFFERFILES);

        let parsed = crate::search::parse_search_result(&pkt.payload).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].hash, [0xAA; 16]);
        assert_eq!(parsed[0].id, FILE_COMPLETE_ID); // LowID complete-file marker
        assert_eq!(parsed[0].port, FILE_COMPLETE_PORT);
        let name = parsed[0]
            .tags
            .iter()
            .find_map(|t| match (&t.name, &t.value) {
                (mule_proto::TagName::Id(FT_FILENAME), TagValue::Str(s)) => {
                    Some(String::from_utf8_lossy(s).into_owned())
                }
                _ => None,
            });
        assert_eq!(name.as_deref(), Some("linux mint.iso"));
    }

    #[test]
    fn offer_files_large_file_uses_split_32bit_size_tags() {
        // A SERVER offer for a >4-GiB file carries FT_FILESIZE(low) +
        // FT_FILESIZE_HI(high) as two 32-bit tags, not a single u64.
        let size: u64 = 5_000_000_000; // > OLD_MAX_FILE_SIZE (~4.29 GiB)
        let files = vec![OfferedFile {
            hash: [0xBB; 16],
            name: "big.iso",
            size,
        }];
        let pkt = build_offer_files(&files, FILE_COMPLETE_ID, FILE_COMPLETE_PORT);
        let parsed = crate::search::parse_search_result(&pkt.payload).unwrap();
        assert_eq!(parsed.len(), 1);
        let lo = parsed[0]
            .tags
            .iter()
            .find_map(|t| match (&t.name, &t.value) {
                (mule_proto::TagName::Id(FT_FILESIZE), TagValue::U32(v)) => Some(*v),
                _ => None,
            });
        let hi = parsed[0]
            .tags
            .iter()
            .find_map(|t| match (&t.name, &t.value) {
                (mule_proto::TagName::Id(FT_FILESIZE_HI), TagValue::U32(v)) => Some(*v),
                _ => None,
            });
        assert_eq!(lo, Some(size as u32));
        assert_eq!(hi, Some((size >> 32) as u32));
        // The two halves reconstruct the true u64 size.
        assert_eq!(((hi.unwrap() as u64) << 32) | lo.unwrap() as u64, size);
    }

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

    #[test]
    fn serv_stat_res_reads_users_and_files_ignoring_extras() {
        // <users 4><files 4>, then a trailing extension a newer server appends.
        let res = [
            0x2A, 0x00, 0x00, 0x00, // users = 42
            0x40, 0xE2, 0x01, 0x00, // files = 123456
            0xFF, 0xFF, // trailing bytes -> ignored
        ];
        assert_eq!(parse_serv_stat_res(&res), Some((42, 123_456)));
        // Too short -> None (never index past the end).
        assert_eq!(parse_serv_stat_res(&[0x01, 0x02, 0x03]), None);
    }

    #[test]
    fn server_list_two_entries() {
        let payload = [
            0x02, // count = 2
            0x01, 0x00, 0x00, 0x0A, 0x36, 0x12, // 0x0A000001 : 4662
            0xEF, 0xBE, 0xAD, 0xDE, 0x35, 0x12, // 0xDEADBEEF : 4661
        ];
        assert_eq!(
            parse_server_list(&payload).unwrap(),
            vec![(0x0A00_0001, 4662), (0xDEAD_BEEF, 4661)]
        );
    }

    #[test]
    fn server_ident_with_name_tag() {
        let mut payload = vec![0xAAu8; 16]; // hash
        payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x0A]); // ip
        payload.extend_from_slice(&[0x36, 0x12]); // port 4662
        payload.extend_from_slice(&[0x01, 0x00, 0x00, 0x00]); // tagcount = 1
                                                              // ST_SERVERNAME(0x01) STRING "s"
        payload.extend_from_slice(&[0x02, 0x01, 0x00, 0x01, 0x01, 0x00, b's']);
        let ident = parse_server_ident(&payload).unwrap();
        assert_eq!(ident.hash, [0xAA; 16]);
        assert_eq!(ident.ip, 0x0A00_0001);
        assert_eq!(ident.port, 4662);
        assert_eq!(
            ident.tags,
            vec![Tag::id(0x01, TagValue::Str(b"s".to_vec()))]
        );
    }
}
