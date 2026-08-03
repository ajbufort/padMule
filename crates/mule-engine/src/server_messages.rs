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
/// Ask the server for its known-servers list: a BODILESS client->server packet
/// (eMule opcodes.h:160 "(null)"). Both authorities send it from
/// ConnectionEstablished right after offering shares, gated on the "update
/// server list when connecting" pref (eMule 0.50a sockets.cpp:253-260 +
/// Preferences.cpp:2105; aMule 3.0.1 ServerConnect.cpp:289-296 +
/// Preferences.cpp:1175). The answer arrives as unsolicited OP_SERVERLIST -
/// and OP_SERVERIDENT comes ONLY to a client that asked (ServerSocket.cpp:431).
/// Device-proven 2026-08-03: modern servers do NOT volunteer the list unasked,
/// so this send is what makes the gossip harvest live.
pub const OP_GETSERVERLIST: u8 = 0x14;

/// Ask a server, over UDP, for the servers IT knows: `OP_SERVER_LIST_REQ2`
/// (0xA4, bodiless), sent to the server's UDP port (TCP + 4). The answer is
/// [`OP_SERVER_LIST_RES`], whose payload is byte-identical to TCP
/// [`OP_SERVERLIST`] - so [`parse_server_list`] reads both.
///
/// DELIBERATE DEVIATION: no CLIENT authority sends this. eMule 0.50a
/// (opcodes.h:205) and aMule (UDP.h:46, both 3.0.1 and master) DEFINE the pair
/// but never send or parse it; on this socket they send the status ping (0x96)
/// and description request (0xA2). padMule sends it because many SERVERS answer
/// it - measured 2026-08-03: one live server returned 32 servers and a first
/// crawl had 28 of 33 answer, while the vendored Lugdunum eserver 17.15 oracle,
/// `ed2k-rust` and eMule Sunrise all stay SILENT (each answering 0x96 and 0xA2
/// in the same burst, so the silence is real). Support is implementation-
/// specific; SILENCE IS NORMAL, never an error or a liveness verdict.
pub const OP_SERVER_LIST_REQ2: u8 = 0xA4;
/// A server's answer to [`OP_SERVER_LIST_REQ2`]: same payload shape as
/// [`OP_SERVERLIST`] (eMule opcodes.h:202).
pub const OP_SERVER_LIST_RES: u8 = 0xA1;

/// Ask a server over UDP for its NAME and description (`<challenge u32>`).
/// UNLIKE the crawl's 0xA4, this one IS what both authorities send - eMule
/// `UDPSocket.cpp:435` and aMule `ServerUDPSocket.cpp:243` fire it right after
/// a status answer - so learning a server's name this way is plain parity.
///
/// This is how a server discovered by the crawl or the gossip harvest gets a
/// NAME: discovery yields only ip:port, and until the name is learned the UI
/// can only show an address.
pub const OP_SERVER_DESC_REQ: u8 = 0xA2;
/// The answer to [`OP_SERVER_DESC_REQ`], in one of TWO forms - see
/// [`parse_server_desc_res`].
pub const OP_SERVER_DESC_RES: u8 = 0xA3;

/// An INVALID string length, used as the low 16 bits of the description
/// challenge so the new (tagged) answer can be told apart from the old one:
/// the first two wire bytes of a new-form answer echo it, where an old-form
/// answer would carry a real `name_len` there (eMule opcodes.h INV_SERV_DESC_LEN
/// and the comment at `UDPSocket.cpp:431-437`).
pub const INV_SERV_DESC_LEN: u16 = 0xF0FF;

// Server description tag ids (eMule opcodes.h:299,300; aMule ServerTags.h:31,33).
const ST_SERVERNAME: u8 = 0x01;
const ST_DESCRIPTION: u8 = 0x0B;

/// Build the 4-byte challenge for [`OP_SERVER_DESC_REQ`]. `seed` varies the
/// high half; the low half MUST be [`INV_SERV_DESC_LEN`], which is what makes
/// the two answer forms distinguishable (eMule `UDPSocket.cpp:436`).
pub fn desc_req_challenge(seed: u16) -> u32 {
    ((seed as u32) << 16) | INV_SERV_DESC_LEN as u32
}

/// What a server says about itself.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerDesc {
    pub name: String,
    pub description: String,
}

/// Parse an OP_SERVER_DESC_RES payload. TWO forms share this opcode and the
/// first two bytes are what tell them apart (eMule `UDPSocket.cpp:452-470`):
///
/// - NEW (eserver 16.45+, only when we sent a challenge): `<challenge u32>
///   <tagcount u32><tags>`, where ST_SERVERNAME/ST_DESCRIPTION carry the text.
///   Recognised by the first u16 being [`INV_SERV_DESC_LEN`] AND the full u32
///   matching the challenge we sent - so a stale or spoofed answer is refused.
/// - OLD: `<name_len u16><name><desc_len u16><desc>`.
pub fn parse_server_desc_res(payload: &[u8], expected_challenge: u32) -> Option<ServerDesc> {
    let mut r = Reader::new(payload);
    if payload.len() >= 8
        && u16::from_le_bytes([payload[0], payload[1]]) == INV_SERV_DESC_LEN
        && u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]])
            == expected_challenge
    {
        let _challenge = r.read_u32().ok()?;
        let count = r.read_u32().ok()?;
        let mut desc = ServerDesc::default();
        // Untrusted count: read until it runs out rather than pre-allocating.
        for _ in 0..count {
            let Ok(tag) = read_tag(&mut r) else { break };
            let id = match tag.name {
                mule_proto::TagName::Id(id) => id,
                mule_proto::TagName::Str(_) => continue,
            };
            if let TagValue::Str(bytes) = &tag.value {
                let text = String::from_utf8_lossy(bytes).into_owned();
                match id {
                    ST_SERVERNAME => desc.name = text,
                    ST_DESCRIPTION => desc.description = text,
                    _ => {}
                }
            }
        }
        return Some(desc);
    }
    // Old form. A truncated description is tolerated: the NAME is the payload
    // we actually want, and some servers send only that.
    let name = r.read_string_u16().ok()?;
    let description = r.read_string_u16().unwrap_or_default();
    Some(ServerDesc {
        name: String::from_utf8_lossy(&name).into_owned(),
        description: String::from_utf8_lossy(&description).into_owned(),
    })
}

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
/// files. Crypt is OFF on the SERVER leg by design - server TCP/UDP
/// obfuscation is a documented v1 opt-out (docs/wiki/obfuscation-posture.md);
/// the c2c and Kad legs ARE obfuscated. Value 0x011D.
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

/// Build the bodiless OP_GETSERVERLIST ask (see the opcode doc for citations).
pub fn build_get_server_list() -> Packet {
    Packet::new(PROT_EDONKEY, OP_GETSERVERLIST, Vec::new())
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
/// TCP + 4). The REQUEST carries a 4-byte CHALLENGE that the server echoes back;
/// the response is `<challenge u32><users u32><files u32>[...]` (min 12 bytes).
/// Authority: eMule 0.50a UDPSocket.cpp:331-346 + aMule 3.0.1
/// ServerUDPSocket.cpp:180-194 (which REQUIRE size >= 12). The `opcodes.h` header
/// comment's challenge-less `<USER 4><FILES 4>` is the STALE legacy format - a
/// modern server IGNORES a challenge-less request, so trust the code, not the
/// comment (see [[padmule-protocol-landmines]] #13/#17).
pub const OP_GLOBSERVSTATREQ: u8 = 0x96;
pub const OP_GLOBSERVSTATRES: u8 = 0x97;

/// The fixed challenge padMule stamps into every status ping; a real server echoes
/// it as the FIRST u32 of the response, so we can confirm the answer is to OUR ping.
pub const SERV_STAT_CHALLENGE: u32 = 0x5061_644D; // "PadM"

/// Parse an OP_GLOBSERVSTATRES payload into `(challenge, users, files)`, or None if
/// it is shorter than the 12-byte minimum. Any trailing extension is ignored.
pub fn parse_serv_stat_res(payload: &[u8]) -> Option<(u32, u32, u32)> {
    if payload.len() < 12 {
        return None;
    }
    let challenge = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let users = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let files = u32::from_le_bytes([payload[8], payload[9], payload[10], payload[11]]);
    Some((challenge, users, files))
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
    fn get_server_list_is_the_bodiless_0x14() {
        let pkt = build_get_server_list();
        assert_eq!(pkt.protocol, PROT_EDONKEY);
        assert_eq!(pkt.opcode, OP_GETSERVERLIST);
        assert!(
            pkt.payload.is_empty(),
            "eMule sends Packet(OP_GETSERVERLIST,0)"
        );
        // Exact wire bytes: proto, u32 size (opcode only = 1), opcode.
        assert_eq!(write_packet(&pkt), vec![0xE3, 0x01, 0x00, 0x00, 0x00, 0x14]);
    }

    /// OP_SERVER_LIST_RES (0xA1, the UDP crawl answer) carries the SAME payload
    /// as TCP OP_SERVERLIST, which is why the crawl reuses parse_server_list
    /// rather than adding a second parser. Bytes taken from the shape in
    /// eMule opcodes.h:202 - `<count 1>(<ip 4><port 2>)[count]`.
    #[test]
    fn the_udp_crawl_answer_shares_the_serverlist_payload() {
        // count=2, then 85.17.116.222:4242 and 77.42.68.79:4232.
        let payload = [2, 85, 17, 116, 222, 0x92, 0x10, 77, 42, 68, 79, 0x88, 0x10];
        let got = parse_server_list(&payload).unwrap();
        assert_eq!(
            got,
            vec![
                (u32::from_le_bytes([85, 17, 116, 222]), 4242),
                (u32::from_le_bytes([77, 42, 68, 79]), 4232),
            ]
        );
    }

    /// The OLD description answer: `<name_len u16><name><desc_len u16><desc>`.
    /// This is what a server that ignores our challenge sends.
    #[test]
    fn the_old_description_answer_yields_the_name() {
        let mut p = Vec::new();
        p.extend_from_slice(&9u16.to_le_bytes());
        p.extend_from_slice(b"Astra-3\0\0"[..9].as_ref());
        p.extend_from_slice(&4u16.to_le_bytes());
        p.extend_from_slice(b"desc");
        let got = parse_server_desc_res(&p, desc_req_challenge(0x1234)).unwrap();
        assert_eq!(got.name.trim_end_matches('\0'), "Astra-3");
        assert_eq!(got.description, "desc");
    }

    /// The NEW (eserver 16.45+) answer: `<challenge u32><tagcount u32><tags>`,
    /// told apart from the old form by the first u16 being INV_SERV_DESC_LEN.
    #[test]
    fn the_new_tagged_description_answer_yields_the_name() {
        let challenge = desc_req_challenge(0xBEEF);
        let mut w = Writer::new();
        w.write_u32(challenge);
        w.write_u32(2);
        write_tag(
            &mut w,
            &Tag::id(0x01, TagValue::Str(b"Drunken Donkey".to_vec())),
        );
        write_tag(&mut w, &Tag::id(0x0B, TagValue::Str(b"a server".to_vec())));
        let got = parse_server_desc_res(&w.into_inner(), challenge).unwrap();
        assert_eq!(got.name, "Drunken Donkey");
        assert_eq!(got.description, "a server");
    }

    /// A tagged answer whose challenge does NOT match ours must not be read as
    /// the new form (it would misparse); the challenge is the anti-stale/spoof
    /// check eMule applies before trusting the tags.
    #[test]
    fn a_tagged_answer_with_the_wrong_challenge_is_not_trusted() {
        let mut w = Writer::new();
        w.write_u32(desc_req_challenge(0x0001));
        w.write_u32(1);
        write_tag(&mut w, &Tag::id(0x01, TagValue::Str(b"spoofed".to_vec())));
        let got = parse_server_desc_res(&w.into_inner(), desc_req_challenge(0xBEEF));
        // Falls through to the OLD reading, which cannot yield our tag name.
        assert!(got.is_none_or(|d| d.name != "spoofed"));
    }

    #[test]
    fn the_description_challenge_keeps_its_protocol_low_half() {
        // eMule UDPSocket.cpp:436 - the low 16 bits MUST be the invalid length,
        // because that is what distinguishes the two answer forms.
        assert_eq!(
            desc_req_challenge(0xBEEF) & 0xFFFF,
            INV_SERV_DESC_LEN as u32
        );
        assert_eq!(desc_req_challenge(0xBEEF) >> 16, 0xBEEF);
    }

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
    fn serv_stat_res_reads_challenge_users_and_files() {
        // <challenge 4><users 4><files 4>, then a trailing extension.
        let res = [
            0x4D, 0x64, 0x61, 0x50, // challenge = 0x5061644D (our SERV_STAT_CHALLENGE)
            0x2A, 0x00, 0x00, 0x00, // users = 42
            0x40, 0xE2, 0x01, 0x00, // files = 123456
            0xFF, 0xFF, // trailing bytes -> ignored
        ];
        assert_eq!(
            parse_serv_stat_res(&res),
            Some((SERV_STAT_CHALLENGE, 42, 123_456))
        );
        // Below the 12-byte minimum -> None (the challenge-less 8-byte form the
        // stale header comment described is NOT a valid response).
        assert_eq!(
            parse_serv_stat_res(&[0x2A, 0, 0, 0, 0x40, 0xE2, 0x01, 0x00]),
            None
        );
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
