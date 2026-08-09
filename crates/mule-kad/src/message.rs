//! Kad2 UDP message codecs for the bootstrap/hello handshake (Wave 6b). Every
//! builder returns `(opcode, payload)` for [`crate::pack_kad`]; every parser
//! consumes an unframed payload. See docs/raw/wave6-kad-research-2026-07-14.md
//! section B, verified against amule-3.0.1 `KademliaUDPListener.cpp` /
//! `SafeFile.cpp::WriteTag`.

use mule_proto::{md4, IoError, Kad128, Reader, Writer};

// --- Kad2 opcodes (packet byte [1]); Kad1 (even) opcodes are deprecated. ---
/// Bootstrap request (empty payload).
pub const OP_BOOTSTRAP_REQ: u8 = 0x01;
/// Bootstrap response (self contact + up to 20 peers).
pub const OP_BOOTSTRAP_RES: u8 = 0x09;
/// Hello request.
pub const OP_HELLO_REQ: u8 = 0x11;
/// Hello response.
pub const OP_HELLO_RES: u8 = 0x19;
/// Hello response ACK (proves IP; sent when the peer requested it and we hold a
/// valid sender key).
pub const OP_HELLO_RES_ACK: u8 = 0x22;
/// FIND_NODE request (Wave 6c).
pub const OP_KAD2_REQ: u8 = 0x21;
/// FIND_NODE response (Wave 6c).
pub const OP_KAD2_RES: u8 = 0x29;
/// Keyword search request.
pub const OP_SEARCH_KEY_REQ: u8 = 0x33;
/// Source search request (Wave 6d).
pub const OP_SEARCH_SOURCE_REQ: u8 = 0x34;
/// Keyword/source search response (Wave 6d).
pub const OP_SEARCH_RES: u8 = 0x3B;
/// PUBLISH a keyword->file index entry (eMule KADEMLIA2_PUBLISH_KEY_REQ,
/// opcodes.h:597): `keyword_target 16 | count u16 | [ fileID 16 | taglist ]`.
pub const OP_PUBLISH_KEY_REQ: u8 = 0x43;
/// PUBLISH a source record for a file (KADEMLIA2_PUBLISH_SOURCE_REQ, :598):
/// `file_target 16 | our_client_hash 16 | taglist`.
pub const OP_PUBLISH_SOURCE_REQ: u8 = 0x44;
/// The storing node's answer to either publish (KADEMLIA2_PUBLISH_RES, :604):
/// `file 16 | load u8 | [ options u8 ]`.
pub const OP_PUBLISH_RES: u8 = 0x4B;
/// Ack the storing node solicits with option bit 0 (KADEMLIA2_PUBLISH_RES_ACK,
/// :605): a null packet. padMule deliberately never sends it - stock eMule
/// 0.50a never sets the soliciting bit in its own PUBLISH_RES sends (see the
/// PUBLISH_RES handling in `kad_live` for the citations).
pub const OP_PUBLISH_RES_ACK: u8 = 0x4C;
/// Liveness ping.
pub const OP_PING: u8 = 0x60;
/// Liveness pong.
pub const OP_PONG: u8 = 0x61;

/// aMule's `KADEMLIA_VERSION` (`kad2/Constants.h`).
pub const KADEMLIA_VERSION_AMULE: u8 = 0x08;
/// eMule's `KADEMLIA_VERSION` (`opcodes.h`).
pub const KADEMLIA_VERSION_EMULE: u8 = 0x09;
/// The version byte written into every self-contact. This is the ONE genuine
/// eMule-vs-aMule Kad wire divergence (eMule 0x09, aMule 0x08). padMule ports
/// aMule and implements exactly its v8 feature level (KADMISCOPTIONS +
/// HELLO_RES_ACK), so it advertises 0x08 - claiming 0x09 would assert eMule's
/// v9 AICH-on-keyword capability we do not provide. Interop-test both at the
/// live gate; flipping this constant is the only change needed.
pub const KADEMLIA_VERSION: u8 = KADEMLIA_VERSION_AMULE;

// --- KADEMLIA2_REQ `type` byte = GetRequestContactCount (opcodes.h:622-625;
// masked & 0x1F on receive). Selects how many contacts the peer returns. ---
/// FIND_VALUE (file/keyword/source/notes searches).
pub const KAD_FIND_VALUE: u8 = 0x02;
/// STORE (publish/buddy).
pub const KAD_STORE: u8 = 0x04;
/// FIND_NODE (node/refresh searches); also the wider FIND_VALUE_MORE reask.
pub const KAD_FIND_NODE: u8 = 0x0B;
/// FIND_VALUE_MORE: the wider reask, same byte as FIND_NODE.
pub const KAD_FIND_VALUE_MORE: u8 = 0x0B;

// --- Kad tag name IDs (single-byte names; amule FileTags.h). ---
/// Sender's internal Kad UDP port (u16).
pub const TAG_SOURCEUPORT: u8 = 0xFC;
/// Firewall/ack option bits: `0x01` UDP-fw, `0x02` TCP-fw, `0x04` requests
/// HELLO_RES_ACK (u8).
pub const TAG_KADMISCOPTIONS: u8 = 0xF2;
/// Source-result tags (KADEMLIA2_SEARCH_RES). `TAG_SOURCETYPE`: 1=HighID,
/// 3=firewalled+buddy, 4=HighID >4GB, 5=firewalled >4GB, 6=firewalled callback.
pub const TAG_SOURCETYPE: u8 = 0xFF;
/// Source IP (u32, host order).
pub const TAG_SOURCEIP: u8 = 0xFE;
/// Source TCP port (u16).
pub const TAG_SOURCEPORT: u8 = 0xFD;
/// The source's obfuscation connect-options byte (u8): `0x01` crypt supported,
/// `0x02` requested, `0x04` required (`0x08` is direct-UDP callback, not crypt).
/// eMule publishes it with every source (Search.cpp:798) and reads it back
/// (:1096) - it is how a client decides to obfuscate an outbound dial BEFORE any
/// hello. Same byte layout as the SX v4 / server crypt field
/// (`CUpDownClient::SetConnectOptions`, BaseClient.cpp:3188).
pub const TAG_ENCRYPTION: u8 = 0xF3;
/// Keyword-result file tags. Filename (string).
pub const TAG_FILENAME: u8 = 0x01;
/// eD2k file-type search term (Audio/Video/...), a string (eMule `TAG_FILETYPE`
/// "\x03", opcodes.h:329). Published so a storing node can filter by type.
pub const TAG_FILETYPE: u8 = 0x03;
/// File size (u32, or a BSOB u64 for >4GB).
pub const TAG_FILESIZE: u8 = 0x02;
/// Advertised source/availability count (u32).
pub const TAG_SOURCES: u8 = 0x15;

// --- Kad tag wire types (TagTypes.h). ---
const TT_HASH16: u8 = 0x01;
const TT_STRING: u8 = 0x02;
const TT_UINT32: u8 = 0x03;
const TT_FLOAT32: u8 = 0x04;
const TT_UINT16: u8 = 0x08;
const TT_UINT8: u8 = 0x09;
const TT_BSOB: u8 = 0x0A;
const TT_UINT64: u8 = 0x0B;

/// A decoded Kad tag value. Integer tags collapse to `Int` (the on-wire type is
/// re-derived minimally on write, matching eMule `CTagVarInt`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KadTagValue {
    Int(u64),
    Str(Vec<u8>),
    Bsob(Vec<u8>),
    Hash([u8; 16]),
    /// Raw 32-bit float bits (never interpreted here).
    Float(u32),
}

/// A Kad tag: a single-byte name and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadTag {
    pub name: u8,
    pub value: KadTagValue,
}

fn write_name(w: &mut Writer, name: u8) {
    w.write_u16(1); // nameLen; Kad names are single bytes
    w.write_u8(name);
}

/// Serialise one tag: `<type u8><nameLen=1 u16 LE><name u8><value>`. Integer
/// values take the smallest type that holds them (eMule `CTagVarInt`).
fn write_kad_tag(w: &mut Writer, tag: &KadTag) {
    match &tag.value {
        KadTagValue::Int(v) => {
            let v = *v;
            if v <= 0xFF {
                w.write_u8(TT_UINT8);
                write_name(w, tag.name);
                w.write_u8(v as u8);
            } else if v <= 0xFFFF {
                w.write_u8(TT_UINT16);
                write_name(w, tag.name);
                w.write_u16(v as u16);
            } else if v <= 0xFFFF_FFFF {
                w.write_u8(TT_UINT32);
                write_name(w, tag.name);
                w.write_u32(v as u32);
            } else {
                w.write_u8(TT_UINT64);
                write_name(w, tag.name);
                w.write_u64(v);
            }
        }
        KadTagValue::Str(s) => {
            w.write_u8(TT_STRING);
            write_name(w, tag.name);
            w.write_string_u16(s);
        }
        KadTagValue::Bsob(b) => {
            w.write_u8(TT_BSOB);
            write_name(w, tag.name);
            // BSOB length is a single byte; cap so prefix and payload agree (a
            // wrapped count would desync the whole taglist).
            let n = b.len().min(u8::MAX as usize);
            w.write_u8(n as u8);
            w.write_bytes(&b[..n]);
        }
        KadTagValue::Hash(h) => {
            w.write_u8(TT_HASH16);
            write_name(w, tag.name);
            w.write_bytes(h);
        }
        KadTagValue::Float(bits) => {
            w.write_u8(TT_FLOAT32);
            write_name(w, tag.name);
            w.write_u32(*bits);
        }
    }
}

/// Read one tag: `<type u8><nameLen u16 LE><name bytes><value>`. eMule
/// `CFileDataIO::ReadTag` reads the name as a length-prefixed string, so a Kad
/// single-byte name is `01 00 <byte>`; we take the first byte as the name ID
/// (like eMule, which then string-compares it) and tolerate any name length so
/// one odd tag never fails a whole result. An unknown TYPE is still an error -
/// we cannot know its value length to skip it.
fn read_kad_tag(r: &mut Reader) -> Result<KadTag, IoError> {
    let ty = r.read_u8()?;
    let name_len = r.read_u16()? as usize;
    let name_bytes = r.read_bytes(name_len)?;
    let name = name_bytes.first().copied().unwrap_or(0);
    let value = match ty {
        TT_UINT8 => KadTagValue::Int(r.read_u8()? as u64),
        TT_UINT16 => KadTagValue::Int(r.read_u16()? as u64),
        TT_UINT32 => KadTagValue::Int(r.read_u32()? as u64),
        TT_UINT64 => KadTagValue::Int(r.read_u64()?),
        TT_STRING => KadTagValue::Str(r.read_string_u16()?),
        TT_BSOB => {
            let n = r.read_u8()? as usize;
            KadTagValue::Bsob(r.read_bytes(n)?)
        }
        TT_HASH16 => {
            let mut h = [0u8; 16];
            h.copy_from_slice(&r.read_bytes(16)?);
            KadTagValue::Hash(h)
        }
        TT_FLOAT32 => KadTagValue::Float(r.read_u32()?),
        other => return Err(IoError::BadTag(other)),
    };
    Ok(KadTag { name, value })
}

fn read_id(r: &mut Reader) -> Result<Kad128, IoError> {
    let mut b = [0u8; 16];
    b.copy_from_slice(&r.read_bytes(16)?);
    Ok(Kad128::from_wire(&b))
}

// --- BOOTSTRAP ---

/// KADEMLIA2_BOOTSTRAP_REQ: empty payload (eMule `Bootstrap()`).
pub fn build_bootstrap_req() -> (u8, Vec<u8>) {
    (OP_BOOTSTRAP_REQ, Vec::new())
}

// --- PING / PONG ---

/// KADEMLIA2_PING: empty payload, like the bootstrap request.
pub fn build_ping() -> (u8, Vec<u8>) {
    (OP_PING, Vec::new())
}

/// KADEMLIA2_PONG, carrying the UDP port we received the ping FROM.
///
/// The payload is NOT empty and it is not about us: eMule's own comment is that
/// a ping "is however only used to determine ones external port"
/// (`Process_KADEMLIA2_PING`, KademliaUDPListener.cpp:1970-1977), and it writes
/// back `uUDPPort` - the port the ping arrived from - so the pinging peer learns
/// its own external port. Its `Process_KADEMLIA2_PONG` THROWS on a payload
/// shorter than 2 bytes, so an empty pong is rejected outright rather than
/// merely being unhelpful.
pub fn build_pong(requester_udp_port: u16) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.write_u16(requester_udp_port);
    (OP_PONG, w.into_inner())
}

/// A contact as it appears on the wire (25 bytes; no UDP key / verified flag,
/// unlike the 34-byte nodes.dat record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireContact {
    pub id: Kad128,
    /// IPv4 in HOST order - the `u32::from(Ipv4Addr)` convention, first octet
    /// in the HIGH byte, exactly like `nodes.dat`'s `KadContact.ip` (eMule
    /// keeps contact IPs host-order and `WriteUInt32`s them LE, so our LE read
    /// recovers the host value directly). `is_blocked_u32` and
    /// `Ipv4Addr::from(u32)` take it RAW; running it through
    /// `mule_files::ip_from_met_u32` (the `.met` low-byte-first convention)
    /// reverses every address - the byte-order bug class fixed three times in
    /// 2026-08 (rows 8cq/8ct). This comment exists because this field feeds
    /// the Kad blocklist gate and carried no convention note at all.
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
}

/// A parsed KADEMLIA2_BOOTSTRAP_RES: the responder's self-contact plus its peer
/// list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapRes {
    pub id: Kad128,
    pub tcp_port: u16,
    pub version: u8,
    pub contacts: Vec<WireContact>,
}

fn read_wire_contact(r: &mut Reader) -> Result<WireContact, IoError> {
    Ok(WireContact {
        id: read_id(r)?,
        ip: r.read_u32()?,
        udp_port: r.read_u16()?,
        tcp_port: r.read_u16()?,
        version: r.read_u8()?,
    })
}

/// The 25-byte wire contact record: `clientID 16 | IP 4 | UDP 2 | TCP 2 | ver 1`.
/// Shared by BOOTSTRAP_RES and KADEMLIA2_RES.
fn write_wire_contact(w: &mut Writer, c: &WireContact) {
    w.write_bytes(&c.id.to_wire());
    w.write_u32(c.ip);
    w.write_u16(c.udp_port);
    w.write_u16(c.tcp_port);
    w.write_u8(c.version);
}

/// Parse a BOOTSTRAP_RES payload: `selfID 16 | tcpPort 2 | version 1 | count 2 |
/// count x 25-byte contact`.
pub fn parse_bootstrap_res(payload: &[u8]) -> Result<BootstrapRes, IoError> {
    let mut r = Reader::new(payload);
    let id = read_id(&mut r)?;
    let tcp_port = r.read_u16()?;
    let version = r.read_u8()?;
    let count = r.read_u16()?;
    let mut contacts = Vec::new();
    for _ in 0..count {
        contacts.push(read_wire_contact(&mut r)?);
    }
    Ok(BootstrapRes {
        id,
        tcp_port,
        version,
        contacts,
    })
}

/// Build a BOOTSTRAP_RES payload (for our own listener / tests).
pub fn build_bootstrap_res(
    id: &Kad128,
    tcp_port: u16,
    version: u8,
    contacts: &[WireContact],
) -> (u8, Vec<u8>) {
    // Cap so the u16 count and the emitted records always agree.
    let contacts = &contacts[..contacts.len().min(u16::MAX as usize)];
    let mut w = Writer::new();
    w.write_bytes(&id.to_wire());
    w.write_u16(tcp_port);
    w.write_u8(version);
    w.write_u16(contacts.len() as u16);
    for c in contacts {
        write_wire_contact(&mut w, c);
    }
    (OP_BOOTSTRAP_RES, w.into_inner())
}

// --- HELLO ---

/// A parsed HELLO_REQ/RES body (eMule `SendMyDetails` / `AddContact2`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub id: Kad128,
    pub tcp_port: u16,
    pub version: u8,
    /// TAG_SOURCEUPORT: the sender's real (internal) UDP port, if present.
    pub source_udp_port: Option<u16>,
    /// TAG_KADMISCOPTIONS bits, if present.
    pub misc_options: Option<u8>,
}

fn build_my_details(
    id: &Kad128,
    tcp_port: u16,
    source_udp_port: Option<u16>,
    misc_options: Option<u8>,
) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_bytes(&id.to_wire());
    w.write_u16(tcp_port);
    w.write_u8(KADEMLIA_VERSION);
    let mut tags = Vec::new();
    if let Some(p) = source_udp_port {
        tags.push(KadTag {
            name: TAG_SOURCEUPORT,
            value: KadTagValue::Int(p as u64),
        });
    }
    if let Some(m) = misc_options {
        tags.push(KadTag {
            name: TAG_KADMISCOPTIONS,
            value: KadTagValue::Int(m as u64),
        });
    }
    w.write_u8(tags.len() as u8);
    for t in &tags {
        write_kad_tag(&mut w, t);
    }
    w.into_inner()
}

/// KADEMLIA2_HELLO_REQ. `source_udp_port` is our real UDP port (omit only when
/// using an external Kad port); `misc_options` carries firewall bits. Do NOT
/// set bit 0x04 on a REQUEST: "send me a HELLO_RES_ACK" is the RESPONDER's bit,
/// set in its HELLO_RES (eMule SendMyDetails requestAckPacket); on a request it
/// trips aMule's AddContact2 wxFAIL and earns nothing (wave 10, commit 65a186b).
pub fn build_hello_req(
    id: &Kad128,
    tcp_port: u16,
    source_udp_port: Option<u16>,
    misc_options: Option<u8>,
) -> (u8, Vec<u8>) {
    (
        OP_HELLO_REQ,
        build_my_details(id, tcp_port, source_udp_port, misc_options),
    )
}

/// KADEMLIA2_HELLO_RES (same body as the request).
pub fn build_hello_res(
    id: &Kad128,
    tcp_port: u16,
    source_udp_port: Option<u16>,
    misc_options: Option<u8>,
) -> (u8, Vec<u8>) {
    (
        OP_HELLO_RES,
        build_my_details(id, tcp_port, source_udp_port, misc_options),
    )
}

/// Parse a HELLO_REQ/RES body, extracting the SOURCEUPORT and KADMISCOPTIONS
/// tags and ignoring any others.
pub fn parse_hello(payload: &[u8]) -> Result<Hello, IoError> {
    let mut r = Reader::new(payload);
    let id = read_id(&mut r)?;
    let tcp_port = r.read_u16()?;
    let version = r.read_u8()?;
    if version == 0 {
        return Err(IoError::BadTag(version)); // eMule rejects version 0
    }
    let tag_count = r.read_u8()?;
    let mut source_udp_port = None;
    let mut misc_options = None;
    for _ in 0..tag_count {
        let t = read_kad_tag(&mut r)?;
        match t.name {
            TAG_SOURCEUPORT => {
                if let KadTagValue::Int(v) = t.value {
                    if v > 0 && v <= 0xFFFF {
                        source_udp_port = Some(v as u16);
                    }
                }
            }
            TAG_KADMISCOPTIONS => {
                if let KadTagValue::Int(v) = t.value {
                    misc_options = Some(v as u8);
                }
            }
            _ => {}
        }
    }
    Ok(Hello {
        id,
        tcp_port,
        version,
        source_udp_port,
        misc_options,
    })
}

/// KADEMLIA2_HELLO_RES_ACK: `selfID 16 | u8 0` (no tags).
pub fn build_hello_res_ack(id: &Kad128) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.write_bytes(&id.to_wire());
    w.write_u8(0);
    (OP_HELLO_RES_ACK, w.into_inner())
}

/// Parse a HELLO_RES_ACK, returning the sender's Kad ID. eMule requires
/// `len >= 17`.
pub fn parse_hello_res_ack(payload: &[u8]) -> Result<Kad128, IoError> {
    if payload.len() < 17 {
        return Err(IoError::UnexpectedEof);
    }
    let mut r = Reader::new(payload);
    read_id(&mut r)
}

// --- FIND_NODE: KADEMLIA2_REQ / KADEMLIA2_RES (iterative lookup, Wave 6c) ---

/// A parsed KADEMLIA2_REQ: `type 1 | target 16 | receiver 16` (33 bytes). eMule
/// `ProcessKademlia2Request`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kad2Req {
    /// Requested contact count / mode (low 5 bits; `& 0x1F` on receive).
    pub req_type: u8,
    /// The node ID being searched for.
    pub target: Kad128,
    /// The recipient's own Kad ID - a sanity check; the recipient silently drops
    /// the request unless this equals its KadID.
    pub receiver: Kad128,
}

/// Build a KADEMLIA2_REQ. `req_type` is one of [`KAD_FIND_NODE`] /
/// [`KAD_FIND_VALUE`] / [`KAD_STORE`]; `receiver` is the destination node's Kad
/// ID (its own-ID sanity check).
pub fn build_kad2_req(req_type: u8, target: &Kad128, receiver: &Kad128) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.write_u8(req_type);
    w.write_bytes(&target.to_wire());
    w.write_bytes(&receiver.to_wire());
    (OP_KAD2_REQ, w.into_inner())
}

/// Parse a KADEMLIA2_REQ. `req_type` is masked to its low 5 bits as eMule does;
/// a zero type is rejected.
pub fn parse_kad2_req(payload: &[u8]) -> Result<Kad2Req, IoError> {
    let mut r = Reader::new(payload);
    let req_type = r.read_u8()? & 0x1F;
    if req_type == 0 {
        return Err(IoError::BadTag(0));
    }
    let target = read_id(&mut r)?;
    let receiver = read_id(&mut r)?;
    Ok(Kad2Req {
        req_type,
        target,
        receiver,
    })
}

/// A parsed KADEMLIA2_RES: the echoed target plus up to 32 contacts closer to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kad2Res {
    pub target: Kad128,
    pub contacts: Vec<WireContact>,
}

/// Build a KADEMLIA2_RES: `target 16 | count 1 | count x 25-byte contact`.
pub fn build_kad2_res(target: &Kad128, contacts: &[WireContact]) -> (u8, Vec<u8>) {
    // The count is one byte; cap so it always matches the emitted records (a
    // wrapped count is a malformed packet). eMule never sends more than 32.
    let contacts = &contacts[..contacts.len().min(u8::MAX as usize)];
    let mut w = Writer::new();
    w.write_bytes(&target.to_wire());
    w.write_u8(contacts.len() as u8);
    for c in contacts {
        write_wire_contact(&mut w, c);
    }
    (OP_KAD2_RES, w.into_inner())
}

/// Parse a KADEMLIA2_RES, enforcing eMule's exact-length check
/// `len == 17 + 25*count`. Kad1 contacts (version <= 1) are dropped, as eMule
/// does. Returns every accepted contact; distance/IP filtering is the lookup's
/// job.
pub fn parse_kad2_res(payload: &[u8]) -> Result<Kad2Res, IoError> {
    let mut r = Reader::new(payload);
    let target = read_id(&mut r)?;
    let count = r.read_u8()? as usize;
    if payload.len() != 17 + 25 * count {
        return Err(IoError::UnexpectedEof);
    }
    let mut contacts = Vec::with_capacity(count);
    for _ in 0..count {
        let c = read_wire_contact(&mut r)?;
        if c.version > 1 {
            contacts.push(c);
        }
    }
    Ok(Kad2Res { target, contacts })
}

// --- SOURCE SEARCH: KADEMLIA2_SEARCH_SOURCE_REQ / KADEMLIA2_SEARCH_RES (6d) ---

/// Build a KADEMLIA2_SEARCH_SOURCE_REQ (26 bytes): `target 16 | startPos 2 |
/// fileSize 8`. `target` is the ed2k file hash as a Kad ID; `start_pos` is masked
/// to 15 bits by the receiver. eMule `Process2SearchSourceRequest`.
pub fn build_search_source_req(target: &Kad128, start_pos: u16, file_size: u64) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.write_bytes(&target.to_wire());
    w.write_u16(start_pos & 0x7FFF);
    w.write_u64(file_size);
    (OP_SEARCH_SOURCE_REQ, w.into_inner())
}

/// One result in a KADEMLIA2_SEARCH_RES: the answer hash (a source's client
/// hash, for a source search) plus its tag list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchResult {
    /// The source's client hash (`sourceID`), as a raw 16-byte value.
    pub answer: Kad128,
    pub tags: Vec<KadTag>,
}

/// A parsed KADEMLIA2_SEARCH_RES.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchRes {
    /// The responding node's Kad ID.
    pub responder: Kad128,
    /// The search key echoed back (the file/keyword hash).
    pub target: Kad128,
    pub results: Vec<SearchResult>,
}

/// Parse a KADEMLIA2_SEARCH_RES: `responderID 16 | target 16 | count 2 | count x
/// { answer 16 | taglist }`. eMule `Process2SearchResponse` /
/// `ProcessSearchResponse`.
pub fn parse_search_res(payload: &[u8]) -> Result<SearchRes, IoError> {
    let mut r = Reader::new(payload);
    let responder = read_id(&mut r)?;
    let target = read_id(&mut r)?;
    let count = r.read_u16()?;
    let mut results = Vec::new();
    for _ in 0..count {
        let answer = read_id(&mut r)?;
        let tags = read_kad_taglist(&mut r)?;
        results.push(SearchResult { answer, tags });
    }
    Ok(SearchRes {
        responder,
        target,
        results,
    })
}

/// A file source distilled from a source-search result's tags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// The source's client hash (the result's answer ID, wire form).
    pub client_hash: Kad128,
    /// TAG_SOURCETYPE: 1=HighID, 3=firewalled+buddy, 4=HighID>4GB,
    /// 5=firewalled>4GB, 6=firewalled callback.
    pub source_type: u8,
    /// TAG_SOURCEIP (host order), if present. HighID sources carry a real IP;
    /// firewalled ones (types 3/6) are reached via buddy/callback instead.
    pub ip: Option<u32>,
    /// TAG_SOURCEPORT (TCP), if present.
    pub tcp_port: Option<u16>,
    /// TAG_SOURCEUPORT (UDP), if present.
    pub udp_port: Option<u16>,
    /// TAG_ENCRYPTION connect-options byte, if the publisher sent one. `None`
    /// means we know nothing about this source's obfuscation support, which is
    /// eMule's default (an all-zero byte) and dials PLAINTEXT.
    pub crypt: Option<u8>,
}

impl SearchResult {
    /// Distil this result's tags into a [`Source`]. eMule `ProcessResultFile`
    /// accepts source types {1,3,4,5,6}; `None` for any other (e.g. a keyword
    /// result, which has no SOURCETYPE tag).
    pub fn as_source(&self) -> Option<Source> {
        let mut source_type = None;
        let mut ip = None;
        let mut tcp_port = None;
        let mut udp_port = None;
        let mut crypt = None;
        for t in &self.tags {
            if let KadTagValue::Int(v) = t.value {
                match t.name {
                    TAG_SOURCETYPE => source_type = Some(v as u8),
                    TAG_SOURCEIP => ip = Some(v as u32),
                    TAG_SOURCEPORT => tcp_port = Some(v as u16),
                    TAG_SOURCEUPORT => udp_port = Some(v as u16),
                    TAG_ENCRYPTION => crypt = Some(v as u8),
                    _ => {}
                }
            }
        }
        let source_type = source_type?;
        if !matches!(source_type, 1 | 3 | 4 | 5 | 6) {
            return None;
        }
        Some(Source {
            client_hash: self.answer,
            source_type,
            ip,
            tcp_port,
            udp_port,
            crypt,
        })
    }
}

/// Characters that SEPARATE Kad keywords - eMule `INV_KAD_KEYWORD_CHARS`
/// (SearchManager.h:34). Everything between them is one indexable word.
pub const INV_KAD_KEYWORD_CHARS: &str = " ()[]{}<>,._-!?:;\\/\"";

/// Minimum UTF-8 BYTE length of an indexable keyword (eMule `GetWords`, and its
/// own comment explains the choice: bytes rather than chars works for Western
/// locales only as long as the floor stays at 3).
const MIN_KEYWORD_BYTES: usize = 3;

/// Split a search phrase into the words Kad actually indexes, exactly as eMule's
/// `CSearchManager::GetWords` does (SearchManager.cpp).
///
/// THIS IS THE WHOLE REASON MULTI-WORD KAD SEARCH WORKS. Kad indexes one entry
/// per WORD, never per phrase - so hashing the raw query string targets a hash
/// nobody ever published to, and the lookup converges perfectly on an empty
/// region and reports nothing. padMule did exactly that until 2026-08-07: a
/// search for "Yes Prime Minister" returned 0 while "minister" alone returned a
/// full page. Single-word queries always worked, which is why it went unseen.
///
/// The rules, all of them from `GetWords`:
/// - split on [`INV_KAD_KEYWORD_CHARS`];
/// - keep a token only if its UTF-8 byte length is >= [`MIN_KEYWORD_BYTES`];
/// - lowercase it;
/// - de-duplicate by REMOVING an earlier copy and appending, so a repeated word
///   takes its LAST position, not its first;
/// - and finally, if more than one word survived and the last token examined was
///   exactly 3 chars AND 3 bytes, drop it - upstream's reasoning is that such a
///   trailing token "is in almost all cases a file's extension".
pub fn kad_keywords(phrase: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let (mut last_chars, mut last_bytes) = (0usize, 0usize);
    for tok in phrase.split(|c| INV_KAD_KEYWORD_CHARS.contains(c)) {
        // An EMPTY token still counts as an iteration, and that is load-bearing
        // rather than pedantry: upstream's loop runs once per delimiter run and
        // leaves `uChars`/`uBytes` at 0, so the extension rule below reads 0 and
        // does NOT fire. The visible consequence is that a trailing delimiter
        // SUPPRESSES the extension drop - "...[DVD]" keeps "dvd" while
        // "...DVD" would lose it. Skipping empties here silently kept stale
        // values and dropped the last real word.
        last_chars = tok.chars().count();
        last_bytes = tok.len();
        if last_bytes < MIN_KEYWORD_BYTES {
            continue;
        }
        let w = tok.to_lowercase();
        words.retain(|e| e != &w);
        words.push(w);
    }
    // The trailing-extension rule. Guarded on more than one word so a search for
    // just "avi" still searches for "avi".
    if words.len() > 1 && last_chars == 3 && last_bytes == 3 {
        words.pop();
    }
    words
}

/// The word a Kad keyword search is actually TARGETED at: the first surviving
/// token (eMule `m_listWords.front()`, SearchManager.cpp:140). The remaining
/// words are not sent - they filter the results locally.
pub fn kad_primary_keyword(phrase: &str) -> Option<String> {
    kad_keywords(phrase).into_iter().next()
}

/// Does `filename` satisfy every word of `query`? eMule applies this to each
/// returned result (Search.cpp:1379-1395): the wire only matched ONE keyword, so
/// without this a search for "yes prime minister" returns everything indexed
/// under "yes".
pub fn kad_filename_matches(filename: &str, query: &str) -> bool {
    let have = kad_keywords(filename);
    kad_keywords(query).iter().all(|w| have.contains(w))
}

/// The Kad keyword-search target: `SetValueBE(MD4(utf8(keyword)))`. Keywords are
/// lowercased so a search matches a publisher's (case-insensitive) keyword.
/// eMule `KadGetKeywordHash` (Kademlia.cpp:500).
///
/// Takes ONE word. Pass [`kad_primary_keyword`] of a phrase, never the phrase.
pub fn kad_keyword_target(keyword: &str) -> Kad128 {
    Kad128::from_hash(&md4(keyword.to_lowercase().as_bytes()))
}

/// The "restrictive" bit in a SEARCH_KEY_REQ's start-position word: when set, a
/// boolean search-expression tree follows the u16 and the STORING NODE applies
/// it before choosing which results to return. The low 15 bits are the start
/// position (eMule `Process_KADEMLIA2_SEARCH_KEY_REQ`,
/// KademliaUDPListener.cpp: `uRestrictive = ((uStartPosition & 0x8000) == 0x8000)`).
pub const SEARCH_KEY_RESTRICTIVE: u16 = 0x8000;

// --- Search-expression tree node types (KademliaUDPListener.cpp
// `CreateSearchExpressionTree`, written by SearchResultsWnd.cpp:895-920). ---
/// Boolean node: followed by a bool-op byte, then LEFT then RIGHT subtree.
const EXPR_BOOL: u8 = 0x00;
/// String term: followed by a u16-length-prefixed UTF-8 string.
const EXPR_STRING: u8 = 0x01;
/// Bool-op: AND.
const EXPR_AND: u8 = 0x00;

/// eMule refuses a tree deeper than this (`CreateSearchExpressionTree`: "if
/// (iLevel >= 24) ... exceeds depth limit"), so an AND-chain must stay inside it
/// or the far end silently discards the whole expression.
pub const EXPR_MAX_DEPTH: usize = 24;

/// Encode "every one of these words appears" as a search-expression tree.
///
/// WHY THIS MATTERS, and it is not an optimisation. A keyword search puts ONE
/// word on the wire, so the storing node returns a bounded sample of everything
/// indexed under it. For a common first word ("yes") that sample is drawn from
/// an enormous pool and the file you want is almost certainly not in it - the
/// caller then filters locally and gets nothing, which looks identical to "not
/// published". With the tree, the node filters BEFORE choosing, so the sample is
/// drawn from matches only.
///
/// Encoding is PREFIX (operator, then left, then right), so N words become a
/// right-leaning chain: `AND w0 (AND w1 (AND w2 w3))`. Depth is therefore N-1
/// and is capped at [`EXPR_MAX_DEPTH`]; surplus words are dropped from the WIRE
/// expression only - the caller still filters those locally, so a very long
/// query loses efficiency, never correctness.
///
/// Returns `None` for fewer than two words: one word needs no restriction (it is
/// already the target), and eMule sends a bare term rather than a bool node.
pub fn build_search_expression_and(words: &[String]) -> Option<Vec<u8>> {
    if words.len() < 2 {
        return None;
    }
    // Keep the chain inside the depth limit: `take` words, leaving depth = n-1.
    let n = words.len().min(EXPR_MAX_DEPTH);
    let mut w = Writer::new();
    for word in &words[..n - 1] {
        w.write_u8(EXPR_BOOL);
        w.write_u8(EXPR_AND);
        w.write_u8(EXPR_STRING);
        w.write_string_u16(word.to_lowercase().as_bytes());
    }
    // The tail of the chain is the last word as a bare string term.
    w.write_u8(EXPR_STRING);
    w.write_string_u16(words[n - 1].to_lowercase().as_bytes());
    Some(w.into_inner())
}

/// Build a KADEMLIA2_SEARCH_KEY_REQ: `target 16 | flags 2`. `flags` is 0 for a
/// plain keyword search; see [`build_search_key_req_restrictive`] to attach a
/// search-expression tree. eMule `Search.cpp:473/506`.
pub fn build_search_key_req(target: &Kad128, flags: u16) -> (u8, Vec<u8>) {
    let mut w = Writer::new();
    w.write_bytes(&target.to_wire());
    w.write_u16(flags);
    (OP_SEARCH_KEY_REQ, w.into_inner())
}

/// A keyword search that asks the STORING NODE to filter: `target 16 |
/// (start_pos | 0x8000) u16 | expression-tree`.
///
/// Falls back to the plain form when `words` carries no restriction to express,
/// so a single-word query is byte-identical to what padMule sent before.
pub fn build_search_key_req_restrictive(
    target: &Kad128,
    start_pos: u16,
    words: &[String],
) -> (u8, Vec<u8>) {
    let Some(expr) = build_search_expression_and(words) else {
        return build_search_key_req(target, start_pos & !SEARCH_KEY_RESTRICTIVE);
    };
    let mut w = Writer::new();
    w.write_bytes(&target.to_wire());
    // The flag rides in the TOP bit of the start position, not a separate field;
    // the receiver masks it off with & 0x7FFF before using the value.
    w.write_u16((start_pos & !SEARCH_KEY_RESTRICTIVE) | SEARCH_KEY_RESTRICTIVE);
    w.write_bytes(&expr);
    (OP_SEARCH_KEY_REQ, w.into_inner())
}

/// A file found by a keyword search (distilled from a KADEMLIA2_SEARCH_RES
/// result's file tags).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileResult {
    /// The ed2k file hash (canonical) - feed to a source search / download.
    pub hash: [u8; 16],
    pub name: String,
    pub size: u64,
    /// Advertised availability (TAG_SOURCES), 0 if absent.
    pub sources: u32,
}

impl SearchResult {
    /// Distil this result's tags into a keyword [`FileResult`]. `None` unless it
    /// carries a filename and a nonzero size (e.g. a source result, which has no
    /// filename). The result's answer ID is the file's ed2k hash.
    pub fn as_file(&self) -> Option<FileResult> {
        let mut name = None;
        let mut size = None;
        let mut sources = 0u32;
        for t in &self.tags {
            match (t.name, &t.value) {
                (TAG_FILENAME, KadTagValue::Str(s)) => {
                    name = Some(String::from_utf8_lossy(s).into_owned())
                }
                (TAG_FILESIZE, KadTagValue::Int(v)) => size = Some(*v),
                (TAG_FILESIZE, KadTagValue::Bsob(b)) if b.len() == 8 => {
                    size = Some(u64::from_le_bytes(b[..8].try_into().unwrap()))
                }
                (TAG_SOURCES, KadTagValue::Int(v)) => sources = *v as u32,
                _ => {}
            }
        }
        let name = name?;
        let size = size?;
        if size == 0 {
            return None;
        }
        Some(FileResult {
            hash: self.answer.to_hash(),
            name,
            size,
            sources,
        })
    }
}

/// Read a Kad tag list: `<u8 count>` then `count` tags.
fn read_kad_taglist(r: &mut Reader) -> Result<Vec<KadTag>, IoError> {
    let count = r.read_u8()? as usize;
    let mut tags = Vec::with_capacity(count);
    for _ in 0..count {
        tags.push(read_kad_tag(r)?);
    }
    Ok(tags)
}

fn write_kad_taglist(w: &mut Writer, tags: &[KadTag]) {
    w.write_u8(tags.len() as u8);
    for t in tags {
        write_kad_tag(w, t);
    }
}

/// What we publish about ONE shared file under a keyword. The storing node
/// indexes these tags against the keyword hash so a searcher's expression tree
/// can filter (eMule `PreparePacketForTags`, Search.cpp:1579). Size chooses
/// its tag width the same way the search parser reads it back: <=4GB as a
/// UINT, above as an 8-byte BSOB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeywordEntry {
    pub file_id: Kad128,
    pub name: String,
    pub size: u64,
    /// Complete-source count we advertise (eMule `m_nCompleteSourcesCount`).
    pub complete_sources: u32,
    /// eD2k file-type search term ("Audio"/"Video"/...), empty to omit.
    pub file_type: String,
}

impl KeywordEntry {
    fn tags(&self) -> Vec<KadTag> {
        let mut tags = vec![KadTag {
            name: TAG_FILENAME,
            value: KadTagValue::Str(self.name.as_bytes().to_vec()),
        }];
        // Size: BSOB-8 above the 32-bit ceiling, UINT below - exactly the two
        // shapes `SearchResult::as_file` reads (Search.cpp:1589-1597).
        if self.size > 0xFFFF_FFFF {
            tags.push(KadTag {
                name: TAG_FILESIZE,
                value: KadTagValue::Bsob(self.size.to_le_bytes().to_vec()),
            });
        } else {
            tags.push(KadTag {
                name: TAG_FILESIZE,
                value: KadTagValue::Int(self.size),
            });
        }
        tags.push(KadTag {
            name: TAG_SOURCES,
            value: KadTagValue::Int(self.complete_sources as u64),
        });
        if !self.file_type.is_empty() {
            tags.push(KadTag {
                name: TAG_FILETYPE,
                value: KadTagValue::Str(self.file_type.as_bytes().to_vec()),
            });
        }
        tags
    }
}

/// The most files eMule packs into ONE keyword-publish datagram
/// (Search.cpp:845, `iPacketCount < 50`).
pub const PUBLISH_KEY_FILES_PER_PACKET: usize = 50;

/// Build a KADEMLIA2_PUBLISH_KEY_REQ: `keyword_target 16 | count u16 |
/// [ fileID 16 | taglist ] x count`. The caller batches at
/// [`PUBLISH_KEY_FILES_PER_PACKET`]; this refuses to emit more than that in one
/// packet (eMule's own `byPacket[1024*50]` bound made concrete), truncating and
/// correcting the count so the u16 and the records always agree.
pub fn build_publish_key_req(keyword_target: &Kad128, entries: &[KeywordEntry]) -> (u8, Vec<u8>) {
    let entries = &entries[..entries.len().min(PUBLISH_KEY_FILES_PER_PACKET)];
    let mut w = Writer::new();
    w.write_bytes(&keyword_target.to_wire());
    w.write_u16(entries.len() as u16);
    for e in entries {
        w.write_bytes(&e.file_id.to_wire());
        write_kad_taglist(&mut w, &e.tags());
    }
    (OP_PUBLISH_KEY_REQ, w.into_inner())
}

/// What we publish about OURSELVES as a source for a file. HighID only for
/// now (`TAG_SOURCETYPE` 1, or 4 for a file above 4GB); padMule does not
/// publish a firewalled buddy record (types 3/5), matching its no-buddy
/// posture. `crypt` is our connect-options byte (eMule `TAG_ENCRYPTION`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceEntry {
    pub size: u64,
    pub tcp_port: u16,
    /// Our internal Kad UDP port, if we advertise it (eMule omits it when a
    /// user forces an external port). `None` to omit `TAG_SOURCEUPORT`.
    pub udp_port: Option<u16>,
    pub crypt: u8,
}

/// Build a KADEMLIA2_PUBLISH_SOURCE_REQ: `file_target 16 | our_client_hash 16 |
/// taglist`. The taglist mirrors what `SearchResult::as_source` parses back:
/// TAG_SOURCETYPE, TAG_SOURCEPORT (TCP), optional TAG_SOURCEUPORT, TAG_FILESIZE,
/// TAG_ENCRYPTION (eMule Search.cpp:783-798).
pub fn build_publish_source_req(
    file_target: &Kad128,
    our_client_hash: &Kad128,
    src: &SourceEntry,
) -> (u8, Vec<u8>) {
    let source_type = if src.size > 0xFFFF_FFFF { 4 } else { 1 };
    let mut tags = vec![
        KadTag {
            name: TAG_SOURCETYPE,
            value: KadTagValue::Int(source_type),
        },
        KadTag {
            name: TAG_SOURCEPORT,
            value: KadTagValue::Int(src.tcp_port as u64),
        },
    ];
    if let Some(uport) = src.udp_port {
        tags.push(KadTag {
            name: TAG_SOURCEUPORT,
            value: KadTagValue::Int(uport as u64),
        });
    }
    tags.push(KadTag {
        name: TAG_FILESIZE,
        value: KadTagValue::Int(src.size),
    });
    tags.push(KadTag {
        name: TAG_ENCRYPTION,
        value: KadTagValue::Int(src.crypt as u64),
    });
    let mut w = Writer::new();
    w.write_bytes(&file_target.to_wire());
    w.write_bytes(&our_client_hash.to_wire());
    write_kad_taglist(&mut w, &tags);
    (OP_PUBLISH_SOURCE_REQ, w.into_inner())
}

/// A storing node's answer to a publish (KADEMLIA2_PUBLISH_RES): which file it
/// stored, and its LOAD 0..100 - how full its index is for that target, the
/// number eMule uses to back off republishing to a saturated node. The
/// trailing option byte (bit 0 = it wants an ACK) is parsed when present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishRes {
    pub file_id: Kad128,
    pub load: u8,
    pub wants_ack: bool,
}

/// Parse a KADEMLIA2_PUBLISH_RES: `file 16 | load u8 | [ options u8 ]`
/// (eMule `Process_KADEMLIA2_PUBLISH_RES`, KademliaUDPListener.cpp).
pub fn parse_publish_res(payload: &[u8]) -> Result<PublishRes, IoError> {
    let mut r = Reader::new(payload);
    let file_id = read_id(&mut r)?;
    let load = r.read_u8()?;
    // The options byte is optional (eMule guards on remaining length); absent
    // means no ACK solicited.
    let wants_ack = r.read_u8().map(|o| o & 0x01 != 0).unwrap_or(false);
    Ok(PublishRes {
        file_id,
        load,
        wants_ack,
    })
}

/// Build a KADEMLIA2_SEARCH_RES (a responder role / tests): `responderID 16 |
/// target 16 | count 2 | count x { answer 16 | taglist }`.
pub fn build_search_res(
    responder: &Kad128,
    target: &Kad128,
    results: &[SearchResult],
) -> (u8, Vec<u8>) {
    // Cap so the u16 count and the emitted records always agree.
    let results = &results[..results.len().min(u16::MAX as usize)];
    let mut w = Writer::new();
    w.write_bytes(&responder.to_wire());
    w.write_bytes(&target.to_wire());
    w.write_u16(results.len() as u16);
    for res in results {
        w.write_bytes(&res.answer.to_wire());
        write_kad_taglist(&mut w, &res.tags);
    }
    (OP_SEARCH_RES, w.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_req_is_empty() {
        assert_eq!(build_bootstrap_req(), (0x01, Vec::new()));
    }

    #[test]
    fn ping_is_bodiless() {
        assert_eq!(build_ping(), (OP_PING, Vec::new()));
    }

    #[test]
    fn pong_carries_the_requesters_udp_port() {
        // NOT empty, and the payload is not ours. eMule's own comment on
        // Process_KADEMLIA2_PING is "currently it is however only used to
        // determine ones external port", and it writes the port it RECEIVED the
        // ping from (KademliaUDPListener.cpp:1970-1977, WriteUInt16(uUDPPort)).
        // Its Process_KADEMLIA2_PONG THROWS on uLenPacket < 2, so an empty pong
        // is not merely unhelpful - it is rejected.
        let (op, payload) = build_pong(4672);
        assert_eq!(op, OP_PONG);
        assert_eq!(payload, vec![0x40, 0x12]); // 4672 LE
        assert_eq!(build_pong(5000).1, vec![0x88, 0x13]); // 5000 LE
    }

    #[test]
    fn hello_req_bytes_are_exact() {
        // id all-0x01 (wire form == canonical here), tcp 4662, udp 4672.
        let id = Kad128::from_hash(&[0x01; 16]);
        let (op, payload) = build_hello_req(&id, 4662, Some(4672), None);
        assert_eq!(op, OP_HELLO_REQ);
        let mut expected = vec![0x01; 16];
        expected.extend_from_slice(&[0x36, 0x12]); // tcp 4662 LE
        expected.push(KADEMLIA_VERSION); // 0x08
        expected.push(1); // tag count
                          // SOURCEUPORT (4672 > 255 -> UINT16): type 08, nameLen 01 00, name FC, val 40 12
        expected.extend_from_slice(&[0x08, 0x01, 0x00, 0xFC, 0x40, 0x12]);
        assert_eq!(payload, expected);
    }

    #[test]
    fn varint_tag_picks_uint8_for_small_values() {
        // A port <= 255 must serialise as UINT8, matching CTagVarInt.
        let id = Kad128::from_hash(&[0; 16]);
        let (_, payload) = build_hello_req(&id, 1, Some(200), Some(0x04));
        // ...tag count then SOURCEUPORT UINT8 [09 01 00 FC C8] then MISC UINT8 [09 01 00 F2 04]
        let tail = &payload[16 + 2 + 1..];
        assert_eq!(tail[0], 2, "two tags");
        assert_eq!(&tail[1..6], &[0x09, 0x01, 0x00, 0xFC, 0xC8]);
        assert_eq!(&tail[6..11], &[0x09, 0x01, 0x00, 0xF2, 0x04]);
    }

    #[test]
    fn hello_round_trips_with_tags() {
        let id = Kad128::from_hash(&[0xAB; 16]);
        let (_, payload) = build_hello_req(&id, 4662, Some(4672), Some(0x06));
        let h = parse_hello(&payload).unwrap();
        assert_eq!(h.id, id);
        assert_eq!(h.tcp_port, 4662);
        assert_eq!(h.version, KADEMLIA_VERSION);
        assert_eq!(h.source_udp_port, Some(4672));
        assert_eq!(h.misc_options, Some(0x06));
    }

    #[test]
    fn hello_res_ack_round_trips() {
        let id = Kad128::from_hash(&[0x5A; 16]);
        let (op, payload) = build_hello_res_ack(&id);
        assert_eq!(op, OP_HELLO_RES_ACK);
        assert_eq!(payload.len(), 17);
        assert_eq!(parse_hello_res_ack(&payload).unwrap(), id);
        // Too-short ACK is rejected.
        assert!(parse_hello_res_ack(&payload[..16]).is_err());
    }

    #[test]
    fn bootstrap_res_round_trips() {
        let id = Kad128::from_hash(&[0x11; 16]);
        let contacts = vec![
            WireContact {
                id: Kad128::from_hash(&[0x22; 16]),
                ip: 0x0102_0304,
                udp_port: 4672,
                tcp_port: 4662,
                version: 8,
            },
            WireContact {
                id: Kad128::from_hash(&[0x33; 16]),
                ip: 0x0506_0708,
                udp_port: 5000,
                tcp_port: 5001,
                version: 9,
            },
        ];
        let (op, payload) = build_bootstrap_res(&id, 4662, 8, &contacts);
        assert_eq!(op, OP_BOOTSTRAP_RES);
        // 16 + 2 + 1 + 2 + 2*25 = 71 bytes.
        assert_eq!(payload.len(), 71);
        let parsed = parse_bootstrap_res(&payload).unwrap();
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.tcp_port, 4662);
        assert_eq!(parsed.version, 8);
        assert_eq!(parsed.contacts, contacts);
    }

    #[test]
    fn parse_hello_rejects_version_zero_and_bad_tags() {
        // version byte 0.
        let mut bad = vec![0u8; 16];
        bad.extend_from_slice(&[0x36, 0x12, 0x00, 0x00]); // tcp, ver=0, tagcount=0
        assert!(parse_hello(&bad).is_err());
        // A tag with an UNKNOWN type is malformed - we cannot know its value
        // length to skip it (a multi-byte NAME, by contrast, is tolerated).
        let mut bad2 = vec![0u8; 16];
        bad2.extend_from_slice(&[0x36, 0x12, 0x08, 0x01]); // tcp, ver=8, tagcount=1
        bad2.extend_from_slice(&[0x99, 0x01, 0x00, 0xFC, 0x01]); // type 0x99 unknown
        assert!(parse_hello(&bad2).is_err());
    }

    #[test]
    fn tag_with_multibyte_name_is_tolerated() {
        // eMule reads the name as a string; a 2-byte name must not fail the parse.
        let mut p = vec![0u8; 16];
        p.extend_from_slice(&[0x36, 0x12, 0x08, 0x01]); // tcp 4662, ver 8, 1 tag
        p.extend_from_slice(&[0x09, 0x02, 0x00, 0xAB, 0xCD, 0x07]); // UINT8, nameLen 2
        let h = parse_hello(&p).unwrap();
        assert_eq!(h.version, 8);
    }

    #[test]
    fn kad2_req_is_33_bytes_and_round_trips() {
        let target = Kad128::from_hash(&[0x11; 16]);
        let receiver = Kad128::from_hash(&[0x22; 16]);
        let (op, payload) = build_kad2_req(KAD_FIND_NODE, &target, &receiver);
        assert_eq!(op, OP_KAD2_REQ);
        assert_eq!(payload.len(), 33);
        assert_eq!(payload[0], 0x0B);
        let req = parse_kad2_req(&payload).unwrap();
        assert_eq!(req.req_type, KAD_FIND_NODE);
        assert_eq!(req.target, target);
        assert_eq!(req.receiver, receiver);
    }

    #[test]
    fn kad2_req_masks_type_and_rejects_zero() {
        let t = Kad128::from_hash(&[0; 16]);
        // High 3 bits set - must be masked off to the low 5 (0x0B).
        let (_, mut payload) = build_kad2_req(0x0B, &t, &t);
        payload[0] = 0xEB; // 0x0B | 0xE0
        assert_eq!(parse_kad2_req(&payload).unwrap().req_type, 0x0B);
        // type == 0 is rejected.
        payload[0] = 0x00;
        assert!(parse_kad2_req(&payload).is_err());
    }

    #[test]
    fn kad2_res_round_trips_and_enforces_exact_length() {
        let target = Kad128::from_hash(&[0x33; 16]);
        let contacts: Vec<WireContact> = (0..3u8)
            .map(|i| WireContact {
                id: Kad128::from_hash(&[i + 1; 16]),
                ip: 0x0A00_0000 | i as u32,
                udp_port: 4000 + i as u16,
                tcp_port: 5000 + i as u16,
                version: 8,
            })
            .collect();
        let (op, payload) = build_kad2_res(&target, &contacts);
        assert_eq!(op, OP_KAD2_RES);
        assert_eq!(payload.len(), 17 + 25 * 3);
        let res = parse_kad2_res(&payload).unwrap();
        assert_eq!(res.target, target);
        assert_eq!(res.contacts, contacts);
        // A truncated packet fails the exact-length check.
        assert!(parse_kad2_res(&payload[..payload.len() - 1]).is_err());
    }

    #[test]
    fn kad2_res_caps_the_one_byte_count_instead_of_wrapping() {
        // 300 contacts would wrap the u8 count to 44 and desync the packet;
        // the builder caps at 255 so count and records always agree.
        let target = Kad128::from_hash(&[0x55; 16]);
        let contacts: Vec<WireContact> = (0..300u16)
            .map(|i| WireContact {
                id: Kad128::from_hash(&[(i % 251) as u8 + 1; 16]),
                ip: 0x0A00_0000 | i as u32,
                udp_port: 4000,
                tcp_port: 5000,
                version: 8,
            })
            .collect();
        let (_, payload) = build_kad2_res(&target, &contacts);
        assert_eq!(payload.len(), 17 + 25 * 255);
        let res = parse_kad2_res(&payload).unwrap();
        assert_eq!(res.contacts.len(), 255);
    }

    #[test]
    fn kad2_res_drops_kad1_contacts() {
        let target = Kad128::from_hash(&[0x44; 16]);
        let contacts = vec![
            WireContact {
                id: Kad128::from_hash(&[1; 16]),
                ip: 1,
                udp_port: 1,
                tcp_port: 1,
                version: 1, // Kad1 -> dropped
            },
            WireContact {
                id: Kad128::from_hash(&[2; 16]),
                ip: 2,
                udp_port: 2,
                tcp_port: 2,
                version: 8, // kept
            },
        ];
        let (_, payload) = build_kad2_res(&target, &contacts);
        let res = parse_kad2_res(&payload).unwrap();
        assert_eq!(res.contacts.len(), 1);
        assert_eq!(res.contacts[0].version, 8);
    }

    #[test]
    fn search_source_req_is_26_bytes_and_masks_start_pos() {
        let target = Kad128::from_hash(&[0x77; 16]);
        let (op, payload) = build_search_source_req(&target, 0xFFFF, 9_728_000);
        assert_eq!(op, OP_SEARCH_SOURCE_REQ);
        assert_eq!(payload.len(), 26);
        // start_pos is masked to 15 bits: 0xFFFF & 0x7FFF = 0x7FFF.
        assert_eq!(&payload[16..18], &[0xFF, 0x7F]);
        // fileSize u64 LE.
        assert_eq!(
            u64::from_le_bytes(payload[18..26].try_into().unwrap()),
            9_728_000
        );
    }

    #[test]
    fn search_res_round_trips_and_distils_sources() {
        let responder = Kad128::from_hash(&[0x01; 16]);
        let target = Kad128::from_hash(&[0x02; 16]);
        // A HighID source (type 1) with IP + TCP + UDP ports.
        let hi = SearchResult {
            answer: Kad128::from_hash(&[0xAA; 16]),
            tags: vec![
                KadTag {
                    name: TAG_SOURCETYPE,
                    value: KadTagValue::Int(1),
                },
                KadTag {
                    name: TAG_SOURCEIP,
                    value: KadTagValue::Int(0x5FEC_24FA),
                },
                KadTag {
                    name: TAG_SOURCEPORT,
                    value: KadTagValue::Int(4662),
                },
                KadTag {
                    name: TAG_SOURCEUPORT,
                    value: KadTagValue::Int(4672),
                },
            ],
        };
        // A keyword-style result (no SOURCETYPE) -> not a source.
        let kw = SearchResult {
            answer: Kad128::from_hash(&[0xBB; 16]),
            tags: vec![KadTag {
                name: 0x01, // TAG_FILENAME
                value: KadTagValue::Str(b"movie.avi".to_vec()),
            }],
        };
        let enc = SearchResult {
            answer: Kad128::from_hash(&[0xCC; 16]),
            tags: vec![
                KadTag {
                    name: TAG_SOURCETYPE,
                    value: KadTagValue::Int(1),
                },
                KadTag {
                    name: TAG_SOURCEIP,
                    value: KadTagValue::Int(0x5FEC_24FA),
                },
                KadTag {
                    name: TAG_SOURCEPORT,
                    value: KadTagValue::Int(4662),
                },
                // TAG_ENCRYPTION: the publisher's connect-options byte
                // (supports|requests). eMule Search.cpp:798 publishes it and
                // :1096 reads it back - it is how a client knows to obfuscate
                // an outbound dial BEFORE any hello.
                KadTag {
                    name: TAG_ENCRYPTION,
                    value: KadTagValue::Int(0x03),
                },
            ],
        };
        assert_eq!(
            enc.as_source().unwrap().crypt,
            Some(0x03),
            "TAG_ENCRYPTION must reach the Source so the dial can be obfuscated"
        );
        // A source WITHOUT the tag carries no crypt info (-> plaintext dial,
        // matching eMule's default of an all-zero connect-options byte).
        assert_eq!(hi.as_source().unwrap().crypt, None);

        let (op, payload) = build_search_res(&responder, &target, &[hi.clone(), kw.clone()]);
        assert_eq!(op, OP_SEARCH_RES);

        let parsed = parse_search_res(&payload).unwrap();
        assert_eq!(parsed.responder, responder);
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.results, vec![hi.clone(), kw.clone()]);

        let src = parsed.results[0].as_source().unwrap();
        assert_eq!(src.source_type, 1);
        assert_eq!(src.ip, Some(0x5FEC_24FA));
        assert_eq!(src.tcp_port, Some(4662));
        assert_eq!(src.udp_port, Some(4672));
        assert_eq!(src.client_hash, hi.answer);
        // The keyword result is not a source.
        assert!(parsed.results[1].as_source().is_none());
    }

    #[test]
    fn keyword_target_is_md4_of_the_lowercased_keyword() {
        use mule_proto::md4;
        let t = kad_keyword_target("PadMule");
        assert_eq!(t, Kad128::from_hash(&md4(b"padmule")));
        // Case-insensitive: different case -> same target.
        assert_eq!(kad_keyword_target("padmule"), kad_keyword_target("PADMULE"));
    }

    #[test]
    fn search_key_req_is_18_bytes() {
        let t = kad_keyword_target("linux");
        let (op, payload) = build_search_key_req(&t, 0);
        assert_eq!(op, OP_SEARCH_KEY_REQ);
        assert_eq!(payload.len(), 18); // target 16 + flags 2
        assert_eq!(&payload[16..18], &[0, 0]);
        assert_eq!(&payload[..16], &t.to_wire());
    }

    #[test]
    fn search_res_distils_a_keyword_file_result() {
        let file_hash = Kad128::from_hash(&[0xEE; 16]);
        let r = SearchResult {
            answer: file_hash,
            tags: vec![
                KadTag {
                    name: TAG_FILENAME,
                    value: KadTagValue::Str(b"ubuntu.iso".to_vec()),
                },
                KadTag {
                    name: TAG_FILESIZE,
                    value: KadTagValue::Int(4_000_000),
                },
                KadTag {
                    name: TAG_SOURCES,
                    value: KadTagValue::Int(42),
                },
            ],
        };
        let f = r.as_file().unwrap();
        assert_eq!(f.hash, file_hash.to_hash());
        assert_eq!(f.name, "ubuntu.iso");
        assert_eq!(f.size, 4_000_000);
        assert_eq!(f.sources, 42);
        // A source result (no filename) is not a file result.
        assert!(SearchResult {
            answer: file_hash,
            tags: vec![KadTag {
                name: TAG_SOURCETYPE,
                value: KadTagValue::Int(1)
            }],
        }
        .as_file()
        .is_none());
    }

    #[test]
    fn search_res_rejects_unaccepted_source_types() {
        let r = SearchResult {
            answer: Kad128::from_hash(&[0xCC; 16]),
            tags: vec![KadTag {
                name: TAG_SOURCETYPE,
                value: KadTagValue::Int(2), // not in {1,3,4,5,6}
            }],
        };
        assert!(r.as_source().is_none());
    }

    /// The rules of eMule's `CSearchManager::GetWords`, each pinned separately,
    /// because getting any one of them wrong silently returns zero results
    /// rather than failing.
    #[test]
    fn kad_keywords_tokenises_exactly_as_emule_getwords() {
        // The bug this whole function exists for: a phrase is MANY keywords.
        assert_eq!(
            kad_keywords("Yes Prime Minister"),
            ["yes", "prime", "minister"]
        );
        // Every delimiter in INV_KAD_KEYWORD_CHARS separates.
        assert_eq!(
            kad_keywords("Yes.Prime-Minister_S01(1986)[DVD]"),
            ["yes", "prime", "minister", "s01", "1986", "dvd"]
        );
        // Under 3 BYTES is dropped, never indexed.
        assert_eq!(kad_keywords("a bc minister"), ["minister"]);
        // Lowercased.
        assert_eq!(kad_keywords("MINISTER"), ["minister"]);
    }

    /// A repeat takes its LAST position - upstream removes then push_backs,
    /// which reorders rather than ignoring the duplicate. This matters because
    /// position 0 decides which word goes on the wire.
    #[test]
    fn a_repeated_word_moves_to_the_back_which_changes_the_target() {
        assert_eq!(
            kad_keywords("minister prime minister"),
            ["prime", "minister"]
        );
        assert_eq!(
            kad_primary_keyword("minister prime minister").unwrap(),
            "prime"
        );
    }

    /// The trailing 3-char/3-byte token is dropped as a presumed extension -
    /// but only when something else survives, or searching for "avi" would
    /// search for nothing.
    #[test]
    fn a_trailing_three_byte_token_is_treated_as_a_file_extension() {
        assert_eq!(
            kad_keywords("Yes Prime Minister.avi"),
            ["yes", "prime", "minister"]
        );
        assert_eq!(kad_keywords("avi"), ["avi"]);
        // Four chars is not an extension by this rule.
        assert_eq!(kad_keywords("minister.mkv4"), ["minister", "mkv4"]);
    }

    /// ONE word goes on the wire - the first - and it is NOT the hash of the
    /// phrase. This is the regression that returned zero for every multi-word
    /// search: the phrase hash targets a region nobody publishes to.
    #[test]
    fn the_target_is_the_first_word_not_the_phrase() {
        assert_eq!(kad_primary_keyword("Yes Prime Minister").unwrap(), "yes");
        assert_eq!(
            kad_keyword_target(&kad_primary_keyword("Yes Prime Minister").unwrap()),
            kad_keyword_target("yes")
        );
        assert_ne!(
            kad_keyword_target(&kad_primary_keyword("Yes Prime Minister").unwrap()),
            kad_keyword_target("Yes Prime Minister"),
            "hashing the whole phrase is the bug; they must not agree"
        );
        assert!(kad_primary_keyword("  ()  ").is_none());
    }

    /// Only one keyword reached the wire, so the OTHER words have to be applied
    /// locally or the caller gets everything indexed under "yes".
    #[test]
    fn results_are_filtered_by_every_remaining_query_word() {
        let q = "Yes Prime Minister";
        assert!(kad_filename_matches("Yes.Prime.Minister.S01E01.avi", q));
        assert!(kad_filename_matches("YES PRIME MINISTER (1986) DVDrip", q));
        // Has "yes" - which is all the wire matched - but not the rest.
        assert!(!kad_filename_matches("Yes.We.Can.mp4", q));
        // Has two of three.
        assert!(!kad_filename_matches("Yes Minister S01E01.avi", q));
    }

    /// The search-expression tree, byte for byte. Wave 6 left
    /// `CreateSearchExpressionTree` "UNSURE - not byte-decoded", so this pins
    /// the layout against BOTH sides of upstream: the writer
    /// (SearchResultsWnd.cpp:895-920) and the decoder
    /// (KademliaUDPListener.cpp `CreateSearchExpressionTree`).
    #[test]
    fn the_search_expression_tree_is_prefix_encoded_and_chain() {
        let w = |s: &str| s.to_string();
        // Two words: AND(bool) then the two string terms, prefix order.
        let e = build_search_expression_and(&[w("prime"), w("minister")]).unwrap();
        assert_eq!(
            e,
            vec![
                0x00, 0x00, // boolean node, AND
                0x01, 5, 0, b'p', b'r', b'i', b'm', b'e', // string term
                0x01, 8, 0, b'm', b'i', b'n', b'i', b's', b't', b'e', b'r',
            ]
        );
        // One word carries no restriction - nothing to AND against.
        assert!(build_search_expression_and(&[w("minister")]).is_none());
        assert!(build_search_expression_and(&[]).is_none());
        // Lowercased on the wire, as the decoder expects ("the search code
        // expects lower case strings!").
        let up = build_search_expression_and(&[w("PRIME"), w("Minister")]).unwrap();
        assert_eq!(up, e);
    }

    /// N words make a right-leaning chain of depth N-1, and it must stay inside
    /// eMule's limit (`iLevel >= 24` aborts and the far end discards the WHOLE
    /// expression, silently reverting to an unfiltered search).
    ///
    /// Decoded structurally rather than by counting bytes - the first version of
    /// this test counted 0x00 bytes, which also matches the high byte of every
    /// u16 string length, so it measured nothing.
    #[test]
    fn the_and_chain_stays_inside_emules_depth_limit() {
        /// Walk the prefix encoding exactly as `CreateSearchExpressionTree`
        /// does, returning (words seen, max depth reached).
        fn decode(b: &[u8], i: &mut usize, level: usize) -> (usize, usize) {
            match b[*i] {
                0x00 => {
                    assert_eq!(b[*i + 1], 0x00, "only AND is emitted");
                    *i += 2;
                    let (lw, ld) = decode(b, i, level + 1);
                    let (rw, rd) = decode(b, i, level + 1);
                    (lw + rw, ld.max(rd))
                }
                0x01 => {
                    *i += 1;
                    let n = u16::from_le_bytes([b[*i], b[*i + 1]]) as usize;
                    *i += 2 + n;
                    (1, level)
                }
                other => panic!("unexpected node type 0x{other:02X}"),
            }
        }

        for count in [2usize, 5, 24, 60] {
            let many: Vec<String> = (0..count).map(|i| format!("word{i:03}")).collect();
            let e = build_search_expression_and(&many).unwrap();
            let mut i = 0;
            let (words, depth) = decode(&e, &mut i, 0);
            assert_eq!(
                i,
                e.len(),
                "trailing bytes: the encoding is not well-formed"
            );
            assert_eq!(words, count.min(EXPR_MAX_DEPTH), "wrong word count encoded");
            assert_eq!(depth, words - 1, "an AND-chain of N words has depth N-1");
            assert!(
                depth < EXPR_MAX_DEPTH,
                "depth {depth} hits eMule's {EXPR_MAX_DEPTH} limit; the whole \
                 expression would be discarded"
            );
        }
    }

    /// The restrictive bit rides in the TOP bit of the start-position word, and
    /// the receiver masks it off (`uStartPosition & 0x7FFF`). A single-word query
    /// must still produce the exact plain packet padMule sent before.
    #[test]
    fn the_restrictive_flag_rides_in_the_start_position_word() {
        let t = Kad128::from_hash(&[0x33; 16]);
        let (op, p) =
            build_search_key_req_restrictive(&t, 0, &["prime".to_string(), "minister".to_string()]);
        assert_eq!(op, OP_SEARCH_KEY_REQ);
        assert_eq!(&p[..16], &t.to_wire()[..]);
        assert_eq!(u16::from_le_bytes([p[16], p[17]]), SEARCH_KEY_RESTRICTIVE);
        assert_eq!(
            &p[18..],
            &build_search_expression_and(&["prime".to_string(), "minister".to_string()]).unwrap()[..]
        );

        // One word -> byte-identical to the plain builder.
        let (_, one) = build_search_key_req_restrictive(&t, 0, &["minister".to_string()]);
        let (_, plain) = build_search_key_req(&t, 0);
        assert_eq!(
            one, plain,
            "a single-word query must not change on the wire"
        );
    }

    /// A keyword publish must be READABLE by the search-result parser: the tags
    /// we write under a fileID are exactly the ones `SearchResult::as_file`
    /// reads back. Assert the header layout AND round-trip one entry's tags
    /// through the parser (the entry body after `fileID` is a taglist, the same
    /// shape a SEARCH_RES record carries).
    #[test]
    fn a_published_keyword_entry_reads_back_through_the_search_parser() {
        let kw = Kad128::from_hash(&[0xAA; 16]);
        let entry = KeywordEntry {
            file_id: Kad128::from_hash(&[0xBB; 16]),
            name: "ubuntu.iso".to_string(),
            size: 1_500_000,
            complete_sources: 7,
            file_type: "Iso".to_string(),
        };
        let (op, p) = build_publish_key_req(&kw, std::slice::from_ref(&entry));
        assert_eq!(op, OP_PUBLISH_KEY_REQ);
        assert_eq!(&p[..16], &kw.to_wire()[..], "keyword target first");
        assert_eq!(u16::from_le_bytes([p[16], p[17]]), 1, "count = 1");
        assert_eq!(&p[18..34], &entry.file_id.to_wire()[..], "then the fileID");
        // The tag list after the fileID parses, and `as_file` recovers the
        // name and size a searcher would see.
        let mut r = Reader::new(&p[34..]);
        let tags = read_kad_taglist(&mut r).unwrap();
        let sr = SearchResult {
            answer: entry.file_id,
            tags,
        };
        let f = sr
            .as_file()
            .expect("a published keyword entry is a file result");
        assert_eq!(f.name, "ubuntu.iso");
        assert_eq!(f.size, 1_500_000);
        assert_eq!(f.sources, 7);
    }

    /// A >4GB file publishes its size as an 8-byte BSOB, which `as_file` reads
    /// via its BSOB-8 arm - the large-file path both sides must agree on.
    #[test]
    fn a_large_file_keyword_entry_uses_a_bsob_size() {
        let big = 5_000_000_000u64;
        let entry = KeywordEntry {
            file_id: Kad128::from_hash(&[0x01; 16]),
            name: "big.bin".to_string(),
            size: big,
            complete_sources: 1,
            file_type: String::new(),
        };
        let (_, p) =
            build_publish_key_req(&Kad128::from_hash(&[0; 16]), std::slice::from_ref(&entry));
        let mut r = Reader::new(&p[34..]);
        let tags = read_kad_taglist(&mut r).unwrap();
        let f = SearchResult {
            answer: entry.file_id,
            tags,
        }
        .as_file()
        .unwrap();
        assert_eq!(f.size, big, "the BSOB size survives the round trip");
    }

    /// A source publish must be READABLE by the source-result parser: the tags
    /// are exactly what `SearchResult::as_source` reads.
    #[test]
    fn a_published_source_reads_back_through_the_source_parser() {
        let file = Kad128::from_hash(&[0xCC; 16]);
        let me = Kad128::from_hash(&[0xDD; 16]);
        let src = SourceEntry {
            size: 900_000,
            tcp_port: 4662,
            udp_port: Some(4672),
            crypt: 0x03,
        };
        let (op, p) = build_publish_source_req(&file, &me, &src);
        assert_eq!(op, OP_PUBLISH_SOURCE_REQ);
        assert_eq!(&p[..16], &file.to_wire()[..], "file target first");
        assert_eq!(&p[16..32], &me.to_wire()[..], "then our client hash");
        let mut r = Reader::new(&p[32..]);
        let tags = read_kad_taglist(&mut r).unwrap();
        let source = SearchResult { answer: me, tags }
            .as_source()
            .expect("a published source is a source result");
        assert_eq!(source.tcp_port, Some(4662));
        assert_eq!(source.udp_port, Some(4672));
        assert_eq!(source.crypt, Some(0x03));
    }

    #[test]
    fn a_publish_key_req_is_capped_at_fifty_files_per_packet() {
        let entries: Vec<KeywordEntry> = (0..60u32)
            .map(|i| KeywordEntry {
                file_id: Kad128::from_words([i, 0, 0, 0]),
                name: "x".to_string(),
                size: 1,
                complete_sources: 0,
                file_type: String::new(),
            })
            .collect();
        let (_, p) = build_publish_key_req(&Kad128::from_hash(&[0; 16]), &entries);
        assert_eq!(
            u16::from_le_bytes([p[16], p[17]]),
            PUBLISH_KEY_FILES_PER_PACKET as u16,
            "one packet never carries more than 50 files"
        );
    }

    #[test]
    fn parse_publish_res_reads_the_load_and_the_optional_ack_bit() {
        let file = Kad128::from_hash(&[0x42; 16]);
        // No option byte: load only.
        let mut p = file.to_wire().to_vec();
        p.push(37);
        let res = parse_publish_res(&p).unwrap();
        assert_eq!(res.file_id, file);
        assert_eq!(res.load, 37);
        assert!(!res.wants_ack, "absent option byte means no ACK solicited");

        // Option byte with bit 0 set: ACK wanted.
        let mut p2 = file.to_wire().to_vec();
        p2.push(90);
        p2.push(0x01);
        assert!(parse_publish_res(&p2).unwrap().wants_ack);
    }
}
