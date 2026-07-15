//! Kad2 UDP message codecs for the bootstrap/hello handshake (Wave 6b). Every
//! builder returns `(opcode, payload)` for [`crate::pack_kad`]; every parser
//! consumes an unframed payload. See docs/raw/wave6-kad-research-2026-07-14.md
//! section B, verified against amule-3.0.1 `KademliaUDPListener.cpp` /
//! `SafeFile.cpp::WriteTag`.

use mule_proto::{IoError, Kad128, Reader, Writer};

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
/// Source search request (Wave 6d).
pub const OP_SEARCH_SOURCE_REQ: u8 = 0x34;
/// Keyword/source search response (Wave 6d).
pub const OP_SEARCH_RES: u8 = 0x3B;
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
            w.write_u8(b.len() as u8);
            w.write_bytes(b);
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

/// A contact as it appears on the wire (25 bytes; no UDP key / verified flag,
/// unlike the 34-byte nodes.dat record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireContact {
    pub id: Kad128,
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
    let mut contacts = Vec::with_capacity(count as usize);
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
/// using an external Kad port); `misc_options` carries firewall/ack bits (set
/// bit 0x04 to request a HELLO_RES_ACK, v>=8 only).
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
    let mut results = Vec::with_capacity(count as usize);
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
        for t in &self.tags {
            if let KadTagValue::Int(v) = t.value {
                match t.name {
                    TAG_SOURCETYPE => source_type = Some(v as u8),
                    TAG_SOURCEIP => ip = Some(v as u32),
                    TAG_SOURCEPORT => tcp_port = Some(v as u16),
                    TAG_SOURCEUPORT => udp_port = Some(v as u16),
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

/// Build a KADEMLIA2_SEARCH_RES (a responder role / tests): `responderID 16 |
/// target 16 | count 2 | count x { answer 16 | taglist }`.
pub fn build_search_res(
    responder: &Kad128,
    target: &Kad128,
    results: &[SearchResult],
) -> (u8, Vec<u8>) {
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
}
