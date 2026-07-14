//! Client-to-client (peer) protocol: the HELLO handshake. See
//! BaseClient.cpp:721-1170 (SendHelloPacket / SendHelloTypePacket) and
//! docs/wiki/protocol-understanding.md Part 2.
//!
//! Whoever opens the connection sends OP_HELLO first (its body is prefixed with
//! a `u8 = 16`, the userhash length); the accepter replies OP_HELLOANSWER with
//! the same body and no prefix. Because padMule never advertises VBT, aMule's
//! `CTagVarInt(.., 32)` forces every int tag to UINT32, so the tags are plain
//! `write_tag` UINT32/STRING tags (Tag.h:129-186).

use crate::server_messages::{EDONKEYVERSION, EMULE_VERSION_TAG};
use mule_proto::{
    read_tag, write_tag, IoError, Packet, Reader, Tag, TagName, TagValue, Writer, PROT_EDONKEY,
};

// Peer opcodes (protocol 0xE3).
pub const OP_HELLO: u8 = 0x01;
pub const OP_HELLOANSWER: u8 = 0x4C;

// Hello tag ids (ClientTags.h).
const CT_NAME: u8 = 0x01;
const CT_VERSION: u8 = 0x11;
const CT_EMULECOMPAT_OPTIONS: u8 = 0xEF;
const CT_EMULE_UDPPORTS: u8 = 0xF9;
const CT_EMULE_MISCOPTIONS1: u8 = 0xFA;
const CT_EMULE_VERSION: u8 = 0xFB;
const CT_EMULE_MISCOPTIONS2: u8 = 0xFE;

/// The Kad protocol version padMule advertises (KADEMLIA_VERSION 0.49b).
pub const KADEMLIA_VERSION: u32 = 0x08;

/// Compute CT_EMULE_MISCOPTIONS1 with the padMule baseline capabilities.
/// `sec_ident` is 0 (no crypto) or 3 (secure-ident available, Wave 5). Verified
/// against BaseClient.cpp:1096-1109; baseline (sec_ident=0) = 0x34103212.
pub const fn baseline_misc_options1(sec_ident: u32) -> u32 {
    let aich: u32 = 1;
    let unicode: u32 = 1;
    let udp_ver: u32 = 4;
    let data_comp: u32 = 1;
    let source_exchange: u32 = 3;
    let ext_requests: u32 = 2;
    let accept_comment: u32 = 1;
    let peercache: u32 = 0;
    let no_view_shared: u32 = 0;
    let multipacket: u32 = 1;
    let preview: u32 = 0;
    (aich << 29)
        | (unicode << 28)
        | (udp_ver << 24)
        | (data_comp << 20)
        | (sec_ident << 16)
        | (source_exchange << 12)
        | (ext_requests << 8)
        | (accept_comment << 4)
        | (peercache << 3)
        | (no_view_shared << 2)
        | (multipacket << 1)
        | preview
}

/// Compute CT_EMULE_MISCOPTIONS2 with the padMule baseline capabilities.
/// Crypt flags are 0 until Wave 5; captcha/direct-UDP-callback are 0 (not
/// supported in v1). Verified against BaseClient.cpp:1131-1144; baseline
/// (crypt off, kad 0x08) = 0x438.
pub const fn baseline_misc_options2(
    crypt_supported: u32,
    crypt_requested: u32,
    crypt_required: u32,
    kad_version: u32,
) -> u32 {
    let direct_udp_callback: u32 = 0;
    let captcha: u32 = 0;
    let source_ex2: u32 = 1;
    let ext_multipacket: u32 = 1;
    let large_files: u32 = 1;
    (direct_udp_callback << 12)
        | (captcha << 11)
        | (source_ex2 << 10)
        | (crypt_required << 9)
        | (crypt_requested << 8)
        | (crypt_supported << 7)
        | (ext_multipacket << 5)
        | (large_files << 4)
        | kad_version
}

/// CT_EMULECOMPAT_OPTIONS baseline: OS-info supported, VBT NEVER set
/// (BaseClient.cpp:1146-1152). Value 1.
pub const COMPAT_OPTIONS_BASELINE: u32 = 1;

/// The identity + capability info exchanged in a HELLO / HELLOANSWER.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloInfo {
    pub user_hash: [u8; 16],
    pub client_id: u32,
    pub tcp_port: u16,
    pub nick: String,
    pub udp_port: u16,
    pub kad_udp_port: u16,
    pub misc_options1: u32,
    pub misc_options2: u32,
    pub compat_options: u32,
    /// The server we are connected to (0 if none), advertised so peers can do
    /// server-assisted LowID callbacks.
    pub server_ip: u32,
    pub server_port: u16,
}

impl HelloInfo {
    /// A baseline HelloInfo (no crypto, no Kad connection, no buddy).
    pub fn baseline(
        user_hash: [u8; 16],
        client_id: u32,
        tcp_port: u16,
        udp_port: u16,
        nick: &str,
    ) -> Self {
        HelloInfo {
            user_hash,
            client_id,
            tcp_port,
            nick: nick.to_string(),
            udp_port,
            kad_udp_port: 0,
            misc_options1: baseline_misc_options1(0),
            misc_options2: baseline_misc_options2(0, 0, 0, KADEMLIA_VERSION),
            compat_options: COMPAT_OPTIONS_BASELINE,
            server_ip: 0,
            server_port: 0,
        }
    }
}

fn write_hello_body(w: &mut Writer, h: &HelloInfo) {
    w.write_bytes(&h.user_hash);
    w.write_u32(h.client_id);
    w.write_u16(h.tcp_port);
    w.write_u32(7); // tag count (baseline, no buddy tags)
    write_tag(
        w,
        &Tag::id(CT_NAME, TagValue::Str(h.nick.as_bytes().to_vec())),
    );
    write_tag(w, &Tag::id(CT_VERSION, TagValue::U32(EDONKEYVERSION)));
    let udp_ports = ((h.kad_udp_port as u32) << 16) | (h.udp_port as u32);
    write_tag(w, &Tag::id(CT_EMULE_UDPPORTS, TagValue::U32(udp_ports)));
    write_tag(
        w,
        &Tag::id(CT_EMULE_VERSION, TagValue::U32(EMULE_VERSION_TAG)),
    );
    write_tag(
        w,
        &Tag::id(CT_EMULE_MISCOPTIONS1, TagValue::U32(h.misc_options1)),
    );
    write_tag(
        w,
        &Tag::id(CT_EMULE_MISCOPTIONS2, TagValue::U32(h.misc_options2)),
    );
    write_tag(
        w,
        &Tag::id(CT_EMULECOMPAT_OPTIONS, TagValue::U32(h.compat_options)),
    );
    w.write_u32(h.server_ip);
    w.write_u16(h.server_port);
}

/// Build an OP_HELLO packet (opener sends this first; body prefixed with the
/// userhash length byte 16).
pub fn build_hello(h: &HelloInfo) -> Packet {
    let mut w = Writer::new();
    w.write_u8(16); // userhash length
    write_hello_body(&mut w, h);
    Packet::new(PROT_EDONKEY, OP_HELLO, w.into_inner())
}

/// Build an OP_HELLOANSWER packet (accepter's reply; no length prefix).
pub fn build_hello_answer(h: &HelloInfo) -> Packet {
    let mut w = Writer::new();
    write_hello_body(&mut w, h);
    Packet::new(PROT_EDONKEY, OP_HELLOANSWER, w.into_inner())
}

/// A parsed HELLO / HELLOANSWER.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedHello {
    pub user_hash: [u8; 16],
    pub client_id: u32,
    pub tcp_port: u16,
    pub tags: Vec<Tag>,
    pub server_ip: u32,
    pub server_port: u16,
}

impl ParsedHello {
    /// Find a numeric-id tag's u32 value (UINT8/16/32 all read as an integer).
    fn tag_u32(&self, id: u8) -> Option<u32> {
        self.tags.iter().find_map(|t| match (&t.name, &t.value) {
            (TagName::Id(i), TagValue::U8(v)) if *i == id => Some(*v as u32),
            (TagName::Id(i), TagValue::U16(v)) if *i == id => Some(*v as u32),
            (TagName::Id(i), TagValue::U32(v)) if *i == id => Some(*v),
            _ => None,
        })
    }

    /// Decode the peer's capabilities from its MISCOPTIONS1/2 tags, if present.
    pub fn capabilities(&self) -> Option<Capabilities> {
        let m1 = self.tag_u32(CT_EMULE_MISCOPTIONS1)?;
        let m2 = self.tag_u32(CT_EMULE_MISCOPTIONS2).unwrap_or(0);
        Some(Capabilities {
            aich: ((m1 >> 29) & 0x7) as u8,
            udp_ver: ((m1 >> 24) & 0xF) as u8,
            data_comp: ((m1 >> 20) & 0xF) as u8,
            sec_ident: ((m1 >> 16) & 0xF) as u8,
            source_exchange: ((m1 >> 12) & 0xF) as u8,
            ext_requests: ((m1 >> 8) & 0xF) as u8,
            large_files: (m2 >> 4) & 1 == 1,
            ext_multipacket: (m2 >> 5) & 1 == 1,
            supports_crypt: (m2 >> 7) & 1 == 1,
            requests_crypt: (m2 >> 8) & 1 == 1,
            requires_crypt: (m2 >> 9) & 1 == 1,
            source_ex2: (m2 >> 10) & 1 == 1,
            kad_version: (m2 & 0xF) as u8,
        })
    }
}

/// A peer's decoded capability set (from MISCOPTIONS1/2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capabilities {
    pub aich: u8,
    pub udp_ver: u8,
    pub data_comp: u8,
    pub sec_ident: u8,
    pub source_exchange: u8,
    pub ext_requests: u8,
    pub large_files: bool,
    pub ext_multipacket: bool,
    pub supports_crypt: bool,
    pub requests_crypt: bool,
    pub requires_crypt: bool,
    pub source_ex2: bool,
    pub kad_version: u8,
}

/// Parse a HELLO (`is_hello = true`, strips the leading length byte) or a
/// HELLOANSWER (`is_hello = false`).
pub fn parse_hello(payload: &[u8], is_hello: bool) -> Result<ParsedHello, IoError> {
    let mut r = Reader::new(payload);
    if is_hello {
        let _hash_len = r.read_u8()?; // 16
    }
    let mut user_hash = [0u8; 16];
    user_hash.copy_from_slice(&r.read_bytes(16)?);
    let client_id = r.read_u32()?;
    let tcp_port = r.read_u16()?;
    let tagcount = r.read_u32()?;
    let mut tags = Vec::new(); // untrusted count: grow as read
    for _ in 0..tagcount {
        tags.push(read_tag(&mut r)?);
    }
    let server_ip = r.read_u32()?;
    let server_port = r.read_u16()?;
    Ok(ParsedHello {
        user_hash,
        client_id,
        tcp_port,
        tags,
        server_ip,
        server_port,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> HelloInfo {
        HelloInfo::baseline([0x33; 16], 0x0A00_0001, 4662, 4672, "padMule")
    }

    #[test]
    fn baseline_misc_options_match_amule() {
        assert_eq!(baseline_misc_options1(0), 0x3410_3212);
        assert_eq!(baseline_misc_options1(3), 0x3413_3212); // secure ident = 3
        assert_eq!(baseline_misc_options2(0, 0, 0, KADEMLIA_VERSION), 0x438);
        assert_eq!(COMPAT_OPTIONS_BASELINE, 1);
    }

    #[test]
    fn hello_has_length_prefix_answer_does_not() {
        let h = sample();
        let hello = build_hello(&h);
        let answer = build_hello_answer(&h);
        assert_eq!(hello.opcode, OP_HELLO);
        assert_eq!(hello.payload[0], 16); // length prefix
        assert_eq!(answer.opcode, OP_HELLOANSWER);
        // The answer body equals the hello body without the leading prefix byte.
        assert_eq!(&hello.payload[1..], &answer.payload[..]);
    }

    #[test]
    fn hello_round_trips_and_decodes_capabilities() {
        let h = sample();
        let pkt = build_hello(&h);
        let parsed = parse_hello(&pkt.payload, true).unwrap();
        assert_eq!(parsed.user_hash, h.user_hash);
        assert_eq!(parsed.client_id, h.client_id);
        assert_eq!(parsed.tcp_port, h.tcp_port);
        assert_eq!(parsed.server_ip, 0);
        assert_eq!(parsed.server_port, 0);

        let caps = parsed.capabilities().unwrap();
        assert_eq!(caps.udp_ver, 4);
        assert_eq!(caps.data_comp, 1);
        assert_eq!(caps.sec_ident, 0);
        assert_eq!(caps.source_exchange, 3);
        assert_eq!(caps.ext_requests, 2);
        assert_eq!(caps.aich, 1);
        assert!(caps.large_files);
        assert!(caps.source_ex2);
        assert!(!caps.supports_crypt);
        assert_eq!(caps.kad_version, KADEMLIA_VERSION as u8);
    }

    #[test]
    fn hello_answer_round_trips() {
        let h = sample();
        let pkt = build_hello_answer(&h);
        let parsed = parse_hello(&pkt.payload, false).unwrap();
        assert_eq!(parsed.user_hash, h.user_hash);
        assert_eq!(parsed.tcp_port, h.tcp_port);
    }

    #[test]
    fn udp_ports_tag_packs_kad_and_client_ports() {
        let mut h = sample();
        h.kad_udp_port = 0x1234;
        h.udp_port = 0x5678;
        let pkt = build_hello(&h);
        let parsed = parse_hello(&pkt.payload, true).unwrap();
        let udp = parsed.tag_u32(CT_EMULE_UDPPORTS).unwrap();
        assert_eq!(udp, 0x1234_5678);
    }
}
