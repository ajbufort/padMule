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

/// padMule-to-padMule enhancement-channel marker (Layer 1 detection). Carried as
/// one extra STRING-named tag in every peer HELLO/HELLOANSWER. Stock eMule 0.50a
/// and aMule 3.0.1 iterate the hello taglist and switch on NUMERIC tag ids only -
/// aMule has no `default` case (BaseClient.cpp:477-478,635), eMule's is benign
/// (BaseClient.cpp:585-592) - so a string-named tag carrying a STANDARD UINT32
/// value is read-and-skipped by both, with no throw and no disconnect (the tag is
/// fully consumed by the CTag reader, Tag.cpp:110-169). It lets one padMule
/// recognize another with zero effect on stock peers. Value layout: low byte =
/// channel version (>= 1), high 24 bits = enhancement-capability flags.
///
/// CRITICAL: the value MUST use a standard tag TYPE byte. A nonstandard type
/// makes aMule THROW and disconnect (Tag.cpp:179) and eMule silently DESYNC its
/// whole parse (packets.cpp:565-572) - so never carry the marker as a custom type.
const PADMULE_HELLO_TAG: &[u8] = b"padMule";

/// The enhancement-channel protocol version padMule advertises.
pub const PADMULE_CHANNEL_VERSION: u8 = 1;

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

/// Build the padMule enhancement-channel marker tag (Layer 1 detection). `caps`
/// is the enhancement-capability bitmask (0 = presence only). NEVER set a bit for
/// a capability padMule does not actually honor - the Wave 4d differential test
/// proved a real peer punishes an advertised-but-unhonoured capability.
fn padmule_marker_tag(caps: u32) -> Tag {
    let value = (caps << 8) | PADMULE_CHANNEL_VERSION as u32;
    Tag {
        name: TagName::Str(PADMULE_HELLO_TAG.to_vec()),
        value: TagValue::U32(value),
    }
}

fn write_hello_body(w: &mut Writer, h: &HelloInfo) {
    w.write_bytes(&h.user_hash);
    w.write_u32(h.client_id);
    w.write_u16(h.tcp_port);
    w.write_u32(8); // tag count: 7 baseline + 1 padMule marker
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
    // padMule enhancement-channel marker (Layer 1). Provably ignored by stock
    // eMule/aMule; recognized by another padMule. caps=0 = presence only (no
    // enhancement is implemented yet, so we honour nothing beyond "I am padMule").
    write_tag(w, &padmule_marker_tag(0));
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

    /// The peer's client software as a display string ("padMule", "aMule 3.0.1",
    /// "eMule 0.50a", "eDonkey", ...), decoded from the CT_EMULE_VERSION tag
    /// (BaseClient.cpp:573-579): high byte = compatible-client id, low 24 bits
    /// pack version as `(v>>17).(v>>10).(v>>7)&7`. A peer with no eMule extension
    /// tag is a plain eDonkey client.
    pub fn client_software(&self) -> String {
        if self.padmule().is_some() {
            return "padMule".to_string();
        }
        let Some(v) = self.tag_u32(CT_EMULE_VERSION) else {
            return "eDonkey".to_string();
        };
        let name = match v >> 24 {
            0 => "eMule",
            1 => "cDonkey",
            2 => "xMule",
            3 => "aMule",
            4 => "Shareaza",
            10 => "MLDonkey",
            20 => "lphant",
            _ => "eMule-compatible",
        };
        let ver = v & 0x00FF_FFFF;
        let major = (ver >> 17) & 0x7F;
        let minor = (ver >> 10) & 0x7F;
        let patch = (ver >> 7) & 0x07;
        format!("{name} {major}.{minor}.{patch}")
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

    /// If this peer is a padMule client, its enhancement-channel info - detected
    /// by the string-named "padMule" marker tag (Layer 1). Returns None for every
    /// stock eMule/aMule peer, which never sends it. Once this is Some, and only
    /// then, it is safe to send padMule-specific Layer-2 messages (a stock peer
    /// would otherwise see an unknown opcode); see [`PADMULE_HELLO_TAG`].
    pub fn padmule(&self) -> Option<PadMuleInfo> {
        let v = self.tags.iter().find_map(|t| match (&t.name, &t.value) {
            (TagName::Str(n), TagValue::U32(v)) if n.as_slice() == PADMULE_HELLO_TAG => Some(*v),
            _ => None,
        })?;
        let channel_version = (v & 0xFF) as u8;
        if channel_version == 0 {
            return None; // malformed marker - treat as not-padMule
        }
        Some(PadMuleInfo {
            channel_version,
            capabilities: v >> 8,
        })
    }
}

/// padMule enhancement-channel info, decoded from a peer's HELLO marker tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PadMuleInfo {
    /// Enhancement-channel protocol version (>= 1).
    pub channel_version: u8,
    /// Enhancement-capability bitmask (0 = presence only).
    pub capabilities: u32,
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

    #[test]
    fn padmule_marker_round_trips_and_is_detected() {
        // Our own hello carries the marker; another padMule (this parser) sees it.
        let pkt = build_hello(&sample());
        let parsed = parse_hello(&pkt.payload, true).unwrap();
        let pm = parsed.padmule().expect("our own hello must be detected");
        assert_eq!(pm.channel_version, PADMULE_CHANNEL_VERSION);
        assert_eq!(pm.capabilities, 0, "no enhancement advertised yet");
        // The marker must NOT disturb the standard tags or the trailing fields:
        // an off-by-one tag count would corrupt these.
        assert!(parsed.capabilities().is_some());
        assert_eq!(parsed.server_ip, 0);
        assert_eq!(parsed.server_port, 0);
    }

    #[test]
    fn marker_is_a_string_named_uint32_the_provably_ignored_shape() {
        // The safety property: stock eMule/aMule ignore a string-named tag with a
        // STANDARD type byte, but throw/desync on a nonstandard type. Pin both.
        let pkt = build_hello(&sample());
        let parsed = parse_hello(&pkt.payload, true).unwrap();
        let marker = parsed
            .tags
            .iter()
            .find(|t| matches!(&t.name, TagName::Str(n) if n.as_slice() == PADMULE_HELLO_TAG))
            .expect("marker present");
        assert!(
            matches!(marker.value, TagValue::U32(_)),
            "marker must be a standard UINT32, never a custom type"
        );
    }

    #[test]
    fn client_software_decodes_the_version_tag() {
        let hello = |tags: Vec<Tag>| ParsedHello {
            user_hash: [0; 16],
            client_id: 0,
            tcp_port: 0,
            tags,
            server_ip: 0,
            server_port: 0,
        };
        // Our own tag (aMule 3.0.1 -> 0x03060080).
        assert_eq!(
            hello(vec![Tag::id(CT_EMULE_VERSION, TagValue::U32(0x0306_0080))]).client_software(),
            "aMule 3.0.1"
        );
        // Compatible-client id 0 = eMule.
        let emule = 0x0032_0100; // id 0, decodes to some eMule x.y.z
        assert!(hello(vec![Tag::id(CT_EMULE_VERSION, TagValue::U32(emule))])
            .client_software()
            .starts_with("eMule "));
        // No eMule extension tag at all -> plain eDonkey.
        assert_eq!(
            hello(vec![Tag::id(CT_NAME, TagValue::Str(b"x".to_vec()))]).client_software(),
            "eDonkey"
        );
        // The padMule marker wins over any version tag.
        assert_eq!(
            hello(vec![padmule_marker_tag(0x0000_0001)]).client_software(),
            "padMule"
        );
    }

    #[test]
    fn stock_hello_is_not_detected_as_padmule() {
        // A hello with only standard tags (what every eMule/aMule sends) -> None.
        let stock = ParsedHello {
            user_hash: [0; 16],
            client_id: 0,
            tcp_port: 0,
            tags: vec![
                Tag::id(CT_NAME, TagValue::Str(b"eMule".to_vec())),
                Tag::id(CT_EMULE_MISCOPTIONS1, TagValue::U32(0x3410_3212)),
            ],
            server_ip: 0,
            server_port: 0,
        };
        assert!(stock.padmule().is_none());
    }

    #[test]
    fn marker_encodes_version_and_capabilities() {
        // caps ride the high 24 bits, version the low byte.
        let parsed = ParsedHello {
            user_hash: [0; 16],
            client_id: 0,
            tcp_port: 0,
            tags: vec![padmule_marker_tag(0x00AB_CDEF)],
            server_ip: 0,
            server_port: 0,
        };
        let pm = parsed.padmule().unwrap();
        assert_eq!(pm.channel_version, PADMULE_CHANNEL_VERSION);
        assert_eq!(pm.capabilities, 0x00AB_CDEF);
    }
}
