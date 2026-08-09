//! nodes.dat: the Kad routing-table bootstrap file (contacts to reach the DHT).
//! See docs/raw/wave6-kad-research-2026-07-14.md section A.
//!
//! Modern layout: `u32 legacy(=0)`, `u32 version(=2)`, `u32 count`, then that many
//! 34-byte v2 contact records. The leading 0 makes pre-versioned clients read a
//! count of 0 and bail. This codec reads/writes the v2 form byte-for-byte (the
//! only form a current aMule emits); v1/v3 (25-byte records) are accepted on
//! read for completeness, while v0 yields zero contacts (refused, matching
//! aMule - see `read_nodes_dat`).

use mule_proto::{IoError, Kad128, Reader, Writer};

/// nodes.dat file version this codec writes.
pub const NODES_DAT_VERSION: u32 = 2;
/// Contacts per written nodes.dat. Matches what aMule writes in practice: its
/// hard cap is CONTACT_FILE_LIMIT=500 (RoutingZone.cpp:76), but the writer only
/// ever collects 200 bootstrap contacts (GetBootstrapContacts, RoutingZone.cpp:301).
pub const MAX_NODES: usize = 200;

/// One Kad contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadContact {
    pub id: Kad128,
    /// IPv4 in HOST order - the `u32::from(Ipv4Addr)` convention, first octet
    /// in the high byte, exactly like `mule_kad::WireContact.ip`. This is what
    /// `is_blocked_u32` / `is_acceptable_contact` consume RAW; running it
    /// through `mule_files::ip_from_met_u32` (the `.met` low-byte-first
    /// convention) reverses every address - the byte-order bug class fixed
    /// three times in 2026-08 (rows 8cq/8ct). Upstream agrees the stored value
    /// is host order, by INVERSION: `IsGoodIP` takes ANTI-host order
    /// (NetworkFunctions.h:112-115), which is exactly why RoutingZone.cpp:
    /// 194-195 wraps this very field in `wxUINT32_SWAP_ALWAYS` before calling
    /// it - a swap that would itself be a bug if the stored value were
    /// anything but host order.
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    /// Kad protocol version this contact speaks (8 = aMule, 9 = eMule).
    pub version: u8,
    /// The peer's UDP verify key: a per-peer key plus the IP that created it.
    /// Present from file version 2; `(0, 0)` for older records.
    pub udp_key: u32,
    pub udp_key_ip: u32,
    /// Whether this contact's identity has been UDP-verified.
    pub verified: bool,
}

/// A parsed nodes.dat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodesDat {
    /// File version as read (preserved so a v2 read-write is byte-identical).
    pub version: u32,
    pub contacts: Vec<KadContact>,
}

/// Parse a nodes.dat (modern versioned form; v1..=3).
///
/// A v0 file - in EITHER shape: a nonzero first dword (the count-first form)
/// or a leading zero with fileVersion == 0 - yields ZERO contacts, matching
/// aMule, which reads numContacts only for fileVersion 1..=3
/// (RoutingZone.cpp:165-172). See the refusals inside.
pub fn read_nodes_dat(bytes: &[u8]) -> Result<NodesDat, IoError> {
    let mut r = Reader::new(bytes);
    let first = r.read_u32()?;
    // Modern files lead with 0; a nonzero first dword is a v0 file whose value is
    // the contact count (with 25-byte records, no version field). aMule accepts
    // fileVersion 1..=3 (RoutingZone.cpp:165); v3 carries an extra
    // bootstrapEdition dword BEFORE the count, and edition 1 switches the records
    // to the v1-style 25-byte bootstrap form (ReadBootstrapNodesDat).
    let (version, count, bootstrap) = if first == 0 {
        let version = r.read_u32()?;
        if version > 3 {
            return Err(IoError::BadHeader(version.min(u8::MAX as u32) as u8));
        }
        if version == 0 {
            // Version 0 behind the modern leading zero: aMule reads
            // numContacts only for fileVersion 1..=3 (RoutingZone.cpp:165-167),
            // so a fileVersion of 0 keeps numContacts == 0 and yields ZERO
            // contacts - the same v0 refusal as the nonzero-first-dword arm
            // below, reached through a different gate. padMule parsed v0-style
            // records on this path until 2026-08-09, a bypass of that refusal.
            return Ok(NodesDat {
                version: 0,
                contacts: Vec::new(),
            });
        }
        let bootstrap = version == 3 && r.read_u32()? == 1;
        let count = r.read_u32()?;
        (version, count, bootstrap)
    } else {
        // A NONZERO FIRST DWORD IS A v0 FILE, AND v0 IS REFUSED - by aMule in so
        // many words: "Don't read version 0 nodes.dat files, because they can't
        // tell the kad version of the contacts stored", setting numContacts = 0
        // (RoutingZone.cpp:169-172). That reason is the whole point: a v0 record
        // carries a TYPE byte where v1+ carry the contact version, so every
        // contact read from one has an unknown Kad version - and a Kad1 contact
        // cannot speak the Kad2 wire padMule sends. padMule parsed these until
        // 2026-08-08 and handed back contacts with `version: 0`, which the
        // routing table now refuses anyway; refusing the FILE is both faithful
        // and honest about why.
        return Ok(NodesDat {
            version: 0,
            contacts: Vec::new(),
        });
    };

    let mut contacts = Vec::new(); // untrusted count; records are fixed-size
    for _ in 0..count {
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&r.read_bytes(16)?);
        let id = Kad128::from_wire(&id_bytes);
        let ip = r.read_u32()?;
        let udp_port = r.read_u16()?;
        let tcp_port = r.read_u16()?;
        // v1+ store the contact version here (a v0 record would carry a "type"
        // byte instead, but v0 files are refused above and never reach this
        // loop). The UDP key + verified flag exist only from v2, and a v3
        // BOOTSTRAP-edition record is the v1 25-byte form (no key/verified).
        let (cver, udp_key, udp_key_ip, verified) = if version == 1 || bootstrap {
            (r.read_u8()?, 0, 0, false)
        } else {
            let cver = r.read_u8()?;
            let key = r.read_u32()?;
            let key_ip = r.read_u32()?;
            let verified = r.read_u8()? != 0;
            (cver, key, key_ip, verified)
        };
        contacts.push(KadContact {
            id,
            ip,
            udp_port,
            tcp_port,
            version: cver,
            udp_key,
            udp_key_ip,
            verified,
        });
    }
    Ok(NodesDat { version, contacts })
}

/// Serialize a nodes.dat in the modern v2 form (regardless of the read version),
/// capping at [`MAX_NODES`] contacts as aMule does.
pub fn write_nodes_dat(n: &NodesDat) -> Vec<u8> {
    let contacts = &n.contacts[..n.contacts.len().min(MAX_NODES)];
    let mut w = Writer::new();
    w.write_u32(0); // legacy count -> old clients read 0 and bail
    w.write_u32(NODES_DAT_VERSION);
    w.write_u32(contacts.len() as u32);
    for c in contacts {
        w.write_bytes(&c.id.to_wire());
        w.write_u32(c.ip);
        w.write_u16(c.udp_port);
        w.write_u16(c.tcp_port);
        w.write_u8(c.version);
        w.write_u32(c.udp_key);
        w.write_u32(c.udp_key_ip);
        w.write_u8(c.verified as u8);
    }
    w.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_the_v2_header_and_34_byte_records() {
        let n = NodesDat {
            version: 2,
            contacts: vec![KadContact {
                id: Kad128::from_hash(&[0xAB; 16]),
                ip: 0x0102_0304,
                udp_port: 4672,
                tcp_port: 4662,
                version: 8,
                udp_key: 0xDEAD_BEEF,
                udp_key_ip: 0x0A00_0001,
                verified: true,
            }],
        };
        let bytes = write_nodes_dat(&n);
        assert_eq!(bytes.len(), 12 + 34);
        assert_eq!(&bytes[0..4], &0u32.to_le_bytes());
        assert_eq!(&bytes[4..8], &2u32.to_le_bytes());
        assert_eq!(&bytes[8..12], &1u32.to_le_bytes());
        assert_eq!(read_nodes_dat(&bytes).unwrap(), n);
    }

    #[test]
    fn a_v0_file_is_refused_because_it_cannot_name_its_contacts_kad_version() {
        // v0: no leading zero, no version field; 25-byte records ending in a
        // "type" byte where v1+ put the contact VERSION - which is exactly why
        // aMule refuses the format outright ("they can't tell the kad version
        // of the contacts stored", RoutingZone.cpp:169-172). This test used to
        // assert padMule PARSED such a file and returned its contact, pinning a
        // divergence as if it were a feature.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // count (nonzero => v0)
        bytes.extend_from_slice(&Kad128::from_hash(&[0xCD; 16]).to_wire());
        bytes.extend_from_slice(&0x0102_0304u32.to_le_bytes()); // ip
        bytes.extend_from_slice(&4672u16.to_le_bytes()); // udp
        bytes.extend_from_slice(&4662u16.to_le_bytes()); // tcp
        bytes.push(2); // type byte - where v1+ put the contact version

        // NOT an error: aMule logs and carries on with zero contacts, so a user
        // with an ancient nodes.dat gets an empty table and a working client,
        // not a failed start. The file is well-formed; it just cannot say what
        // it needs to say.
        let n = read_nodes_dat(&bytes).unwrap();
        assert_eq!(n.version, 0);
        assert!(
            n.contacts.is_empty(),
            "a v0 file must yield NO contacts - every one of them has an \
             unknown Kad version, and a Kad1 contact cannot speak our wire"
        );
    }

    #[test]
    fn a_zero_led_version_0_file_also_yields_zero_contacts() {
        // The v0 refusal must not have a bypass: a file shaped
        // `u32 0, u32 version==0, u32 count, 25-byte records` is still a v0
        // file, and aMule reads numContacts only for fileVersion 1..=3
        // (RoutingZone.cpp:165-167) - fileVersion 0 keeps numContacts == 0 and
        // yields ZERO contacts, exactly like the nonzero-first-dword form.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes()); // modern leading zero
        bytes.extend_from_slice(&0u32.to_le_bytes()); // file version 0
        bytes.extend_from_slice(&1u32.to_le_bytes()); // count
        bytes.extend_from_slice(&Kad128::from_hash(&[0xCD; 16]).to_wire());
        bytes.extend_from_slice(&0x0102_0304u32.to_le_bytes()); // ip
        bytes.extend_from_slice(&4672u16.to_le_bytes()); // udp
        bytes.extend_from_slice(&4662u16.to_le_bytes()); // tcp
        bytes.push(2); // v0 type byte
        let n = read_nodes_dat(&bytes).unwrap();
        assert_eq!(n.version, 0);
        assert!(
            n.contacts.is_empty(),
            "a version-0 file behind the modern leading zero must yield no \
             contacts, matching aMule's fileVersion 1..=3 gate"
        );
    }

    #[test]
    fn reads_a_v3_regular_file_with_the_extra_edition_dword() {
        // v3 non-bootstrap: aMule reads a bootstrapEdition dword (0) BEFORE the
        // count (RoutingZone.cpp:156-166); records are the v2 34-byte form.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes()); // file version
        bytes.extend_from_slice(&0u32.to_le_bytes()); // bootstrapEdition = 0
        bytes.extend_from_slice(&1u32.to_le_bytes()); // count
        bytes.extend_from_slice(&Kad128::from_hash(&[0x11; 16]).to_wire());
        bytes.extend_from_slice(&0x0102_0304u32.to_le_bytes()); // ip
        bytes.extend_from_slice(&4672u16.to_le_bytes()); // udp
        bytes.extend_from_slice(&4662u16.to_le_bytes()); // tcp
        bytes.push(8); // contact version
        bytes.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes()); // udp_key
        bytes.extend_from_slice(&0x0A00_0001u32.to_le_bytes()); // udp_key_ip
        bytes.push(1); // verified
        let n = read_nodes_dat(&bytes).unwrap();
        assert_eq!(n.version, 3);
        assert_eq!(n.contacts.len(), 1);
        let c = &n.contacts[0];
        assert_eq!(c.ip, 0x0102_0304);
        assert_eq!((c.udp_port, c.tcp_port), (4672, 4662));
        assert_eq!(
            (c.version, c.udp_key, c.udp_key_ip, c.verified),
            (8, 0xDEAD_BEEF, 0x0A00_0001, true)
        );
    }

    #[test]
    fn reads_a_v3_bootstrap_edition_file_with_25_byte_records() {
        // v3 bootstrapEdition=1: v1-style 25-byte records (ReadBootstrapNodesDat),
        // no key/verified fields.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&3u32.to_le_bytes()); // file version
        bytes.extend_from_slice(&1u32.to_le_bytes()); // bootstrapEdition = 1
        bytes.extend_from_slice(&1u32.to_le_bytes()); // count
        bytes.extend_from_slice(&Kad128::from_hash(&[0x22; 16]).to_wire());
        bytes.extend_from_slice(&0x0506_0708u32.to_le_bytes()); // ip
        bytes.extend_from_slice(&4672u16.to_le_bytes()); // udp
        bytes.extend_from_slice(&4662u16.to_le_bytes()); // tcp
        bytes.push(9); // contact version
        let n = read_nodes_dat(&bytes).unwrap();
        assert_eq!(n.version, 3);
        assert_eq!(n.contacts.len(), 1);
        let c = &n.contacts[0];
        assert_eq!(c.ip, 0x0506_0708);
        assert_eq!(
            (c.version, c.udp_key, c.udp_key_ip, c.verified),
            (9, 0, 0, false)
        );
    }

    #[test]
    fn rejects_an_unknown_future_version() {
        // aMule accepts fileVersion 1..=3 only (RoutingZone.cpp:165); a future
        // version must ERROR, not silently misparse the stream as contacts.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&4u32.to_le_bytes()); // unknown version
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 34]);
        assert!(read_nodes_dat(&bytes).is_err());
    }

    #[test]
    fn reads_a_v1_file_with_25_byte_records() {
        // v1: leading zero + version 1; the trailing byte is the contact version.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes()); // file version
        bytes.extend_from_slice(&1u32.to_le_bytes()); // count
        bytes.extend_from_slice(&Kad128::from_hash(&[0xEF; 16]).to_wire());
        bytes.extend_from_slice(&0x0A00_0002u32.to_le_bytes()); // ip
        bytes.extend_from_slice(&1234u16.to_le_bytes()); // udp
        bytes.extend_from_slice(&5678u16.to_le_bytes()); // tcp
        bytes.push(9); // contact version (eMule)
        let n = read_nodes_dat(&bytes).unwrap();
        assert_eq!(n.version, 1);
        assert_eq!(n.contacts.len(), 1);
        let c = &n.contacts[0];
        assert_eq!(c.version, 9);
        assert_eq!((c.udp_key, c.udp_key_ip, c.verified), (0, 0, false));
        // The writer re-emits the modern v2 form regardless of the read version.
        let rewritten = write_nodes_dat(&n);
        assert_eq!(&rewritten[4..8], &2u32.to_le_bytes());
    }

    #[test]
    fn a_truncated_file_errors_rather_than_panicking() {
        let n = NodesDat {
            version: 2,
            contacts: vec![KadContact {
                id: Kad128::default(),
                ip: 0,
                udp_port: 0,
                tcp_port: 0,
                version: 8,
                udp_key: 0,
                udp_key_ip: 0,
                verified: false,
            }],
        };
        let mut bytes = write_nodes_dat(&n);
        bytes.truncate(bytes.len() - 1);
        assert!(read_nodes_dat(&bytes).is_err());
    }

    #[test]
    fn a_bogus_count_does_not_overallocate() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&u32::MAX.to_le_bytes()); // huge count, no records
        assert!(read_nodes_dat(&bytes).is_err());
    }
}
