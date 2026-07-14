//! nodes.dat: the Kad routing-table bootstrap file (contacts to reach the DHT).
//! See docs/raw/wave6-kad-research-2026-07-14.md section A.
//!
//! Modern layout: `u32 legacy(=0)`, `u32 version(=2)`, `u32 count`, then that many
//! 34-byte v2 contact records. The leading 0 makes pre-versioned clients read a
//! count of 0 and bail. This codec reads/writes the v2 form byte-for-byte (the
//! only form a current aMule emits); v0/v1 (25-byte records) are accepted on read
//! for completeness.

use mule_proto::{IoError, Kad128, Reader, Writer};

/// nodes.dat file version this codec writes.
pub const NODES_DAT_VERSION: u32 = 2;
/// aMule caps a written nodes.dat at this many contacts.
pub const MAX_NODES: usize = 200;

/// One Kad contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadContact {
    pub id: Kad128,
    /// IPv4, network-order octets as stored (pass-through; ntohl only to display).
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

/// Parse a nodes.dat (modern versioned form; also accepts v0/v1 records).
pub fn read_nodes_dat(bytes: &[u8]) -> Result<NodesDat, IoError> {
    let mut r = Reader::new(bytes);
    let first = r.read_u32()?;
    // Modern files lead with 0; a nonzero first dword is a v0 file whose value is
    // the contact count (with 25-byte records, no version field).
    let (version, count) = if first == 0 {
        let version = r.read_u32()?;
        let count = r.read_u32()?;
        (version, count)
    } else {
        (0, first)
    };

    let mut contacts = Vec::new(); // untrusted count; records are fixed-size
    for _ in 0..count {
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&r.read_bytes(16)?);
        let id = Kad128::from_wire(&id_bytes);
        let ip = r.read_u32()?;
        let udp_port = r.read_u16()?;
        let tcp_port = r.read_u16()?;
        // v0 stores a "type" byte here that we do not use; v1+ store the contact
        // version. The UDP key + verified flag exist only from v2.
        let (cver, udp_key, udp_key_ip, verified) = if version == 0 {
            let _byte_type = r.read_u8()?;
            (0, 0, 0, false)
        } else if version == 1 {
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
