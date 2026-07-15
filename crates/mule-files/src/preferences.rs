//! Byte-compatible readers/writers for aMule's identity files:
//! `preferences.dat` (the eD2k userhash) and `preferencesKad.dat` (the Kad ID).
//! Both are tiny, and matching their exact layout lets padMule share a config
//! directory with a real aMule install. The RSA identity lives in
//! `cryptkey.dat`, handled in `mule-engine::secure_ident`.
//!
//! - `preferences.dat`: `<version u8><userhash 16>` (`Preferences.cpp:1040`,
//!   `:1636`). The version byte is ignored on read.
//! - `preferencesKad.dat`: `<ip u32><u16 unused><KadID 16 wire><u8 tagcount>`
//!   (`kademlia/Prefs.cpp:114-136`). The trailing tag count is 0 in practice.

use mule_proto::{IoError, Kad128, Reader, Writer};

/// aMule's `PREFFILE_VERSION` (`DataFileVersion.h`). Written verbatim; ignored on
/// read.
pub const PREFFILE_VERSION: u8 = 0x14;

/// Bytes 5 and 14 of an eD2k userhash mark it as an eMule-type hash. aMule
/// applies these to the in-memory hash after loading (`Preferences.cpp:1076`).
pub const USERHASH_MARKER: [(usize, u8); 2] = [(5, 14), (14, 111)];

fn apply_userhash_markers(h: &mut [u8; 16]) {
    for (i, v) in USERHASH_MARKER {
        h[i] = v;
    }
}

/// Read the userhash from a `preferences.dat`, with the eMule marker bytes
/// applied (the wire form aMule actually uses).
pub fn read_preferences_dat(bytes: &[u8]) -> Result<[u8; 16], IoError> {
    let mut r = Reader::new(bytes);
    let _version = r.read_u8()?;
    let mut hash = [0u8; 16];
    hash.copy_from_slice(&r.read_bytes(16)?);
    apply_userhash_markers(&mut hash);
    Ok(hash)
}

/// Serialise a `preferences.dat`: `<PREFFILE_VERSION><userhash 16>`.
pub fn write_preferences_dat(userhash: &[u8; 16]) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u8(PREFFILE_VERSION);
    w.write_bytes(userhash);
    w.into_inner()
}

/// The persisted Kad preferences: our last-known external IP and our Kad ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KadPrefs {
    /// Our external IP as last seen (0 if unknown); stored, not load-bearing.
    pub ip: u32,
    /// Our stable Kad node ID.
    pub kad_id: Kad128,
}

/// Read a `preferencesKad.dat`. Tolerates the file with or without the trailing
/// tag-count byte.
pub fn read_kad_prefs(bytes: &[u8]) -> Result<KadPrefs, IoError> {
    let mut r = Reader::new(bytes);
    let ip = r.read_u32()?;
    let _unused = r.read_u16()?;
    let mut id = [0u8; 16];
    id.copy_from_slice(&r.read_bytes(16)?);
    Ok(KadPrefs {
        ip,
        kad_id: Kad128::from_wire(&id),
    })
}

/// Serialise a `preferencesKad.dat`: `<ip u32><u16 0><KadID 16 wire><u8 0>`.
pub fn write_kad_prefs(p: &KadPrefs) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_u32(p.ip);
    w.write_u16(0); // no longer used
    w.write_bytes(&p.kad_id.to_wire());
    w.write_u8(0); // tag count: no tags
    w.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preferences_dat_round_trips_and_applies_markers() {
        let mut raw = [0x33u8; 16];
        let bytes = write_preferences_dat(&raw);
        assert_eq!(bytes.len(), 17);
        assert_eq!(bytes[0], PREFFILE_VERSION);
        let got = read_preferences_dat(&bytes).unwrap();
        // Markers are applied on read regardless of the stored bytes.
        apply_userhash_markers(&mut raw);
        assert_eq!(got, raw);
        assert_eq!(got[5], 14);
        assert_eq!(got[14], 111);
    }

    #[test]
    fn read_preferences_dat_ignores_the_version_byte() {
        let mut bytes = vec![0xAB]; // any version
        bytes.extend_from_slice(&[0x42; 16]);
        let got = read_preferences_dat(&bytes).unwrap();
        assert_eq!(got[0], 0x42);
        assert_eq!(got[5], 14); // marker applied
    }

    #[test]
    fn kad_prefs_round_trips() {
        let p = KadPrefs {
            ip: 0x0102_0304,
            kad_id: Kad128::from_hash(&[0xCD; 16]),
        };
        let bytes = write_kad_prefs(&p);
        assert_eq!(bytes.len(), 4 + 2 + 16 + 1);
        assert_eq!(read_kad_prefs(&bytes).unwrap(), p);
    }

    #[test]
    fn kad_prefs_reads_a_file_without_the_trailing_tag_byte() {
        let p = KadPrefs {
            ip: 0,
            kad_id: Kad128::from_hash(&[0x11; 16]),
        };
        let bytes = write_kad_prefs(&p);
        // Drop the trailing tag-count byte (older writers omitted it).
        assert_eq!(read_kad_prefs(&bytes[..bytes.len() - 1]).unwrap(), p);
    }
}
