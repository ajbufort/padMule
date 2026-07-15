//! The node's persistent identity: the eD2k userhash, the Kad ID, the Kad UDP
//! anti-spoof key, and the RSA secure-identification key. A stable identity
//! across launches is a hard prerequisite for the app - a fresh identity each
//! run would reset credits with every peer and re-key Kad on every start.
//!
//! Three files are aMule-byte-compatible (so padMule can share a config dir with
//! a real aMule): `preferences.dat` (userhash), `preferencesKad.dat` (Kad ID),
//! and `cryptkey.dat` (RSA). The Kad UDP key lives in aMule's `amule.conf` INI,
//! which we do not parse, so padMule keeps it in its own tiny `kadudpkey.dat`.

use crate::secure_ident::Identity as RsaIdentity;
use mule_files::{
    read_kad_prefs, read_preferences_dat, write_kad_prefs, write_preferences_dat, KadPrefs,
};
use mule_proto::Kad128;
use std::io;
use std::path::Path;

/// The node's full, persistent identity.
pub struct NodeIdentity {
    /// eD2k userhash (with the eMule marker bytes 5=14, 14=111).
    pub userhash: [u8; 16],
    /// Kad node ID.
    pub kad_id: Kad128,
    /// Per-install Kad UDP anti-spoof key (feeds `udp_verify_key`).
    pub kad_udp_key: u32,
    /// RSA secure-identification key.
    pub rsa: RsaIdentity,
}

fn generate_userhash() -> [u8; 16] {
    let mut h: [u8; 16] = rand::random();
    h[5] = 14;
    h[14] = 111;
    h
}

fn generate_kad_id() -> Kad128 {
    Kad128::from_words([
        rand::random(),
        rand::random(),
        rand::random(),
        rand::random(),
    ])
}

impl NodeIdentity {
    /// A fresh random identity (does RSA keygen - the slow part).
    pub fn generate() -> Self {
        NodeIdentity {
            userhash: generate_userhash(),
            kad_id: generate_kad_id(),
            kad_udp_key: rand::random(),
            rsa: RsaIdentity::generate(),
        }
    }

    /// Load the identity from `dir`, generating (and persisting) only the parts
    /// whose files are missing or unreadable - so an existing `cryptkey.dat`
    /// skips the RSA keygen, and a partial config is completed in place.
    pub fn load_or_create(dir: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let userhash = std::fs::read(dir.join("preferences.dat"))
            .ok()
            .and_then(|b| read_preferences_dat(&b).ok())
            .unwrap_or_else(generate_userhash);
        let kad_id = std::fs::read(dir.join("preferencesKad.dat"))
            .ok()
            .and_then(|b| read_kad_prefs(&b).ok())
            .map(|p| p.kad_id)
            .unwrap_or_else(generate_kad_id);
        let kad_udp_key = std::fs::read(dir.join("kadudpkey.dat"))
            .ok()
            .filter(|b| b.len() >= 4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .unwrap_or_else(rand::random);
        let rsa = std::fs::read(dir.join("cryptkey.dat"))
            .ok()
            .and_then(|b| RsaIdentity::from_cryptkey_dat(&b).ok())
            .unwrap_or_else(RsaIdentity::generate);

        let id = NodeIdentity {
            userhash,
            kad_id,
            kad_udp_key,
            rsa,
        };
        id.save(dir)?; // persist any freshly-generated parts
        Ok(id)
    }

    /// Persist every part to `dir` in aMule-compatible formats (plus the padMule
    /// `kadudpkey.dat`).
    pub fn save(&self, dir: &Path) -> io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(
            dir.join("preferences.dat"),
            write_preferences_dat(&self.userhash),
        )?;
        std::fs::write(
            dir.join("preferencesKad.dat"),
            write_kad_prefs(&KadPrefs {
                ip: 0,
                kad_id: self.kad_id,
            }),
        )?;
        std::fs::write(dir.join("kadudpkey.dat"), self.kad_udp_key.to_le_bytes())?;
        std::fs::write(dir.join("cryptkey.dat"), self.rsa.to_cryptkey_dat())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("padmule-id-{tag}-{}", std::process::id()))
    }

    #[test]
    fn generate_produces_a_marked_userhash() {
        let id = NodeIdentity::generate();
        assert_eq!(id.userhash[5], 14);
        assert_eq!(id.userhash[14], 111);
    }

    #[test]
    fn identity_is_stable_across_load_or_create() {
        let dir = tmp("stable");
        let _ = std::fs::remove_dir_all(&dir);
        let a = NodeIdentity::load_or_create(&dir).unwrap();
        let b = NodeIdentity::load_or_create(&dir).unwrap();
        assert_eq!(a.userhash, b.userhash, "userhash persists");
        assert_eq!(a.kad_id, b.kad_id, "kad id persists");
        assert_eq!(a.kad_udp_key, b.kad_udp_key, "udp key persists");
        assert_eq!(
            a.rsa.public_key_der(),
            b.rsa.public_key_der(),
            "rsa key persists"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn writes_the_amule_compatible_files() {
        let dir = tmp("files");
        let _ = std::fs::remove_dir_all(&dir);
        let id = NodeIdentity::load_or_create(&dir).unwrap();
        // preferences.dat is 17 bytes and re-reads to the same userhash.
        let pd = std::fs::read(dir.join("preferences.dat")).unwrap();
        assert_eq!(pd.len(), 17);
        assert_eq!(read_preferences_dat(&pd).unwrap(), id.userhash);
        // preferencesKad.dat re-reads to the same Kad id.
        let kd = std::fs::read(dir.join("preferencesKad.dat")).unwrap();
        assert_eq!(read_kad_prefs(&kd).unwrap().kad_id, id.kad_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn partial_config_is_completed_without_rersa() {
        // A dir with only a Kad prefs file: userhash + rsa get generated + saved,
        // and the pre-existing kad id is preserved.
        let dir = tmp("partial");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let kad_id = Kad128::from_hash(&[0x77; 16]);
        std::fs::write(
            dir.join("preferencesKad.dat"),
            write_kad_prefs(&KadPrefs { ip: 0, kad_id }),
        )
        .unwrap();
        let id = NodeIdentity::load_or_create(&dir).unwrap();
        assert_eq!(id.kad_id, kad_id, "existing kad id preserved");
        assert!(dir.join("cryptkey.dat").exists(), "rsa generated + saved");
        assert!(dir.join("preferences.dat").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
