//! clients.met: the credit list (how much each peer has uploaded to us and
//! downloaded from us). See docs/raw/wave4d-upstream-research-2026-07-14.md
//! section 1 (ClientCreditsList.cpp:65-219).
//!
//! Unlike server.met/known.met/part.met this is NOT a tag file - it is a fixed
//! width record file: `u8` version (0x12) + `u32` count, then that many 119-byte
//! records, all integers little-endian.
//!
//! THE TRAP: the 64-bit transfer totals are split into low/high dwords that are
//! NOT adjacent - `last_seen` sits between them. The on-disk order is
//! `up_lo, down_lo, last_seen, up_hi, down_hi`, a backwards-compat artifact of
//! the older 0x11 record. Getting this wrong silently corrupts every peer's
//! credits.
//!
//! Records preserve every field as read (including `reserved` and the full
//! 80-byte key blob regardless of `key_size`, which aMule admits may be garbage)
//! so a read-then-write round-trips bit-for-bit.

use mule_proto::{IoError, Reader, Writer};

/// The only version aMule writes, and the only one it will read.
pub const CREDIT_FILE_VERSION: u8 = 0x12;
/// Size of the secure-identification public key blob, always written in full.
pub const MAX_PUBKEY_SIZE: usize = 80;
/// Every record is exactly this many bytes.
pub const CREDIT_RECORD_LEN: usize = 119;
/// Entries unseen for this long are dropped at load time (150 days).
pub const CREDIT_EXPIRE_SECS: u32 = 12_960_000;

/// One peer's credit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditEntry {
    pub user_hash: [u8; 16],
    /// Bytes we have uploaded TO this peer.
    pub uploaded: u64,
    /// Bytes we have downloaded FROM this peer.
    pub downloaded: u64,
    /// Unix seconds; refreshed on every contact.
    pub last_seen: u32,
    /// Preserved verbatim; aMule always writes 0.
    pub reserved: u16,
    /// Length of the meaningful prefix of `secure_ident` (0 = no key).
    pub key_size: u8,
    /// The RSA public key blob. Always 80 bytes on disk even when `key_size` is
    /// smaller (or 0); the tail is undefined, so it is preserved as read.
    pub secure_ident: [u8; MAX_PUBKEY_SIZE],
}

impl CreditEntry {
    /// A fresh entry for a peer we have no key for (the Wave-4 case: secure
    /// ident lands in Wave 5, and aMule reads `key_size == 0` records fine).
    pub fn new(user_hash: [u8; 16], last_seen: u32) -> Self {
        CreditEntry {
            user_hash,
            uploaded: 0,
            downloaded: 0,
            last_seen,
            reserved: 0,
            key_size: 0,
            secure_ident: [0u8; MAX_PUBKEY_SIZE],
        }
    }

    /// True if this entry carries no transfer history. aMule skips these on save.
    pub fn is_empty(&self) -> bool {
        self.uploaded == 0 && self.downloaded == 0
    }

    /// True if `now` is at least `CREDIT_EXPIRE_SECS` past `last_seen`. aMule
    /// drops such entries when loading.
    pub fn is_expired(&self, now: u32) -> bool {
        now.saturating_sub(self.last_seen) >= CREDIT_EXPIRE_SECS
    }
}

/// A parsed clients.met.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ClientsMet {
    pub entries: Vec<CreditEntry>,
}

/// Parse a clients.met.
///
/// Rejects any version other than 0x12 (aMule cannot read eMule's legacy 0x11
/// either) and, matching aMule, treats `key_size > 80` as corruption of the
/// whole file rather than of one record.
pub fn read_clients_met(bytes: &[u8]) -> Result<ClientsMet, IoError> {
    let mut r = Reader::new(bytes);
    let version = r.read_u8()?;
    if version != CREDIT_FILE_VERSION {
        return Err(IoError::BadTag(version));
    }
    let count = r.read_u32()?;
    // Do not preallocate from an untrusted count; records are fixed-size, so a
    // bogus count just runs out of bytes.
    let mut entries = Vec::new();
    for _ in 0..count {
        let mut user_hash = [0u8; 16];
        user_hash.copy_from_slice(&r.read_bytes(16)?);

        // The low dwords, then last_seen, THEN the high dwords. Not a typo.
        let up_lo = r.read_u32()? as u64;
        let down_lo = r.read_u32()? as u64;
        let last_seen = r.read_u32()?;
        let up_hi = r.read_u32()? as u64;
        let down_hi = r.read_u32()? as u64;

        let reserved = r.read_u16()?;
        let key_size = r.read_u8()?;
        if key_size as usize > MAX_PUBKEY_SIZE {
            return Err(IoError::BadTag(key_size));
        }
        let mut secure_ident = [0u8; MAX_PUBKEY_SIZE];
        secure_ident.copy_from_slice(&r.read_bytes(MAX_PUBKEY_SIZE)?);

        entries.push(CreditEntry {
            user_hash,
            uploaded: up_lo | (up_hi << 32),
            downloaded: down_lo | (down_hi << 32),
            last_seen,
            reserved,
            key_size,
            secure_ident,
        });
    }
    Ok(ClientsMet { entries })
}

/// Serialize a clients.met, reproducing aMule's byte layout.
///
/// Entries with no transfer history are skipped, as aMule does.
pub fn write_clients_met(m: &ClientsMet) -> Vec<u8> {
    let kept: Vec<&CreditEntry> = m.entries.iter().filter(|e| !e.is_empty()).collect();
    let mut w = Writer::new();
    w.write_u8(CREDIT_FILE_VERSION);
    w.write_u32(kept.len() as u32);
    for e in kept {
        w.write_bytes(&e.user_hash);
        w.write_u32(e.uploaded as u32);
        w.write_u32(e.downloaded as u32);
        w.write_u32(e.last_seen);
        w.write_u32((e.uploaded >> 32) as u32);
        w.write_u32((e.downloaded >> 32) as u32);
        w.write_u16(e.reserved);
        w.write_u8(e.key_size);
        w.write_bytes(&e.secure_ident);
    }
    w.into_inner()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CreditEntry {
        CreditEntry {
            user_hash: [0xAB; 16],
            // Straddles 32 bits so a lo/hi mix-up cannot pass.
            uploaded: 0x0000_0007_1234_5678,
            downloaded: 0x0000_0003_9ABC_DEF0,
            last_seen: 0x5F5E_0100,
            reserved: 0,
            key_size: 0,
            secure_ident: [0u8; MAX_PUBKEY_SIZE],
        }
    }

    #[test]
    fn record_is_119_bytes_and_header_is_5() {
        let m = ClientsMet {
            entries: vec![sample()],
        };
        let bytes = write_clients_met(&m);
        assert_eq!(bytes.len(), 5 + CREDIT_RECORD_LEN);
        assert_eq!(bytes[0], CREDIT_FILE_VERSION);
        assert_eq!(&bytes[1..5], &1u32.to_le_bytes());
    }

    #[test]
    fn splits_64bit_totals_with_last_seen_between_the_halves() {
        let e = sample();
        let bytes = write_clients_met(&ClientsMet {
            entries: vec![e.clone()],
        });
        let rec = &bytes[5..];
        // This is the whole point of the test: the layout is
        // hash | up_lo | down_lo | last_seen | up_hi | down_hi.
        assert_eq!(&rec[0..16], &e.user_hash);
        assert_eq!(&rec[16..20], &0x1234_5678u32.to_le_bytes());
        assert_eq!(&rec[20..24], &0x9ABC_DEF0u32.to_le_bytes());
        assert_eq!(&rec[24..28], &e.last_seen.to_le_bytes());
        assert_eq!(&rec[28..32], &7u32.to_le_bytes());
        assert_eq!(&rec[32..36], &3u32.to_le_bytes());
        assert_eq!(&rec[36..38], &0u16.to_le_bytes());
        assert_eq!(rec[38], 0);
        assert_eq!(&rec[39..119], &[0u8; 80][..]);
    }

    #[test]
    fn round_trips_bit_identically() {
        let mut keyed = sample();
        keyed.user_hash = [0x11; 16];
        keyed.key_size = 3;
        // Garbage past key_size must be preserved, not zeroed.
        keyed.secure_ident[0] = 0xDE;
        keyed.secure_ident[1] = 0xAD;
        keyed.secure_ident[2] = 0xBE;
        keyed.secure_ident[79] = 0xFF;
        keyed.reserved = 0;

        let m = ClientsMet {
            entries: vec![sample(), keyed],
        };
        let bytes = write_clients_met(&m);
        let back = read_clients_met(&bytes).unwrap();
        assert_eq!(back, m);
        assert_eq!(write_clients_met(&back), bytes);
    }

    #[test]
    fn skips_entries_with_no_transfer_history() {
        let m = ClientsMet {
            entries: vec![sample(), CreditEntry::new([0x22; 16], 12345)],
        };
        let bytes = write_clients_met(&m);
        // The empty entry is dropped, so the count is 1, not 2.
        assert_eq!(&bytes[1..5], &1u32.to_le_bytes());
        assert_eq!(bytes.len(), 5 + CREDIT_RECORD_LEN);
        assert_eq!(read_clients_met(&bytes).unwrap().entries.len(), 1);
    }

    #[test]
    fn rejects_a_bad_version() {
        let bytes = [0x11u8, 0, 0, 0, 0];
        assert!(matches!(
            read_clients_met(&bytes),
            Err(IoError::BadTag(0x11))
        ));
    }

    #[test]
    fn rejects_an_oversized_key_and_discards_the_file() {
        let mut bytes = write_clients_met(&ClientsMet {
            entries: vec![sample()],
        });
        bytes[5 + 38] = 81; // key_size > MAX_PUBKEY_SIZE
        assert!(matches!(read_clients_met(&bytes), Err(IoError::BadTag(81))));
    }

    #[test]
    fn a_truncated_record_is_an_error_not_a_panic() {
        let mut bytes = write_clients_met(&ClientsMet {
            entries: vec![sample()],
        });
        bytes.truncate(bytes.len() - 1);
        assert!(read_clients_met(&bytes).is_err());
    }

    #[test]
    fn a_bogus_count_does_not_allocate_wildly() {
        // count = u32::MAX with no records behind it.
        let mut bytes = vec![CREDIT_FILE_VERSION];
        bytes.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_clients_met(&bytes).is_err());
    }

    #[test]
    fn expiry_is_150_days() {
        let e = CreditEntry::new([0u8; 16], 1000);
        assert!(!e.is_expired(1000 + CREDIT_EXPIRE_SECS - 1));
        assert!(e.is_expired(1000 + CREDIT_EXPIRE_SECS));
    }
}
