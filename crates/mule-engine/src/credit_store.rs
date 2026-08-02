//! The live credit store: a userhash-keyed map of [`CreditEntry`] records, loaded
//! from `clients.met` on engine start and written back on `pause()` (the only
//! reliable iPadOS checkpoint). It turns the pure credit formula ([`crate::credits`])
//! into a running account: bytes moved are accrued per peer, a verified peer's key
//! is bound (with eMule's anti-theft credit wipe), and a peer's upload-queue score
//! is resolved from its history + its secure-ident state.
//!
//! Everything here is LOCAL policy - nothing goes on the wire - and it is
//! REWEIGHT-ONLY: [`CreditStore::score`] never returns below `1.0`, so no identity
//! outcome can ever deny a peer a slot. Accrual is UNGATED (bytes are bytes,
//! matching eMule's `AddDownloaded`); the secure-ident gate that withholds a bonus
//! from an unverified key-bearer lives at score time ([`score_ratio_ident`]),
//! exactly as eMule gates it in `GetScoreRatio`.

use std::collections::HashMap;
use std::sync::Mutex;

use mule_files::clients_met::MAX_PUBKEY_SIZE;
use mule_files::{read_clients_met, write_clients_met, ClientsMet, CreditEntry};

use crate::credits::{resolve_ident_state, score_ratio_ident};

/// Current Unix time in seconds for `last_seen` stamps. Saturates at `u32::MAX`
/// (year 2106); a clock before the epoch reads 0.
pub fn now_secs() -> u32 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().min(u32::MAX as u64) as u32)
        .unwrap_or(0)
}

/// A userhash-keyed credit account, byte-compatible with `clients.met` on disk.
pub struct CreditStore {
    inner: Mutex<HashMap<[u8; 16], CreditEntry>>,
    /// Whether WE hold a key pair. When false the secure-ident gate is a
    /// pass-through (we cannot verify anyone), so a key-bearing-but-unverified
    /// peer is not penalised - see [`score_ratio_ident`].
    crypto_available: bool,
}

impl CreditStore {
    /// An empty store (no history yet).
    pub fn empty(crypto_available: bool) -> Self {
        CreditStore {
            inner: Mutex::new(HashMap::new()),
            crypto_available,
        }
    }

    /// Load from `clients.met` bytes, dropping entries unseen for
    /// `CREDIT_EXPIRE_SECS` (matching aMule's load-time prune). Corrupt bytes
    /// yield an empty store rather than an error - a lost credit history is not
    /// worth failing startup over.
    pub fn load(bytes: &[u8], now: u32, crypto_available: bool) -> Self {
        let map = read_clients_met(bytes)
            .map(|m| {
                m.entries
                    .into_iter()
                    .filter(|e| !e.is_expired(now))
                    .map(|e| (e.user_hash, e))
                    .collect()
            })
            .unwrap_or_default();
        CreditStore {
            inner: Mutex::new(map),
            crypto_available,
        }
    }

    /// Serialize to `clients.met` bytes (empty-history entries are skipped by
    /// `write_clients_met`, as aMule does).
    pub fn save(&self) -> Vec<u8> {
        let entries: Vec<CreditEntry> = self.inner.lock().unwrap().values().cloned().collect();
        write_clients_met(&ClientsMet { entries })
    }

    fn with_entry<R>(
        &self,
        userhash: [u8; 16],
        now: u32,
        f: impl FnOnce(&mut CreditEntry) -> R,
    ) -> R {
        let mut g = self.inner.lock().unwrap();
        let e = g
            .entry(userhash)
            .or_insert_with(|| CreditEntry::new(userhash, now));
        e.last_seen = now;
        f(e)
    }

    /// Find-or-create the peer's record and refresh `last_seen` (call at hello).
    pub fn touch(&self, userhash: [u8; 16], now: u32) {
        self.with_entry(userhash, now, |_| {});
    }

    /// Accrue bytes we UPLOADED to this peer (lowers its future score - it took).
    pub fn add_uploaded(&self, userhash: [u8; 16], n: u64, now: u32) {
        self.with_entry(userhash, now, |e| e.uploaded = e.uploaded.saturating_add(n));
    }

    /// Accrue bytes we DOWNLOADED from this peer (raises its future score - it gave).
    pub fn add_downloaded(&self, userhash: [u8; 16], n: u64, now: u32) {
        self.with_entry(userhash, now, |e| {
            e.downloaded = e.downloaded.saturating_add(n)
        });
    }

    /// Bind a peer's verified public key to its userhash. Faithful to eMule's
    /// `CClientCredits::Verified` (ClientCredits.cpp:377): the key is copied in only
    /// when there is not one yet, and binding a key to a record that ALREADY has
    /// prior credits WIPES them to one byte each - "delete all prior credits due to
    /// new SecureIdent", so a stolen userhash cannot inherit keyless-accumulated
    /// history by presenting a fresh key. A verified key never changes once set.
    pub fn bind_verified(&self, userhash: [u8; 16], pubkey: &[u8], now: u32) {
        self.with_entry(userhash, now, |e| {
            if e.key_size == 0 {
                let len = pubkey.len().min(MAX_PUBKEY_SIZE);
                e.secure_ident[..len].copy_from_slice(&pubkey[..len]);
                e.key_size = len as u8;
                if e.downloaded > 0 {
                    e.uploaded = 1;
                    e.downloaded = 1;
                }
            }
        });
    }

    /// The peer's upload-queue credit multiplier on this connection, in `[1.0,
    /// 10.0]`. `verified_ip` is `Some(ip)` if the peer proved its identity THIS
    /// session (from `ip`); `failed` if a verification was attempted and failed.
    /// The secure-ident gate is applied here (never at accrual), so an unverified
    /// key-bearer earns no bonus while we hold crypto. NEVER below 1.0 - reweight,
    /// never refuse.
    pub fn score(
        &self,
        userhash: &[u8; 16],
        verified_ip: Option<u32>,
        current_ip: u32,
        failed: bool,
    ) -> f32 {
        let (uploaded, downloaded, has_key) = {
            let g = self.inner.lock().unwrap();
            match g.get(userhash) {
                Some(e) => (e.uploaded, e.downloaded, e.key_size > 0),
                None => (0, 0, false),
            }
        };
        let ident = resolve_ident_state(has_key, verified_ip, current_ip, failed);
        score_ratio_ident(uploaded, downloaded, ident, self.crypto_available)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credits::{CREDIT_MAX_RATIO, CREDIT_MIN_RATIO};

    const H: [u8; 16] = [0xAB; 16];
    const NOW: u32 = 1_700_000_000;

    #[test]
    fn accrual_and_save_load_round_trip() {
        let s = CreditStore::empty(true);
        s.add_downloaded(H, 5 * 1_048_576, NOW);
        s.add_uploaded(H, 1_048_576, NOW);
        // Round-trips through clients.met byte-compatibly.
        let bytes = s.save();
        let s2 = CreditStore::load(&bytes, NOW, true);
        let g = s2.inner.lock().unwrap();
        let e = g.get(&H).expect("entry survives save/load");
        assert_eq!(e.downloaded, 5 * 1_048_576);
        assert_eq!(e.uploaded, 1_048_576);
    }

    #[test]
    fn expired_entries_are_dropped_on_load() {
        let s = CreditStore::empty(true);
        s.add_downloaded(H, 2 * 1_048_576, NOW - 20_000_000); // last_seen far in the past
        let bytes = s.save();
        // 20M seconds > CREDIT_EXPIRE_SECS (12.96M) -> dropped.
        let s2 = CreditStore::load(&bytes, NOW, true);
        assert!(s2.inner.lock().unwrap().get(&H).is_none());
    }

    #[test]
    fn a_verified_peer_earns_its_credit_bonus_but_an_unverified_key_bearer_does_not() {
        let ip = 0x0A00_0001;
        let s = CreditStore::empty(true);
        s.add_downloaded(H, 20 * 1_048_576, NOW); // enough to score > 1.0

        // Verified THIS session from `ip` -> full bonus.
        let verified = s.score(&H, Some(ip), ip, false);
        assert!(
            verified > CREDIT_MIN_RATIO,
            "verified peer earns a bonus: {verified}"
        );

        // Bind a key, then DON'T verify this session -> IdNeeded -> no bonus. (Bind
        // wipes the prior keyless credits, so re-accrue to isolate the gate.)
        let s2 = CreditStore::empty(true);
        s2.bind_verified(H, &[0x11; 64], NOW);
        s2.add_downloaded(H, 20 * 1_048_576, NOW);
        assert_eq!(
            s2.score(&H, None, ip, false),
            CREDIT_MIN_RATIO,
            "a key-bearer that has not verified this session earns no bonus"
        );
    }

    #[test]
    fn binding_a_key_wipes_prior_keyless_credits() {
        let s = CreditStore::empty(true);
        s.add_downloaded(H, 50 * 1_048_576, NOW);
        s.add_uploaded(H, 3 * 1_048_576, NOW);
        // First key bind with prior credits -> wiped to 1 byte each (anti-theft).
        s.bind_verified(H, &[0x22; 64], NOW);
        let g = s.inner.lock().unwrap();
        let e = g.get(&H).unwrap();
        assert_eq!(e.uploaded, 1);
        assert_eq!(e.downloaded, 1);
        assert_eq!(e.key_size, 64);
    }

    #[test]
    fn binding_the_same_key_again_does_not_re_wipe() {
        let s = CreditStore::empty(true);
        s.bind_verified(H, &[0x33; 64], NOW); // first bind, no prior credits
        s.add_downloaded(H, 40 * 1_048_576, NOW); // earn credits AFTER binding
        s.bind_verified(H, &[0x33; 64], NOW); // re-verify same session
        let g = s.inner.lock().unwrap();
        let e = g.get(&H).unwrap();
        // The key was already set, so no wipe: the earned credits survive.
        assert_eq!(e.downloaded, 40 * 1_048_576);
    }

    #[test]
    fn a_keyless_peer_is_never_penalised_and_score_never_drops_below_one() {
        let ip = 0x0A00_0001;
        let s = CreditStore::empty(true);
        s.add_downloaded(H, 20 * 1_048_576, NOW);
        // No key on file -> NotAvailable -> full ratio.
        assert!(s.score(&H, None, ip, false) > CREDIT_MIN_RATIO);
        // An unknown peer scores the floor, never panics.
        let r = s.score(&[0x00; 16], None, ip, false);
        assert!((CREDIT_MIN_RATIO..=CREDIT_MAX_RATIO).contains(&r));
    }
}
