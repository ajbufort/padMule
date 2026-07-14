//! The credit system: peers that have given us data get a better place in our
//! upload queue. See docs/raw/wave4d-upstream-research-2026-07-14.md section 1
//! (ClientCredits.cpp:121-161).
//!
//! Credits are a purely LOCAL policy - nothing here goes on the wire - but they
//! are persisted byte-compatibly in clients.met (`mule_files::clients_met`) so
//! an aMule install and padMule can share a credit history.
//!
//! Secure identification (RSA, Wave 5) ties in here: a peer that has advertised
//! a public key but has NOT proved it owns it (or proved it from a different IP)
//! earns no credit bonus, which is the whole point - it stops a stolen userhash
//! from inheriting the real owner's credits. A peer with NO key (an old client)
//! is not penalised; only a key-bearing-but-unverified/failed peer is. When
//! padMule has no key pair (`crypto_available == false`) every identity branch is
//! a pass-through and credits work as before.

/// Below this many bytes downloaded from a peer, it gets no credit bonus.
/// Note this is a DECIMAL megabyte, while the sqrt term below uses a BINARY one.
/// Both are faithful to upstream; it is not a typo.
pub const CREDIT_MIN_DOWNLOADED: u64 = 1_000_000;
/// The ratio is clamped to this range.
pub const CREDIT_MIN_RATIO: f32 = 1.0;
pub const CREDIT_MAX_RATIO: f32 = 10.0;

/// The credit multiplier a peer has earned, in `[1.0, 10.0]`.
///
/// `uploaded` is what we have sent TO the peer; `downloaded` is what we have
/// received FROM it. A peer that has given us a lot and taken little scores
/// high, which multiplies its upload-queue score.
///
/// The sqrt term caps how fast credit can be earned, so a peer cannot leap the
/// queue on a single generous burst.
pub fn score_ratio(uploaded: u64, downloaded: u64) -> f32 {
    if downloaded < CREDIT_MIN_DOWNLOADED {
        return CREDIT_MIN_RATIO;
    }
    let by_ratio = if uploaded == 0 {
        CREDIT_MAX_RATIO
    } else {
        (downloaded as f64 * 2.0 / uploaded as f64) as f32
    };
    let by_volume = ((downloaded as f64 / 1_048_576.0) + 2.0).sqrt() as f32;
    by_ratio
        .min(by_volume)
        .clamp(CREDIT_MIN_RATIO, CREDIT_MAX_RATIO)
}

/// A peer's secure-identification state, as it bears on credits. Mirrors aMule's
/// `EIdentState` (ClientCredits.h) - the values the credit formula distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentState {
    /// No public key on file - an old/keyless client. NOT penalised.
    NotAvailable,
    /// Has a key but has not proved ownership this session. No bonus yet.
    IdNeeded,
    /// Proved ownership of its key for this IP. Full credits.
    Identified,
    /// Presented a key that failed signature verification. No bonus.
    IdFailed,
    /// Key verified, but the userhash is now appearing from a DIFFERENT IP -
    /// a replayed/stolen hash. No bonus.
    IdBadGuy,
}

/// Resolve the ident state for the peer on the current connection, given what we
/// know about its key. Mirrors `CClientCredits::GetCurrentIdentState`
/// (ClientCredits.cpp:219-231): an identity is bound to the IP it verified from,
/// so the same userhash from another IP reads as a bad guy.
pub fn resolve_ident_state(
    has_pubkey: bool,
    verified_ip: Option<u32>,
    current_ip: u32,
    verification_failed: bool,
) -> IdentState {
    if !has_pubkey {
        return IdentState::NotAvailable;
    }
    if verification_failed {
        return IdentState::IdFailed;
    }
    match verified_ip {
        Some(ip) if ip == current_ip => IdentState::Identified,
        Some(_) => IdentState::IdBadGuy,
        None => IdentState::IdNeeded,
    }
}

/// The credit ratio, gated by secure-identification state (aMule
/// ClientCredits.cpp:121-161). A key-bearing peer that is not (yet) verified,
/// failed verification, or is replaying a hash from another IP gets no bonus -
/// but only when WE have crypto (`crypto_available`); without our own key the
/// gate is a pass-through. A keyless peer (`NotAvailable`) and a verified peer
/// (`Identified`) both get the normal ratio.
pub fn score_ratio_ident(
    uploaded: u64,
    downloaded: u64,
    ident: IdentState,
    crypto_available: bool,
) -> f32 {
    if crypto_available
        && matches!(
            ident,
            IdentState::IdFailed | IdentState::IdBadGuy | IdentState::IdNeeded
        )
    {
        return CREDIT_MIN_RATIO;
    }
    score_ratio(uploaded, downloaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_we_have_barely_downloaded_from_gets_no_bonus() {
        assert_eq!(score_ratio(0, 0), 1.0);
        assert_eq!(score_ratio(0, CREDIT_MIN_DOWNLOADED - 1), 1.0);
        // The threshold is the DECIMAL megabyte, so 1 MiB is comfortably over it
        // but 999_999 bytes is not.
        assert!(score_ratio(0, CREDIT_MIN_DOWNLOADED) > 1.0);
    }

    #[test]
    fn a_peer_that_gave_and_took_nothing_back_is_capped_by_the_sqrt_term() {
        // uploaded == 0 would give ratio 10.0, but the volume cap bites first:
        // sqrt(2MiB/1MiB + 2) = sqrt(4) = 2.0
        let r = score_ratio(0, 2 * 1_048_576);
        assert!((r - 2.0).abs() < 1e-5, "got {r}");
    }

    #[test]
    fn the_ratio_term_bites_when_we_have_uploaded_a_lot() {
        // downloaded*2/uploaded = 20MiB*2/40MiB = 1.0, well under the sqrt cap.
        let r = score_ratio(40 * 1_048_576, 20 * 1_048_576);
        assert!((r - 1.0).abs() < 1e-5, "got {r}");
    }

    #[test]
    fn is_clamped_to_ten() {
        // A peer that gave us a huge amount and took nothing: sqrt cap would be
        // large, ratio term is 10.0 (uploaded == 0), so the clamp holds at 10.
        assert_eq!(score_ratio(0, 10_000 * 1_048_576), CREDIT_MAX_RATIO);
    }

    #[test]
    fn never_drops_below_one_even_when_we_have_been_generous() {
        // We uploaded 1 GiB and got 2 MiB back: raw ratio is ~0.004.
        assert_eq!(
            score_ratio(1024 * 1_048_576, 2 * 1_048_576),
            CREDIT_MIN_RATIO
        );
    }

    #[test]
    fn does_not_panic_on_extreme_totals() {
        let r = score_ratio(u64::MAX, u64::MAX);
        assert!((CREDIT_MIN_RATIO..=CREDIT_MAX_RATIO).contains(&r));
        let r = score_ratio(1, u64::MAX);
        assert!((CREDIT_MIN_RATIO..=CREDIT_MAX_RATIO).contains(&r));
    }

    #[test]
    fn ident_state_binds_to_the_verifying_ip() {
        let ip = 0x0A00_0001;
        // No key -> NotAvailable (a keyless old client).
        assert_eq!(
            resolve_ident_state(false, None, ip, false),
            IdentState::NotAvailable
        );
        // Has a key, not yet verified -> IdNeeded.
        assert_eq!(
            resolve_ident_state(true, None, ip, false),
            IdentState::IdNeeded
        );
        // Verified for this IP -> Identified.
        assert_eq!(
            resolve_ident_state(true, Some(ip), ip, false),
            IdentState::Identified
        );
        // Verified for a DIFFERENT IP (hash replayed) -> IdBadGuy.
        assert_eq!(
            resolve_ident_state(true, Some(0x0B00_0002), ip, false),
            IdentState::IdBadGuy
        );
        // Verification failed -> IdFailed.
        assert_eq!(
            resolve_ident_state(true, None, ip, true),
            IdentState::IdFailed
        );
    }

    #[test]
    fn a_generous_but_unverified_key_bearing_peer_earns_no_bonus() {
        // Gave us 20 MiB (would normally score ~2.0), but has a key it has not
        // proved -> no bonus while we have crypto.
        let up = 20 * 1_048_576;
        let down = 20 * 1_048_576;
        let earned = score_ratio(up, down); // baseline (>1.0)
        assert!(earned > 1.0);
        assert_eq!(
            score_ratio_ident(up, down, IdentState::IdNeeded, true),
            CREDIT_MIN_RATIO
        );
        assert_eq!(
            score_ratio_ident(up, down, IdentState::IdBadGuy, true),
            CREDIT_MIN_RATIO
        );
        assert_eq!(
            score_ratio_ident(up, down, IdentState::IdFailed, true),
            CREDIT_MIN_RATIO
        );
    }

    #[test]
    fn a_verified_or_keyless_peer_earns_full_credits() {
        let up = 20 * 1_048_576;
        let down = 20 * 1_048_576;
        let baseline = score_ratio(up, down);
        assert_eq!(
            score_ratio_ident(up, down, IdentState::Identified, true),
            baseline
        );
        // A keyless peer is not penalised.
        assert_eq!(
            score_ratio_ident(up, down, IdentState::NotAvailable, true),
            baseline
        );
    }

    #[test]
    fn without_our_own_key_the_ident_gate_is_a_pass_through() {
        let up = 20 * 1_048_576;
        let down = 20 * 1_048_576;
        let baseline = score_ratio(up, down);
        // crypto_available == false: even a bad-guy state does not penalise,
        // because we cannot verify anyone anyway.
        assert_eq!(
            score_ratio_ident(up, down, IdentState::IdBadGuy, false),
            baseline
        );
    }
}
