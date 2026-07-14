//! The credit system: peers that have given us data get a better place in our
//! upload queue. See docs/raw/wave4d-upstream-research-2026-07-14.md section 1
//! (ClientCredits.cpp:121-161).
//!
//! Credits are a purely LOCAL policy - nothing here goes on the wire - but they
//! are persisted byte-compatibly in clients.met (`mule_files::clients_met`) so
//! an aMule install and padMule can share a credit history.
//!
//! Secure identification (RSA) lands in Wave 5. Until then padMule has no key
//! pair, which upstream calls `crypto_available == false`; in that state every
//! identity branch of the formula is a pass-through and the credit system works
//! fully. Unidentified peers are NOT penalised upstream either - only peers that
//! present a key and then FAIL verification are, which cannot happen yet.

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
}
