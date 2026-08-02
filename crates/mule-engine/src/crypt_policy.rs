//! When to obfuscate: the capability-gating decision for a client connection.
//! See docs/raw/wave5-crypto-research-2026-07-14.md section D (BaseClient.cpp
//! TryToConnect / Connect).
//!
//! Three crypt bits are exchanged in the hello (CT_EMULE_MISCOPTIONS2 bits
//! 7/8/9): a peer SUPPORTS, REQUESTS, or REQUIRES obfuscation. We hold the same
//! three as local preferences. [`Capabilities`] decodes the peer's bits RAW, on
//! purpose: eMule 0.50a does NOT sanitize them either (SetConnectOptions,
//! BaseClient.cpp:3190-3192, sets each bit independently), and the two
//! predicates below are byte-identical to eMule's own (reject at
//! BaseClient.cpp:1437, obfuscate at :1647). An incoherent peer (requires
//! without supports) therefore resolves EXACTLY as eMule resolves it: not
//! rejected (we support crypt), not obfuscated (the peer does not), so a
//! plaintext connect that the malformed peer can accept or drop. Adding an
//! implication sanitizer here would DIVERGE from the wire authority, so we do
//! not - matching eMule is the point.

use crate::peer::Capabilities;

/// Our local obfuscation preferences. padMule's default matches amuled
/// (`Preferences.cpp:1371-1373`): supported and requested, not required - so we
/// obfuscate whenever a peer will, but never refuse a plaintext peer.
#[derive(Debug, Clone, Copy)]
pub struct CryptPrefs {
    pub supported: bool,
    pub requested: bool,
    pub required: bool,
}

impl Default for CryptPrefs {
    fn default() -> Self {
        CryptPrefs {
            supported: true,
            requested: true,
            required: false,
        }
    }
}

/// A peer's three crypt bits, however we learned them. Two channels carry the
/// same information: a peer's HELLO (`Capabilities`, only available AFTER a
/// connection exists) and a source's connect-options BYTE, which arrives with
/// the source itself - the Kad `TAG_ENCRYPTION` tag, an SX v4 record, or the
/// obfuscated server source/callback. Only the byte can inform the DIAL, which
/// is why upstream keeps it per client (`CUpDownClient::SetConnectOptions`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerCrypt {
    pub supports: bool,
    pub requests: bool,
    pub requires: bool,
}

impl PeerCrypt {
    /// Decode upstream's connect-options byte exactly as
    /// `CUpDownClient::SetConnectOptions` does (BaseClient.cpp:3188-3193):
    /// `0x01` supported, `0x02` requested, `0x04` requires. `0x08` is the
    /// direct-UDP-callback bit and is NOT a crypt bit.
    ///
    /// `None` (no crypt info ever learned for this source) yields all-false -
    /// eMule's default for a client it has heard nothing about - so the dial
    /// goes PLAINTEXT. That is the safe default in both directions: a
    /// crypt-capable peer accepts plaintext (we never require crypt), whereas
    /// obfuscating blind is unrecoverable, since neither eMule nor padMule
    /// retries a failed obfuscated dial in plaintext.
    pub fn from_connect_options(byte: Option<u8>) -> Self {
        let b = byte.unwrap_or(0);
        PeerCrypt {
            supports: b & 0x01 != 0,
            requests: b & 0x02 != 0,
            requires: b & 0x04 != 0,
        }
    }
}

impl From<&Capabilities> for PeerCrypt {
    fn from(c: &Capabilities) -> Self {
        PeerCrypt {
            supports: c.supports_crypt,
            requests: c.requests_crypt,
            requires: c.requires_crypt,
        }
    }
}

/// Whether to REJECT a connection to/from this peer outright over obfuscation
/// policy (aMule `TryToConnect`): the peer requires it and we do not support it,
/// or we require it and the peer does not support it. NOTE: under padMule's
/// default prefs (support yes, require no) this can never fire, so it has no
/// live caller; it exists for the day the prefs become user-settable.
pub fn should_reject(peer: PeerCrypt, ours: &CryptPrefs) -> bool {
    (peer.requires && !ours.supported) || (ours.required && !peer.supports)
}

/// Whether to OBFUSCATE an outbound connection to this peer, byte-faithful to
/// eMule `CUpDownClient::Connect` (BaseClient.cpp:1647):
/// `HasValidHash() && SupportsCryptLayer() && thePrefs.IsClientCryptLayerSupported()
/// && (RequestsCryptLayer() || thePrefs.IsClientCryptLayerRequested())`.
///
/// Knowing the userhash is NECESSARY (it seeds the RC4 key) but not SUFFICIENT:
/// the peer must have advertised support. Obfuscating a peer that never did
/// sends it an RC4 handshake it reads as a malformed eD2k packet, and it drops
/// the connection - with no plaintext retry anywhere in eMule or padMule, that
/// source is simply lost.
pub fn should_obfuscate_outbound(peer: PeerCrypt, ours: &CryptPrefs, have_peer_hash: bool) -> bool {
    have_peer_hash && peer.supports && ours.supported && (peer.requests || ours.requested)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(supports: bool, requests: bool, requires: bool) -> Capabilities {
        Capabilities {
            aich: 0,
            udp_ver: 4,
            data_comp: 1,
            sec_ident: 0,
            source_exchange: 3,
            ext_requests: 2,
            accept_comment: 1,
            large_files: true,
            ext_multipacket: false,
            supports_crypt: supports,
            requests_crypt: requests,
            requires_crypt: requires,
            source_ex2: false,
            kad_version: 8,
        }
    }

    #[test]
    fn connect_options_byte_decodes_like_set_connect_options() {
        // eMule CUpDownClient::SetConnectOptions (BaseClient.cpp:3188-3193):
        // 0x01 supported, 0x02 requested, 0x04 requires. 0x08 is the direct-UDP
        // callback bit and must NOT be mistaken for a crypt bit.
        let none = PeerCrypt::from_connect_options(None);
        assert_eq!(
            (none.supports, none.requests, none.requires),
            (false, false, false),
            "no crypt info known -> assume nothing (eMule's default) -> plaintext"
        );
        let s = PeerCrypt::from_connect_options(Some(0x01));
        assert_eq!((s.supports, s.requests, s.requires), (true, false, false));
        let sr = PeerCrypt::from_connect_options(Some(0x03));
        assert_eq!((sr.supports, sr.requests, sr.requires), (true, true, false));
        let all = PeerCrypt::from_connect_options(Some(0x07));
        assert_eq!(
            (all.supports, all.requests, all.requires),
            (true, true, true)
        );
        let cb = PeerCrypt::from_connect_options(Some(0x08));
        assert_eq!(
            (cb.supports, cb.requests, cb.requires),
            (false, false, false),
            "0x08 is direct-UDP-callback, not a crypt bit"
        );
    }

    #[test]
    fn an_unknown_peer_is_dialed_plaintext_even_when_we_hold_its_hash() {
        // THE fidelity rule: eMule's Connect() obfuscates only when
        // SupportsCryptLayer() - knowing the userhash is necessary but NOT
        // sufficient. A source that arrived with no crypt info (a Kad result
        // without TAG_ENCRYPTION, an SX v1-v3 record) is dialed PLAINTEXT, which
        // is also the only choice that cannot break a crypt-disabled peer.
        let ours = CryptPrefs::default();
        assert!(!should_obfuscate_outbound(
            PeerCrypt::from_connect_options(None),
            &ours,
            true
        ));
        // The same source, once it advertises support, IS obfuscated.
        assert!(should_obfuscate_outbound(
            PeerCrypt::from_connect_options(Some(0x01)),
            &ours,
            true
        ));
    }

    #[test]
    fn default_prefs_match_amuled() {
        let p = CryptPrefs::default();
        assert!(p.supported && p.requested && !p.required);
    }

    #[test]
    fn we_obfuscate_when_the_peer_requests_and_we_have_its_hash() {
        let ours = CryptPrefs::default();
        // Peer supports + requests; we have the hash -> obfuscate.
        assert!(should_obfuscate_outbound(
            PeerCrypt::from(&caps(true, true, false)),
            &ours,
            true
        ));
        // Same, but we do not know the peer's hash -> cannot obfuscate.
        assert!(!should_obfuscate_outbound(
            PeerCrypt::from(&caps(true, true, false)),
            &ours,
            false
        ));
        // Peer does not support crypt -> plaintext.
        assert!(!should_obfuscate_outbound(
            PeerCrypt::from(&caps(false, false, false)),
            &ours,
            true
        ));
    }

    #[test]
    fn we_obfuscate_when_only_we_request_it() {
        // Peer merely supports (does not request); our default requests -> obf.
        let ours = CryptPrefs::default();
        assert!(should_obfuscate_outbound(
            PeerCrypt::from(&caps(true, false, false)),
            &ours,
            true
        ));
        // If we also do not request and the peer does not either -> plaintext.
        let passive = CryptPrefs {
            supported: true,
            requested: false,
            required: false,
        };
        assert!(!should_obfuscate_outbound(
            PeerCrypt::from(&caps(true, false, false)),
            &passive,
            true
        ));
    }

    #[test]
    fn reject_only_on_a_hard_requirement_mismatch() {
        let ours = CryptPrefs::default(); // not required
                                          // A peer that REQUIRES crypt is fine because we support it.
        assert!(!should_reject(
            PeerCrypt::from(&caps(true, true, true)),
            &ours
        ));
        // If WE required it and the peer does not support it -> reject.
        let strict = CryptPrefs {
            supported: true,
            requested: true,
            required: true,
        };
        assert!(should_reject(
            PeerCrypt::from(&caps(false, false, false)),
            &strict
        ));
        // A peer that requires crypt while we do NOT support it -> reject.
        let no_support = CryptPrefs {
            supported: false,
            requested: false,
            required: false,
        };
        assert!(should_reject(
            PeerCrypt::from(&caps(true, true, true)),
            &no_support
        ));
    }

    #[test]
    fn a_plaintext_only_pair_is_never_rejected_by_default() {
        let ours = CryptPrefs::default();
        assert!(!should_reject(
            PeerCrypt::from(&caps(false, false, false)),
            &ours
        ));
    }
}
