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

/// Whether to REJECT a connection to/from this peer outright over obfuscation
/// policy (aMule `TryToConnect`): the peer requires it and we do not support it,
/// or we require it and the peer does not support it.
pub fn should_reject(peer: &Capabilities, ours: &CryptPrefs) -> bool {
    (peer.requires_crypt && !ours.supported) || (ours.required && !peer.supports_crypt)
}

/// Whether to OBFUSCATE an outbound connection to this peer (aMule `Connect`):
/// we must know the peer's userhash (the RC4 key seed), the peer must support
/// crypt and we must support crypt, and either the peer requests it or we do.
pub fn should_obfuscate_outbound(
    peer: &Capabilities,
    ours: &CryptPrefs,
    have_peer_hash: bool,
) -> bool {
    have_peer_hash
        && peer.supports_crypt
        && ours.supported
        && (peer.requests_crypt || ours.requested)
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
    fn default_prefs_match_amuled() {
        let p = CryptPrefs::default();
        assert!(p.supported && p.requested && !p.required);
    }

    #[test]
    fn we_obfuscate_when_the_peer_requests_and_we_have_its_hash() {
        let ours = CryptPrefs::default();
        // Peer supports + requests; we have the hash -> obfuscate.
        assert!(should_obfuscate_outbound(
            &caps(true, true, false),
            &ours,
            true
        ));
        // Same, but we do not know the peer's hash -> cannot obfuscate.
        assert!(!should_obfuscate_outbound(
            &caps(true, true, false),
            &ours,
            false
        ));
        // Peer does not support crypt -> plaintext.
        assert!(!should_obfuscate_outbound(
            &caps(false, false, false),
            &ours,
            true
        ));
    }

    #[test]
    fn we_obfuscate_when_only_we_request_it() {
        // Peer merely supports (does not request); our default requests -> obf.
        let ours = CryptPrefs::default();
        assert!(should_obfuscate_outbound(
            &caps(true, false, false),
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
            &caps(true, false, false),
            &passive,
            true
        ));
    }

    #[test]
    fn reject_only_on_a_hard_requirement_mismatch() {
        let ours = CryptPrefs::default(); // not required
                                          // A peer that REQUIRES crypt is fine because we support it.
        assert!(!should_reject(&caps(true, true, true), &ours));
        // If WE required it and the peer does not support it -> reject.
        let strict = CryptPrefs {
            supported: true,
            requested: true,
            required: true,
        };
        assert!(should_reject(&caps(false, false, false), &strict));
        // A peer that requires crypt while we do NOT support it -> reject.
        let no_support = CryptPrefs {
            supported: false,
            requested: false,
            required: false,
        };
        assert!(should_reject(&caps(true, true, true), &no_support));
    }

    #[test]
    fn a_plaintext_only_pair_is_never_rejected_by_default() {
        let ours = CryptPrefs::default();
        assert!(!should_reject(&caps(false, false, false), &ours));
    }
}
