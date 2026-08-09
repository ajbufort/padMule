//! Answering inbound Kad requests - the RULES, with no I/O.
//!
//! padMule answers ROUTING queries only: PING, HELLO, FIND_NODE and BOOTSTRAP.
//! It stores nothing and publishes nothing, so a search or a publish gets no
//! answer at all - see `answer_request` for why silence is the faithful choice
//! there rather than the lazy one. It also judges one inbound RESPONSE: the
//! HELLO_RES_ACK that completes the three-way handshake our own HELLO_RES asks
//! for - see [`accept_hello_res_ack`].
//!
//! Pure on purpose. The socket loop lives in `kad_live`; everything decided
//! here (who gets a reply, what it contains, when the ACK bit is set) is a rule
//! a remote peer's behaviour depends on, so it must be testable without a
//! socket.

use mule_kad::{
    build_bootstrap_res, build_hello_res, build_kad2_res, build_pong, parse_hello,
    parse_hello_res_ack, parse_kad2_req, WireContact, KADEMLIA_VERSION, OP_BOOTSTRAP_REQ,
    OP_HELLO_REQ, OP_KAD2_REQ, OP_PING,
};
use mule_proto::Kad128;

/// What we tell a peer about ourselves when answering.
pub struct ServeIdentity {
    pub kad_id: Kad128,
    pub tcp_port: u16,
    /// The port peers should DIAL - the advertised one, which differs from the
    /// bound port behind a VPN remote-to-local forward. Answering with the bound
    /// port there would put us in the peer's table at an address nobody
    /// forwards, which is worse than not answering at all.
    pub advertised_udp_port: u16,
}

/// One outbound answer.
pub struct ServeAnswer {
    pub opcode: u8,
    pub payload: Vec<u8>,
    /// True when we asked the peer for a verification ACK, so the caller knows
    /// an inbound `HELLO_RES_ACK` from it is expected. Set only where eMule sets
    /// it - see [`answer_hello`].
    pub request_ack: bool,
}

impl ServeAnswer {
    fn plain(op: u8, payload: Vec<u8>) -> Option<Self> {
        Some(ServeAnswer {
            opcode: op,
            payload,
            request_ack: false,
        })
    }
}

/// Decide the answer to one inbound request, or `None` to stay silent.
///
/// `valid_receiver_key` is eMule's `bValidReceiverKey`: whether the request
/// echoed back the verify key we issue for this sender's address, which PROVES
/// the sender receives at that IP.
///
/// `closest` yields our routing table's closest VERIFIED contacts to a target,
/// passed as a closure so this stays free of the table's lock.
///
/// WHAT IS DELIBERATELY NOT ANSWERED, and why silence is faithful rather than
/// lazy: padMule stores nothing, so it has no results for a
/// `SEARCH_KEY_REQ`/`SEARCH_SOURCE_REQ` and nothing to acknowledge for a
/// `PUBLISH_*`. eMule STAYS SILENT in exactly that position -
/// `CIndexed::SendValidKeywordResult` (Indexed.cpp:696) builds and sends a
/// packet only inside `if (m_mapKeyword.Lookup(...))`, so no entry means no
/// packet, and there is no empty-`SEARCH_RES` path in stock eMule anywhere.
/// An earlier draft of this design had us answer empty as a courtesy; since no
/// stock client emits that packet and we would emit one for nearly every search
/// reaching us, it would have been a padMule fingerprint broadcast to the
/// network. Reversed 2026-08-07 on that evidence. A bonus: we never parse an
/// attacker-supplied search payload or expression tree at all.
pub fn answer_request(
    op: u8,
    payload: &[u8],
    from_udp_port: u16,
    me: &ServeIdentity,
    valid_receiver_key: bool,
    // TWO POOLS, because eMule uses two and they differ by design. A FIND
    // answer comes from `GetClosestTo(2, ...)` - contacts we have ourselves had
    // an answer from (`Process_KADEMLIA2_REQ`, KademliaUDPListener.cpp:738).
    // A BOOTSTRAP answer comes from an UNFILTERED sample
    // (`Process_KADEMLIA2_BOOTSTRAP_REQ` -> `GetBootstrapContacts` ->
    // `TopDepth` -> `CRoutingBin::GetEntries`, which filters nothing) - and it
    // must stay wide, because a bootstrapping node is exactly the caller that
    // cannot afford a thin answer. Taking two closures rather than letting the
    // CALLER pick one per opcode keeps that distinction here, in the pure
    // module that owns the answering rules, instead of in the read loop.
    closest_serving: impl FnOnce(&Kad128, usize) -> Vec<WireContact>,
    bootstrap_pool: impl FnOnce(&Kad128, usize) -> Vec<WireContact>,
) -> Option<ServeAnswer> {
    match op {
        OP_PING => {
            let (o, p) = build_pong(from_udp_port);
            ServeAnswer::plain(o, p)
        }
        OP_HELLO_REQ => answer_hello(payload, me, valid_receiver_key),
        OP_KAD2_REQ => {
            let req = parse_kad2_req(payload).ok()?;
            // The receiver field is the sender's own check that it reached the
            // node it meant to; eMule silently drops a request naming someone
            // else, and so do we.
            if req.receiver != me.kad_id {
                return None;
            }
            // ANSWER THE COUNT THE REQUESTER ASKED FOR. The type byte IS the
            // count upstream: eMule hands it straight to the table
            // (`GetClosestTo(2, uTarget, uDistance, (uint32)byType, &results)`,
            // KademliaUDPListener.cpp:737) and `GetRequestContactCount`
            // (Search.cpp:1782-1809) picks it per search type -
            // KADEMLIA_FIND_VALUE = 2 for FILE/KEYWORD/FINDSOURCE/NOTES,
            // KADEMLIA_STORE = 4 for the store types, 11 for a plain FIND_NODE.
            // Over-answering is not generosity: the searcher DISCARDS a reply
            // longer than it asked for (Search.cpp:377, "not only a protocol
            // violation but most likely a malicious answer"), so every value
            // lookup we over-answered was thrown away by the very node we are
            // trying to stay known to - and since no stock client over-answers,
            // it was a padMule fingerprint too.
            //
            // Our own cap still binds on top: `req_type` is attacker-controlled
            // and only masked to 5 bits (message.rs:481), so it can reach 31.
            let want = (req.req_type as usize).min(KAD_FIND_NODE_ANSWER_CAP);
            let mut contacts = closest_serving(&req.target, want);
            // TRUNCATE HERE, do not merely ASK for the count. Passing the limit
            // to the closure and trusting it is the "moved the check == removed
            // the check" shape: the rule is ours, the wire consequence is ours,
            // so the enforcement belongs here rather than in whatever happens to
            // supply the contacts.
            contacts.truncate(want);
            let (o, p) = build_kad2_res(&req.target, &contacts);
            ServeAnswer::plain(o, p)
        }
        OP_BOOTSTRAP_REQ => {
            let mut contacts = bootstrap_pool(&me.kad_id, KAD_BOOTSTRAP_ANSWER_CAP);
            contacts.truncate(KAD_BOOTSTRAP_ANSWER_CAP);
            let (o, p) = build_bootstrap_res(&me.kad_id, me.tcp_port, KADEMLIA_VERSION, &contacts);
            ServeAnswer::plain(o, p)
        }
        _ => None,
    }
}

/// The most contacts we put in a KADEMLIA2_RES.
///
/// eMule requests 11 (`KAD_FIND_NODE`) and REJECTS an answer longer than it
/// asked for (Search.cpp:377), so an over-long answer is not generosity - it
/// gets the whole response discarded by the node we are trying to stay known to.
pub const KAD_FIND_NODE_ANSWER_CAP: usize = 11;

/// Contacts in a BOOTSTRAP_RES.
///
/// AMPLIFICATION, capped deliberately: this is the largest response padMule
/// emits for the smallest request (a bodiless BOOTSTRAP_REQ), and UDP source
/// addresses are spoofable, so answering at all makes padMule a reflector. eMule
/// carries the same exposure; that is not a sufficient reason to match it
/// without a limit. 20 contacts is ~500 bytes against a ~30-byte request. The
/// per-IP flood limit on this opcode is the other half of the mitigation.
pub const KAD_BOOTSTRAP_ANSWER_CAP: usize = 20;

/// The misc-options bit that asks the peer for a HELLO_RES_ACK (eMule
/// `SendMyDetails`, KademliaUDPListener.cpp:106-140).
const MISC_REQUEST_ACK: u8 = 0x04;

/// Answer a KADEMLIA2_HELLO_REQ.
///
/// The ACK is requested only when the sender's IP is NOT already proven - eMule
/// sets `bRequestAckPackage` as `bAddedOrUpdated && !bValidReceiverKey`
/// (KademliaUDPListener.cpp:601). Asking a peer that already verified us is
/// pointless traffic; the first draft of the design said "always".
pub fn answer_hello(
    payload: &[u8],
    me: &ServeIdentity,
    valid_receiver_key: bool,
) -> Option<ServeAnswer> {
    // Parsed for validity even though we take nothing from it: a malformed
    // HELLO must be dropped rather than answered.
    parse_hello(payload).ok()?;
    let request_ack = !valid_receiver_key;
    let (o, p) = build_hello_res(
        &me.kad_id,
        me.tcp_port,
        Some(me.advertised_udp_port),
        request_ack.then_some(MISC_REQUEST_ACK),
    );
    Some(ServeAnswer {
        opcode: o,
        payload: p,
        request_ack,
    })
}

/// What one inbound KADEMLIA2_HELLO_RES_ACK means. Returned by
/// [`accept_hello_res_ack`]; there is no packet to send back in either case -
/// eMule's handler (`Process_KADEMLIA2_HELLO_RES_ACK`,
/// KademliaUDPListener.cpp:631-657) never emits one.
///
/// This is an enum whose accept arm CARRIES the data the action needs, rather
/// than a bool or an Option, so the socket layer cannot mark anything verified
/// without first destructuring the verdict - and `must_use` makes discarding
/// the whole verdict a build error under our `-D warnings` gate.
#[must_use = "an ignored verdict throws away the IP-verification the peer just completed"]
#[derive(Debug, PartialEq, Eq)]
pub enum AckVerdict {
    /// The ACK passed every gate. The caller MUST now mark the contact with
    /// this Kad ID verified IN ITS ROUTING TABLE - and only if that contact's
    /// STORED address equals the datagram's source IP, which is the half of
    /// eMule's `VerifyContact` (RoutingZone.cpp:980-996, IP check at :985-986)
    /// that needs the table and so cannot live here. A lookup miss or an IP
    /// mismatch is a no-op, exactly as there.
    ///
    /// This mark is what makes the whole handshake matter: `closest_to` hands
    /// out only IP-verified contacts when `enforce_verified` is on, so a peer
    /// never marked verified can never appear in any answer we give.
    MarkSenderVerified { sender_id: Kad128 },
    /// Drop the packet: no reply, no state change. eMule's reject paths are a
    /// `throw` (caught and merely logged, ClientUDPSocket.cpp:178,199-213) or a
    /// bare `return` - either way a silent drop, never a ban.
    Drop,
}

/// Judge an inbound KADEMLIA2_HELLO_RES_ACK - the third leg of the handshake
/// that [`answer_hello`]'s `0x04` misc-option asks for, proving the sender
/// really receives at its claimed IP.
///
/// Gates, in eMule's order (`Process_KADEMLIA2_HELLO_RES_ACK`,
/// KademliaUDPListener.cpp:631-657):
///
/// 1. Well-formed: at least 17 bytes, `senderID 16 | tags u8` (:633-638;
///    [`parse_hello_res_ack`] enforces the same bound).
/// 2. SOLICITED: eMule drops the ACK unless it sent a HELLO_RES to that IP
///    within the last 180 seconds - `IsOnOutTrackList(uIP, KADEMLIA2_HELLO_RES)`
///    (:639-643; PacketTracking.cpp:84-97, entry added for EVERY sent HELLO_RES
///    at KademliaUDPListener.cpp:2049 via the opcode list PacketTracking.cpp:65,
///    and CONSUMED on match). Note the gate is "a HELLO_RES was sent", not "the
///    ACK bit was set in it". That clock and list belong to the socket owner;
///    its verdict arrives here as `hello_res_recently_sent`.
/// 3. `valid_receiver_key`: the packet echoed the verify key we issue for this
///    sender's address. eMule hard-drops on an invalid key (:644-647) - the
///    whole point is proving the IP, and the key is that proof.
///
/// All three failures are silent drops (see [`AckVerdict::Drop`]).
pub fn accept_hello_res_ack(
    payload: &[u8],
    hello_res_recently_sent: bool,
    valid_receiver_key: bool,
) -> AckVerdict {
    let Ok(sender_id) = parse_hello_res_ack(payload) else {
        return AckVerdict::Drop;
    };
    if !hello_res_recently_sent {
        return AckVerdict::Drop;
    }
    if !valid_receiver_key {
        return AckVerdict::Drop;
    }
    AckVerdict::MarkSenderVerified { sender_id }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> ServeIdentity {
        ServeIdentity {
            kad_id: Kad128::from_hash(&[0x01; 16]),
            tcp_port: 4662,
            advertised_udp_port: 4672,
        }
    }

    fn no_contacts(_: &Kad128, _: usize) -> Vec<WireContact> {
        Vec::new()
    }

    /// THE TWO POOLS MUST NOT BE CROSSED. A FIND answer comes from the narrow
    /// serve pool (eMule `GetClosestTo(2, ...)`, KademliaUDPListener.cpp:738); a
    /// BOOTSTRAP answer comes from the wide unfiltered one
    /// (`GetBootstrapContacts` -> `TopDepth` -> `GetEntries`, no filter). Each
    /// closure PANICS if the other opcode reaches it, so a caller that wires one
    /// pool to both arms - which is what padMule did until 2026-08-09 - fails
    /// here rather than silently over-sharing unproven contacts.
    #[test]
    fn a_find_answers_from_the_serve_pool_and_a_bootstrap_from_its_own() {
        let target = Kad128::from_hash(&[7; 16]);
        let req = mule_kad::build_kad2_req(mule_kad::KAD_FIND_NODE, &target, &me().kad_id).1;

        let a = answer_request(
            OP_KAD2_REQ,
            &req,
            5000,
            &me(),
            false,
            |_, _| vec![contact(1, 0x0A00_0001)],
            |_, _| panic!("a FIND must not draw from the bootstrap pool"),
        )
        .expect("a find must be answered");
        assert_eq!(a.opcode, mule_kad::OP_KAD2_RES);

        let b = answer_request(
            OP_BOOTSTRAP_REQ,
            &[],
            5000,
            &me(),
            false,
            |_, _| panic!("a BOOTSTRAP must not draw from the narrow serve pool"),
            |_, _| vec![contact(2, 0x0A00_0002)],
        )
        .expect("a bootstrap must be answered");
        assert_eq!(b.opcode, mule_kad::OP_BOOTSTRAP_RES);
    }

    /// A PING is answered with the REQUESTER's port, which is how the peer
    /// learns its own external port - and answering at all is what stops eMule
    /// evicting us on its OnSmallTimer sweep, which is the whole point of the
    /// serve loop.
    #[test]
    fn a_ping_is_answered_with_the_requesters_port() {
        let a = answer_request(OP_PING, &[], 5000, &me(), false, no_contacts, no_contacts)
            .expect("a ping must be answered");
        assert_eq!(a.opcode, mule_kad::OP_PONG);
        assert_eq!(a.payload, vec![0x88, 0x13]); // 5000 LE
    }

    /// An opcode we do not serve produces NO answer - and must not panic. This
    /// is most of the protocol (publish, notes, buddies, firewall checks).
    #[test]
    fn an_unserved_opcode_is_silently_ignored() {
        assert!(answer_request(0x43, &[], 5000, &me(), false, no_contacts, no_contacts).is_none());
    }

    fn contact(seed: u8, ip: u32) -> WireContact {
        WireContact {
            id: Kad128::from_hash(&[seed; 16]),
            ip,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
        }
    }

    fn hello_req() -> Vec<u8> {
        let peer = Kad128::from_hash(&[0x55; 16]);
        mule_kad::build_hello_req(&peer, 4662, Some(4672), None).1
    }

    /// eMule asks for a verification ACK only when it has NOT already proved the
    /// sender's IP: `bAddedOrUpdated && !bValidReceiverKey`
    /// (KademliaUDPListener.cpp:601). Asking a peer that already verified us is
    /// pointless traffic, and the first draft of the design said "always".
    #[test]
    fn the_ack_is_requested_only_when_the_senders_ip_is_not_yet_proven() {
        let unproven = answer_hello(&hello_req(), &me(), false).unwrap();
        assert!(unproven.request_ack, "an unverified sender must be asked");
        assert_eq!(
            parse_hello(&unproven.payload).unwrap().misc_options,
            Some(MISC_REQUEST_ACK),
            "the ask must be ON THE WIRE, not just on the struct"
        );

        let proven = answer_hello(&hello_req(), &me(), true).unwrap();
        assert!(
            !proven.request_ack,
            "a sender that already proved its IP must not be asked again"
        );
        assert_ne!(
            parse_hello(&proven.payload).unwrap().misc_options,
            Some(MISC_REQUEST_ACK)
        );
    }

    /// The udp port in our HELLO_RES must be the ADVERTISED one. Behind a VPN
    /// remote-to-local forward the bound port is not the port peers can reach,
    /// and answering with it puts us in their table at a dead address - worse
    /// than not answering.
    #[test]
    fn the_hello_response_advertises_our_reachable_port() {
        let mut id = me();
        id.advertised_udp_port = 5999; // the forwarded port, not the bound one
        let a = answer_hello(&hello_req(), &id, false).unwrap();
        assert_eq!(a.opcode, mule_kad::OP_HELLO_RES);
        let parsed = parse_hello(&a.payload).unwrap();
        assert_eq!(parsed.id, id.kad_id);
        assert_eq!(parsed.source_udp_port, Some(5999));
    }

    #[test]
    fn a_malformed_hello_is_not_answered() {
        assert!(answer_hello(&[0u8; 4], &me(), false).is_none());
    }

    /// A FIND_NODE is answered from our table, capped at what the requester
    /// asked for - eMule REJECTS an over-long answer (Search.cpp:377), so
    /// sending one gets the whole response discarded by the node we are trying
    /// to stay known to.
    #[test]
    fn find_node_is_answered_and_capped_at_the_requested_count() {
        let target = Kad128::from_hash(&[0x33; 16]);
        let (_, req) = mule_kad::build_kad2_req(mule_kad::KAD_FIND_NODE, &target, &me().kad_id);
        let pool: Vec<WireContact> = (1..=20)
            .map(|i| contact(i, 0x0A00_0000 + i as u32))
            .collect();

        // The closure DELIBERATELY IGNORES `want` and hands back all 20. If it
        // honoured the cap the assertion below would compare the cap against
        // itself and could never fail - which is exactly what the first version
        // of this test did, and a mutation raising the cap to 100 sailed
        // straight through it.
        let a = answer_request(
            OP_KAD2_REQ,
            &req,
            5000,
            &me(),
            false,
            |t, _want| {
                assert_eq!(
                    *t, target,
                    "the table must be asked for the REQUESTED target"
                );
                pool.clone()
            },
            no_contacts,
        )
        .expect("a find_node must be answered");

        assert_eq!(a.opcode, mule_kad::OP_KAD2_RES);
        let res = mule_kad::parse_kad2_res(&a.payload).unwrap();
        assert_eq!(res.target, target);
        // A LITERAL, not the constant: asserting against the same symbol the
        // production code uses cannot catch that symbol changing.
        assert_eq!(
            res.contacts.len(),
            11,
            "20 contacts offered, 11 is eMule's requested count, got {}",
            res.contacts.len()
        );
    }

    /// A VALUE lookup asks for 2 contacts, not 11 - and the request type byte
    /// IS the count. eMule's handler passes it straight through:
    /// `GetClosestTo(2, uTarget, uDistance, (uint32)byType, &results)`
    /// (KademliaUDPListener.cpp:737), and `GetRequestContactCount`
    /// (Search.cpp:1782-1809) returns KADEMLIA_FIND_VALUE = 2 for
    /// FILE/KEYWORD/FINDSOURCE/NOTES and KADEMLIA_STORE = 4 for the store
    /// types. The searcher then DISCARDS any answer longer than it asked for
    /// (Search.cpp:377) - the same rule the find_node test above cites - so
    /// over-answering a value lookup gets the whole reply thrown away by the
    /// node we are trying to stay known to, and no stock client over-answers,
    /// which makes it a padMule fingerprint besides.
    ///
    /// The test above cannot catch this: it only ever sends KAD_FIND_NODE,
    /// whose count (11) happens to equal our own cap, so the cap and the
    /// requested count were indistinguishable in it.
    #[test]
    fn a_value_lookup_is_answered_with_the_two_contacts_it_asked_for() {
        let target = Kad128::from_hash(&[0x44; 16]);
        let (_, req) = mule_kad::build_kad2_req(mule_kad::KAD_FIND_VALUE, &target, &me().kad_id);
        let pool: Vec<WireContact> = (1..=20)
            .map(|i| contact(i, 0x0A00_0000 + i as u32))
            .collect();

        // Ignores `want` for the same reason as the test above: a closure that
        // self-limits makes the assertion tautological.
        let a = answer_request(
            OP_KAD2_REQ,
            &req,
            5000,
            &me(),
            false,
            |_, _want| pool.clone(),
            no_contacts,
        )
        .expect("a value lookup must be answered");

        let res = mule_kad::parse_kad2_res(&a.payload).unwrap();
        assert_eq!(
            res.contacts.len(),
            2,
            "KAD_FIND_VALUE asks for 2; eMule discards a longer answer wholesale, got {}",
            res.contacts.len()
        );
    }

    /// A STORE request asks for 4 (KADEMLIA_STORE, Search.cpp:1795-1801).
    /// Pinned separately from the value case so a fix that hard-codes 2 rather
    /// than reading the requested count goes red here.
    #[test]
    fn a_store_lookup_is_answered_with_the_four_contacts_it_asked_for() {
        let target = Kad128::from_hash(&[0x55; 16]);
        let (_, req) = mule_kad::build_kad2_req(mule_kad::KAD_STORE, &target, &me().kad_id);
        let pool: Vec<WireContact> = (1..=20)
            .map(|i| contact(i, 0x0A00_0000 + i as u32))
            .collect();

        let a = answer_request(
            OP_KAD2_REQ,
            &req,
            5000,
            &me(),
            false,
            |_, _want| pool.clone(),
            no_contacts,
        )
        .expect("a store lookup must be answered");

        let res = mule_kad::parse_kad2_res(&a.payload).unwrap();
        assert_eq!(
            res.contacts.len(),
            4,
            "KAD_STORE asks for 4, got {}",
            res.contacts.len()
        );
    }

    /// The cap still binds when a peer asks for MORE than we will ever send.
    /// The request type byte is attacker-controlled and masked to 5 bits
    /// (message.rs:481), so it can reach 31 - our own 11-contact ceiling is
    /// what stops an amplification ask, and it must survive the fix that
    /// starts honouring the requested count.
    #[test]
    fn a_request_for_more_than_the_cap_is_still_truncated_to_the_cap() {
        let target = Kad128::from_hash(&[0x66; 16]);
        let (_, req) = mule_kad::build_kad2_req(0x1F, &target, &me().kad_id);
        let pool: Vec<WireContact> = (1..=30)
            .map(|i| contact(i, 0x0A00_0000 + i as u32))
            .collect();

        let a = answer_request(
            OP_KAD2_REQ,
            &req,
            5000,
            &me(),
            false,
            |_, _want| pool.clone(),
            no_contacts,
        )
        .expect("an over-large ask is still answered, just capped");

        let res = mule_kad::parse_kad2_res(&a.payload).unwrap();
        assert_eq!(
            res.contacts.len(),
            11,
            "a 31-contact ask must still be cut to our 11 ceiling, got {}",
            res.contacts.len()
        );
    }

    /// A request addressed to a DIFFERENT node's id is not ours to answer. That
    /// field exists precisely so a contact can tell it reached the right node.
    #[test]
    fn a_request_addressed_to_another_node_is_ignored() {
        let target = Kad128::from_hash(&[0x33; 16]);
        let someone_else = Kad128::from_hash(&[0xEE; 16]);
        let (_, req) = mule_kad::build_kad2_req(mule_kad::KAD_FIND_NODE, &target, &someone_else);
        assert!(answer_request(
            OP_KAD2_REQ,
            &req,
            5000,
            &me(),
            false,
            |_, _| vec![contact(1, 1)],
            no_contacts,
        )
        .is_none());
    }

    #[test]
    fn a_malformed_find_node_is_not_answered() {
        assert!(answer_request(
            OP_KAD2_REQ,
            &[0u8; 5],
            5000,
            &me(),
            false,
            no_contacts,
            no_contacts
        )
        .is_none());
    }

    /// A bootstrap answer carries our details plus contacts - it is how a cold
    /// node enters the network - and it is CAPPED, because it is the largest
    /// thing we emit for the smallest request on a protocol with spoofable
    /// source addresses.
    #[test]
    fn bootstrap_is_answered_with_our_details_and_a_capped_contact_list() {
        let pool: Vec<WireContact> = (1..=30)
            .map(|i| contact(i, 0x0A00_0000 + i as u32))
            .collect();
        // Ignores `want` for the same reason as the find_node test: a closure
        // that self-limits makes the cap assertion tautological.
        // The BOOTSTRAP pool is the SEVENTH argument, and passing `no_contacts`
        // as the sixth is the point: a bootstrap answer must not be drawn from
        // the narrow serve pool. eMule serves it from an unfiltered sample
        // (`GetBootstrapContacts` -> `TopDepth` -> `CRoutingBin::GetEntries`,
        // which filters nothing), because a bootstrapping node is exactly the
        // caller that cannot afford a thin answer.
        let a = answer_request(
            OP_BOOTSTRAP_REQ,
            &[],
            5000,
            &me(),
            false,
            no_contacts,
            |_, _want| pool.clone(),
        )
        .expect("bootstrap must be answered");
        assert_eq!(a.opcode, mule_kad::OP_BOOTSTRAP_RES);
        let res = mule_kad::parse_bootstrap_res(&a.payload).unwrap();
        assert_eq!(res.id, me().kad_id);
        assert_eq!(res.tcp_port, 4662);
        assert_eq!(
            res.contacts.len(),
            20,
            "30 contacts offered; the amplification cap is 20, got {}",
            res.contacts.len()
        );
    }

    /// padMule stores nothing, so a search gets SILENCE - which is exactly what
    /// eMule does in the same position: `CIndexed::SendValidKeywordResult`
    /// (Indexed.cpp:696) sends a packet only inside
    /// `if (m_mapKeyword.Lookup(...))`, and stock eMule has no empty-SEARCH_RES
    /// path anywhere. An earlier draft answered empty as a courtesy; since no
    /// stock client emits that packet, every one would have fingerprinted
    /// padMule to anyone searching a keyword we lack.
    #[test]
    fn a_search_gets_silence_because_that_is_what_emule_gives() {
        let kw = mule_kad::kad_keyword_target("minister");
        let (_, key_req) = mule_kad::build_search_key_req(&kw, 0);
        assert!(
            answer_request(
                mule_kad::OP_SEARCH_KEY_REQ,
                &key_req,
                5000,
                &me(),
                false,
                no_contacts,
                no_contacts
            )
            .is_none(),
            "answering a keyword search would fingerprint padMule"
        );

        let file = Kad128::from_hash(&[0x77; 16]);
        let (_, src_req) = mule_kad::build_search_source_req(&file, 0, 9_728_000);
        assert!(answer_request(
            mule_kad::OP_SEARCH_SOURCE_REQ,
            &src_req,
            5000,
            &me(),
            false,
            no_contacts,
            no_contacts
        )
        .is_none());
    }

    /// We store nothing, so acknowledging a publish would be a lie.
    #[test]
    fn a_publish_is_ignored_rather_than_falsely_acknowledged() {
        for op in [0x43u8, 0x44, 0x45] {
            assert!(
                answer_request(op, &[0u8; 40], 5000, &me(), false, no_contacts, no_contacts)
                    .is_none()
            );
        }
    }

    fn ack_from(seed: u8) -> Vec<u8> {
        mule_kad::build_hello_res_ack(&Kad128::from_hash(&[seed; 16])).1
    }

    /// The happy path of the three-way handshake: a well-formed, solicited ACK
    /// with a valid receiver key must come back as MarkSenderVerified CARRYING
    /// THE SENDER'S PARSED ID - the id is what the caller marks, so a wrong or
    /// constant id here would verify the wrong contact.
    #[test]
    fn a_solicited_ack_with_a_valid_key_marks_the_sender_verified() {
        let peer = Kad128::from_hash(&[0x55; 16]);
        match accept_hello_res_ack(&ack_from(0x55), true, true) {
            AckVerdict::MarkSenderVerified { sender_id } => assert_eq!(
                sender_id, peer,
                "the verdict must carry the ID parsed from the packet"
            ),
            AckVerdict::Drop => panic!("an ACK that passes every gate must verify the sender"),
        }
    }

    /// eMule hard-drops an ACK whose receiver key is invalid
    /// (Process_KADEMLIA2_HELLO_RES_ACK, KademliaUDPListener.cpp:644-647). The
    /// key IS the IP proof; accepting without it would let a spoofed source
    /// address become a verified contact.
    #[test]
    fn an_ack_without_a_valid_receiver_key_is_dropped() {
        assert_eq!(
            accept_hello_res_ack(&ack_from(0x55), true, false),
            AckVerdict::Drop
        );
    }

    /// eMule drops an ACK from an IP it did not recently send a HELLO_RES to -
    /// `IsOnOutTrackList(uIP, KADEMLIA2_HELLO_RES)`
    /// (KademliaUDPListener.cpp:639-643). The design spec omitted this gate;
    /// the source is the authority.
    #[test]
    fn an_unsolicited_ack_is_dropped() {
        assert_eq!(
            accept_hello_res_ack(&ack_from(0x55), false, true),
            AckVerdict::Drop
        );
    }

    /// Shorter than `senderID 16 | tags u8` is malformed and dropped
    /// (KademliaUDPListener.cpp:633-638), never guessed at.
    #[test]
    fn a_malformed_ack_is_dropped() {
        assert_eq!(
            accept_hello_res_ack(&ack_from(0x55)[..16], true, true),
            AckVerdict::Drop
        );
        assert_eq!(accept_hello_res_ack(&[], true, true), AckVerdict::Drop);
    }
}
