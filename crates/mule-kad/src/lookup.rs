//! Event-driven Kademlia lookup (eMule `CSearch`) - the pure, deterministic
//! core. No sockets, no timers: the live engine (`mule-engine::kad_live`) owns
//! the I/O and feeds this state machine one event at a time.
//!
//! Shape, from eMule 0.50a Search.cpp (the WIRE+behaviour authority here):
//!
//! - `possible` (eMule `m_mapPossible`): every known candidate keyed by XOR
//!   distance to the target, CONSUMED front-first by [`CSearch::harvest`] as
//!   entries resolve. A dispatched contact stays here until harvested - eMule
//!   only erases entries in its JumpStart walk (Search.cpp:325-350).
//! - `tried` (eMule `m_mapTried`): everything ever dispatched, kept forever;
//!   it is the dedup set and the responder register.
//! - `best` (eMule `m_mapBest`): the `ALPHA_QUERY` closest distances seen in
//!   answers - the gate on IMMEDIATE dispatch (Search.cpp:481-509): a returned
//!   contact closer than its responder that lands in the top-alpha is asked at
//!   once, inside the response handler, with no round barrier.
//! - `responded` (eMule `m_mapResponded`): presence only. eMule stores a
//!   provided-closer bool but the only reader we would have is the
//!   "best FIND_VALUE nodes all dead -> re-ask for more" case (Search.cpp:
//!   291-322), which padMule deliberately skips: it exists because eMule's
//!   value lookups request only KADEMLIA_FIND_VALUE = 2 contacts per hop and
//!   can starve on duplicates of dead nodes; padMule requests 11
//!   (KAD_FIND_NODE) on every hop, so that starvation cannot arise.
//! - `failed`: NOT in eMule. eMule has no per-request deadline - JumpStart
//!   presumes 3s of silence means death. padMule's driver gives every request
//!   its own deadline, so death is an explicit event and `harvest` never has
//!   to guess whether the closest entry is dead or merely in flight.
//!
//! Per-answer anti-poisoning (unique IPs, the 2-per-/24 cap) is a live-layer
//! concern applied to the SEARCH FRONTIER only, before contacts reach
//! [`CSearch::on_response`] - see `kad_live::frontier_filter`. Here we dedup by
//! node ID (XOR distance to the target is injective, so it doubles as the sort
//! key).

use crate::message::WireContact;
use mule_proto::Kad128;
use std::collections::{BTreeMap, BTreeSet};

/// Concurrent queries in flight (eMule `ALPHA_QUERY`, Defines.h:45,
/// authoritative 3; aMule ships 5 - we use eMule's, a behavior-not-wire
/// choice).
pub const ALPHA_QUERY: usize = 3;

/// One event-driven lookup toward `target`. Feed it events, send what it
/// returns: [`CSearch::refill`] keeps requests in flight,
/// [`CSearch::on_response`] yields eMule's immediate dispatches, and
/// [`CSearch::harvest`] yields the interleaved value asks.
pub struct CSearch {
    target: Kad128,
    /// Candidates by XOR distance (ascending), consumed by `harvest`.
    possible: BTreeMap<Kad128, WireContact>,
    /// Everything dispatched, by distance, kept forever.
    tried: BTreeMap<Kad128, WireContact>,
    /// Distances that answered our FIND.
    responded: BTreeSet<Kad128>,
    /// Distances whose FIND timed out (or could not be sent).
    failed: BTreeSet<Kad128>,
    /// The top `ALPHA_QUERY` answer distances - the immediate-dispatch gate.
    best: BTreeSet<Kad128>,
    /// FIND_NODE requests this lookup may still spend.
    find_budget: usize,
    /// Value requests this lookup may still spend.
    value_budget: usize,
    /// How deep into `possible` `refill` may reach (the classic K frontier).
    frontier: usize,
}

impl CSearch {
    /// Start a lookup toward `target` seeded with some contacts (typically the
    /// routing table's closest-to-target set - eMule Go() seeds 50 the same
    /// way, Search.cpp:183).
    pub fn new(
        target: Kad128,
        seeds: impl IntoIterator<Item = WireContact>,
        find_budget: usize,
        value_budget: usize,
        frontier: usize,
    ) -> Self {
        let mut s = CSearch {
            target,
            possible: BTreeMap::new(),
            tried: BTreeMap::new(),
            responded: BTreeSet::new(),
            failed: BTreeSet::new(),
            best: BTreeSet::new(),
            find_budget,
            value_budget,
            frontier,
        };
        for c in seeds {
            s.add(c);
        }
        s
    }

    /// Add one candidate; `Some(distance)` if it was new. Kad1 contacts are
    /// not accepted (eMule ignores version <= 1, KademliaUDPListener.cpp:832).
    fn add(&mut self, c: WireContact) -> Option<Kad128> {
        if c.version <= 1 {
            return None;
        }
        let dist = self.target.distance(&c.id);
        if self.possible.contains_key(&dist) || self.tried.contains_key(&dist) {
            return None;
        }
        self.possible.insert(dist, c);
        Some(dist)
    }

    /// Up to `capacity` closest untried candidates within the frontier, marked
    /// tried and charged to the find budget. The driver sends a FIND_NODE to
    /// each. This is eMule's Go() initial burst (Search.cpp:197-216) and the
    /// refill that keeps `ALPHA_QUERY` requests in flight thereafter.
    pub fn refill(&mut self, capacity: usize) -> Vec<WireContact> {
        let mut out = Vec::new();
        for (dist, c) in self.possible.iter().take(self.frontier) {
            if out.len() >= capacity.min(self.find_budget) {
                break;
            }
            if !self.tried.contains_key(dist) {
                out.push(c.clone());
            }
        }
        for c in &out {
            self.find_budget -= 1;
            self.tried.insert(self.target.distance(&c.id), c.clone());
        }
        out
    }

    /// Process one FIND_NODE answer (eMule ProcessResponse, Search.cpp:353).
    /// Every contact joins `possible`; a contact CLOSER THAN ITS RESPONDER that
    /// lands in the top-alpha `best` set is returned for IMMEDIATE dispatch
    /// (marked tried, budget charged), at most `capacity` of them - the cap is
    /// padMule's in-flight bound, which eMule does not have. A qualifying
    /// contact past the cap stays untried and is `refill`'s to pick up.
    ///
    /// An answer from a contact we never asked is ignored entirely (eMule's
    /// pFromContact == NULL path).
    pub fn on_response(
        &mut self,
        from: &WireContact,
        contacts: Vec<WireContact>,
        capacity: usize,
    ) -> Vec<WireContact> {
        let from_dist = self.target.distance(&from.id);
        if !self.tried.contains_key(&from_dist) {
            return Vec::new();
        }
        let mut dispatch = Vec::new();
        for c in contacts {
            let Some(dist) = self.add(c.clone()) else {
                continue; // already known or tried (Search.cpp:442-445)
            };
            if dist < from_dist {
                // The top-ALPHA_QUERY gate (Search.cpp:481-499): top if best
                // has room, or if closer than the worst best entry (evicting
                // it).
                let top = if self.best.len() < ALPHA_QUERY {
                    self.best.insert(dist);
                    true
                } else {
                    let worst = *self.best.last().expect("best is non-empty here");
                    if dist < worst {
                        self.best.remove(&worst);
                        self.best.insert(dist);
                        true
                    } else {
                        false
                    }
                };
                if top && dispatch.len() < capacity && self.find_budget > 0 {
                    self.find_budget -= 1;
                    self.tried.insert(dist, c.clone());
                    dispatch.push(c);
                }
            }
        }
        self.responded.insert(from_dist);
        dispatch
    }

    /// Record that `from`'s FIND timed out (or could not be sent), so
    /// `harvest` can consume the entry instead of waiting on it forever.
    pub fn on_timeout(&mut self, from: &WireContact) {
        let dist = self.target.distance(&from.id);
        if self.tried.contains_key(&dist) {
            self.failed.insert(dist);
        }
    }

    /// The JumpStart walk (Search.cpp:325-350) minus the timing, which is the
    /// driver's: consume `possible` front-first while entries are RESOLVED.
    /// A tried+responded entry within the storage tolerance is returned as a
    /// value ask (eMule StorePacket, reached the same way); a tried+failed
    /// entry is consumed silently (eMule erases tried-unresponded entries -
    /// a node that never answered the FIND is never value-asked). The walk
    /// stops at an IN-FLIGHT entry - its outcome decides what comes next -
    /// and at the first dispatchable untried entry, which is `refill`'s.
    /// An untried entry the exhausted find budget can never reach is consumed,
    /// so resolved entries behind it are not stranded.
    pub fn harvest(&mut self) -> Vec<WireContact> {
        let mut asks = Vec::new();
        while let Some((dist, c)) = self.possible.first_key_value() {
            let dist = *dist;
            if self.tried.contains_key(&dist) {
                if self.responded.contains(&dist) {
                    if dist.within_tolerance() && self.value_budget > 0 {
                        self.value_budget -= 1;
                        asks.push(c.clone());
                    }
                    self.possible.pop_first();
                } else if self.failed.contains(&dist) {
                    self.possible.pop_first();
                } else {
                    break; // in flight
                }
            } else if self.find_budget == 0 {
                self.possible.pop_first();
            } else {
                break; // untried and still dispatchable
            }
        }
        asks
    }

    /// The `k` closest contacts this lookup ever learned of, harvested or not
    /// (`tried` remembers what `harvest` consumed).
    pub fn closest(&self, k: usize) -> Vec<WireContact> {
        let mut merged: BTreeMap<Kad128, &WireContact> = BTreeMap::new();
        for (d, c) in self.tried.iter().chain(self.possible.iter()) {
            merged.entry(*d).or_insert(c);
        }
        merged.into_values().take(k).cloned().collect()
    }

    /// Candidates not yet consumed by the walk.
    pub fn candidate_count(&self) -> usize {
        self.possible.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A contact whose XOR distance to the all-zero target IS its leading
    /// word - so `d` doubles as the distance in every assertion below, with
    /// nothing derived from the constants under test.
    fn at(d: u32) -> WireContact {
        WireContact {
            id: Kad128::from_words([d, 0, 0, 0]),
            ip: 0xCB00_7100 | (d & 0xFF), // 203.0.113.x - irrelevant here
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
        }
    }

    fn target() -> Kad128 {
        Kad128::from_words([0, 0, 0, 0])
    }

    /// Distances small enough for `within_tolerance` (< 2^120): leading word
    /// well under 0x0100_0000.
    const NEAR_A: u32 = 0x0000_0080;
    const NEAR_B: u32 = 0x0000_0100;
    const NEAR_C: u32 = 0x0000_0200;

    fn ids(v: &[WireContact]) -> Vec<u32> {
        v.iter().map(|c| c.id.words()[0]).collect()
    }

    fn search(seeds: &[u32]) -> CSearch {
        CSearch::new(target(), seeds.iter().map(|&d| at(d)), 1000, 1000, 10)
    }

    #[test]
    fn refill_dispatches_the_closest_untried_up_to_capacity() {
        let mut cs = search(&[0x30, 0x10, 0x20, 0x40]);
        assert_eq!(ids(&cs.refill(3)), vec![0x10, 0x20, 0x30]);
        assert_eq!(ids(&cs.refill(3)), vec![0x40], "already-tried are skipped");
        assert!(cs.refill(3).is_empty(), "nothing untried remains");
    }

    #[test]
    fn a_contact_closer_than_its_responder_dispatches_immediately() {
        let mut cs = search(&[0x10]);
        assert_eq!(ids(&cs.refill(3)), vec![0x10]);
        let d = cs.on_response(&at(0x10), vec![at(0x08)], 3);
        assert_eq!(
            ids(&d),
            vec![0x08],
            "closer than its responder and top-alpha: eMule sends the FIND \
             inside the response handler (Search.cpp:508)"
        );
    }

    #[test]
    fn a_contact_farther_than_its_responder_never_dispatches_immediately() {
        let mut cs = search(&[0x10]);
        cs.refill(3);
        let d = cs.on_response(&at(0x10), vec![at(0x20)], 3);
        assert!(
            d.is_empty(),
            "0x20 is farther than its responder 0x10 - eMule only immediate-\
             dispatches on uDistance < uFromDistance (Search.cpp:479)"
        );
        // It still joined the frontier; refill picks it up.
        assert_eq!(ids(&cs.refill(1)), vec![0x20]);
    }

    #[test]
    fn the_top_alpha_gate_blocks_a_closer_contact_that_is_not_top() {
        let mut cs = search(&[0x80, 0x90]);
        cs.refill(3);
        let d = cs.on_response(&at(0x80), vec![at(0x10), at(0x20), at(0x30)], 3);
        assert_eq!(ids(&d), vec![0x10, 0x20, 0x30], "best had room for all 3");
        // 0x40 is closer than its responder 0x90, but worse than the worst
        // best entry (0x30) - not top, no immediate dispatch.
        let d = cs.on_response(&at(0x90), vec![at(0x40)], 3);
        assert!(
            d.is_empty(),
            "closer-than-responder alone is not enough; it must also make the \
             top-ALPHA_QUERY best set (Search.cpp:483-499)"
        );
        // A contact better than the worst best entry evicts it and goes out.
        let d = cs.on_response(&at(0x30), vec![at(0x28)], 3);
        assert_eq!(ids(&d), vec![0x28], "evicts worst best entry 0x30");
        // The blocked 0x40 is refill's to pick up, not lost.
        assert_eq!(ids(&cs.refill(3)), vec![0x40]);
    }

    #[test]
    fn the_capacity_cap_defers_a_top_contact_to_refill() {
        let mut cs = search(&[0x10]);
        cs.refill(3);
        let d = cs.on_response(&at(0x10), vec![at(0x08), at(0x04)], 1);
        assert_eq!(d.len(), 1, "capacity 1 admits exactly one immediate send");
        // The other qualifying contact was not stranded: it is untried and
        // closest, so refill returns it.
        let next = cs.refill(1);
        assert_eq!(next.len(), 1);
        assert!(
            ids(&d) != ids(&next),
            "refill must hand out the DEFERRED contact, not re-dispatch"
        );
    }

    #[test]
    fn a_known_or_tried_contact_is_not_reprocessed() {
        let mut cs = search(&[0x10]);
        cs.refill(3);
        // The answer names the responder's own id and a new contact twice.
        let d = cs.on_response(&at(0x10), vec![at(0x10), at(0x08), at(0x08)], 3);
        assert_eq!(ids(&d), vec![0x08], "dispatched once, not twice");
        assert_eq!(cs.candidate_count(), 2, "0x10 (seed) + 0x08, no dups");
    }

    #[test]
    fn an_unknown_responder_is_ignored() {
        let mut cs = search(&[0x10]);
        cs.refill(3);
        let d = cs.on_response(&at(0x77), vec![at(0x04)], 3);
        assert!(
            d.is_empty(),
            "we never asked 0x77 (eMule pFromContact NULL)"
        );
        assert_eq!(cs.candidate_count(), 1, "its contacts are not admitted");
    }

    #[test]
    fn kad1_contacts_are_rejected() {
        let mut k1 = at(0x10);
        k1.version = 1;
        let cs = CSearch::new(target(), [k1], 1000, 1000, 10);
        assert_eq!(cs.candidate_count(), 0);
    }

    #[test]
    fn harvest_asks_the_closest_responded_in_tolerance_node_and_consumes_it() {
        let mut cs = search(&[NEAR_A]);
        cs.refill(3);
        cs.on_response(&at(NEAR_A), vec![], 3);
        assert_eq!(ids(&cs.harvest()), vec![NEAR_A]);
        assert!(cs.harvest().is_empty(), "consumed: one ask per node");
        // Consumed from possible, but not forgotten.
        assert_eq!(ids(&cs.closest(1)), vec![NEAR_A]);
    }

    #[test]
    fn an_out_of_tolerance_responder_is_consumed_without_a_value_ask() {
        // 0x7000_0000 in the leading word is a distance far beyond 2^120.
        let mut cs = search(&[0x7000_0000]);
        cs.refill(3);
        cs.on_response(&at(0x7000_0000), vec![], 3);
        assert!(
            cs.harvest().is_empty(),
            "eMule StorePacket returns without sending beyond SEARCHTOLERANCE \
             (Search.cpp:543) - and the entry is still consumed"
        );
        assert_eq!(cs.candidate_count(), 0);
    }

    #[test]
    fn harvest_waits_for_a_closer_in_flight_probe_before_asking_a_farther_responder() {
        let mut cs = search(&[NEAR_A, NEAR_B]);
        cs.refill(2);
        cs.on_response(&at(NEAR_B), vec![], 2);
        assert!(
            cs.harvest().is_empty(),
            "NEAR_A is closer and still in flight - asking NEAR_B now would \
             invert eMule's strict closest-first walk order"
        );
        cs.on_response(&at(NEAR_A), vec![], 2);
        assert_eq!(ids(&cs.harvest()), vec![NEAR_A, NEAR_B]);
    }

    #[test]
    fn a_failed_probe_unblocks_the_value_asks_behind_it() {
        let mut cs = search(&[NEAR_A, NEAR_B]);
        cs.refill(2);
        cs.on_response(&at(NEAR_B), vec![], 2);
        cs.on_timeout(&at(NEAR_A));
        assert_eq!(
            ids(&cs.harvest()),
            vec![NEAR_B],
            "the dead closest entry is consumed unasked (eMule erases \
             tried-unresponded entries in the walk) and the responder behind \
             it gets its ask"
        );
    }

    #[test]
    fn the_value_budget_caps_how_many_asks_a_lookup_spends() {
        let mut cs = CSearch::new(
            target(),
            [at(NEAR_A), at(NEAR_B), at(NEAR_C)],
            1000,
            2, // independent literal; the assertions below use their own
            10,
        );
        cs.refill(3);
        for d in [NEAR_A, NEAR_B, NEAR_C] {
            cs.on_response(&at(d), vec![], 3);
        }
        assert_eq!(
            ids(&cs.harvest()),
            vec![NEAR_A, NEAR_B],
            "two asks, closest first; the third responder is consumed unasked"
        );
        assert_eq!(cs.candidate_count(), 0);
    }

    #[test]
    fn the_find_budget_caps_dispatches_and_does_not_strand_the_walk() {
        let mut cs = CSearch::new(target(), [at(NEAR_A), at(NEAR_B)], 1, 1000, 10);
        assert_eq!(ids(&cs.refill(3)), vec![NEAR_A], "budget 1 spends 1");
        cs.on_response(&at(NEAR_A), vec![], 3);
        assert_eq!(
            ids(&cs.harvest()),
            vec![NEAR_A],
            "the untried-but-unaffordable NEAR_B must not block the walk"
        );
        assert_eq!(
            cs.candidate_count(),
            0,
            "NEAR_B was consumed - the exhausted budget can never try it"
        );
    }

    // A deterministic simulated network where each node's knowledge is a REAL
    // routing table (the Wave-6a bin-tree) loaded with every other node. A real
    // K-bucketed table spans distance scales, so greedy iterative lookup is
    // navigable - unlike a naive "M nearest neighbors" graph, which has no
    // long-range links and strands the lookup in a local minimum.
    struct SimNet {
        nodes: Vec<Kad128>,
    }
    impl SimNet {
        fn new(n: usize) -> Self {
            // Deterministic pseudo-random 128-bit ids (no Math.random - splitmix64).
            let mut nodes = Vec::with_capacity(n);
            for i in 0..n as u64 {
                let mut z = i
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .wrapping_add(0x1234_5678);
                let mut w = [0u32; 4];
                for word in w.iter_mut() {
                    z ^= z >> 30;
                    z = z.wrapping_mul(0xBF58_476D_1CE4_E5B9);
                    z ^= z >> 27;
                    *word = (z >> 16) as u32;
                }
                nodes.push(Kad128::from_words(w));
            }
            SimNet { nodes }
        }

        fn contact(id: Kad128) -> WireContact {
            WireContact {
                id,
                ip: 0x0A00_0001,
                udp_port: 4672,
                tcp_port: 4662,
                version: 8,
            }
        }

        // `node`'s answer to a lookup for `target`: the `resp` contacts in its
        // routing table closest to the target.
        fn respond(&self, node: &Kad128, target: &Kad128, resp: usize) -> Vec<WireContact> {
            let mut rt = crate::routing::RoutingTable::new(*node);
            for x in &self.nodes {
                // Verified: a real node answers from IP-verified contacts only
                // (RoutingBin::GetClosestTo), and this sim is about convergence.
                rt.add(*x, 0x0A00_0001, 4672, 4662, 8, true);
            }
            rt.closest_to(target, resp)
                .into_iter()
                .map(|c| Self::contact(c.id))
                .collect()
        }

        fn true_closest(&self, target: &Kad128, k: usize) -> Vec<Kad128> {
            let mut v = self.nodes.clone();
            v.sort_by_key(|x| target.distance(x));
            v.into_iter().take(k).collect()
        }
    }

    /// The convergence proof, driven the way the live driver drives it: an
    /// in-flight set capped at ALPHA_QUERY, each response feeding immediate
    /// dispatches and a refill - no rounds anywhere.
    #[test]
    fn the_event_driven_lookup_converges_to_the_globally_closest_node() {
        let net = SimNet::new(160);
        let target = net.nodes[40];
        let seeds = [net.nodes[5], net.nodes[90], net.nodes[150]].map(SimNet::contact);

        let frontier = 10;
        let mut cs = CSearch::new(target, seeds, 10_000, 0, frontier);
        let mut inflight: Vec<WireContact> = cs.refill(ALPHA_QUERY);
        let mut events = 0;
        while let Some(node) = inflight.pop() {
            let answer = net.respond(&node.id, &target, 10);
            let cap = ALPHA_QUERY - inflight.len();
            inflight.extend(cs.on_response(&node, answer, cap));
            let cap = ALPHA_QUERY.saturating_sub(inflight.len());
            inflight.extend(cs.refill(cap));
            assert!(
                inflight.len() <= ALPHA_QUERY,
                "the in-flight set must never exceed ALPHA_QUERY"
            );
            events += 1;
            assert!(events < 1000, "lookup must terminate");
        }

        let true_k = net.true_closest(&target, frontier);
        let found: Vec<Kad128> = cs.closest(frontier).iter().map(|c| c.id).collect();
        assert_eq!(found[0], target, "must find the exact closest node");
        assert_eq!(found, true_k, "converges to the true k-closest");
    }
}
