//! Iterative Kademlia node lookup (eMule `CSearch`), Wave 6c. Given a target ID
//! and some seed contacts, repeatedly query the ALPHA closest not-yet-queried
//! candidates; each KADEMLIA2_RES adds contacts closer to the target, advancing
//! the frontier until the closest known nodes have all been queried.
//!
//! This is the pure, deterministic core - no sockets or timers. The live engine
//! drives it: `next_queries` -> send KADEMLIA2_REQ (FIND_NODE) -> feed each
//! KADEMLIA2_RES to `on_response`, with JumpStart/timeout handling on top. IP /
//! per-/24 anti-poisoning dedup is likewise a live-layer concern; here we dedup
//! by node ID (XOR distance to the target is injective, so it doubles as the
//! sort key). See docs/raw/wave6-kad-research-2026-07-14.md section D.

use crate::message::WireContact;
use mule_proto::Kad128;
use std::collections::{BTreeMap, HashSet};

/// Concurrent queries in flight (eMule `ALPHA_QUERY`, authoritative 3; aMule
/// ships 5 - we use eMule's, a behavior-not-wire choice).
pub const ALPHA_QUERY: usize = 3;

/// One iterative node lookup toward `target`.
pub struct Lookup {
    target: Kad128,
    /// Candidates keyed by XOR distance to the target (ascending). Distance is
    /// unique per ID, so this is also a by-ID set.
    candidates: BTreeMap<Kad128, WireContact>,
    /// IDs we have already sent a request to.
    tried: HashSet<Kad128>,
    /// Every ID ever inserted (dedup).
    seen: HashSet<Kad128>,
}

impl Lookup {
    /// Start a lookup toward `target` seeded with some contacts (typically the
    /// routing table's closest-to-target set).
    pub fn new(target: Kad128, seeds: impl IntoIterator<Item = WireContact>) -> Self {
        let mut l = Lookup {
            target,
            candidates: BTreeMap::new(),
            tried: HashSet::new(),
            seen: HashSet::new(),
        };
        for c in seeds {
            l.add(c);
        }
        l
    }

    fn add(&mut self, c: WireContact) {
        if c.version <= 1 {
            return; // Kad1 contacts are not accepted
        }
        if !self.seen.insert(c.id) {
            return; // already known
        }
        let dist = self.target.distance(&c.id);
        self.candidates.insert(dist, c);
    }

    /// Up to `alpha` closest not-yet-queried candidates from within the
    /// `frontier` closest (marks them queried). Empty once every candidate in the
    /// frontier has been queried - the convergence signal.
    pub fn next_queries(&mut self, alpha: usize, frontier: usize) -> Vec<WireContact> {
        let mut out = Vec::new();
        for c in self.candidates.values().take(frontier) {
            if out.len() >= alpha {
                break;
            }
            if !self.tried.contains(&c.id) {
                out.push(c.clone());
            }
        }
        for c in &out {
            self.tried.insert(c.id);
        }
        out
    }

    /// Feed the contacts a queried node returned (KADEMLIA2_RES). New, closer
    /// contacts enter the frontier and get queried on a later `next_queries`.
    pub fn on_response(&mut self, contacts: impl IntoIterator<Item = WireContact>) {
        for c in contacts {
            self.add(c);
        }
    }

    /// The `k` closest known contacts to the target.
    pub fn closest(&self, k: usize) -> Vec<WireContact> {
        self.candidates.values().take(k).cloned().collect()
    }

    /// True once the `frontier` closest known candidates have all been queried,
    /// i.e. no un-queried node remains in the frontier so nothing closer can
    /// still surface. Equivalent to `next_queries(_, frontier)` being empty.
    pub fn is_converged(&self, frontier: usize) -> bool {
        self.candidates
            .values()
            .take(frontier)
            .all(|c| self.tried.contains(&c.id))
    }

    /// Total candidates known.
    pub fn candidate_count(&self) -> usize {
        self.candidates.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contact(id: Kad128) -> WireContact {
        WireContact {
            id,
            ip: 0x0A00_0001,
            udp_port: 4672,
            tcp_port: 4662,
            version: 8,
        }
    }

    fn kid(seed: u8) -> Kad128 {
        Kad128::from_hash(&[seed; 16])
    }

    #[test]
    fn seeds_are_ordered_by_distance_and_next_queries_picks_closest_untried() {
        let target = kid(0x00);
        // Seeds at increasing distance from the target 0x00..0.
        let seeds: Vec<WireContact> = [0x01, 0x40, 0x02, 0x80]
            .iter()
            .map(|&s| contact(kid(s)))
            .collect();
        let mut lk = Lookup::new(target, seeds);
        assert_eq!(lk.candidate_count(), 4);

        // The two closest to 0x00.. are 0x01.. and 0x02.. (smaller high byte).
        let batch = lk.next_queries(2, 10);
        assert_eq!(batch.len(), 2);
        let ids: Vec<Kad128> = batch.iter().map(|c| c.id).collect();
        assert_eq!(ids, vec![kid(0x01), kid(0x02)]);
    }

    #[test]
    fn dedup_and_kad1_rejection() {
        let target = kid(0x00);
        let mut lk = Lookup::new(target, [contact(kid(0x05))]);
        // Re-adding the same id is a no-op.
        lk.on_response([contact(kid(0x05))]);
        assert_eq!(lk.candidate_count(), 1);
        // A Kad1 (version <= 1) contact is rejected.
        let mut k1 = contact(kid(0x06));
        k1.version = 1;
        lk.on_response([k1]);
        assert_eq!(lk.candidate_count(), 1);
    }

    #[test]
    fn converges_when_the_frontier_is_all_queried() {
        let target = kid(0x00);
        let mut lk = Lookup::new(target, [contact(kid(0x10))]);
        assert!(!lk.is_converged(10));
        // Query the only seed; it returns nothing closer.
        let batch = lk.next_queries(ALPHA_QUERY, 10);
        assert_eq!(batch.len(), 1);
        lk.on_response(Vec::new());
        assert!(
            lk.is_converged(10),
            "single tried seed, no new nodes -> done"
        );
        assert!(lk.next_queries(ALPHA_QUERY, 10).is_empty());
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

        // `node`'s answer to a lookup for `target`: the `resp` contacts in its
        // routing table closest to the target.
        fn respond(&self, node: &Kad128, target: &Kad128, resp: usize) -> Vec<WireContact> {
            let mut rt = crate::routing::RoutingTable::new(*node);
            for x in &self.nodes {
                rt.add(*x, 0x0A00_0001, 4672, 4662, 8);
            }
            rt.closest_to(target, resp)
                .into_iter()
                .map(|c| contact(c.id))
                .collect()
        }

        fn true_closest(&self, target: &Kad128, k: usize) -> Vec<Kad128> {
            let mut v = self.nodes.clone();
            v.sort_by_key(|x| target.distance(x));
            v.into_iter().take(k).collect()
        }
    }

    #[test]
    fn iterative_lookup_converges_to_the_globally_closest_node() {
        let net = SimNet::new(160);
        // Target is a node that exists in the network (index 40).
        let target = net.nodes[40];
        // Seed with three arbitrary (mostly far) nodes.
        let seeds = [net.nodes[5], net.nodes[90], net.nodes[150]].map(contact);

        let mut lk = Lookup::new(target, seeds);
        let frontier = 10;
        let mut rounds = 0;
        loop {
            let batch = lk.next_queries(ALPHA_QUERY, frontier);
            if batch.is_empty() {
                break;
            }
            for node in batch {
                lk.on_response(net.respond(&node.id, &target, 10));
            }
            rounds += 1;
            assert!(rounds < 100, "lookup must terminate");
        }

        // The single closest node to the target is the target itself; the lookup
        // must have found it, and its best set must match the true k-closest.
        let true_k = net.true_closest(&target, frontier);
        let found: Vec<Kad128> = lk.closest(frontier).iter().map(|c| c.id).collect();
        assert_eq!(found[0], target, "must find the exact closest node");
        assert_eq!(found[0], true_k[0]);
        // The dense routing tables make the whole k-closest set exact.
        assert_eq!(found, true_k, "converges to the true k-closest");
    }
}
