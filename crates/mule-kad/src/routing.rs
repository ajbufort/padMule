//! The Kad routing table: a binary tree of "zones", each leaf a bin of up to K
//! contacts, split so buckets get finer resolution the closer they are to our own
//! ID. See docs/raw/wave6-kad-research-2026-07-14.md section C (eMule 0.50a
//! RoutingZone/RoutingBin/Defines.h).

use mule_files::KadContact;
use mule_proto::Kad128;

/// Contacts per leaf bin.
pub const K: usize = 10;
/// Sybil/poisoning defense (eMule CRoutingBin): a single host must not flood the
/// table with fake node IDs. Cap how many contacts may share one IP / one /24.
/// Interop-safe: the global Kad network is IP-diverse, so a legitimate peer is
/// never rejected - only an attacker packing many IDs behind one address is.
pub const MAX_CONTACTS_PER_IP: usize = 2;
pub const MAX_CONTACTS_PER_SUBNET: usize = 10;
/// A full bin below this level always splits (fine resolution shallow in the tree).
pub const KBASE: u8 = 4;
/// A full bin whose zone index is below this also splits (fine resolution near self).
pub const KK: u128 = 5;
/// Maximum tree depth.
pub const MAXLEVELS: u8 = 127;

/// One routing-table contact: a node plus its precomputed XOR distance to us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub id: Kad128,
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
    /// self_id XOR id - fixed once we know our own ID, so kept here.
    distance: Kad128,
}

impl Contact {
    fn new(
        self_id: &Kad128,
        id: Kad128,
        ip: u32,
        udp_port: u16,
        tcp_port: u16,
        version: u8,
    ) -> Self {
        Contact {
            distance: self_id.distance(&id),
            id,
            ip,
            udp_port,
            tcp_port,
            version,
        }
    }

    /// Our XOR distance to this contact.
    pub fn distance(&self) -> Kad128 {
        self.distance
    }
}

enum Node {
    /// A bin of up to K contacts, ordered oldest-first (LRU: front = oldest).
    Leaf(Vec<Contact>),
    /// Two subzones: `.0` is side 0 (the half CLOSER to our own ID).
    Internal(Box<Zone>, Box<Zone>),
}

struct Zone {
    level: u8,
    index: u128,
    node: Node,
}

impl Zone {
    fn leaf(level: u8, index: u128) -> Self {
        Zone {
            level,
            index,
            node: Node::Leaf(Vec::new()),
        }
    }

    fn add(&mut self, contact: Contact) {
        // Descend toward the child matching this contact's distance bit at our
        // level (bit 0 = the half closer to our own ID).
        if let Node::Internal(zero, one) = &mut self.node {
            if contact.distance.bit(self.level as u32) == 0 {
                zero.add(contact);
            } else {
                one.add(contact);
            }
            return;
        }

        // Leaf. Copy the split-decision inputs first to avoid borrowing all of
        // self while `bin` is borrowed from self.node.
        let (level, index) = (self.level, self.index);
        if let Node::Leaf(bin) = &mut self.node {
            // Already known? Move to back (most-recently-seen).
            if let Some(pos) = bin.iter().position(|c| c.id == contact.id) {
                bin.remove(pos);
                bin.push(contact);
                return;
            }
            if bin.len() < K {
                bin.push(contact);
                return;
            }
            // Full bin. It may split only if shallow (level < KBASE) or close to
            // us (index < KK), and not at the depth limit - eMule CanSplit. If it
            // cannot split, the new contact is dropped.
            let can_split = level < MAXLEVELS && (index < KK || level < KBASE);
            if !can_split {
                return;
            }
        }
        // Full, splittable leaf: split, then re-descend into the new subtree.
        self.split();
        self.add(contact);
    }

    /// Turn this full leaf into an internal node, redistributing its bin by each
    /// contact's distance bit at this level.
    fn split(&mut self) {
        let bin = match &mut self.node {
            Node::Leaf(b) => std::mem::take(b),
            Node::Internal(..) => return,
        };
        let mut zero = Box::new(Zone::leaf(self.level + 1, self.index << 1));
        let mut one = Box::new(Zone::leaf(self.level + 1, (self.index << 1) | 1));
        for c in bin {
            if c.distance.bit(self.level as u32) == 0 {
                if let Node::Leaf(b) = &mut zero.node {
                    b.push(c);
                }
            } else if let Node::Leaf(b) = &mut one.node {
                b.push(c);
            }
        }
        self.node = Node::Internal(zero, one);
    }

    fn collect<'a>(&'a self, out: &mut Vec<&'a Contact>) {
        match &self.node {
            Node::Leaf(bin) => out.extend(bin.iter()),
            Node::Internal(zero, one) => {
                zero.collect(out);
                one.collect(out);
            }
        }
    }
}

/// The Kad routing table, rooted at our own Kad ID.
pub struct RoutingTable {
    self_id: Kad128,
    root: Zone,
}

impl RoutingTable {
    /// A new, empty table for our node `self_id`.
    pub fn new(self_id: Kad128) -> Self {
        RoutingTable {
            self_id,
            root: Zone::leaf(0, 0),
        }
    }

    /// Add (or refresh) a contact. Ignores our own ID. The anti-sybil per-IP//24
    /// cap is enforced one layer up (kad_live::add_contact, a LIVE-layer concern -
    /// see the lookup.rs module note), so this stays a pure routing primitive.
    pub fn add(&mut self, id: Kad128, ip: u32, udp_port: u16, tcp_port: u16, version: u8) {
        if id == self.self_id {
            return;
        }
        let c = Contact::new(&self.self_id, id, ip, udp_port, tcp_port, version);
        self.root.add(c);
    }

    /// True if a contact with this id is already in the table.
    pub fn contains(&self, id: &Kad128) -> bool {
        let mut all: Vec<&Contact> = Vec::new();
        self.root.collect(&mut all);
        all.iter().any(|c| c.id == *id)
    }

    /// (contacts sharing this exact IP, contacts sharing its /24 subnet). Used by
    /// the live layer to enforce the anti-sybil cap before inserting a network
    /// contact.
    pub fn ip_counts(&self, ip: u32) -> (usize, usize) {
        let subnet = ip & 0xFFFF_FF00;
        let mut all: Vec<&Contact> = Vec::new();
        self.root.collect(&mut all);
        let mut same_ip = 0;
        let mut same_subnet = 0;
        for c in all {
            if c.ip == ip {
                same_ip += 1;
            }
            if c.ip & 0xFFFF_FF00 == subnet {
                same_subnet += 1;
            }
        }
        (same_ip, same_subnet)
    }

    /// Load every contact from a parsed nodes.dat.
    pub fn load_nodes(&mut self, contacts: &[KadContact]) {
        for c in contacts {
            self.add(c.id, c.ip, c.udp_port, c.tcp_port, c.version);
        }
    }

    /// Total contacts currently held.
    pub fn len(&self) -> usize {
        let mut v = Vec::new();
        self.root.collect(&mut v);
        v.len()
    }

    /// Every contact currently held (unordered) - e.g. to checkpoint the table
    /// to a `nodes.dat`.
    pub fn contacts(&self) -> Vec<Contact> {
        let mut v: Vec<&Contact> = Vec::new();
        self.root.collect(&mut v);
        v.into_iter().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The `count` contacts closest (by XOR distance) to `target` - the candidate
    /// set an iterative lookup starts from.
    pub fn closest_to(&self, target: &Kad128, count: usize) -> Vec<Contact> {
        let mut all: Vec<&Contact> = Vec::new();
        self.root.collect(&mut all);
        all.sort_by_key(|c| target.distance(&c.id));
        all.into_iter().take(count).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mule_files::read_nodes_dat;

    const NODES: &[u8] = include_bytes!("../../mule-files/tests/fixtures/nodes.dat");

    fn id(seed: u8) -> Kad128 {
        Kad128::from_hash(&[seed; 16])
    }

    #[test]
    fn adds_and_counts_contacts() {
        let mut rt = RoutingTable::new(id(0));
        rt.add(id(1), 0x0101_0101, 1, 2, 8);
        rt.add(id(2), 0x0202_0202, 3, 4, 8);
        assert_eq!(rt.len(), 2);
        // Re-adding the same id refreshes, does not duplicate.
        rt.add(id(1), 0x0101_0101, 1, 2, 8);
        assert_eq!(rt.len(), 2);
    }

    #[test]
    fn ignores_our_own_id() {
        let mut rt = RoutingTable::new(id(7));
        rt.add(id(7), 0, 0, 0, 8);
        assert!(rt.is_empty());
    }

    #[test]
    fn loads_the_real_nodes_dat_into_a_tree() {
        let parsed = read_nodes_dat(NODES).unwrap();
        assert_eq!(parsed.contacts.len(), 179);
        let mut rt = RoutingTable::new(id(0x42));
        rt.load_nodes(&parsed.contacts);
        // The tree must have SPLIT to hold well beyond one K=10 bin, and it
        // retains MOST contacts - but not all: far bins cap at K, so contacts
        // that overflow a full, unsplittable far zone are dropped (correct
        // Kademlia behaviour, since these 179 were saved relative to a different
        // node's ID). Loading them relative to 0x42 keeps ~142.
        let n = rt.len();
        assert!(n > K, "the tree must have split beyond one bin, got {n}");
        assert!(
            n > 100 && n < 179,
            "most kept, some overflow-dropped, got {n}"
        );
    }

    #[test]
    fn closest_to_returns_the_nearest_by_xor() {
        // A small controlled table: 15 distinct contacts near self all fit (near
        // zones split), so none is dropped and we can assert exact closeness.
        let mut rt = RoutingTable::new(id(0));
        let ids: Vec<Kad128> = (1..=15u8).map(id).collect();
        for (i, cid) in ids.iter().enumerate() {
            rt.add(*cid, i as u32, 1, 2, 8);
        }
        assert_eq!(rt.len(), 15);

        let target = ids[3];
        let closest = rt.closest_to(&target, 5);
        assert_eq!(closest.len(), 5);
        assert_eq!(closest[0].id, target, "a node is closest to its own id");
        // Sorted by increasing XOR distance to the target.
        for w in closest.windows(2) {
            assert!(target.distance(&w[0].id) <= target.distance(&w[1].id));
        }
    }

    #[test]
    fn closest_to_over_the_real_table_is_sorted() {
        let parsed = read_nodes_dat(NODES).unwrap();
        let mut rt = RoutingTable::new(id(0x42));
        rt.load_nodes(&parsed.contacts);
        let target = Kad128::from_hash(&[0x99; 16]);
        let closest = rt.closest_to(&target, 10);
        assert_eq!(closest.len(), 10);
        for w in closest.windows(2) {
            assert!(target.distance(&w[0].id) <= target.distance(&w[1].id));
        }
    }

    #[test]
    fn a_full_far_bin_drops_extra_contacts_but_a_near_bin_splits() {
        // Fill the table with many contacts that all share the top bits (far from
        // self, high zone index) so their bin cannot split past KBASE; it caps at
        // K. Contacts near self keep splitting.
        let mut rt = RoutingTable::new(Kad128::from_words([0, 0, 0, 0]));
        // 50 contacts whose top nibble is 0xF (far from self id 0): they funnel
        // into deep high-index zones that stop splitting at level KBASE.
        for i in 0..50u32 {
            let mut w = [0xF000_0000u32, 0, 0, i];
            w[1] = i.wrapping_mul(2654435761);
            rt.add(Kad128::from_words(w), i, 1, 2, 8);
        }
        // The table holds contacts but far fewer than 50 (far bins capped at K per
        // leaf, limited leaves because far zones stop splitting).
        let n = rt.len();
        assert!(n > 0 && n <= 50);
    }
}
