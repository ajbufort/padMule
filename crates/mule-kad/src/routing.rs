//! The Kad routing table: a binary tree of "zones", each leaf a bin of up to K
//! contacts, split so buckets get finer resolution the closer they are to our own
//! ID. See docs/raw/wave6-kad-research-2026-07-14.md section C (eMule 0.50a
//! RoutingZone/RoutingBin/Defines.h).

use mule_files::KadContact;
use mule_proto::Kad128;

/// Contacts per leaf bin.
pub const K: usize = 10;
/// Sybil/poisoning defense (eMule CRoutingBin, RoutingBin.cpp:56-57): a single
/// host must not flood the table with fake node IDs. Cap how many contacts may
/// share one IP / one /24. Interop-safe: the global Kad network is IP-diverse, so
/// a legitimate peer is never rejected - only an attacker packing many IDs behind
/// one address is (eMule's own comment: multiple KAD clients behind one IP still
/// index/search fine; they just are not all kept in the routing table).
pub const MAX_CONTACTS_PER_IP: usize = 1;
pub const MAX_CONTACTS_PER_SUBNET: usize = 10;
/// A full bin below this level always splits (fine resolution shallow in the tree).
pub const KBASE: u8 = 4;
/// A full bin whose zone index is below this also splits (fine resolution near self).
pub const KK: u128 = 5;
/// Maximum tree depth.
pub const MAXLEVELS: u8 = 127;

// --- CONTACT AGING (eMule `CContact`, Contact.cpp) ---
// padMule had NO aging at all before 2026-08-08: nothing expired, nothing was
// probed, nothing was ever removed. These are eMule's own numbers, read from
// the source rather than the spec.
/// A new or nodes.dat-loaded contact: unproven, no lease yet (`InitContact`,
/// Contact.cpp:120-129 - type 3, expires 0). One failed probe from death.
pub const KAD_TYPE_NEW: u8 = 3;
/// A contact that has just proven itself alive (`UpdateType` hour-0 arm,
/// Contact.cpp:233-236).
pub const KAD_TYPE_ALIVE: u8 = 2;
/// Probed and awaiting an answer. The only type a sweep may REMOVE
/// (`OnSmallTimer`, RoutingZone.cpp:868-885).
pub const KAD_TYPE_PROBED: u8 = 4;
/// The lease a proven-alive contact gets (`UpdateType` hour-0, HR2S(1)).
pub const ALIVE_LEASE_SECS: u64 = 3600;
/// How long a probed contact has to answer before a sweep removes it
/// (`CheckingType`, Contact.cpp:223 - MIN2S(2)).
pub const PROBE_WINDOW_SECS: u64 = 120;
/// `CheckingType` refuses to re-stamp within 10 seconds (Contact.cpp:218), so a
/// burst of sweeps cannot march a contact to death faster than the wire allows.
pub const CHECKING_TYPE_MIN_GAP: u64 = 10;

/// What one [`RoutingTable::sweep`] pass did: who must be probed, and who was
/// removed for failing to answer an earlier probe.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SweepOutcome {
    /// Contacts to send a `KADEMLIA2_HELLO_REQ` to. Already stamped as probed,
    /// so a sweep that fires while these are in flight will not re-probe them.
    pub probes: Vec<Contact>,
    /// Contacts removed this pass. The caller tombstones these so they are not
    /// written back to nodes.dat.
    pub removed: Vec<Kad128>,
}

/// One routing-table contact: a node plus its precomputed XOR distance to us.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contact {
    pub id: Kad128,
    pub ip: u32,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub version: u8,
    /// Whether this contact's (KadID, IP) has been UDP-verified (eMule
    /// `CContact::IsIpVerified`): true once a receiver-key-valid reply arrived
    /// from this IP, or as read from a nodes.dat that recorded it. Monotonic
    /// (promoted false->true, never regresses); persisted across restarts.
    pub verified: bool,
    /// The verify key this peer handed us (its `senderVerifyKey`), which we echo
    /// as our `receiverVerifyKey` on future requests so IT can verify US. Bound to
    /// OUR public IP at capture time (`udp_key_ip`), since the key is
    /// `udp_verify_key(peer_secret, OUR_ip)` - stale if our IP changes. 0 = none
    /// yet (echo 0, first-contact-safe). eMule `CContact::SetReceiverKey`.
    pub udp_key: u32,
    /// Our public IP when `udp_key` was minted; the key is only echoed while this
    /// still matches our current public IP (mirrors `CKadUDPKey::GetKeyValue`).
    pub udp_key_ip: u32,
    /// eMule `CContact::m_byType`: 3 = new/unproven, 2 = proven alive, 4 =
    /// probed and awaiting an answer. Lower is better-established. Only a
    /// type-4 contact past its `expires` may be removed by a sweep.
    pub kad_type: u8,
    /// eMule `CContact::m_tExpires`, as an absolute second on the caller's
    /// clock. `None` is eMule's 0 sentinel - "never stamped" - which the first
    /// sweep replaces with `now` so the second sweep can probe it.
    pub expires: Option<u64>,
    /// eMule `CContact::m_tLastTypeSet`, guarding `CheckingType`'s 10s floor.
    pub last_type_set: u64,
    /// self_id XOR id - fixed once we know our own ID, so kept here.
    distance: Kad128,
}

impl Contact {
    #[allow(clippy::too_many_arguments)]
    fn new(
        self_id: &Kad128,
        id: Kad128,
        ip: u32,
        udp_port: u16,
        tcp_port: u16,
        version: u8,
        verified: bool,
        udp_key: u32,
        udp_key_ip: u32,
    ) -> Self {
        Contact {
            distance: self_id.distance(&id),
            id,
            ip,
            udp_port,
            tcp_port,
            version,
            verified,
            udp_key,
            udp_key_ip,
            // eMule `InitContact`: every contact starts unproven with no lease,
            // including one loaded from nodes.dat - aging is never persisted
            // (nodes.dat carries no type/expiry field), so a restart re-proves
            // everyone. That is what makes a dead seed die ~3-4 minutes into a
            // session rather than never.
            kad_type: KAD_TYPE_NEW,
            expires: None,
            last_type_set: 0,
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
                // ANTI-HIJACK, at the TABLE (eMule RoutingZone.cpp:525-533).
                // A contact we hold a sender key for is one we have actually
                // corresponded with; eMule refuses to update such an entry from
                // a packet that does not carry the SAME key, and an EMPTY key
                // explicitly fails that test ("failed to provide the proper
                // sender key (Sent Empty: Yes) ... denying update"). A contact
                // named inside a third party's KADEMLIA2_RES payload carries no
                // key, so that is precisely the packet being refused.
                //
                // NARROWER THAN eMULE, DELIBERATELY, and this is the one place
                // it matters: eMule denies the whole update, but its incoming
                // contact carries the sender's key, so a peer refreshing itself
                // still passes. padMule records keys OUT OF BAND
                // (`note_verify_key`), so `add` NEVER carries one - denying
                // every update would also kill honest same-address refreshes.
                // Refusing only the ADDRESS CHANGE keeps the security property
                // (a third party cannot move a contact we have talked to) while
                // leaving refreshes working. Left un-refreshed too: an attacker
                // must not be able to forge a liveness signal either.
                if bin[pos].udp_key != 0
                    && contact.udp_key == 0
                    && (bin[pos].ip != contact.ip || bin[pos].udp_port != contact.udp_port)
                {
                    return;
                }
                // IN PLACE, and the POSITION is the load-bearing half. eMule's
                // found-contact branch returns without `PushToBottom`, which
                // lives only inside `SetAlive` (RoutingZone.cpp:519-597,
                // RoutingBin.cpp:136). Since the sweep probes the bin FRONT,
                // rotating on hearsay would let a contact that other nodes keep
                // naming dodge the probe forever - exactly the zombie this
                // feature exists to kill. padMule rotated here until 2026-08-08.
                let old = bin[pos].clone();
                let mut contact = contact;
                // The verified bit is monotonic ONLY while the IP is unchanged
                // (eMule Contact.cpp:175-178 clears IsIpVerified on ANY ip change).
                // A verified (id, ip) proves nothing at a DIFFERENT ip, and a
                // KadID is semi-public - so an attacker must not inherit the bit by
                // re-pointing a known verified id to their own ip. Same ip = a
                // genuine refresh, keep the bit.
                if old.ip == contact.ip {
                    contact.verified |= old.verified;
                    // Keep the peer's stored verify key on a refresh that carries
                    // none (a RES-payload refresh has no key; a direct-response
                    // refresh brings a fresh one, which wins). Dropped on an IP
                    // change, like the verified bit - a new IP re-learns its key.
                    if contact.udp_key == 0 {
                        contact.udp_key = old.udp_key;
                        contact.udp_key_ip = old.udp_key_ip;
                    }
                }
                // Aging survives a same-address refresh and RESETS on a move:
                // a new address is a new lease, exactly as the verified bit is
                // already dropped above.
                if old.ip == contact.ip {
                    contact.kad_type = old.kad_type;
                    contact.expires = old.expires;
                    contact.last_type_set = old.last_type_set;
                }
                bin[pos] = contact;
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

    /// eMule `CRoutingBin::SetAlive` (RoutingBin.cpp:125-138): `UpdateType`
    /// plus `PushToBottom`. Returns true if the contact was found here.
    fn set_alive(&mut self, id: &Kad128, now: u64) -> bool {
        match &mut self.node {
            Node::Leaf(bin) => {
                let Some(pos) = bin.iter().position(|c| c.id == *id) else {
                    return false;
                };
                let mut c = bin.remove(pos);
                // Only `UpdateType`'s hour-0 arm. The 1h/1.5h/2h ladder needs a
                // creation clock and every rung outlasts a padMule foreground
                // session, so the branch that picks among them cannot be
                // observed here - a documented, wire-neutral divergence.
                c.kad_type = KAD_TYPE_ALIVE;
                c.expires = Some(now + ALIVE_LEASE_SECS);
                c.last_type_set = now;
                bin.push(c); // PushToBottom: no longer the oldest
                true
            }
            Node::Internal(zero, one) => zero.set_alive(id, now) || one.set_alive(id, now),
        }
    }

    /// One `OnSmallTimer` pass over this subtree (eMule RoutingZone.cpp:860-905).
    /// Removal and stamping run for EVERY leaf; only probe EMISSION is capped,
    /// so a wide table cannot burst a HELLO at every bin at once (eMule gets
    /// that stagger free from its per-zone timers, RoutingZone.cpp:124).
    fn sweep(&mut self, now: u64, max_probes: usize, out: &mut SweepOutcome) {
        match &mut self.node {
            Node::Leaf(bin) => {
                // 1. Remove the dead: probed, past expiry. No other type is ever
                //    removed by a sweep, however stale it looks.
                bin.retain(|c| {
                    let dead = c.kad_type == KAD_TYPE_PROBED && c.expires.is_some_and(|e| e <= now);
                    if dead {
                        out.removed.push(c.id);
                    }
                    !dead
                });
                // 2. Stamp the never-stamped, so the NEXT sweep can probe them.
                for c in bin.iter_mut().filter(|c| c.expires.is_none()) {
                    c.expires = Some(now);
                }
                // 3. Probe the oldest DUE contact - the bin front.
                if out.probes.len() >= max_probes || bin.is_empty() {
                    return;
                }
                let front = &bin[0];
                if front.expires.is_some_and(|e| e >= now) || front.kad_type == KAD_TYPE_PROBED {
                    // Not due, or already awaiting an answer: rotate it away so
                    // the next contact gets its turn (eMule PushToBottom).
                    let c = bin.remove(0);
                    bin.push(c);
                    return;
                }
                let c = &mut bin[0];
                if now.saturating_sub(c.last_type_set) < CHECKING_TYPE_MIN_GAP {
                    return; // eMule's 10s floor on re-stamping
                }
                c.last_type_set = now;
                c.expires = Some(now + PROBE_WINDOW_SECS);
                c.kad_type = c.kad_type.saturating_add(1);
                out.probes.push(c.clone());
            }
            Node::Internal(zero, one) => {
                zero.sweep(now, max_probes, out);
                one.sweep(now, max_probes, out);
            }
        }
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

    /// Find a contact by id for mutation. Full traversal (called rarely - once per
    /// reply to stash a verify key - so simplicity beats a distance descent).
    fn find_mut(&mut self, id: &Kad128) -> Option<&mut Contact> {
        match &mut self.node {
            Node::Leaf(bin) => bin.iter_mut().find(|c| c.id == *id),
            Node::Internal(zero, one) => zero.find_mut(id).or_else(|| one.find_mut(id)),
        }
    }
}

/// The Kad routing table, rooted at our own Kad ID.
pub struct RoutingTable {
    self_id: Kad128,
    root: Zone,
    /// Hand out only IP-VERIFIED contacts as lookup candidates, as eMule does
    /// unconditionally (`CRoutingBin::GetClosestTo`, RoutingBin.cpp:244). ON by
    /// default: an unverified contact has never proven it lives at the address
    /// we hold for it, so using it to steer a search is exactly the opening a
    /// spoofer wants. Bootstrap does not go through here (it dials the nodes.dat
    /// list directly) and every node that answers becomes verified, so the
    /// candidate pool fills as the session runs.
    enforce_verified: bool,
}

impl RoutingTable {
    /// A new, empty table for our node `self_id`.
    pub fn new(self_id: Kad128) -> Self {
        RoutingTable {
            self_id,
            root: Zone::leaf(0, 0),
            enforce_verified: true,
        }
    }

    /// Lift (or restore) the verified-only rule. Provided for a live diagnostic
    /// that needs to see the raw table; the shipped engine leaves it ON.
    pub fn set_enforce_verified(&mut self, on: bool) {
        self.enforce_verified = on;
    }

    /// Whether a lookup ANSWER naming `id` at `ip`:`udp_port` may be accepted,
    /// mirroring eMule's `CRoutingZone::IsAcceptableContact` (RoutingZone.cpp:
    /// 1014-1020): a contact we have already VERIFIED owns its id at its address,
    /// so the same id arriving at a different address is a hijack attempt and is
    /// refused. An unverified contact never proved anything, so it may be
    /// replaced freely.
    pub fn is_acceptable_answer(&self, id: &Kad128, ip: u32, udp_port: u16) -> bool {
        let mut all: Vec<&Contact> = Vec::new();
        self.root.collect(&mut all);
        match all.iter().find(|c| c.id == *id) {
            Some(known) if known.verified => known.ip == ip && known.udp_port == udp_port,
            _ => true,
        }
    }

    /// Add (or refresh) a contact. Ignores our own ID. The anti-sybil per-IP//24
    /// cap is enforced one layer up (kad_live::add_contact, a LIVE-layer concern -
    /// see the lookup.rs module note), so this stays a pure routing primitive.
    pub fn add(
        &mut self,
        id: Kad128,
        ip: u32,
        udp_port: u16,
        tcp_port: u16,
        version: u8,
        verified: bool,
    ) {
        // eMule runs its entire insert inside `if (uID != uMe && uVersion > 1)`
        // (RoutingZone.cpp:494), so BOTH conditions belong at this one gate
        // rather than at each caller. Kad1 contacts cannot speak the Kad2 wire
        // padMule sends, so every request to one is a wasted datagram - and
        // `closest_to` would pass it on to other nodes as a lead.
        if id == self.self_id || version <= 1 {
            return;
        }
        let c = Contact::new(
            &self.self_id,
            id,
            ip,
            udp_port,
            tcp_port,
            version,
            verified,
            0,
            0,
        );
        self.root.add(c);
    }

    /// Record the verify key `key` (minted against OUR IP `key_ip`) that the peer
    /// `id` at `ip` handed us, so we can echo it back and be verified. A no-op if
    /// the contact is absent or at a different IP (a key is IP-bound). Kept a
    /// separate call so `add`'s many callers stay untouched.
    /// A contact has PROVEN itself alive - it answered something we sent, or
    /// sent us a HELLO_REQ whose sender key matches the one we hold for it.
    /// eMule `SetAlive` (RoutingBin.cpp:125-138), reached from the `bUpdate =
    /// true` paths only: an inbound HELLO_REQ, a HELLO_RES to a request of ours
    /// (which includes the sweep's own probe), and the BOOTSTRAP_RES responder.
    /// NOT from find/value answers - eMule adds those with `bUpdate = false`
    /// (KademliaUDPListener.cpp:846, signature RoutingZone.cpp:492), so hearsay
    /// never refreshes a lease.
    pub fn set_alive(&mut self, id: &Kad128, now: u64) -> bool {
        self.root.set_alive(id, now)
    }

    /// One `OnSmallTimer` pass: remove contacts that failed their probe, stamp
    /// the never-stamped, and hand back up to `max_probes` contacts to send a
    /// HELLO_REQ to. PURE - the caller does the I/O and calls
    /// [`set_alive`](RoutingTable::set_alive) on whoever answers.
    ///
    /// A contact walks eMule's exact death march: stamped by one sweep, probed
    /// by the next (type -> 4, two minutes to answer), removed by the first
    /// sweep past that. A nodes.dat seed starts at type 3, so a dead one is
    /// gone ~3-4 minutes into a session.
    ///
    /// NO `InUse` REFCOUNT, deliberately. eMule needs one (Search.cpp:183 takes
    /// seeds `bInUse = true`, released in `~CSearch` :148-150) because
    /// `OnSmallTimer` `delete`s a `CContact*` a running search still points at.
    /// padMule's lookups CLONE contacts out of the table, so a removal mid
    /// lookup dangles nothing - the refcount would have no referent.
    pub fn sweep(&mut self, now: u64, max_probes: usize) -> SweepOutcome {
        let mut out = SweepOutcome::default();
        self.root.sweep(now, max_probes, &mut out);
        out
    }

    pub fn note_verify_key(&mut self, id: &Kad128, ip: u32, key: u32, key_ip: u32) {
        if let Some(c) = self.root.find_mut(id) {
            if c.ip == ip {
                c.udp_key = key;
                c.udp_key_ip = key_ip;
            }
        }
    }

    /// The verify key to ECHO to contact `id` at `ip` so it can verify US - the
    /// key it handed us, but ONLY while it was minted against our CURRENT public IP
    /// (`our_ip`), since the key is `udp_verify_key(peer_secret, our_ip)` and a
    /// changed IP makes it stale. Returns 0 (send no key - first-contact-safe) if
    /// the contact is absent, at a different IP, keyless, or IP-mismatched. This is
    /// the entire send-side gate (eMule `CKadUDPKey::GetKeyValue`).
    pub fn verify_key_for(&self, id: &Kad128, ip: u32, our_ip: u32) -> u32 {
        let mut all: Vec<&Contact> = Vec::new();
        self.root.collect(&mut all);
        all.iter()
            .find(|c| c.id == *id && c.ip == ip)
            .filter(|c| c.udp_key != 0 && c.udp_key_ip == our_ip && our_ip != 0)
            .map(|c| c.udp_key)
            .unwrap_or(0)
    }

    /// True if a contact with this id is already in the table.
    pub fn contains(&self, id: &Kad128) -> bool {
        let mut all: Vec<&Contact> = Vec::new();
        self.root.collect(&mut all);
        all.iter().any(|c| c.id == *id)
    }

    /// The IP currently stored for `id`, if the table holds it. Lets the live
    /// layer tell a genuine refresh (same id, same IP) from an id being re-pointed
    /// to a new IP (a hijack attempt that must face the anti-sybil cap).
    pub fn ip_of(&self, id: &Kad128) -> Option<u32> {
        let mut all: Vec<&Contact> = Vec::new();
        self.root.collect(&mut all);
        all.iter().find(|c| c.id == *id).map(|c| c.ip)
    }

    /// Mark the contact with `id` IP-VERIFIED, but ONLY if the address we have
    /// stored for it matches `ip`. Returns whether it was verified.
    ///
    /// eMule's `CRoutingZone::VerifyContact` (RoutingZone.cpp:980-996): a miss
    /// returns false (:982-984), a stored-IP MISMATCH returns false without
    /// touching anything (:985-986), and only an exact match sets the bit
    /// (:991). The mismatch rule is the whole security value - a KadID is
    /// semi-public, so without it anyone could complete the handshake from any
    /// address and have somebody else's contact marked verified.
    ///
    /// Idempotent: re-verifying an already-verified contact is a no-op that
    /// still returns true, exactly as there.
    pub fn verify_contact(&mut self, id: &Kad128, ip: u32) -> bool {
        match self.root.find_mut(id) {
            Some(c) if c.ip == ip => {
                c.verified = true;
                true
            }
            _ => false,
        }
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
            self.add(c.id, c.ip, c.udp_port, c.tcp_port, c.version, c.verified);
            if c.udp_key != 0 {
                self.note_verify_key(&c.id, c.ip, c.udp_key, c.udp_key_ip);
            }
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
        if self.enforce_verified {
            all.retain(|c| c.verified);
        }
        // A contact awaiting a probe answer is one we already doubt: eMule
        // seeds a search from `GetClosestTo(3, ...)` (Search.cpp:183), and the
        // bin filter is `GetType() <= uMaxType` (RoutingBin.cpp:244), so type 4
        // is excluded from lookups. This is the half of the feature that pays
        // off immediately - a dying contact stops being handed out as a seed a
        // full probe window before it is removed.
        //
        // NOT narrowed to eMule's SERVE rule (`GetClosestTo(2, ...)`,
        // KademliaUDPListener.cpp:738) here: that changes what padMule TELLS
        // other nodes and wants the amuled A/B oracle first. Recorded in the
        // handoff as the remaining half.
        all.retain(|c| c.kad_type < KAD_TYPE_PROBED);
        all.sort_by_key(|c| target.distance(&c.id));
        all.into_iter().take(count).cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// eMule's VerifyContact rule, which is the whole point of the three-way
    /// HELLO handshake: the bit is set only when the address we already have
    /// for that ID matches the address the ACK arrived from. A KadID is
    /// semi-public, so without the mismatch check anyone could complete the
    /// handshake from any address and have someone else's contact verified.
    #[test]
    fn verify_contact_sets_the_bit_only_on_an_exact_ip_match() {
        let mut t = RoutingTable::new(Kad128::from_hash(&[0x01; 16]));
        let id = Kad128::from_hash(&[0x22; 16]);
        t.add(id, 0x0A00_0001, 4672, 4662, 8, false);

        assert!(
            !t.verify_contact(&id, 0x0A00_0002),
            "a DIFFERENT ip must not verify - that is the hijack this blocks"
        );
        assert!(
            !t.contacts().iter().any(|c| c.id == id && c.verified),
            "the mismatch must not have set the bit as a side effect"
        );

        let unknown = Kad128::from_hash(&[0x33; 16]);
        assert!(!t.verify_contact(&unknown, 0x0A00_0001), "a miss is false");

        assert!(t.verify_contact(&id, 0x0A00_0001), "the exact ip verifies");
        assert!(t.contacts().iter().any(|c| c.id == id && c.verified));
        assert!(
            t.verify_contact(&id, 0x0A00_0001),
            "idempotent: re-verifying is a no-op that still returns true"
        );
    }
    use mule_files::read_nodes_dat;

    const NODES: &[u8] = include_bytes!("../../mule-files/tests/fixtures/nodes.dat");

    fn id(seed: u8) -> Kad128 {
        Kad128::from_hash(&[seed; 16])
    }

    #[test]
    fn closest_to_hands_out_only_ip_verified_contacts() {
        // Wave-10 Batch B, the enforcement eMule applies unconditionally:
        // CRoutingBin::GetClosestTo returns a contact only when
        // `IsIpVerified()` (RoutingBin.cpp:244). An unverified contact has not
        // proven it actually lives at the IP we hold, so handing it out as a
        // lookup candidate is what lets a spoofer steer our searches.
        let mut rt = RoutingTable::new(id(0));
        rt.add(id(1), 0x0101_0101, 1, 2, 8, /*verified=*/ true);
        rt.add(id(2), 0x0202_0202, 1, 2, 8, /*verified=*/ false);
        let got = rt.closest_to(&id(3), 10);
        assert_eq!(got.len(), 1, "the unverified contact is withheld");
        assert_eq!(got[0].id, id(1));
        assert!(got.iter().all(|c| c.verified));

        // It is a FILTER, not a reordering: with nothing verified there are no
        // candidates at all, and a lookup correctly reports NotReady rather than
        // querying peers that never proved their address. (Bootstrap is
        // unaffected - it dials the nodes.dat list directly, not closest_to -
        // and each node that answers becomes verified, so the pool grows.)
        let mut fresh = RoutingTable::new(id(0));
        fresh.add(id(9), 0x0909_0909, 1, 2, 8, false);
        assert!(fresh.closest_to(&id(3), 10).is_empty());
    }

    #[test]
    fn the_verified_gate_can_be_lifted_for_diagnostics() {
        // An escape hatch for a live diagnostic (e.g. proving a routing table
        // loaded correctly before anything has answered). OFF by default, so the
        // shipped engine always enforces.
        let mut rt = RoutingTable::new(id(0));
        rt.add(id(1), 0x0101_0101, 1, 2, 8, false);
        assert!(rt.closest_to(&id(3), 10).is_empty());
        rt.set_enforce_verified(false);
        assert_eq!(rt.closest_to(&id(3), 10).len(), 1);
    }

    #[test]
    fn a_verified_contact_is_not_hijacked_to_a_new_address() {
        // eMule's IsAcceptableContact (RoutingZone.cpp:1014-1020): once a
        // contact is VERIFIED, an answer naming that same KadID at a DIFFERENT
        // ip/port is refused outright - a KadID is semi-public, so this is the
        // move an attacker makes to take over a known node's identity.
        let mut rt = RoutingTable::new(id(0));
        rt.add(id(1), 0x0101_0101, 4672, 4662, 8, true);
        assert!(!rt.is_acceptable_answer(&id(1), 0x0505_0505, 4672));
        // Same address is fine (an ordinary refresh), as is an unknown id.
        assert!(rt.is_acceptable_answer(&id(1), 0x0101_0101, 4672));
        assert!(rt.is_acceptable_answer(&id(7), 0x0707_0707, 4672));
        // An UNVERIFIED contact never proved its address, so it has no claim on
        // the id: a different address is allowed to replace it.
        rt.add(id(2), 0x0202_0202, 4672, 4662, 8, false);
        assert!(rt.is_acceptable_answer(&id(2), 0x0606_0606, 4672));
    }

    /// THE TABLE needs its own anti-hijack rule, not just the search does.
    ///
    /// `is_acceptable_answer` (tested above) protects the SEARCH FRONTIER, and
    /// that split is faithful - eMule feeds the table through `AddUnfiltered`
    /// and applies `IsAcceptableContact` only to what the search sees
    /// (KademliaUDPListener.cpp:848, `if (bWasAdded || IsAcceptableContact)`).
    /// But eMule's table path carries its OWN protection that padMule had lost:
    /// a contact holding a sender key may only be updated by a packet carrying
    /// the SAME key, and an EMPTY key explicitly fails the test - eMule logs
    /// "failed to provide the proper sender key (Sent Empty: Yes) ... denying
    /// update" (RoutingZone.cpp:525-533). A contact named inside a third
    /// party's KADEMLIA2_RES payload carries no key at all, so that is exactly
    /// the packet the rule refuses.
    ///
    /// Without it, one hostile answer naming a known KadID at an attacker IP
    /// re-points the contact and drops its verified bit - and since
    /// `closest_to` is verified-only, repeating that drains the seed pool every
    /// future lookup starts from.
    #[test]
    fn a_keyed_contact_cannot_be_repointed_by_a_keyless_answer() {
        let mut rt = RoutingTable::new(id(0));
        let our_ip = 0x0A00_0001;
        rt.add(id(1), 0x0101_0101, 4672, 4662, 8, true);
        // We have CORRESPONDED with this contact: it handed us a sender key.
        rt.note_verify_key(&id(1), 0x0101_0101, 0xDEAD_BEEF, our_ip);

        // The hijack: a third party's answer names id(1) at ITS address. Adds
        // from a RES payload never carry a key (see `RoutingTable::add`).
        rt.add(id(1), 0x0505_0505, 4672, 4662, 8, false);

        assert_eq!(
            rt.ip_of(&id(1)),
            Some(0x0101_0101),
            "a keyed contact must keep its address against a keyless re-point"
        );
        assert_eq!(
            rt.verify_key_for(&id(1), 0x0101_0101, our_ip),
            0xDEAD_BEEF,
            "and must keep the key that makes it echo-able"
        );
        assert!(
            rt.is_acceptable_answer(&id(1), 0x0101_0101, 4672),
            "the contact is still verified at its real address"
        );
    }

    /// The rule above must not break the ordinary case: a contact we hold a key
    /// for still refreshes at its OWN address, and an UNKEYED contact (one we
    /// have only ever heard about second-hand) is still free to move, because
    /// we hold no evidence tying it to an address.
    #[test]
    fn the_repoint_refusal_is_narrow_refresh_and_unkeyed_moves_still_work() {
        let mut rt = RoutingTable::new(id(0));
        let our_ip = 0x0A00_0001;

        rt.add(id(1), 0x0101_0101, 4672, 4662, 8, true);
        rt.note_verify_key(&id(1), 0x0101_0101, 0xDEAD_BEEF, our_ip);
        // Same address = a genuine refresh, still accepted.
        rt.add(id(1), 0x0101_0101, 4672, 4662, 8, false);
        assert_eq!(rt.ip_of(&id(1)), Some(0x0101_0101));
        assert_eq!(
            rt.verify_key_for(&id(1), 0x0101_0101, our_ip),
            0xDEAD_BEEF,
            "a refresh keeps the key"
        );

        // A contact with NO stored key has proved nothing, so it may move -
        // this is what stops the rule freezing a table full of hearsay.
        rt.add(id(2), 0x0202_0202, 4672, 4662, 8, false);
        rt.add(id(2), 0x0606_0606, 4672, 4662, 8, false);
        assert_eq!(
            rt.ip_of(&id(2)),
            Some(0x0606_0606),
            "an unkeyed contact still moves"
        );
    }

    /// KAD1 CONTACTS NEVER ENTER THE TABLE. eMule gates this at the single
    /// insert point - `AddUnfiltered` runs its whole body inside
    /// `if (uID != uMe && uVersion > 1)` (RoutingZone.cpp:494) - so a Kad1
    /// contact is refused no matter which path offered it. padMule gated it
    /// only where contacts came off DISK (`read_nodes_dat`) and in
    /// `CSearch::add` for the FRONTIER, so a peer's answer could still put a
    /// v0/v1 contact in the live table: the same frontier-guarded/table-open
    /// asymmetry as the re-point above, one layer down.
    ///
    /// It matters because a Kad1 contact cannot speak the Kad2 wire we send -
    /// every request addressed to it is a datagram spent on a peer that will
    /// never answer, and `closest_to` would hand it out to others as a lead.
    #[test]
    fn a_kad1_contact_is_refused_by_the_table_whatever_offered_it() {
        let mut rt = RoutingTable::new(id(0));
        rt.add(id(1), 0x0101_0101, 4672, 4662, 1, false);
        rt.add(id(2), 0x0202_0202, 4672, 4662, 0, false);
        assert_eq!(rt.len(), 0, "version 0 and 1 are Kad1 - never routable");

        // The same gate must hold for contacts arriving from nodes.dat, which
        // is a separate public entry point onto the same table.
        rt.load_nodes(&[KadContact {
            id: id(3),
            ip: 0x0303_0303,
            udp_port: 4672,
            tcp_port: 4662,
            version: 1,
            verified: false,
            udp_key: 0,
            udp_key_ip: 0,
        }]);
        assert_eq!(rt.len(), 0, "a Kad1 contact from disk is refused too");

        // Kad2 and later are accepted, as they must be.
        rt.add(id(4), 0x0404_0404, 4672, 4662, 2, false);
        assert_eq!(rt.len(), 1, "version 2 is Kad2 - accepted");
    }

    #[test]
    fn adds_and_counts_contacts() {
        let mut rt = RoutingTable::new(id(0));
        rt.add(id(1), 0x0101_0101, 1, 2, 8, false);
        rt.add(id(2), 0x0202_0202, 3, 4, 8, false);
        assert_eq!(rt.len(), 2);
        // Re-adding the same id refreshes, does not duplicate.
        rt.add(id(1), 0x0101_0101, 1, 2, 8, false);
        assert_eq!(rt.len(), 2);
    }

    fn find(rt: &RoutingTable, want: Kad128) -> Contact {
        rt.contacts().into_iter().find(|c| c.id == want).unwrap()
    }

    #[test]
    fn a_peers_verify_key_is_stored_ip_bound_and_kept_across_a_refresh() {
        let mut rt = RoutingTable::new(id(0));
        rt.add(id(1), 0x0101_0101, 1, 2, 8, false);
        // The key the peer handed us (minted against OUR IP 0x0A00_0001) is stored.
        rt.note_verify_key(&id(1), 0x0101_0101, 0xDEAD_BEEF, 0x0A00_0001);
        let c = find(&rt, id(1));
        assert_eq!(c.udp_key, 0xDEAD_BEEF);
        assert_eq!(c.udp_key_ip, 0x0A00_0001);
        // A keyless refresh (a RES-payload sighting) keeps the stored key.
        rt.add(id(1), 0x0101_0101, 1, 2, 8, false);
        assert_eq!(
            find(&rt, id(1)).udp_key,
            0xDEAD_BEEF,
            "refresh keeps the key"
        );
        // note_verify_key at a DIFFERENT ip is a no-op (a key is IP-bound).
        rt.note_verify_key(&id(1), 0x0202_0202, 0x1234, 0x0A00_0001);
        assert_eq!(
            find(&rt, id(1)).udp_key,
            0xDEAD_BEEF,
            "wrong-ip key ignored"
        );
    }

    #[test]
    fn verified_flag_is_sticky_matching_emule() {
        // eMule RoutingZone.cpp:585-587: an existing contact's verified bit is
        // monotonic - it can be promoted false->true but never regresses to false.
        let mut rt = RoutingTable::new(id(0));
        rt.add(id(1), 0x0101_0101, 1, 2, 8, false);
        assert!(!find(&rt, id(1)).verified, "starts unverified");
        rt.add(id(1), 0x0101_0101, 1, 2, 8, true);
        assert!(find(&rt, id(1)).verified, "promoted to verified");
        rt.add(id(1), 0x0101_0101, 1, 2, 8, false);
        assert!(find(&rt, id(1)).verified, "stays verified (sticky)");
    }

    #[test]
    fn verified_clears_when_a_known_id_moves_to_a_new_ip() {
        // A semi-public KadID must not carry its verified bit to a DIFFERENT IP
        // (eMule Contact.cpp:175-178 clears IsIpVerified on any ip change), or an
        // attacker could inherit trust by re-pointing a known id to their own IP.
        let mut rt = RoutingTable::new(id(0));
        rt.add(id(1), 0x0101_0101, 1, 2, 8, true);
        assert!(find(&rt, id(1)).verified);
        // Same id at a NEW ip (hijack shape) -> verified cleared.
        rt.add(id(1), 0x0202_0202, 1, 2, 8, false);
        let c = find(&rt, id(1));
        assert_eq!(c.ip, 0x0202_0202);
        assert!(!c.verified, "verified dropped on the ip change");
        // A genuine refresh (same id, SAME ip) still keeps it.
        rt.add(id(1), 0x0202_0202, 1, 2, 8, true);
        assert!(find(&rt, id(1)).verified);
    }

    #[test]
    fn verified_flag_survives_a_split() {
        // A contact keeps its verified bit when its full bin splits.
        let mut rt = RoutingTable::new(id(0));
        for i in 1..=12u8 {
            rt.add(id(i), i as u32, 1, 2, 8, i == 5);
        }
        assert!(
            find(&rt, id(5)).verified,
            "the verified one survived the split"
        );
    }

    #[test]
    fn ignores_our_own_id() {
        let mut rt = RoutingTable::new(id(7));
        rt.add(id(7), 0, 0, 0, 8, false);
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
        // Verified, because closest_to hands out only IP-verified contacts (the
        // Batch-B gate); this test is about XOR ordering, not verification.
        let ids: Vec<Kad128> = (1..=15u8).map(id).collect();
        for (i, cid) in ids.iter().enumerate() {
            rt.add(*cid, i as u32, 1, 2, 8, true);
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
            rt.add(Kad128::from_words(w), i, 1, 2, 8, false);
        }
        // The table holds contacts but far fewer than 50 (far bins capped at K per
        // leaf, limited leaves because far zones stop splitting).
        let n = rt.len();
        assert!(n > 0 && n <= 50);
    }

    /// Find a contact by id, for the aging tests.
    fn find_c(t: &RoutingTable, want: Kad128) -> Contact {
        t.contacts()
            .into_iter()
            .find(|c| c.id == want)
            .expect("contact present")
    }

    /// eMule `CRoutingBin::SetAlive` (RoutingBin.cpp:125-138) is `UpdateType`
    /// plus `PushToBottom`: a contact that has just PROVEN itself alive gets a
    /// fresh lease and goes to the back of its bin, so the sweep's "oldest"
    /// (the front) keeps naming the least-recently-proven contact.
    #[test]
    fn set_alive_marks_a_contact_proven_and_moves_it_to_the_back_of_its_bin() {
        let mut t = RoutingTable::new(id(0));
        t.add(id(1), 0x0101_0101, 4672, 4662, 8, true);
        t.add(id(2), 0x0202_0202, 4672, 4662, 8, true);

        t.set_alive(&id(1), 500);

        let c = find_c(&t, id(1));
        assert_eq!(c.kad_type, KAD_TYPE_ALIVE, "UpdateType hour-0 arm");
        assert_eq!(c.expires, Some(500 + ALIVE_LEASE_SECS));
        assert_eq!(
            t.contacts().last().unwrap().id,
            id(1),
            "PushToBottom: the freshly-proven contact is no longer the oldest"
        );
    }

    /// A HEARSAY add - a contact named inside a third party's answer - must
    /// touch NEITHER aging NOR bin position. eMule's found-contact branch
    /// returns without `SetAlive`, and `PushToBottom` lives only inside
    /// `SetAlive` (RoutingZone.cpp:519-597, RoutingBin.cpp:136); its
    /// KADEMLIA2_RES handler passes `bUpdate = false`
    /// (KademliaUDPListener.cpp:846, signature RoutingZone.cpp:492).
    /// POSITION is the load-bearing half: the sweep probes the FRONT, so a
    /// zombie that gets named often would rotate to the back and dodge the
    /// probe forever - exactly the contact this feature exists to kill.
    #[test]
    fn a_hearsay_refresh_touches_neither_aging_nor_position() {
        let mut t = RoutingTable::new(id(0));
        t.add(id(1), 0x0101_0101, 4672, 4662, 8, true);
        t.add(id(2), 0x0202_0202, 4672, 4662, 8, true);
        t.add(id(3), 0x0303_0303, 4672, 4662, 8, true);
        // Prove id2 then id1, leaving id2 in the MIDDLE: [id3, id2, id1]. The
        // hearsay target must not already be at the back, or a rotation is a
        // no-op and this test cannot see it - the first version of this test
        // had exactly that hole and a rotate mutant survived it.
        t.set_alive(&id(2), 100);
        t.set_alive(&id(1), 100);
        assert_eq!(
            t.contacts().iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![id(3), id(2), id(1)],
            "precondition: the hearsay target sits in the middle"
        );

        t.add(id(2), 0x0202_0202, 4672, 4662, 8, true); // hearsay, same address

        let order: Vec<Kad128> = t.contacts().iter().map(|c| c.id).collect();
        assert_eq!(
            order,
            vec![id(3), id(2), id(1)],
            "hearsay must not rotate a contact out of the probe queue"
        );
        assert_eq!(
            find_c(&t, id(2)).kad_type,
            KAD_TYPE_ALIVE,
            "aging untouched"
        );
        assert_eq!(find_c(&t, id(2)).expires, Some(100 + ALIVE_LEASE_SECS));
    }

    /// A new address is a new lease: aging resets exactly as the verified bit
    /// already does, so a peer that moved must re-prove itself.
    #[test]
    fn an_ip_change_resets_aging_like_it_already_resets_verification() {
        let mut t = RoutingTable::new(id(0));
        t.add(id(2), 0x0202_0202, 4672, 4662, 8, false);
        t.set_alive(&id(2), 100);

        t.add(id(2), 0x0606_0606, 4672, 4662, 8, false);

        let c = find_c(&t, id(2));
        assert_eq!(
            (c.kad_type, c.expires),
            (KAD_TYPE_NEW, None),
            "a new address re-proves from scratch"
        );
    }

    /// THE DEATH MARCH, at eMule's own clocks (`OnSmallTimer`,
    /// RoutingZone.cpp:860-905; `CheckingType` +2min, Contact.cpp:216-226):
    /// sweep 1 only STAMPS `expires`, sweep 2 probes (type 3 -> 4), and the
    /// first sweep past that expiry removes. A contact loaded from nodes.dat
    /// starts at type 3, so a dead seed dies about 3-4 minutes into a session -
    /// which is what makes this observable at all in a foreground-only client.
    #[test]
    fn a_silent_contact_walks_emules_exact_death_march() {
        let mut t = RoutingTable::new(id(0));
        t.add(id(1), 0x0101_0101, 4672, 4662, 8, true);

        assert!(
            t.sweep(100, 8).probes.is_empty(),
            "sweep 1 stamps expires, it never probes"
        );
        let s = t.sweep(160, 8);
        assert_eq!(
            s.probes.iter().map(|c| c.id).collect::<Vec<_>>(),
            vec![id(1)],
            "sweep 2 probes the oldest due contact"
        );
        assert_eq!(find_c(&t, id(1)).kad_type, KAD_TYPE_PROBED);
        assert_eq!(find_c(&t, id(1)).expires, Some(160 + PROBE_WINDOW_SECS));

        assert!(
            t.sweep(220, 8).removed.is_empty(),
            "still inside the 2-minute probe window"
        );
        assert_eq!(t.sweep(340, 8).removed, vec![id(1)], "past expiry: removed");
        assert_eq!(t.len(), 0);
    }

    /// The probe is a QUESTION, not a sentence: an answer cancels the march.
    #[test]
    fn an_answered_probe_cancels_the_death_march() {
        let mut t = RoutingTable::new(id(0));
        t.add(id(1), 0x0101_0101, 4672, 4662, 8, true);
        t.sweep(100, 8);
        t.sweep(160, 8); // probed: type 4
        t.set_alive(&id(1), 170); // the HELLO_RES arrived

        let s = t.sweep(340, 8);
        assert!(s.removed.is_empty(), "an alive contact is never removed");
        assert!(s.probes.is_empty(), "and it is not due again for an hour");
        assert_eq!(find_c(&t, id(1)).kad_type, KAD_TYPE_ALIVE);
    }

    /// Only a type-4 contact past its expiry is removed. A contact with a stale
    /// lease that has NOT been probed yet must be PROBED, never removed - eMule
    /// guards removal on `GetType() == 4` (RoutingZone.cpp:868-885).
    #[test]
    fn an_unprobed_contact_is_never_removed_however_stale() {
        let mut t = RoutingTable::new(id(0));
        t.add(id(1), 0x0101_0101, 4672, 4662, 8, true);
        t.set_alive(&id(1), 0); // type 2, lease to 3600

        let s = t.sweep(9_999, 8);
        assert!(s.removed.is_empty(), "type 2 is never removed by a sweep");
        assert_eq!(s.probes.len(), 1, "it is asked, not executed");
        assert_eq!(t.len(), 1);
    }

    /// THE BLACKHOLE HALF, and the reason this feature is urgent. The per-IP
    /// cap is computed from live table CONTENTS, so an immortal contact holds
    /// its address against every other Kad ID forever. Removal must free it.
    #[test]
    fn removal_frees_the_per_ip_and_subnet_slots() {
        let mut t = RoutingTable::new(id(0));
        t.add(id(1), 0x0101_0101, 4672, 4662, 8, true);
        assert_eq!(t.ip_counts(0x0101_0101), (1, 1));

        t.sweep(100, 8);
        t.sweep(160, 8);
        t.sweep(340, 8);

        assert_eq!(
            t.ip_counts(0x0101_0101),
            (0, 0),
            "the evicted contact no longer holds its address"
        );
    }

    /// eMule staggers probe traffic with a per-zone timer (RoutingZone.cpp:124).
    /// padMule sweeps the whole tree in one pass, so the cap is what stops a
    /// first sweep over a wide table bursting a HELLO at every bin at once.
    #[test]
    fn probe_emission_is_capped_and_never_re_asks_an_in_flight_contact() {
        let mut t = RoutingTable::new(id(0));
        // Near-self ids so the tree splits into several leaf bins.
        for i in 1..=24u8 {
            let mut raw = [0u8; 16];
            raw[0] = i;
            t.add(
                Kad128::from_hash(&raw),
                0x0100_0000 + i as u32,
                4672,
                4662,
                8,
                true,
            );
        }
        t.sweep(100, 64); // stamp everything; nothing is due yet

        let first = t.sweep(200, 2);
        assert_eq!(first.probes.len(), 2, "the cap is honoured");

        // The SAME instant again: a bin already probed must stay silent (its
        // front is type 4 and gets rotated away, not re-asked), and the pass
        // must move on to a bin that has not been probed. Asserting "no
        // overlap" rather than a second exact count, because how many leaf bins
        // this id set produces is an implementation detail of the split rule -
        // pinning that number would make this a test of the tree shape.
        let second = t.sweep(200, 2);
        assert!(
            !second.probes.is_empty(),
            "the pass moves on to another bin"
        );
        for c in &second.probes {
            assert!(
                !first.probes.iter().any(|p| p.id == c.id),
                "an in-flight probe must never be re-sent in the same window"
            );
            assert_eq!(c.kad_type, KAD_TYPE_PROBED);
        }
    }

    /// A contact we are already doubting must not be handed to a lookup as a
    /// seed. eMule filters search seeds at `GetType() <= 3`
    /// (Search.cpp:183 -> RoutingBin.cpp:244), which excludes exactly the
    /// probed-and-unanswered type 4.
    #[test]
    fn a_contact_awaiting_its_probe_answer_is_not_handed_to_a_lookup() {
        let mut t = RoutingTable::new(id(0));
        t.add(id(1), 0x0101_0101, 4672, 4662, 8, true);
        assert_eq!(t.closest_to(&id(9), 10).len(), 1, "seeded while healthy");

        t.sweep(100, 8);
        t.sweep(160, 8); // probed: type 4

        assert!(
            t.closest_to(&id(9), 10).is_empty(),
            "a dying contact is withheld from lookups a probe window before it dies"
        );
        t.set_alive(&id(1), 170);
        assert_eq!(t.closest_to(&id(9), 10).len(), 1, "answering restores it");
    }

    /// REGRESSION GUARD, and it pins FAITHFULNESS rather than a padMule choice.
    /// eMule does NOT probe-the-oldest when a bin fills: `CRoutingZone::Add`'s
    /// unsplittable-full branch is `bUpdate = false; return false`
    /// (RoutingZone.cpp:617-620) and `CRoutingBin::AddContact` returns false
    /// without probing anything (RoutingBin.cpp:116-122); aMule 3.0.1 is
    /// identical (RoutingZone.cpp:503-514). The oldest contact is challenged
    /// ONLY by the timer. This test exists because the classic Kademlia paper
    /// says otherwise and padMule's own hazard list called this a defect until
    /// 2026-08-08 - do not "fix" it toward the paper.
    #[test]
    fn a_full_unsplittable_bin_still_drops_the_newcomer() {
        let mut t = RoutingTable::new(id(0));
        for i in 1..=(K as u8 + 4) {
            let mut raw = [0xF0; 16];
            raw[15] = i;
            t.add(
                Kad128::from_hash(&raw),
                0x0A00_0000 + i as u32,
                4672,
                4662,
                8,
                true,
            );
        }
        let before = t.len();
        let mut raw = [0xF0; 16];
        raw[15] = 0xEE;
        let newcomer = Kad128::from_hash(&raw);
        t.add(newcomer, 0x0A00_00EE, 4672, 4662, 8, true);

        assert_eq!(t.len(), before, "the table did not grow");
        assert!(
            !t.contacts().iter().any(|c| c.id == newcomer),
            "the ARRIVING contact is the one dropped, exactly as eMule does"
        );
    }
}
