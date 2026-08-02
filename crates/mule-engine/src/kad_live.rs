//! Live Kad UDP node - the socket driver that turns the Wave 6a/6b/6c codecs
//! into a real conversation with the Kad network (Wave 6 gate). Sends an
//! obfuscated BOOTSTRAP_REQ to known contacts, decodes the BOOTSTRAP_RES, and
//! seeds the routing table; then a HELLO handshake and, later, iterative
//! lookups.
//!
//! IP byte convention (confirmed by live capture, Wave 6b gate): eMule keeps a
//! contact IP in HOST order (MSByte = first octet) and `WriteUInt32`s it
//! little-endian to disk/wire, so our `read_u32` (LE) recovers that host-order
//! value directly - e.g. 95.236.36.250 -> 0x5FEC24FA. The dotted quad is thus
//! the BIG-endian view of `ip` (`Ipv4Addr::from(ip)`), NOT `to_le_bytes` (which
//! yields the reversed 250.36.236.95, a multicast address the packet never
//! reaches). A peer's socket IP converts back with `u32::from(Ipv4Addr)`. The
//! same u32 feeds `udp_verify_key`, so the key we issue on send matches the one
//! we recompute on receive (same peer, same convention both directions).

use mule_files::{IpFilter, KadContact};
use mule_kad::{
    build_bootstrap_req, build_hello_req, build_kad2_req, build_search_key_req,
    build_search_source_req, is_acceptable_contact, kad_deobfuscate, kad_keyword_target,
    kad_obfuscate_request, pack_kad, parse_bootstrap_res, parse_hello, parse_kad2_res,
    parse_search_res, unpack_kad, BootstrapRes, FileResult, Hello, Lookup, RoutingTable, Source,
    WireContact, ALPHA_QUERY, K, KAD_FIND_NODE, OP_BOOTSTRAP_RES, OP_HELLO_RES, OP_KAD2_RES,
    OP_SEARCH_RES,
};
use mule_proto::Kad128;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Instant};

/// The contact count padMule requests in a KADEMLIA2_REQ (KAD_FIND_NODE = 0x0B).
/// A KADEMLIA2_RES with more than this is a malicious over-long answer and is
/// dropped (eMule caps the response at the requested count, Search.cpp:377).
const KAD_REQUESTED_CONTACTS: usize = 11;

/// A contact's host-order `ip` u32 to its socket address (big-endian view).
fn contact_addr(ip: u32, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
}

/// A peer's socket IP back to the host-order u32 used for keys/records.
fn ip_u32(addr: &SocketAddr) -> u32 {
    match addr {
        SocketAddr::V4(v4) => (*v4.ip()).into(),
        SocketAddr::V6(_) => 0,
    }
}

/// Errors from a live Kad exchange.
#[derive(Debug)]
pub enum KadError {
    Io(std::io::Error),
    Timeout,
    /// The datagram was plaintext or matched no key.
    NotDecryptable,
    /// The node has no routing contacts yet (bootstrap first).
    NotReady,
    /// A codec/parse error on the decrypted payload.
    Decode(mule_proto::IoError),
    /// A valid Kad frame but not the opcode we awaited.
    Unexpected(u8),
}

impl std::fmt::Display for KadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KadError::Io(e) => write!(f, "io: {e}"),
            KadError::Timeout => write!(f, "timed out"),
            KadError::NotDecryptable => {
                write!(f, "response not decryptable (plaintext or wrong key)")
            }
            KadError::NotReady => write!(f, "no Kad contacts yet (bootstrap first)"),
            KadError::Decode(e) => write!(f, "decode: {e}"),
            KadError::Unexpected(op) => write!(f, "unexpected opcode 0x{op:02x}"),
        }
    }
}

impl From<std::io::Error> for KadError {
    fn from(e: std::io::Error) -> Self {
        KadError::Io(e)
    }
}
impl From<mule_proto::IoError> for KadError {
    fn from(e: mule_proto::IoError) -> Self {
        KadError::Decode(e)
    }
}

/// A live Kad node: a bound UDP socket plus our identity and routing table.
pub struct KadNode {
    socket: UdpSocket,
    kad_id: Kad128,
    udp_key: u32,
    tcp_port: u16,
    udp_port: u16,
    routing: RoutingTable,
    /// The user IP blocklist (ipfilter.dat/.p2p), if loaded. eMule consults it on
    /// every Kad routing insert (RoutingZone.cpp:477); padMule threads the engine's
    /// filter in so a blocklisted range cannot poison the routing table.
    ip_filter: Option<std::sync::Arc<IpFilter>>,
}

impl KadNode {
    /// Bind a Kad node on `bind_addr` (e.g. `0.0.0.0:4672`) with a fresh random
    /// identity. `tcp_port` is advertised in HELLO. For one-shot CLI use; a
    /// long-lived client should pass its persisted identity via
    /// [`KadNode::bind_with_identity`] (eMule persists both values - a stable
    /// ID keeps routing-table reciprocity, and a stable install key keeps the
    /// UDP verify keys peers stored for us valid across restarts).
    pub async fn bind(bind_addr: SocketAddr, tcp_port: u16) -> Result<Self, KadError> {
        let kad_id = Kad128::from_words([
            rand::random(),
            rand::random(),
            rand::random(),
            rand::random(),
        ]);
        Self::bind_with_identity(bind_addr, tcp_port, kad_id, rand::random()).await
    }

    /// Bind a Kad node using a persisted identity (`NodeIdentity::kad_id` /
    /// `kad_udp_key`).
    pub async fn bind_with_identity(
        bind_addr: SocketAddr,
        tcp_port: u16,
        kad_id: Kad128,
        udp_key: u32,
    ) -> Result<Self, KadError> {
        let socket = UdpSocket::bind(bind_addr).await?;
        let udp_port = socket.local_addr()?.port();
        Ok(KadNode {
            socket,
            kad_id,
            udp_key,
            tcp_port,
            udp_port,
            routing: RoutingTable::new(kad_id),
            ip_filter: None,
        })
    }

    /// Install the user IP blocklist so blocklisted ranges are dropped from every
    /// routing insert (matching eMule). `None` = no filter (fail-open).
    pub fn set_ip_filter(&mut self, filter: Option<std::sync::Arc<IpFilter>>) {
        self.ip_filter = filter;
    }

    pub fn kad_id(&self) -> Kad128 {
        self.kad_id
    }
    pub fn routing(&self) -> &RoutingTable {
        &self.routing
    }
    pub fn contacts_known(&self) -> usize {
        self.routing.len()
    }

    /// Add a contact to the routing table only if its IP:port is a routable
    /// public address with a usable UDP port (eMule 0.70b hardening) - junk /
    /// unroutable / port-0 contacts never enter the table.
    fn add_contact(
        &mut self,
        id: Kad128,
        ip: u32,
        udp_port: u16,
        tcp_port: u16,
        version: u8,
        verified: bool,
    ) {
        if !is_acceptable_contact(ip, udp_port, /*allow_private=*/ false) {
            return;
        }
        // Drop a DNS-port contact from a LEGACY node (anti-reflection: a nodes.dat
        // naming `victim:53` would spray Kad requests at a DNS server). eMule gates
        // this on version <= KADEMLIA_VERSION5_48a (0x05), keeping modern nodes, so
        // match that exactly rather than a blanket reject (which is stricter than
        // eMule - it would drop a node eMule keeps).
        if udp_port == 53 && version <= 5 {
            return;
        }
        // The user blocklist gates Kad inserts exactly as it gates eD2k sources
        // (eMule RoutingZone.cpp:477): a range the user chose to block never enters
        // the routing table. Fail-open when no filter is loaded.
        if let Some(f) = &self.ip_filter {
            if f.is_blocked_u32(ip) {
                return;
            }
        }
        // Anti-sybil (live-layer): cap how many contacts share one IP / /24, so a
        // hostile node cannot flood our routing table with fake IDs behind one
        // address. Skip the cap ONLY for a genuine refresh (same id, SAME ip); a
        // known id arriving at a DIFFERENT ip is a hijack attempt (KadIDs are
        // semi-public) and faces the cap on the new ip like a new contact (Zone::add
        // also clears its verified bit on the ip change). Interop-safe: the real Kad
        // network is IP-diverse, so a legitimate peer is never dropped.
        let refresh = self.routing.ip_of(&id) == Some(ip);
        if ip != 0 && !refresh {
            let (same_ip, same_subnet) = self.routing.ip_counts(ip);
            if same_ip >= mule_kad::MAX_CONTACTS_PER_IP
                || same_subnet >= mule_kad::MAX_CONTACTS_PER_SUBNET
            {
                return;
            }
        }
        self.routing
            .add(id, ip, udp_port, tcp_port, version, verified);
    }

    /// Send an obfuscated Kad request (NodeID-keyed on `target_id`, our
    /// senderVerifyKey issued for `dest`) and wait for a decryptable reply with
    /// opcode `expect` FROM `dest`, ignoring interleaved/stray datagrams (other
    /// nodes' pings, a HELLO from the peer) until the deadline.
    /// Returns `(payload, valid_receiver_key)`. `valid_receiver_key` is eMule's
    /// `bValidReceiverKey`: the reply echoed back the verify key we issue for
    /// `dest` (`udp_verify_key(our_key, dest_ip)`), proving it came from a node
    /// that actually received our packet at that IP (anti-spoof). It NEVER causes
    /// a drop here - matching eMule, which only hard-drops HELLO_RES_ACK on an
    /// invalid receiver key; for every other opcode it just marks the contact
    /// unverified. The caller uses it to set the contact's `verified` bit.
    async fn request(
        &self,
        target_id: &Kad128,
        dest: SocketAddr,
        frame: &[u8],
        expect: u8,
        wait: Duration,
    ) -> Result<(Vec<u8>, bool), KadError> {
        let dest_ip = ip_u32(&dest);
        let sender_vk = mule_kad::udp_verify_key(self.udp_key, dest_ip);
        let datagram = kad_obfuscate_request(
            frame,
            target_id,
            rand::random(), // random key seed
            0,              // no receiver key on first contact
            sender_vk,      // want this echoed to prove our IP
            rand::random(), // marker randomness
        );
        self.socket.send_to(&datagram, dest).await?;

        let deadline = Instant::now() + wait;
        let mut buf = vec![0u8; 8192];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(KadError::Timeout);
            }
            let (n, from) = match timeout(remaining, self.socket.recv_from(&mut buf)).await {
                Ok(r) => r?,
                Err(_) => return Err(KadError::Timeout),
            };
            if ip_u32(&from) != dest_ip {
                continue; // unsolicited traffic from another node
            }
            let Some(dec) = kad_deobfuscate(&buf[..n], &self.kad_id, self.udp_key, dest_ip) else {
                continue; // plaintext or wrong key - not our reply
            };
            let Ok((op, payload)) = unpack_kad(&dec.payload) else {
                continue;
            };
            if op == expect {
                // bValidReceiverKey = GetUDPVerifyKey(senderIP) == packet receiver
                // key (eMule ClientUDPSocket.cpp:127). The value we issued as our
                // sender key is exactly udp_verify_key(our_key, dest_ip), so the
                // peer echoing it back means the key round-tripped.
                let valid_receiver_key = dec.receiver_vk == sender_vk;
                return Ok((payload, valid_receiver_key));
            }
            // A different opcode from the same peer (e.g. HELLO_REQ) - keep waiting.
        }
    }

    /// Send a BOOTSTRAP_REQ to one contact and parse its BOOTSTRAP_RES, seeding
    /// the routing table with the returned contacts (and the responder itself).
    pub async fn bootstrap_from(
        &mut self,
        contact: &KadContact,
        wait: Duration,
    ) -> Result<BootstrapRes, KadError> {
        let (op, payload) = build_bootstrap_req();
        let frame = pack_kad(op, payload);
        let dest = contact_addr(contact.ip, contact.udp_port);
        let (res_payload, verified) = self
            .request(&contact.id, dest, &frame, OP_BOOTSTRAP_RES, wait)
            .await?;
        let res = parse_bootstrap_res(&res_payload)?;
        // The responder itself (at the address we reached) is IP-verified iff its
        // reply echoed our verify key; the listed contacts are always unverified
        // until they prove their own IP (eMule KademliaUDPListener.cpp:567 vs the
        // payload contacts added unverified).
        self.add_contact(
            res.id,
            contact.ip,
            contact.udp_port,
            res.tcp_port,
            res.version,
            verified,
        );
        for c in &res.contacts {
            self.add_contact(c.id, c.ip, c.udp_port, c.tcp_port, c.version, false);
        }
        Ok(res)
    }

    /// Try each contact in turn until one answers a BOOTSTRAP_REQ. Returns the
    /// (contact index, response) of the first success.
    pub async fn bootstrap_any(
        &mut self,
        contacts: &[KadContact],
        per_contact: Duration,
        max_tries: usize,
    ) -> Result<(usize, BootstrapRes), KadError> {
        let mut last = KadError::Timeout;
        for (i, c) in contacts.iter().take(max_tries).enumerate() {
            match self.bootstrap_from(c, per_contact).await {
                Ok(res) => return Ok((i, res)),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    /// Send a HELLO_REQ to a contact (requesting a HELLO_RES_ACK) and parse the
    /// HELLO_RES.
    pub async fn hello(&mut self, contact: &KadContact, wait: Duration) -> Result<Hello, KadError> {
        // misc_options bit 0x04 requests a HELLO_RES_ACK (v>=8).
        let (op, payload) =
            build_hello_req(&self.kad_id, self.tcp_port, Some(self.udp_port), Some(0x04));
        let frame = pack_kad(op, payload);
        let dest = contact_addr(contact.ip, contact.udp_port);
        let (res_payload, _verified) = self
            .request(&contact.id, dest, &frame, OP_HELLO_RES, wait)
            .await?;
        Ok(parse_hello(&res_payload)?)
    }

    /// Ask one node (KADEMLIA2_REQ, FIND_NODE) for the contacts it knows closest
    /// to `target`, returning its KADEMLIA2_RES contacts.
    async fn find_node(
        &self,
        node: &WireContact,
        target: &Kad128,
        wait: Duration,
    ) -> Result<(Vec<WireContact>, bool), KadError> {
        let (op, payload) = build_kad2_req(KAD_FIND_NODE, target, &node.id);
        let frame = pack_kad(op, payload);
        let dest = contact_addr(node.ip, node.udp_port);
        let (res_payload, verified) = self
            .request(&node.id, dest, &frame, OP_KAD2_RES, wait)
            .await?;
        let mut contacts = parse_kad2_res(&res_payload)?.contacts;
        // Drop a malicious over-long answer: padMule requests KAD_FIND_NODE, whose
        // count field caps at what we asked for (11); a compliant node never
        // exceeds it, a hostile one may pad up to 255 fabricated contacts (eMule
        // Search.cpp:377 rejects the same way).
        if contacts.len() > KAD_REQUESTED_CONTACTS {
            return Err(KadError::Unexpected(OP_KAD2_RES));
        }
        // A node may not answer with itself, and may not list many IDs on one IP:
        // keep at most one contact per source IP within a single answer (eMule
        // Search.cpp:423/449 - honest nodes never do either).
        let responder_ip = node.ip;
        let mut seen_ips = std::collections::HashSet::new();
        contacts.retain(|c| c.ip != responder_ip && seen_ips.insert(c.ip));
        Ok((contacts, verified))
    }

    /// Ask one node (KADEMLIA2_SEARCH_SOURCE_REQ) for sources of `file_hash`,
    /// returning the accepted sources from its KADEMLIA2_SEARCH_RES.
    async fn search_source(
        &self,
        node: &WireContact,
        file_hash: &Kad128,
        file_size: u64,
        wait: Duration,
    ) -> Result<Vec<Source>, KadError> {
        let (op, payload) = build_search_source_req(file_hash, 0, file_size);
        let frame = pack_kad(op, payload);
        let dest = contact_addr(node.ip, node.udp_port);
        let (res_payload, _verified) = self
            .request(&node.id, dest, &frame, OP_SEARCH_RES, wait)
            .await?;
        let res = parse_search_res(&res_payload)?;
        Ok(res.results.iter().filter_map(|r| r.as_source()).collect())
    }

    /// The Wave-6 goal: resolve an ed2k `file_hash` to sources. Runs an iterative
    /// FIND_NODE lookup toward the hash over the current routing table, then sends
    /// SEARCH_SOURCE_REQ to the closest nodes within tolerance, collecting sources
    /// until at least `want` are found or the candidates are exhausted.
    pub async fn resolve_sources(
        &mut self,
        file_hash: &Kad128,
        file_size: u64,
        want: usize,
        per_query: Duration,
    ) -> Result<ResolveOutcome, KadError> {
        // Seed the lookup from the routing table's closest-to-hash contacts.
        let seeds: Vec<WireContact> = self
            .routing
            .closest_to(file_hash, 50)
            .into_iter()
            .map(|c| WireContact {
                id: c.id,
                ip: c.ip,
                udp_port: c.udp_port,
                tcp_port: c.tcp_port,
                version: c.version,
            })
            .collect();
        if seeds.is_empty() {
            return Err(KadError::NotReady); // no routing table - bootstrap first
        }
        let mut lookup = Lookup::new(*file_hash, seeds);
        let mut out = ResolveOutcome::default();

        // Iteratively converge on the nodes closest to the hash.
        for _round in 0..12 {
            let batch = lookup.next_queries(ALPHA_QUERY, K);
            if batch.is_empty() {
                break;
            }
            for node in &batch {
                out.nodes_queried += 1;
                if let Ok((contacts, verified)) = self.find_node(node, file_hash, per_query).await {
                    out.find_node_responses += 1;
                    // The node that answered proved its IP iff the receiver key was
                    // valid; the contacts it named are unverified until they answer.
                    self.add_contact(
                        node.id,
                        node.ip,
                        node.udp_port,
                        node.tcp_port,
                        node.version,
                        verified,
                    );
                    for c in &contacts {
                        self.add_contact(c.id, c.ip, c.udp_port, c.tcp_port, c.version, false);
                    }
                    lookup.on_response(contacts);
                }
            }
        }

        // How close did we get? Leading zero bits of the closest node's distance
        // to the hash (higher = closer; a real converged lookup reaches deep).
        if let Some(closest) = lookup.closest(1).first() {
            out.closest_prefix_bits = leading_zero_bits(&file_hash.distance(&closest.id));
        }

        // Query the closest nodes within the storage tolerance for sources.
        for node in lookup.closest(K) {
            if !file_hash.distance(&node.id).within_tolerance() {
                continue;
            }
            out.nodes_searched += 1;
            if let Ok(mut found) = self
                .search_source(&node, file_hash, file_size, per_query)
                .await
            {
                out.search_responses += 1;
                for s in found.drain(..) {
                    if !out.sources.iter().any(|e| e.client_hash == s.client_hash) {
                        out.sources.push(s);
                    }
                }
                if out.sources.len() >= want {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Ask one node for keyword matches (KADEMLIA2_SEARCH_KEY_REQ) and distil the
    /// file results from its KADEMLIA2_SEARCH_RES.
    async fn search_keyword_node(
        &self,
        node: &WireContact,
        target: &Kad128,
        wait: Duration,
    ) -> Result<Vec<FileResult>, KadError> {
        let (op, payload) = build_search_key_req(target, 0);
        let frame = pack_kad(op, payload);
        let dest = contact_addr(node.ip, node.udp_port);
        let (res_payload, _verified) = self
            .request(&node.id, dest, &frame, OP_SEARCH_RES, wait)
            .await?;
        let res = parse_search_res(&res_payload)?;
        Ok(res.results.iter().filter_map(|r| r.as_file()).collect())
    }

    /// Resolve a `keyword` to files over the live Kad network: an iterative
    /// FIND_NODE lookup toward the keyword hash, then KADEMLIA2_SEARCH_KEY_REQ to
    /// the closest in-tolerance nodes. Results are de-duped by file hash. This is
    /// a SERVERLESS search - no eD2k server needed.
    pub async fn resolve_keyword(
        &mut self,
        keyword: &str,
        want: usize,
        per_query: Duration,
    ) -> Result<Vec<FileResult>, KadError> {
        let target = kad_keyword_target(keyword);
        let seeds: Vec<WireContact> = self
            .routing
            .closest_to(&target, 50)
            .into_iter()
            .map(|c| WireContact {
                id: c.id,
                ip: c.ip,
                udp_port: c.udp_port,
                tcp_port: c.tcp_port,
                version: c.version,
            })
            .collect();
        if seeds.is_empty() {
            return Err(KadError::NotReady); // bootstrap first
        }
        let mut lookup = Lookup::new(target, seeds);
        for _round in 0..12 {
            let batch = lookup.next_queries(ALPHA_QUERY, K);
            if batch.is_empty() {
                break;
            }
            for node in &batch {
                if let Ok((contacts, verified)) = self.find_node(node, &target, per_query).await {
                    self.add_contact(
                        node.id,
                        node.ip,
                        node.udp_port,
                        node.tcp_port,
                        node.version,
                        verified,
                    );
                    for c in &contacts {
                        self.add_contact(c.id, c.ip, c.udp_port, c.tcp_port, c.version, false);
                    }
                    lookup.on_response(contacts);
                }
            }
        }

        let mut files: Vec<FileResult> = Vec::new();
        for node in lookup.closest(K) {
            if !target.distance(&node.id).within_tolerance() {
                continue;
            }
            if let Ok(found) = self.search_keyword_node(&node, &target, per_query).await {
                for f in found {
                    if !files.iter().any(|e| e.hash == f.hash) {
                        files.push(f);
                    }
                }
                if files.len() >= want {
                    break;
                }
            }
        }
        Ok(files)
    }
}

/// Leading zero bits of a 128-bit distance (the shared-prefix length with the
/// target); higher means a closer node.
fn leading_zero_bits(d: &Kad128) -> u32 {
    let w = d.words();
    for (i, word) in w.iter().enumerate() {
        if *word != 0 {
            return i as u32 * 32 + word.leading_zeros();
        }
    }
    128
}

/// The result of a source-resolution attempt, with lookup diagnostics so a live
/// run is legible even when a hash currently has no published sources.
#[derive(Debug, Default)]
pub struct ResolveOutcome {
    /// Sources found (empty if the hash has no current Kad sources).
    pub sources: Vec<Source>,
    /// FIND_NODE requests sent during the lookup.
    pub nodes_queried: usize,
    /// FIND_NODE requests that got a KADEMLIA2_RES back (live protocol proof).
    pub find_node_responses: usize,
    /// In-tolerance nodes we sent SEARCH_SOURCE_REQ to.
    pub nodes_searched: usize,
    /// SEARCH_SOURCE_REQs that got a KADEMLIA2_SEARCH_RES back.
    pub search_responses: usize,
    /// Shared-prefix bits between the hash and the closest node the lookup found.
    pub closest_prefix_bits: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contact_ip_uses_the_big_endian_view_confirmed_live() {
        // A real fresh-nodes.dat contact: wire bytes FA 24 EC 5F -> read_u32 LE
        // 0x5FEC24FA -> the real IP is 95.236.36.250 (a valid public host), NOT
        // the byte-reversed 250.36.236.95 (multicast). This convention is what
        // made the live Wave-6 bootstrap gate pass.
        let ip: u32 = 0x5FEC_24FA;
        let addr = contact_addr(ip, 4672);
        assert_eq!(addr, "95.236.36.250:4672".parse().unwrap());
        // Round-trips back to the same host-order u32 the record stored.
        assert_eq!(ip_u32(&addr), ip);
    }

    #[test]
    fn ip_u32_round_trips_an_arbitrary_v4() {
        let addr: SocketAddr = "203.0.113.7:1234".parse().unwrap();
        assert_eq!(contact_addr(ip_u32(&addr), 1234), addr);
    }

    // Faithful mock-peer helpers for the receiver-key tests: they play the real
    // responder role (interop-test-fidelity), not a same-role echo.
    use mule_kad::{build_bootstrap_res, kad_obfuscate_response, udp_verify_key};

    #[tokio::test]
    async fn request_reports_a_valid_receiver_key_when_the_peer_echoes_our_sender_key() {
        // A real v2 node decrypts our request, reads the sender verify key we
        // issued for its IP, and echoes it back as the receiver key of a
        // receiver-keyed response. request() must report bValidReceiverKey = true.
        let our_key = 0x1234_5678u32;
        let our_id = Kad128::from_words([9, 9, 9, 9]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, our_key)
                .await
                .unwrap();
        let peer_id = Kad128::from_hash(&[0x55; 16]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (n, from) = peer.recv_from(&mut buf).await.unwrap();
            // The peer decrypts our request keyed on its OWN id, learning our
            // sender verify key, then echoes it in a receiver-keyed response.
            let dec = kad_deobfuscate(&buf[..n], &peer_id, 0, ip_u32(&from)).unwrap();
            let (rop, rpayload) = build_bootstrap_res(&peer_id, 4662, 8, &[]);
            let rframe = pack_kad(rop, rpayload);
            let dg = kad_obfuscate_response(&rframe, 0x2468, dec.sender_vk, 0, 0x80);
            peer.send_to(&dg, from).await.unwrap();
        });

        let (op, payload) = build_bootstrap_req();
        let frame = pack_kad(op, payload);
        let (_res, valid) = node
            .request(
                &peer_id,
                peer_addr,
                &frame,
                OP_BOOTSTRAP_RES,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(
            valid,
            "the peer echoed our sender key -> receiver key is valid"
        );
        mock.await.unwrap();
    }

    #[tokio::test]
    async fn request_reports_an_invalid_receiver_key_for_a_nodeid_path_forgery() {
        // An off-path attacker who knows only our (semi-public) KadID can craft a
        // response that decrypts via the NodeID path, but cannot know the verify
        // key derived from our secret UDP key - so its receiver key is wrong and
        // request() must report bValidReceiverKey = false (the contact will be
        // recorded UNVERIFIED, matching eMule - the packet is still processed).
        let our_key = 0xDEAD_BEEFu32;
        let our_id = Kad128::from_words([1, 2, 3, 4]);
        let node =
            KadNode::bind_with_identity("127.0.0.1:0".parse().unwrap(), 4662, our_id, our_key)
                .await
                .unwrap();
        let peer_id = Kad128::from_hash(&[0x66; 16]);
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mock = tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let (_n, from) = peer.recv_from(&mut buf).await.unwrap();
            // Forge a NodeID-path response keyed on our KadID with a bogus
            // receiver key (the attacker cannot derive the real one).
            let (rop, rpayload) = build_bootstrap_res(&peer_id, 4662, 8, &[]);
            let rframe = pack_kad(rop, rpayload);
            let dg =
                mule_kad::kad_obfuscate_request(&rframe, &our_id, 0x1111, 0xBADD_0000, 0, 0x40);
            peer.send_to(&dg, from).await.unwrap();
        });

        let (op, payload) = build_bootstrap_req();
        let frame = pack_kad(op, payload);
        let (_res, valid) = node
            .request(
                &peer_id,
                peer_addr,
                &frame,
                OP_BOOTSTRAP_RES,
                Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(!valid, "a NodeID-path forgery has no valid receiver key");
        mock.await.unwrap();

        // Silence the unused-import warning when only one test path uses it.
        let _ = udp_verify_key(our_key, 0);
    }

    #[tokio::test]
    async fn add_contact_drops_ipfiltered_ranges() {
        use mule_files::{IpFilter, DEFAULT_IPFILTER_LEVEL};
        use std::sync::Arc;
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = KadNode::bind(bind, 4662).await.unwrap();
        node.set_ip_filter(Some(Arc::new(IpFilter::parse(
            "9.9.9.0 - 9.9.9.255 , 0 , blocked\n",
            DEFAULT_IPFILTER_LEVEL,
        ))));
        // A user-blocklisted public IP never enters the routing table...
        node.add_contact(
            Kad128::from_hash(&[1; 16]),
            0x0909_0909,
            4672,
            4662,
            8,
            false,
        );
        assert_eq!(node.contacts_known(), 0, "blocklisted contact dropped");
        // ...but an allowed public IP does.
        node.add_contact(
            Kad128::from_hash(&[2; 16]),
            0x0808_0808,
            4672,
            4662,
            8,
            false,
        );
        assert_eq!(node.contacts_known(), 1, "allowed contact kept");
    }

    #[tokio::test]
    async fn add_contact_version_gates_the_port_53_guard() {
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = KadNode::bind(bind, 4662).await.unwrap();
        // A LEGACY node (version <= 5) on DNS port 53 is dropped (anti-reflection)...
        node.add_contact(Kad128::from_hash(&[1; 16]), 0x0808_0808, 53, 4662, 5, false);
        assert_eq!(node.contacts_known(), 0, "legacy port-53 contact dropped");
        // ...but a MODERN node on 53 is KEPT - eMule keeps it, so we must not be
        // stricter (that would drop a peer eMule accepts).
        node.add_contact(Kad128::from_hash(&[2; 16]), 0x0909_0909, 53, 4662, 8, false);
        assert_eq!(
            node.contacts_known(),
            1,
            "modern port-53 contact kept (faithful)"
        );
    }

    #[tokio::test]
    async fn a_known_id_repointed_to_a_full_ip_is_refused() {
        // A known KadID re-pointed to a DIFFERENT ip is a hijack attempt and faces
        // the anti-sybil cap on the new ip - it is not a free refresh past the cap.
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = KadNode::bind(bind, 4662).await.unwrap();
        let id1 = Kad128::from_hash(&[1; 16]);
        node.add_contact(id1, 0x0808_0808, 4672, 4662, 8, false);
        node.add_contact(
            Kad128::from_hash(&[2; 16]),
            0x0808_0809,
            4672,
            4662,
            8,
            false,
        );
        // The attacker's ip (0x0808_0809) is already at the 1-per-IP cap, so
        // re-pointing id1 onto it is refused; id1 stays at its original ip.
        node.add_contact(id1, 0x0808_0809, 4672, 4662, 8, false);
        assert_eq!(
            node.routing().ip_of(&id1),
            Some(0x0808_0808),
            "hijack to a full IP refused; id stays put"
        );
    }

    #[tokio::test]
    async fn add_contact_enforces_one_id_per_ip() {
        // eMule MAX_CONTACTS_IP = 1: a second KadID behind one IP is refused (the
        // cheapest sybil primitive).
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut node = KadNode::bind(bind, 4662).await.unwrap();
        node.add_contact(
            Kad128::from_hash(&[1; 16]),
            0x0808_0808,
            4672,
            4662,
            8,
            false,
        );
        node.add_contact(
            Kad128::from_hash(&[2; 16]),
            0x0808_0808,
            4672,
            4662,
            8,
            false,
        );
        assert_eq!(node.contacts_known(), 1, "second id on the same IP refused");
    }

    #[tokio::test]
    async fn bind_with_identity_keeps_the_persisted_id_and_key() {
        // The engine passes NodeIdentity::{kad_id, kad_udp_key}; the node must
        // adopt them verbatim (a fresh random identity here would silently
        // re-key Kad on every app start - the bug this constructor fixes).
        let id = Kad128::from_words([1, 2, 3, 4]);
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let node = KadNode::bind_with_identity(bind, 4662, id, 0xDEAD_BEEF)
            .await
            .unwrap();
        assert_eq!(node.kad_id(), id);
        assert_eq!(node.udp_key, 0xDEAD_BEEF);
    }
}
