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

use mule_files::KadContact;
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
        })
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
    fn add_contact(&mut self, id: Kad128, ip: u32, udp_port: u16, tcp_port: u16, version: u8) {
        if !is_acceptable_contact(ip, udp_port, /*allow_private=*/ false) {
            return;
        }
        // Anti-sybil (live-layer): cap how many contacts share one IP / /24, so a
        // hostile node cannot flood our routing table with fake IDs behind one
        // address. Refreshing an id we already hold is always allowed. Interop-safe:
        // the real Kad network is IP-diverse, so a legitimate peer is never dropped.
        if ip != 0 && !self.routing.contains(&id) {
            let (same_ip, same_subnet) = self.routing.ip_counts(ip);
            if same_ip >= mule_kad::MAX_CONTACTS_PER_IP
                || same_subnet >= mule_kad::MAX_CONTACTS_PER_SUBNET
            {
                return;
            }
        }
        self.routing.add(id, ip, udp_port, tcp_port, version);
    }

    /// Send an obfuscated Kad request (NodeID-keyed on `target_id`, our
    /// senderVerifyKey issued for `dest`) and wait for a decryptable reply with
    /// opcode `expect` FROM `dest`, ignoring interleaved/stray datagrams (other
    /// nodes' pings, a HELLO from the peer) until the deadline.
    async fn request(
        &self,
        target_id: &Kad128,
        dest: SocketAddr,
        frame: &[u8],
        expect: u8,
        wait: Duration,
    ) -> Result<Vec<u8>, KadError> {
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
                return Ok(payload);
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
        let res_payload = self
            .request(&contact.id, dest, &frame, OP_BOOTSTRAP_RES, wait)
            .await?;
        let res = parse_bootstrap_res(&res_payload)?;
        // The responder itself (at the address we reached), then every listed contact.
        self.add_contact(
            res.id,
            contact.ip,
            contact.udp_port,
            res.tcp_port,
            res.version,
        );
        for c in &res.contacts {
            self.add_contact(c.id, c.ip, c.udp_port, c.tcp_port, c.version);
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
        let res_payload = self
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
    ) -> Result<Vec<WireContact>, KadError> {
        let (op, payload) = build_kad2_req(KAD_FIND_NODE, target, &node.id);
        let frame = pack_kad(op, payload);
        let dest = contact_addr(node.ip, node.udp_port);
        let res_payload = self
            .request(&node.id, dest, &frame, OP_KAD2_RES, wait)
            .await?;
        Ok(parse_kad2_res(&res_payload)?.contacts)
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
        let res_payload = self
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
                if let Ok(contacts) = self.find_node(node, file_hash, per_query).await {
                    out.find_node_responses += 1;
                    for c in &contacts {
                        self.add_contact(c.id, c.ip, c.udp_port, c.tcp_port, c.version);
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
        let res_payload = self
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
                if let Ok(contacts) = self.find_node(node, &target, per_query).await {
                    for c in &contacts {
                        self.add_contact(c.id, c.ip, c.udp_port, c.tcp_port, c.version);
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
