//! The Server Hunter recursive crawl, as a PURE state machine (no I/O).
//!
//! Same split as `mule_kad::lookup`: the policy - who to ask next, what to
//! accept, when to stop - lives here and is fully testable offline, while
//! `Engine::crawl_servers` drives it over a real UDP socket.
//!
//! WIRE (evidence-grounded, 2026-08-03): the ask is `OP_SERVER_LIST_REQ2`
//! (0xA4, bodiless) to the server's UDP port (TCP + 4); the answer is
//! `OP_SERVER_LIST_RES` (0xA1) whose payload is byte-identical to TCP
//! `OP_SERVERLIST` - `<count u8>(<ip u32><port u16>)[count]` - so
//! `server_messages::parse_server_list` reads both.
//!
//! DELIBERATE DEVIATION, recorded honestly: NO client authority sends 0xA4.
//! eMule 0.50a and aMule (3.0.1 and master) DEFINE the opcode pair but never
//! send or parse it; what they send on this socket is the status ping (0x96)
//! and the description request (0xA2). padMule sends it because many SERVERS
//! implement it - measured, not assumed (2026-08-03).
//!
//! SUPPORT IS IMPLEMENTATION-SPECIFIC, and the obvious guess was WRONG: the
//! vendored Lugdunum eserver 17.15 oracle does NOT answer 0xA4 (nor does the
//! `ed2k-rust` server at 85.17.116.222, nor eMule Sunrise), while a first live
//! crawl had 28 of 33 asked servers answer. Every silent server answered 0x96
//! and 0xA2 from the same datagram burst, so the silence is a real negative,
//! not a dead host or a lost packet.
//!
//! SILENCE IS THEREFORE A NORMAL ANSWER. A crawl that treats no-reply as an
//! error, or as evidence the server is dead, would be wrong about a large part
//! of the network - including the oracle we test against.
//!
//! The abuse profile is deliberately no worse than what padMule already does:
//! the Servers screen fans a UDP status ping to every server in the list, and
//! this adds one more small datagram to those same hosts, paced and bounded.
//! Whole-net scanning stays out of scope (docs/wiki/feature-server-hunter.md).

use std::collections::HashSet;
use std::net::Ipv4Addr;

/// A server address in padMule's met convention: `ip` is the server.met u32
/// (little-endian, low byte = first octet) and `port` is the TCP port.
pub type ServerAddr = (u32, u16);

/// Hard ceiling on how many addresses one crawl may accumulate, so a hostile
/// answer chain cannot grow the run without bound. A real crawl finds tens.
pub const MAX_CRAWL_DISCOVERED: usize = 1000;

/// Structural acceptance for a crawl candidate: a usable port, and a routable
/// PUBLIC address. The user ipfilter is applied by the caller (it lives on the
/// engine), both before asking and again at merge time.
///
/// This is the SSRF posture from the readiness audit: a server that advertises
/// 127.0.0.1, a LAN address, or a multicast range must never become something
/// we send a datagram to.
pub fn is_crawlable(ip: u32, port: u16) -> bool {
    // The met u32 is LITTLE-endian (low byte = first octet), so the dotted quad
    // is its LE bytes - the same conversion `engine::ip_from_met_u32` does.
    // Spelled with to_le_bytes rather than to_be(), which would silently invert
    // on a big-endian target (the IP byte-order landmine, docs/wiki/
    // protocol-understanding.md).
    port != 0 && crate::fetch::is_routable_public_v4(Ipv4Addr::from(ip.to_le_bytes()))
}

/// The crawl frontier: who has been asked, who is next, and what was learned.
#[derive(Debug, Default)]
pub struct ServerCrawl {
    asked: HashSet<ServerAddr>,
    frontier: Vec<ServerAddr>,
    discovered: Vec<ServerAddr>,
    seen: HashSet<ServerAddr>,
}

impl ServerCrawl {
    /// Seed the crawl with the servers already known (typically server.met).
    /// Seeds are candidates to ASK; they are not themselves "discovered".
    pub fn new(seed: impl IntoIterator<Item = ServerAddr>) -> Self {
        let mut c = Self::default();
        for (ip, port) in seed {
            if is_crawlable(ip, port) && c.seen.insert((ip, port)) {
                c.frontier.push((ip, port));
            }
        }
        c
    }

    /// Take up to `max` not-yet-asked addresses off the frontier, marking them
    /// asked so a later round never re-asks them.
    pub fn next_asks(&mut self, max: usize) -> Vec<ServerAddr> {
        let mut out = Vec::new();
        while out.len() < max {
            let Some(a) = self.frontier.pop() else { break };
            if self.asked.insert(a) {
                out.push(a);
            }
        }
        out
    }

    /// Fold one server's answer in. Returns how many addresses were NEW.
    ///
    /// The caller must already have verified the answer came from an address it
    /// actually asked (anti-spoof happens at the socket, where the source is
    /// known). Entries failing the structural rule, already seen, or past the
    /// ceiling are dropped here.
    pub fn on_answer(&mut self, servers: &[ServerAddr]) -> usize {
        let mut fresh = 0;
        for &(ip, port) in servers {
            if self.discovered.len() >= MAX_CRAWL_DISCOVERED {
                break;
            }
            if !is_crawlable(ip, port) || !self.seen.insert((ip, port)) {
                continue;
            }
            self.discovered.push((ip, port));
            self.frontier.push((ip, port));
            fresh += 1;
        }
        fresh
    }

    /// Everything the crawl learned that it did not start with.
    pub fn discovered(&self) -> &[ServerAddr] {
        &self.discovered
    }

    /// True once there is nobody left to ask.
    pub fn is_exhausted(&self) -> bool {
        self.frontier.is_empty()
    }

    /// How many servers have been asked so far (for an honest progress line).
    pub fn asked_count(&self) -> usize {
        self.asked.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// met-u32 for a.b.c.d (little-endian: low byte is the first octet).
    fn met(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_le_bytes([a, b, c, d])
    }

    #[test]
    fn only_routable_public_addresses_are_crawlable() {
        assert!(is_crawlable(met(85, 17, 116, 222), 4242));
        assert!(!is_crawlable(met(85, 17, 116, 222), 0), "port 0");
        assert!(!is_crawlable(met(127, 0, 0, 1), 4242), "loopback");
        assert!(!is_crawlable(met(192, 168, 0, 5), 4242), "LAN");
        assert!(!is_crawlable(met(10, 0, 0, 7), 4242), "private");
        assert!(!is_crawlable(met(224, 0, 0, 1), 4242), "multicast");
    }

    #[test]
    fn a_seed_is_asked_once_and_never_re_asked() {
        let a = (met(85, 17, 116, 222), 4242);
        let mut c = ServerCrawl::new([a]);
        assert_eq!(c.next_asks(10), vec![a]);
        assert!(c.next_asks(10).is_empty(), "no re-ask");
        assert!(c.is_exhausted());
        assert_eq!(c.asked_count(), 1);
    }

    /// The whole point of the RECURSIVE crawl: a server we were never
    /// configured with, learned two hops out, still gets asked.
    #[test]
    fn the_crawl_recurses_two_hops_out() {
        let a = (met(85, 17, 116, 222), 4242);
        let b = (met(77, 42, 68, 79), 4232);
        let d = (met(193, 187, 90, 12), 4661);

        let mut c = ServerCrawl::new([a]);
        assert_eq!(c.next_asks(10), vec![a]);
        assert_eq!(c.on_answer(&[b]), 1, "A advertises B");
        assert_eq!(c.next_asks(10), vec![b], "B is asked in the next round");
        assert_eq!(c.on_answer(&[d]), 1, "B advertises D");
        assert_eq!(c.next_asks(10), vec![d], "D - two hops from the seed");

        let found = c.discovered();
        assert!(found.contains(&b) && found.contains(&d));
        assert!(!found.contains(&a), "a seed is not a discovery");
    }

    #[test]
    fn hostile_and_duplicate_answers_are_dropped() {
        let a = (met(85, 17, 116, 222), 4242);
        let good = (met(77, 42, 68, 79), 4232);
        let mut c = ServerCrawl::new([a]);
        c.next_asks(10);

        let fresh = c.on_answer(&[
            good,
            (met(127, 0, 0, 1), 4242),   // loopback - our own box
            (met(192, 168, 0, 5), 4242), // the user's LAN
            (met(8, 8, 8, 8), 0),        // port 0
            good,                        // duplicate inside one answer
            a,                           // the seed we already know
        ]);
        assert_eq!(fresh, 1, "only the one good address is new");
        assert_eq!(c.discovered(), &[good]);

        assert_eq!(c.on_answer(&[good]), 0, "duplicate across answers");
    }

    #[test]
    fn the_discovery_ceiling_bounds_a_hostile_answer_chain() {
        let mut c = ServerCrawl::new([(met(85, 17, 116, 222), 4242)]);
        c.next_asks(10);
        // Feed far more than the ceiling from a "server" that answers forever.
        for chunk in 0..40u32 {
            let flood: Vec<ServerAddr> = (0..100u32)
                .map(|i| {
                    let n = chunk * 100 + i;
                    (met(85, 17, (n >> 8) as u8, (n & 0xFF) as u8), 4242)
                })
                .collect();
            c.on_answer(&flood);
        }
        assert_eq!(c.discovered().len(), MAX_CRAWL_DISCOVERED);
    }

    #[test]
    fn next_asks_honors_its_batch_cap() {
        let seed: Vec<ServerAddr> = (1..=50u32)
            .map(|i| (met(85, 17, 0, i as u8), 4242))
            .collect();
        let mut c = ServerCrawl::new(seed);
        assert_eq!(c.next_asks(20).len(), 20);
        assert_eq!(c.next_asks(20).len(), 20);
        assert_eq!(c.next_asks(20).len(), 10, "the rest");
        assert!(c.is_exhausted());
    }
}
