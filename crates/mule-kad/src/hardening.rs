//! Kad anti-abuse hardening (behavioral, NOT wire) - adopted from eMule 0.70b's
//! community fixes: reject junk/unroutable contacts, and rate-limit floods of
//! requests from a single IP. None of this changes what goes on the wire; it
//! just makes a long-lived public Kad node harder to poison or DoS.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Is this contact IP a routable public address worth keeping? `ip` is the
/// host-order value padMule uses (MSByte = first octet), so the dotted quad is
/// `Ipv4Addr::from(ip)`. Rejects the MAJOR unroutable ranges eMule's `IsGoodIP`
/// drops: 0.x, loopback, link-local, private, multicast, and 240/4 reserved.
/// NOT full parity with aMule's table-driven reserved_ranges
/// (NetworkFunctions.cpp:133) - the exotic blocks (39/8, 128.0/16, 192.0.2/24,
/// 198.18/15, ...) are not filtered here. (LAN-only Kad would pass
/// `allow_private = true`.)
pub fn is_acceptable_contact_ip(ip: u32, allow_private: bool) -> bool {
    if ip == 0 {
        return false;
    }
    let o = ip.to_be_bytes(); // [a, b, c, d]
    match o[0] {
        0 | 127 => false,              // "this network" / loopback
        224..=255 => false,            // multicast + reserved/broadcast
        10 if !allow_private => false, // private
        169 if o[1] == 254 => false,   // link-local
        172 if (16..=31).contains(&o[1]) && !allow_private => false,
        192 if o[1] == 168 && !allow_private => false,
        _ => true,
    }
}

/// A contact must also have a usable UDP port. (The DNS-port-53 anti-reflection
/// guard is applied at the live layer, `kad_live::add_contact`, where the contact
/// version is known - eMule drops port 53 only for legacy nodes, version <= 5.)
pub fn is_acceptable_contact(ip: u32, udp_port: u16, allow_private: bool) -> bool {
    udp_port != 0 && is_acceptable_contact_ip(ip, allow_private)
}

/// What to do with a request from an IP that the flood tracker has been watching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloodVerdict {
    /// Under the limit - handle normally.
    Allow,
    /// Over the soft limit - silently ignore this request (do not reply).
    Ignore,
    /// Over the hard limit - the IP is now banned for a while.
    Ban,
}

struct Entry {
    count: u32,
    window_start: Instant,
    banned_until: Option<Instant>,
}

/// The most source addresses one [`FloodTracker`] will hold.
///
/// `entries` is keyed by an ATTACKER-CONTROLLED UDP source address, so without
/// a ceiling the limiter becomes the memory-exhaustion vector it exists to
/// prevent - and a banned entry pins itself for the whole ban, making the
/// busiest attacker the most persistent. eMule prunes on a desktop timer;
/// padMule has a ~100MB jetsam budget and no such timer, so it prunes on insert
/// and then refuses to grow. THE ONE DEFINITION: `kad_live`'s out-track list
/// imports this (via the crate root) for the same reasoning, rather than
/// mirroring the number.
pub const MAX_TRACKED_IPS: usize = 4096;

/// Per-IP request-rate limiter with ignore-then-ban escalation (eMule 0.70b:
/// "If Kad receives more requests of a specific type from one IP than expected,
/// it starts ignoring those requests and eventually bans the source"). Time is
/// injected as `now` so it is deterministically testable; the live caller passes
/// `Instant::now()`. Use one tracker per request type for per-type limits.
pub struct FloodTracker {
    window: Duration,
    soft_limit: u32,
    hard_limit: u32,
    ban_duration: Duration,
    entries: HashMap<u32, Entry>,
}

impl FloodTracker {
    /// `soft_limit`/`hard_limit` requests allowed per `window` before ignoring /
    /// banning; a banned IP stays banned for `ban_duration`.
    pub fn new(window: Duration, soft_limit: u32, hard_limit: u32, ban_duration: Duration) -> Self {
        FloodTracker {
            window,
            soft_limit,
            hard_limit,
            ban_duration,
            entries: HashMap::new(),
        }
    }

    /// Record a request from `ip` at `now` and return the verdict.
    pub fn record(&mut self, ip: u32, now: Instant) -> FloodVerdict {
        // BOUND THE MAP BEFORE ADMITTING A NEW SOURCE - see [`MAX_TRACKED_IPS`].
        // Only on the new-key path, so the ordinary case stays O(1) and the
        // O(n) prune is paid only when the map is actually full. FAIL-OPEN if
        // it is still full after pruning: declining to TRACK an address costs
        // us rate-limiting for it alone, while declining to SERVE every unknown
        // source under a spoofed spray would hand the attacker the outage the
        // limiter exists to prevent.
        if self.entries.len() >= MAX_TRACKED_IPS && !self.entries.contains_key(&ip) {
            self.evict_expired(now);
            if self.entries.len() >= MAX_TRACKED_IPS {
                return FloodVerdict::Allow;
            }
        }
        let e = self.entries.entry(ip).or_insert(Entry {
            count: 0,
            window_start: now,
            banned_until: None,
        });
        if let Some(until) = e.banned_until {
            if now < until {
                return FloodVerdict::Ban;
            }
            // Ban expired: start fresh.
            e.banned_until = None;
            e.count = 0;
            e.window_start = now;
        }
        if now.duration_since(e.window_start) > self.window {
            e.count = 0;
            e.window_start = now;
        }
        e.count += 1;
        if e.count > self.hard_limit {
            e.banned_until = Some(now + self.ban_duration);
            return FloodVerdict::Ban;
        }
        if e.count > self.soft_limit {
            return FloodVerdict::Ignore;
        }
        FloodVerdict::Allow
    }

    /// How many source addresses are currently tracked. The observable for the
    /// [`MAX_TRACKED_IPS`] bound - without it the memory property can only be
    /// asserted by proxy.
    pub fn tracked(&self) -> usize {
        self.entries.len()
    }

    /// Is `ip` currently banned?
    pub fn is_banned(&self, ip: u32, now: Instant) -> bool {
        self.entries
            .get(&ip)
            .and_then(|e| e.banned_until)
            .is_some_and(|until| now < until)
    }

    /// Drop tracking state for IPs whose window and ban have both lapsed, to
    /// bound memory on a busy node.
    pub fn evict_expired(&mut self, now: Instant) {
        self.entries.retain(|_, e| {
            e.banned_until.is_some_and(|u| now < u)
                || now.duration_since(e.window_start) <= self.window
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> u32 {
        u32::from_be_bytes([a, b, c, d])
    }

    #[test]
    fn accepts_public_rejects_junk() {
        assert!(is_acceptable_contact_ip(ip(95, 236, 36, 250), false));
        assert!(is_acceptable_contact_ip(ip(45, 87, 41, 16), false));
        // Junk / unroutable:
        assert!(!is_acceptable_contact_ip(0, false));
        assert!(!is_acceptable_contact_ip(ip(127, 0, 0, 1), false));
        assert!(!is_acceptable_contact_ip(ip(10, 0, 0, 33), false));
        assert!(!is_acceptable_contact_ip(ip(192, 168, 1, 5), false));
        assert!(!is_acceptable_contact_ip(ip(172, 16, 0, 1), false));
        assert!(!is_acceptable_contact_ip(ip(169, 254, 0, 1), false));
        assert!(!is_acceptable_contact_ip(ip(224, 0, 0, 1), false)); // multicast
        assert!(!is_acceptable_contact_ip(ip(250, 36, 236, 95), false)); // reserved (the byte-swap of a real IP!)
    }

    #[test]
    fn lan_mode_allows_private() {
        assert!(is_acceptable_contact_ip(ip(10, 0, 0, 33), true));
        assert!(is_acceptable_contact_ip(ip(192, 168, 1, 5), true));
        // still rejects truly-bad ones
        assert!(!is_acceptable_contact_ip(ip(224, 0, 0, 1), true));
    }

    #[test]
    fn contact_needs_a_usable_udp_port() {
        assert!(is_acceptable_contact(ip(95, 236, 36, 250), 4672, false));
        assert!(!is_acceptable_contact(ip(95, 236, 36, 250), 0, false));
    }

    /// THE LIMITER MUST NOT BECOME THE EXHAUSTION VECTOR IT PREVENTS.
    ///
    /// `entries` is keyed by an ATTACKER-CONTROLLED UDP source address, and a
    /// spoofed spray names a fresh one every datagram. `evict_expired` was
    /// written for this and had NO caller, so on a device with a ~100MB jetsam
    /// budget the anti-flood map grew without limit - and a BANNED entry pins
    /// itself for the full 2h ban, so the busiest attacker was the most
    /// persistent memory.
    ///
    /// FAIL-OPEN when full, deliberately, and the reasoning is padMule's own
    /// (the identical rule already guards the out-track list): refusing to
    /// track a new IP only costs us rate-limiting for that address, whereas
    /// refusing to SERVE every unknown source under a spoofed spray would be a
    /// self-inflicted outage - the attacker would have achieved by flooding
    /// exactly what the limiter exists to prevent.
    #[test]
    fn flood_tracking_is_bounded_and_prunes_before_it_refuses() {
        let window = Duration::from_secs(60);
        let mut ft = FloodTracker::new(window, 3, 5, Duration::from_secs(7200));
        let t0 = Instant::now();

        // A spoofed spray: far more distinct sources than the bound allows.
        for i in 0..(MAX_TRACKED_IPS as u32 + 500) {
            ft.record(0x0100_0000 + i, t0);
        }
        assert!(
            ft.tracked() <= MAX_TRACKED_IPS,
            "the tracker grew to {} entries - it IS the exhaustion vector now",
            ft.tracked()
        );

        // Everything above lapses once the window passes, so a later arrival
        // finds room and is tracked again rather than being permanently
        // untracked: the bound must not be a one-way door.
        let later = t0 + window + Duration::from_secs(1);
        for _ in 0..6 {
            ft.record(0x0900_0001, later);
        }
        assert!(
            ft.is_banned(0x0900_0001, later),
            "after the spray lapses, a real flooder must still be catchable"
        );
    }

    #[test]
    fn flood_tracker_escalates_ignore_then_ban() {
        let mut ft = FloodTracker::new(
            Duration::from_secs(10),
            3, // soft
            5, // hard
            Duration::from_secs(60),
        );
        let t0 = Instant::now();
        let src = ip(1, 2, 3, 4);
        // First 3 are allowed.
        for _ in 0..3 {
            assert_eq!(ft.record(src, t0), FloodVerdict::Allow);
        }
        // 4th, 5th over the soft limit -> ignore.
        assert_eq!(ft.record(src, t0), FloodVerdict::Ignore);
        assert_eq!(ft.record(src, t0), FloodVerdict::Ignore);
        // 6th over the hard limit -> ban.
        assert_eq!(ft.record(src, t0), FloodVerdict::Ban);
        assert!(ft.is_banned(src, t0));
        // Still banned within the ban window; a different IP is unaffected.
        assert_eq!(
            ft.record(src, t0 + Duration::from_secs(5)),
            FloodVerdict::Ban
        );
        assert_eq!(ft.record(ip(9, 9, 9, 9), t0), FloodVerdict::Allow);
    }

    #[test]
    fn window_resets_the_count() {
        let mut ft = FloodTracker::new(Duration::from_secs(10), 3, 5, Duration::from_secs(60));
        let t0 = Instant::now();
        let src = ip(1, 2, 3, 4);
        for _ in 0..3 {
            ft.record(src, t0);
        }
        // After the window passes, the count resets so we are Allowed again.
        assert_eq!(
            ft.record(src, t0 + Duration::from_secs(11)),
            FloodVerdict::Allow
        );
    }

    #[test]
    fn ban_expires() {
        let mut ft = FloodTracker::new(Duration::from_secs(10), 1, 2, Duration::from_secs(30));
        let t0 = Instant::now();
        let src = ip(1, 2, 3, 4);
        ft.record(src, t0);
        ft.record(src, t0);
        assert_eq!(ft.record(src, t0), FloodVerdict::Ban);
        // After the ban duration, it is allowed again.
        assert_eq!(
            ft.record(src, t0 + Duration::from_secs(31)),
            FloodVerdict::Allow
        );
        assert!(!ft.is_banned(src, t0 + Duration::from_secs(31)));
    }
}
