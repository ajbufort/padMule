//! Kad anti-abuse hardening (behavioral, NOT wire) - adopted from eMule 0.70b's
//! community fixes: reject junk/unroutable contacts, and rate-limit floods of
//! requests from a single IP. None of this changes what goes on the wire; it
//! just makes a long-lived public Kad node harder to poison or DoS.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Is this contact IP a routable public address worth keeping? `ip` is the
/// host-order value padMule uses (MSByte = first octet), so the dotted quad is
/// `Ipv4Addr::from(ip)`. Rejects the unroutable ranges eMule's `IsGoodIP` drops:
/// 0.x, loopback, link-local, private, multicast, and reserved. (LAN-only Kad
/// would pass `allow_private = true`.)
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

/// A contact must also have a usable UDP port.
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
    fn contact_needs_a_udp_port() {
        assert!(is_acceptable_contact(ip(95, 236, 36, 250), 4672, false));
        assert!(!is_acceptable_contact(ip(95, 236, 36, 250), 0, false));
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
