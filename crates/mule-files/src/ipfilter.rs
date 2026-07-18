//! IP blocklist: parse `ipfilter.dat` (PeerGuardian) and `.p2p` (AntiP2P /
//! Guarding.P2P) range lists and test an address against them.
//!
//! Format-faithful to aMule (`IPFilterScanner.l`) so published community lists
//! load unchanged. Two per-line text forms, decimal dotted-quad only:
//!
//! - `IPa - IPb , level , description`   (ipfilter.dat; level 0-255)
//! - `description : IPa - IPb`           (.p2p; level forced to 0)
//!
//! A leading `#` is a comment; anything else that does not parse is skipped.
//!
//! Access level: a range BLOCKS iff its level is strictly less than the
//! configured level (aMule default 127, `IPFilter.cpp:143`). We keep only the
//! blocking ranges and MERGE them into a non-overlapping sorted set, so the
//! runtime test is a plain binary search: an IP is blocked iff it falls in the
//! union of blocking ranges. (This intentionally does not honor aMule's
//! last-writer-wins overlap cropping, where a later higher-level range can carve
//! an allow-hole in a block range - for the all-block community lists padMule
//! loads the union is identical; a cross-list whitelist-by-overlap would be
//! slightly over-blocked, which is the safe direction for a blocklist.)
//!
//! IP numbering: host order, first dotted octet in the most-significant byte
//! (`1.2.3.4` -> `0x01020304`), matching `u32::from(Ipv4Addr)`.

use std::net::Ipv4Addr;

/// aMule's default IP-filter level (`Preferences.cpp:1314`). A range blocks iff
/// its level `<` this.
pub const DEFAULT_IPFILTER_LEVEL: u8 = 127;

/// A parsed, level-filtered, merged IP blocklist.
#[derive(Debug, Clone, Default)]
pub struct IpFilter {
    /// Non-overlapping, sorted by start; each `(start, end)` inclusive, host order.
    ranges: Vec<(u32, u32)>,
}

/// Parse a decimal dotted-quad into a host-order u32 (`1.2.3.4` -> 0x01020304).
fn parse_ipv4(s: &str) -> Option<u32> {
    let mut octets = [0u32; 4];
    let mut n = 0;
    for part in s.trim().split('.') {
        if n == 4 {
            return None; // too many octets
        }
        let v: u32 = part.trim().parse().ok()?;
        if v > 255 {
            return None;
        }
        octets[n] = v;
        n += 1;
    }
    if n != 4 {
        return None;
    }
    Some((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3])
}

/// Parse an `IPa - IPb` range (whitespace around the dash tolerated).
fn parse_range(s: &str) -> Option<(u32, u32)> {
    let (a, b) = s.split_once('-')?;
    let start = parse_ipv4(a)?;
    let end = parse_ipv4(b)?;
    if start <= end {
        Some((start, end))
    } else {
        None // reversed range: discard, matching aMule's start<=end gate
    }
}

impl IpFilter {
    /// Parse `text` (mixed ipfilter.dat / .p2p lines), keeping ranges that block
    /// at `level`, and merge them. An empty/garbage input yields an empty filter.
    pub fn parse(text: &str, level: u8) -> Self {
        let mut blocking: Vec<(u32, u32)> = Vec::new();
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Format A: `IPa - IPb , lvl , desc` - needs at least two commas.
            let mut parsed = None;
            let commas: Vec<&str> = line.splitn(3, ',').collect();
            if commas.len() == 3 {
                if let (Some(range), Ok(lvl)) =
                    (parse_range(commas[0]), commas[1].trim().parse::<u32>())
                {
                    if lvl <= 255 && (lvl as u8) < level {
                        parsed = Some(range);
                    } else {
                        continue; // valid line, but not a blocking level
                    }
                }
            }
            // Format B: `desc : IPa - IPb` (level 0). Split on the LAST colon.
            if parsed.is_none() {
                if let Some(idx) = line.rfind(':') {
                    if let Some(range) = parse_range(&line[idx + 1..]) {
                        // level 0 blocks whenever the configured level is >= 1.
                        if level > 0 {
                            parsed = Some(range);
                        }
                    }
                }
            }
            if let Some(range) = parsed {
                blocking.push(range);
            }
        }
        Self::from_ranges(blocking)
    }

    /// Build from raw blocking ranges: sort by start, then coalesce overlapping
    /// or adjacent ranges so the union is a minimal non-overlapping set.
    fn from_ranges(mut ranges: Vec<(u32, u32)>) -> Self {
        ranges.sort_unstable();
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(ranges.len());
        for (start, end) in ranges {
            match merged.last_mut() {
                // Overlaps or touches the previous range (guard the +1 against
                // u32::MAX so adjacency near the top of the space cannot wrap).
                Some(last) if start <= last.1.saturating_add(1) => {
                    if end > last.1 {
                        last.1 = end;
                    }
                }
                _ => merged.push((start, end)),
            }
        }
        IpFilter { ranges: merged }
    }

    /// How many merged blocking ranges are loaded.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// True if `ip` (host-order u32) falls in a blocking range.
    pub fn is_blocked_u32(&self, ip: u32) -> bool {
        // Find the range with the greatest start <= ip and check its end. Safe
        // because the ranges are non-overlapping and sorted after merging.
        match self.ranges.binary_search_by(|&(s, _)| s.cmp(&ip)) {
            Ok(_) => true, // ip is exactly a range start
            Err(0) => false,
            Err(i) => {
                let (start, end) = self.ranges[i - 1];
                start <= ip && ip <= end
            }
        }
    }

    /// True if `ip` is blocked.
    pub fn is_blocked(&self, ip: Ipv4Addr) -> bool {
        self.is_blocked_u32(u32::from(ip))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dotted_quad_host_order() {
        assert_eq!(parse_ipv4("1.2.3.4"), Some(0x0102_0304));
        assert_eq!(parse_ipv4("0.0.0.0"), Some(0));
        assert_eq!(parse_ipv4("255.255.255.255"), Some(0xFFFF_FFFF));
        assert_eq!(parse_ipv4("256.0.0.0"), None); // octet out of range
        assert_eq!(parse_ipv4("1.2.3"), None); // too few
        assert_eq!(parse_ipv4("1.2.3.4.5"), None); // too many
    }

    #[test]
    fn ipfilter_dat_format_and_level() {
        // Two block ranges (level < 127) and one allow range (level 200, kept out).
        let text = "\
# a comment line
000.000.000.000 - 000.255.255.255 , 0 , reserved
10.0.0.0 - 10.0.0.255 , 100 , some bad range
200.200.200.200 - 200.200.200.255 , 200 , allowed (level too high)
";
        let f = IpFilter::parse(text, DEFAULT_IPFILTER_LEVEL);
        assert!(f.is_blocked("0.1.2.3".parse().unwrap()));
        assert!(f.is_blocked("10.0.0.7".parse().unwrap()));
        assert!(!f.is_blocked("10.0.1.0".parse().unwrap())); // just past the range
        assert!(!f.is_blocked("200.200.200.210".parse().unwrap())); // level 200, not blocking
        assert!(!f.is_blocked("8.8.8.8".parse().unwrap())); // not in any range
    }

    #[test]
    fn p2p_format_forces_level_zero_blocks() {
        let text = "Bad Actors Inc:5.6.7.0-5.6.7.255\nAnother\\:Weird : 9.9.9.9 - 9.9.9.9\n";
        let f = IpFilter::parse(text, DEFAULT_IPFILTER_LEVEL);
        assert!(f.is_blocked("5.6.7.128".parse().unwrap()));
        // The last colon is the split point, so the odd description is fine.
        assert!(f.is_blocked("9.9.9.9".parse().unwrap()));
        assert!(!f.is_blocked("5.6.8.0".parse().unwrap()));
    }

    #[test]
    fn overlapping_ranges_merge() {
        let text = "\
1.0.0.0 - 1.0.0.100 , 0 , a
1.0.0.50 - 1.0.0.200 , 0 , b overlaps a
1.0.0.201 - 1.0.0.255 , 0 , c is adjacent
";
        let f = IpFilter::parse(text, DEFAULT_IPFILTER_LEVEL);
        assert_eq!(f.len(), 1, "the three coalesce into one range");
        assert!(f.is_blocked("1.0.0.0".parse().unwrap()));
        assert!(f.is_blocked("1.0.0.150".parse().unwrap())); // inside the overlap
        assert!(f.is_blocked("1.0.0.255".parse().unwrap())); // the adjacent tail
        assert!(!f.is_blocked("1.0.1.0".parse().unwrap()));
    }

    #[test]
    fn empty_and_garbage_yield_no_blocks() {
        let f = IpFilter::parse("not an ip filter line at all\n\n#only comments\n", 127);
        assert!(f.is_empty());
        assert!(!f.is_blocked("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn level_zero_config_blocks_nothing() {
        // With configured level 0, NO range blocks (nothing has level < 0).
        let text = "1.0.0.0 - 1.255.255.255 , 0 , x\ndesc:2.0.0.0-2.0.0.255\n";
        let f = IpFilter::parse(text, 0);
        assert!(f.is_empty());
    }
}
