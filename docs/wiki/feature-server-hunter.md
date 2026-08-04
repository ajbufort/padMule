# Feature: Server Hunter (future work)

Updated: 2026-08-04 (narrative + design split verbatim to
[[feature-server-hunter-history]]; the scope boundary stays here. 2026-08-03: the
RECURSIVE UDP CRAWL shipped and live-proven - the
Server Hunter is now feature-complete as designed)
Status: ALL FOUR PARTS SHIPPED. Part 1 multi-URL lists + gzip/zip unwrap; part 2
the UDP health probe; part 3 the gossip crawl (harvest-on-connect + the
OP_GETSERVERLIST ask); part 4 the RECURSIVE UDP crawl (2026-08-03). Whole-net
scanning remains deliberately out of scope (below).

## Status: COMPLETE

All four parts shipped and were device-verified 2026-08-03 (10 seeds -> 35
servers, 32 of them named): multi-URL server lists with gzip/zip unwrap, the
UDP health probe, the gossip crawl (harvest-on-connect plus the
OP_GETSERVERLIST ask), and the RECURSIVE UDP crawl.

The per-part narrative and the pre-build design rationale moved verbatim to
[[feature-server-hunter-history]] on 2026-08-04. The scope boundary below did
NOT move: it is a standing decision, and it is the thing to read before anyone
proposes a scanner.

## Why NOT literal "scan the whole net" (push-back, for the record)

The war-dialer analogy breaks down, and this part needs a deliberate decision -
do not build it by default:

- **Scale.** Phone-number war-dialing worked because the space was small and
  dense. IPv4 is ~4 billion addresses; scanning it for a handful of eD2k ports
  is masscan/zmap-class INFRASTRUCTURE (raw-socket SYN flooding at line rate),
  not an app feature. IPv6 is entirely unscannable by brute force.
- **iOS can't do it.** iOS gives no raw/SYN sockets; you would be doing ~4e9
  full `connect()` calls - impossible within battery, memory (jetsam), fd
  limits, and time on an iPad. Foreground-only ([[ipados-constraints]]) makes it
  worse.
- **Abuse / legal.** Indiscriminate internet-wide port scanning draws abuse
  complaints, gets the source IP flagged/null-routed by ISPs, and is legally
  gray-to-prohibited in many jurisdictions and under many ISP ToS. It would harm
  the very user running it.
- **Unnecessary.** Options 1-3 above already find every live PUBLIC server (they
  advertise themselves); a blind scan mostly finds nothing new.

If a bounded discovery scan is ever wanted, constrain it hard: opt-in only, only
the known eD2k port set, only user-supplied CIDR ranges (never 0.0.0.0/0),
strict rate limiting, clear legal warning, and never on cellular. Even then,
prefer options 1-3.

## Related

- [[feature-server-hunter-history]] - the shipped narrative + pre-build design,
  split out verbatim 2026-08-04.
- [[ref-ecosystem]] - the trusted live server.met source.
- [[protocol-understanding]] - OP_SERVERLIST gossip + UDP server status; Kad.
- [[ipados-constraints]] - why mass scanning is infeasible on the target.
- [[build-progress]]
