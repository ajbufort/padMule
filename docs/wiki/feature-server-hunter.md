# Feature: Server Hunter (future work)

Updated: 2026-07-13
Status: BACKLOG (post-core; parts are near-term, one part needs care)

Anthony wants a "Server Hunter" feature (2026-07-13): a tool that discovers and
verifies active eD2k servers to build a safe, working, live server list - by
analogy to old dial-up "war dialers" that dialed number ranges listening for a
modem tone, but with modern IP:port probing.

## The real goal (what we actually want)

A self-maintaining, VERIFIED, LIVE server list, so the user is never stuck with
a dead list (the exact problem we hit on 2026-07-13 - stale lists all failed
until we found a current one). Freshness + liveness + safety, discovered
automatically.

## How to build it responsibly (the smart version)

Achieve the goal WITHOUT indiscriminate internet-wide scanning, using the fact
that eD2k servers are PUBLIC services that WANT to be found and already gossip
about each other:

1. **Auto-update from a trusted URL (easy, do early).** Fetch `server.met` from
   a configured URL on startup and merge (eMule's `addresses.dat` model - a list
   of `server.met` URLs auto-updated each launch). Trusted default:
   `http://upd.emule-security.org/server.met` ([[ref-ecosystem]]). Low risk,
   high value; fits server-list management.
2. **Verify / health-check (easy, mostly built).** Probe each candidate
   `IP:port` by connecting + doing the login handshake (exactly `mule-cli
   login-any` today) and/or the UDP `OP_GLOBSERVSTATREQ` status ping; record
   uptime, users, files, ping. This IS the legitimate "Server Hunter"
   verification role - turn a candidate list into a ranked live list.
3. **Server-graph crawl (medium, the real discovery engine).** eD2k servers
   gossip their peer servers via `OP_SERVERLIST` (we already parse it) and
   answer UDP `OP_SERVER_LIST_REQ`/`OP_GLOBSERVSTATREQ`. Start from a few known
   servers, harvest their advertised servers, verify each, recurse. This
   discovers the actual live server graph efficiently and non-abusively -
   servers volunteer this data.
4. **Kad makes servers optional.** A healthy Kad node ([[protocol-understanding]]
   Part 4) needs no servers at all. "Server Hunter" is a nicety; Kad is the
   real resilience.

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

## Recommendation

Build 1 + 2 as part of server-list management (near-term; #2 is mostly
`login-any` already), and 3 as the "Server Hunter" discovery engine (post-core).
Treat literal whole-internet scanning as out of scope for the shipped product;
if Anthony still wants an experimental bounded scanner, gate it behind the
constraints above as a deliberate, separate, opt-in tool.

## Related

- [[ref-ecosystem]] - the trusted live server.met source.
- [[protocol-understanding]] - OP_SERVERLIST gossip + UDP server status; Kad.
- [[ipados-constraints]] - why mass scanning is infeasible on the target.
- [[build-progress]]
