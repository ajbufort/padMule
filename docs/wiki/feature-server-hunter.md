# Feature: Server Hunter (future work)

Updated: 2026-08-03 (the OP_GETSERVERLIST ask SHIPPED and LIVE-PROVEN - the
gossip harvest is no longer inert)
Status: PARTS 1-2 SHIPPED; part 1 EXTENDED to multi-URL 2026-08-03; gzip-wrapped
lists SHIPPED; part-3 gossip crawl LIVE (harvest-on-connect + the
OP_GETSERVERLIST ask); the recursive UDP crawl is the remaining future work.

## Progress (2026-08-03)

- **Part 1 (auto-update from a trusted URL) SHIPPED and now EXTENDED to eMule's
  full `addresses.dat` model**: the Settings screen holds a LIST of server.met
  URLs, and `updateAllServerLists` fetches + merges each. The engine's
  `merge_server_met` keeps existing entries and appends only new (ip,port)s, so
  several lists accumulate into one comprehensive set. NB `server.met` is a single
  shared format - eMule and aMule both read/write it and the published lists are
  the same files, so there is no eMule-vs-aMule list to reconcile (Anthony asked;
  verified in `mule-files/src/server_met.rs`, which accepts headers 0xE0 AND the
  legacy 0x0E).
- **Part 2 (verify/health-check) SHIPPED** as the 8x Servers screen UDP probe.
- **gzip/zip-wrapped lists SHIPPED (2026-08-03)**: `bootstrap::maybe_decompress`
  runs inside `http_get_bytes`, so EVERY fetched list (and nodes.dat) is
  transparently unwrapped before parsing - gzip (`server.met.gz`, the common
  case) and single-entry ZIP (stored + deflate). Bounded to 32 MiB out to refuse
  a decompression bomb from a user-entered URL; anything unrecognised or malformed
  falls through to the raw bytes, which the validator then rejects cleanly. So a
  gzipped list is no longer silently excluded from "comprehensive".
- **Part 3 gossip crawl - FIRST CUT SHIPPED (2026-08-03), harvest-on-connect.**
  The gap was precise: a connected server VOLUNTEERS its known servers via
  OP_SERVERLIST during the connect burst, padMule already parsed it into
  `ServerEvent::ServerList`, and the engine then DROPPED it with a cosmetic
  "N servers known" notice (engine.rs:925). Now the forwarder stashes those
  advertised (ip,port)s and the 1s heartbeat merges them into server.met via the
  existing `merge_server_met` (`Engine::maintain_server_harvest`). So simply
  CONNECTING to a server teaches padMule about servers in no published list -
  the responsible answer to the "hidden servers" question, since the servers
  volunteer the data. No scanning, no new sockets, no recursion. Safety: the
  merge filters to routable public ip:port and honors the user ipfilter (a server
  advertising 127.0.0.1 / a LAN / a blocked address is dropped, else the UDP probe
  would later point at our own network - the B8 SSRF posture); the pending queue
  is bounded (2000) against a flood; runs on the engine task, so no server.met
  write races update_server_list. STILL FOLLOW-UP work, honestly scoped: (a) we
  ACCEPT what a server offers but do not yet SEND OP_GETSERVERLIST to ask (eMule
  gates that on an "update list when connecting" pref). **DEVICE PASS 2026-08-03
  PROVED THIS IS REQUIRED, not optional:** connected HighID to a real Lugdunum
  server (ed2k-rust) and NO OP_SERVERLIST arrived (no "servers known" notice, no
  merge) - modern servers do NOT volunteer the list on connect, you must ask.
  So the harvest-on-connect cut is correct but INERT against real servers until
  the OP_GETSERVERLIST send lands; that is now the immediate next step, not a
  nicety. [SHIPPED same day - next bullet.] (b) the RECURSIVE UDP crawl (harvest
  from servers we are NOT connected to, verify, recurse) is the fuller "crawl"
  and remains unbuilt. Whole-net scanning stays out of scope (below).
- **The OP_GETSERVERLIST ask SHIPPED (2026-08-03) - part 3 is LIVE.** A fresh
  login now sends the bodiless OP_GETSERVERLIST (0x14) right after the shares
  offer, exactly where BOTH authorities send it (eMule 0.50a sockets.cpp:253-260,
  aMule ServerConnect.cpp:289-296), on connect AND on resume (a resume is a
  fresh login). Gated on eMule's AddServersFromServer pref, exposed in Settings
  as "Ask connected servers for more servers"; both authorities DEFAULT it OFF
  (eMule Preferences.cpp:2105, aMule Preferences.cpp:1175) - padMule defaults it
  ON as a DELIBERATE documented deviation (wire bytes + timing identical; the
  merge is filtered + bounded; a default-off pref would keep this feature inert
  on every fresh install). Also fixed alongside: the event forwarder now stashes
  a ServerList BEFORE its flood limiter, so an answer arriving inside a busy
  connect burst can never be silently dropped (regression-tested RED-first).
  **LIVE-PROVEN both ways:** the isolated Lugdunum eserver accepts the ask
  cleanly through a full pause/resume lifecycle (it advertises nothing - it
  knows no other servers), and a REAL public server answered with
  `[serverlist] 33 servers` on a HighID login - the exact list that stayed
  silent without the ask on the device pass. 537 tests.

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
