# Feature: Server Hunter (future work)

Updated: 2026-08-03 (the RECURSIVE UDP CRAWL shipped and live-proven - the
Server Hunter is now feature-complete as designed)
Status: ALL FOUR PARTS SHIPPED. Part 1 multi-URL lists + gzip/zip unwrap; part 2
the UDP health probe; part 3 the gossip crawl (harvest-on-connect + the
OP_GETSERVERLIST ask); part 4 the RECURSIVE UDP crawl (2026-08-03). Whole-net
scanning remains deliberately out of scope (below).

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
  silent without the ask on the device pass. 537 tests. **DEVICE-VERIFIED
  same day (fff31dc install, agent-driven):** connecting to that server on
  the iPad produced "Discovered 24 server(s) from the network" and the
  Servers table grew 10 -> 34 rows after a refresh - the whole gossip loop
  (ask -> answer -> filter -> merge -> UI) working on glass.
- **Part 4: the RECURSIVE UDP CRAWL SHIPPED (2026-08-03) - the discovery engine
  is complete.** Where the harvest learns only from the ONE server we logged
  into, the crawl asks servers we are NOT connected to, over UDP, and then asks
  the ones that answer - the "server-graph crawl" of item 3 below.
  `Engine::crawl_servers(rounds)`, driven from a "Discover more servers" button
  on the Servers screen and `mule-cli server-crawl <server.met> [rounds]`.
  **WIRE, and the deviation:** the ask is `OP_SERVER_LIST_REQ2` (0xA4,
  bodiless) to UDP TCP+4; the answer `OP_SERVER_LIST_RES` (0xA1) has a payload
  byte-identical to TCP OP_SERVERLIST, so `parse_server_list` reads both and no
  second parser exists. NO CLIENT AUTHORITY SENDS 0xA4 - eMule 0.50a
  (opcodes.h:205) and aMule (UDP.h:46) DEFINE the pair but never send or parse
  it, sending only 0x96/0xA2 on this socket. padMule sends it because many
  SERVERS answer, which was MEASURED rather than assumed - and the obvious guess
  was WRONG: the vendored **Lugdunum eserver 17.15 oracle does NOT answer 0xA4**
  (nor does `ed2k-rust`, nor eMule Sunrise), yet a live crawl had 28 of 33 asked
  servers answer. Every silent server answered 0x96 and 0xA2 in the same burst,
  so the silence is a real negative, not a dead host. **SILENCE IS THEREFORE A
  NORMAL ANSWER** and is never treated as an error or a liveness verdict.
  **Safety** (this is the one path that contacts hosts the user never chose):
  bounded to 3 rounds / 40 asks per round / a 40ms send pace / a 4s collection
  budget / 1000 discovered total; the user ipfilter gates who is SENT to, not
  just what is kept; only routable public addresses are ever asked or merged
  (the B8 SSRF posture); answers are accepted ONLY from an address we just asked
  (anti-spoof, as the global UDP search does); and the merge reuses the ONE
  shared gate `merge_discovered_servers`, which the connect-time harvest also
  uses, so the rule cannot drift between the two channels. The abuse profile is
  deliberately no worse than the Servers screen's existing status probe, which
  already sends every known server a datagram. **LIVE-PROVEN 2026-08-03:** from
  the 10-server published list, a 2-round crawl asked 33, had 28 answer, and
  added 25 new servers (10 -> 35); a 3-round run reached 35 asked / 29 answered
  and converged on the same 25, i.e. the reachable graph from that seed is
  small and the crawl terminates rather than running away. The merged result was
  audited byte-by-byte: ZERO private, loopback, multicast, reserved or port-0
  entries, and one discovered address matched an independent raw-Python probe of
  the same server exactly. Structure follows `mule_kad::lookup`: a PURE
  `server_crawl::ServerCrawl` state machine (frontier, dedup, ceiling, the
  recursion) unit-tested offline and MUTATION-CHECKED, with a thin I/O driver;
  the SSRF posture is additionally asserted on the production entry point, since
  a test of the helper would not prove the caller consults it.
- **Discovered servers now learn their NAME (2026-08-03).** Anthony caught the
  gap immediately: discovery yields only `ip:port`, so every harvested or
  crawled server rendered as a bare address while the published-list entries
  had names. Fixed with plain parity rather than an invention - BOTH authorities
  fire `OP_SERVER_DESC_REQ` (0xA2) right after a status answer (eMule
  `UDPSocket.cpp:435`, aMule `ServerUDPSocket.cpp:243`), so `probe_server_list`
  now sends it alongside the existing status ping and adopts the returned name.
  The answer has TWO forms sharing one opcode, both handled: the OLD
  `<name_len u16><name><desc_len u16><desc>`, and the eserver-16.45+ tagged
  `<challenge u32><tagcount u32><tags>` (ST_SERVERNAME 0x01 / ST_DESCRIPTION
  0x0B) - told apart by the first u16 being the deliberately INVALID length
  `INV_SERV_DESC_LEN` 0xF0FF, which is exactly why eMule builds its challenge as
  `(random << 16) | 0xF0FF`. A tagged answer whose challenge does not match ours
  is refused (anti-stale/spoof). A learned name is PERSISTED into server.met as
  tag 0x01 and never overwrites a name the user's own list already carries, so
  it also fixes the connected status line for a discovered server. LIVE: after
  a crawl, **33 of 35 servers have names** - Drunken Donkey, Astra-3/4/5, Akteon
  Server No3/No8, Holy Donkey 1/2/3, Pentium Pilat 2022/2023, eMule Security,
  Gaal and the rest - the only two unnamed being the two that answered nothing
  at all. `mule-cli server-crawl` now probes after crawling, mirroring the app's
  crawl -> reload sequence, and prints the named table.

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
