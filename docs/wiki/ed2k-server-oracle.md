# eD2k server oracle (real Lugdunum eserver, sandboxed)

Updated: 2026-07-19

The SERVER-side oracle, completing the set: padMule can now be tested against the
REAL software the whole eD2k network runs on - **Lugdunum eserver 17.15**, the
reverse-engineered eDonkey2000 server (closed-source, discontinued 2007) - run
LOCALLY and fully ISOLATED. This is what makes #9 (global server UDP search) and
any server-protocol work testable against a real server rather than a mock we
author (which the SX-record lesson warns can be consistently-wrong-together).

Oracles now: amuled (peer, differential-test.sh), real eMule (peer,
[[emule-peer-oracle]]), and this - real eserver (server).

## Run it

```bash
cargo build --release -p mule-cli
scripts/eserver-oracle.sh                       # start eserver + padMule login
scripts/eserver-oracle.sh login 127.0.0.1 4661  # or any mule-cli subcommand
```

The script obtains + sha256-verifies the binary (first run), writes a loopback
`donkey.ini`, and runs EVERYTHING inside `unshare -rn`. PROVEN working: padMule
logs into eserver and gets `Connected { id: 2, low_id: true }` plus eserver's own
"your ip 0.0.0.0 ends with a 0 -> LOWID" message - a complete, correct server
exchange against the real thing. (LowID is correct: padMule has no routable IP
inside the isolated namespace.)

## SECURITY: the binary is untrusted, so it runs with zero egress

eserver is a legacy (2007) closed-source third-party binary from a mirror. It is
run inside an unprivileged network namespace (`unshare -rn`) whose ONLY interface
is loopback - external egress is physically impossible (an egress probe fails
"Network is unreachable", verified in the script's own output). So even a hostile
binary cannot phone home or reach the LAN; padMule (run in the same namespace)
reaches it on 127.0.0.1. The binary is NOT committed - it lives gitignored under
`build-oracle/eserver/`.

Provenance: `https://www.emule-security.org/downloads/100` (the same site padMule
already trusts for `server.met`) -> `lugdunum_eserver_17.15_linux.zip`.
- zip sha256:    `e518451a619edef5eb8aab1486715fab6364bacd9fc79a47a5d45b77250b47ea`
- eserver-i686:  `fe38ecdf7165badf0ca47185e6aff813e4c0b074b48f7fc4094231b5303b6f55`
- eserver-x86_64:`82d190179bb64a3806659f47344102840de919c011fd0cab5bda251308e72ed7`

## The 32-bit gotcha (why i686, not x86_64)

The x86_64 build SIGSEGVs at startup: `segfault at ffffffffff600400 ip
ffffffffff600400` - it calls `time()` via the legacy **vsyscall** page, which
modern kernels (WSL2 6.6, no `vsyscall=emulate` on the cmdline) block. The i686
build does not use the x86_64 vsyscall page and runs fine under WSL2's IA32
emulation, so the oracle uses `eserver-i686`. (To run the x86_64 build instead,
Anthony would set `[wsl2] kernelCommandLine = vsyscall=emulate` in `.wslconfig`
and `wsl --shutdown`; not needed - i686 works.)

## What it validates / next

- DONE: server connect - login, ID assignment (LowID here), server messages,
  pause/resume reconnect - all against real eserver.
- DONE: #9 global server UDP search - `mule-cli global-search 127.0.0.1:4661
  <kw>` sends OP_GLOBSEARCHREQ to the UDP port (TCP+4 = 4665) and parses
  OP_GLOBSEARCHRES; eserver accepts it.
- DONE: OP_OFFERFILES - `mule-cli offer-hold 127.0.0.1 4661 "<name[|name...]>"`
  logs in + announces one or more files ('|'-separated = one shared library in a
  single OP_OFFERFILES); eserver INDEXES them ("N files, N complete, M keyw" in
  its `g` stats). This makes eserver a DETERMINISTIC SEARCH oracle. The self-filter
  is by USER HASH, not IP: `offer-search` (offer + search from ONE client, same
  demo hash) shows the file indexed but not returned, BUT a full offer->find works
  fine on the same loopback IP when the offerer and searcher have DIFFERENT user
  hashes - no separate IP needed.
- DONE (2026-07-19): full offer->FIND search oracle, via `scripts/simulate.sh`.
  It launches ONE background `offer-hold` seeder (demo hash) holding a 3-file
  library named with the keyword, then runs the FFI `simulate` engine (a distinct
  user hash) which PROBES + connects + searches. Live: the status probe reports
  users=1 files=3 alive=true (the OP_GLOBSERVSTATREQ challenge fix, commit
  05fbe5a) and SEARCH returns the 3 real typed sourced results. Boolean `NOT` and
  UDP global search return 0 from THIS server - padMule's boolean encoding is
  byte-identical to eMule 0.50a (ops 00 00 / 00 01 / 00 02, string 01, prefix
  order), so those are Lugdunum server-side evaluation quirks, not padMule bugs.
  `KEEP_LOG=1 scripts/simulate.sh` persists the eserver log out of the namespace.
- DONE: #10 related-files search - `mule-cli related-search 127.0.0.1 4661
  <hash>` logs in and sends `related::<UPPERHEX>` (a normal OP_SEARCHREQUEST).
  PROVEN: the real eserver ADVERTISES SRV_TCPFLG_RELATEDSEARCH (0x40) - padMule
  read `related_search: true` straight off the live server - AND accepted the
  `related::` query without error. (No hits: an empty single-client server has
  no co-occurrence index, and the self-filter caveat above applies - a returned
  related hit needs the searcher on a different IP than the offerer.) So the flag
  read + query acceptance are live-validated; a populated related result is not
  reproducible in the single-IP isolated setup.
- HighID would need a routable IP + callback; the isolated loopback setup gives
  LowID, which is a complete protocol exchange regardless.

## Related

- [[emule-peer-oracle]]
- [[padmule-amuled-oracle]]
- [[interop-test-fidelity]]
- [[ref-source-trees]]
