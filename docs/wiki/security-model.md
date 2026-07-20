# Security Model + the "Bulletproof" Release Gate

Updated: 2026-07-20 (security-completeness audit run - SCORECARD below)

RELEASE BLOCKER (Anthony, 2026-07-20; memory: [[security-bulletproof-release-gate]]):
before padMule ships to the community, security must be **BULLETPROOF** =
(1) every eMule/Kad spec-intended measure FULLY OPERATIONAL end-to-end (wired,
requested AND honored, both roles - not codec-present); (2) PLUS reasonable
NON-BURDENSOME hardening (interop-safe; degrades gracefully; never cuts the user
off from most peers/servers).

## SCORECARD (security-completeness audit, 2026-07-20)

A 26-measure adversarial audit (6 domain finders -> per-measure attacker ->
synthesis, 33 agents). Tally: **11 OPERATIONAL, 12 PARTIAL, 3 MISSING**.
Full adversarial detail: workflow wf_231184f5-a1b transcript.

**BOTTOM LINE: NOT yet bulletproof.** BUT no failure delivers a corrupt file or
RCE - whole-file ed2k MD4, ipfilter, hash-keyed transfers, and the OOM/parse
hardening are genuinely OPERATIONAL + oracle-proven. The gaps are
anti-impersonation/anti-leech completeness + two reachable DoSes + routing/SSRF
poison vectors. Shortest path to yes = the Band A/B fixes (almost all LOW burden,
~a week) + convert code-only claims to oracle-proven; the credit system is the one
larger item (build, or ship documented as not-yet-active).

| Measure | Status | Note |
|---------|--------|------|
| Kad UDP obfuscation | OPERATIONAL | wired every send/recv, live-proven vs real Kad |
| ed2k whole-file hash verify | OPERATIONAL | oracle-proven vs amuled; fails closed (finalize wiring untested) |
| Server status-ping challenge | OPERATIONAL | drop-on-wrong enforced, live vs eserver (challenge is a fixed const - LOW) |
| Client search throttle | OPERATIONAL | 2s guard, graceful degrade |
| ipfilter OUTBOUND | OPERATIONAL | gates server+Kad sources before dial |
| ipfilter INBOUND (post-handshake) | OPERATIONAL | every serve/download path downstream of is_blocked |
| ipfilter parse robustness | OPERATIONAL | bounded, fail-closed |
| Input safety: untrusted-count OOM | OPERATIONAL | grow+EOF under a 2MB cap (readiness audit) |
| Input safety: trapping casts | OPERATIONAL | Int64(clamping:) + widening/checked casts |
| Input safety: no hostile-peer crash/OOM/hang | OPERATIONAL | bounds+timeout-checked parse paths (not fuzz-proven) |
| Privacy: no public-IP/client-id leak | OPERATIONAL | id never Debug-formatted into UI (audit fix) |
| Secure identification (RSA, both roles) | PARTIAL | download-side computes verified (crypto UNPROVEN vs independent impl); SERVE side does none - serves stolen-userhash peers |
| TCP c2c obfuscation (RC4) | PARTIAL | outbound-initiator proven once; INBOUND obf absent + HELLO advertises crypt-unsupported -> crypt-required peers unreachable both ways |
| Kad UDP verify/sender keys | PARTIAL | derivation proven; receive-side IP-verification absent (receiver_vk=0 always) -> forged-response window |
| Kad node-ID/IP verification + 2^120 | PARTIAL | tolerance proven; per-contact IP-verified bit absent -> forged (KadID,IP) seeds lookups |
| Kad anti-flood hardening | PARTIAL | per-IP//24 sybil cap wired; FloodTracker dead; caps looser than eMule |
| AICH part-level + block RECOVERY | PARTIAL | master hash byte-valid but DEAD; no per-part MD4; recovery unimplemented; AICH bit advertised-then-dropped |
| Poisoning defense (bad part re-fetchable) | PARTIAL | whole-file MD4 holds, but no per-part verify + no source attribution -> one bad source = full re-download loop / stall |
| Search-result SPAM filter | PARTIAL | intra-hash heuristics only; eMule's cross-hash filename-repetition defense absent |
| Server MOTD/result FLOOD rate-limit | PARTIAL | forwards into an UNBOUNDED events channel -> memory-exhaustion DoS via auto get_sources |
| Server-trust (source/IP sanity) | PARTIAL | LowID/port0 rejected, no reserved/loopback/LAN guard -> SSRF-lite localhost/LAN probe on fresh install |
| ipfilter Kad UDP coverage | PARTIAL | routing inserts + inbound Kad UDP NOT ipfiltered -> blocklisted ranges poison routing |
| Input safety: bounded inbound listener | PARTIAL | 200-permit semaphore but no per-IP cap + no serve-session budget -> one IP starves all permits |
| Credit system (clients.met, ident-gated) | MISSING | dead code: FIFO gate, no accounting, clients.met never used |
| Server TCP obfuscation | MISSING | plaintext-only; OPT-IN anti-DPI, no server cut off (ship documented) |
| Server UDP obfuscation | MISSING | cleartext port+4; OPT-IN; low-burden partial via OP_GETSOURCES_OBFU |

## Release blockers (fix before community release)

Band A (HIGH): TCP c2c obf both-roles [LOW], secure-ident SERVE side [LOW-MED],
per-part verify + poison recovery in the engine [LOW], AICH block recovery
[per-part LOW / full HIGH, or clear the advertised bit], credit system [MED-HIGH
or document as not-active]. Band B (MED, mostly LOW fix): server MOTD flood DoS,
inbound per-IP cap + serve-session budget, reserved/loopback/LAN source drop
(SSRF), Kad node-ID/IP verified bit, Kad receiver-verify-key, ipfilter into the
Kad path, cross-hash spam score [MED], tighten Kad sybil caps + wire/delete
FloodTracker. Band C (LOW, opt-in): server TCP/UDP obf - ship documented.

## Interop-safe hardening backlog (all degrade gracefully)

The Band A/B fixes above ARE the top hardening (each closes a blocker with a
LOW-burden internal change - no wire break, no peer cut off). Plus: random
per-request status-ping challenge; move ipfilter is_blocked to accept()-time;
length-cap + "[server]" attribution on MOTD; and CI regression guards that turn
the code-only claims (secure-ident wire crypto, whole-file finalize, ipfilter
dial-block) into oracle-proven ones (differential-test assertions + a parse fuzz
target + a >200-conn/trickle loopback test).

## Related

- [[security-bulletproof-release-gate]]
- [[padmule-protocol-landmines]] / [[padmule-kad-notes]]
- [[interop-test-fidelity]] (prove operation vs a faithful other-side)
- [[ed2k-server-oracle]] / [[padmule-amuled-oracle]] / [[emule-peer-oracle]]
- [[build-progress]]
