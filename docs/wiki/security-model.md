# Security Model + the "Bulletproof" Release Gate

Updated: 2026-08-01 (tally re-synced to the B6+B8 closures, commit 625df39)

RELEASE BLOCKER (Anthony, 2026-07-20; memory: [[security-bulletproof-release-gate]]):
before padMule ships to the community, security must be **BULLETPROOF** =
(1) every eMule/Kad spec-intended measure FULLY OPERATIONAL end-to-end (wired,
requested AND honored, both roles - not codec-present); (2) PLUS reasonable
NON-BURDENSOME hardening (interop-safe; degrades gracefully; never cuts the user
off from most peers/servers).

## SCORECARD (security-completeness audit, 2026-07-20)

A 26-measure adversarial audit (6 domain finders -> per-measure attacker ->
synthesis, 33 agents). Tally as of 2026-08-02: **19 OPERATIONAL, 4 PARTIAL,
3 MISSING**. History: the 2026-07-20 audit scored 11/12/3; B6 MOTD-flood + B8
SSRF closed it to 13/10/3 (commit 625df39); the 2026-08-01 security-hardening
batch (Kad receiver-key/verified-bit + ipfilter/sybil/answer-validation, per-part
poison recovery, per-IP inbound cap, inbound TCP obfuscation, search availability
cap) moved five more rows to OPERATIONAL (-> 18/5/3); the 2026-08-02 serve-side
secure-ident (build-progress 8af, commit 4d874e5) closed the last identification
gap - both roles now verify, oracle-proven (-> 19/4/3). Each change was
eMule-0.50a-grounded, test-first, and adversarially re-reviewed - see
[[build-progress]] rows 8ab / 8af.

**BOTTOM LINE: NOT yet bulletproof, but close.** No failure delivers a corrupt
file or RCE - the integrity core is OPERATIONAL + oracle-proven. The 4 remaining
PARTIAL rows are anti-impersonation/anti-leech COMPLETENESS (Kad verified-bit not
yet ENFORCED in routing; Kad send-side receiver keys; per-source corruption
attribution; AICH block recovery) - none is an integrity or RCE hole. Serve-side
secure-ident landed 2026-08-02 (8af). Shortest path to yes = the credit system
(wire the verified identity, now available both roles, into an upload-queue
reweight) + Kad hard-verify, all validated against the real-eMule/eserver oracles.

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
| Secure identification (RSA, both roles) | OPERATIONAL (2026-08-02) | BOTH roles now compute verified. Download side: oracle-proven vs amuled + real eMule, DoS-bounded (one RSA verify per connection). SERVE side (build-progress 8af, commit 4d874e5): padMule advertises sec-ident on the listener + drives the mutual exchange via `classify_inbound` (a bounded secure-ident DRAIN that re-applies the leecher-vs-source discriminator on the first NON-secident packet - the fix for the 8ac regression where a leading OP_SECIDENTSTATE broke the first-packet peek) + finishes verification interleaved with serving in `serve_shared`. Oracle-proven: the reverse oracle asserts padMule verified a REAL amuled 3.0.1 serve-side (byte-for-byte download + verified) - the [[interop-test-fidelity]] rule satisfied against a faithful other-side (a real downloader + a faithful mock LEECHER that INITIATES). NOTE: verification is currently OBSERVATIONAL - what padMule DOES with the verified identity (the credit reweight) is the separate "Credit system" row (still MISSING): serve-side verify feeds an on_verified sink that is a no-op in the engine today, to be wired to the credit store in the credits batch. Never-refuse holds: no ident outcome denies a slot or drops a connection. |
| TCP c2c obfuscation (RC4) | OPERATIONAL (2026-08-01) | outbound proven vs amuled; INBOUND obf now wired (obf_accept auto-detect) + listener advertises crypt-SUPPORTED (never REQUIRED) -> crypt-required peers reachable. Plaintext byte-identical (differential passes); live inbound-obf vs real eMule dialing us pending [[emule-peer-oracle]] |
| Kad UDP verify/sender keys | PARTIAL | RECEIVE side now computes bValidReceiverKey (== udp_verify_key(our_key, senderIP)) and sets the contact verified bit (2026-08-01); SEND side still emits receiver_vk=0 (no per-peer key store), so peers still see us unverified until we echo stored keys |
| Kad node-ID/IP verification + 2^120 | PARTIAL | tolerance proven; verified bit now TRACKED + persisted + set from the receiver key + CLEARED on any ip change (2026-08-01); still not ENFORCED (unverified contacts are used in routing) - hard exclusion needs the HELLO_RES_ACK challenge machinery |
| Kad anti-flood hardening | OPERATIONAL (2026-08-01) | sybil cap now 1/IP + 10//24 (matches eMule RoutingBin.cpp:56); a known id re-pointed to a new IP faces the cap (no free hijack). FloodTracker is N/A for a requests-only client (eMule exempts RESPONSE opcodes from its inbound flood limiter; padMule serves no inbound Kad requests) - documented, ready if a request-server is ever added |
| AICH part-level + block RECOVERY | PARTIAL | per-part MD4 blame + targeted re-fetch now live (localize_corruption, 2026-08-01), so integrity is safe without AICH; AICH master hash byte-valid; the 180KB block-recovery protocol (OP_AICHREQUEST) is a future OPTIMIZATION, not an integrity/interop gap. KEEP advertising the AICH bit: 0x34103212 is byte-verified against real aMule (which also advertises it), and an unanswered AICH request is NON-breaking - eMule calls ClientAICHRequestFailed and re-downloads the part (DownloadClient.cpp:2295), never disconnects/bans (verified 2026-08-01). Clearing the bit would DIVERGE from every real client for no benefit. |
| Poisoning defense (bad part re-fetchable) | PARTIAL | whole-file MD4 holds AND a bad part is now blamed per-MD4 and re-fetched alone (2026-08-01, closes the full-re-download loop); per-SOURCE attribution + ban (eMule CorruptionBlackBox) still absent |
| Search-result SPAM filter | OPERATIONAL (2026-08-01) | intra-hash heuristics + a spam-availability cap (Suspect rows ranked at min(sources,5), eMule SearchList.cpp:813). eMule's "cross-hash filename-repetition" is NOT a real 0.50a feature (audit correction); a padMule cross-hash score was built then REMOVED - it flagged legit files sharing a generic name (adversarial review finding) |
| Server MOTD/result FLOOD rate-limit | OPERATIONAL (B6 fixed 625df39) | forwarder now rate-limits server events 30/10s (State exempt); MOTD attributed + 500-char capped |
| Server-trust (source/IP sanity) | OPERATIONAL (B8 fixed 625df39) | PeerSource::from_found/from_kad now reject non-public IPv4 unconditionally (SSRF closed); LowID/port0 already rejected |
| ipfilter Kad UDP coverage | OPERATIONAL (2026-08-01) | the user blocklist now gates every Kad routing insert (kad_live::add_contact, matches eMule RoutingZone.cpp:477); inbound Kad UDP is only ever a reply from an IP we queried (from the now-filtered routing table) |
| Input safety: bounded inbound listener | OPERATIONAL (2026-08-01) | 200-permit global semaphore + a per-IP cap (16/IP, IpConnSlot) so one address cannot starve all permits; serve-session budget (60s idle / 120s queue) already present |
| Credit system (clients.met, ident-gated) | MISSING | dead code: FIFO gate, no accounting, clients.met never used |
| Server TCP obfuscation | MISSING | plaintext-only; OPT-IN anti-DPI, no server cut off (ship documented) |
| Server UDP obfuscation | MISSING | cleartext port+4; OPT-IN; low-burden partial via OP_GETSOURCES_OBFU |

## Release blockers (fix before community release)

REMAINING (after the 2026-08-01 batch): secure-ident SERVE side [LOW-MED, validate
vs [[emule-peer-oracle]]]; Kad verified-bit ENFORCEMENT in routing [MED, needs the
HELLO_RES_ACK challenge]; per-source corruption attribution + ban [MED]; AICH block
recovery [full HIGH, or clear the advertised bit]; credit system [MED-HIGH, or ship
documented as not-active]; server TCP/UDP obf [Band C, LOW-MED, opt-in - ship
documented, never REQUIRE].

CLOSED: server MOTD flood [B6, 625df39]; SSRF source drop [B8, 625df39]; TCP c2c
obf both-roles, ipfilter-into-Kad, per-IP inbound cap, Kad sybil caps + IP-change
hijack, Kad receiver-key -> verified bit, per-part poison recovery, search
availability cap (all 2026-08-01, [[build-progress]] row 8ab).

## Interop-safe hardening backlog (all degrade gracefully)

The Band A/B fixes above ARE the top hardening (each closes a blocker with a
LOW-burden internal change - no wire break, no peer cut off). Plus: random
per-request status-ping challenge; move ipfilter is_blocked to accept()-time
(the MOTD length-cap + "[server]" attribution landed with B6); and CI
regression guards that turn the code-only claims (secure-ident wire crypto,
whole-file finalize, ipfilter dial-block) into oracle-proven ones
(differential-test assertions + a parse fuzz target + a >200-conn/trickle
loopback test).

## Related

- [[security-bulletproof-release-gate]]
- [[padmule-protocol-landmines]] / [[padmule-kad-notes]]
- [[interop-test-fidelity]] (prove operation vs a faithful other-side)
- [[ed2k-server-oracle]] / [[padmule-amuled-oracle]] / [[emule-peer-oracle]]
- [[build-progress]]
