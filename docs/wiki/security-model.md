# Security Model + the "Bulletproof" Release Gate

Updated: 2026-08-02 (wave-10 Batch B landed - the Kad verified bit is ENFORCED,
23/1/2; send-side terminal proof 7e8fe9c; credit + poisoning rows OPERATIONAL per
8ag-8ai; row notes re-synced in the 2026-08-02 reanalysis lint)

RELEASE BLOCKER (Anthony, 2026-07-20; memory: [[security-bulletproof-release-gate]]):
before padMule ships to the community, security must be **BULLETPROOF** =
(1) every eMule/Kad spec-intended measure FULLY OPERATIONAL end-to-end (wired,
requested AND honored, both roles - not codec-present); (2) PLUS reasonable
NON-BURDENSOME hardening (interop-safe; degrades gracefully; never cuts the user
off from most peers/servers).

## SCORECARD (security-completeness audit, 2026-07-20)

A 26-measure adversarial audit (6 domain finders -> per-measure attacker ->
synthesis, 33 agents). Tally as of 2026-08-02: **23 OPERATIONAL, 1 PARTIAL,
2 DOCUMENTED opt-outs** (credit-system row: MISSING -> PARTIAL when its store
landed, 8ag, -> OPERATIONAL with the reweight + download accrual, 8ah;
poisoning-defense row -> OPERATIONAL with per-source corruption attribution + ban,
8ai; Kad verify/sender-keys -> OPERATIONAL when 8ak closed the search-path
key-capture gap on top of the wave-10 terminal proof; the two server-obfuscation
rows moved MISSING -> DEFERRED-documented, a deliberate interop-safe v1 opt-out
recorded in [[obfuscation-posture]]). The 1 remaining PARTIAL is AICH completeness (block recovery), an
OPTIMIZATION rather than an integrity gap. History: the 2026-07-20 audit
scored 11/12/3; B6 MOTD-flood + B8
SSRF closed it to 13/10/3 (commit 625df39); the 2026-08-01 security-hardening
batch (Kad receiver-key/verified-bit + ipfilter/sybil/answer-validation, per-part
poison recovery, per-IP inbound cap, inbound TCP obfuscation, search availability
cap) moved five more rows to OPERATIONAL (-> 18/5/3); the 2026-08-02 serve-side
secure-ident (build-progress 8af, commit 4d874e5) closed the last identification
gap - both roles now verify, oracle-proven (-> 19/4/3); the credit store +
reweight/accrual (8ag/8ah) took the credit row to OPERATIONAL (-> 20/4/2); the
per-source corruption ban (8ai) closed the poisoning row (-> 21/3/2); the
reanalysis fix round (8ak) closed the Kad send-side key-capture gap (-> 22/2/2);
wave-10 Batch B (8ao, commit 5ef4c2e) ENFORCED the Kad verified bit in routing,
closing the Kad node-ID/IP row (-> 23/1/2).
Each change was eMule-0.50a-grounded, test-first, and adversarially re-reviewed -
see [[build-progress]] rows 8ab / 8af-8ak.

**BOTTOM LINE: NOT yet bulletproof, but very close.** No failure delivers a corrupt
file or RCE - the integrity core is OPERATIONAL + oracle-proven. Serve-side
secure-ident (8af) AND the full credit system (8ag store + 8ah reweight/accrual)
landed 2026-08-02, closing the whole anti-impersonation/anti-leech identity+credit
axis, and per-source corruption attribution + ban (8ai) closed the poisoning row.
The 1 remaining PARTIAL row is AICH block recovery, an OPTIMIZATION rather than an
integrity gap (per-part MD4 + the poisoning ban already carry integrity). The send-side "a real eMule verifies
us" claim IS now faithfully proven: the wave-10 build landed the per-contact key
store + echo (3bf0162, 9c12e88), completed the v8 HELLO_RES_ACK handshake
(65a186b), and a log-patched REAL amuled Kad oracle ([[kad-verify-oracle]],
commit 7e8fe9c) observed VerifyContact fire for padMule reproducibly. Server
TCP/UDP obfuscation is a DELIBERATE, documented v1 opt-out
([[obfuscation-posture]]): opt-in anti-DPI, never REQUIRED, cuts off no server -
not a gap, a choice.
Wave-10 Batch B LANDED 2026-08-02 (commit 5ef4c2e), so the Kad hard-verify pair is
complete: the verified bit is now ENFORCED in routing, not merely tracked. What is
left before "yes" is no longer a protocol gap - it is AICH block recovery
(an optimization) plus the standing bar of re-proving the whole set against the
oracles before release.

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
| Secure identification (RSA, both roles) | OPERATIONAL (2026-08-02) | BOTH roles now compute verified. Download side: oracle-proven vs amuled + real eMule, DoS-bounded (one RSA verify per connection). SERVE side (build-progress 8af, commit 4d874e5): padMule advertises sec-ident on the listener + drives the mutual exchange via `classify_inbound` (a bounded secure-ident DRAIN that re-applies the leecher-vs-source discriminator on the first NON-secident packet - the fix for the 8ac regression where a leading OP_SECIDENTSTATE broke the first-packet peek) + finishes verification interleaved with serving in `serve_shared`. Oracle-proven: the reverse oracle asserts padMule verified a REAL amuled 3.0.1 serve-side (byte-for-byte download + verified) - the [[interop-test-fidelity]] rule satisfied against a faithful other-side (a real downloader + a faithful mock LEECHER that INITIATES). [SUPERSEDED 2026-08-02 by 8ag/8ah: verification is no longer observational - the on_verified sink binds the peer's key in the live credit store, and the score-ordered UploadGate consumes the verified-gated score; see the now-OPERATIONAL "Credit system" row.] Never-refuse holds: no ident outcome denies a slot or drops a connection. |
| TCP c2c obfuscation (RC4) | OPERATIONAL (2026-08-01) | outbound proven vs amuled; INBOUND obf now wired (obf_accept auto-detect) + listener advertises crypt-SUPPORTED (never REQUIRED) -> crypt-required peers reachable. Plaintext byte-identical (differential passes); live inbound-obf vs real eMule dialing us pending [[emule-peer-oracle]] |
| Kad UDP verify/sender keys | OPERATIONAL (2026-08-02) | RECEIVE side computes bValidReceiverKey (== udp_verify_key(our_key, senderIP)) and sets the contact verified bit (2026-08-01). SEND side landed in wave 10: per-contact key store + IP-gated echo (3bf0162, 9c12e88) and the completed v8 HELLO_RES_ACK handshake (65a186b), TERMINAL-PROVEN - a log-patched real amuled marks padMule IP-verified via VerifyContact ([[kad-verify-oracle]], 7e8fe9c, now 3/3 first-attempt). The last gap closed in 8ak (commit 2ab7800): EVERY answered request records the responder through one `note_responder` path, so the two search paths no longer discard the peer's sender key (a search-only node used to be permanently un-echoable). |
| Kad node-ID/IP verification + 2^120 | OPERATIONAL (2026-08-02) | tolerance proven; verified bit TRACKED + persisted + set from the receiver key + CLEARED on any ip change (2026-08-01); ENFORCED since wave-10 Batch B (2026-08-02, commit 5ef4c2e): closest_to hands out ONLY IP-verified contacts, exactly as eMule's CRoutingBin::GetClosestTo does unconditionally (RoutingBin.cpp:244), plus IsAcceptableContact's companion rule - an answer naming an already-verified KadID at a different ip/port is refused (RoutingZone.cpp:1014-1020). Proven live: with the gate ON, bootstrap and a real Kad keyword search both still work (bootstrap does not seed from closest_to, and every node that answers becomes verified) |
| Kad anti-flood hardening | OPERATIONAL (2026-08-01) | sybil cap now 1/IP + 10//24 (matches eMule RoutingBin.cpp:56); a known id re-pointed to a new IP faces the cap (no free hijack). FloodTracker is N/A for a requests-only client (eMule exempts RESPONSE opcodes from its inbound flood limiter; padMule serves no inbound Kad requests) - documented, ready if a request-server is ever added |
| AICH part-level + block RECOVERY | PARTIAL | per-part MD4 blame + targeted re-fetch now live (localize_corruption, 2026-08-01), so integrity is safe without AICH; AICH master hash byte-valid; the 180KB block-recovery protocol (OP_AICHREQUEST) is a future OPTIMIZATION, not an integrity/interop gap. KEEP advertising the AICH bit: 0x34103212 is byte-verified against real aMule (which also advertises it), and an unanswered AICH request is NON-breaking - eMule calls ClientAICHRequestFailed and re-downloads the part (DownloadClient.cpp:2295), never disconnects/bans (verified 2026-08-01). Clearing the bit would DIVERGE from every real client for no benefit. |
| Poisoning defense (bad part re-fetchable) | OPERATIONAL (2026-08-02) | whole-file MD4 holds; a bad part is blamed per-MD4 and re-fetched alone (8ab); AND the SOURCE that delivered a bad part is now attributed + BANNED for that file (8ai, eMule CorruptionBlackBox). SOLE-contributor rule = a good source is never false-banned (a part fed by >1 source blames nobody, since without AICH block hashes we cannot pinpoint the bad block). LIMITATION: an attacker sharing every poisoned part with a good source evades the ban (finer attribution needs the deferred AICH block recovery) - strictly better than no attribution, never false-positives. |
| Search-result SPAM filter | OPERATIONAL (2026-08-01) | intra-hash heuristics + a spam-availability cap (Suspect rows ranked at min(sources,5), eMule SearchList.cpp:813). eMule's "cross-hash filename-repetition" is NOT a real 0.50a feature (audit correction); a padMule cross-hash score was built then REMOVED - it flagged legit files sharing a generic name (adversarial review finding) |
| Server MOTD/result FLOOD rate-limit | OPERATIONAL (B6 fixed 625df39) | forwarder now rate-limits server events 30/10s (State exempt); MOTD attributed + 500-char capped |
| Server-trust (source/IP sanity) | OPERATIONAL (B8 fixed 625df39) | PeerSource::from_found/from_kad now reject non-public IPv4 unconditionally (SSRF closed); LowID/port0 already rejected |
| ipfilter Kad UDP coverage | OPERATIONAL (2026-08-01) | the user blocklist now gates every Kad routing insert (kad_live::add_contact, matches eMule RoutingZone.cpp:477); inbound Kad UDP is only ever a reply from an IP we queried (from the now-filtered routing table) |
| Input safety: bounded inbound listener | OPERATIONAL (2026-08-01) | 200-permit global semaphore + a per-IP cap (16/IP, IpConnSlot) so one address cannot starve all permits; serve-session budget (60s idle / 120s queue) already present |
| Credit system (clients.met, ident-gated) | OPERATIONAL (2026-08-02) | FULLY live (build-progress 8ag store + 8ah reweight, commits dbcc0ab + b6262c8). credit_store::CreditStore persists clients.met (load on start / save on pause), binds a verified peer's key with eMule's anti-theft wipe, accrues BOTH upload bytes (per leecher) and download bytes (per source, threaded through the download path), resolves a reweight-only score (resolve_ident_state + score_ratio_ident, clamped [1.0,10.0]), and the upload queue is a PRIORITY UploadGate that serves the best-scored waiter first. NEVER-REFUSE: score only reorders; the sole refusal is a full queue, identity-independent. Adversarial review of the concurrency (lost-wakeup/leak/starvation/ordering) came back CLEAN; proven end-to-end by a client SIMULATION (a HIGH-credit leecher queued 2nd is served before a fresh one queued 1st). This is what makes serve-side secure-ident (the row above) do WORK - the verified identity now feeds the reweight. |
| Server TCP obfuscation | DEFERRED (documented v1 opt-out) | plaintext server link; OPT-IN anti-DPI, never REQUIRED, no server cut off. A DELIBERATE, documented v1 decision - see [[obfuscation-posture]]. Not an integrity/reachability gap (the c2c + Kad traffic that carries transfers IS obfuscated); reversible into an opt-in feature without a wire break. |
| Server UDP obfuscation | DEFERRED (documented v1 opt-out) | cleartext server UDP (port+4); OPT-IN; low-burden partial via OP_GETSOURCES_OBFU. Same deliberate deferral, documented in [[obfuscation-posture]]. |

## Release blockers (fix before community release)

REMAINING (as of 2026-08-02, post Batch B): the **Kad hard-verify is COMPLETE** -
send-side receiver keys terminal-proven ([[kad-verify-oracle]]), key capture closed
(8ak), and the verified bit now ENFORCED in routing (8ao, commit 5ef4c2e). What is
left is AICH block recovery
[OPTIMIZATION - integrity already holds via per-part MD4 + the poisoning ban, and
the advertised AICH bit is non-breaking, so this is not release-blocking].

NOT blockers (documented decisions): server TCP/UDP obfuscation - a deliberate,
interop-safe v1 opt-out, [[obfuscation-posture]].

CLOSED 2026-08-02: serve-side secure-ident [8af]; full credit system - store + bind
+ both-side accrual + upload-queue reweight [8ag/8ah]; per-source corruption
attribution + ban [8ai]. CLOSED 2026-08-01: server MOTD flood [B6]; SSRF source drop
[B8]; TCP c2c obf both-roles, ipfilter-into-Kad, per-IP inbound cap, Kad sybil caps +
IP-change hijack, Kad receiver-key -> verified bit, per-part poison recovery, search
availability cap [8ab].

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
