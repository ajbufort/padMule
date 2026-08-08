# Kad Verify Oracle (log-patched amuled)

Updated: 2026-08-07

The REVERSE-Kad oracle: a real amuled 3.0.1, instrumented with a committed
logging-only patch, that proves the terminal claim of the wave-10 send-side work
- "a REAL eMule-family node marks padMule IP-VERIFIED". Built 2026-08-02
(commit 7e8fe9c); the third member of the oracle set alongside
[[emule-peer-oracle]] (eD2k peer, both directions) and [[ed2k-server-oracle]]
(eD2k server). EXTENDED 2026-08-07 into the serve-loop survival oracle: the
same amuled now also proves padMule STAYS in its routing table because the
owning read loop answers the OnSmallTimer liveness probe (see the A/B section
below - the success test the kad-owning-read-loop spec names).

## Why it exists

aMule flips a v8 peer's IP-verified bit only when the peer completes the Kad2
HELLO_RES_ACK three-way handshake (Process2HelloResponseAck -> VerifyContact) or
sends a HELLO_REQ with a valid receiver key (AddContact2). Stock amuled logs
NOTHING on that transition, so no unpatched node can attest it. The patch adds
two log lines at exactly those sites; when padMule's handshake (kad_live::hello
+ send_hello_res_ack, commit 65a186b) runs against it, the oracle prints
`PADMULE-ORACLE-VERIFIED contact (sender: 77.77.0.9) via VerifyContact` -
observed reproducibly across consecutive runs. Per [[interop-test-fidelity]],
this is the faithful other-side the send-side claim needed.

## Artifacts (all in scripts/)

- `amule-oracle-kad-verify.patch` - pure-insertion hunks, LOGGING-ONLY
  (audited: no existing line modified or deleted). The original two (2026-08-02):
  RoutingZone.cpp AddContact2-update path, logs when an updated contact flips
  to IsIPVerified(); and right after VerifyContact's SetIPVerified(true).
  EXTENDED 2026-08-07 with five more insertions so the serve-loop survival
  claim is observable: OnSmallTimer's probe send (`PADMULE-ORACLE-SMALLTIMER`)
  and its type-4 removal (`PADMULE-ORACLE-EVICTED`) in RoutingZone.cpp, the
  refresh after `m_bin->SetAlive` (`PADMULE-ORACLE-REFRESH`), and in
  KademliaUDPListener.cpp the tracked-packet receipts `PADMULE-ORACLE-HELLO-RES`
  (Process2HelloResponse) and `PADMULE-ORACLE-PONG` (Process2Pong) - both sit
  AFTER CHECK_TRACKED_PACKET, so each logged receipt proves a full round trip
  amuled itself initiated. Uses AddDebugLogLineC, which is ACTIVE IN RELEASE
  builds (Logger.h:452 defines it outside the __DEBUG__ guard; critical lines
  bypass the verbose gate, Logger.cpp:138).
- `build-amuled-kad-oracle.sh` - copies the PRISTINE amule-3.0.1/ tree to
  gitignored build-oracle/amule-instrumented-src (the vendored oracle is never
  touched), applies the patch, builds a Release daemon into
  build-oracle/kad-build/src/amuled. Idempotent; `clean` forces a rebuild.
- `kad-verify-oracle.sh` - since 2026-08-07 an A/B EXPERIMENT, not just a
  handshake check (and SLOW BY NATURE, ~5 minutes: it must sit through real
  eviction cycles). One `unshare -rn` namespace, fake-public IPs, amuled at
  88.88.0.3; TWO padMule instances against one amuled routing table:
  - CONTROL at 77.77.0.8: `mule-cli kad-bootstrap` - the OLD one-shot
    behaviour. Handshakes, exits, goes silent. Must be EVICTED.
  - SERVE at 77.77.0.9: `mule-cli kad-serve <nodes.dat> [bind-ip] [secs]`
    (added for this oracle) - binds a real KadNode, whose
    `bind_with_identity` spawns the owning read loop, seeds routing,
    handshakes, then idles while the loop answers. Must SURVIVE.
  Same amuled, same table, same OnSmallTimer sweeps - the asymmetry is the
  proof. Seeds amuled's Kad ID via a written preferencesKad.dat, hands both
  padMule instances a one-contact v2 nodes.dat, waits for "Kad started", then
  watches the oracle lines for the verdict.

## The 2026-08-07 A/B run: padMule SURVIVES the sweep that evicts a silent node

PASS on the first attempt (one run, one pass; exit 0). The instrumented
amuled's own log, verbatim and in order:

```
23:17:07 PADMULE-ORACLE-VERIFIED contact (sender: 77.77.0.8) via VerifyContact
23:17:07 PADMULE-ORACLE-VERIFIED contact (sender: 77.77.0.9) via VerifyContact
23:17:07 PADMULE-ORACLE-PONG from 77.77.0.9
23:18:08 PADMULE-ORACLE-SMALLTIMER probe -> 77.77.0.9 (type now 4)
23:18:08 PADMULE-ORACLE-REFRESH contact (77.77.0.9) type=2
23:18:08 PADMULE-ORACLE-HELLO-RES from 77.77.0.9 (contact added/updated)
23:19:09 PADMULE-ORACLE-SMALLTIMER probe -> 77.77.0.8 (type now 4)
   (nine more PONG from 77.77.0.9 lines through 23:20:56)
23:21:12 PADMULE-ORACLE-EVICTED contact (77.77.0.8) - probe unanswered past expiry
```

Reading it: both instances complete the v8 handshake and are VERIFIED at
23:17:07. At 23:18:08 amuled's OnSmallTimer probes the SERVE node with a
HELLO_REQ (type set to 4, expiry +2 min); padMule's read loop answers, the
HELLO_RES passes CHECK_TRACKED_PACKET, and AddContact2's update path runs
`SetAlive` -> `UpdateType` - the REFRESH line, type back to 2, expiry pushed to
+1 hour. At 23:19:09 the same sweep machinery probes the silent CONTROL; it
never answers, and at 23:21:12 (probe + 2 min expiry + next sweep) it is
REMOVED. The serve node was never evicted and its process was still
heartbeating when the run ended. The control is literally the old padMule (a
one-shot `kad-bootstrap`), so the eviction it suffered is a demonstration - in
this same run, on these same sweeps - of the fate the read loop now prevents.

TIMING FACTS, read from source, not guessed (aMule 3.0.1 == eMule 0.50a here):

- Sweep cadence: 60s per zone. aMule `Kademlia.cpp:254-257`
  (`zone->m_nextSmallTimer = MIN2S(1) + now`); eMule 0.50a
  `Kademlia.cpp:276-277` identical.
- The probe is a KADEMLIA2_HELLO_REQ, NOT a KADEMLIA2_PING - aMule
  `RoutingZone.cpp:792-816` (`OnSmallTimer` -> `SendMyDetails(KADEMLIA2_HELLO_REQ, ...)`).
- A probed contact gets type=4 and expiry now+2min: aMule `Contact.cpp:80-92`
  (`CheckingType`); eMule 0.50a `Contact.cpp:223` identical.
- Expired type-4 contacts are removed by the next sweep's dead-entry pass:
  aMule `RoutingZone.cpp:766-782`.

So a silent contact dies ~3-4 sweeps after being learned, and the whole A/B
fits in ~5 minutes at FULL fidelity - no timer was shortened for this test.

Where the PING/PONG lines come from: amuled wants its external UDP port and
sends KADEMLIA2_PING to a contact every ~15s while it does
(`Kademlia.cpp:210-221`, plus one after each HELLO_RES,
`KademliaUDPListener.cpp:627-631`). That is FASTER than padMule's 2/min PING
flood budget, so some pings go unanswered BY DESIGN - visible as gaps in the
PONG series (e.g. 23:19:56-23:20:41). Routing survival never depends on those
pings: liveness rides the HELLO probe (HELLO_REQ budget 3/min, probed at
1/min), so the limiter and the survival proof coexist. Do not misread the PONG
gaps as the serve loop failing.

Harness footnote: this build writes log lines to BOTH stdout and
`$CFG/logfile`, so the result block prints each oracle line twice; the verdict
greps are `-q` and unaffected.

## What it proves (and what it does not)

- PROVES: padMule's v8 handshake bytes are accepted end-to-end by real aMule
  Kad code - HELLO_REQ (no 0x04), HELLO_RES consumed, HELLO_RES_ACK echoing
  the peer's sender key -> bValidReceiverKey true -> VerifyContact. This is
  the wave-10 send-side terminal proof ([[build-progress]] wave 10).
- PROVES (2026-08-07): padMule's SERVE side - the owning read loop's HELLO_RES
  is consumed by a real amuled as the answer to its own OnSmallTimer probe,
  its PONG is consumed as the answer to a tracked KADEMLIA2_PING, and the
  contact is refreshed and KEPT past the sweep that evicts a silent node
  (row 8cl; the A/B section above).
- Does NOT prove: verified-bit ENFORCEMENT in padMule's own routing - that is
  offline-provable and is covered by its own tests.
  [BOTH gaps this bullet used to list are now CLOSED (2026-08-02), and the
  bullet is corrected rather than deleted so the sequence stays legible:
  Batch B enforcement LANDED (commit 5ef4c2e, [[build-progress]] 8ao - closest_to
  hands out only IP-verified contacts), and the search-path key-echo gap
  (search_source / search_keyword_node discarding the peer's sender key) was
  closed by 8ak's single `note_responder` path (commit 2ab7800). Re-verified
  against the code in the 2026-08-02 reanalysis.]
- Related discovery: BOTH eD2k terminal claims need NO patch - stock aMule
  already logs the multipacket answer receipt (ClientTCPSocket.cpp:1147) and
  secure-ident success (BaseClient.cpp:2207); the reverse peer oracle asserts
  them by enabling verbose logging.

## The "flakiness" was a harness bug, not a port problem (2026-08-02)

This oracle was first recorded with "KNOWN harness flakiness: amuled's Kad UDP
socket occasionally binds an ephemeral port". That diagnosis was WRONG. amuled
always bound 4672. Two defects in the runner made it blind:

1. `LOGS()` read only the stdout redirect, but this build writes its log lines
   to `$CFG/logfile` and leaves stdout nearly empty - so the harness could not
   see "Kad started", the UDP-socket line, or its own PADMULE-ORACLE-VERIFIED
   success line.
2. The port check grepped `Client UDP socket (extended eMule) at`, a string
   aMule 3.0.1 never emits; it logs `Created Client UDP-Socket at port N`. The
   resulting WARN was always false.

Both fixed (row 8ak): `LOGS()` reads BOTH sinks and the grep matches the real
string. The oracle now passes 3/3 on the FIRST attempt, no retries, no WARN.

LESSON (a [[verify-before-reporting]] case): a harness that cannot observe
success will invent a plausible-sounding cause for the failure. "Known
flakiness" is a claim that deserves the same evidence bar as a passing test -
here, reading amuled's actual log text refuted it in one run.

Separate real prereq worth knowing: amuled REFUSES to start with
`AcceptExternalConnections=0` ("aMule daemon cannot be used when external
connections are disabled"), which is why the runner sets it plus an ECPassword.

## Related

- [[build-progress]] - wave 10 (the build this oracle terminates).
- [[security-model]] - the Kad verify/sender-keys scorecard row.
- [[emule-peer-oracle]] - the eD2k reverse oracle (same philosophy, TCP side).
- [[ed2k-server-oracle]] - the isolated eserver oracle (same isolation recipe).
- [[padmule-kad-notes]] - Kad byte-exact facts (memory).
- [[interop-test-fidelity]] - the rule this oracle satisfies (memory).
