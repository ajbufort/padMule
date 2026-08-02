# Kad Verify Oracle (log-patched amuled)

Updated: 2026-08-02

The REVERSE-Kad oracle: a real amuled 3.0.1, instrumented with a committed
logging-only patch, that proves the terminal claim of the wave-10 send-side work
- "a REAL eMule-family node marks padMule IP-VERIFIED". Built 2026-08-02
(commit 7e8fe9c); the third member of the oracle set alongside
[[emule-peer-oracle]] (eD2k peer, both directions) and [[ed2k-server-oracle]]
(eD2k server).

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

- `amule-oracle-kad-verify.patch` - two pure-insertion hunks, LOGGING-ONLY
  (audited: no existing line modified or deleted). Hunk 1: RoutingZone.cpp
  ~:494, logs when an updated contact reads IsIPVerified() (the AddContact2
  path). Hunk 2: ~:888, logs right after VerifyContact's SetIPVerified(true).
  Uses AddDebugLogLineC, which is ACTIVE IN RELEASE builds (Logger.h:452
  defines it outside the __DEBUG__ guard; critical lines bypass the verbose
  gate, Logger.cpp:138).
- `build-amuled-kad-oracle.sh` - copies the PRISTINE amule-3.0.1/ tree to
  gitignored build-oracle/amule-instrumented-src (the vendored oracle is never
  touched), applies the patch, builds a Release daemon into
  build-oracle/kad-build/src/amuled. Idempotent; `clean` forces a rebuild.
- `kad-verify-oracle.sh` - the isolated 2-node runner: one `unshare -rn`
  namespace, fake-public IPs (amuled at 77.77.0.2, padMule sourced from
  77.77.0.9 via an explicit src-route - without it the kernel picks amuled's
  own address and amuled self-rejects). Seeds amuled's Kad ID via a written
  preferencesKad.dat, hands padMule a one-contact v2 nodes.dat, waits for
  "Kad started", then retries `mule-cli kad-bootstrap <nodes.dat> [bind-ip]`
  (the optional bind-ip was added for this harness) until the oracle line
  appears (up to 8 attempts).

## What it proves (and what it does not)

- PROVES: padMule's v8 handshake bytes are accepted end-to-end by real aMule
  Kad code - HELLO_REQ (no 0x04), HELLO_RES consumed, HELLO_RES_ACK echoing
  the peer's sender key -> bValidReceiverKey true -> VerifyContact. This is
  the wave-10 send-side terminal proof ([[build-progress]] wave 10).
- Does NOT prove: verified-bit ENFORCEMENT in padMule's own routing (Batch B,
  offline-provable, still pending), or key-echo coverage on the search paths
  (search_source / search_keyword_node currently discard the peer's sender
  key - 2026-08-02 reanalysis finding).
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
