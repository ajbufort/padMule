# Security Model + the "Bulletproof" Release Gate

Updated: 2026-07-20

RELEASE BLOCKER (Anthony, 2026-07-20; memory: [[security-bulletproof-release-gate]]):
before padMule ships to the community, security must be **BULLETPROOF** =

1. **Every eMule/Kad spec-intended security measure FULLY OPERATIONAL** - wired
   end to end, not stubbed / codec-only / partial.
2. **PLUS reasonable, NON-BURDENSOME additions** - interop-safe only; nothing that
   would stop the user downloading/uploading with the bulk of the live network. Any
   addition must DEGRADE GRACEFULLY when the peer/server lacks support.

This is distinct from "runs on-device" (already true). Proving it is a DEDICATED
security-completeness audit that maps each measure -> real status and verifies it
against the oracles ([[ed2k-server-oracle]], [[padmule-amuled-oracle]],
[[emule-peer-oracle]]), per [[interop-test-fidelity]] (a faithful other-side, not
a mock). Status column below is the LAST KNOWN claim from build-progress; the
audit RE-VERIFIES each as truly operational end-to-end (do not treat as proven).

## Spec-intended measures (the checklist)

| Measure | Purpose | Last-known status (re-verify) |
|---------|---------|-------------------------------|
| Secure Identification (RSA peer identity) | anti-impersonation / credit theft | DONE build-progress 8m (verified vs real aMule "verified: true"); confirm it is REQUESTED + honored on every transfer, both roles |
| Credit system (clients.met) | reward uploaders / anti-leech | codecs present (mule-files clients_met); confirm credits are computed + applied to the upload queue, tied to secure-ident |
| TCP obfuscation (RC4) | anti-throttling / privacy | present (mule-proto RC4, TCP obf in engine); confirm negotiated + used with obf-capable peers, plaintext fallback safe |
| UDP obfuscation (Kad + server UDP) | same, over UDP | present (mule-kad udp_obf, 16B header); confirm keys correct + used |
| Kad UDP verify / sender keys | anti-spoof + anti-DDoS-reflection (a node must prove its IP) | derivations present ([[padmule-kad-notes]]); confirm ENFORCED on receive (drop unverified), not just computed |
| Kad node-ID / IP verification + 2^120 tolerance | routing-poison resistance | tolerance known ([[padmule-protocol-landmines]]); confirm enforced in lookup + routing insert |
| Kad anti-flood / anti-abuse hardening | contact flooding, poisoning | "hardening" claimed (mule-kad); ENUMERATE the concrete limits vs eMule + confirm |
| ipfilter (ipfilter.dat / .p2p) | block known-bad ranges | DONE #1 (gates outbound sources + inbound peers post-handshake) |
| Hash verification: ed2k whole-file | reject corrupt/poisoned files | done (fetch verifies before finish); confirm no accept-without-full-hash window |
| Hash verification: AICH part-level | corruption RECOVERY (re-fetch a bad 180K block, not the whole file) | root byte-validated vs amuled (8u); confirm the RECOVERY path actually re-requests bad blocks |
| Server status-ping challenge | anti-spoof of status replies | DONE (build-progress 8x; 4-byte challenge echoed + verified) |
| Message / result spam + flood filtering | UI abuse, fake results | partial (search trust flags); enumerate + confirm |

## Non-burdensome hardening beyond spec (candidates)

Interop-safe extras (must degrade gracefully): safe parsing of ALL untrusted input
(the group-2 readiness audit hunts panics/OOM), no public-IP/client-id leak into
UI/logs (privacy), sane rate limits, rejecting obviously-hostile packets. These do
NOT gate interop, so they fit the bar. Do NOT add anything that REQUIRES a peer to
support a padMule-only measure to transfer - that would cut off the network.

## Related

- [[security-bulletproof-release-gate]]
- [[padmule-protocol-landmines]]
- [[padmule-kad-notes]]
- [[interop-test-fidelity]]
- [[build-progress]]
