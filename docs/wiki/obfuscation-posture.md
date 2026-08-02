# Obfuscation + encryption posture (what padMule protects, and what it deliberately does not)

Updated: 2026-08-02

This entry is the DELIBERATE, documented record of padMule's transport-obfuscation
scope for v1 - so the two "server obfuscation" rows on the [[security-model]]
scorecard are a conscious opt-out, not an oversight. eD2k obfuscation is ANTI-DPI
(defeat an ISP/middlebox that fingerprints the protocol), NOT confidentiality or
integrity: the RC4 key is derived from public values, so it stops fingerprinting,
not a determined observer. Integrity is carried entirely by the hash layer
(ed2k/MD4 whole-file + per-part + the [[security-model]] poisoning defenses), which
is independent of obfuscation.

## OPERATIONAL (padMule does these)

- **Client-to-client TCP obfuscation (RC4)** - both roles. Outbound proven vs
  amuled; inbound wired via `obf_accept` auto-detect; the listener advertises
  crypt-SUPPORTED (never REQUIRED) so a crypt-required peer can reach us and a
  plaintext peer stays byte-identical. See [[build-progress]] rows 5a / 8ab.
- **Kad UDP obfuscation** - every Kad2 datagram is obfuscated (NodeID-keyed
  requests, ReceiverKey-keyed responses); live-proven decoding real v8 nodes.
- **Secure identification (RSA)** - both roles verify a peer's userhash ownership
  (a different mechanism from transport obfuscation; see [[security-model]]).

## DEFERRED for v1 (deliberate, interop-safe, documented here)

Both are **OPT-IN anti-DPI** in eMule, **never REQUIRED**, so opting out cuts off
NOBODY - every eD2k server and the whole network accept plaintext:

- **Server-connection TCP obfuscation.** padMule connects to eD2k servers in
  plaintext. eMule's "obfuscated server connection" is a per-server preference off
  by default network-wide; Lugdunum servers accept both. NOT an integrity or
  reachability gap - only an anti-DPI nicety for the server link.
- **Server UDP obfuscation.** padMule's server UDP (global search / OP_GLOBGETSOURCES)
  is cleartext on the standard server-UDP port (TCP port + 4). A low-burden partial
  (`OP_GETSOURCES_OBFU`) exists in eMule; deferred with the same reasoning.

Why deferred, not done: v1 scope. Neither affects whether a download completes,
whether a file is correct, or whether a peer/server will talk to us. They are pure
DPI-evasion on the server leg, valuable only to a user whose ISP throttles eD2k
servers specifically - a narrow case, and even then the c2c + Kad traffic (the bulk)
is already obfuscated. Shipping without them is honest and safe.

How to add later (if a throttling ISP makes it worth it): the RC4 machinery
already exists (`mule-proto` RC4 + the c2c `EncryptedStreamSocket` port); a
server-obf build would reuse it for the server TCP handshake (DH-keyed, per eMule's
server obfuscation) and wrap the server UDP send/recv. It stays OPT-IN + degrade-to-
plaintext, so it can never cut us off from a server that does not support it.

## Bottom line

The obfuscation that matters for a foreground iPad client - the c2c + Kad traffic
that carries the actual transfers and lookups - IS obfuscated. The server leg is
plaintext by deliberate v1 choice; it is anti-DPI only, interop-safe, and reversible
into an opt-in feature without a wire break.

## Related

- [[security-model]] (the scorecard; these are the 2 "server obfuscation" rows)
- [[build-progress]] (5a c2c obf, 6b Kad obf, 8ab inbound obf)
- [[decisions-and-lessons]]
- [[padmule-protocol-landmines]]
