# eMule peer oracle (real eMule on the Windows host)

Updated: 2026-08-01

A SECOND, independent peer oracle for padMule's client-to-client protocol: a
real **eMule running on the Windows host**, alongside the headless **amuled**
that [[build-progress]]'s `scripts/differential-test.sh` already builds in WSL.

Two oracles catch different things. amuled (aMule 3.0.1) is the vendored,
scriptable, deterministic gate. Real eMule 0.50a is the WIRE AUTHORITY
([[decisions-and-lessons]]) and what most of the live network actually runs -
so it is the right oracle for anything eMule-specific, and in particular for
**secure identification** (task #32), which the amuled harness cannot exercise
(its serve side is never driven through a secure-ident exchange). See
[[interop-test-fidelity]]: test an interop feature against a FAITHFUL other side.

This is a MANUAL oracle - eMule is a GUI app on Windows, so Anthony launches it;
padMule (in WSL) then connects to it. Nothing here runs unattended.

## Which eMule

- **eMule 0.50a** (recommended): the wire/format authority padMule matches
  byte-for-byte. From emule-project.net. `refs/emule-0.50a` is its source.
- **eMuleAI** (modern fork, active 2026, [[emule-ecosystem-refs]]) or the eMule
  0.70b community build also work as peer oracles; 0.50a is the cleanest match.

## Networking (already correct on this box)

WSL2 is in **mirrored** mode ([[padmule-dev-box-networking]]), so the WSL engine
and Windows share `127.0.0.1` and the LAN IP `192.168.0.32`. A Windows-side eMule
is therefore reachable from padMule (WSL) at **`127.0.0.1:<eMule TCP port>`**
(fallback `192.168.0.32`).

- LANDMINE: mirrored mode SHARES the port space. padMule's own engine binds TCP
  4662, so give eMule a DIFFERENT TCP port - the oracle defaults to **4663**.
  (The CLI oracle test does not start padMule's engine, so there is no clash
  during a test, but a distinct port avoids surprises if the app is also open.)

## eMule setup (one time)

1. **Options -> Connection**: set "TCP port" to **4663** (or any port != 4662).
   UDP port can stay default. Click "Test ports" if you like.
2. **Options -> Security**: leave **"Use secure identification"** ON (eMule's
   default). This is what makes the oracle useful for #32 - eMule will offer
   secure-ident to a peer that advertises support.
3. **Windows Firewall**: allow eMule (Windows usually prompts on first run).
   Mirrored-mode localhost does not need a LAN rule, but allowing eMule is
   simplest.
4. **Share a small test file**: drop a file in eMule's shared folder (Options ->
   Directories), or right-click -> "Share". A few hundred KB is plenty.
5. **Copy its ED2K link**: right-click the shared file -> "Create ED2K-Link"
   (or Shared Files view -> copy). It looks like
   `ed2k://|file|NAME|SIZE|HASH|/` - that carries the hash + size padMule needs.

## Run a transfer test (the amuled analogue)

With eMule running + sharing, from the repo:

```bash
cargo build --release -p mule-cli
scripts/emule-oracle.sh 'ed2k://|file|NAME|SIZE|HASH|/'      # host 127.0.0.1, port 4663
scripts/emule-oracle.sh 'ed2k://|file|...|/' 192.168.0.32 4663   # explicit host/port
```

The script parses the link and runs `mule-cli peer-download`, which connects to
eMule, does the HELLO, requests the file, pulls it across (queuing if eMule
rations its upload slot, exactly like a real downloader), and VERIFIES the ed2k
hash. A PASS means padMule interoperates with real eMule end to end.

## Inspect the handshake (for #32 secure-ident)

To watch the raw packet sequence - including whether eMule sends OP_SECIDENTSTATE
(proto 0xC5, opcode 0x87) after the HELLO:

```bash
target/release/mule-cli peer-probe 127.0.0.1 4663 <HASH>
```

NOTE: as of #32 (2026-07-19), the fetch path AND `peer-download` advertise
SecureIdent v1 and run the exchange, so `scripts/emule-oracle.sh` prints
"source identity verified (secure-ident): true/false" - the live confirmation
against real eMule. (`peer-probe` still uses the sec_ident=0 baseline, so it is
only a plain-handshake tracer; use the oracle script for the secure-ident check.)

## The REVERSE-direction oracle (real amuled downloads FROM padMule) - AUTOMATED

`scripts/differential-test.sh` and the eMule test above both have padMule
DOWNLOAD from the other side, so they exercise padMule's DOWNLOADER wire bytes.
They never touch padMule's SERVE side. `scripts/amuled-reverse-oracle.sh`
(added 2026-08-01) closes that gap fully unattended: a real **amuled 3.0.1
downloads a file FROM padMule**, relayed through the real Lugdunum eserver
([[ed2k-server-oracle]]), all inside one isolated `unshare -rn` namespace.

Why the eserver relay: amuled will NOT dial an OFFLINE, link-embedded source,
but it WILL request sources from a connected server and dial them. So padMule
serves the file AND offers it to the eserver (`serve-file <port> <path>
<eserver-host> <eserver-port>` logs in + OP_OFFERFILES); amuled, connected to the
same eserver, discovers padMule as a source and dials it. This is the same
"server relays the source" technique the live network uses for HighID sources.

Namespace details that MATTER (each was a real failure before the test passed):

- **Public-looking IPs on distinct /24s.** amuled filters PRIVATE server IPs
  (`FilterLanIPs`), and a source must differ from both the server IP and
  amuled's own IP. The script uses 45.45/77.77/88.88 addresses on one dummy
  interface; nothing leaves the namespace.
- **padMule's serve IP is added FIRST** so it is the interface primary -> that
  is the HighID source address the eserver hands to amuled.
- **server.met stores the IP in dotted-quad order** (`inet_aton`, NOT reversed).
- amuled is driven headlessly: `-c CFG -o -i`, `Autoconnect=1`, crypt/ipfilter
  off, the download queued via its `ED2KLinks` file (NO embedded source).

Run it (after `build-amuled-oracle.sh` + `eserver-oracle.sh` once, release CLI):

```bash
cargo build --release -p mule-cli
scripts/amuled-reverse-oracle.sh    # PASS = amuled pulled the file byte-for-byte
```

What it caught on day one: the **multipacket serve bug** ([[build-progress]] row
8ad). padMule's HELLO advertised ext_multipacket, so amuled sent the bundled
OP_MULTIPACKET_EXT (0xa4) request, which padMule's serve loop dropped - transfer
died at 0 bytes. Every symmetric test missed it because padMule-as-downloader
sends the INDIVIDUAL opcodes. 8ad's stopgap stopped advertising multipacket; row
8ae then HONOURED it (padMule now answers OP_MULTIPACKET(_EXT) with
OP_MULTIPACKETANSWER and re-advertises the capability). Set `SERVE_DEBUG=1` to
trace the serve opcodes padMule receives (you will see `0xa4` when multipacket is
on).

IMPORTANT (row 8ae): the oracle now routes `serve-file` through the REAL
production serve path - the inbound listener's `is_upload_request()` classifier
gate plus `share::serve_shared` (the loop a real inbound peer hits on the device)
- NOT the minimal `transfer_session::serve` demo shim it used at first. That shim
bypassed the classifier, so the oracle originally could not see that
`is_upload_request` failed to recognise the multipacket opener (a capable
downloader LEADS with 0xa4 once we advertise the bit) and the listener silently
dropped the connection. An adversarial code review caught that; the fix added the
opcodes to `is_upload_request` AND pointed the oracle at the production path, so a
regression there now FAILS the oracle. Lesson: an oracle only tests the code path
it actually drives - aim it at production, not a demo path.

It ALSO validates SERVE-SIDE secure identification (2026-08-02, build-progress
8af): amuled advertises `sec_ident=3` by default (gated on CryptoAvailable, which
the obfuscation-off `sed` block does NOT disable), so padMule's serve path issues
its own OP_SECIDENTSTATE, amuled answers with its pubkey + signature, and padMule
verifies it. cmd_serve_file prints `identity verified (secure-ident): true`, and
the oracle's RESULT block `grep -q`s for that line ALONGSIDE the byte-for-byte
`cmp` - so a serve-side verification regression fails the oracle. This is what the
[[interop-test-fidelity]] rule demanded before shipping serve-side secure-ident: a
real downloader proving padMule verifies it, not a mock in the wrong role.

## Troubleshooting

- "cannot resolve" / connection refused: eMule not running, wrong port, or the
  firewall blocked it. Confirm eMule's TCP port and that it is "Connected".
- Handshake OK but 0 bytes / "no file": eMule is not sharing that exact hash, or
  the share list has not refreshed - re-copy the ED2K link from eMule.
- Stalls in a queue: expected if eMule has no free upload slot; peer-download
  waits like a normal client (it does not bail on a single dedicated source).

## Related

- [[interop-test-fidelity]]
- [[padmule-dev-box-networking]]
- [[decisions-and-lessons]]
- [[ref-source-trees]]
- [[build-progress]]
