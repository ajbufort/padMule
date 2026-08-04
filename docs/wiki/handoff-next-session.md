# HANDOFF - start here next session

Updated: 2026-08-04, written fresh at the close of a very long session.
Everything below is verified; anything NOT verified says so.

Living doc - replace it wholesale next time. Full narrative: [[build-progress]]
rows 8bj-8bq and the [[log]] entries for 2026-08-03/04.

## State of the tree

- main is clean and pushed. History LINEAR across 390+ commits - zero merge
  commits, ever. Keep it that way (`gh pr merge --rebase`).
- **Gate**: 608 Rust tests, clippy `-D warnings` clean, fmt clean, ASCII clean.
- **All four oracles pass**: amuled differential, the REVERSE oracle, the
  isolated eserver login, the Kad verify oracle.
- [[security-model]]: **24 OPERATIONAL / 0 PARTIAL / 2 documented opt-outs**.
  Wave 11 (AICH block recovery) closed the last PARTIAL and is MERGED to main.
- Installed on the iPad: **8068a71**. Device is on iPadOS **26.6**.
- **Cert re-signed 2026-08-04**, so it lapses about **2026-08-11**. Renewing is
  just another Sideloadly install.

## What landed this session

Wave 11 AICH merged, then eleven PRs. The headline is not the features - it is
that **five real bugs were found by USING the app, none caught by any test or
oracle**:

1. **The serve side sent every block up to THREE times.** eMule re-states its
   3-block window on each completed block and relies on the uploader to dedup
   (`AddReqBlock`); padMule had no such check. Both oracles passed throughout,
   because duplicate bytes still verify byte-for-byte - a pass/fail harness is
   structurally blind to a BANDWIDTH defect.
2. **The AICH serve answer was unreachable** on the path real clients use:
   `is_upload_request` omitted 0x9B/0x9E, so the listener hung up on exactly the
   connections eMule opens to ask.
3. **Called-back sources were tracked nowhere**, so a transfer visibly
   progressed with no source listed - caught within minutes of the badge
   shipping.
4. **A second corruption round blamed the first round's source** - a false ban,
   the one thing the attribution design promises never to do.
5. **Live servers shown dead** - a single lost UDP datagram read as death.

Also landed: continuous block-request top-up, the source-origin badge, the Kad
advertised-vs-bound port split, UPnP defaulting OFF, the Files button, real Open
(hand off to another app), sortable Downloaded/Servers, alphanumeric search
sort, and the floating Top button.

## HighID over AirVPN - SOLVED, and the cause is a trap

padMule is **HighID on the VPN**, device-proven. Days of LowID were not
padMule's fault: AirVPN's **"Local port" field cannot be left blank**. The form
refuses to save an empty value and silently keeps the previous one, so the rule
kept forwarding 5999 to an old **4662** while padMule listened on 5999.

**The diagnostic is worth more than the fix:** `Connection refused (111)` from
AirVPN's checker, rather than a TIMEOUT, proves the packet traversed the tunnel
and reached the device, which actively answered "nothing listening". The tunnel,
keepalive and routing were never suspects - only the port number. A timeout
would have meant the opposite. Two servers both reporting LowID had already
ruled out a per-server callback quirk.

The setup that works: one port, TCP+UDP, **Local port set to the SAME number**,
padMule's four port fields all that number, UPnP OFF (now the default).

## Scope decisions

- **Wave 9 seedbox mode: DROPPED** (2026-08-04). Cut, not deferred again.
  Foreground-only is padMule's PERMANENT posture, so the honest pause/resume,
  the readiness-gated splash, keep-screen-awake and Stop-releases-the-port are
  the FINAL design rather than stopgaps. Do not promise an always-on mode.

## Open work (ranked)

1. **The Status scalars still lag during a long search.** The serial-queue fix
   freed the transfer list (UI polls no longer take the engine lock), but
   `state`, `server_info` and `kad_contacts` genuinely live in the engine, so
   they stall behind `Engine::search`'s ~20s `&mut self`. Closing it needs
   `server` and `kad` made independently shareable - a real ownership change,
   and NOT required for a responsive UI. Judge whether the risk is worth it.
2. **Device-verify what shipped unseen**: the Downloaded sort control, the Open
   handoff to another app, and search's alphanumeric ordering. All are
   CI-verified and unit-tested, none seen on glass.
3. **Portability Tier 2** ([[portability-audit]]): NAT-PMP is dead code; the 4s
   `offer_files` timeout silently drops uploads on a slow link; no bandwidth
   limiting anywhere.
4. **Settings Tier 1/2**: nickname (hardcoded "padMule"), obfuscation policy
   tri-state, ipfilter controls, upload slots, bandwidth caps (`upload_queue.rs`
   holds dead kbps logic to revive-or-delete), See-My-Shared-Files.
5. **Smaller items**: the harvest queue is lost if the server.met write fails;
   no thin-file guard on nodes.dat writes (aMule refuses < 25 contacts); the
   related-search fallback pollutes Recent Searches; Settings accepts `https://`
   list URLs the engine rejects (http-only); the kick alert may not surface
   while a sheet is open; `hash-file` exits 0 on failure and two oracle scripts
   consume it without `-e`; MSRV declared but unenforced in CI.

## Discipline that keeps earning its keep

- **User testing finds what tests cannot.** Five bugs this session, zero caught
  by the gate. Green measures what you thought to check.
- **MUTATION-CHECK anything load-bearing.** Every fix this session was verified
  by breaking it and watching the right test go red. Two of them DEADLOCK on
  regression rather than failing slowly, which makes the assertion a liveness
  check.
- **"An event is not state"** - now FOUR occurrences
  ([[an-event-is-not-state]]). A silent path must still speak; one datum is
  never a verdict.
- **A green oracle proves only the path it drives**, and says nothing at all
  about COST - bandwidth, battery, wakeups.
- **Swift type-checks ONLY in CI on this box.** Wait for the iOS workflows.
- **Scope a scary refactor by reading first.** The serial-queue fix looked like
  it needed an ownership overhaul; reading the struct showed five polls needed
  no engine state at all, and the change became small and safe.
- **`strings` on the .ipa can FALSE-NEGATIVE**: Swift stores strings of <=15
  bytes inline, so a missing marker is not proof. Pick longer markers.
- **Two agents in one worktree is a data-loss shape** -
  [[parallel-sessions-one-worktree]].

## Related

- [[build-progress]] / [[security-model]] / [[log]] / [[decisions-and-lessons]]
- [[net-highid-and-port-forwarding]] - the AirVPN setup and the Local-port trap.
- [[ipad-usb-tooling]] - device runbook. NB `usbipd bind` is NOT needed;
  pymobiledevice3 reaches the iPad through Windows' own Apple service.
- [[lifecycle-and-reactivation]] - foreground-only, now permanent.
