# HANDOFF - start here next session

Updated: 2026-08-02 (end of a long session; everything below is verified, not assumed)

Living doc: replace it wholesale next time rather than appending. For the full
narrative see [[build-progress]] rows 8aj-8ar and the [[log]] entries for
2026-08-02.

## State of the tree

- **All work is committed AND pushed**; working tree clean; branch even with
  origin/main. Last commit of the session is the docs commit that added this file.
- **Gate**: 518 tests, clippy clean, fmt clean, ASCII clean.
- **CI**: green on every push today (Rust gate + iOS build + iOS simulator tests).
- **Oracles**: all re-run green today - amuled differential (3 files,
  byte-for-byte), reverse oracle (real amuled downloads FROM padMule +
  serve-side secure-ident), Kad verify oracle (3/3, first attempt).

## The headline: the bulletproof gate has NO protocol work left

[[security-model]] scorecard is **23 OPERATIONAL / 1 PARTIAL / 2 documented
opt-outs**. Wave 10 (Kad hard-verify) is COMPLETE: send-side keys terminal-proven
via [[kad-verify-oracle]], key capture closed, and Batch B landed - the verified
bit is now ENFORCED in routing.

The single PARTIAL is **AICH block recovery** (task #1, [[build-progress]] wave
11). It is an OPTIMIZATION, not an integrity hole.

## Open tasks (session task list; recreate if lost)

1. **AICH block recovery** - the last PARTIAL. Design inputs already captured in
   the task: do NOT port the vendored 3.0.1 oracle's racy `known2_64.met`
   orphan-prune (upstream fixed it after 3.0.1); route `localize_corruption`'s
   blamed parts into block-level recovery; ship the AICH request rate limit and
   an O(1) index in the SAME change (aMule ran a naive linear scan ~20 years
   before it was caught as a DoS). Also lifts 8ai's sole-contributor limitation.
5. **Research-pass backlog** - Download Inspector (content-fakes that hash
   correctly: zero-fills, DRM stubs, extension mismatch - a failure mode the
   corruption black box structurally cannot catch), known/downloaded/cancelled
   marking in search results, majority-filename rename (steal eMuleAI's
   percentage + minimum-votes two-gate design), throughput-based upload-slot
   recycling (NB the eMuleAI report's "squats for an hour" claim was WRONG - it
   read the dead `upload_queue.rs`; the live path drops a silent peer at 60s,
   so only TRICKLING peers can hold a slot), bulk select, persisted search
   results, ipfilter auto-update.
7. **Continuous block-request top-up** - padMule is stop-and-wait per batch,
   SHALLOWER THAN BOTH authorities. eMule tops the pending list up as each block
   completes (DownloadClient.cpp:870-919); adopt that, no wire change, big win at
   cellular RTT. Do NOT adopt aMule master's [3,24] BDP clamp - it cites eMule as
   precedent for a depth eMule never requests.

Also open, not yet tasks: serving PARTIAL files (we share complete files only -
`share.rs` says so; real clients serve partials, and it would earn credit), and
no oracle yet proves a real client CONSUMING our source-exchange answer.

## THE TOP NEXT ACTION: verify today's work on the device

Eleven pushes landed today and **none has been exercised on the iPad**. padMule
IS installed (fresh build from CI run 30777433779, commit 91466a5). Nobody has
launched it yet.

What to look for:
- The **function strip** (six labelled icons) - a visual change CI cannot judge.
- Whether it earns **HighID** on the BE9700 (regression check for the UPnP fix;
  the BE9700 is IGD:1, so it does not exercise the new IGD:2 path).
- The **free-space guard** should stay silent (476GB free).
- Kad search health with the verified-bit gate ON (proven live via CLI already).

## Device tooling - a major capability unlocked today

See [[ipad-usb-tooling]] for the full runbook and gotchas. Summary:

- The iPad is reachable from this WSL box over USB (usbipd-win, busid **7-12**,
  already `bind --force`'d so only `attach` is needed).
- **I can SEE the screen** (`pymobiledevice3 developer dvt screenshot`, no root)
  and **read live engine logs** (`idevicesyslog -p padMule`).
- **I can sign and install padMule myself** with zsign + Sideloadly's cached
  cert/key + a device-pulled profile - no Sideloadly round trip, no detach dance.
  Anthony runs the zsign command (a safety classifier correctly blocks the agent
  from touching his signing key - keep it that way).
- **Profiles + free cert EXPIRE 2026-08-10.** Renewal needs Sideloadly; after
  renewing, re-pull with `ideviceprovision copy`.
- **Touch control (WebDriverAgent) is signed + installed but will not launch
  yet** - go-ios's tunnel stopped establishing. Three concrete things to try are
  listed in [[ipad-usb-tooling]]. Everything except the tunnel is proven: the
  XCUITest handshake with `testmanagerd` succeeded earlier in the session.

## Discipline reminders that earned their keep today

- **eMule 0.50a decides wire + formats; aMule is the runnable oracle + wire-
  neutral policy; where they conflict, follow eMule.** Now stated in the README,
  the GitHub summary, CLAUDE.md and the `emule-vs-amule-authority` memory. It
  refused aMule twice today (tag 0x55, block depth) and took aMule's side once
  (the part.met save ordering).
- **Verify before reporting.** Today that overturned a "known flaky" oracle
  (it was a harness bug), an "obfuscation regression" (my test forgot aMule's
  userhash marker bytes), an agent's severity claim (it read dead code), and the
  documented target device (it changed to an M4 iPad Pro, `iPad16,3`).
- The vendored `amule-3.0.1/` oracle can itself contain bugs upstream later
  fixed - check `refs/amule-master/` (refreshed today to `3.0.1-405`) before
  transcribing.

## Related

- [[build-progress]] - rows 8aj through 8ar are today.
- [[security-model]] - the scorecard.
- [[ipad-usb-tooling]] - the device runbook.
- [[kad-verify-oracle]] - the wave-10 terminal proof.
