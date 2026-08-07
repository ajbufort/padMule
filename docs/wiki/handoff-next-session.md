# HANDOFF - start here next session

Updated: 2026-08-07, after the Kad-search session. Living doc - replace wholesale.

Full narrative: [[build-progress]] rows 8ce-8cg and the [[log]] entries for
2026-08-06 and 2026-08-07.

## THE ONE-LINE SUMMARY

Kad keyword search was broken for EVERY multi-word query since Wave 6 and is now
fixed and device-proven; the UI-freeze half of the GUI slowness is fixed and
device-proven; **the operations are still individually slow and that is the
biggest remaining user-facing win.**

## State of the tree

- **Gate**: 641 Rust tests, 24 Swift simulator tests, clippy `-D warnings`,
  fmt + ASCII clean.
- **BRANCH `fetch-funnel`, nothing merged.** Do not trust prose for counts - run
  `git log --oneline main..HEAD` and `git log --oneline origin/main..main`.
  History is LINEAR and must stay that way (`gh pr merge --rebase`).
- **`rust.yml` only fires on push to `main` and on PRs**, so the branch commits
  have NOT been through the CI Rust gate. The local gate is the only one.
- **Installed on device: `f946e02`.** Confirm any install by reading
  Settings > This device > **Build**, not by spotting a UI change.

## THE INSTALL PATH CHANGED - read this before touching Sideloadly

**zsign + `pymobiledevice3` is the default. Sideloadly is for RENEWALS ONLY.**

    # Anthony runs this (his key, and it stays his):
    /home/ajbufort/padmule-resign/zsign -k <sideloadly>/key.pem \
      -c /home/ajbufort/padmule-resign/cert.pem \
      -m /home/ajbufort/padmule-resign/padmule.mobileprovision \
      -b us.ajbconsulting.padMule.Q444CHAF2Z \
      -o padmule-signed.ipa padmule-unsigned.ipa
    # then the agent installs, ~30 seconds:
    pymobiledevice3 apps install padmule-signed.ipa

Kits stay staged at `/home/ajbufort/padmule-resign/` and
`/home/ajbufort/wda-resign/`. **Every Sideloadly round re-signs WebDriverAgent
without signing its nested `.xctest` and breaks the automation** - that cost an
hour on 2026-08-07. This capability was documented on 2026-08-02 and a stale
MEMORY line said the opposite, so it went unused for five days.

**PROFILE EXPIRIES (the 7-day clock is the PROFILE; the cert runs to 2027):**
WebDriverAgent **2026-08-10**, padMule **2026-08-14**. WDA is the binding one -
when it lapses, agent-driven device testing stops until a Sideloadly renewal.

## Shipped this session

1. **Kad keyword search, all three pieces** (8cf). `kad_keyword_target` hashed the
   WHOLE phrase, so every multi-word search walked toward a hash nobody publishes
   to and reported nothing WITHOUT failing. Now: tokenise per word exactly as
   `CSearchManager::GetWords`, hash only the primary word, filter results
   locally, AND send the search-expression tree (flags `0x8000`) so the storing
   node filters before choosing. **Device-proven: "Yes Prime Minister" returns
   143 results, `server + kad` on every row.** Zero on every prior build.
2. **The status poll no longer waits behind a search** (8cg). Four scalars were
   taking a 20s-capable lock to read a bool, a Copy enum and an `Arc::len`.
   `StatusPub` publishes them as atomics through `EngineHandles`; the Swift reads
   moved from `refresh()` into `refreshFast()`. **Device-proven** - see below.
3. **Three Kad routing fixes** (8ce): live table seeded from what we already
   know, ONE honest contact count, `maintain_kad` capped at 3s.

## HOW TO MEASURE ANYTHING ON THIS DEVICE - read before you measure

**`GET /source` is NOT a passive read.** It walks the whole view hierarchy on the
MAIN THREAD at 1.4-2.4s per call. Polling it once a second STARVES main-thread
work and will manufacture the freeze you are trying to measure. On 2026-08-07 it
produced a reading that refuted a correct fix.

**Take the measurement OUT of the window: record, leave, record once.**

Verified numbers, unobserved, during a real search:

| path | idle | during a search |
|---|---|---|
| status polls (lock-free) | ~1.2/s | **0.94/s** - keeps running |
| heartbeats (takes the lock) | ~1.2/s | **0.69/s** - loses ~10s of ticks |

The counters are on Stats -> **UI responsiveness**. They are a DIAGNOSTIC; if
they stop earning their place, remove them rather than let them accumulate.

**The WDA search field CONCATENATES.** The helper now clears, sets and READS THE
FIELD BACK, aborting on mismatch. Hit again on 2026-08-07: a re-run silently
searched `ministerminister`, which returns nothing fast and therefore produced a
measurement that looked clean *because* it was meaningless.

## THE TOP NEXT ACTION

**The operations are individually slow, and nothing has touched that.** Measured
on device: a search is **10.3s** submit-to-results; a server probe round is
**7.5-10.5s**. `SEARCH_WAIT` is 20s with BOTH arms awaited, and
`PROBE_COLLECT_BUDGET` is 6s held under the engine lock throughout. The freeze is
fixed; the slowness is not, and it is now the biggest user-facing win available.

Two obvious angles, neither measured yet: return the server arm as soon as it
answers instead of awaiting the slower Kad arm (row 8bx did exactly this for
`add_download` and made it 75x faster), and stop holding the engine lock across
the probe's collection budget.

## OPEN

1. **Track 2 - concurrency under load. NOT STARTED.** Anthony's complaint:
   padMule handles numerous concurrent downloads badly. There is **NO cap at all**
   on concurrent downloads - each gets ~4 workers, so 20 downloads is ~80
   concurrent dials. Use HIS shared files as the controlled set (eMule on the
   Acer, port 5998, HighID, on eMule Sunrise); a known swarm beats a public one,
   whose variance has made every prior measurement ambiguous.
2. **Per-file pause/resume: DOES NOT EXIST.** Verified - no engine API, no FFI
   method, no per-download state. `pause()`/`resume()` are whole-engine lifecycle.
   Anthony asked for it plus a clear per-file state. **A build, not a bug.**
3. **A settable max-active download cap with the rest QUEUED**, per-file status
   like eMule. Anthony suggested 20 active. Same feature family as (2) - both
   need a per-file state machine plus a scheduler.
4. **padMule PUBLISHES NOTHING to Kad.** Opcodes 0x43-0x45 undefined, no call
   site; its shares are invisible to every client searching Kad. Payloads decoded
   and banked in [[kad-routing-lifecycle]]. Deliberately NOT half-built - codecs
   without a driver are dead code (row 8by's mistake).
5. **Kad gaps still open** (8ce): no contact expiry or liveness ping (eMule's
   `OnSmallTimer` half), near-biased nodes.dat sample, no bootstrap retry, and
   `KadNode::add_contact` has no Kad-version gate so a peer can put a v1 contact
   in the table over the wire.
6. **The pause teardown does not finish before iOS suspends** - 465ms to
   suspension, 30.5s to completion. `pause()` now logs whether the background
   assertion was GRANTED/REFUSED and how long the work waited. One background
   round trip on a current build answers it. Do not theorise first.
7. Housekeeping: eleven remote branches fully merged and deletable; `main` is
   ahead of `origin/main`, unpushed.

## STANDING DIRECTIVE ADDED THIS SESSION

**eMule 0.70b is the authority for GUI, Settings and per-file behaviour**
(Anthony, 2026-08-06). Third row in the authority table in `CLAUDE.md`; 0.50a
still decides the wire. Check 0.70b BEFORE designing a screen or a download
state, and diverge only deliberately.

## What this session actually taught

- **The answer was already in the repo, three times.** The Kad keyword spec was in
  `docs/raw/wave6-kad-research` line 246 and unimplemented; the install path was
  in `ipad-usb-tooling` and contradicted by a memory line; the Swift bottleneck
  was visible in the code. None needed new information. **Grep our own research
  against the code that claims to implement it.**
- **A capability filed under a soft heading at the bottom of an entry reads as
  trivia, and a memory that contradicts it wins by default.** Anything that
  changes the DEFAULT WORKFLOW goes at the top of the entry AND in memory.
- **An audit of the PLUMBING is not an audit of the FEATURE.** The 2026-08-06
  reanalysis verified the Kad routing table, contact counts, maintenance timers
  and bootstrap - and never ran one keyword search.
- **Two thirds of a spec is not a fix.** Tokenising was correct and "Yes Prime
  Minister" still returned zero until the expression tree landed.
- **Three of this session's instruments were vacuous on the first attempt** - a
  test that passed with its own fix reverted, a depth check that counted bytes
  that meant something else, and a probe that starved what it measured. **Check
  an instrument can FAIL before believing it.**
- **A failed verification deserves the same scepticism as a successful one.** The
  first counter reading refuted a correct fix, and the refutation was the thing
  that was wrong.

## Related

- [[build-progress]] / [[kad-routing-lifecycle]] / [[log]] / [[decisions-and-lessons]]
- [[ipad-usb-tooling]] - install path, WDA runbook, the measurement rules above.
- [[padmule-ipa-delivery]] - the build-and-deliver loop (memory).
- [[net-highid-and-port-forwarding]] - the AirVPN setup; eMule on 5998, HighID.
