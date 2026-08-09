#!/usr/bin/env bash
# THE CLOSED LOOP: commit -> CI -> verify -> sign -> install -> confirm.
#
# Anthony granted the signing key to the agent on 2026-08-07, which is what
# makes this a loop rather than a relay. Before that, every device round needed
# him to run zsign by hand, so an agent could build but never see its own change
# on glass.
#
# THE GUARDS ARE THE POINT, not the convenience. Each one exists because its
# absence already cost a session:
#
#   1. ALL THREE CI workflows must be GREEN for the exact sha - the iOS build,
#      the Rust unit gate AND the Swift simulator tests. Until 2026-08-07 this
#      only checked the iOS build: the Rust gate was dispatched and its result
#      never read, and the Swift tests were never dispatched at all, so a red
#      workspace would ship.
#   2. The artifact's headSha must equal local HEAD. On 2026-08-07 a
#      `gh run download` hit a pre-existing file, errored, and a two-day-old
#      artifact was one step from being delivered as current.
#   3. CFBundleVersion INSIDE the downloaded ipa must equal the short sha, read
#      from a FRESH extraction directory - the check that caught (2).
#   4. The installed build is confirmed by reading CFBundleVersion back OFF THE
#      DEVICE and comparing it to the sha, never by assuming the install
#      succeeded. `apps install` exits 0 on paths that leave no new build, so
#      its exit status is not evidence. [Until 2026-08-08 this guard did not
#      exist: the code carrying the label was a WebDriverAgent /status ping and
#      the run ended by telling a HUMAN to read Settings, so the loop was open
#      at its last link while the header claimed otherwise. Found by the row-8cp
#      reanalysis and closed the same day.]
#   5. origin/<branch> must ALREADY be at HEAD. `gh workflow run --ref` builds
#      the REMOTE ref, so an unpushed commit silently builds the wrong tree.
#      Added 2026-08-08 after 12 local commits sent CI to build the tip from
#      before them; guard 2 caught it, but reported "no run found" rather than
#      the actual cause.
#   6. An open XCUITest session is CLOSED before installing, and a RUNNING
#      padMule is terminated. Either one has been observed parking
#      `apps install` at zero CPU, which is indistinguishable from a slow
#      install. (The session case is proven; the running-app case is a strong
#      timing correlation from a single 2026-08-08 observation.)
#
# Usage: scripts/ship.sh [--no-install]
set -euo pipefail

cd "$(dirname "$0")/.."
KIT=/home/ajbufort/padmule-resign
KEY=/mnt/c/Users/ajbuf/AppData/Roaming/Sideloadly/key.pem
# THE BUNDLE ID COMES FROM THE PROVISIONING PROFILE, never from a literal here.
#
# Two reasons, and the second is the better one. (1) PRIVACY: the id embeds the
# Apple TEAM ID, a personal account identifier, and this repo is public - the
# same rule that keeps public IPs and client ids out of it (CLAUDE.md). (2)
# CORRECTNESS: zsign must sign with the id the profile actually authorises, so
# reading it FROM the profile makes a mismatch impossible instead of merely
# unlikely. `padmule.mobileprovision` lives in $KIT, which is outside the repo.
#
# Override with PADMULE_BUNDLE_ID when signing against a different profile.
BUNDLE="${PADMULE_BUNDLE_ID:-$(python3 - "$KIT/padmule.mobileprovision" <<'PYEOF'
import plistlib, sys
try:
    raw = open(sys.argv[1], "rb").read()
    start = raw.find(b"<?xml")
    end = raw.find(b"</plist>") + len(b"</plist>")
    d = plistlib.loads(raw[start:end])
    # "application-identifier" is "<TEAMID>.<bundle id>"; drop the team prefix.
    app_id = d["Entitlements"]["application-identifier"]
    print(app_id.split(".", 1)[1])
except Exception:
    pass
PYEOF
)}"
if [ -z "$BUNDLE" ]; then
  echo "ABORT: could not read the bundle id from $KIT/padmule.mobileprovision." >&2
  echo "       That profile is what authorises the signature, so guessing the id" >&2
  echo "       would just produce an app the device refuses. Set PADMULE_BUNDLE_ID" >&2
  echo "       to override." >&2
  exit 1
fi
WORK="${CLAUDE_JOB_DIR:-/tmp}/ship"

# ONE SHIP AT A TIME. Two overlapping runs on 2026-08-07 both reached the
# install and both LOST it: iOS answers a second concurrent installation with
# "Coordinator superseded", so the earlier one dies and the later one can die
# too. The device is a single resource and the lock says so.
LOCK=/tmp/padmule-ship.lock
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "ABORT: another ship is in flight (holding $LOCK). The device takes one \
installation at a time - a second one supersedes the first and can lose both." >&2
  exit 1
fi

SHA=$(git rev-parse HEAD)
SHORT=$(git rev-parse --short HEAD)
echo "== shipping $SHORT =="

if [ -n "$(git status --porcelain)" ]; then
  echo "ABORT: working tree is dirty. Commit first - the whole loop keys off HEAD." >&2
  exit 1
fi

BRANCH="$(git rev-parse --abbrev-ref HEAD)"

# THE REMOTE MUST ALREADY BE AT HEAD. `gh workflow run --ref` dispatches against
# the REMOTE branch, so an unpushed commit builds whatever origin last saw - and
# every downstream guard then correctly refuses the artifact, reporting the
# useless "no run found for <sha>" instead of the actual cause. Cost one ship on
# 2026-08-08, with 12 local commits and CI happily building the tip from before
# them. Checked here so the message names the real problem.
REMOTE_SHA="$(git rev-parse "origin/$BRANCH" 2>/dev/null || true)"
if [ "$REMOTE_SHA" != "$SHA" ]; then
  echo "ABORT: origin/$BRANCH is at ${REMOTE_SHA:-<no remote branch>}, HEAD is $SHA." >&2
  echo "       CI builds the REMOTE ref, so it would build the wrong tree." >&2
  echo "       Push first:  git push origin $BRANCH" >&2
  exit 1
fi

echo "-- dispatching CI on this sha"
# ALL THREE, and all three are CHECKED below. Until 2026-08-07 this script
# dispatched the Rust gate and never read its conclusion, and never dispatched
# the Swift tests at all - so guard 1 ("CI must be GREEN for the exact sha")
# was true only of the iOS build, and a red workspace would ship. That matters
# more since row 8ci, because the Swift suite is what RENDERS the views, and
# rendering is the only thing that can catch a layout bug the accessibility
# tree reads as correct.
for wf in "iOS build (unsigned IPA)" "Rust unit gate" "iOS unit tests (simulator)"; do
  gh workflow run "$wf" --ref "$BRANCH"
done
sleep 15

# Find a workflow's run FOR THIS EXACT SHA, wait for it, and require success.
# --limit 20, not 1: the newest run of a workflow is not necessarily ours (a
# parallel branch, a re-run), and with --limit 1 a mismatch looked identical to
# "CI has not started yet".
run_id_for () {
  gh run list --workflow="$1" --limit 20 --json databaseId,headSha \
    -q "[.[] | select(.headSha==\"$SHA\")][0].databaseId"
}
require_green () {
  local wf="$1" rid=""
  for _ in $(seq 1 12); do
    rid=$(run_id_for "$wf"); [ -n "$rid" ] && break; sleep 10
  done
  [ -n "$rid" ] || { echo "ABORT: no '$wf' run found for $SHORT" >&2; exit 1; }
  echo "-- $wf: run $rid" >&2
  # BOUNDED. This used to be an unbounded `until completed`, and it runs while
  # the flock is HELD - so a queued or wedged runner blocked every later ship
  # with "another ship is in flight" and no way to tell that from a real one.
  # 40 minutes is generous against the ~12 the macOS jobs take.
  local waited=0
  until [ "$(gh run view "$rid" --json status -q .status)" = "completed" ]; do
    sleep 20
    waited=$((waited + 20))
    if [ "$waited" -ge 2400 ]; then
      echo "ABORT: '$wf' (run $rid) still not completed after 40min - not holding \
the device lock any longer. Check it: gh run view $rid" >&2
      exit 1
    fi
  done
  local conc; conc=$(gh run view "$rid" --json conclusion -q .conclusion)
  [ "$conc" = "success" ] || { echo "ABORT: '$wf' $conc - nothing reaches the device" >&2; exit 1; }
  # GUARD 2 per workflow: the run must BE this commit.
  local head; head=$(gh run view "$rid" --json headSha -q .headSha)
  [ "$SHA" = "$head" ] || { echo "ABORT: '$wf' run is $head, HEAD is $SHA" >&2; exit 1; }
  echo "$rid"
}

RID=$(require_green "iOS build (unsigned IPA)")
require_green "Rust unit gate" >/dev/null
require_green "iOS unit tests (simulator)" >/dev/null

echo "-- downloading into a FRESH directory"
rm -rf "$WORK"; mkdir -p "$WORK/x"
gh run download "$RID" --dir "$WORK" >/dev/null
( cd "$WORK/x" && unzip -q "$WORK/padMule-ipa/padMule.ipa" )

# GUARD 3: read the version out of the artifact itself.
GOT=$(python3 -c "import plistlib;print(plistlib.load(open('$WORK/x/Payload/padMule.app/Info.plist','rb'))['CFBundleVersion'])")
[ "$GOT" = "$SHORT" ] || { echo "ABORT: artifact says '$GOT', expected '$SHORT'" >&2; exit 1; }
echo "-- artifact verified as $SHORT"

cp "$WORK/padMule-ipa/padMule.ipa" "/mnt/c/Users/ajbuf/Downloads/padMule-INSTALL-THIS-unsigned-$SHORT.ipa"
cp "$WORK/padMule-ipa/padMule.ipa" "$KIT/padmule-unsigned-$SHORT.ipa"

echo "-- signing"
# A FAILING zsign MUST STOP THE SHIP. This was
#   ( ... zsign ... ) | grep -E "Version|Signed OK" || true
# where the `|| true` discarded zsign's exit status entirely (and under
# pipefail the grep's too), so a signing failure printed nothing and the run
# marched on to install whatever `padmule-signed-$SHORT.ipa` happened to be on
# disk - which, on a re-ship of the same sha, is the PREVIOUS attempt's file.
# Silently installing a stale build is exactly the class of lie guards 2 and 3
# exist to prevent, so it is checked the same way.
rm -f "$KIT/padmule-signed-$SHORT.ipa"
if ! ( cd "$KIT" && ./zsign -k "$KEY" -c cert.pem -m padmule.mobileprovision -b "$BUNDLE" \
    -o "padmule-signed-$SHORT.ipa" "padmule-unsigned-$SHORT.ipa" ) > "$WORK/zsign.log" 2>&1; then
  echo "ABORT: zsign FAILED - nothing reaches the device. Its output:" >&2
  tail -20 "$WORK/zsign.log" >&2
  exit 1
fi
grep -E "Version|Signed OK" "$WORK/zsign.log" || true
# And the file must actually exist now: `rm -f` above plus this turns "zsign
# quietly wrote nothing" into an abort rather than an install of a ghost.
[ -s "$KIT/padmule-signed-$SHORT.ipa" ] || {
  echo "ABORT: zsign reported success but produced no signed ipa" >&2; exit 1; }

if [ "${1:-}" = "--no-install" ]; then
  echo "== built and signed $SHORT (install skipped) =="
  exit 0
fi

# AN ACTIVE XCUITest SESSION BLOCKS `apps install` INDEFINITELY - ten minutes at
# ZERO CPU parked in do_epoll_wait, released instantly by DELETE /session. It
# looks exactly like a slow install, which is the worst kind of hang. Closing a
# session we did not open is safe: it only ends UI DRIVING, which an install is
# about to invalidate anyway, and the next `POST /session` re-creates it.
SESS=$(curl -s --max-time 8 localhost:8100/status \
  | python3 -c "import sys,json;print(json.load(sys.stdin).get('sessionId') or '')" 2>/dev/null || true)
if [ -n "$SESS" ]; then
  echo "-- closing the open WDA session $SESS (it would block the install)"
  curl -s -X DELETE --max-time 15 "localhost:8100/session/$SESS" >/dev/null || true
fi

# AND TERMINATE THE APP ITSELF IF IT IS RUNNING. On 2026-08-08 an install sat
# PARKED for ~9 minutes - `apps install` at ZERO CPU, 151 ticks unchanged across
# a 10s sample - with NO WDA session open, so it was not the trap above. padMule
# was RUNNING at the time; killing it at 20:06:41 was followed by
# "Installation succeed" at 20:06:42. **ONE OBSERVATION, so this is a strong
# timing correlation rather than proven causation** - but it matches the earlier
# clean install that day, where closing the WDA session had already terminated
# the app, and terminating a build you are about to REPLACE costs nothing.
RUNPID=$(pymobiledevice3 developer dvt proclist 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print(next((str(p.get('pid')) for p in d if str(p.get('name')) == 'padMule'), ''))
" 2>/dev/null || true)
if [ -n "$RUNPID" ]; then
  echo "-- padMule is running (pid $RUNPID); terminating it before the install"
  pymobiledevice3 developer dvt kill "$RUNPID" >/dev/null 2>&1 || true
  sleep 2
fi

echo "-- installing"
# BOUNDED, and for the same reason the CI wait is: this whole script holds the
# flock, so an install that never returns does not just hang this run - it
# blocks every later ship with "another ship is in flight" and no way to tell
# that from a real one. Guards 6/6b remove the two KNOWN parking causes (an
# open XCUITest session, a running padMule); a third would park here forever.
# 10 minutes is ~20x a normal ~30s install and longer than either measured
# parking episode.
if ! timeout 600 pymobiledevice3 apps install "$KIT/padmule-signed-$SHORT.ipa" 2>&1 | tail -1; then
  echo "ABORT: the install did not finish within 600s (or failed outright)." >&2
  echo "       If it PARKED, the cause is a third blocker beyond the XCUITest" >&2
  echo "       session and a running padMule - sample the installer's CPU twice:" >&2
  echo "       parked ticks mean blocked, climbing ticks mean merely slow." >&2
  exit 1
fi

# GUARD 4, FOR REAL. This block used to be a WebDriverAgent `/status` ping, and
# the run ended by telling a HUMAN to read Settings - so the "closed loop" was
# open at its last link, and the header above it claimed a read-back that the
# code never performed. `pymobiledevice3 apps install` also exits 0 on paths
# that do not leave a new build installed, which is precisely why the version
# has to come back OFF THE DEVICE rather than from the installer's exit.
echo "-- reading the installed build back off the device"
# EXACT bundle id, not a substring. `'padMule' in k` took the FIRST key merely
# CONTAINING the name, so a second padMule left over under a different team
# suffix could answer for this one - and a guard whose whole job is to not be
# fooled must not read another app's version. $BUNDLE is derived from the
# profile above and already validated non-empty.
ON_DEV=$(pymobiledevice3 apps list 2>/dev/null | python3 -c "
import sys,json
d=json.load(sys.stdin)
print(d.get(sys.argv[1],{}).get('CFBundleVersion',''))
" "$BUNDLE" 2>/dev/null || true)
[ "$ON_DEV" = "$SHORT" ] || {
  echo "ABORT: the device reports '$ON_DEV', expected '$SHORT' - the install did \
NOT land, whatever the installer said" >&2; exit 1; }
echo "-- CONFIRMED on the device: $ON_DEV"

# WDA is a SEPARATE question from the install: a Sideloadly round breaks it every
# time, the zsign path does not, and this is what proves it did not. Never fatal.
curl -s --max-time 8 localhost:8100/status \
  | python3 -c "import sys,json;print('-- WDA ready:', json.load(sys.stdin)['value'].get('ready'))" \
  2>/dev/null || echo "-- WDA NOT ANSWERING (UI driving unavailable; install is unaffected)"

echo "== $SHORT is ON the device, read back off it. =="
echo "   Installed is not RUNNING: launch it to confirm execution -"
echo "   pymobiledevice3 developer dvt launch $BUNDLE"

# ---------------------------------------------------------------------------
# AFTER A SHIP: the KB and the handoff are part of the loop, not a chore that
# follows it (Anthony, 2026-08-07). A `.claude` stop hook already refuses to let
# a session end with code committed and docs/wiki untouched; this is the same
# rule stated where the work happens.
#
#   1. docs/wiki/build-progress.md   - a row for what shipped and what it MEANS
#   2. the entry the change belongs to (kad-routing-lifecycle, security-model...)
#   3. docs/wiki/index.md            - if an entry was created or changed subject
#   4. docs/wiki/log.md              - append, always
#   5. docs/wiki/handoff-for-fable.md - update IN PLACE (there is exactly ONE
#      handoff since the 2026-08-08 merge; handoff-next-session.md is a retired
#      stub - do not write there): state of the tree, what is installed, what is
#      measured vs assumed, and the top next action. This is what a session
#      after an auto-compact reads FIRST, so it must be true, and RE-READ THE
#      WHOLE FILE after editing - its worst failures are self-contradictions.
#   6. cross-session memory under ~/.claude/projects/.../memory/
#
# AND AFTER A COMPACT: run the `reanalyze` skill before touching code. A
# compacted session has the conclusions but not the reasons, and this project's
# recurring failure is a claim inherited without its evidence.
