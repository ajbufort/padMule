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
#   4. The installed build is confirmed by reading it back off the device, never
#      by assuming the install succeeded.
#
# Usage: scripts/ship.sh [--no-install]
set -euo pipefail

cd "$(dirname "$0")/.."
KIT=/home/ajbufort/padmule-resign
KEY=/mnt/c/Users/ajbuf/AppData/Roaming/Sideloadly/key.pem
BUNDLE=us.ajbconsulting.padMule.Q444CHAF2Z
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
  until [ "$(gh run view "$rid" --json status -q .status)" = "completed" ]; do sleep 20; done
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
( cd "$KIT" && ./zsign -k "$KEY" -c cert.pem -m padmule.mobileprovision -b "$BUNDLE" \
    -o "padmule-signed-$SHORT.ipa" "padmule-unsigned-$SHORT.ipa" ) | grep -E "Version|Signed OK" || true

if [ "${1:-}" = "--no-install" ]; then
  echo "== built and signed $SHORT (install skipped) =="
  exit 0
fi

echo "-- installing"
pymobiledevice3 apps install "$KIT/padmule-signed-$SHORT.ipa" 2>&1 | tail -1

# GUARD 4: WDA must still answer. A Sideloadly round breaks it every time; the
# zsign path does not, and this is what proves it did not.
curl -s --max-time 8 localhost:8100/status \
  | python3 -c "import sys,json;print('-- WDA ready:', json.load(sys.stdin)['value'].get('ready'))" \
  2>/dev/null || echo "-- WDA NOT ANSWERING (device testing unavailable)"

echo "== $SHORT on the device. CONFIRM IT by reading Settings > This device > Build =="

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
#   5. docs/wiki/handoff-next-session.md - REPLACE WHOLESALE: state of the tree,
#      what is installed, what is measured vs assumed, and the top next action.
#      This is what a session after an auto-compact reads FIRST, so it must be
#      true rather than aspirational.
#   6. cross-session memory under ~/.claude/projects/.../memory/
#
# AND AFTER A COMPACT: run the `reanalyze` skill before touching code. A
# compacted session has the conclusions but not the reasons, and this project's
# recurring failure is a claim inherited without its evidence.
