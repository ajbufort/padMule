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
#   1. CI must be GREEN for the exact sha. A red build never reaches the device.
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

SHA=$(git rev-parse HEAD)
SHORT=$(git rev-parse --short HEAD)
echo "== shipping $SHORT =="

if [ -n "$(git status --porcelain)" ]; then
  echo "ABORT: working tree is dirty. Commit first - the whole loop keys off HEAD." >&2
  exit 1
fi

echo "-- dispatching CI on this sha"
gh workflow run "iOS build (unsigned IPA)" --ref "$(git rev-parse --abbrev-ref HEAD)"
gh workflow run "Rust unit gate" --ref "$(git rev-parse --abbrev-ref HEAD)"
sleep 15

RID=$(gh run list --workflow="iOS build (unsigned IPA)" --limit 1 --json databaseId,headSha \
      -q "[.[] | select(.headSha==\"$SHA\")][0].databaseId")
[ -n "$RID" ] || { echo "ABORT: no iOS run found for $SHORT" >&2; exit 1; }
echo "-- iOS run $RID"

until [ "$(gh run view "$RID" --json status -q .status)" = "completed" ]; do sleep 20; done
CONC=$(gh run view "$RID" --json conclusion -q .conclusion)
[ "$CONC" = "success" ] || { echo "ABORT: iOS build $CONC - nothing reaches the device" >&2; exit 1; }

# GUARD 2: the artifact must BE this commit.
HEADSHA=$(gh run view "$RID" --json headSha -q .headSha)
[ "$SHA" = "$HEADSHA" ] || { echo "ABORT: run is $HEADSHA, HEAD is $SHA" >&2; exit 1; }

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
