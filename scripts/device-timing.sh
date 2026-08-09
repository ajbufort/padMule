#!/usr/bin/env bash
# Time search submit-to-first-results on the real device, over WebDriverAgent.
# Prints one line per reading; nothing else.
#
# WHY THIS IS A SCRIPT AND NOT A SEQUENCE OF CURLS: every rule below was learned
# by getting a wrong number out of the device, and each one is a line of code
# here rather than a thing to remember.
#
#   1. `GET /source` walks the whole view hierarchy on the MAIN THREAD at
#      1.4-2.4s per call, so it is NEVER the polling probe - only a one-shot
#      read at the end. One `elements` query is ~0.18s; the poll uses those.
#   2. The search field CONCATENATES. Setting it twice searches
#      "ministerminister", which returns nothing fast and therefore looks like a
#      clean, fast result. Every set is cleared first and READ BACK, and a
#      mismatch aborts rather than producing a number.
#   3. THE RESULTS LIST IS NOT CLEARED BETWEEN SEARCHES. A probe polling for
#      rows finds the PREVIOUS run's at t=0 and reports probe latency as a
#      search time. Tap "Clear search" and ASSERT ZERO ROWS before any clock
#      starts.
#   4. A single pair of runs cannot attribute a difference: search populations
#      and probe rounds vary. Each reading is repeated and all values printed -
#      read the spread, not the first number.
#
# FIXED 2026-08-08 after this script was found unable to produce a number at
# all. It had been correct for a UI that changed underneath it:
#   - it located the field with label="Search", which now matches the Search TAB
#     BUTTON ("Search the eD2k network" is the PLACEHOLDER, not the label);
#   - it submitted with POST /wda/keyboard/return, which WDA 16.1.1 does not
#     implement, and curl exits 0 on an error BODY - so the failure was SILENT
#     and the loop timed a search that was never submitted;
#   - it cleared the FIELD but never the RESULTS, walking into rule 3 above -
#     which this very script exists to encode;
#   - it polled /source every 2.5s, a resolution worse than the effect.
# A harness that encodes the rules still has to be RUN to be believed.
#
# NOTE creating the session RELAUNCHES padMule (pid changes), so every
# cumulative in-app counter resets. On-disk state survives, so the app stays
# WARM - see docs/wiki/ipad-usb-tooling.md.
#
# Usage: scripts/device-timing.sh [query] [repeats]
set -uo pipefail

WDA=localhost:8100
# THE BUNDLE ID IS ASKED OF THE DEVICE, not written here. It embeds the Apple
# TEAM ID - a personal account identifier - and this repo is public (CLAUDE.md).
# The device already knows which padMule is installed, and this script is
# talking to it regardless, so asking is both private and more truthful than a
# literal: if a differently-signed build is installed, this drives THAT one
# instead of failing to find a bundle nobody has. Override with
# PADMULE_BUNDLE_ID.
BUNDLE="${PADMULE_BUNDLE_ID:-$(pymobiledevice3 apps list 2>/dev/null | python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(0)
print(next((k for k in d if 'padMule' in k), ''))
" 2>/dev/null)}"
if [ -z "$BUNDLE" ]; then
  echo "ABORT: no padMule bundle found on the device (is it installed, and is" >&2
  echo "       the device reachable?). Set PADMULE_BUNDLE_ID to override." >&2
  exit 1
fi
QUERY="${1:-yes prime minister}"
REPEATS="${2:-5}"

api() { curl -s --max-time 30 "$@"; }

need() {
  api "$WDA/status" | grep -q '"ready" : true' || {
    echo "WDA is not ready on $WDA - start the runner and the port forward first" >&2
    exit 1
  }
}

session() {
  api -X POST "$WDA/session" -H 'Content-Type: application/json' \
    -d "{\"capabilities\":{\"alwaysMatch\":{\"bundleId\":\"$BUNDLE\"}}}" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["value"]["sessionId"])'
}

# The accessibility tree as one flat text blob. EXPENSIVE (rule 1) - one-shot
# reads only, never in a poll.
source_text() {
  api "$WDA/source?format=json" |
    python3 -c '
import json,sys
def walk(n, out):
    for k in ("label","name","value"):
        v = n.get(k)
        if isinstance(v,str) and v.strip():
            out.append(v.strip())
    for c in n.get("children",[]) or []:
        walk(c,out)
d=json.load(sys.stdin)
out=[]
walk(d.get("value",d),out)
print("\n".join(out))
'
}

# Element ids for a locator, space separated.
els() {
  api -X POST "$WDA/session/$SID/elements" -H 'Content-Type: application/json' -d "$1" |
    python3 -c 'import json,sys
v=json.load(sys.stdin).get("value") or []
print(" ".join(e["ELEMENT"] for e in v))'
}
first_by_label() { els "{\"using\":\"link text\",\"value\":\"label=$1\"}" | awk '{print $1}'; }
tap() { api -X POST "$WDA/session/$SID/element/$1/click" -d '{}' >/dev/null; }

# Result rows. Marker is `Get` - ONE BUTTON PER ROW - never `srcs`: a
# single-source row reads "1 src", so an `srcs` matcher cannot fire on a thin
# result set, which is exactly what an unpopular query returns.
count_rows() { els '{"using":"partial link text","value":"label=Get"}' | wc -w; }

need
SID=$(session)
echo "session $SID"
sleep 8 # let the activation settle before timing anything

echo "--- build on device ---"
source_text | grep -iE "^Build|version" | head -3

echo "--- search submit-to-first-results ---"
for i in $(seq 1 "$REPEATS"); do
  # RULE 3: clear the RESULTS, and prove it.
  C=$(first_by_label "Clear search")
  [ -n "$C" ] && tap "$C"
  sleep 1.5
  N=$(count_rows)
  if [ "$N" -ne 0 ]; then echo "run $i: ABORT - $N stale rows survived Clear search"; continue; fi

  # RULE 2: set, then READ BACK.
  F=$(els '{"using":"class name","value":"XCUIElementTypeTextField"}' | awk '{print $1}')
  [ -z "$F" ] && { echo "run $i: ABORT - no search field"; continue; }
  api -X POST "$WDA/session/$SID/element/$F/clear" -d '{}' >/dev/null
  api -X POST "$WDA/session/$SID/element/$F/value" -H 'Content-Type: application/json' \
     -d "$(python3 -c 'import json,sys;print(json.dumps({"value":list(sys.argv[1])}))' "$QUERY")" >/dev/null
  GOT=$(api "$WDA/session/$SID/element/$F/attribute/value" |
        python3 -c 'import json,sys;print(json.load(sys.stdin).get("value") or "")')
  [ "$GOT" = "$QUERY" ] || { echo "run $i: ABORT - field reads '$GOT', not '$QUERY'"; continue; }

  # Submit by TAPPING the keyboard's return key. /wda/keyboard/return does not
  # exist in WDA 16.1.1 and fails silently through curl.
  SK=$(first_by_label "search")
  [ -z "$SK" ] && { echo "run $i: ABORT - no keyboard search key (is the keyboard up?)"; continue; }
  T0=$(date +%s.%N); tap "$SK"
  DL=$(echo "$T0 + 45" | bc -l); HIT=""
  while (( $(echo "$(date +%s.%N) < $DL" | bc -l) )); do
    if [ "$(count_rows)" -gt 0 ]; then HIT=1; break; fi
    sleep 0.4
  done
  EL=$(echo "$(date +%s.%N) - $T0" | bc -l)
  if [ -n "$HIT" ]; then printf "run %d: %.2fs  (%s rows)\n" "$i" "$EL" "$(count_rows)"
  else printf "run %d: TIMEOUT >45s\n" "$i"; fi
  sleep 5 # the engine's server-search flood guard, with room
done

echo "--- READ ONCE, AT THE END: Stats -> Longest poll gap + the Kad panel ---"
echo "(poll gap near 1s = the lock-free poll really did keep running)"
S=$(first_by_label "Statistics"); [ -n "$S" ] && tap "$S"
sleep 4
source_text | grep -iE "poll gap|lookups run|first result|completed|TIMEOUT|FIND_NODE|value ask|high-water|rounds|silent" | head -20
