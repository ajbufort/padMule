#!/usr/bin/env bash
# Time the operations row 8ch was meant to speed up, on the real device, over
# WebDriverAgent. Prints one line per reading; nothing else.
#
# WHY THIS IS A SCRIPT AND NOT A SEQUENCE OF CURLS: every rule below was learned
# by getting a wrong number out of the device, and each one is a line of code
# here rather than a thing to remember.
#
#   1. `GET /source` walks the whole view hierarchy on the MAIN THREAD at
#      1.4-2.4s per call. Polling it once a second STARVES the work being
#      measured and manufactures the freeze. So the poll interval is 2.5s and
#      the readings that matter are taken AFTER the operation, never during.
#   2. The WDA search field CONCATENATES. Setting it twice searches
#      "ministerminister", which returns nothing fast and therefore looks like a
#      clean, fast result. Every set is cleared first and READ BACK, and a
#      mismatch aborts rather than producing a number.
#   3. A single pair of runs cannot attribute a difference: search populations
#      and probe rounds vary. Each reading is repeated and all values printed -
#      read the spread, not the first number.
#
# Usage: scripts/device-timing.sh [query]
set -uo pipefail

WDA=localhost:8100
BUNDLE=us.ajbconsulting.padMule.Q444CHAF2Z
QUERY="${1:-yes prime minister}"
REPEATS=2

api() { curl -s --max-time 30 "$@"; }

need() {
  api "$WDA/status" | grep -q '"ready" : true' || {
    echo "WDA is not ready on $WDA - start the runner and the port forward first" >&2
    exit 1
  }
}

# The accessibility tree as one flat text blob: every label, one per line. Cheap
# enough to grep, expensive enough that callers must not loop on it tightly.
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

session() {
  api -X POST "$WDA/session" -H 'Content-Type: application/json' \
    -d "{\"capabilities\":{\"alwaysMatch\":{\"bundleId\":\"$BUNDLE\"}}}" |
    python3 -c 'import json,sys; print(json.load(sys.stdin)["value"]["sessionId"])'
}

# First element whose name/label matches $2 exactly, as an element id.
find_element() {
  api -X POST "$WDA/session/$1/elements" -H 'Content-Type: application/json' \
    -d "{\"using\":\"link text\",\"value\":\"label=$2\"}" |
    python3 -c 'import json,sys
v=json.load(sys.stdin).get("value") or []
print(v[0]["ELEMENT"] if v else "")'
}

tap() { api -X POST "$WDA/session/$1/element/$2/click" -d '{}' >/dev/null; }

# Clear, set, and READ BACK. Rule 2 above: the field concatenates, and a silent
# concatenation produces a fast meaningless result that looks like a good one.
set_field() {
  local sid=$1 eid=$2 text=$3
  api -X POST "$WDA/session/$sid/element/$eid/clear" -d '{}' >/dev/null
  api -X POST "$WDA/session/$sid/element/$eid/value" -H 'Content-Type: application/json' \
    -d "$(python3 -c 'import json,sys; print(json.dumps({"value":list(sys.argv[1])}))' "$text")" >/dev/null
  local got
  got=$(api "$WDA/session/$sid/element/$eid/attribute/value" |
    python3 -c 'import json,sys; print(json.load(sys.stdin).get("value") or "")')
  if [ "$got" != "$text" ]; then
    echo "ABORT: the search field reads '$got', not '$text' - it concatenated." >&2
    return 1
  fi
}

# Wait until the tree contains $2, polling no faster than rule 1 allows.
# Prints the elapsed seconds, or "timeout".
wait_for() {
  local pattern=$1 limit=$2 t0 now
  t0=$(date +%s.%N)
  while :; do
    now=$(date +%s.%N)
    if (($(echo "$now - $t0 > $limit" | bc -l))); then
      echo "timeout"
      return 1
    fi
    if source_text | grep -qE "$pattern"; then
      echo "$(echo "$now - $t0" | bc -l)"
      return 0
    fi
    sleep 2.5
  done
}

need
SID=$(session)
echo "session $SID"
sleep 8 # let the activation settle before timing anything

echo "--- build on device ---"
source_text | grep -iE "build|version" | head -5

echo "--- search submit-to-results (was 10.3s) ---"
for i in $(seq 1 $REPEATS); do
  FIELD=$(find_element "$SID" "Search")
  [ -z "$FIELD" ] && { echo "run $i: no search field found"; break; }
  set_field "$SID" "$FIELD" "$QUERY" || break
  T0=$(date +%s.%N)
  api -X POST "$WDA/session/$SID/wda/keyboard/return" -d '{}' >/dev/null 2>&1 ||
    api -X POST "$WDA/session/$SID/element/$FIELD/value" \
      -H 'Content-Type: application/json' -d '{"value":["\n"]}' >/dev/null
  echo "run $i: $(wait_for 'srcs|sources|server \+ kad|No results' 40)s"
  sleep 5 # the engine's 2s server-search flood guard, with room
done

echo "--- READ ONCE, AT THE END: Stats -> Longest poll gap ---"
echo "(near 1s = the lock-free poll really did keep running)"
source_text | grep -iE "poll gap|Status polls|Heartbeats" | head -6
