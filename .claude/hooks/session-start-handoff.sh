#!/usr/bin/env bash
# SessionStart: begin grounded in the handoff rather than in a summary.
set -uo pipefail
cd "$(dirname "$0")/../.." 2>/dev/null || true
HANDOFF="docs/wiki/handoff-for-fable.md"
[ -f "$HANDOFF" ] || exit 0
# Read the CURRENT gate figure out of the handoff. Four things this has to
# survive, all of them true of the file as it is written today:
#   1. The handoff bolds the WHOLE phrase - "Gate: **838 passed / 0 failed
#      / 4 ignored**" - not just the number, so strip markdown asterisks
#      BEFORE matching. The previous pattern '\*\*[0-9]{3}\*\* (on|pass)'
#      assumed the bold hugged the number, matched nothing, and injected an
#      EMPTY slot into the sentence below without a word of complaint.
#   2. The phrase WRAPS across two source lines, so fold newlines to spaces.
#   3. A SUPERSEDED "Gate: 791 Rust tests" line survives further down in a
#      dated section. It cannot match (it says "Rust tests", not "passed"),
#      and head -1 takes the earliest match in file order anyway - the
#      current one at the top of STATE OF THE TREE.
#   4. The capture is interpolated into the JSON string below, so it is
#      reduced to digits, letters, spaces and slashes: it CANNOT then carry a
#      quote, a backslash or a newline that would make the JSON malformed and
#      get the whole message discarded - the same silent failure again.
GATE="$(tr -d '*' <"$HANDOFF" | tr '\n' ' ' \
  | grep -oE 'Gate: [0-9]+ passed[^,]{0,64}' \
  | head -1 | sed 's/^Gate: //' | tr -s ' ' | tr -cd '0-9A-Za-z /' || true)"
# Require a leading digit: an empty or figure-less capture must SAY it failed,
# never emit a sentence with a hole in it.
if [[ "$GATE" =~ ^[0-9] ]]; then
  GATE_CLAUSE="the gate line there says $GATE, and it is stale the moment the tree moves"
else
  GATE_CLAUSE="THIS HOOK COULD NOT PARSE THE GATE LINE out of that file - go read it there yourself and trust no remembered count"
fi
cat <<JSON
{
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "padMule: READ $HANDOFF IN FULL before doing anything else. It is THE handoff - the only one - and it carries what to do, how this project judges work, the verified state of the tree, the device traps and the carried hazards. Do not act on a remembered state: $GATE_CLAUSE, so re-verify anything load-bearing. Also read /CLAUDE.md for the house rules (ASCII only, never modify amule-3.0.1/ or refs/)."
  }
}
JSON
