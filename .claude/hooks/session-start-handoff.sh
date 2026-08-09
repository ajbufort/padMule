#!/usr/bin/env bash
# SessionStart: begin grounded in the handoff rather than in a summary.
set -uo pipefail
cd "$(dirname "$0")/../.." 2>/dev/null || true
HANDOFF="docs/wiki/handoff-for-fable.md"
[ -f "$HANDOFF" ] || exit 0
GATE="$(grep -m1 -oE '\*\*[0-9]{3}\*\* (on|pass)' "$HANDOFF" 2>/dev/null || true)"
cat <<JSON
{
  "hookSpecificOutput": {
    "hookEventName": "SessionStart",
    "additionalContext": "padMule: READ $HANDOFF IN FULL before doing anything else. It is THE handoff - the only one - and it carries what to do, how this project judges work, the verified state of the tree, the device traps and the carried hazards. Do not act on a remembered state: the gate line there says $GATE, and it is stale the moment the tree moves, so re-verify anything load-bearing. Also read /CLAUDE.md for the house rules (ASCII only, never modify amule-3.0.1/ or refs/)."
  }
}
JSON
