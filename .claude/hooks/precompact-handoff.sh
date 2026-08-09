#!/usr/bin/env bash
# PreCompact: the handoff is the ONLY thing that survives compaction intact.
#
# Anthony's standing pain (2026-08-08): after each compaction the session drifts,
# and re-grounding it by hand (/clear then /reanalyze) is taxing. Compaction is
# exactly the moment the handoff must be true, because everything else is about
# to become a summary of a summary.
set -uo pipefail
HANDOFF="docs/wiki/handoff-for-fable.md"
cat <<JSON
{
  "systemMessage": "PreCompact: update $HANDOFF before context is summarised.",
  "hookSpecificOutput": {
    "hookEventName": "PreCompact",
    "additionalContext": "CONTEXT IS ABOUT TO BE COMPACTED. Before it is, bring $HANDOFF up to date - it is the ONE document that survives compaction intact, and everything else you are holding is about to become a summary. Specifically: (1) VERIFY rather than remember - re-run the gate (cargo test --workspace, clippy, fmt) and read git log/status for the real state, because a remembered number is exactly what goes stale here; (2) update the task list, striking what closed and adding what you found, since an ephemeral list does not survive; (3) record any hazard, trap or refuted finding discovered this session; (4) re-read the WHOLE file afterwards, not just your edit - its worst failures have been self-contradiction, one bullet disagreeing with another 25 lines away. Then say in one line what you changed."
  }
}
JSON
