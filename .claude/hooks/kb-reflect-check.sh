#!/usr/bin/env bash
# Stop hook: if code was committed after the wiki was last updated, block
# stopping and ask for a reflection pass. Escape hatch: a one-line note in
# docs/wiki/log.md counts as a wiki update, so trivial changes never loop.
#
# The harness passes Stop hooks a JSON object on stdin; stop_hook_active is
# true when this stop is already the result of a previous Stop-hook block,
# i.e. the reminder was ALREADY delivered this turn. Exit quietly then, so
# the hook reminds once per turn instead of blocking every stop. Empty or
# unparseable stdin falls back to the normal blocking behaviour - a hook
# that silently stops reminding is worse than one that reminds twice.
input=$(timeout 1 cat 2>/dev/null || true)
active=""
if [ -n "$input" ]; then
  if command -v jq >/dev/null 2>&1; then
    active=$(printf '%s' "$input" | jq -r '.stop_hook_active // false' 2>/dev/null)
  elif printf '%s' "$input" | grep -Eq '"stop_hook_active"[[:space:]]*:[[:space:]]*true'; then
    active="true"
  fi
fi
if [ "$active" = "true" ]; then
  exit 0
fi

repo="${CLAUDE_PROJECT_DIR:-/home/ajbufort/claude-projects/padMule}"
cd "$repo" 2>/dev/null || exit 0
git rev-parse --git-dir >/dev/null 2>&1 || exit 0

wiki_commit=$(git log -1 --format=%H -- docs/wiki 2>/dev/null)
if [ -n "$wiki_commit" ]; then
  code_since=$(git log --format=%H "${wiki_commit}..HEAD" -- . ':!docs' ':!.claude' ':!CLAUDE.md' 2>/dev/null | wc -l | tr -d ' ')
else
  code_since=$(git log --format=%H -- . ':!docs' ':!.claude' ':!CLAUDE.md' 2>/dev/null | wc -l | tr -d ' ')
fi

if [ "${code_since:-0}" -gt 0 ]; then
  printf '{"decision":"block","reason":"KB check: %s commit(s) touched code since docs/wiki was last updated. Before stopping, reflect any substantive change into docs/wiki (create/update the entry, update index.md, append log.md) and memory. If the change was genuinely trivial, add a one-line note to docs/wiki/log.md to acknowledge it and satisfy this check."}\n' "$code_since"
fi
exit 0
