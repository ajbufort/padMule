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

# THE WIKI LIVES IN ITS OWN REPOSITORY (2026-08-11). It is gitignored here and
# has no remote, deliberately - see CLAUDE.md. The original hook asked this
# repo when docs/wiki last changed, which returns NOTHING once the wiki is
# untracked, so it fell through to counting EVERY code commit ever and reported
# 316. Compare TIMESTAMPS across the two repositories instead: the wiki's own
# last commit against this repo's last code commit.
wiki_time=$(git -C docs/wiki log -1 --format=%ct 2>/dev/null)

if [ -z "$wiki_time" ]; then
  # No wiki repo reachable (fresh clone, or the wiki was not obtained). Say so
  # rather than blocking on a count that cannot mean anything here.
  printf '{"decision":"block","reason":"KB check: docs/wiki has no git repository, so the reflection state cannot be read. The wiki is LOCAL-ONLY and is not in this repo (see CLAUDE.md) - obtain it, or run: git -C docs/wiki init. Do not add the wiki back to the public tree."}\n'
  exit 0
fi

code_time=$(git log -1 --format=%ct -- . ':!docs' ':!.claude' ':!CLAUDE.md' 2>/dev/null)
[ -z "$code_time" ] && exit 0

if [ "$code_time" -gt "$wiki_time" ]; then
  # Count the code commits since that moment, for a message that says how much
  # is outstanding rather than merely that something is.
  n=$(git log --format=%H --since="@${wiki_time}" -- . ':!docs' ':!.claude' ':!CLAUDE.md' 2>/dev/null | wc -l | tr -d ' ')
  printf '{"decision":"block","reason":"KB check: %s commit(s) touched code since the wiki was last updated (wiki repo is separate and local-only). Before stopping, reflect any substantive change into docs/wiki (create/update the entry, update index.md, append log.md) and memory, then COMMIT IT IN THE WIKI REPO: git -C docs/wiki add -A && git -C docs/wiki commit. If the change was genuinely trivial, a one-line note in docs/wiki/log.md satisfies this check."}\n' "$n"
fi
exit 0
