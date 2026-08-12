#!/usr/bin/env bash
# Stop hook: catch KB DRIFT in docs/wiki/handoff-for-fable.md - the one document
# every session is told to read IN FULL. Three checks:
#
#   1. CONTRADICTION (BLOCKS) - two un-annotated answers to the same question.
#      The file's convention is that the TOP block is current and every dated
#      block below it is history, annotated in place when superseded. That
#      convention fails SILENTLY: an un-annotated stale block is indistinguishable
#      from current text. It happened - for two days the file said both "838
#      passed / 4 ignored" and "791 Rust tests", both "e786ce5" and "6652ed5"
#      on the device, and it was caught by an audit, never by a reader.
#   2. CLOSED WORK ACCUMULATING (warns) - struck-through and CLOSED/DONE/FIXED
#      items piling up instead of moving to a *-history archive.
#   3. ENTRY SIZE (warns) - recently-touched wiki entries over the ~150-line
#      convention in CLAUDE.md.
#
# NOTHING HERE IS HARD-CODED TO TODAY'S NUMBERS. Check 1 asks whether two
# DISTINCT un-annotated values coexist, not whether a count equals some figure.
#
# TESTING: pass an alternate handoff path as $1, e.g.
#   .claude/hooks/kb-drift-check.sh /tmp/fixture.md
# Defaults to docs/wiki/handoff-for-fable.md. Checks 2 and 3 are read-only, so
# running it by hand cannot touch the wiki. Check 1 assumes a document whose
# CURRENT answer is at the top; pointed at an append-only ledger like log.md it
# reports every dated entry, because there every differing figure is legitimate.

# The harness passes Stop hooks a JSON object on stdin; stop_hook_active is
# true when this stop is already the result of a previous Stop-hook block,
# i.e. the reminder was ALREADY delivered this turn. Exit quietly then, so the
# hook reminds once per turn instead of blocking every stop. Empty or
# unparseable stdin falls back to the normal behavior - a hook that silently
# stops reminding is worse than one that reminds twice.
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
wiki="$repo/docs/wiki"
handoff="${1:-$wiki/handoff-for-fable.md}"
[ -f "$handoff" ] || exit 0

# JSON string sanitizer: everything interpolated below is reduced to characters
# that cannot break out of a JSON string. A message that arrives malformed is
# discarded whole, which is the same silent failure this hook exists to stop.
clean() { printf '%s' "$1" | tr -cd '0-9A-Za-z ,.:;/()#_@+-'; }

# ---------------------------------------------------------------- check 1
# Claims of two kinds, in file order:
#   GATE   - "Gate: **840 passed / ..." and, historically, "Gate: 791 Rust tests"
#   DEVICE - "ON THE DEVICE: `<sha>`" / "On the device: `<sha>`"
# The FIRST occurrence of a kind is the current answer and needs no annotation
# (it is the top block). Every LATER occurrence with a DIFFERENT value must
# carry a supersession marker, or it reads as a second live answer.
#
# The device pattern requires the sha in BACKTICKS and within a few characters
# of the phrase. That is how the file writes a STATE claim; quoted ship.sh quotes
# further down ("-- CONFIRMED on the device: 6652ed5") are narrative, not state,
# and matching them would fire on correctly-annotated text and train the reader
# to ignore this hook.
#
# A marker counts if it appears anywhere in the claim's own block (blank line,
# heading, bullet or numbered item starts a new one) or, for "~~", on the claim's
# own line. "~~" is NOT taken block-wide: this file strikes through closed
# checklist items constantly, and one of those sits inside the very block that
# carried the real defect - honoring it block-wide would miss the defect.
# [CLOSED / [DONE / [FIXED / [CLEARED / [VERIFIED are deliberately NOT markers:
# they close work, they do not supersede a claim. The marker list was taken from
# the vocabulary the handoff actually uses, so a correctly-annotated block does
# not fire - a check that fires on correct text is as useless as one that misses.
findings=$(awk '
function record(kind, val,   i) {
  i = ++n[kind]
  L[kind, i] = NR; V[kind, i] = val; S[kind, i] = scope
  SELF[kind, i] = ($0 ~ /~~/) ? 1 : 0
}
BEGIN { scope = 0 }
{
  if ($0 ~ /^[[:space:]]*$/ || $0 ~ /^#/ || $0 ~ /^- / || $0 ~ /^[0-9]+\. /) scope++
  U = toupper($0)
  if (U ~ /\[(STALE|SUPERSEDED|SUPERSEDES|CORRECTED|OBSOLETE|OUTDATED|COUNT NOW WRONG|NO LONGER|HISTORICAL|UPDATED|WAS )/) marked[scope] = 1

  # GATE
  u = $0; gsub(/[*`]/, "", u); UG = toupper(u)
  p = index(UG, "GATE:")
  if (p > 0) {
    rest = substr(u, p + 5)
    sub(/^[ \t]+/, "", rest)
    if (match(rest, /^[0-9]+/)) record("gate", substr(rest, RSTART, RLENGTH))
  }

  # DEVICE
  p = index(U, "ON THE DEVICE:")
  if (p > 0) {
    rest = substr($0, p + 14)
    a = index(rest, "`")
    if (a > 0 && a <= 25) {
      r2 = substr(rest, a + 1); b = index(r2, "`")
      if (b > 1) {
        sha = substr(r2, 1, b - 1)
        if (sha ~ /^[0-9a-fA-F]+$/ && length(sha) >= 7 && length(sha) <= 40) record("device", sha)
      }
    }
  }
}
END {
  split("gate device", kinds, " ")
  for (k = 1; k <= 2; k++) {
    kind = kinds[k]
    if (n[kind] < 2) continue
    for (i = 2; i <= n[kind]; i++) {
      if (V[kind, i] == V[kind, 1]) continue
      if (marked[S[kind, i]] || SELF[kind, i]) continue
      printf "%s|%d|%s|%d|%s\n", toupper(kind), L[kind, 1], V[kind, 1], L[kind, i], V[kind, i]
    }
  }
}' "$handoff")

# ---------------------------------------------------------------- check 2
# Closed work accumulating. THRESHOLD 35, measured rather than guessed. Before
# the 2026-08-11 split the handoff carried 20 struck-through numbered items plus
# 16 CLOSED/DONE/FIXED lines (36) - and that is the level at which the split into
# handoff-history.md was actually judged necessary. After it the file carries
# 7 + 8 = 15. So 35 is the level a human already called unwieldy: it cannot fire
# today at less than half of it, it does not fire on a session that closes a few
# items, and it fires exactly when the file has climbed back to the state that
# needed an archive split last time. A threshold that fires on day one is noise
# and gets worked around.
CLOSED_MAX=35
struck=$(grep -cE '^[0-9]+\. ~~' "$handoff" 2>/dev/null || true)
closed=$(grep -cE '\[(CLOSED|DONE|FIXED)' "$handoff" 2>/dev/null || true)
[ -z "$struck" ] && struck=0
[ -z "$closed" ] && closed=0
closed_total=$((struck + closed))

# ---------------------------------------------------------------- check 3
# Entry size, per the CLAUDE.md convention "keep entries under ~150 lines -
# EXCEPT append-only ledgers (log.md, decisions-and-lessons) and archive entries
# (build-history)". CLAUDE.md does not list build-progress.md by name, but it
# calls it the ledger that split its own *-history archive, so it is exempt as a
# ledger; *-history.md generalizes the archive exemption CLAUDE.md names.
# 13 non-exempt entries are over the line today, so the report is capped at a
# count plus the 3 largest and scoped to entries touched in the last 24 hours:
# naming a standing backlog in full at every stop is a nag, not a finding, and
# gets tuned out. Scoped this way it decays to nothing as the KB is tidied.
big=""
big_n=0
if [ -d "$wiki" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    base=$(basename "$f")
    case "$base" in
      log.md|build-progress.md|decisions-and-lessons.md|*-history.md) continue ;;
    esac
    lines=$(wc -l <"$f" 2>/dev/null || echo 0)
    if [ "$lines" -gt 150 ]; then
      big_n=$((big_n + 1))
      [ "$big_n" -le 3 ] && big="$big $base ($lines)"
    fi
  done <<EOF
$(find "$wiki" -maxdepth 1 -name '*.md' -mmin -1440 2>/dev/null | sort)
EOF
fi

# ---------------------------------------------------------------- report
name=$(basename "$handoff")
block=""
found_n=0
while IFS='|' read -r kind l1 v1 l2 v2; do
  [ -n "$kind" ] || continue
  found_n=$((found_n + 1))
  # Cap the named findings: a reason with dozens of clauses is unreadable, and
  # the first few are enough to find the block that needs annotating.
  [ "$found_n" -le 4 ] || continue
  block="$block $(clean "$kind") claim: line $(clean "$l1") says $(clean "$v1") (first in file order, so the current one) and line $(clean "$l2") says $(clean "$v2") with no supersession marker."
done <<EOF
$findings
EOF
if [ "$found_n" -gt 4 ]; then
  block="$block Plus $(clean "$((found_n - 4))") more of the same shape."
fi

warn=""
if [ "$closed_total" -gt "$CLOSED_MAX" ]; then
  warn="$warn Closed work is accumulating in $(clean "$name"): $(clean "$struck") struck-through numbered items plus $(clean "$closed") CLOSED/DONE/FIXED lines (threshold $CLOSED_MAX). Move the closed narratives VERBATIM into handoff-history rather than trimming them."
fi
if [ "$big_n" -gt 0 ]; then
  warn="$warn Entry size: $(clean "$big_n") non-exempt wiki entr(y/ies) touched in the last 24h exceed the ~150-line convention -$(clean "$big"). Split completed narratives verbatim into a *-history archive."
fi

if [ -n "$block" ]; then
  printf '{"decision":"block","reason":"KB drift check FAILED on %s - it now holds two live answers to the same question, and an un-annotated stale block is indistinguishable from current text.%s Fix it before stopping: annotate the superseded text IN PLACE (**[STALE - ... ]**) naming what replaces it, or move it to handoff-history. Do not leave it for later; that is what produced a two-day contradiction in the one file every session reads in full.%s"}\n' \
    "$(clean "$name")" "$block" "$warn"
  exit 0
fi

if [ -n "$warn" ]; then
  printf '{"continue":true,"systemMessage":"KB drift check:%s"}\n' "$warn"
  exit 0
fi

exit 0
