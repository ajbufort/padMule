#!/usr/bin/env bash
# Stop hook: enforce CLAUDE.md rule 7 - no intention without a task.
#
# THE DEFECT (2026-08-11). The coordinator ended turns with "I'll do X next";
# the next message redirected, and the intention vanished with no record. Twice
# Anthony had to ask for work that had already been promised. Prose is not a
# ledger, and a promise to do better is not a fix - that was proved the same
# night, when the KB already said an agent may renew a signing profile and
# permission was asked for anyway.
#
# THE TASK LIST IS REAL STATE ON DISK (verified 2026-08-12):
#   ${CLAUDE_CONFIG_DIR:-$HOME/.claude}/tasks/<session-id>/<n>.json
# one JSON object per task, with id / subject / description / status, where
# status is pending | in_progress | completed. It is readable by a hook.
#
# WHAT IS NOT USABLE AS THE TRIGGER: the presence of pending or in_progress
# tasks. "pending" is a legitimate backlog that outlives a session, and the task
# tool instructs the model to keep at least one task in_progress at all times,
# so a hook that blocks on either state fires on every ordinary stop. A Stop
# hook that fires on every turn becomes noise, gets worked around, and then the
# guard is gone.
#
# THE TRIGGER. Two conditions, BOTH required:
#   1. The CLOSING message of the turn - the one Anthony reads, written after
#      every tool call is done, so anything future-tense in it is by
#      construction not happening this turn - SCHEDULES a future action: a
#      first-person commitment ("I'll", "I will", "I'm going to", "I plan to")
#      in the same sentence as a scheduling marker ("next", "then", "once",
#      "as soon as", "later", "tomorrow", "remaining"), and NOT conditional on
#      Anthony answering ("say the word and I'll ..." is an offer, not a
#      commitment).
#   2. The session task list was NOT written during that turn (no task file
#      modified since the timestamp of the message that opened it).
#
# MEASURED, NOT GUESSED, over the 47 closing messages of the session that earned
# the rule: a bare "I'll" appears in 29 of them (62 percent - a hook on that
# alone is noise), while condition 1 selects 14, and all 14 are genuine
# scheduled commitments, including both that were actually dropped. Two further
# sessions put that night in proportion: over 649 closing messages, bare "I'll"
# is 18 percent and condition 1 is 9 percent; over 17, it is 47 and 29 percent.
# Condition 2 then clears every one of them the moment the commitment is
# recorded, which is a single task write. So a turn that promises nothing cannot
# fire, and a turn that promises something and tracks it cannot fire either.
#
# It is ESCAPABLE by design - a session legitimately ends with queued work - and
# stop_hook_active makes it remind ONCE per turn rather than trap the session.
#
# TESTING: pass a transcript path as $1 and a task directory as $2, e.g.
#   .claude/hooks/commitment-check.sh /tmp/fixture.jsonl /tmp/tasks
# Everything it does is read-only.

# The harness passes Stop hooks a JSON object on stdin; stop_hook_active is
# true when this stop is already the result of a previous Stop-hook block,
# i.e. the reminder was ALREADY delivered this turn. Exit quietly then, so the
# hook reminds once per turn instead of blocking every stop. Empty or
# unparseable stdin falls back to the normal behavior - a hook that silently
# stops reminding is worse than one that reminds twice.
input=$(timeout 1 cat 2>/dev/null || true)
active=""
sid=""
tpath=""
if [ -n "$input" ]; then
  if command -v jq >/dev/null 2>&1; then
    active=$(printf '%s' "$input" | jq -r '.stop_hook_active // false' 2>/dev/null)
    sid=$(printf '%s' "$input" | jq -r '.session_id // empty' 2>/dev/null)
    tpath=$(printf '%s' "$input" | jq -r '.transcript_path // empty' 2>/dev/null)
  else
    if printf '%s' "$input" | grep -Eq '"stop_hook_active"[[:space:]]*:[[:space:]]*true'; then
      active="true"
    fi
    sid=$(printf '%s' "$input" | grep -o '"session_id"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
    tpath=$(printf '%s' "$input" | grep -o '"transcript_path"[[:space:]]*:[[:space:]]*"[^"]*"' | head -1 | cut -d'"' -f4)
  fi
fi
if [ "$active" = "true" ]; then
  exit 0
fi

# Test overrides win, so both directions can be demonstrated against fixtures.
[ -n "${1:-}" ] && tpath="$1"
cfg="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"
[ -z "$sid" ] && sid="${CLAUDE_CODE_SESSION_ID:-}"
tasks="$cfg/tasks/$sid"
[ -n "${2:-}" ] && tasks="$2"

# The harness supplies transcript_path; fall back to the per-project transcript
# named for the session, which is where it lives.
if [ -z "$tpath" ] && [ -n "$sid" ]; then
  for c in "$cfg"/projects/*/"$sid".jsonl; do
    [ -f "$c" ] && tpath="$c" && break
  done
fi

# JSON string sanitizer, as in kb-drift-check.sh: everything interpolated below
# is reduced to characters that cannot break out of a JSON string. A message
# that arrives malformed is discarded whole, which is the same silent failure
# this hook exists to stop.
clean() { printf '%s' "$1" | tr -cd '0-9A-Za-z ,.:;/()#_@+-'; }

if ! command -v python3 >/dev/null 2>&1; then
  printf '{"continue":true,"systemMessage":"Commitment check (CLAUDE.md rule 7) is NOT running: python3 is not on PATH, so nothing is enforcing that a stated future action reaches the task list."}\n'
  exit 0
fi

out=$(python3 - "$tpath" "$tasks" <<'PY' 2>/dev/null
import glob
import json
import os
import re
import sys

tpath = sys.argv[1]
tasks = sys.argv[2]
KEEP = re.compile(r"[^0-9A-Za-z ,.:;/()#_@+-]")


def safe(s, n):
    return KEEP.sub(" ", s)[:n].strip()


def note(msg):
    print("NOTE\t" + safe(msg, 200))
    raise SystemExit(0)


if not tpath or not os.path.isfile(tpath):
    note("commitment check could not find the session transcript, so rule 7 is NOT being checked this turn")

# Read only the tail: transcripts reach tens of megabytes, and the closing
# message of the turn is at the end of the file.
TAIL = 4 * 1024 * 1024
try:
    size = os.path.getsize(tpath)
    with open(tpath, "rb") as f:
        if size > TAIL:
            f.seek(size - TAIL)
        raw = f.read().decode("utf-8", "replace")
except OSError:
    note("commitment check could not read the session transcript, so rule 7 is NOT being checked this turn")

lines = raw.splitlines()
if size > TAIL and lines:
    lines = lines[1:]
objs = []
for ln in lines:
    ln = ln.strip()
    if not ln.startswith("{"):
        continue
    try:
        objs.append(json.loads(ln))
    except ValueError:
        pass
if not objs:
    note("commitment check found no readable entries in the session transcript, so rule 7 is NOT being checked this turn")


def texts(o):
    m = o.get("message")
    if not isinstance(m, dict):
        return []
    c = m.get("content")
    if isinstance(c, str):
        return [c]
    if isinstance(c, list):
        return [b.get("text", "") for b in c if isinstance(b, dict) and b.get("type") == "text"]
    return []


def spoke(o):
    return any(t.strip() for t in texts(o))


def is_user(o):
    return o.get("type") == "user" and not o.get("isMeta") and spoke(o)


def when(o):
    t = o.get("timestamp")
    if not isinstance(t, str):
        return None
    try:
        import datetime
        return datetime.datetime.fromisoformat(t.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


# The closing message: the last assistant text of the turn. Scanning back stops
# at a user message, so a turn that ended without the assistant saying anything
# is silent rather than judged on an older message.
closing = None
closing_i = None
for i in range(len(objs) - 1, -1, -1):
    o = objs[i]
    if o.get("type") == "assistant" and not o.get("isSidechain") and spoke(o):
        closing = "\n".join(t for t in texts(o) if t.strip())
        closing_i = i
        break
    if is_user(o):
        break
if closing is None:
    raise SystemExit(0)

COMMIT = re.compile(r"\b(i'?ll|i will|i'?m going to|i am going to|i plan to|i intend to)\b", re.I)
SCHED = re.compile(
    r"\b(next|then|afterwards?|after that|once |as soon as|later|tomorrow|in the morning"
    r"|remaining|still to do|will follow|before stopping|when (it|they|that|the)\b)", re.I)
COND = re.compile(r"(say the word|if you|tell me|let me know|your call|unless you|should you|say so and)", re.I)

hits = []
for s in re.split(r"(?<=[.!?:])\s+|\n+", closing):
    if COMMIT.search(s) and SCHED.search(s) and not COND.search(s):
        hits.append(" ".join(s.split()))
if not hits:
    raise SystemExit(0)

# The turn opened at the last user message; if the tail does not reach it, fall
# back to the oldest entry in the tail, which can only make the window WIDER and
# therefore the hook quieter. Under-firing is the safe direction.
start = None
for i in range(closing_i, -1, -1):
    if is_user(objs[i]):
        start = when(objs[i])
        break
if start is None:
    stamps = [w for w in (when(o) for o in objs) if w]
    start = min(stamps) if stamps else 0.0

touched = False
pending = 0
running = 0
subjects = []
for fp in sorted(glob.glob(os.path.join(tasks, "*.json"))):
    try:
        if os.path.getmtime(fp) >= start - 2:
            touched = True
        with open(fp, encoding="utf-8", errors="replace") as f:
            d = json.load(f)
    except (OSError, ValueError):
        continue
    if not isinstance(d, dict):
        continue
    st = d.get("status")
    if st == "pending":
        pending += 1
    elif st == "in_progress":
        running += 1
    else:
        continue
    if len(subjects) < 3:
        subjects.append(safe(str(d.get("subject", "")), 60))

if touched:
    raise SystemExit(0)

state = "The list holds %d open item(s): %d pending, %d in progress." % (pending + running, pending, running)
if subjects:
    state += " Open now: " + "; ".join(subjects) + "."
print("BLOCK\t" + safe(hits[0], 200) + "\t" + safe(state, 400))
PY
)

kind=$(printf '%s' "$out" | head -1 | cut -f1)

if [ "$kind" = "BLOCK" ]; then
  excerpt=$(printf '%s' "$out" | head -1 | cut -f2)
  state=$(printf '%s' "$out" | head -1 | cut -f3)
  printf '{"decision":"block","reason":"Rule 7 (no intention without a task): the closing message schedules a future action - \\"%s\\" - and the session task list was not written this turn, so that commitment exists only in prose. Prose does not survive the next message: twice on 2026-08-11 an announced next step died when the reply redirected. %s Before stopping, do ONE of these deliberately: record the commitment with the task tool (add it, or mark the task it belongs to), or say plainly in the reply that it is being carried unrecorded and why. This reminder fires once per turn, so it cannot trap the session."}\n' \
    "$(clean "$excerpt")" "$(clean "$state")"
  exit 0
fi

if [ "$kind" = "NOTE" ]; then
  msg=$(printf '%s' "$out" | head -1 | cut -f2)
  printf '{"continue":true,"systemMessage":"%s."}\n' "$(clean "$msg")"
  exit 0
fi

exit 0
