#!/usr/bin/env bash
# Differential transfer test: padMule downloads a file from a REAL amuled and
# verifies it byte-for-byte. This is the true Wave 4 gate - padMule talking to
# genuine aMule, not to another padMule.
#
# The shared file is deliberately COMPRESSIBLE so amuled serves it via
# OP_COMPRESSEDPART (the per-block zlib path the Wave-4d review fix added). A
# second random file exercises the raw OP_SENDINGPART path.
#
# Prereq: scripts/build-amuled-oracle.sh has produced build-oracle/src/amuled,
# and `cargo build --release -p mule-cli` has produced target/release/mule-cli.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AMULED="$REPO/build-oracle/src/amuled"
CLI="$REPO/target/release/mule-cli"
WORK="${SCRATCH:-/tmp}/padmule-difftest-$$"
CFG="$WORK/amuled-cfg"
PORT=5662
FAIL=0

# Kill amuled on exit. Do NOT `wait` on it - it is a network daemon that dies by
# signal (exit 128+SIG), and `wait` would surface that as the script's status.
cleanup() {
  [ -n "${AM_PID:-}" ] && kill "$AM_PID" 2>/dev/null
  # give it a moment to release the port; disown so its signal death is not ours
  sleep 1
}
trap cleanup EXIT

command -v "$AMULED" >/dev/null || { echo "amuled not built: $AMULED"; exit 1; }
[ -x "$CLI" ] || { echo "mule-cli not built: $CLI"; exit 1; }

mkdir -p "$CFG/Incoming" "$CFG/Temp" "$WORK/out"

# Three shared files exercising the distinct download paths:
#  - compressible (single part)  -> OP_COMPRESSEDPART
#  - random       (single part)  -> raw OP_SENDINGPART
#  - multipart 15 MB (2 eD2k parts, mixed content) -> OP_HASHSETREQUEST/ANSWER +
#    per-part MD4 verification against amuled's real hashset.
python3 - "$CFG/Incoming" <<'PY'
import os, sys, random
d = sys.argv[1]
r = random.Random(1234)
with open(os.path.join(d, "compressible.bin"), "wb") as f:
    f.write((b"padMule differential test, the quick brown fox jumps. " * 12000)[:600_000])
with open(os.path.join(d, "random.bin"), "wb") as f:
    f.write(r.randbytes(400_000))  # randbytes: fast, avoids per-byte generators
# 15 MB, alternating compressible + random 1 MB chunks (both block paths, needs a hashset).
chunks = [(b"block %d compressible filler ... " % i * 40000)[:1_000_000] if i % 2 == 0
          else r.randbytes(1_000_000) for i in range(15)]
with open(os.path.join(d, "multipart.bin"), "wb") as f:
    f.write(b"".join(chunks))
print("shared files written")
PY

# Generate amuled's default config, then tune it. amuled REFUSES to run with
# external connections disabled, so we must enable EC (password stored as MD5;
# this is md5("test")). We also set our TCP port and disable server auto-connect
# (this is an offline peer-to-peer test).
timeout 6 "$AMULED" -c "$CFG" -o -i >/dev/null 2>&1
sed -i -E "s/^Port=.*/Port=$PORT/; \
  s/^Autoconnect=.*/Autoconnect=0/; \
  s/^AcceptExternalConnections=.*/AcceptExternalConnections=1/; \
  s/^ECPassword=.*/ECPassword=098f6bcd4621d373cade4e832627b4f6/" "$CFG/amule.conf"

echo "== starting amuled on 127.0.0.1:$PORT (sharing Incoming) =="
"$AMULED" -c "$CFG" -o -i > "$WORK/amuled.log" 2>&1 &
AM_PID=$!
disown "$AM_PID" 2>/dev/null || true

# Wait until amuled is listening on the TCP port. known.met grows past its 5-byte
# empty header once the shared files are hashed.
LISTENING=0
for _ in $(seq 1 60); do
  if ss -ltn 2>/dev/null | grep -q ":$PORT "; then LISTENING=1; break; fi
  if ! kill -0 "$AM_PID" 2>/dev/null; then break; fi
  sleep 0.5
done
if [ "$LISTENING" != 1 ]; then
  echo "amuled never listened on $PORT; log tail:"; tail -25 "$WORK/amuled.log"; exit 1
fi
# Give the async hasher time to finish all shared files (the 15 MB one is the
# slowest). known.met grows past its 5-byte empty header once files are hashed.
for _ in $(seq 1 40); do
  [ "$(stat -c%s "$CFG/known.met" 2>/dev/null || echo 0)" -gt 100 ] && break
  sleep 0.5
done
sleep 4

run_one() {
  local name="$1"
  local src="$CFG/Incoming/$name"
  local out="$WORK/out/$name"
  local hash size
  read -r hash size < <("$CLI" hash-file "$src")
  echo "-- $name: hash=$hash size=$size"
  "$CLI" peer-download 127.0.0.1 "$PORT" "$hash" "$size" "$out"
  if [ -f "$out" ] && cmp -s "$src" "$out"; then
    echo "   PASS: $name transferred byte-for-byte from amuled"
  else
    echo "   FAIL: $name did not match (see $out)"; FAIL=1
  fi
}

echo "== downloading from amuled with padMule =="
run_one compressible.bin
run_one random.bin
run_one multipart.bin  # multi-part: exercises the hashset exchange + verification

echo
if [ "$FAIL" = 0 ]; then
  echo "DIFFERENTIAL TEST PASSED: padMule interoperates with real aMule 3.0.1"
else
  echo "DIFFERENTIAL TEST FAILED"; echo "amuled log tail:"; tail -30 "$WORK/amuled.log"
fi
exit $FAIL
