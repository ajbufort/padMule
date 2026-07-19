#!/usr/bin/env bash
# Generate a GOLDEN AICH root hash from the REAL amuled oracle, for the
# differential AICH test (crates/mule-proto/src/aich.rs). aMule computes the AICH
# hashset while hashing a shared file and stores it in `known2_64.met` (the AICH
# hashset backup), laid out as version(1) | [ root(20) | count(u32) |
# count*hash(20) ] per file. (known.met itself stays a 5-byte empty header, so the
# root is read from known2_64.met.) We share a DETERMINISTIC 10 MB file (> PARTSIZE
# 9,728,000, so the multi-part tree branch is exercised), let amuled hash it, then
# read the 20-byte master root.
#
# The file bytes follow a fixed LCG so the Rust test can regenerate them exactly:
#   byte[i] = ((i * 1103515245 + 12345) >> 16) & 0xFF     (i < 2^34, no overflow)
#
# Prereq: scripts/build-amuled-oracle.sh has produced build-oracle/src/amuled.
# Output: prints "AICH_GOLDEN_HEX=<40 hex>" for the 20-byte root.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
AMULED="$REPO/build-oracle/src/amuled"
PORT=4712
N=10000000

command -v "$AMULED" >/dev/null || { echo "amuled not built: $AMULED (run scripts/build-amuled-oracle.sh)"; exit 1; }

WORK="$(mktemp -d)"
CFG="$WORK/amuled-cfg"
trap 'pkill -P $$ 2>/dev/null || true; [ -n "${AM_PID:-}" ] && kill "$AM_PID" 2>/dev/null || true; rm -rf "$WORK"' EXIT
mkdir -p "$CFG/Incoming" "$CFG/Temp"

python3 - "$CFG/Incoming/aich-golden-10mb.bin" "$N" <<'PY'
import sys
path, n = sys.argv[1], int(sys.argv[2])
buf = bytearray(n)
for i in range(n):
    buf[i] = ((i * 1103515245 + 12345) >> 16) & 0xFF
with open(path, "wb") as f:
    f.write(buf)
print(f"wrote {n} deterministic bytes")
PY

# amuled refuses to run with external connections off; mirror differential-test.sh.
timeout 6 "$AMULED" -c "$CFG" -o -i >/dev/null 2>&1 || true
sed -i -E "s/^Port=.*/Port=$PORT/; \
  s/^Autoconnect=.*/Autoconnect=0/; \
  s/^AcceptExternalConnections=.*/AcceptExternalConnections=1/; \
  s/^ECPassword=.*/ECPassword=098f6bcd4621d373cade4e832627b4f6/" "$CFG/amule.conf"

echo "== starting amuled (sharing the golden file) =="
"$AMULED" -c "$CFG" -o -i > "$WORK/amuled.log" 2>&1 &
AM_PID=$!
for _ in $(seq 1 60); do
  ss -ltn 2>/dev/null | grep -q ":$PORT " && break
  kill -0 "$AM_PID" 2>/dev/null || { echo "amuled died:"; tail -20 "$WORK/amuled.log"; exit 1; }
  sleep 0.5
done
# Wait for the async hasher to write the AICH hashset backup.
for _ in $(seq 1 60); do
  [ "$(stat -c%s "$CFG/known2_64.met" 2>/dev/null || echo 0)" -gt 25 ] && break
  sleep 0.5
done
sleep 4

# Read the 20-byte master root from known2_64.met and verify the structure.
python3 - "$CFG/known2_64.met" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
if len(data) <= 25:
    sys.exit("known2_64.met too small - amuled did not hash the shared file")
ver = data[0]
root = data[1:21]
count = int.from_bytes(data[21:25], "little")
expect = 1 + 20 + 4 + count * 20
assert expect == len(data), f"unexpected layout: 1+20+4+{count}*20={expect} != {len(data)}"
print(f"known2_64.met version={ver:#x}, blocks={count}, ok")
print("AICH_GOLDEN_HEX=" + root.hex())
PY
