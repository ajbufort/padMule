#!/usr/bin/env bash
# HANDS-ON APP SIMULATION against the real Lugdunum eserver oracle.
#
# Runs the mule-ffi `simulate` example - which drives the REAL MuleEngine FFI
# through EngineModel's exact call sequence (boot -> start -> connect -> search ->
# get -> transfers -> stats -> preview -> related -> leech -> pause/resume) - inside
# the isolated eserver namespace, so it connects to a real eD2k server with zero
# egress. It is a hands-on review of the on-device experience without a device.
#
# Prereq: run `scripts/eserver-oracle.sh` once so build-oracle/eserver/eserver
# exists (obtained + sha256-verified there). Usage: scripts/simulate.sh [keyword]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/build-oracle/eserver/eserver"
SIM="$REPO/target/release/examples/simulate"
CLI="$REPO/target/release/mule-cli"
PORT=4661
KEYWORD="${1:-test}"

if [ "${SIM_IN_NS:-}" != "1" ]; then
  [ -x "$BIN" ] || { echo "run scripts/eserver-oracle.sh once first (eserver not obtained)"; exit 1; }
  # Build the simulate example AND mule-cli (the index seeder, below).
  ( cd "$REPO" && cargo build --release -p mule-ffi --example simulate -p mule-cli >/dev/null 2>&1 ) \
    || { echo "failed to build the simulate example / mule-cli"; exit 1; }
  export SIM_IN_NS=1 REPO BIN SIM CLI PORT KEYWORD
  exec unshare -rn bash "$0"
fi

# ---- inside the isolated namespace (loopback only) ----
ip link set lo up
WORK="$(mktemp -d)"
ORACLE="$WORK/eserver"; CFG="$WORK/config"; DL="$WORK/downloads"
mkdir -p "$ORACLE" "$CFG" "$DL"
cat > "$ORACLE/donkey.ini" <<EOF
name=padMule-sim-oracle
port=$PORT
welcome=padMule simulation server (isolated)
lowid=1
maxclients=100
EOF
cd "$ORACLE"
rm -f ctl; mkfifo ctl
"$BIN" < ctl > eserver.log 2>&1 &
ESRV=$!
exec 9> ctl
for _ in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 0.2; done

# A minimal server.met so the engine's connect_server dials the local eserver
# (0xE0 header, 1 server, ip 127.0.0.1 low-byte-first, port 4661, no tags).
python3 - "$CFG/server.met" "$PORT" <<'PY'
import sys, struct
path, port = sys.argv[1], int(sys.argv[2])
data = bytes([0xE0]) + struct.pack('<I', 1) \
     + bytes([0x7F, 0x00, 0x00, 0x01]) + struct.pack('<H', port) + struct.pack('<I', 0)
open(path, 'wb').write(data)
PY

# Seed the eserver's index: ONE client offers a small shared library (files named
# with the search keyword) and HOLDS the connection, so the files stay searchable
# while the simulation runs. This is how a real eD2k server gets a searchable index
# - from clients that offer - so the SEARCH screen returns real, sourced results
# instead of an empty set. The seeder is a distinct user from the simulate engine,
# so the searcher sees them as another peer's files. Synthetic names only, no
# content (validates SEARCH + result color-coding, not the byte transfer, which the
# amuled differential test already covers).
SEED_LIB="$KEYWORD sample video.avi|$KEYWORD music track.mp3|$KEYWORD readme notes.txt"
# Hold well past the run; the seeder is killed as soon as the simulation returns.
# A large ceiling lets MATRIX_GAP>0 space searches past the server cooldown.
"$CLI" offer-hold 127.0.0.1 "$PORT" "$SEED_LIB" 300 &
SEED_PID=$!
sleep 2 # let the seeder log in + offer before the search runs
echo "== seeded the eserver index (keyword '$KEYWORD'); running the app simulation =="
"$SIM" "$CFG" "$DL" "$KEYWORD"

kill "$SEED_PID" 2>/dev/null || true
[ -n "${KEEP_LOG:-}" ] && cp "$ORACLE/eserver.log" "$REPO/build-oracle/eserver-sim.log" 2>/dev/null || true
exec 9>&-
wait "$ESRV" 2>/dev/null || true
rm -rf "$WORK"
