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
PORT=4661
KEYWORD="${1:-test}"

if [ "${SIM_IN_NS:-}" != "1" ]; then
  [ -x "$BIN" ] || { echo "run scripts/eserver-oracle.sh once first (eserver not obtained)"; exit 1; }
  ( cd "$REPO" && cargo build --release -p mule-ffi --example simulate >/dev/null 2>&1 ) \
    || { echo "failed to build the simulate example"; exit 1; }
  export SIM_IN_NS=1 REPO BIN SIM PORT KEYWORD
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

echo "== eserver up on 127.0.0.1:$PORT (isolated) - running the app simulation =="
"$SIM" "$CFG" "$DL" "$KEYWORD"

exec 9>&-
wait "$ESRV" 2>/dev/null || true
rm -rf "$WORK"
