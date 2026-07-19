#!/usr/bin/env bash
# Local eD2k SERVER oracle: run the REAL Lugdunum eserver 17.15 in a fully
# ISOLATED network namespace (loopback only, NO internet egress) and point
# padMule at it. This is the server-side counterpart to the amuled/eMule PEER
# oracles - it lets padMule's server-connect + (future) global-UDP-search code
# talk to the actual software the whole eD2k network runs on. See
# docs/wiki/ed2k-server-oracle.md.
#
# SECURITY: eserver is a legacy (2007) closed-source third-party binary. It runs
# with ZERO network egress inside `unshare -rn` - it physically cannot reach
# anything but loopback (verified: an egress probe fails "Network is
# unreachable"). It is NOT committed (gitignored under build-oracle/eserver/).
#
# The i686 (32-bit) build is used on purpose: the x86_64 build hits the legacy
# vsyscall page (segfault at 0xffffffffff600400), which modern kernels block; the
# 32-bit build does not use it and runs fine under WSL2's IA32 emulation.
#
# Usage:
#   scripts/eserver-oracle.sh                       # eserver + `mule-cli login 127.0.0.1 4661`
#   scripts/eserver-oracle.sh login 127.0.0.1 4661  # any mule-cli subcommand + args
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ORACLE="$REPO/build-oracle/eserver"
BIN="$ORACLE/eserver"
CLI="$REPO/target/release/mule-cli"
PORT=4661
ZIP_URL="https://files.emule-security.org/lugdunum_eserver_17.15_linux.zip"
BIN_SHA="fe38ecdf7165badf0ca47185e6aff813e4c0b074b48f7fc4094231b5303b6f55" # eserver-i686 17.15

if [ "${ESERVER_IN_NS:-}" != "1" ]; then
  # ---- outer: obtain + verify + configure, then re-exec inside the namespace ----
  [ -x "$CLI" ] || { echo "build padMule first: cargo build --release -p mule-cli"; exit 1; }
  if [ ! -x "$BIN" ]; then
    echo "== fetching eserver 17.15 (run isolated only; verified by sha256) =="
    mkdir -p "$ORACLE"; tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/e.zip" "$ZIP_URL"
    unzip -o "$tmp/e.zip" -d "$tmp" >/dev/null
    install -m 0755 "$tmp/eserver-i686" "$BIN"
    rm -rf "$tmp"
  fi
  got="$(sha256sum "$BIN" | cut -d' ' -f1)"
  [ "$got" = "$BIN_SHA" ] || { echo "eserver sha256 mismatch ($got); refusing to run"; exit 1; }
  cat > "$ORACLE/donkey.ini" <<EOF
name=padMule-test-oracle
port=$PORT
welcome=padMule local test server (isolated)
lowid=1
maxclients=100
EOF
  export ESERVER_IN_NS=1 ORACLE BIN CLI PORT
  exec unshare -rn bash "$0" "$@"
fi

# ---- inner: isolated net namespace (only loopback, no egress) ----
ip link set lo up
cd "$ORACLE"
rm -f ctl; mkfifo ctl
"$BIN" < ctl > eserver.log 2>&1 &
ESRV=$!
exec 9> ctl # hold stdin open so eserver does not EOF-exit
for i in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q ":$PORT " && break; sleep 0.2; done

echo "== eserver 17.15 (lugdunum) listening on 127.0.0.1:$PORT - isolated, no internet egress =="
if [ "$#" -gt 0 ]; then
  "$CLI" "$@"
else
  "$CLI" login 127.0.0.1 "$PORT"
fi

exec 9>&- # EOF -> eserver exits
wait "$ESRV" 2>/dev/null || true
