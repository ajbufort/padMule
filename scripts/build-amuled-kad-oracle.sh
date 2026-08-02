#!/usr/bin/env bash
# Build a LOG-INSTRUMENTED amuled for the Kad verified-bit oracle. This is the
# reverse-Kad oracle padMule could not otherwise have: a REAL amuled that logs
# when it flips a contact's IP-verified bit, so we can prove padMule's v8
# HELLO_RES_ACK handshake actually earns the verified bit at a genuine node.
#
# FIDELITY: the pristine amule-3.0.1/ tree is NEVER touched. We copy it into the
# gitignored build-oracle/ area and apply scripts/amule-oracle-kad-verify.patch -
# a LOGGING-ONLY diff (two AddDebugLogLineC calls, zero behaviour change), which
# is committed and auditable. AddDebugLogLineC is the CRITICAL log macro; unlike
# AddDebugLogLineN it is compiled in for a Release build and always emits, so no
# verbose config is needed and no __DEBUG__ build (with its wxASSERTs) is required.
#
# Prereqs: same as scripts/build-amuled-oracle.sh
#   sudo apt install -y cmake libwxgtk3.2-dev libcrypto++-dev zlib1g-dev
# This script itself needs no sudo. One-time (~minutes); idempotent (skips if the
# instrumented amuled already exists - pass `clean` to force a rebuild).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRISTINE="$REPO/amule-3.0.1"
PATCH="$REPO/scripts/amule-oracle-kad-verify.patch"
SRC="$REPO/build-oracle/amule-instrumented-src"
BUILD="$REPO/build-oracle/kad-build"
AMULED="$BUILD/src/amuled"

if [ "${1:-}" = "clean" ]; then rm -rf "$SRC" "$BUILD"; fi
if [ -x "$AMULED" ]; then
  echo "instrumented amuled already built: $AMULED"
  echo "(pass 'clean' to force a rebuild)"
  exit 0
fi

echo "== copying pristine amule-3.0.1 -> build-oracle/amule-instrumented-src (pristine untouched) =="
rm -rf "$SRC"
cp -a "$PRISTINE" "$SRC"

echo "== applying the logging-only patch (auditable: scripts/amule-oracle-kad-verify.patch) =="
( cd "$SRC" && patch -p1 < "$PATCH" )

echo "== configuring instrumented amuled (daemon only, Release - same flags as build-amuled-oracle.sh) =="
cmake -S "$SRC" -B "$BUILD" \
  -DBUILD_DAEMON=ON \
  -DBUILD_MONOLITHIC=OFF \
  -DBUILD_TESTING=OFF \
  -DENABLE_IP2COUNTRY=NO \
  -DENABLE_UPNP=NO \
  -DENABLE_BFD=NO \
  -DENABLE_NLS=NO \
  -DCMAKE_BUILD_TYPE=Release

echo "== building =="
cmake --build "$BUILD" -j"$(nproc)"

echo
if [ -x "$AMULED" ]; then
  echo "instrumented amuled: $AMULED"
else
  echo "BUILD FAILED - amuled not found at $AMULED"; exit 1
fi
