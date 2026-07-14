#!/usr/bin/env bash
# Build a headless amuled from amule-3.0.1/ to use as the differential-test
# ORACLE for padMule. This is the true end-to-end check for the Wave 4 gate:
# padMule talking to real aMule, not to another padMule (which cannot catch a
# mistake we made consistently in both directions).
#
# Prereqs (need Anthony's password once):
#   sudo apt install -y cmake libwxgtk3.2-dev libcrypto++-dev zlib1g-dev
#
# This script itself needs no sudo.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$REPO/amule-3.0.1"
BUILD="$REPO/build-oracle"

echo "== configuring amuled (daemon only, no GUI) =="
cmake -S "$SRC" -B "$BUILD" \
  -DBUILD_DAEMON=ON \
  -DBUILD_MONOLITHIC=OFF \
  -DBUILD_TESTING=ON \
  -DCMAKE_BUILD_TYPE=Release

echo "== building =="
cmake --build "$BUILD" -j"$(nproc)"

echo "== upstream unit tests (independent cross-check of our codecs) =="
ctest --test-dir "$BUILD" --output-on-failure || true

echo
echo "amuled binary:"
find "$BUILD" -name 'amuled' -type f -printf '  %p\n' || echo "  (not found - check the build log)"
