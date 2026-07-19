#!/usr/bin/env bash
# Live peer-oracle test: download a file a REAL eMule (running on the Windows
# host) is sharing, and verify it byte-for-byte. This is the eMule analogue of
# differential-test.sh (which uses a headless amuled built in WSL); it gives a
# SECOND, independent peer oracle - a real Windows eMule 0.50a - for the peer
# protocol (HELLO, file request, transfer, and secure identification).
#
# Setup + why: docs/wiki/emule-peer-oracle.md.
#
# Usage:
#   scripts/emule-oracle.sh 'ed2k://|file|NAME|SIZE|HASH|/' [host] [port]
#
#   - Paste eMule's ED2K link for a SHARED file (eMule: right-click the file ->
#     "Create ED2K-Link", or Shared Files -> copy link). We parse hash + size.
#   - host defaults to 127.0.0.1: WSL2 mirrored networking shares the Windows
#     host's localhost, so a Windows-side eMule is reachable there. (Fallback:
#     this box's LAN IP, 192.168.0.32.)
#   - port defaults to 4663: set eMule's TCP port to this. Do NOT use 4662 -
#     mirrored mode shares the port space with padMule's own 4662 listener.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
CLI="$REPO/target/release/mule-cli"
LINK="${1:?usage: emule-oracle.sh <ed2k-link> [host] [port]}"
HOST="${2:-127.0.0.1}"
PORT="${3:-4663}"

[ -x "$CLI" ] || { echo "build first: cargo build --release -p mule-cli"; exit 1; }

# ed2k://|file|<name>|<size>|<hash>|/  ->  split on '|'
IFS='|' read -r _scheme _kind NAME SIZE HASH _rest <<<"$LINK"
if [ -z "${HASH:-}" ] || [ -z "${SIZE:-}" ]; then
  echo "could not parse ED2K link (want ed2k://|file|NAME|SIZE|HASH|/): $LINK"
  exit 1
fi

OUTDIR="$(mktemp -d)"
OUT="$OUTDIR/${NAME:-out.bin}"
echo "== eMule peer oracle =="
echo "   file: ${NAME:-?}  size: $SIZE  hash: $HASH"
echo "   from: $HOST:$PORT  (real eMule on the Windows host)"
echo

# peer-download connects out to eMule, runs the HELLO + file request, pulls the
# file across (queuing if eMule rations its slot), and verifies the ed2k hash.
"$CLI" peer-download "$HOST" "$PORT" "$HASH" "$SIZE" "$OUT"

echo
got=$(stat -c%s "$OUT" 2>/dev/null || echo 0)
if [ "$got" = "$SIZE" ]; then
  echo "PASS: got all $SIZE bytes (hash-verified) -> $OUT"
else
  echo "INCOMPLETE: got $got of $SIZE bytes (see the peer-download output above)."
  echo "(inspect the raw handshake, incl. any OP_SECIDENTSTATE, with:"
  echo "   $CLI peer-probe $HOST $PORT $HASH )"
fi
