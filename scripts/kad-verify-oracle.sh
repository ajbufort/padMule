#!/usr/bin/env bash
# REVERSE-KAD ORACLE: prove a REAL amuled 3.0.1 flips padMule's Kad IP-verified
# bit via padMule's v8 HELLO_RES_ACK three-way handshake. This is the terminal
# proof for the Kad hard-verify send-side work (docs/wiki/build-progress wave 10):
# the receive side was live-proven, but "a real node verifies US" could not be,
# because a stock node logs nothing when it flips the bit. So we run a LOGGING-
# INSTRUMENTED amuled (scripts/build-amuled-kad-oracle.sh - a committed, auditable,
# logging-only patch; the pristine amule-3.0.1/ is untouched) and watch for its
# PADMULE-ORACLE-VERIFIED line naming padMule's IP.
#
# Topology (all inside one `unshare -rn` namespace, zero egress):
#   padMule (mule-cli kad-bootstrap) at PAD_IP  --HELLO_REQ/RES/RES_ACK-->  amuled at AM_IP
# We pre-seed amuled's Kad ID (preferencesKad.dat) so we can build a one-contact
# nodes.dat pointing padMule straight at it, and a src-route so padMule's socket
# sources from PAD_IP (distinct from amuled's, or amuled would self-reject).
#
# Prereqs: scripts/build-amuled-kad-oracle.sh once + `cargo build --release -p mule-cli`.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$REPO/target/release/mule-cli"
AMULED="$REPO/build-oracle/kad-build/src/amuled"

PAD_IP=77.77.0.9        # padMule (mule-cli) source IP
AM_IP=88.88.0.3         # amuled Kad node IP
# Kad rides the CLIENT UDP socket, which binds to UDPPort. The SERVER UDP socket
# binds to TCP+3, so UDPPort must NOT equal TCP+3 or the client socket collides
# and falls back to an ephemeral port. TCP 4662 -> server UDP 4665; Kad UDP 4672.
AM_UDP=4672             # amuled client/Kad UDP port (= UDPPort)
AM_TCP=4662             # amuled ed2k TCP port (server UDP = 4665)
# padMule's mule-cli kad-bootstrap binds UDP 4672 (hardcoded); nothing to set.

# A fixed, non-zero 16-byte Kad ID we assign to amuled (byte-identical in its
# preferencesKad.dat and in padMule's nodes.dat -> the NodeID obfuscation keys match).
KADID_HEX="0123456789abcdef0123456789abcdef"

if [ "${KV_IN_NS:-}" != "1" ]; then
  [ -x "$CLI" ]    || { echo "build padMule first: cargo build --release -p mule-cli"; exit 1; }
  [ -x "$AMULED" ] || { echo "instrumented amuled missing: run scripts/build-amuled-kad-oracle.sh"; exit 1; }
  export KV_IN_NS=1
  exec unshare -rn bash "$0" "$@"
fi

# ---- inside the isolated namespace ----
WORK="$(mktemp -d)"; CFG="$WORK/amuled"
mkdir -p "$CFG/Incoming" "$CFG/Temp"
cleanup() { kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

ip link set lo up
ip link add name d0 type dummy 2>/dev/null
ip addr add "$PAD_IP/24" dev d0        # padMule IP first (interface primary)
ip addr add "$AM_IP/24"  dev d0
ip link set d0 up
# Force padMule's UNSPECIFIED-bound socket to source from PAD_IP when it dials
# amuled (else the kernel would pick AM_IP - amuled's own subnet address - and
# amuled would reject a contact at its own IP).
ip route add "$AM_IP/32" dev d0 src "$PAD_IP"

# 1) amuled: generate a default config, then tune it for an isolated Kad-only run.
timeout 6 "$AMULED" -c "$CFG" -o -i >/dev/null 2>&1
sed -i -E "s/^Port=.*/Port=$AM_TCP/; s/^UDPPort=.*/UDPPort=$AM_UDP/; \
  s/^Autoconnect=.*/Autoconnect=1/; s/^ConnectToKad=.*/ConnectToKad=1/; \
  s/^AcceptExternalConnections=.*/AcceptExternalConnections=1/; \
  s/^ECPassword=.*/ECPassword=098f6bcd4621d373cade4e832627b4f6/; \
  s|^Address=.*|Address=$AM_IP|; \
  s/^FilterLanIPs=.*/FilterLanIPs=0/; \
  s/^IpFilterClients=.*/IpFilterClients=0/; s/^IpFilterServers=.*/IpFilterServers=0/; \
  s/^IPFilterAutoLoad=.*/IPFilterAutoLoad=0/; \
  s/^IsCryptLayerSupported=.*/IsCryptLayerSupported=0/; \
  s/^IsCryptLayerRequested=.*/IsCryptLayerRequested=0/; \
  s/^IsCryptLayerRequired=.*/IsCryptLayerRequired=0/" "$CFG/amule.conf"

# 2) Pre-seed amuled's Kad identity so we know its Kad ID up front.
#    preferencesKad.dat = u32 ip | u16 (unused) | u128 kadID(16) | u8 0
python3 - "$CFG/preferencesKad.dat" "$KADID_HEX" <<'PY'
import sys, struct
path, kadhex = sys.argv[1], sys.argv[2]
kad = bytes.fromhex(kadhex)
assert len(kad) == 16
open(path, 'wb').write(struct.pack('<I', 0) + struct.pack('<H', 0) + kad + b'\x00')
PY

# 3) padMule's nodes.dat: a single contact = amuled (same Kad ID bytes).
#    header u32 0 | u32 2 | u32 1, then a 34-byte v2 record.
NODES="$WORK/nodes.dat"
python3 - "$NODES" "$KADID_HEX" "$AM_IP" "$AM_UDP" "$AM_TCP" <<'PY'
import sys, struct, socket
path, kadhex, ip, udp, tcp = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
kad = bytes.fromhex(kadhex)
ip_host = int.from_bytes(socket.inet_aton(ip), 'big')   # host-order u32 (MSB=first octet)
rec  = kad
rec += struct.pack('<I', ip_host)      # ip (LE of host-order, matches mule-files read_u32)
rec += struct.pack('<H', udp)          # udp port
rec += struct.pack('<H', tcp)          # tcp port
rec += struct.pack('<B', 8)            # contact version (aMule v8)
rec += struct.pack('<I', 0)            # udp_key
rec += struct.pack('<I', 0)            # udp_key_ip
rec += struct.pack('<B', 0)            # verified
hdr = struct.pack('<III', 0, 2, 1)
open(path, 'wb').write(hdr + rec)
PY

# 4) start amuled (Kad auto-starts via Autoconnect + ConnectToKad). Clear the
# logfile the config-gen run left behind so diagnostics reflect only THIS run.
rm -f "$CFG/logfile"
"$AMULED" -c "$CFG" -o -i > "$WORK/amuled.log" 2>&1 &
AM=$!
echo "== instrumented amuled starting (Kad on $AM_IP:$AM_UDP, id $KADID_HEX)..."
# `-o` sends the full log (incl. our critical PADMULE-ORACLE line) to stdout, so
# the redirected amuled.log is authoritative on its own.
LOGS() { cat "$WORK/amuled.log" 2>/dev/null; }

# Wait until Kad is actually up (its listener rides the CLIENT UDP socket) before
# driving padMule - otherwise early attempts hit a not-yet-listening node.
for _ in $(seq 1 30); do
  kill -0 "$AM" 2>/dev/null || { echo "amuled exited early"; LOGS | tail -20; exit 1; }
  LOGS | grep -q "Kad started" && break
  sleep 0.5
done
# Diagnostic: the client UDP socket MUST be on $AM_UDP. If a port collision forced
# an ephemeral fallback, padMule can never reach Kad - surface it plainly.
CUDP="$(LOGS | grep -oE 'Client UDP socket \(extended eMule\) at [0-9.]+:[0-9]+' | tail -1)"
echo "== $CUDP (need :$AM_UDP)"
case "$CUDP" in
  *":$AM_UDP") : ;;
  *) echo "WARN: client/Kad UDP is NOT on $AM_UDP - padMule cannot reach it"; ;;
esac

# 5) drive padMule against it, retrying a few times for Kad warmup.
VERIFIED=0
for attempt in $(seq 1 8); do
  kill -0 "$AM" 2>/dev/null || { echo "amuled exited early"; break; }
  "$CLI" kad-bootstrap "$NODES" "$PAD_IP" > "$WORK/cli.$attempt.log" 2>&1
  if LOGS | grep -q "PADMULE-ORACLE-VERIFIED"; then VERIFIED=1; break; fi
  sleep 2
done

echo; echo "===== RESULT ====="
if [ "$VERIFIED" = 1 ]; then
  echo "PASS: a REAL amuled 3.0.1 marked padMule IP-verified via the v8 handshake."
  echo "--- amuled verify line(s) ---"
  LOGS | grep "PADMULE-ORACLE-VERIFIED"
  echo "--- padMule side (last attempt) ---"
  grep -E "BOOTSTRAP_RES|HELLO_RES|HELLO after" "$WORK"/cli.*.log 2>/dev/null | tail -4
else
  echo "FAIL/INCOMPLETE: no PADMULE-ORACLE-VERIFIED line from amuled."
  echo "--- padMule last attempt ---"; tail -8 "$WORK"/cli.*.log 2>/dev/null | tail -12
  echo "--- amuled log (Kad lines) ---"; LOGS | grep -iE "kad|verif|bootstrap|hello" | tail -20
  echo "--- amuled log tail ---"; LOGS | tail -15
fi
[ "$VERIFIED" = 1 ]
