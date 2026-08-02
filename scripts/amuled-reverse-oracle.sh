#!/usr/bin/env bash
# REVERSE-direction peer oracle: a REAL amuled DOWNLOADS a file FROM padMule,
# relayed through the real Lugdunum eserver. This validates padMule's SERVE-side
# wire bytes (filename/status/hashset/accept/sending-part) against a genuine
# client - the direction scripts/differential-test.sh does NOT cover (that one
# has padMule download FROM amuled). See docs/wiki/emule-peer-oracle.md.
#
# Why the eserver: amuled will NOT dial an OFFLINE, link-embedded source, but it
# WILL request sources from a connected server and dial them. So padMule offers
# the file to the eserver, and amuled (connected to it) discovers padMule as a
# source and dials it.
#
# All processes run in ONE isolated network namespace (unshare -rn, no egress)
# with PUBLIC-looking IPs on distinct /24s: amuled filters PRIVATE server IPs, and
# a source must differ from both the server IP and amuled's own IP. Everything is
# fake and local; no packet leaves the namespace.
#
# Prereqs: scripts/build-amuled-oracle.sh (amuled) + scripts/eserver-oracle.sh once
# (eserver, sha256-verified) + `cargo build --release -p mule-cli`.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$REPO/target/release/mule-cli"
AMULED="$REPO/build-oracle/src/amuled"
ESERVER="$REPO/build-oracle/eserver/eserver"

ESRV_PORT=4661
ESRV_IP=45.45.0.1       # eserver address amuled connects to (its "server IP")
PAD_ESRV_IP=77.77.0.9   # eserver address padMule connects to (padMule's /24)
SRV_IP=77.77.0.2        # padMule serve/HighID subnet (interface primary)
SERVE_PORT=4662
AM_IP=88.88.0.3         # amuled subnet (bound via its Address= config)
AMULE_PORT=4665

if [ "${REV_IN_NS:-}" != "1" ]; then
  [ -x "$CLI" ]     || { echo "build padMule first: cargo build --release -p mule-cli"; exit 1; }
  [ -x "$AMULED" ]  || { echo "amuled not built: run scripts/build-amuled-oracle.sh"; exit 1; }
  [ -x "$ESERVER" ] || { echo "eserver not present: run scripts/eserver-oracle.sh once"; exit 1; }
  export REV_IN_NS=1
  exec unshare -rn bash "$0" "$@"
fi

# ---- inside the isolated namespace ----
WORK="$(mktemp -d)"; CFG="$WORK/amuled"; ESRVDIR="$WORK/eserver"
mkdir -p "$CFG/Incoming" "$CFG/Temp" "$ESRVDIR" "$WORK/shared"
cleanup() { kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

ip link set lo up
ip link add name d0 type dummy 2>/dev/null
# padMule's serve IP FIRST so it is the interface primary (padMule's HighID source).
for ip in "$SRV_IP" "$ESRV_IP" "$PAD_ESRV_IP" "$AM_IP"; do ip addr add "$ip/24" dev d0; done
ip link set d0 up

# 1) eserver
cat > "$ESRVDIR/donkey.ini" <<EOF
name=padMule-revtest
port=$ESRV_PORT
lowid=1
maxclients=100
EOF
cd "$ESRVDIR"; rm -f ctl; mkfifo ctl
"$ESERVER" < ctl > eserver.log 2>&1 &
exec 9> ctl
for _ in $(seq 1 30); do ss -ltn 2>/dev/null | grep -q ":$ESRV_PORT " && break; sleep 0.2; done
echo "== eserver 17.15 up on $ESRV_IP:$ESRV_PORT (isolated)"

# 2) padMule: serve a real file AND offer it to the eserver (earns HighID; the
#    eserver indexes it as a directly-dialable source).
python3 - "$WORK/shared/revtest.bin" <<'PY'
import sys
open(sys.argv[1],'wb').write(bytes((i*37+11)&0xff for i in range(300000)))
PY
read -r HASH SIZE < <("$CLI" hash-file "$WORK/shared/revtest.bin")
"$CLI" serve-file "$SERVE_PORT" "$WORK/shared/revtest.bin" "$PAD_ESRV_IP" "$ESRV_PORT" > "$WORK/serve.log" 2>&1 &
sleep 3
echo "== padMule serving + offering revtest.bin (hash=$HASH); HighID: $(grep -o 'low_id=false' "$WORK/serve.log" | head -1 || echo '?')"

# 3) amuled: connect to the eserver, add the download (NO embedded source - it must
#    GET padMule from the server), FilterLanIPs/obfuscation off for a clean run.
python3 - "$CFG/server.met" "$ESRV_IP" "$ESRV_PORT" <<'PY'
import sys, struct, socket
path, ip, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
open(path,'wb').write(bytes([0xE0]) + struct.pack('<I',1) + socket.inet_aton(ip) + struct.pack('<H',port) + struct.pack('<I',0))
PY
timeout 6 "$AMULED" -c "$CFG" -o -i >/dev/null 2>&1
sed -i -E "s/^Port=.*/Port=$AMULE_PORT/; s/^Autoconnect=.*/Autoconnect=1/; \
  s/^AcceptExternalConnections=.*/AcceptExternalConnections=1/; \
  s/^ECPassword=.*/ECPassword=098f6bcd4621d373cade4e832627b4f6/; \
  s/^FilterLanIPs=.*/FilterLanIPs=0/; s|^Address=.*|Address=$AM_IP|; \
  s/^IpFilterClients=.*/IpFilterClients=0/; s/^IpFilterServers=.*/IpFilterServers=0/; \
  s/^IPFilterAutoLoad=.*/IPFilterAutoLoad=0/; \
  s/^IsCryptLayerSupported=.*/IsCryptLayerSupported=0/; \
  s/^IsCryptLayerRequested=.*/IsCryptLayerRequested=0/; \
  s/^IsCryptLayerRequired=.*/IsCryptLayerRequired=0/" "$CFG/amule.conf"
echo "ed2k://|file|revtest.bin|$SIZE|$HASH|/" > "$CFG/ED2KLinks"

"$AMULED" -c "$CFG" -o -i > "$WORK/amuled.log" 2>&1 &
AM=$!
echo "== amuled connecting -> requesting sources -> dialing padMule..."

DONE=0
for _ in $(seq 1 120); do
  [ -f "$CFG/Incoming/revtest.bin" ] && cmp -s "$WORK/shared/revtest.bin" "$CFG/Incoming/revtest.bin" && { DONE=1; break; }
  kill -0 "$AM" 2>/dev/null || { echo "amuled exited early"; break; }
  sleep 1
done

echo; echo "===== RESULT ====="
if [ "$DONE" = 1 ]; then
  echo "PASS: real amuled 3.0.1 downloaded revtest.bin FROM padMule (via the eserver), byte-for-byte."
  # Serve-side secure identification: padMule issues its own OP_SECIDENTSTATE, amuled
  # (sec_ident=3 by default, gated only on CryptoAvailable - obfuscation being off is
  # orthogonal) answers with its pubkey+signature, and padMule verifies it.
  if grep -q 'identity verified (secure-ident): true' "$WORK/serve.log"; then
    echo "PASS: padMule VERIFIED amuled's secure identity serve-side."
  else
    echo "FAIL: padMule did NOT verify amuled's identity serve-side."
    echo "--- serve.log (secure-ident) ---"; grep -iE 'verified|secure|serve <-' "$WORK/serve.log" | tail -12
    DONE=0
  fi
else
  echo "FAIL/INCOMPLETE: Incoming=$(stat -c%s "$CFG/Incoming/revtest.bin" 2>/dev/null || echo 0) bytes"
  echo "--- padMule serve.log ---"; tail -12 "$WORK/serve.log"
  echo "--- amuled log ---"; find "$CFG" -maxdepth 2 -name logfile -exec tail -20 {} \; 2>/dev/null
fi
[ "$DONE" = 1 ]
