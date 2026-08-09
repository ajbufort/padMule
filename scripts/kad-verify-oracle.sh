#!/usr/bin/env bash
# REVERSE-KAD ORACLE: prove against a REAL amuled 3.0.1 that padMule (a) earns
# the Kad IP-verified bit via its v8 HELLO_RES_ACK three-way handshake, and
# (b) - the 2026-08-07 serve-loop extension - STAYS in amuled's routing table
# because it now ANSWERS the OnSmallTimer liveness probe that used to evict it.
#
# The run is an A/B experiment inside one amuled routing table:
#   CONTROL  (CTRL_IP): `mule-cli kad-bootstrap` - the OLD one-shot behaviour.
#            It handshakes, exits, and goes silent - exactly what padMule did
#            before the owning read loop. amuled must EVICT it.
#   SERVE    (PAD_IP):  `mule-cli kad-serve` - the read loop stays up and
#            answers. amuled must probe it, get a HELLO_RES back, REFRESH the
#            contact, and never evict it.
# Same amuled, same table, same OnSmallTimer sweeps: the asymmetry is the proof.
#
# Evidence comes from a LOGGING-INSTRUMENTED amuled (scripts/
# build-amuled-kad-oracle.sh applies scripts/amule-oracle-kad-verify.patch - a
# committed, auditable, logging-only patch; the pristine amule-3.0.1/ is never
# touched). The oracle lines it emits:
#   PADMULE-ORACLE-VERIFIED   - amuled flipped a contact's IP-verified bit
#   PADMULE-ORACLE-SMALLTIMER - OnSmallTimer probed its oldest contact (HELLO_REQ)
#   PADMULE-ORACLE-HELLO-RES  - a HELLO_RES answered a HELLO_REQ amuled sent
#   PADMULE-ORACLE-PONG       - a PONG answered a KADEMLIA2_PING amuled sent
#   PADMULE-ORACLE-REFRESH    - the probed contact was KEPT (SetAlive/UpdateType)
#   PADMULE-ORACLE-EVICTED    - a probed contact stayed silent and was removed
#
# TIMING (all read out of amule-3.0.1 sources, not guessed):
#   Kademlia.cpp:254-257  - OnSmallTimer per zone every MIN2S(1) = 60 s
#   Contact.cpp:90        - a probed contact gets type=4, expiry now+2 min
#   RoutingZone.cpp:770-777 - expired type-4 contacts are removed next sweep
# So a silent contact dies ~3-4 sweeps after being learned; the whole A/B run
# fits in ~8 minutes. This script is therefore SLOW BY NATURE - it must sit
# through real eviction cycles.
#
# Topology (one `unshare -rn` namespace, zero egress):
#   kad-serve at PAD_IP, kad-bootstrap at CTRL_IP  <-UDP->  amuled at AM_IP
# amuled's Kad ID is pre-seeded (preferencesKad.dat) so a one-contact nodes.dat
# can point both padMule instances straight at it; a src-route keeps an
# UNSPECIFIED-bound socket sourcing from the right address.
#
# Prereqs: scripts/build-amuled-kad-oracle.sh once + `cargo build --release -p mule-cli`.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$REPO/target/release/mule-cli"
AMULED="$REPO/build-oracle/kad-build/src/amuled"

PAD_IP=77.77.0.9        # padMule SERVE node (mule-cli kad-serve) - must survive
CTRL_IP=77.77.0.8       # CONTROL (one-shot kad-bootstrap) - must be evicted
AM_IP=88.88.0.3         # amuled Kad node IP
# Kad rides the CLIENT UDP socket, which binds to UDPPort. The SERVER UDP socket
# binds to TCP+3, so UDPPort must NOT equal TCP+3 or the client socket collides
# and falls back to an ephemeral port. TCP 4662 -> server UDP 4665; Kad UDP 4672.
AM_UDP=4672             # amuled client/Kad UDP port (= UDPPort)
AM_TCP=4662             # amuled ed2k TCP port (server UDP = 4665)
# Both padMule instances bind UDP 4672 (hardcoded) on their own IPs.

# How long the serve node stays up. Must outlast: learn (~60s) + probe (~120s)
# + control eviction (~240s) + margin.
SERVE_SECS=560
# Give up watching after this long (the sweeps are 60s apart; 9 min is 3+ full
# probe-and-evict cycles past the handshakes).
WATCH_SECS=540

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
cleanup() { local j; j=$(jobs -p); [ -n "$j" ] && kill $j 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# ENVIRONMENT PREFLIGHT: every ip command must succeed, or the run burns the
# whole ${WATCH_SECS}s watch and ends in a PROTOCOL-shaped FAIL/INCOMPLETE for
# what was a namespace-setup failure (e.g. no dummy module). Abort immediately,
# labeled as environment - never as a verdict. The namespace is fresh, so d0
# cannot pre-exist and `ip link add` needs no error suppression.
net() { "$@" || { echo "ENVIRONMENT FAIL (not a protocol verdict): '$*' failed" \
  "- the namespace/dummy-interface setup did not come up (see stderr above)"; exit 1; }; }
net ip link set lo up
net ip link add name d0 type dummy
net ip addr add "$PAD_IP/24" dev d0    # padMule IP first (interface primary)
net ip addr add "$CTRL_IP/24" dev d0
net ip addr add "$AM_IP/24"  dev d0
net ip link set d0 up
# Force an UNSPECIFIED-bound socket to source from PAD_IP when it dials amuled
# (both mule-cli invocations pass an explicit bind IP, which pins the source
# anyway; this keeps the old belt-and-braces behaviour).
net ip route add "$AM_IP/32" dev d0 src "$PAD_IP"

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
# Read BOTH sinks: despite `-o`, this build writes its log lines to $CFG/logfile
# and leaves stdout nearly empty, so reading only the stdout redirect made the
# harness blind to "Kad started", to the UDP-socket line, AND to the oracle's own
# verify line (which is what the 2026-08-02 "ephemeral port" flakiness actually
# was - a false WARN plus an unobservable PASS, not a port problem).
LOGS() { cat "$WORK/amuled.log" "$CFG/logfile" 2>/dev/null; }

# Wait until Kad is actually up (its listener rides the CLIENT UDP socket) before
# driving padMule - otherwise early attempts hit a not-yet-listening node.
for _ in $(seq 1 30); do
  kill -0 "$AM" 2>/dev/null || { echo "amuled exited early"; LOGS | tail -20; exit 1; }
  LOGS | grep -q "Kad started" && break
  sleep 0.5
done
# Diagnostic: the client UDP socket (which Kad rides) MUST be on $AM_UDP. If a
# port collision forced an ephemeral fallback, padMule can never reach Kad -
# surface it plainly. aMule 3.0.1 logs "Created Client UDP-Socket at port N".
CUDP="$(LOGS | grep -oE 'Client UDP-Socket at port [0-9]+' | tail -1)"
echo "== ${CUDP:-<no client UDP socket line>} (need port $AM_UDP)"
case "$CUDP" in
  *" $AM_UDP") : ;;
  # No line at all stays a WARN: the 2026-08-02 flakiness was exactly a log line
  # this harness could not see, and aborting on absent WORDING would recreate it.
  "") echo "WARN: no client-UDP-socket line found - cannot confirm the Kad port"; ;;
  # A line POSITIVELY naming the wrong port is fatal: padMule can never reach
  # Kad, so the ${WATCH_SECS}s watch could only end in a false FAIL/INCOMPLETE.
  *) echo "ENVIRONMENT FAIL (not a protocol verdict): client/Kad UDP is NOT on" \
       "$AM_UDP - a port collision forced an ephemeral fallback; padMule cannot" \
       "reach it, so watching would only produce a false protocol FAIL"
     exit 1 ;;
esac

# 5) SERVE node: kad-serve stays up for the whole run, its read loop answering.
"$CLI" kad-serve "$NODES" "$PAD_IP" "$SERVE_SECS" > "$WORK/serve.log" 2>&1 &
SERVE=$!
echo "== kad-serve up at $PAD_IP (pid $SERVE, ${SERVE_SECS}s)"

# 6) CONTROL: the OLD one-shot behaviour - handshake, exit, go silent.
"$CLI" kad-bootstrap "$NODES" "$CTRL_IP" > "$WORK/ctrl.log" 2>&1
echo "== control kad-bootstrap at $CTRL_IP done (process exited - now silent)"

# 7) Watch amuled's oracle lines for the A/B outcome.
#    PASS needs, in one run:
#      VERIFIED  for $PAD_IP        (proof 1: the v8 handshake earns the bit)
#      SMALLTIMER probe -> $PAD_IP  (proof 2: amuled probed padMule...)
#      HELLO-RES from $PAD_IP       (...and padMule ANSWERED)
#      REFRESH   for $PAD_IP        (proof 3a: the answer KEPT the contact)
#      EVICTED   for $CTRL_IP       (proof 3b: the same sweeps evicted the
#                                    silent one-shot - the old behaviour)
#      no EVICTED for $PAD_IP       (proof 3c: ...and never the serve node)
seen() { LOGS | grep -q "$1"; }
START=$(date +%s)
echo "== watching (up to ${WATCH_SECS}s; sweeps are 60s apart, eviction needs ~4-6 of them)"
VERDICT=incomplete
while :; do
  NOW=$(( $(date +%s) - START ))
  if ! kill -0 "$AM" 2>/dev/null; then echo "amuled exited early"; break; fi
  if seen "PADMULE-ORACLE-EVICTED contact ($PAD_IP)"; then
    VERDICT=serve-evicted; break
  fi
  if seen "PADMULE-ORACLE-VERIFIED contact (sender: $PAD_IP)" \
     && seen "PADMULE-ORACLE-SMALLTIMER probe -> $PAD_IP" \
     && seen "PADMULE-ORACLE-HELLO-RES from $PAD_IP" \
     && seen "PADMULE-ORACLE-REFRESH contact ($PAD_IP)" \
     && seen "PADMULE-ORACLE-EVICTED contact ($CTRL_IP)"; then
    VERDICT=pass; break
  fi
  if [ "$NOW" -ge "$WATCH_SECS" ]; then break; fi
  # progress line every ~30s so a long run is visibly alive
  if [ $(( NOW % 30 )) -lt 5 ]; then
    echo "   t=${NOW}s: $(LOGS | grep -c 'PADMULE-ORACLE-SMALLTIMER') probes, \
$(LOGS | grep -c 'PADMULE-ORACLE-REFRESH') refreshes, \
$(LOGS | grep -c 'PADMULE-ORACLE-EVICTED') evictions"
  fi
  sleep 5
done

echo; echo "===== RESULT ====="
echo "--- all oracle lines, in order ---"
# ONE sink here, not LOGS: this build mirrors the lines to stdout AND the
# logfile, so a LOGS dump printed the whole block TWICE - with the
# block-buffered stdout sink's unterminated last line glued to the logfile's
# first (seen in the 2026-08-09 PASS log). The line-flushed logfile is the
# complete copy; fall back to the stdout sink only if it holds no lines. No
# text-level dedupe - identical PONG lines in one second are real events.
ORACLE_LINES="$(grep "PADMULE-ORACLE" "$CFG/logfile" 2>/dev/null)"
[ -n "$ORACLE_LINES" ] || ORACLE_LINES="$(grep "PADMULE-ORACLE" "$WORK/amuled.log" 2>/dev/null)"
[ -n "$ORACLE_LINES" ] && printf '%s\n' "$ORACLE_LINES" | sed 's/^/    /'
echo "--- serve node last heartbeats ---"
tail -4 "$WORK/serve.log" | sed 's/^/    /'
echo
case "$VERDICT" in
  pass)
    echo "PASS: a REAL amuled 3.0.1 (1) marked padMule IP-verified, (2) probed it"
    echo "on the OnSmallTimer sweep and got a HELLO_RES back, and (3) KEPT it in"
    echo "the routing table - while the SAME sweeps evicted the silent one-shot"
    echo "control at $CTRL_IP, which is exactly what padMule used to be."
    ;;
  serve-evicted)
    echo "FAIL: amuled EVICTED the serve node at $PAD_IP - the read loop did not"
    echo "keep it alive. Check $WORK/serve.log and the flood budgets."
    ;;
  *)
    echo "FAIL/INCOMPLETE after ${WATCH_SECS}s. Missing evidence:"
    seen "PADMULE-ORACLE-VERIFIED contact (sender: $PAD_IP)" || echo "  - VERIFIED for $PAD_IP"
    seen "PADMULE-ORACLE-SMALLTIMER probe -> $PAD_IP"        || echo "  - SMALLTIMER probe -> $PAD_IP"
    seen "PADMULE-ORACLE-HELLO-RES from $PAD_IP"             || echo "  - HELLO-RES from $PAD_IP"
    seen "PADMULE-ORACLE-REFRESH contact ($PAD_IP)"          || echo "  - REFRESH for $PAD_IP"
    seen "PADMULE-ORACLE-EVICTED contact ($CTRL_IP)"         || echo "  - EVICTED for control $CTRL_IP"
    echo "--- padMule serve log tail ---"; tail -12 "$WORK/serve.log"
    echo "--- control log tail ---"; tail -6 "$WORK/ctrl.log"
    echo "--- amuled log (Kad lines) ---"; LOGS | grep -iE "kad|verif|bootstrap|hello" | tail -20
    ;;
esac
[ "$VERDICT" = pass ]
