#!/usr/bin/env bash
# KAD STORE-AND-SEARCH ORACLE: prove against REAL amuled 3.0.1 nodes that a
# padMule Kad keyword PUBLISH is not merely ACKED but STORED - by getting the
# record BACK out of an amulecmd search.
#
# WHY AN ACK IS NOT ENOUGH: eMule/aMule answer KADEMLIA2_PUBLISH_RES even when
# CIndexed::AddKeyword (Indexed.cpp:474) REJECTS the entry - the handler sends
# the success packet regardless (KademliaUDPListener.cpp:1091-1108, "we still
# send a success"): a busy node reports success ON PURPOSE so hot nodes do not
# shed popular keywords onto their neighbours. The 424 store-acks proven on-device 2026-08-09 therefore
# bound only the SEND leg; this oracle closes the loop wiki row 8de left owed:
# publish -> store -> search -> the same filename comes back.
#
# Topology (one `unshare -rn` namespace, zero egress). THREE Kad nodes, because
# a searching node never consults its own index (CSearch::Go only walks the
# routing table), so the storer and the searcher must be distinct:
#
#   padMule publisher (mule-cli kad-publish)   77.77.0.9  udp 4672
#        |  KADEMLIA2_PUBLISH_KEY_REQ -> KADEMLIA2_PUBLISH_RES (the ack)
#        v
#   amuled S - the STORING node    88.88.0.3  tcp 4666 / udp 4682 / EC 4713
#        ^  KADEMLIA2_SEARCH_KEY_REQ -> KADEMLIA2_SEARCH_RES (the evidence)
#        |
#   amuled Q - the SEARCHING node  88.88.0.4  tcp 4762 / udp 4772 / EC 4712
#        ^
#        |  EC over loopback (amulecmd -h 127.0.0.1 -p 4712)
#   amulecmd: "search kad <word>" then "results"
#
# S's Kad ID is PINNED to the keyword's target hash (`mule-cli kad-publish
# --keyword-target` emits the disk-order bytes for preferencesKad.dat), which
# passes every 2^120 tolerance gate at once: padMule stores AT S, S accepts the
# publish (Process2PublishKeyRequest distance check), and Q sends its search
# request to S (CSearch::StorePacket tolerance). Q learns S from a one-contact
# nodes.dat in its config dir.
#
# ENV LIMIT (dev-box memory): WSL2 mirrored networking silently DROPS loopback
# UDP past ~1472 bytes. Everything here is ONE file under ONE short keyword -
# the publish and the search result are each ~100 B, far under the cliff.
# Keep it that way; do not grow this into a multi-file publish.
#
# amuled behaviors handled (verified in amule-3.0.1 source, not guessed):
#   - it logs to <cfg>/logfile and leaves stdout nearly empty despite -o
#     (the 2026-08-02 logfile-not-stdout gotcha) - read BOTH sinks
#   - Kad readiness gated on "Kad started." plus the client-UDP-socket port
#     line (Kad rides the CLIENT UDP socket; UDPPort must not equal TCP+3 or
#     it collides and falls back to an ephemeral port - kad-verify lesson)
#   - the keyword index is per-WORD: the search asks for the EXACT word
#     published, and the published fileNAME contains that word (a searcher
#     filters results whose name lacks the searched word)
#   - amulecmd 3.0.1 has no --command option: commands are piped on stdin
#     (ExternalConnector.cpp falls back to fgets when stdin is not a tty)
#   - a distinct Kad identity per node: S's is pinned, Q's and padMule's are
#     random - three different IDs on three different IPs
#
# Prereqs: scripts/build-amuled-kad-oracle.sh once (the instrumented tree; no
# log patch is needed here - the SEARCH RESULT is the evidence - but that tree
# is the one already built), amulecmd built into the same tree:
#   cmake -DBUILD_AMULECMD=ON build-oracle/kad-build
#   cmake --build build-oracle/kad-build --target amulecmd
# and `cargo build --release -p mule-cli`.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLI="$REPO/target/release/mule-cli"
AMULED="$REPO/build-oracle/kad-build/src/amuled"
AMULECMD="$REPO/build-oracle/kad-build/src/amulecmd"
LOG="$HOME/.claude/jobs/5c55bcbb/tmp/kad-store-oracle.log"

PAD_IP=77.77.0.9        # padMule publisher (mule-cli kad-publish, udp 4672)
S_IP=88.88.0.3          # amuled S - stores the record
Q_IP=88.88.0.4          # amuled Q - searches for it via EC
S_TCP=4666; S_UDP=4682; S_EC=4713   # 4666+3=4669 != 4682: no socket collision
Q_TCP=4762; Q_UDP=4772; Q_EC=4712   # 4762+3=4765 != 4772
ECPASS_MD5=098f6bcd4621d373cade4e832627b4f6   # md5("test"); amulecmd -P test

KEYWORD=padstoreoracle
FILENAME=padstoreoracle-proof.txt   # MUST contain $KEYWORD (searcher-side filter)
SIZE=123456                          # nonzero: AddKeyword drops size-0 entries

if [ "${KSO_IN_NS:-}" != "1" ]; then
  [ -x "$CLI" ]      || { echo "build padMule first: cargo build --release -p mule-cli"; exit 1; }
  [ -x "$AMULED" ]   || { echo "amuled missing: run scripts/build-amuled-kad-oracle.sh"; exit 1; }
  [ -x "$AMULECMD" ] || { echo "amulecmd missing: cmake -DBUILD_AMULECMD=ON build-oracle/kad-build && cmake --build build-oracle/kad-build --target amulecmd"; exit 1; }
  # The keyword target's disk-order bytes - S's pinned Kad identity.
  TARGET_HEX="$("$CLI" kad-publish --keyword-target "$KEYWORD")" \
    || { echo "could not compute the keyword target"; exit 1; }
  case "$TARGET_HEX" in
    *[!0-9a-f]*|"") echo "bad keyword-target output: '$TARGET_HEX'"; exit 1 ;;
  esac
  mkdir -p "$(dirname "$LOG")"
  export KSO_IN_NS=1 KSO_TARGET_HEX="$TARGET_HEX"
  unshare -rn bash "$0" "$@" 2>&1 | tee "$LOG"
  exit "${PIPESTATUS[0]}"
fi

# ---- inside the isolated namespace ----
TARGET_HEX="$KSO_TARGET_HEX"
WORK="$(mktemp -d)"
cleanup() { local j; j=$(jobs -p); [ -n "$j" ] && kill $j 2>/dev/null; rm -rf "$WORK"; }
trap cleanup EXIT

# ENVIRONMENT PREFLIGHT (kad-verify pattern): every ip command must succeed or
# the run would end in a protocol-shaped FAIL for a namespace-setup failure.
net() { "$@" || { echo "ENVIRONMENT FAIL (not a protocol verdict): '$*' failed" \
  "- the namespace/dummy-interface setup did not come up (see stderr above)"; exit 1; }; }
net ip link set lo up
net ip link add name d0 type dummy
net ip addr add "$PAD_IP/24" dev d0
net ip addr add "$S_IP/24" dev d0
net ip addr add "$Q_IP/24" dev d0
net ip link set d0 up
# No src-pinning routes needed: padMule binds $PAD_IP explicitly and both
# amuleds bind their own Address= from the config.

echo "== keyword '$KEYWORD' -> target (disk hex) $TARGET_HEX"

# One amuled config: generate the default, then tune it for an isolated
# Kad-only run (same knobs as kad-verify-oracle.sh, plus a per-instance ECPort
# so two daemons can host EC at once).
mk_cfg() { # cfgdir ip tcp udp ecport
  local cfg="$1" ip="$2" tcp="$3" udp="$4" ec="$5"
  mkdir -p "$cfg/Incoming" "$cfg/Temp"
  timeout 6 "$AMULED" -c "$cfg" -o -i >/dev/null 2>&1
  [ -f "$cfg/amule.conf" ] || { echo "ENVIRONMENT FAIL (not a protocol verdict):" \
    "config generation produced no amule.conf in $cfg"; exit 1; }
  sed -i -E "s/^Port=.*/Port=$tcp/; s/^UDPPort=.*/UDPPort=$udp/; \
    s/^ECPort=.*/ECPort=$ec/; \
    s/^Autoconnect=.*/Autoconnect=1/; s/^ConnectToKad=.*/ConnectToKad=1/; \
    s/^ConnectToED2K=.*/ConnectToED2K=0/; \
    s/^AcceptExternalConnections=.*/AcceptExternalConnections=1/; \
    s/^ECPassword=.*/ECPassword=$ECPASS_MD5/; \
    s|^Address=.*|Address=$ip|; \
    s/^FilterLanIPs=.*/FilterLanIPs=0/; \
    s/^IpFilterClients=.*/IpFilterClients=0/; s/^IpFilterServers=.*/IpFilterServers=0/; \
    s/^IPFilterAutoLoad=.*/IPFilterAutoLoad=0/; \
    s/^IsCryptLayerSupported=.*/IsCryptLayerSupported=0/; \
    s/^IsCryptLayerRequested=.*/IsCryptLayerRequested=0/; \
    s/^IsCryptLayerRequired=.*/IsCryptLayerRequired=0/" "$cfg/amule.conf"
  rm -f "$cfg/logfile"   # config-gen leftovers would pollute the readiness greps
}

CFG_S="$WORK/amuled-s"; CFG_Q="$WORK/amuled-q"
mk_cfg "$CFG_S" "$S_IP" "$S_TCP" "$S_UDP" "$S_EC"
mk_cfg "$CFG_Q" "$Q_IP" "$Q_TCP" "$Q_UDP" "$Q_EC"

# S's pinned Kad identity: preferencesKad.dat = u32 ip | u16 unused |
# u128 kadID (disk order - exactly the --keyword-target bytes) | u8 0.
python3 - "$CFG_S/preferencesKad.dat" "$TARGET_HEX" <<'PY'
import sys, struct
path, kadhex = sys.argv[1], sys.argv[2]
kad = bytes.fromhex(kadhex)
assert len(kad) == 16
open(path, 'wb').write(struct.pack('<I', 0) + struct.pack('<H', 0) + kad + b'\x00')
PY

# One-contact nodes.dat pointing at S (id = the same disk-order target bytes):
# header u32 0 | u32 2 | u32 1, then a 34-byte v2 record, verified=1.
# Written once, used by BOTH padMule (publish walk) and Q (its routing table).
NODES="$WORK/nodes.dat"
python3 - "$NODES" "$TARGET_HEX" "$S_IP" "$S_UDP" "$S_TCP" <<'PY'
import sys, struct, socket
path, kadhex, ip, udp, tcp = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
kad = bytes.fromhex(kadhex)
ip_host = int.from_bytes(socket.inet_aton(ip), 'big')   # host-order u32
rec  = kad
rec += struct.pack('<I', ip_host)      # ip
rec += struct.pack('<H', udp)          # udp port
rec += struct.pack('<H', tcp)          # tcp port
rec += struct.pack('<B', 8)            # contact version (aMule v8)
rec += struct.pack('<I', 0)            # udp_key
rec += struct.pack('<I', 0)            # udp_key_ip
rec += struct.pack('<B', 1)            # verified
open(path, 'wb').write(struct.pack('<III', 0, 2, 1) + rec)
PY
cp "$NODES" "$CFG_Q/nodes.dat"

LOGS() { cat "$WORK/$1.stdout" "$2/logfile" 2>/dev/null; }  # BOTH sinks, always

start_amuled() { # name cfgdir
  "$AMULED" -c "$2" -o -i > "$WORK/$1.stdout" 2>&1 &
  echo $! > "$WORK/$1.pid"
}

wait_kad() { # name cfgdir udp-port
  local name="$1" cfg="$2" udp="$3" pid i cudp
  pid="$(cat "$WORK/$name.pid")"
  for i in $(seq 1 60); do
    kill -0 "$pid" 2>/dev/null || { echo "ENVIRONMENT FAIL (not a protocol" \
      "verdict): amuled($name) exited early"; LOGS "$name" "$cfg" | tail -20; exit 1; }
    LOGS "$name" "$cfg" | grep -q "Kad started" && break
    sleep 0.5
  done
  LOGS "$name" "$cfg" | grep -q "Kad started" || { echo "ENVIRONMENT FAIL (not" \
    "a protocol verdict): amuled($name) never reported 'Kad started.'"; \
    LOGS "$name" "$cfg" | tail -20; exit 1; }
  # Kad rides the CLIENT UDP socket; a port collision would strand it on an
  # ephemeral port nobody dials. Same WARN/FAIL split as kad-verify: absent
  # wording is a WARN (a grep the harness cannot see must not abort), a line
  # POSITIVELY naming the wrong port is an environment abort.
  cudp="$(LOGS "$name" "$cfg" | grep -oE 'Client UDP-Socket at port [0-9]+' | tail -1)"
  echo "== amuled($name): ${cudp:-<no client UDP socket line>} (need port $udp)"
  case "$cudp" in
    *" $udp") : ;;
    "") echo "WARN: no client-UDP-socket line for $name - cannot confirm the Kad port" ;;
    *) echo "ENVIRONMENT FAIL (not a protocol verdict): amuled($name) Kad UDP" \
         "is NOT on $udp - a collision forced an ephemeral fallback"; exit 1 ;;
  esac
}

echo "== starting amuled S (stores; Kad ID pinned to the keyword target) ..."
start_amuled s "$CFG_S"
wait_kad s "$CFG_S" "$S_UDP"

echo "== starting amuled Q (searches; learns S from a one-contact nodes.dat) ..."
start_amuled q "$CFG_Q"
wait_kad q "$CFG_Q" "$Q_UDP"
# Q MUST have actually ingested the contact, or its search walks an empty
# table and returns nothing - a protocol-shaped verdict for a setup failure.
for i in $(seq 1 20); do
  LOGS q "$CFG_Q" | grep -q "Read 1 Kad contact" && break
  sleep 0.5
done
LOGS q "$CFG_Q" | grep -q "Read 1 Kad contact" || { echo "ENVIRONMENT FAIL (not" \
  "a protocol verdict): amuled(q) did not read its seeded nodes.dat contact"; \
  LOGS q "$CFG_Q" | tail -20; exit 1; }
echo "== amuled(q) read its seeded contact (S is in the routing table)"

# ---- leg 1: padMule PUBLISHES the keyword record at S ----
echo "== padMule publishing '$FILENAME' ($SIZE B) under '$KEYWORD' at S ..."
ACKS=0
for attempt in 1 2 3; do
  if timeout 90 "$CLI" kad-publish "$NODES" "$KEYWORD" "$FILENAME" "$SIZE" "$PAD_IP" \
      > "$WORK/publish.$attempt.log" 2>&1; then
    ACKS="$(grep -oE 'PUBLISH_ACKS=[0-9]+' "$WORK/publish.$attempt.log" | tail -1 | cut -d= -f2)"
    sed 's/^/    /' "$WORK/publish.$attempt.log"
    break
  fi
  echo "   publish attempt $attempt did not ack:"
  tail -6 "$WORK/publish.$attempt.log" | sed 's/^/    /'
  sleep 3
done
if [ "${ACKS:-0}" -lt 1 ]; then
  echo; echo "===== RESULT ====="
  echo "FAIL (publish leg): S never acked padMule's KADEMLIA2_PUBLISH_KEY_REQ."
  echo "--- S log (Kad lines) ---"; LOGS s "$CFG_S" | grep -iE "kad|udp" | tail -15
  exit 1
fi

# ---- leg 2: amulecmd drives Q's Kad search; the record must come BACK ----
ec() { printf '%s\nquit\n' "$1" | timeout 20 "$AMULECMD" -h 127.0.0.1 -p "$Q_EC" -P test 2>/dev/null; }

echo "== starting the Kad search on Q via amulecmd (EC 127.0.0.1:$Q_EC) ..."
STARTED=0; SOUT=""
for i in $(seq 1 12); do
  SOUT="$(ec "search kad $KEYWORD")"
  if echo "$SOUT" | grep -q "Search in progress"; then STARTED=1; break; fi
  if echo "$SOUT" | grep -qi "Kad is not running\|can't be done"; then
    echo "ENVIRONMENT FAIL (not a protocol verdict): Q refuses a Kad search:"
    echo "$SOUT" | tail -4; exit 1
  fi
  sleep 5   # EC may not be accepting yet right after startup
done
if [ "$STARTED" != 1 ]; then
  echo "ENVIRONMENT FAIL (not a protocol verdict): could not start an EC Kad search on Q"
  echo "$SOUT" | tail -6; exit 1
fi

# Two search rounds: the first can race Q's bootstrap of S; a re-search is
# exactly what a GUI user's retry would be. Results are fetched by polling
# `results` - the search runs inside amuled, so separate EC sessions see it.
VERDICT=fail; ROUT=""
for round in 1 2; do
  [ "$round" = 2 ] && { echo "== round 2: re-issuing the search ..."; ec "search kad $KEYWORD" >/dev/null; }
  for i in $(seq 1 18); do
    sleep 5
    ROUT="$(ec results)"
    if echo "$ROUT" | grep -q "$FILENAME"; then VERDICT=pass; break 2; fi
  done
done

echo; echo "===== RESULT ====="
if [ "$VERDICT" = pass ]; then
  echo "amulecmd 'results' on Q returned:"
  echo "$ROUT" | grep -E "Nr\.|-----|$FILENAME" | sed 's/^/    /'
  echo
  echo "PASS: a REAL amuled 3.0.1 (S) STORED padMule's keyword publish and"
  echo "RETURNED it to a second real amuled's Kad search: the published"
  echo "filename '$FILENAME' came back through"
  echo "KADEMLIA2_SEARCH_KEY_REQ -> KADEMLIA2_SEARCH_RES, served from S's"
  echo "CIndexed keyword store (publish acks were $ACKS)."
else
  echo "FAIL (store-or-return leg): S acked the publish ($ACKS ack(s)) but the"
  echo "record did not come back out of Q's Kad search within the watch."
  echo "--- last amulecmd results output ---"; echo "$ROUT" | tail -10 | sed 's/^/    /'
  echo "--- Q log (Kad/search lines) ---"; LOGS q "$CFG_Q" | grep -iE "kad|search" | tail -15 | sed 's/^/    /'
  echo "--- S log (Kad lines) ---"; LOGS s "$CFG_S" | grep -iE "kad|udp" | tail -15 | sed 's/^/    /'
fi
[ "$VERDICT" = pass ]
