# Lane slots (bft-core#1218): every listening port of the paired devnet lanes is derived from one slot, so several lanes can run on one
# host at once, each in its own tree copy. Definitions only apart from the two exports below: sourcing this file starts nothing and takes no port.
#
#   LANE_SLOT=N        0..3 (default 0: the historical ports, unchanged)
#
# The slot alone determines every port: there is no other offset knob, so the host lock (scripts/lane-slot.sh) reserves exactly what a lane uses.
# The offset is LANE_SLOT * 1000 (LANE_SLOT_STRIDE). Every default port below is `default + offset`: lane_port 18545 prints 19545 on slot 1.
# No default port of the table is within 1000*k of another for k = 1..3, and none is within the slots' reach of the docker package's 8545/8088/8090/9090
# (lane_slot_selftest checks both). Work directories need no scheme: test-nodes/ is relative to the tree, so two trees never share a path.
#
# Linux hands out ephemeral ports from ip_local_port_range (32768..60999 by default): lane_slot_ephemeral_conflicts lists the core listeners of a slot inside
# it, and scripts/lane-slot.sh acquire refuses such a slot (slot 3 on a default host). Auxiliary listeners (the f6b/f6c acceptance lanes, seed, F8, the section-3
# negative clients) belong to one lane each and are reported, not refused: slot 0's own are already in the range.

LANE_SLOT_STRIDE=1000

lane_slot_init() {
  local slot=${LANE_SLOT:-0} off
  case "$slot" in 0 | 1 | 2 | 3) ;; *) echo "LANE_SLOT must be 0, 1, 2 or 3 (got '$slot')" >&2; return 2 ;; esac
  off=$((slot * LANE_SLOT_STRIDE))
  LANE_PORT_OFFSET=$off
  # a name suffix for per-run directories that default to a timestamp: empty on slot 0 (names unchanged), -slotN elsewhere
  if [ "$off" = 0 ]; then LANE_RUN_TAG=; else LANE_RUN_TAG=-slot$slot; fi
  export LANE_SLOT LANE_PORT_OFFSET LANE_RUN_TAG
}
lane_slot_init || { return 2 2>/dev/null || exit 2; }

# lane_port DEFAULT: the default port shifted into this lane's slot
lane_port() { echo $(($1 + LANE_PORT_OFFSET)); }

# The table: name, default port (slot 0), count, class (core: every paired lane; aux: one lane's, see above). Everything a lane listens on; the lane scripts take their ports from here by value.
lane_port_table() {
  cat <<'EOF'
reth-eth 18545 6
reth-engine 18551 6
reth-p2p 30401 6
reth-eth-bystander 18565 4
reth-engine-bystander 18581 4
reth-p2p-bystander 30421 4
d2c-proof-proxy 18645 1
d2c-engine-proxy 18651 1
neg-reth-wrong-engine 18699 1 aux
neg-reth-wrongchain 18745 1 aux
neg-reth-wrongchain-engine 18751 1 aux
neg-reth-othergenesis 18845 1 aux
neg-reth-othergenesis-engine 18851 1 aux
neg-reth-laterfork 18945 1 aux
neg-reth-laterfork-engine 18951 1 aux
neg-reth-p2p 30499 1 aux
neg-reth-p2p-2 30599 1 aux
neg-reth-p2p-3 30699 1 aux
neg-reth-p2p-4 30799 1 aux
neg-shard-p2p 28001 4 aux
root-rpc 25866 8
root-p2p 26662 8
mongo 27117 1
shard-p2p 28111 6
shard-dissemination 28211 6
shard-rpc 28311 6
f8-http 28601 3 aux
aggregator-bft-p2p 29101 2
aggregator-http 3001 2
seed-serve 38480 4 aux
seed-bundle 38600 8 aux
f6c-root-p2p 36662 1 aux
f6c-root-rpc 36866 1 aux
f6c-shard-p2p 36111 1 aux
f6c-shard-rpc 36311 1 aux
f6c-backup-root-p2p 46662 1 aux
f6c-backup-root-rpc 46866 1 aux
f6c-backup-val-p2p 46111 6 aux
f6c-backup-val-rpc 46311 6 aux
f6c-backup-reth-engine 48551 6 aux
f6c-backup-reth-eth 48545 6 aux
f6c-backup-reth-p2p 40401 6 aux
EOF
}

# lane_slot_ports [SLOT]: "name port" for every port of the slot (the signing-authority sockets are paths under the tree's test-nodes/, not ports)
# lane_slot_ephemeral_conflicts SLOT [CLASS]: "name port" of the slot's listeners (default class: core) inside the host's ephemeral range
# (ip_local_port_range) and not in ip_local_reserved_ports. Prints nothing where /proc/sys/net/ipv4 is absent (not Linux).
lane_slot_ephemeral_conflicts() {
  local slot=$1 class=${2:-core} lo hi reserved name port c
  read -r lo hi <"${LANE_PORT_RANGE_FILE:-/proc/sys/net/ipv4/ip_local_port_range}" 2>/dev/null || return 0
  reserved=$(cat "${LANE_PORT_RESERVED_FILE:-/proc/sys/net/ipv4/ip_local_reserved_ports}" 2>/dev/null || true)
  while read -r name port c; do
    [ "$c" = "$class" ] || continue
    [ "$port" -ge "$lo" ] && [ "$port" -le "$hi" ] || continue
    if [ -n "$reserved" ] && echo "$reserved" | tr ',' '\n' | awk -F- -v p="$port" '{a=$1; b=($2==""?$1:$2)} a!=""&&p>=a&&p<=b{f=1} END{exit !f}'; then continue; fi
    echo "$name $port"
  done < <(lane_slot_ports "$slot")
}

lane_slot_ports() {
  local off=$(( ${1:-$LANE_SLOT} * LANE_SLOT_STRIDE )) name base count class k
  while read -r name base count class; do
    for ((k = 0; k < count; k++)); do echo "$name $((base + k + off)) ${class:-core}"; done
  done < <(lane_port_table)
}

# lane_slot_selftest: no port collides within a slot, across slots 0..3, or with the docker package's published ports
lane_slot_selftest() {
  local s all dup docker="8545 8088 8090 9090"
  all=$(for s in 0 1 2 3; do lane_slot_ports "$s" | awk -v s="$s" '{print $2, s, $1}'; done)
  dup=$(echo "$all" | awk '{c[$1]++; n[$1]=n[$1] " " $3 "@slot" $2} END{for(p in c) if(c[p]>1) print p ":" n[p]}')
  [ -z "$dup" ] || { echo "lane slot ports collide:" >&2; echo "$dup" >&2; return 1; }
  for p in $docker; do
    echo "$all" | awk -v p="$p" '$1==p{f=1} END{exit f}' || { echo "lane port collides with docker port $p" >&2; return 1; }
  done
  echo "lane slot ports: $(echo "$all" | wc -l | tr -d ' ') ports in slots 0..3, no collision, clear of docker $docker"
}
