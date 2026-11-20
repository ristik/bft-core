# Lane slots (bft-core#1218): every listening port of the paired devnet lanes is derived from one slot, so several lanes can run on one
# host at once, each in its own tree copy. Definitions only apart from the two exports below: sourcing this file starts nothing and takes no port.
#
#   LANE_SLOT=N        0..3 (default 0: the historical ports, unchanged)
#   LANE_PORT_BASE=N   an explicit offset instead (0..17000), for a host that needs another layout; it wins over LANE_SLOT
#
# The offset is LANE_SLOT * 1000 (LANE_SLOT_STRIDE). Every default port below is `default + offset`: lane_port 18545 prints 19545 on slot 1.
# No default port of the table is within 1000*k of another for k = 1..3, and none is within the slots' reach of the docker package's 8545/8088/8090/9090
# (lane_slot_selftest checks both). Work directories need no scheme: test-nodes/ is relative to the tree, so two trees never share a path.
#
# Linux hands out ephemeral ports from 32768, so slot 3's 30xxx ports (33xxx) can meet an outgoing connection: use slots 0..2 where it matters.

LANE_SLOT_STRIDE=1000

lane_slot_init() {
  local slot=${LANE_SLOT:-0} off
  case "$slot" in 0 | 1 | 2 | 3) ;; *) echo "LANE_SLOT must be 0, 1, 2 or 3 (got '$slot')" >&2; return 2 ;; esac
  if [ -n "${LANE_PORT_BASE:-}" ]; then
    case "$LANE_PORT_BASE" in '' | *[!0-9]*) echo "LANE_PORT_BASE must be a number 0..17000 (got '$LANE_PORT_BASE')" >&2; return 2 ;; esac
    [ "$LANE_PORT_BASE" -le 17000 ] || { echo "LANE_PORT_BASE must be 0..17000 (the highest default port, 48551, must stay below 65536)" >&2; return 2; }
    off=$((10#$LANE_PORT_BASE))
  else
    off=$((slot * LANE_SLOT_STRIDE))
  fi
  LANE_PORT_OFFSET=$off
  # a name suffix for per-run directories that default to a timestamp: empty on slot 0 (names unchanged), -slotN elsewhere
  if [ "$off" = 0 ]; then LANE_RUN_TAG=; else LANE_RUN_TAG=-slot$slot; fi
  export LANE_SLOT LANE_PORT_OFFSET LANE_RUN_TAG
}
lane_slot_init || { return 2 2>/dev/null || exit 2; }

# lane_port DEFAULT: the default port shifted into this lane's slot
lane_port() { echo $(($1 + LANE_PORT_OFFSET)); }

# The table: name, default port (slot 0), count. Everything a lane listens on; the lane scripts take their ports from here by value.
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
neg-reth-wrong-engine 18699 1
neg-reth-wrongchain 18745 1
neg-reth-wrongchain-engine 18751 1
neg-reth-othergenesis 18845 1
neg-reth-othergenesis-engine 18851 1
neg-reth-laterfork 18945 1
neg-reth-laterfork-engine 18951 1
neg-reth-p2p 30499 1
neg-reth-p2p-2 30599 1
neg-reth-p2p-3 30699 1
neg-reth-p2p-4 30799 1
neg-shard-p2p 28001 4
root-rpc 25866 8
root-p2p 26662 8
mongo 27117 1
shard-p2p 28111 6
shard-dissemination 28211 6
shard-rpc 28311 6
f8-http 28601 3
aggregator-bft-p2p 29101 2
aggregator-http 3001 2
seed-serve 38480 4
f6c-root-p2p 36662 1
f6c-root-rpc 36866 1
f6c-shard-p2p 36111 1
f6c-shard-rpc 36311 1
f6c-backup-root-p2p 46662 1
f6c-backup-root-rpc 46866 1
f6c-backup-val-p2p 46111 6
f6c-backup-val-rpc 46311 6
f6c-backup-reth-engine 48551 6
f6c-backup-reth-eth 48545 6
f6c-backup-reth-p2p 40401 6
EOF
}

# lane_slot_ports [SLOT]: "name port" for every port of the slot (the signing-authority sockets are paths under the tree's test-nodes/, not ports)
lane_slot_ports() {
  local off=$(( ${1:-$LANE_SLOT} * LANE_SLOT_STRIDE )) name base count k
  [ -z "${LANE_PORT_BASE:-}" ] || [ -n "${1:-}" ] || off=$LANE_PORT_OFFSET
  while read -r name base count; do
    for ((k = 0; k < count; k++)); do echo "$name $((base + k + off))"; done
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
