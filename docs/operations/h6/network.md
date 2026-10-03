# Manual network: setup, lifecycle and configuration

Complete [build.md](build.md), then enter the lock shell from [README](README.md).
The exported `H6_*` variables are inherited by that shell. All following blocks
run in the same shell. Every block stops on failure; preserve its output in the
run directory. Do not rerun generation over an existing network.

## Topology

One private host, four root validators, four EVM shard nodes, four independent
signing-authority processes and four Ureth instances. Each shard's archive server
runs inside that shard process; there is no separate archive daemon. Every
publisher has two distinct replica peer IDs. Authorities have separate homes and
Unix sockets, but share the host: this models validator-disk loss, not host loss.

| Role, index i=1..4 | Listener | Home/state |
|---|---|---|
| Root | P2P 26662+i−1; operator HTTP 25866+i−1 | `test-nodes/root<i>/` |
| Shard | P2P 28111+i−1; operator HTTP 28311+i−1 | `test-nodes/evm<i>/`, including journal |
| Ureth | Engine 18551+i−1; eth HTTP 18545+i−1; P2P 30401+i−1 | `test-nodes/reth<i>/dd/` |
| Authority | `client.sock`, `operator.sock`, no TCP listener | `test-nodes/auth<i>/` |
| Archive | Shard libp2p transport | `test-nodes/archives/evm<i>/` |

H3 additionally uses root/shard/EL/authority indices through 7 and aggregator
HTTP ports 28601–28603 with ephemeral libp2p ports. Reserve all of those ports
before a lane. Bind HTTP/Engine/operator services to loopback; operator status
has no authentication. Never expose the fixture's admin/debug APIs publicly.

## Generate identities and finalize genesis

```sh
set -eo pipefail
cd "$H6_SRC"
exec > >(tee -a "$H6_RUN/manual.log") 2>&1
export SIGNING=authority M2_PROFILE2=1 REGISTRY_LAYOUT=2
export URETH_PIN_COMMIT="$H6_OLD"
export URETH_BIN="$H6_RUN/bin/ureth-$H6_OLD"
. scripts/lib/reth-pin.sh
. helper.sh
. scripts/lib/m2-handoff-lib.sh
validators=4
partitionID=8
rethEthBase=18545
rethEngineBase=18551
rethP2PBase=30401
M2_CHAIN_ID=31337
M2_NEXT_NONCE=0
M2_PAID_REGISTRY_CHECK=0
chainSpec=test-nodes/evm-genesis-finalized-funded.json
fullShardConf=test-nodes/evm-full-shard-conf-v2.json
# Refuse to touch occupied fixture ports or an existing home.
test ! -e test-nodes
for base in 26662 25866 28111 28311 18551 18545 30401; do
  for i in 0 1 2 3 4 5 6; do
    if lsof -nP -iTCP:$((base+i)) -sTCP:LISTEN >/dev/null; then
      echo "STOP: port $((base+i)) occupied"; exit 1
    fi
  done
done
mkdir test-nodes
registry_layout_init
init_root_nodes 4
init_evm_validators 4
init_evm_authorities 4 8
generate_evm_shard_conf 4 8 31337 5000 exec
generate_evm_genesis 8
build/evmtx -alloc > "$H6_RUN/test-alloc.json"
jq --slurpfile alloc "$H6_RUN/test-alloc.json" '.alloc=$alloc[0]' \
  test-nodes/evm-genesis.json > test-nodes/evm-genesis-funded.json
build/ubft engine-api genesis --shard-conf test-nodes/shard-conf-8_0.json \
  --alloc-source test-nodes/evm-genesis-funded.json --registry-layout 2 \
  --out "$chainSpec" --full-shard-conf "$fullShardConf" | tee "$H6_RUN/genesis-identities.txt"
cp "$fullShardConf" test-nodes/shard-conf-8_0.json
enroll_evm_authorities 4 8
cp test-nodes/trust-base.json test-nodes/trust-base-epoch1.json
build/ubft trust-base verify --trust-base test-nodes/trust-base.json
generate_log_configuration 'test-nodes/*/'
shasum -a 256 "$chainSpec" "$fullShardConf" test-nodes/trust-base.json \
  registrygenesis/seal-registry-v2.json > "$H6_RUN/genesis.sha256"
```

The order matters: authority keys are generated in memory, `node-info` supplies
the public signing keys, finalization supplies the full configuration, then
`complete-enrollment` binds each authority to that configuration and
`replace-session` writes a client credential. Root/shard `keys.json` also contain
transport identities; they are not a backup of the external authority key.
These commands mirror `helper.sh:46`, `:194`, `:207`, `:243`, `:263` and
`scripts/reth-paired-devnet.sh:230`. The known funded key is only a test fixture.

## Start Ureth, roots, and shards

Define these process functions once. `start_reth` refuses an occupied pidfile;
use `stop_pidfile` and verify exit before restarting. It never regenerates JWTs.

```sh
rpc() {
  curl -fsS --max-time 10 "$1" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":$3}"
}
pyget() { python3 -c "import json,sys; d=json.load(sys.stdin); print(d$1)" 2>/dev/null; }
start_reth() {
  local i=$1
  test ! -e "test-nodes/reth$i/pid"
  urethPinVerifyBinary "$URETH_BIN" "$URETH_PIN_COMMIT"
  registry_layout_require
  "$URETH_BIN" node --chain "$chainSpec" --datadir "test-nodes/reth$i/dd" \
    --authrpc.jwtsecret "test-nodes/evm$i/jwt.hex" \
    --authrpc.addr 127.0.0.1 --authrpc.port $((18551+i-1)) \
    --http --http.addr 127.0.0.1 --http.port $((18545+i-1)) \
    --http.api eth,net,web3,admin,debug --rpc.eth-proof-window 64 \
    --port $((30401+i-1)) --disable-discovery --ipcdisable \
    --engine.persistence-threshold 64 --builder.gaslimit 30000000 \
    $(urethPinUnicityFlags) >> "test-nodes/reth$i/reth.log" 2>&1 &
  echo $! > "test-nodes/reth$i/pid"
  local ready=0 n
  for n in $(seq 1 60); do
    kill -0 "$(cat "test-nodes/reth$i/pid")"
    if rpc "http://127.0.0.1:$((18545+i-1))" eth_chainId '[]' | \
      jq -e '.result == "0x7a69"' >/dev/null; then ready=1; break; fi
    sleep 1
  done
  test "$ready" = 1
}
peer_reth() {
  local i j enode
  for i in 1 2 3 4; do
    enode=$(rpc "http://127.0.0.1:$((18545+i-1))" admin_nodeInfo '[]' | jq -er '.result.enode')
    for j in 1 2 3 4; do
      [ "$i" = "$j" ] && continue
      rpc "http://127.0.0.1:$((18545+j-1))" admin_addPeer "[\"$enode\"]" | jq -e '.result == true'
    done
  done
}
for i in 1 2 3 4; do
  mkdir -p "test-nodes/reth$i"
  (umask 077; openssl rand -hex 32 > "test-nodes/evm$i/jwt.hex")
  start_reth "$i"
  export "EVM_ENGINE_URL_$i=http://127.0.0.1:$((18551+i-1))"
  export "EVM_ETH_URL_$i=http://127.0.0.1:$((18545+i-1))"
done
peer_reth
export EVM_GENESIS_FILE="$chainSpec" EVM_FULL_SHARD_CONF="$fullShardConf"
export EVM_ENGINE_FEE_COLLECTOR="$URETH_PIN_FEE_COLLECTOR"
export EVM_ARCHIVE_ROOT=test-nodes/archives EVM_JOURNAL_CANDIDATES=32
start_root_nodes
wait_for_root_chain_settle
start_evm_validators 4 8 "$(m2_root_addr 1)" engine-api rpc
m2_send_paid 1 0 || { echo "STOP: paid certification check failed"; exit 1; }
```

The last command submits the same signed transfer to each EL, waits for a
successful receipt and matching certificate admission, and advances
`M2_NEXT_NONCE`. It is intentionally **not idempotent**. Never repeat it with an
old nonce after a lost response: query `eth_getTransactionCount` for
`build/evmtx -address` and reconcile the receipt first. Source command forms:
`scripts/reth-paired-devnet.sh:285`, `helper.sh:447`,
`scripts/lib/m2-handoff-lib.sh:93`. Root startup waits on its listener; if it
hangs, inspect the current root log and stop that owned process, not the host.

## Health and process lifecycle

```sh
snapshot() {
  local label=$1 i
  mkdir "$H6_RUN/$label"
  for i in 1 2 3 4; do
    curl -fsS "http://127.0.0.1:$((25866+i-1))/api/v1/roundInfo" > "$H6_RUN/$label/root$i.json"
    curl -fsS "http://127.0.0.1:$((28311+i-1))/api/v1/health" > "$H6_RUN/$label/health$i.json"
    build/ubft shard-node status --url "http://127.0.0.1:$((28311+i-1))" > "$H6_RUN/$label/shard$i.json"
    build/ubft signing-authority status --operator-socket "test-nodes/auth$i/operator.sock" \
      --operator-credential "test-nodes/auth$i/operator.cred" > "$H6_RUN/$label/authority$i.json"
    rpc "http://127.0.0.1:$((18545+i-1))" eth_getBlockByNumber '["finalized",false]' | \
      jq -e '.result | select(.hash and .stateRoot and .receiptsRoot)' > "$H6_RUN/$label/finalized$i.json"
  done
}
snapshot baseline
```

Require matching finalized height/hash/stateRoot/receiptsRoot across validators,
positive certified height, enrolled/nonfaulted/nonlost authorities, advancing
reserved rounds and both replica acknowledgements. Repeat after every operation;
an HTTP 200 or live PID alone is insufficient. Missing JSON fields are failure,
not zero. Apply [M2 shared checks](../m2-runbook.md#shared-preflight-and-evidence).

Stop/restart just shard 1 (authority and Ureth stay alive):

```sh
old=$(cat test-nodes/evm1/pid)
stop_one_evm_validator 1
for n in $(seq 1 60); do kill -0 "$old" 2>/dev/null || break; sleep 1; done
if kill -0 "$old" 2>/dev/null; then echo 'STOP: shard did not exit'; exit 1; fi
start_one_evm_validator 1 4 8 "$(m2_root_addr 1)" engine-api rpc
```

Require `execution journal restored`, a later `certification request signed`, a
later `certificate admitted`, unchanged authority PID/fingerprint/generation,
and a greater reserved round. After an intentional session replacement, generation
must instead increase and the new credential is read at shard startup. Do not
restart an authority to fix a socket error.

For final teardown only, save evidence, stop shards, roots and ELs, then authorities:

```sh
snapshot final
if [ -n "${H6_OBSERVER:-}" ]; then
  kill "$H6_OBSERVER"
  wait "$H6_OBSERVER" || true
fi
cp -R test-nodes "$H6_RUN/private-final-state"
stop_evm_validators
stop_root_nodes
for i in 1 2 3 4; do
  stop_pidfile "test-nodes/reth$i/pid" 'reth.* node' INT
done
for i in 1 2 3 4; do
  stop_pidfile "test-nodes/auth$i/pid" 'ubft signing-authority run' INT
done
# A pidfile stop sends a signal; verify all owned processes actually exited.
for n in $(seq 1 60); do
  remaining=$(owned_pids 'ubft (root-node|shard-node|signing-authority)|reth.* node')
  [ -z "$remaining" ] && break
  sleep 1
done
test -z "$remaining"
exit
```

`private-final-state` contains keys/JWTs/credentials; never publish it. It is
forensic evidence, not a consistent live backup or authority recovery source.
Once the authorities stop, this fixture cannot resume under the same keys.

## Configuration reference

This table covers the values the operator sets in this guide. Leave other CLI
defaults unchanged; save full `--help` output with the evidence for those defaults.

| Input/flag/file | Source and rule |
|---|---|
| `H6_BASE`, `H6_RUN`, `H6_SRC`, compiler/cache variables | Operator-owned absolute paths; fresh clone/run; run directory outside `test-nodes/`. |
| `H6_BFT`, `H6_OLD`, `H6_NEW`, contract/aggregator pins, binary paths | build.md; immutable full SHAs, verified executable metadata and SHA-256. |
| `--home`, `--key-conf`, pid/log paths | Topology above; init generates keys and node-info, pidfiles record launched processes; do not share homes. |
| `SIGNING=authority`, authority ID/sockets/operator credential | `init_evm_authorities`: `paired-evm-i`, `auth<i>/`; credential files mode-restricted; keys volatile. |
| Network 3; partition/type 8; shard `0x80`; chain 31337 | Independent fixture identifiers, not interchangeable; T6 uses chain 1337. |
| Trust epoch/start 1/1, shard epoch 0, stake/node list | `init_root_nodes` and authority node-info; trust bases signed by root keys; all unit weights. |
| T2 5000 ms, `proof_type=exec` | `generate_evm_shard_conf`; H3 adds three aggregator configurations automatically. |
| `--registry-layout 2`, `test-nodes/registry-layout` | Resolves registry artifact hash and Ureth pin once; preserved through restarts. Upgrade changes only recorded client pin after compatibility checks. |
| `--alloc-source`, `--out`, `--full-shard-conf`, `--genesis` | Funded fixture allocation, finalized JSON and full configuration generated together; never hand-edit after initialization. |
| `--profile-2`, root `--shard-conf`, `--trust-base` | Full genesis config supplied at root startup; epoch-1 trust anchor retained; no post-genesis configuration PUT. |
| Root `--install-handoff-epoch` | Only after H is committed; derived from successor epoch, verified bundle must exist. |
| `--address`, `--bootnodes`, RPC URLs | Port table; bootnode addresses include generated `/p2p/<node-id>`; shards peer with roots and siblings. |
| `--executor engine-api`, per-validator `EVM_ENGINE_URL_i`/`EVM_ETH_URL_i` | Exactly one EL per shard, not default shared 8551/8545. |
| JWT; `--authrpc.jwtsecret` / `--jwt-secret` | Same generated 32-byte hex file for the matching EL/shard pair; preserve at restart. |
| EL chain/datadir, discovery/IPC, HTTP API/proof window, gas limit, persistence threshold | `start_reth` above: fixed chain; datadir preserved; discovery/IPC off; APIs explicitly listed; 64/30,000,000/64. |
| `--unicity.fee-collector` / `--engine-fee-collector` | Same fixture `0x000000000000000000000000000000000000dead`; T6 uses its manifest beneficiary. |
| `--execution-journal`, `--archive-store`, `--archive-prune`, `--archive-replica` | Helper creates evm journal and archive; exactly two peer IDs from other validators 2–4, excluding self; preserve order. |
| `EVM_JOURNAL_CANDIDATES` | Manual/T6 lane 32, H3 256; CLI default 256; standard F9 recovery profile 16 is a distinct budget. Byte default 67,108,864, observation default 512. |
| `--trust-history-profile-2`, `--registry-layout` on shard | Required for handoff replay/layout-2; generated by helper from profile and layout record. |
| Logging/metrics | Root debug/text + Prometheus; shard info/text and status RPC. Shard Prometheus is not enabled by this helper; use status or explicitly add `--metrics prometheus` for F9 metric collection. |
| Restore `--tip-uc`, `--tip-tr`, `--trust-body-id` | `h4-restore-pin` output; genesis trust anchor remains epoch 1; current body ID comes from authenticated history, never a guessed hash. |
| Handoff context/validators/bindings/PoPs/assignment | H3 lane generates exact attempt context; retained and new authority keys sign PoPs; root entity maps to one EVM delegate. |
| Abort target, timeout and RPC list | scenarios.md captures network, epoch, predecessor, attempt and SHA-256 of planned canonical body; CLI reauthenticates the target. Timeout means unknown. |
