# Validator handbook

This guide operates one validator on a Validator Registry (VR) proof-of-stake generation with the P85 prototype contracts. One validator runs a root node, an EVM shard node, ureth for execution, and a signing authority for the shard's certification key. The Foundation publishes the network release and endpoints. Use its authenticated release announcement to obtain the release digest and the UTB genesis EntryID.

## Quick start with the validator container

Use an amd64 Linux Docker host with a reachable IPv4 address. Forward TCP 27652
and 29252 to that host if a router owns the public address. A laptop without
those inbound routes cannot join. The operator and Engine RPCs and ureth stay
on loopback. The public peer lists are in the
`/release/validator-container/` bundle.

Obtain the container bundle's `SHA256SUMS` digest from the authenticated
announcement. The tarball is a `docker save` archive for the one image used by
both roles. Use the loader from a trusted checkout of this handbook's release.
It checks the archive's OCI manifest and platform before handing it to Docker.

```bash
set -euo pipefail
RELEASE=https://pos.staging.unicity.network/release/validator-container
read -rp 'Published container SHA256SUMS digest: ' BUNDLE_DIGEST
curl -fsS "$RELEASE/SHA256SUMS" -o SHA256SUMS
printf '%s  SHA256SUMS\n' "$BUNDLE_DIGEST" | sha256sum -c -
while read -r digest name; do curl -fsS "$RELEASE/$name" -o "$name"; done < SHA256SUMS
sha256sum -c SHA256SUMS
# Set BFT_CORE to the absolute path of the trusted bft-core checkout.
IMAGE=$(python3 "$BFT_CORE/deploy/testnet/validator-container/load.py" "$PWD" "$BUNDLE_DIGEST")
```

Keep the named volume private. Start the authority once. Both roles can share
the host network, and only the two P2P ports need inbound forwarding. Supply
your own IPv4 address in place of the example. The profile and UTB genesis
are pinned by the image. If the operator's authenticated launch instructions
name a later epoch, the node verifies that epoch from genesis before it
provisions the authority. The defaults select the current epoch automatically.

```bash
docker volume create unicity-validator
docker run --rm --network host -v unicity-validator:/data "$IMAGE" \
  init --announce-addresses /ip4/192.0.2.10
docker run -d --name unicity-authority --restart=no --network host \
  -v unicity-validator:/data "$IMAGE" authority
docker run -d --name unicity-node --network host \
  -v unicity-validator:/data "$IMAGE" run
docker exec unicity-node ubft-validator join --yes
docker exec unicity-node ubft-validator status
```

Use the faucet page to fund the printed payee. One 200 UCT claim covers the
100 UCT bond and gas. The join command resumes from the private journal.
Every validator submits its own frozen-member proof and can publish the
result once all proofs are recorded. The joining node uses the activation
proof from its own synced root and verifies it from its pinned lineage.

Keep the authority container running during node updates. Replace only
`unicity-node`, with the same data volume, then repeat `join --yes` if the
join was interrupted. For authority process loss, follow [Authority loss](#authority-loss).
For retirement run
`docker exec unicity-node ubft-validator exit --yes`. After the maturity
conditions in section 6 hold, run
`docker exec unicity-node ubft-validator exit --claim --yes`.

The manual procedure below is the reference for incident recovery and
for validating the resulting committee and certification evidence.

## Authority loss

Keep the authority volume and its fail-stop marker intact. The marker is
the `lifetime` file the container writes before the authority first
starts; a volume that carries it never runs an authority again. Never
restore an authority from a backup or copy its volume. Determine the
identity's registration and bond state from certified chain data and
reconcile any submitted registration, delegation or bond transactions.

- If the identity is unregistered, unbonded and has no unresolved submissions,
  keep the original volume for diagnosis. Initialize a new identity in a
  separately named volume and fund its new payee before joining.
- If the identity is registered and bonded, recover it in place with
  `ubft validator recover` (container: `ubft-validator recover`, below). A
  new EVM key is a new EVM node identity: create a fresh shard node key (a
  new EVM node id), a new authority in a fresh volume and an empty shard
  data directory. The new shard node joins through the joiner path: it
  syncs, stays staging-only and activates at the boundary. The old node and
  authority stay stopped; their volumes and the marker are preserved and
  never reused. The root key, root node, payee and bond stay. The bond stays in
  its lots at custody's current generation, so nothing unbonds. Preserve the
  old volume and marker: recover requires the marker in the old volume
  (`--old-authority-home`) and refuses a new authority inside it. An
  unreachable authority alone is not evidence of key loss, and recover
  refuses a configured authority that still answers and holds its key.

`recover` reads the certified (finalized) state first and refuses unless
the custody owner is the operator, the identity has open lots, has not
requested retirement and is not excluded. Then it sends two transactions,
each confirmed and re-read before the next:

1. `ElectionPolicy.admitDelegation` of the new EVM key at custody's current
   generation. It fences the old key: no later election snapshot selects the
   identity with the old key.
2. `VR.proposeBinding` of the identical words. The next election freezes the
   new key, the new authority proves possession, and the boundary installs
   the binding at the same generation.

A re-run compares the exact words and skips the steps already done, so an
interrupted recovery is resumed with the same command. While an open
election result has frozen the identity's staged binding, recover refuses to
replace it; wait until that result is published and acknowledged, rejected
or recovered. A result that froze the old, dead key cannot publish; it ends
by rejection after its reservation lifetime and the incumbents continue. An
identity still in the active committee keeps signing on n-1 until the next
boundary, where the new authority activates through the join path.

Refused states take the exit path with the owner wallet: root-key loss (the
root key never changes in place), a requested retirement, an exclusion, or
a lost operator key. Run `validator exit`, wait for the closure and the
holder retirement, `validator claim`, then join a fresh identity with new
keys (or re-bond and `apply` at the next generation).

For the container, the old authority container has already stopped (it is
fail-stop). Keep `unicity-node` running and its volume mounted:

RECOVER_CONTAINER_COMMANDS

## Rehearsal shell## Rehearsal shell

For VT-13, use the dedicated `vt13operator` account on the rehearsal host. Generate a new SSH key on your workstation and submit **only the public key** in `briefs/vt13-operator-log.md` for the rehearsal maintainer to install. Use the host address from the public RPC URL in the rehearsal inputs.

```bash
install -d -m 700 "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/vt13-operator" -C vt13-operator
cat "$HOME/.ssh/vt13-operator.pub"
```

After the maintainer confirms the key is installed, check the server's SSH host fingerprint at the connection prompt. The rehearsal host's ECDSA fingerprint is `SHA256:Q9TuHHqEgdBwZrhgFitNfo1RaOhpOtg9uuIxtCo0X2A`. Connect using the new key.

```bash
ssh -o IdentitiesOnly=yes -o HostKeyAlgorithms=ecdsa-sha2-nistp256 \
  -o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
  -i "$HOME/.ssh/vt13-operator" vt13operator@212.23.222.159
```

Start or attach the rehearsal's persistent terminal before starting any services. Do the remaining steps inside it. To leave it running, detach with `Ctrl-b` then `d`. After an SSH interruption, reconnect and repeat this command to attach to the same session and retain its shell variables and jobs.

```bash
tmux new-session -A -s vt13-validator
```

The authority's enrolled key lives in the authority process. Keep its tmux window and the host running through the acknowledged exclusion. If the authority process exits before exclusion, record the failure and preserve its volume and fail-stop marker. Do not start a replacement: a retiring identity cannot be recovered in place (`validator recover` refuses it), and the remaining incumbents carry the shard until the exclusion. After exclusion and closure, the incumbents can finish processing your confirmed retirement request independently of your authority. Keep your wallet available for the maturity and claim steps.

## 1. Install the release

Use a synchronized clock and persistent SSD storage. Allow inbound root and shard libp2p TCP and the release's ureth devp2p ports. Use outbound access to the public RPC, seed and peers. Keep operator RPC, metrics, Engine API and signing sockets on loopback or a private admin network. Archive replay needs the local ureth debug API for header witnesses. The reference host has 6 CPU cores / 12 threads, 64 GB RAM and two 1 TB NVMe drives. Size for your release and retention policy, and check `validator doctor`.

Install the matching Linux `ubft` and `unicity-reth` from the release's checksum manifest. The rehearsal release is built for Linux x86-64. These examples use Bash, curl, jq, GnuPG and the GNU core utilities. Run them from a fresh login shell. Keep the same values when supervising services or starting another shell.

```bash
umask 077
export UBFT_HOME="$HOME/validator"
export PATH="$HOME/.local/bin:$PATH"
install -d -m 700 "$UBFT_HOME" "$HOME/.local/bin"
cd "$UBFT_HOME"
read -rp 'Public EVM RPC URL: ' RPC_URL
read -rp 'Public release URL: ' RELEASE_URL
read -rp 'Public seed URL: ' SEED_URL
read -rp 'Pinned UTB genesis EntryID: ' GENESIS_PIN
read -rp 'Release SHA256SUMS digest: ' RELEASE_DIGEST
install -d -m 700 release logs
install_release() (
  set -eo pipefail
  curl -fsS "${RELEASE_URL%/}/SHA256SUMS" -o release/SHA256SUMS
  printf '%s  %s\n' "$RELEASE_DIGEST" release/SHA256SUMS | sha256sum -c -
  while read -r digest name; do
    mkdir -p "release/$(dirname "$name")"
    curl -fsS "${RELEASE_URL%/}/$name" -o "release/$name"
  done < release/SHA256SUMS
  (cd release && sha256sum -c SHA256SUMS)
  install -m 755 release/ubft release/unicity-reth "$HOME/.local/bin/"
  ubft validator --help
  unicity-reth --version
)
install_release
```

Continue after all manifest entries verify. The commands below use free local ports 26652 (root), 28152 (shard), 30303 (ureth devp2p), 8545 (Ethereum RPC), 8551 (Engine), 25852 (root status) and 28352 (shard status). Adapt the ports together if these are in use.

## 2. Create the operator identity and start the authority

The single-account commands in Sections 2–4 are for the isolated rehearsal. For an external deployment, put the authority and its operator socket, administrative credential and wallet in an administrative security boundary. Run root, shard and ureth as separate unprivileged services. Keep their homes, credentials and backups separate from the administrative files. Restrict the root to the PoP socket and `pop.cred`, and the shard to the certification socket and current `client.cred`. Ureth needs neither endpoint.

For separate Linux accounts, place the authority's operator, PoP and certification sockets in three distinct directories. The authority creates each socket owner-only and restricts its directory on startup. After the listeners are ready, have the supervisor grant the paired root UID traversal and connect access to the PoP directory and socket, and the paired shard UID those rights to the certification directory and socket, for example with per-user filesystem ACLs. Reapply the grants after each authority startup. Keep the operator socket and credential in an admin-only location. Deliver each service's own credential to its private directory and update the shard's copy when a session is replaced. Before starting services, verify from each service account that it can reach its own endpoint and read its own credential, and that access to the administrative credential and the other service's credential is denied. [Authority credential model](../design/f6c-signing-state-contract.md#the-authority-process-boundary-before-step-4)

Before creating the authority, have the Foundation confirm the next election is still open to applications and give you its successor shard epoch and application cutoff. For the rehearsal, use the maintainer's admission-window entry in the operator log. The current root epoch alone cannot establish this scope.

`validator init` creates the root key, the shard's local key file for peer identity, the ureth devp2p secret, the Engine JWT and the operator transaction key. The authority generates its own shard signing key in memory. It starts pending, with signing sessions disabled until enrollment. Create and hold the authority outside the shard's backup and restart scope. If its process is lost, its signing identity is lost. Arrange a new binding and enrollment before returning to service.

```bash
CHAIN_ID=$(jq -er '.config.chainId' release/genesis.json)
NETWORK_WORD=$(jq -er '.networkWord' release/vr-deployment.json)
ELECTION=$(jq -er '.election' release/deployment.json)
CUSTODY=$(jq -er '.custody' release/deployment.json)
REGISTRY=0xff00000000000000000000000000000000000003
ubft validator init --rpc "$RPC_URL" --chain-id "$CHAIN_ID" --ports 26652,28152,30303
OPERATOR=$(jq -er '.payee' validator.json)
ROOT_EPOCH=$(ubft validator status --sample 0 --json | jq -er '.rootEpoch | select(. >= 1)')
read -rp 'Confirmed successor shard epoch: ' NEXT_SHARD_EPOCH
SHARD_NODE=$(ubft node-id --home "$UBFT_HOME/evm" | tail -n1)
install -d -m 700 authority
ubft signing-authority credential --out authority/operator.cred
ubft signing-authority credential --out authority/pop.cred
jq -n --arg network "$NETWORK_WORD" --argjson chainId "$CHAIN_ID" \
  --arg registry "$REGISTRY" --arg owner "$OPERATOR" \
  --slurpfile root root/node-info.json \
  '{network:$network,chainId:$chainId,registry:$registry,authorized:[
    {action:"register",owner:$owner,payee:$owner,rootNodeId:$root[0].nodeId,rootKey:$root[0].sigKey}
  ]}' > authority/registration.json
ubft signing-authority run --home "$UBFT_HOME/authority" --authority-id "$SHARD_NODE" --network-id 3 --partition-id 8 \
  --shard-id 0x80 --shard-epoch "$NEXT_SHARD_EPOCH" --root-epoch 1 --node-id "$SHARD_NODE" \
  --trust-base "$UBFT_HOME/release/trust-base.json" \
  --client-socket "$UBFT_HOME/authority/client.sock" \
  --operator-socket "$UBFT_HOME/authority/operator.sock" --operator-credential "$UBFT_HOME/authority/operator.cred" \
  --pop-socket "$UBFT_HOME/authority/pop.sock" --pop-credential "$UBFT_HOME/authority/pop.cred" \
  --registration-policy "$UBFT_HOME/authority/registration.json" --dev-allow-late-pos-policy \
  --metrics-address 127.0.0.1:29352 >logs/authority.log 2>&1 &
AUTHORITY_PID=$!
```

A pending authority is scoped to the shard epoch that will first name it. Save the confirmed cutoff, successor shard epoch and current root epoch with your service configuration.

The late P85 pin is for this prototype rehearsal when VR assigns the identity at application. For a deployment with a provisioned identity, use an approved startup `--pos-policy` and `--require-pos-policy`. Wait for `signing authority running` in `logs/authority.log`, then select the authority in the validator config.

```bash
AUTH=(--operator-socket "$UBFT_HOME/authority/operator.sock" --operator-credential "$UBFT_HOME/authority/operator.cred")
ubft signing-authority node-info "${AUTH[@]}" --out authority/node-info.json
ubft validator init --force --rpc "$RPC_URL" --chain-id "$CHAIN_ID" --ports 26652,28152,30303 \
  --evm-authority-socket authority/operator.sock --evm-authority-credential authority/operator.cred \
  --evm-authority-node-info authority/node-info.json
ubft validator doctor
```

Fund the printed operator address with the bond plus transaction gas using the release's funding instructions. For a local rehearsal backup, run this from the validator home in your SSH terminal. GnuPG asks you to choose and confirm a fresh backup passphrase. Keep it out of the operator log.

```bash
export GPG_TTY=$(tty)
install -d -m 700 "$HOME/validator-backups"
BACKUP="$HOME/validator-backups/validator-$(date -u +%Y%m%dT%H%M%SZ).tar.gz.gpg"
backup_validator() (
  set -eo pipefail
  files=(root/keys.json evm/keys.json ureth-key/p2p-secret operator/key validator.json)
  work=$(mktemp -d "$HOME/validator-backups/.verify.XXXXXXXX")
  trap 'rm -r -- "$work"' EXIT
  tar -czf - "${files[@]}" |
    gpg --symmetric --cipher-algo AES256 --output "$work/backup.gpg"
  gpg --decrypt "$work/backup.gpg" | tar -tzf - > "$work/entries"
  printf '%s\n' "${files[@]}" | LC_ALL=C sort > "$work/expected"
  LC_ALL=C sort "$work/entries" -o "$work/entries"
  diff -u "$work/expected" "$work/entries"
  mv -- "$work/backup.gpg" "$BACKUP"
  printf 'Verified encrypted backup: %s\n' "$BACKUP"
)
backup_validator
```

The check decrypts into a pipe and compares the archive's entry list before publishing the encrypted backup. Keep the JWT and authority credentials private. Start only one instance per identity. Always pass the same `--p2p-secret-key` to ureth so its enode survives a datadir rebuild.

Before applying, check that `validator status --sample 0 --json` still reports the recorded `ROOT_EPOCH` and that your confirmed election cutoff has passed neither in certified time nor progress. Confirm a new window if the cutoff elapsed or an intervening handoff closed it. See [Missed admission](#missed-admission) for the binding recovery.

## 3. Verify the seed and start as a follower

### Choose the release's execution proof profile

**VT-07 release.** Set ureth to serve archive state proofs and point the root's `--pos-evm-rpc` at that private execution endpoint. The VT-07 root retains observations in a durable queue and can request an exact block hash long after it was certified. A bounded proof window can leave that entry at the front of the queue and delay later publications.

```bash
URETH_PROOF_ARGS=(--unicity.archive-state-proofs)
ROOT_EXEC_RPC=http://127.0.0.1:8545
```

Keep ureth's HTTP, WebSocket if enabled, and authenticated RPC bound to loopback. Retain unpruned **account history and storage history** for all certified blocks the root might replay. Disable any account- or storage-history pruning in both CLI flags and `reth.toml`. Allocate persistent SSD space for full execution history and its growth, and monitor that volume. Turning on archive proofs cannot recover state already pruned. Build the proof source with full retained history from genesis or from the release's verified archival recovery procedure before pointing the root at it. This history is separate from the shard's certified archive and from a seed. [ureth archive state proofs](https://github.com/ristik/ureth/pull/106) · [VT-07 root schedule](https://github.com/ristik/bft-core/pull/1228)

**Pre-VT-07 release, including the pinned VT-13 rehearsal.** Use these assignments instead. This bounded window covers the paired shard's recent parent witnesses and restart admission on this release.

```bash
URETH_PROOF_ARGS=(--rpc.eth-proof-window 64)
ROOT_EXEC_RPC=$RPC_URL
```

For other pre-VT-07 deployments, set `ROOT_EXEC_RPC` to the deployment's designated execution endpoint.

The following preflight is for an epoch-1 checkpoint. For a later checkpoint, fetch the published activation bundles in epoch order and pass each to `seed restore-pin` with `--bundle`. See [Sync from a seed](sync-seed.md) for mirror agreement, history verification and retention.

```bash
ubft seed fetch --from "$SEED_URL" --utb-genesis-id "$GENESIS_PIN" \
  --full-shard-conf release/full-shard-conf.json --out downloaded-seed
ubft seed import --dir downloaded-seed --home "$UBFT_HOME" --source "$SEED_URL" \
  --utb-genesis release/utb-genesis.cbor --utb-genesis-id "$GENESIS_PIN" \
  --full-shard-conf release/full-shard-conf.json --root-utb-db root/root-utb-entries.db \
  --shard-utb-db evm/shard-utb-entries.db
PIN_RESULT=$(ubft seed restore-pin --dir downloaded-seed --utb-genesis-id "$GENESIS_PIN" \
  --full-shard-conf release/full-shard-conf.json --trust-base release/trust-base.json --out seed-pin)
TRUST_BODY_ID=${PIN_RESULT##*bodyID=}
```

Continue after preflight succeeds. The release's peer files contain one multiaddress per line. Rehearsal peers are reachable from the dev host. For an external host, use the release's routable peers and set the host's public IPv4 address before running the next block. Forward TCP 26652 and 28152 to this host if it is behind NAT. The nodes still serve their operator RPC on loopback.

```bash
read -rp 'Public IPv4 address for your external node: ' PUBLIC_P2P_IP
```

Leave `PUBLIC_P2P_IP` unset during the rehearsal.

```bash
read -r -a URETH_FLAGS <<< "$(paste -sd' ' release/ureth-flags.txt)"
ROOT_PEERS=$(paste -sd, release/root-peers.txt)
SHARD_PEERS=$(paste -sd, release/shard-peers.txt)
mapfile -t ARCHIVE_PEERS < <(head -n 2 release/shard-peers.txt | sed 's|.*/p2p/||')
FEE_COLLECTOR=$(cat release/fee-collector.txt)
ROOT_P2P=(--address /ip4/127.0.0.1/tcp/26652)
SHARD_P2P=(--address /ip4/127.0.0.1/tcp/28152)
if [[ -n ${PUBLIC_P2P_IP:-} ]]; then
  ROOT_P2P=(--address /ip4/0.0.0.0/tcp/26652 --announce-addresses "/ip4/$PUBLIC_P2P_IP/tcp/26652")
  SHARD_P2P=(--address /ip4/0.0.0.0/tcp/28152 --announce-addresses "/ip4/$PUBLIC_P2P_IP/tcp/28152")
fi
ROOT_INSTALL=()
if (( ROOT_EPOCH > 1 )); then
  ROOT_INSTALL=(--install-handoff-epoch "$ROOT_EPOCH")
fi
UTB=(--utb-genesis "$UBFT_HOME/release/utb-genesis.cbor" --utb-genesis-id "$GENESIS_PIN")
unicity-reth node --chain "$UBFT_HOME/release/genesis.json" --datadir "$UBFT_HOME/ureth" \
  --p2p-secret-key "$UBFT_HOME/ureth-key/p2p-secret" --disable-discovery \
  --port 30303 --ipcdisable --http --http.addr 127.0.0.1 --http.port 8545 --http.api eth,net,debug \
  "${URETH_PROOF_ARGS[@]}" \
  --authrpc.addr 127.0.0.1 --authrpc.port 8551 --authrpc.jwtsecret "$UBFT_HOME/jwt/jwt.hex" \
  "${URETH_FLAGS[@]}" >logs/ureth.log 2>&1 &
URETH_PID=$!
```

Wait for both ureth listeners before starting the root and shard. Continue after this check succeeds.

```bash
timeout 45 bash -c '
  until curl -fsS --max-time 2 -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_chainId\",\"params\":[],\"id\":1}" http://127.0.0.1:8545 |
      jq -e ".result != null" >/dev/null &&
      ( : </dev/tcp/127.0.0.1/8551 ) 2>/dev/null; do
    sleep 1
  done
'
```

```bash
ROOT_ARGS=(--home "$UBFT_HOME/root" "${ROOT_P2P[@]}"
  --bootnodes "$ROOT_PEERS" --metrics prometheus --rpc-server-address 127.0.0.1:25852
  --trust-base release/trust-base.json --shard-conf release/full-shard-conf.json --profile-3 --q3-lane --b1-registry
  --genesis-identities release/genesis-identities.json --vr-deployment release/vr-deployment.json
  --pos-evm-rpc "$ROOT_EXEC_RPC" --vr-shard-rpc http://127.0.0.1:28352
  --vr-evm-authority-socket "$UBFT_HOME/authority/pop.sock"
  --vr-evm-authority-credential "$UBFT_HOME/authority/pop.cred" "${UTB[@]}")
ubft root-node run "${ROOT_ARGS[@]}" "${ROOT_INSTALL[@]}" >>logs/root.log 2>&1 &
ROOT_PID=$!
SHARD_ARGS=(--home "$UBFT_HOME/evm" "${SHARD_P2P[@]}"
  --bootnodes "$ROOT_PEERS,$SHARD_PEERS" --metrics prometheus --rpc-server-address 127.0.0.1:28352
  --trust-base release/trust-base.json --full-shard-conf release/full-shard-conf.json
  --executor engine-api --genesis release/genesis.json --b1-profile release/b1-profile.json
  --engine-url http://127.0.0.1:8551 --eth-url http://127.0.0.1:8545
  --jwt-secret "$UBFT_HOME/jwt/jwt.hex" --engine-fee-collector "$FEE_COLLECTOR"
  --execution-journal "$UBFT_HOME/evm/execution-journal.db" --archive-store "$UBFT_HOME/evm/archive"
  --archive-prune --archive-replica "${ARCHIVE_PEERS[0]}" --archive-replica "${ARCHIVE_PEERS[1]}"
  --trust-history-profile-2 --q3-lane --journal-candidates 4096 --journal-observations 8192 --journal-bytes 134217728
  --signing-authority-socket "$UBFT_HOME/authority/client.sock"
  --signing-authority-credential "$UBFT_HOME/authority/client.cred" "${UTB[@]}")
ubft shard-node restore "${SHARD_ARGS[@]}" --tip-uc seed-pin.uc.cbor --tip-tr seed-pin.tr.cbor \
  --trust-body-id "$TRUST_BODY_ID" >logs/shard.log 2>&1 &
```

If the initial shard restore exited at the Engine dial with connection refused, leave the healthy root running. After ureth's readiness check succeeds, repeat just `shard-node restore` when the journal and archive are still fresh. If a same-epoch restore recorded a checkpoint and then stopped, repeat the restore with the same pin, journal, archive and execution datadir. See [archive restore](../single-epoch-archive-restore.md) for the retry checks.

The root starts from genesis, and the shard and ureth replay certified data from archive peers to the seed checkpoint. Before the roots stage your identity, your shard may retry its handshake and the local head may trail the network. Keep the services running through application and check for catch-up once the election publishes and the roots stage the successor. After a successful restore, supervise subsequent shard starts with `ubft shard-node run "${SHARD_ARGS[@]}"`. Preserve the databases, sessions and high-water records across restarts.

### Bring a lagging root to an activated epoch

If the root stays on the same round and times out across an intervening public handoff, read its local epoch and the public VR epoch. For a confirmed gap, stop only your root and install the next missing root epoch from peers using the existing root home. Leave the authority and shard replay running. The root verifies the activation before it installs it.

```bash
LOCAL_ROOT_EPOCH=$(curl -fsS http://127.0.0.1:25852/api/v1/roundInfo | jq -er '.epochNumber | tonumber')
PUBLIC_ROOT_EPOCH=$(ubft validator status --sample 0 --json | jq -er '.rootEpoch | select(. >= 1)')
if [[ -n "$LOCAL_ROOT_EPOCH" && -n "$PUBLIC_ROOT_EPOCH" ]] &&
   (( LOCAL_ROOT_EPOCH < PUBLIC_ROOT_EPOCH )); then
  kill "$ROOT_PID"
  wait "$ROOT_PID" || true
  ubft root-node run "${ROOT_ARGS[@]}" --install-handoff-epoch "$((LOCAL_ROOT_EPOCH + 1))" >>logs/root.log 2>&1 &
  ROOT_PID=$!
fi
```

Check the new local epoch with the same round-info request. Repeat only after one activation has installed if more epochs are missing. Preserve the existing root database, UTB entry stores and member signing state.

## 4. Apply, stake and join

Check the PoS committee profile in the authenticated release announcement. A sixteen-seat generation allows up to 16 seats in primary and recovered assignments and 20 live identities. Each identity generation has one lifetime lot with room for four simultaneous assignment references. Released obligations free capacity. A recovery preserves the incumbent's ordered seats and historical lot references. Check the certified assignment and epoch before changing your authority scope. The existing PoS generation uses the limits in its own release announcement.

Use a fresh root signing key for every root history. Never bring a root key from an earlier generation or reset, whether you enroll now, join later or rotate. Post-term evidence charges a quorum seal from its signed bytes, and those bytes bind the network but not the root genesis. A seal your old key signed in another history that shares the network would therefore be chargeable here ([D5 §2.1](../design/d5-accountability-retirement-inbox.md#21-post-term-seal-offence-1297)). The release ships the retired root key hashes as `retired-root-keys.json`. `apply` and `rotate` read `release/retired-root-keys.json` under the validator home by default and refuse a configured root key on the list. A release of a first generation has no list, and then there is nothing to check. `--retired-root-keys FILE` names another list, and `--no-retired-root-keys` skips the shipped one.

```bash
ubft validator apply --dry-run
ubft validator apply
ID=$(jq -er '.id' validator.json)
jq -n --arg network "$NETWORK_WORD" --argjson chainId "$CHAIN_ID" --arg election "$ELECTION" \
  --argjson id "$ID" '{network:$network,chainId:$chainId,election:$election,ids:[$id]}' > authority/pos-policy.json
ubft signing-authority pos-policy "${AUTH[@]}" --policy authority/pos-policy.json
```

On PoS, apply registers the keys in VR and P85 custody, bonds the stake and admits the delegation. The default is one bond unit. To choose the amount or recipient, supply `--bond` in decimal base units and `--withdrawal` on the initial application. Keep the same settings on retries. A dry run previews the next transaction against the state currently visible. Read the receipts before treating an application as complete.

Wait for a P85 election to reserve a result naming your identity. With the release that includes the per-validator proof command, submit your own assignment possession proof. Each frozen member submits one through its own authority. The relayer can then finalize P85 and publish in VR. A member with an unavailable authority can hold up that result until it expires. Keep the nodes running and follow the next attempt.

```bash
ubft validator pos-publish --own-proof
```

Once the result is published, the roots derive the intent and the nodes collect readiness. Watch for Prepare, Freeze, the committed handoff and activation. Wait for your own root to install the first activated epoch that names you. Read its certified configuration and trust base over its loopback operator RPC. Use the root epoch and successor shard epoch confirmed for that handoff. Immediately after a root switch, round-info can still show the shard epoch of the last certificate. That early sample cannot distinguish a root-only change from a coupled assignment. Check that the verified shard configuration for the confirmed epoch is available before changing the authority's scope.

```bash
read -rp 'Activated root epoch: ' ACTIVATED_ROOT_EPOCH
read -rp 'Activated shard epoch: ' ACTIVATED_SHARD_EPOCH
read -rp 'First enrollment or later handoff (enroll/advance): ' HANDOFF_MODE
install_authority_scope() (
  set -eo pipefail
  [[ "$ACTIVATED_ROOT_EPOCH" =~ ^[1-9][0-9]*$ && "$ACTIVATED_SHARD_EPOCH" =~ ^[0-9]+$ ]]
  [[ "$HANDOFF_MODE" == enroll || "$HANDOFF_MODE" == advance ]]
  activation=$(mktemp -d "$UBFT_HOME/activation-root-${ACTIVATED_ROOT_EPOCH}-shard-${ACTIVATED_SHARD_EPOCH}.XXXXXXXX")
  shard_conf="$activation/shard-conf.json"
  trust_base="$activation/trust-base.json"
  ubft q3 shard-conf --root-rpc http://127.0.0.1:25852 --epoch "$ACTIVATED_SHARD_EPOCH" --out "$shard_conf"
  ubft q3 trust-base --root-rpc http://127.0.0.1:25852 --epoch "$ACTIVATED_ROOT_EPOCH" --out "$trust_base"
  jq -e --arg epoch "$ACTIVATED_SHARD_EPOCH" '(.epoch | tostring) == $epoch' "$shard_conf" > /dev/null
  jq -e --arg epoch "$ACTIVATED_ROOT_EPOCH" '(.epoch | tostring) == $epoch' "$trust_base" > /dev/null
  if [[ "$HANDOFF_MODE" == enroll ]]; then
    ubft signing-authority complete-enrollment "${AUTH[@]}" --shard-conf "$shard_conf"
  fi
  ubft signing-authority advance-epoch "${AUTH[@]}" --shard-conf "$shard_conf" --trust-base "$trust_base"
  ubft signing-authority replace-session "${AUTH[@]}" --out "$UBFT_HOME/authority/client.cred"
)
install_authority_scope
```

Use `enroll` only for the first enrollment. For each later handoff, use `advance` with the confirmed pair. If a lookup fails or the epochs disagree, wait for the paired root to serve the confirmed configuration, then check the authority before retrying. Each attempt fetches into a fresh directory. If you previously advanced using a stale shard epoch, use `advance` with the same verified root epoch and the confirmed higher shard epoch. For an authority already equipped with a lineage pin and an installed configuration, use `signing-authority advance-with-proof` and the verified activation bundles in epoch order. Keep its certification session private.

#### Resume an interrupted authority handoff

Keep the authority running. Keep the intended epoch pair from the verified lookups and read the authority's current status before retrying a command.

```bash
ubft signing-authority status "${AUTH[@]}" |
  jq '{enrollmentComplete, rootEpoch, shardEpoch, sessionIssued, generation, retired, faulted, keyLost}'
```

- If `enrollmentComplete` is false, resume with `enroll`. If it is true and the scope still needs to move to the verified pair, resume the main block with `advance`. Check with the Foundation if the reported scope is ahead of, or inconsistent with, the intended pair, or if the authority reports a fault, retirement or lost key.
- If both epochs match the verified pair and `sessionIssued` is false, run only the block below. A scope advance fences the old client credential.
- If both epochs match and `sessionIssued` is true, the authority already issued a session for that scope. If the replacement wrote `client.cred`, continue with the shard reload and confirm that the shard accepts the credential and resumes signing. An issued session does not prove the file was written. If the command reported a write failure, the credential is missing, or the shard reports that the credential is fenced, run only `ubft signing-authority replace-session "${AUTH[@]}" --out "$UBFT_HOME/authority/client.cred"` to recover the credential. A timeout or an unavailable shard alone does not establish that the file is stale.

```bash
resume_authority_session() (
  set -eo pipefail
  ubft signing-authority status "${AUTH[@]}" |
    jq -e --arg root "$ACTIVATED_ROOT_EPOCH" --arg shard "$ACTIVATED_SHARD_EPOCH" '
      .enrollmentComplete and (.rootEpoch | tostring) == $root and
      (.shardEpoch | tostring) == $shard and (.sessionIssued == false) and
      (.retired == false) and (.faulted == false) and (.keyLost == false)
    ' >/dev/null
  ubft signing-authority replace-session "${AUTH[@]}" --out "$UBFT_HOME/authority/client.cred"
)
resume_authority_session
```

Wait for the local shard to activate the same root epoch. If the shard needs to reload its session, stop that shard process through its supervisor and restart it with the same `run` arguments. A registered identity or reserved result is still waiting to validate. Check that the successor handoff is acknowledged, the registry lists your membership, your root votes, your shard certifies with the authority, and local ureth tracks the public head.

**PoA special case.** Use the same setup and `validator apply` without the bond, withdrawal or P85 steps. The Foundation multisig admits the application after both governance delays. Wait for the candidate to include you and follow the same certified handoff, enrollment and session procedure. Ask the Foundation about a parked application or use `ubft validator rejoin` if still eligible.

## 5. Validate, monitor and upgrade

```bash
ubft validator status --custody "$CUSTODY"
ubft validator status --custody "$CUSTODY" --json --exit-code
ubft validator exporter --custody "$CUSTODY" --root-metrics http://127.0.0.1:25852/api/v1/metrics \
  --listen 127.0.0.1:9180 --disk-path "execution=$UBFT_HOME/ureth"
```

For PoA, omit `--custody`. In JSON, check `member`, `rootEpoch`, `health`, `sync`, `recordCursor` and `findings`. With `--exit-code`, 0 is OK, 1 warning, 2 critical and 3 unknown. An unavailable head may be null. Monitor the local root, shard, ureth and authority as well as the exporter. Import the [Grafana dashboard](../../deploy/testnet/monitoring/grafana-validator.json) and use the [metrics catalogue](monitoring/metrics-catalogue.md), [alert rules](../../deploy/testnet/monitoring/validator-alerts.yml), [event names](monitoring/events.md) and [runbooks](monitoring/runbooks.md).

With a VT-07 activation-capable release, check the schedule and the named release before the activation epoch. These commands require the VT-07 binary. Older release builds expose schedule observations in validator status and the exporter.

```bash
ubft validator upgrade --rpc "$RPC_URL"
ubft validator upgrade --rpc "$RPC_URL" --json --exit-code
```

Stage a verified, compatible release before the scheduled root epoch, and coordinate the restart of the affected services and authorities with the Foundation. An unsupported rule fences the component at activation. Follow the release instructions for the authority process and its in-memory key.

`validator status` reports previous and current base fee floor, change denominator and collector, and the effective EVM block. Fee changes come from certified registry state at the parent. Leave the startup collector at the release value. Watch the live fee and committee limit changes in `ubft governance list --rpc "$RPC_URL"` and verify the effective values through status.

### Upgrade to a hotfix release

Use the Foundation's authenticated announcement for your generation. It gives the affected component, hotfix URL, manifest SHA-256 and rollout window. Stage the binary under a distinct filename so the supervisor can still select the previous release. This example stages a root-only `ubft` hotfix.

```bash
read -rp 'Hotfix release URL: ' HOTFIX_URL
read -rp 'Hotfix SHA256SUMS digest: ' HOTFIX_MANIFEST_SHA
HOTFIX_BINARY="$UBFT_HOME/release/ubft-hotfix-$HOTFIX_MANIFEST_SHA"
stage_hotfix() (
  set -eo pipefail
  [[ "$HOTFIX_MANIFEST_SHA" =~ ^[0-9a-f]{64}$ ]]
  work=$(mktemp -d "$UBFT_HOME/release/.hotfix.XXXXXXXX")
  trap 'rm -r -- "$work"' EXIT
  curl -fsS "${HOTFIX_URL%/}/SHA256SUMS" -o "$work/SHA256SUMS"
  printf '%s  %s\n' "$HOTFIX_MANIFEST_SHA" "$work/SHA256SUMS" | sha256sum -c -
  curl -fsS "${HOTFIX_URL%/}/ubft" -o "$work/ubft"
  (cd "$work" && sha256sum -c SHA256SUMS)
  install -m 755 "$work/ubft" "$HOTFIX_BINARY"
  "$HOTFIX_BINARY" root-node run --help >/dev/null
)
stage_hotfix
```

After staging succeeds, use the service supervisor to stop the affected root and start it with `"$HOTFIX_BINARY" root-node run`, the existing `ROOT_ARGS` and the same home. Keep the shard, execution client and signing authority running, and keep the proof profile for this generation. Check that the root has caught up and is voting if it remains a committee member. If startup fails, contact the Foundation. Use a verified rollback release only if it enforces the current signing state, including any durable proposal fence and reservations. Keep the same root database and trust history. If a compatible executable is unavailable, keep the root signer stopped. [First adoption of durable root proposal signing](foundation-handbook.md#first-adoption-of-durable-root-proposal-signing)

An operator already excluded can complete the PoS exit using the public RPC and wallet after the incumbent roots produce the retirement record.

## 6. Exit and retire

```bash
ubft validator exit --dry-run
ubft validator exit
ubft validator status --custody "$CUSTODY" --json --exit-code
```

On PoS, exit requests custody retirement. Keep serving until the committee has excluded your identity through an acknowledged handoff. Wait for closure, the HolderRetirement record and custody's maturity gates. With the default withdrawal address, the operator account can then mature and claim. A different withdrawal address must claim its own credit through custody.

Custody also refuses `mature` with `TermAnchorPending` while a closed term of your lots has no report anchors ([D5 §2.1](../design/d5-accountability-retirement-inbox.md#21-post-term-seal-offence-1297)). Anyone can capture them with `custody.anchorTerm(assignmentID, hRecordID, terminalRoot)`, using the words of the term's Closure record. There is no keeper. `validator claim` first sends one `anchorTerm` for each such term, then matures and claims. If the dry run shows `SuccessorNotInstalled`, the successor epoch is not installed yet: run the claim again later. The floors then count from the anchor.

```bash
ubft validator claim --dry-run && ubft validator claim
```

The pinned pre-VT-07 CLI can print `the operator account has no credit to claim` and exit 1 after both transactions were included. It checks the now-empty credit again after the claim. Use the public receipts to confirm the outcome when your operator account is both the configured payee and the withdrawal address. Both receipts must have status `0x1` and name the release custody contract. The claim receipt must contain exactly one custody `CreditClaimed` event with the configured payee as both creditor and recipient and a nonzero amount. Compare its hexadecimal amount in base units with the intended withdrawal before treating the exit as complete.

```bash
read -rp 'Maturity transaction hash: ' MATURE_TX
read -rp 'Claim transaction hash: ' CLAIM_TX
check_exit_receipts() (
  set -o pipefail
  [[ "$MATURE_TX" =~ ^0x[0-9a-fA-F]{64}$ && "$CLAIM_TX" =~ ^0x[0-9a-fA-F]{64}$ ]] || return 1
  [[ "${MATURE_TX,,}" != "${CLAIM_TX,,}" ]] || return 1
  PAYEE=$(jq -er '.payee | select(test("^0x[0-9a-fA-F]{40}$"))' validator.json) || return 1
  for TX in "$MATURE_TX" "$CLAIM_TX"; do
    curl -fsS --max-time 10 -H 'Content-Type: application/json' \
      --data "$(jq -cn --arg tx "$TX" '{jsonrpc:"2.0",id:1,method:"eth_getTransactionReceipt",params:[$tx]}')" \
      "$RPC_URL" | jq -e --arg custody "$CUSTODY" --arg payee "$PAYEE" --arg tx "$TX" --arg claim "$CLAIM_TX" '
        ("0x" + ("0" * 24) + ($payee | ascii_downcase | ltrimstr("0x"))) as $payeeTopic |
        .result | select(.status == "0x1" and (.to | ascii_downcase) == ($custody | ascii_downcase)
          and (.transactionHash | ascii_downcase) == ($tx | ascii_downcase)) |
        [.logs[] | select((.address | ascii_downcase) == ($custody | ascii_downcase)
          and .topics[0] == "0xc4b5041307ee38be8c4f25df5d980a372ac8a9a73ea8f459891000a5386f5322")] as $events |
        if $tx == $claim then
          select(($events | length) == 1 and ($events[0].topics | length) == 3
            and ($events[0].topics[1] | ascii_downcase) == $payeeTopic
            and ($events[0].topics[2] | ascii_downcase) == $payeeTopic
            and ($events[0].data | test("^0x[0-9a-fA-F]{64}$") and test("[1-9a-fA-F]"))) |
          {transactionHash, blockNumber, status, from, to, creditClaimed: [
            $events[0] | {creditor: .topics[1], recipient: .topics[2], amountWord: .data}
          ]}
        else
          {transactionHash, blockNumber, status, from, to}
        end
      ' || return 1
  done
)
check_exit_receipts
```

On PoA, exit withdraws an unadmitted application or requests the exit of an active member. The Foundation confirms an active member's exit. Keep serving until the acknowledged boundary and `Exited` status. For Admitted, Joining or Parked PoA states, ask the Foundation for the appropriate removal.

### Check PoS retirement and maturity

The exit receipt confirms that custody recorded the request. The public `member` field stays true until the exclusion is acknowledged. The `--custody` flag adds the record cursor. To check retirement and election timing on this P85 release, read the public contract views below. They send no transactions.

```bash
pos_view() {
  local contract=$1 data=$2
  curl -fsS --max-time 10 -H 'Content-Type: application/json' \
    --data "$(jq -cn --arg to "$contract" --arg data "$data" \
      '{jsonrpc:"2.0",id:1,method:"eth_call",params:[{to:$to,data:$data},"latest"]}')" \
    "$RPC_URL" | jq -er '.result | select(type=="string" and startswith("0x")) | ltrimstr("0x")'
}
ID=$(jq -er '.id' validator.json)
ID_WORD=$(printf '%064x' "$ID")
# positions(uint64) returns nine fixed words, including generation and retirementRequested.
POSITION=$(pos_view "$CUSTODY" "0x60f3ce04$ID_WORD")
if [[ ${#POSITION} -eq 576 ]]; then
  GENERATION_WORD=${POSITION:256:64}
  printf 'retirement requested: %d\n' "0x${POSITION:512:64}"
  # liveExposures(uint64,uint64) counts remaining open liability exposures.
  EXPOSURES=$(pos_view "$CUSTODY" "0xf0011d97$ID_WORD$GENERATION_WORD")
  if [[ ${#EXPOSURES} -eq 64 ]]; then
    printf 'live liability exposures: %d\n' "0x$EXPOSURES"
  fi
  # retirements(uint64,uint64) returns imported, retirement progress and UC time.
  RETIREMENT=$(pos_view "$CUSTODY" "0xa09fe98c$ID_WORD$GENERATION_WORD")
  if [[ ${#RETIREMENT} -eq 192 ]]; then
    printf 'holder retirement imported: %d\n' "0x${RETIREMENT:0:64}"
  fi
fi
# thresholds() returns the next election's certified progress and time floors.
THRESHOLDS=$(pos_view "$ELECTION" 0xcda43b3a)
if [[ ${#THRESHOLDS} -eq 128 ]]; then
  printf 'election progress floor: %d, UC time floor: %d\n' \
    "0x${THRESHOLDS:0:64}" "0x${THRESHOLDS:64:64}"
fi
ubft validator status --custody "$CUSTODY" --sample 0
```

`retirement requested: 1` with `member: true` means the validator is still serving while exclusion is pending. The next election requires both floors. If no result is open after both floors, check for the next successful attempt.

1. **Exclusion.** After the acknowledged handoff, `validator status --json` shows `member: false` and your identity is absent from `committee`.
2. **Closure.** Wait for `live liability exposures: 0` for the retiring generation. Keep checking as custody applies the root records.
3. **HolderRetirement.** Wait for `holder retirement imported: 1`. This confirms custody processed the retirement record for that generation.
4. **Maturity.** Run `ubft validator claim --dry-run` to simulate the remaining record, time, progress and evidence gates. The preview describes the next transaction. Successful maturation creates the withdrawal credit.

The election floors above describe exclusion timing. HolderRetirement is ordered by an eligible root after closure, after the holder and SealRegistry catch up, and outside a handoff. A subsequent election gives no guarantee that the record has been ordered.

If custody still reports `0` after closure, compare the incumbent root target, SealRegistry count and the VR and custody cursors from the same point. A node still catching up can report an older root target. If the four counts have converged across several eligible EVM blocks, report the request transaction, identity, generation, acknowledged root epoch, zero-exposure reading and cursor values to the network maintainers. They can check for `exit.retirement.requested` and `exit.retirement.proof_ready` on incumbents and kind 8 in the SealRegistry. The original VT-13 rehearsal roots require the retirement hotfix. Preserve the confirmed request during recovery. After import, continue at the maturity dry-run. [Retirement issue](https://github.com/ristik/bft-core/issues/1242) · [Record catch-up runbook](vr-record-catch-up.md#what-to-monitor) · [Retirement events](monitoring/events.md)

If the maturity dry-run gives a generic revert, read the captured terms for each lot listed in the preview. Use the retirement view and `pos_view` from above. The progress floor is strict and the certified-time floor is inclusive. Compare both with the `clock` line in `validator status`. Custody also requires zero lot references, zero pending evidence holds and a complete root-record prefix with no pending assignment.

```bash
read -rp 'Lot ID from the maturity preview: ' MATURITY_LOT
if [[ "$MATURITY_LOT" =~ ^[0-9]+$ && ${#RETIREMENT} -eq 192 && ${RETIREMENT:63:1} == 1 ]]; then
  LOT_WORD=$(printf '%064x' "$((10#$MATURITY_LOT))")
  # lots(uint256) returns 13 fixed words, including the captured holds.
  LOT=$(pos_view "$CUSTODY" "0xf1648e84$LOT_WORD")
  if [[ ${#LOT} -eq 832 ]]; then
    ROUND_FLOOR=$((0x${RETIREMENT:64:64} + 0x${LOT:512:64}))
    TIME_FLOOR=$((0x${RETIREMENT:128:64} + 0x${LOT:576:64}))
    for FLOOR in "0x${LOT:640:64}" "0x${LOT:704:64}"; do
      if (( FLOOR > ROUND_FLOOR )); then ROUND_FLOOR=$((FLOOR)); fi
    done
    if (( 0x${LOT:768:64} > TIME_FLOOR )); then TIME_FLOOR=$((0x${LOT:768:64})); fi
    printf 'progress must be greater than %d; UC time must be at least %d; lot references: %d\n' \
      "$ROUND_FLOOR" "$TIME_FLOOR" "0x${LOT:448:64}"
  fi
fi
ubft validator status --custody "$CUSTODY" --sample 0 | grep '^clock'
```

## Missed admission

If the application has sent no registration, confirm a new window, stop only the pending authority using its saved `AUTHORITY_PID`, and start an authority for the confirmed successor using the existing registration policy and credentials. Write its node info to a fresh filename and select it with `validator init --force`. Keep the wallet, root key, shard peer identity and payee.

If PoS registration already committed, keep the authority running. While it runs and holds its key, change keys only with `validator rotate`: on the PoS adapter it sends `admitDelegation` of the new words at custody's current generation first, then `VR.proposeBinding` of the identical words, and a re-run resumes. `validator apply` on a bonded identity refuses a delegation that is not VR's current or staged binding and points to `rotate`. Rotate refuses a root-key change, and it refuses to replace a staged binding that an open election result froze. If the authority has already stopped, follow [Authority loss](#authority-loss): preserve the old volume and marker and run `recover`.

## Troubleshooting

- Seed verification or replay fails. Check the independent genesis pin, shard config, checkpoint epoch and archive reachability. See [Sync from a seed](sync-seed.md) and [restore trust pins](bootstrap-trust-pin.md).
- Local head stalls or the four record counts diverge. Start with [catch-up](vr-record-catch-up.md) and the [monitoring runbooks](monitoring/runbooks.md#unicityshardexecutioncatchup).
- An output expires, a module faults or a handoff stalls. Record the result ID, root epoch, timings and status JSON. See the [output expiry runbook](monitoring/runbooks.md#unicityoutputexpired), [module runbook](monitoring/runbooks.md#unicityvrmoduleunhealthy), and [handoff recovery](root-handoff-abort.md).
- A shard restart reports that `eth_getProof` exceeded the proof window. Check which [release proof profile](#choose-the-releases-execution-proof-profile) is active. Restart only ureth with the same datadir, peer key and the correct release flags. VT-07 also needs the requested historical state to exist on the private proof source. Wait for both listeners, then check restart admission's exact-parent witness request.
- The journal reports a certified candidate missing its resulting observation. Preserve the journal and logs and use the recovery release designated for the incident. Keep the signing authority, its enrolled key and its session state. While the shard stays unready, report root participation and shard certification separately. A PoS exit request uses the operator wallet and public RPC. Keep the root serving until the acknowledged exclusion.
- The signing authority is unavailable or faulted. Stop the signing client and follow the [authority runbook](monitoring/runbooks.md#unicityauthorityfaulted). Preserve all signing and node state. Never duplicate an active signing identity.

### Rehearsal recovery for an interrupted journal observation

A journal left with an incomplete local-proposal certificate association by a pre-#1240 build is refused by the loader. Use the documented incident recovery for your release or [re-sync from a verified seed](sync-seed.md).

For the pre-VT-07 rehearsal, the maintainer may publish a compatible shard recovery build for [the interrupted observation incident](https://github.com/ristik/bft-core/issues/1239). Keep the root and authority running. Use the existing shard journal, archive and ureth datadir. Make sure ureth uses the pre-VT-07 proof settings and passes its readiness check. In your rehearsal shell recreate `SHARD_ARGS` from Section 3 if you reconnected, and confirm the failed shard has exited. Obtain the recovery binary's SHA-256 from the maintainer in the operator log.

```bash
read -rp 'Journal recovery binary SHA-256: ' RECOVERY_SHA256
install_journal_recovery() (
  set -o pipefail
  [[ "$RECOVERY_SHA256" =~ ^[0-9a-fA-F]{64}$ ]] || return 1
  curl -fsS "${RELEASE_URL%/}/ubft-journal-recovery" -o release/ubft-journal-recovery.download || return 1
  printf '%s  %s\n' "$RECOVERY_SHA256" release/ubft-journal-recovery.download | sha256sum -c - || return 1
  install -m 755 release/ubft-journal-recovery.download release/ubft-journal-recovery || return 1
)
if install_journal_recovery; then
  "$UBFT_HOME/release/ubft-journal-recovery" shard-node run "${SHARD_ARGS[@]}" >>logs/shard.log 2>&1 &
  SHARD_PID=$!
else
  printf 'Journal recovery binary was not verified and installed.\n' >&2
  false
fi
```

Use local shard health, ureth catch-up and the authority's signing metrics to check that the recovered shard actually validates. Preserve the same data and report the first new error if startup or replay stops again.
