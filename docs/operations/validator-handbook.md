# Validator handbook

This guide operates one validator on a Validator Registry (VR) proof-of-stake generation with the P85 prototype contracts. One validator runs a root node, an EVM shard node, ureth for execution, and a signing authority for the shard's certification key. The Foundation publishes the network release and endpoints. Use its authenticated release announcement to obtain the release digest and the UTB genesis EntryID.

## Rehearsal shell

For VT-13, use the dedicated `vt13operator` account on the rehearsal host. Generate a new SSH key on your workstation and submit **only the public key** in `briefs/vt13-operator-log.md` for the rehearsal maintainer to install. Use the host address from the public RPC URL in the rehearsal inputs.

```bash
install -d -m 700 "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/vt13-operator" -C vt13-operator
cat "$HOME/.ssh/vt13-operator.pub"
```

After the maintainer confirms the key is installed, check the server's SSH host fingerprint at the connection prompt. The rehearsal host's ECDSA fingerprint is `SHA256:Q9TuHHqEgdBwZrhgFitNfo1RaOhpOtg9uuIxtCo0X2A`. Connect using the new key and do the remaining steps in that shell.

```bash
ssh -o IdentitiesOnly=yes -o HostKeyAlgorithms=ecdsa-sha2-nistp256 \
  -i "$HOME/.ssh/vt13-operator" vt13operator@212.23.222.159
```

## 1. Install the release

Use a dedicated Linux service account, a synchronized clock and persistent SSD storage. Allow inbound root and shard libp2p TCP and the release's ureth devp2p ports. Use outbound access to the public RPC, seed and peers. Keep operator RPC, metrics, Engine API and signing sockets on loopback or a private admin network. Archive replay needs the local ureth debug API for header witnesses. The reference host has 6 CPU cores / 12 threads, 64 GB RAM and two 1 TB NVMe drives. Size for your release and retention policy, and check `validator doctor`.

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
tar -czf - root/keys.json evm/keys.json ureth-key/p2p-secret operator/key validator.json | \
  gpg --symmetric --cipher-algo AES256 --output "$BACKUP"
gpg --decrypt "$BACKUP" | tar -tzf -
```

The second command lists the encrypted archive's entries without writing a decrypted archive. Keep the JWT and authority credentials private. Start only one instance per identity. Always pass the same `--p2p-secret-key` to ureth so its enode survives a datadir rebuild.

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

If the initial shard restore exited at the Engine dial with connection refused, leave the healthy root running. After ureth's readiness check succeeds, repeat just `shard-node restore` when the journal and archive are still fresh. If restore already wrote replay state, preserve it and inspect the error before choosing a recovery procedure.

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

Once the result is published, the roots derive the intent and the nodes collect readiness. Watch for Prepare, Freeze, the committed handoff and activation. Wait for your own root to install the first activated epoch that names you. Read its certified configuration and trust base over its loopback operator RPC. Use the exact root and shard epochs from that activation.

```bash
read -rp 'Activated root epoch: ' ACTIVATED_ROOT_EPOCH
read -rp 'Activated shard epoch: ' ACTIVATED_SHARD_EPOCH
ubft q3 shard-conf --root-rpc http://127.0.0.1:25852 --epoch "$ACTIVATED_SHARD_EPOCH" --out activated-shard-conf.json
ubft q3 trust-base --root-rpc http://127.0.0.1:25852 --epoch "$ACTIVATED_ROOT_EPOCH" --out activated-trust-base.json
ubft signing-authority complete-enrollment "${AUTH[@]}" --shard-conf activated-shard-conf.json
ubft signing-authority advance-epoch "${AUTH[@]}" --shard-conf activated-shard-conf.json --trust-base activated-trust-base.json
ubft signing-authority replace-session "${AUTH[@]}" --out "$UBFT_HOME/authority/client.cred"
```

This initial enrollment uses the configuration verified by your paired root. At each later handoff, repeat the advance and session steps with the new verified files. Complete enrollment only once. For an authority already equipped with a lineage pin and an installed configuration, use `signing-authority advance-with-proof` and the verified activation bundles in epoch order. Keep its certification session private.

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

## 6. Exit and retire

```bash
ubft validator exit --dry-run
ubft validator exit
ubft validator status --custody "$CUSTODY" --json --exit-code
```

On PoS, exit requests custody retirement. Keep serving until the committee has excluded your identity through an acknowledged handoff. Wait for closure, the HolderRetirement record and custody's maturity gates. With the default withdrawal address, the operator account can then mature and claim. A different withdrawal address must claim its own credit through custody.

```bash
ubft validator claim
```

On PoA, exit withdraws an unadmitted application or requests the exit of an active member. The Foundation confirms an active member's exit. Keep serving until the acknowledged boundary and `Exited` status. For Admitted, Joining or Parked PoA states, ask the Foundation for the appropriate removal.

## Missed admission

If the application has sent no registration, confirm a new window, stop only the pending authority using its saved `AUTHORITY_PID`, and start an authority for the confirmed successor using the existing registration policy and credentials. Write its node info to a fresh filename and select it with `validator init --force`. Keep the wallet, root key, shard peer identity and payee.

If registration already committed, changing a pending authority loses the key the registry knows. Ask the Foundation to confirm that your identity is outside the active committee and that no open result can install the previous binding. Keep the current authority running until that is confirmed. Keep the same owner, identity, bond, root key and peer identity. Provision the replacement authority for the new confirmed epoch in a separate directory. Its registration policy must authorize the same owner, root key and payee with `action: "binding"` and the existing VR identity as `id`. Set `REPLACEMENT_AUTH` to that authority's directory with its own operator socket, credential and node info. Stage its binding and then resume the PoS application for the same identity.

```bash
ID=$(jq -er '.id' validator.json)
ubft validator rotate --id "$ID" --new-evm-authority-socket "$REPLACEMENT_AUTH/operator.sock" \
  --new-evm-authority-credential "$REPLACEMENT_AUTH/operator.cred" \
  --new-evm-node-info "$REPLACEMENT_AUTH/node-info.json"
ubft validator init --force --id "$ID" --rpc "$RPC_URL" --chain-id "$CHAIN_ID" --ports 26652,28152,30303 \
  --evm-authority-socket "$REPLACEMENT_AUTH/operator.sock" \
  --evm-authority-credential "$REPLACEMENT_AUTH/operator.cred" \
  --evm-authority-node-info "$REPLACEMENT_AUTH/node-info.json"
ubft validator apply
```

Use the replacement authority's sockets and credentials in the node commands, and pin its updated P85 policy to the same identity. Stop and coordinate with the Foundation if either the staged binding or delegation is refused.

## Troubleshooting

- Seed verification or replay fails. Check the independent genesis pin, shard config, checkpoint epoch and archive reachability. See [Sync from a seed](sync-seed.md) and [restore trust pins](bootstrap-trust-pin.md).
- Local head stalls or the four record counts diverge. Start with [catch-up](vr-record-catch-up.md) and the [monitoring runbooks](monitoring/runbooks.md#unicityshardexecutioncatchup).
- An output expires, a module faults or a handoff stalls. Record the result ID, root epoch, timings and status JSON. See the [output expiry runbook](monitoring/runbooks.md#unicityoutputexpired), [module runbook](monitoring/runbooks.md#unicityvrmoduleunhealthy), and [handoff recovery](root-handoff-abort.md).
- A shard restart reports that `eth_getProof` exceeded the proof window. Check which [release proof profile](#choose-the-releases-execution-proof-profile) is active. Restart only ureth with the same datadir, peer key and the correct release flags. VT-07 also needs the requested historical state to exist on the private proof source. Wait for both listeners, then check restart admission's exact-parent witness request.
- The journal reports a certified candidate missing its resulting observation. Preserve the journal and logs and use the recovery release designated for the incident. Keep the signing authority, its enrolled key and its session state. While the shard stays unready, report root participation and shard certification separately. A PoS exit request uses the operator wallet and public RPC. Keep the root serving until the acknowledged exclusion.
- The signing authority is unavailable or faulted. Stop the signing client and follow the [authority runbook](monitoring/runbooks.md#unicityauthorityfaulted). Preserve all signing and node state. Never duplicate an active signing identity.

### Rehearsal recovery for an interrupted journal observation

For the pre-VT-07 rehearsal, the maintainer may publish a compatible shard recovery build for [the interrupted observation incident](https://github.com/ristik/bft-core/issues/1239). Keep the root and authority running. Use the existing shard journal, archive and ureth datadir. Make sure ureth uses the pre-VT-07 proof settings and passes its readiness check. In your rehearsal shell recreate `SHARD_ARGS` from Section 3 if you reconnected, and confirm the failed shard has exited. Obtain the recovery binary's SHA-256 from the maintainer in the operator log.

```bash
read -rp 'Journal recovery binary SHA-256: ' RECOVERY_SHA256
install_journal_recovery() (
  set -eo pipefail
  curl -fsS "${RELEASE_URL%/}/ubft-journal-recovery" -o release/ubft-journal-recovery.download
  printf '%s  %s\n' "$RECOVERY_SHA256" release/ubft-journal-recovery.download | sha256sum -c -
  install -m 755 release/ubft-journal-recovery.download release/ubft-journal-recovery
)
install_journal_recovery &&
  "$UBFT_HOME/release/ubft-journal-recovery" shard-node run "${SHARD_ARGS[@]}" >>logs/shard.log 2>&1 &
SHARD_PID=$!
```

Use local shard health, ureth catch-up and the authority's signing metrics to check that the recovered shard actually validates. Preserve the same data and report the first new error if startup or replay stops again.
