# Bridge recovery runbook (testnet package)

What an operator does when a part of the bridge fails on a testnet generation. It covers the bridge's services, not the network's: the package's own
procedures (pause, restart, backup and restore, reset) are in [the package README](../README.md), and this runbook uses them.

**Fake value.** The bridge moves test ether. A failure that loses locks or bridged tokens loses nothing of value, and the tester page says so. The
priority is the integrity of what still exists: the vault must never pay a lock twice, and nothing published may name a service that no longer serves
this generation.

## Roles

The package's roles ([README, "Monitoring, logs and incidents"](../README.md#monitoring-logs-and-incidents)), with what each does for the bridge:

| role | for the bridge |
| --- | --- |
| **network operator** | runs every procedure below: restarts, the replacement lock-proof endpoint, the redeploy after a reset, republishing `bridge/public/` |
| **incident owner** | owns a bridge incident from detection to the recorded decision: which procedure, why, and the checks that closed it |
| **release manager** | owns the bridge release manifest (`bridge/public/bridge-release.json`) and approves a reset that loses outstanding locks |
| **faucet operator** | funds testers; pauses faucet claims while the bridge is down, so testers do not lock into a bridge that cannot mint |

## What depends on what

```
 tester ── lock ──────────────► BridgeVault (EVM, every validator)        custody: the vault's own balance and books
   │                                  │
   ├── lock proof ◄── lock-proof endpoint ◄── one validator's archive + its ureth   (stateless: any validator's serves the same bytes)
   │
   ├── mint, transfers, burn ──► aggregator (partition 7) ◄── MongoDB             (state: every certified token state)
   │
   └── redeem, claim ──────────► BridgeVault                              (needs the return proof and the trust base: bridge/public/)
```

- **Lock-proof endpoint**: stateless; it reads one validator's certified-block archive and that validator's execution client. A replacement on any
  validator serves the same bytes.
- **Aggregator**: the only service that holds bridge state off chain. MongoDB has every certified state. The root checks only the aggregator's
  signature, not its SMT transitions (no `proof_type`, [README](../README.md)). So an aggregator running on lost or older state is not refused by the
  root.
- **Vault**: on chain, replicated by every validator. It pays each lock at most once, on its nonce's nullifier, whatever the aggregator certified.
  A rolled-back aggregator can therefore let a token be spent twice between testers, but it cannot get the vault to pay the same lock twice. The
  `negatives` and `custody` rehearsal stages show both halves.

## Checks after any procedure

Run them before reopening ingress or faucet claims. The incident owner records each result.

1. **Custody.** `rehearse_bridge.py --generation GEN --evidence DIR --stages custody` (on the host; `--cast PATH` when Foundry's `cast` is not on
   `PATH`). It is read-only and checks the vault's whole event log against
   its counters and balance:
   - each lock once, each credit once and for its lock's amount;
   - L, D and P equal to the events' sums;
   - the claimable credit summing to D − P;
   - the balance equal to L − P plus donations.

   A failure here is an incident of its own: escalate it to the release manager and do not reopen.
2. **Lock proofs.** `curl -s -o /dev/null -w '%{http_code}' 'http://127.0.0.1:8090/healthz'` gives 200. For a recent lock, `GET /v1/lockproof?block=…&nonce=…` gives 200.
3. **Published files.** `bridge/public/tester-config.json` and `bridge-release.json` name this generation: its chain ID, genesis hash, vault and endpoints.
4. **One round trip**, when the aggregator or the vault was involved. Use the tester CLI from `bridge/public/`, or the rehearsal's `roundtrip` stage
   on a rehearsal generation.

## Procedures

### 1. The lock-proof endpoint is down, or its validator's archive is unavailable

Symptom: `/healthz` fails, or the endpoint answers 502 (its execution client failed). Testers cannot mint.

The network operator starts a replacement on another validator's archive and execution client (`N`). `overlay.py` rewrites the overlay, and Compose
replaces the one service:

```sh
python3 deploy/testnet/bridge/overlay.py /srv/testnet/GEN --archive-of N
cd /srv/testnet/GEN && docker compose -f compose.yaml -f compose.bridge.yaml up -d --no-deps --force-recreate lockproof
```

The endpoint holds no state, so nothing else changes and nothing is republished: testers keep the same URL. The `lockproof` rehearsal stage replaces it
this way and checks that the new one serves byte-identical proofs.

**Not recoverable:** a lock older than the proof window (64 blocks, `limits.proofWindowBlocks` in the manifest) whose tester never fetched its proof.
The endpoint answers 404 and the ether stays in the vault, by design: it is disclosed on the tester page. Record the count. Nothing is to be done.

### 2. The public RPC (gateway) is down

Symptom: the gateway's `/healthz` fails. Locks, redemptions and claims cannot be sent from outside. The bridge's own services keep working, because
they use the validators' execution clients on the internal network.

Follow the package's procedure for the gateway and its validators ([README](../README.md)). No bridge step is needed. A redemption larger than the
gateway's body bound (`limits.gatewayMaxBodyBytes`; a return proof is 16–26 KB as hex) never fits the gateway. It goes to `redeemEthUrl` when the
deployment has one. Until it does, testers cannot redeem from outside: that is an open owner decision, not a failure.

### 3. The aggregator stops or restarts

Symptom: the aggregator's `/health` (port 8080 in validator 1's namespace) fails, or mints and transfers time out.

When MongoDB and its data are intact, the network operator restarts the service:

```sh
cd /srv/testnet/GEN && docker compose restart aggregator
```

The aggregator resumes from MongoDB, and tokens keep their certified history. A tester whose request was in flight when it stopped sends it again.

### 4. The aggregator's state is lost (MongoDB data, or the aggregator's key)

Symptom: MongoDB will not start on its data, or `aggregator/keys.json` is gone.

**There is no in-place recovery that keeps the bridged tokens.**
- An empty or older MongoDB would let the aggregator certify spends of states it has forgotten, and the root does not check its SMT transitions.
- A new aggregator key is a new partition configuration.

So the incident owner stops the faucet and ingress and records the custody check (above). The release manager then decides between:
- **The same-generation restore**, when a quiesced backup exists and nothing has been signed since it ([README, "Quiesced backup and same-generation
  restore"](../README.md#quiesced-backup-and-same-generation-restore)). The backup holds MongoDB, the aggregator's key and `GENERATION/bridge/`. The restore
  refuses advanced authority state, so in practice this fits only a failure right after a backup. After it, restart the lock-proof endpoint
  (`up -d lockproof` as above) and run the checks. The `backup-restore` rehearsal stage does exactly this, then:
  - finds the redeemed lock still spent;
  - finds every replay still refused;
  - completes a new round trip.
- **The asset-losing reset** (procedure 5), otherwise.

### 5. A reset with outstanding locks

A reset ([README, "ASSET-LOSING arbitrary reset"](../README.md#asset-losing-arbitrary-reset)) deletes the generation. Every lock still in the vault and
every bridged token is lost with it, by design and as disclosed. Nothing carries over and nothing is compatible with the new generation.

1. **Release manager:** approves the reset.
2. **Incident owner:** keeps the old generation's record before it is deleted:
   - the custody check's `custody.json`: how many locks were outstanding, L − P;
   - `bridge/public/bridge-release.json`;
   - `bridge/bridge-addresses.json`.
3. **Network operator:** stops publishing the old `bridge/public/`, runs `reset.py`, starts the new generation, then deploys the bridge on it:
   ```sh
   # only when bridge/pins.json changed: rebuild the tools image ("Operator steps" in README.md)
   python3 deploy/testnet/bridge/build-bridge-image.py --contracts-source /srv/src/contracts-pinned --nbp-source /srv/src/nbp-pinned
   python3 deploy/testnet/bridge/deploy_bridge.py /srv/testnet/NEWGEN --agg-conf network/aggregator-conf.json --agg-url http://aggregator:8080 \
       --tester-eth-url https://… --tester-agg-url https://… --tester-lockproof-url https://…
   python3 deploy/testnet/bridge/overlay.py /srv/testnet/NEWGEN
   cd /srv/testnet/NEWGEN && docker compose -f compose.yaml -f compose.bridge.yaml up -d --no-deps lockproof
   ```
4. **Network operator:** points the nginx `location /bridge/` alias at the new `bridge/public/`. The new `bridge-release.json` names the new
   generation, genesis and vault. The announcement of the reset (the package's reset procedure) tells testers to start a new wallet from the new
   `tester-config.json`. An old wallet names the old vault, which has no code on the new chain. The tester CLI does not check that yet, so a lock
   sent from an old wallet is lost: test ether, but say it.
5. **Faucet operator:** reopens claims after the checks.

### 6. A validator stops during a redemption or a claim

No bridge action. The transaction is mined by the others, and the validator rejoins with the same blocks. The `roundtrip` rehearsal stage redeems
and claims with one validator stopped and checks this.

## Not covered

- A second operator's recovery of the bridge-enabled package (#428/#429).
- Root key rotation: the bridge job has no root handoff.
- Public routes to the aggregator and for redemptions: open owner decisions ([README, "The bridge tester"](README.md#the-bridge-tester)).
