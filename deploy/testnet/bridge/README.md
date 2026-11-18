# The bridge on the testnet package

**Native bridge v2 (NB2, #1096) is the bridge the lanes deploy and test** (NB2-09, #1105): `nb2/`, below. Spec:
`docs/design/native-bridge-v2.md`. The protocol 6/7 files further down (TN-B #429/#438: `deploy_bridge.py`'s BridgeVault, the lock-proof
endpoint, the tester, `rehearse_bridge.py`'s stages, `bridge_pos.py`, `bridge_load.py`) are no longer run by any lane; NB2-10 (#1106) removes
them. The lock-proof service is not part of the v2 package: a v2 wallet fetches every piece of evidence from the ordinary node RPC behind the
public gateway (spec section 12.7).

## Native bridge v2 (`nb2/`)

| file | what it does |
|---|---|
| `nb2/deploy_nb2.py` | an operator action on a running generation: the trust-base bundle and its pin (`dnb-tool trust-bundle`), the verifier (`NativeBridgeVerifierV2`, which creates its receipt helper), Γ by the Go reference (`nb2-evidence gamma`) for the vault's predicted address, and the vault with exactly those bytes, all from the tools image's contracts build output (`cast send --create`, signed with the faucet keystore). It deploys the test build (K = 4, B = 2) and the production build (64, 16) beside it, reads `config()` and `domain()` back, and writes `GENERATION/bridge/nb2/` |
| `nb2/release_nb2.py` | the release manifest `GENERATION/bridge/nb2/public/nb2-release.json` (below) |
| `nb2/driver.ts` | the live driver: the TypeScript wallet plug-in (native-bridge-plugins `packages/native-bridge-plugin/src/nb2`, NB2-07) through the public gateway only. It runs in the bridge tools image with this directory mounted read-only at `tests/live/nb2lane/` of the image's plug-in checkout |
| `nb2/rehearse_nb2.py` | the lane stages (below) |
| `nb2/lane_open.ts` | how every driver command opens its wallet: no installation check unless asked, and no wallet lock, since a `docker kill`ed command's lock would block every later command on that wallet (`lane_open.test.ts`) |

The wallet is the reference command-line wallet of native-bridge-plugins (`wallet/nb2-wallet.ts` on `wallet/core.ts`, bft-core#1107), and the wallet
integration guide is native-bridge-plugins
[`docs/nb2-wallet-guide.md`](https://github.com/ristik/native-bridge-plugins/blob/main/docs/nb2-wallet-guide.md). The driver's deposit, mint,
transfer, split, burn and redeem are that wallet's core functions on that wallet's directory layout, so there is one wallet implementation; the
driver adds the lane's measurements, mutations and fault injection. The `walkthrough` stage runs the command-line wallet itself, exactly as the
guide does, and keeps its transcript (`nb2/walkthrough.txt` in the evidence).

```
python3 deploy/testnet/bridge/build-bridge-image.py --bft-source <bft at deploy/testnet/pins.json> --contracts-source <contracts at pin> --nbp-source <plug-ins at pin>
go build -o /tmp/nb2-evidence ./scripts/nb2-evidence
# generation up as in ../README.md, then:
sudo python3 deploy/testnet/bridge/nb2/deploy_nb2.py /srv/<generation> --nb2-evidence /tmp/nb2-evidence [--k 4 --b 2 | --k 64 --b 16 --no-production]
```

Publish `GENERATION/bridge/nb2/public/` (the manifest, the trust bundle and its pin) and nothing else. `GENERATION/bridge/nb2/driver.env` holds the lane's
keys while a run lasts (`rehearse_nb2.py` deletes it at the end unless `--keep-keys`). The manifest checks every validator's execution client
(ureth1..N): each must be a full proof source with the same pool byte and gas pins, or the deploy refuses.

### The release manifest

`nb2-release.json` holds no secret. Each value is read from where it is in force:

| part | contents | read from |
| --- | --- | --- |
| `pins` | spec section 4.3, as a wallet's `DeploymentPins`: `gamma`, `build`, `vaultRuntimeCodeHash`, `maxEncodedTxBytes`, `userGasLimit`, `gasReserve` 500,000, `returnReserveSegments` 64, `deploymentBlock` (the vault's creation block, from which wallets read logs), `stateReadOnly` false, `nativeGasSchedule` (the native gas schedules the plug-ins' default gas estimate assumes, `release_nb2.py` `NATIVE_GAS_SCHEDULE` from the pinned ureth; without it the default estimate does not apply) | the deployment and the limits below |
| `deployment` | per build: Γ and D, K, B, Qmax; the vault's, the verifier's and the receipt helper's address, creation transaction, block and code hash | the creation receipts and the chain |
| `profile` | the semantic profile hash (in Γ), the vectors digest, the B1 profile's sha256 | the image's plug-in checkout; `network/b1-profile.json` |
| `trust` | the bundle's file and its genesis EntryID (Γ.rootGenesis32); where newer entries come from | `dnb-tool trust-bundle` |
| `limits` | `maxEncodedTxBytes` (L_max) 512 KiB, the wallets' limit; the path's own limits: each pool's `--txpool.max-tx-input-bytes` (4 MiB) and `--txpool.max-tx-gas` (the ordinary capacity), the gateway's largest carried transaction; `userGasLimit` and the block gas limit, the gateway's bodies, log window and answer cap, retention, how transactions and blocks travel | `release_nb2.py` `L_MAX`; `compose.yaml` (the B1 profile's ureth flags, `ubft engine-api b1-profile`), `network/b1-profile.json` (`ordinaryCapacity`, `maxGas`), `gateway.py`. The manifest refuses a validator that is not a full proof source, a pool below L_max or without the profile's gas cap, or a gateway bound below 2 L_max + 64 KiB |
| `envelope` | the operating envelope: per split depth, the largest transfer history whose return passes the pre-burn preflight at `returnReserveSegments` (the burn counted at the decoder bounds, about 3.4M gas), the historical proofs that fit beside it by bytes and by gas, and for the reference part the return delay at 1, 10 and 100 payments a second | `driver.ts envelope`: the plug-in's gas estimate (`MeasuredGasModel`, estimate-nb2-1179, a measured conservative estimate with a safety margin, native-bridge-plugins `docs/nb2-gas-model.md`) on parts built from the lane's template (`nb2/envelope_template.cbor`, `nb2/envelope_shape.ts`) over the pins |

The pools admit more than L_max (4 MiB, set by the B1 profile for the protocol 6/7 envelope), so L_max binds in the wallet's preflight, not in a
pool. Gas binds first on this deployment, before bytes: at `userGasLimit` 60M the largest admitted unsplit history is about 270 transfers in
16 certificate groups (in the bft-core#1179 round-2 dev-server run, on the estimate with its walks per item form, its vault for a fresh recipient
and its safety margin, 268 admitted and 270 refused on a fresh tree; about 430 KB of evidence), and L_max binds at about 310. The `boundary` stage locates
the bound on live tokens within two transfers and executes every token it builds as the preflight judged it (a refusal is sound over
`userGasLimit` by its own gas or over L_max by bytes; fresh tokens' gas varies by about one transfer's step between builds, so an exact adjacent pair
is not observable live).

### The rehearsal stages

`nb2/rehearse_nb2.py` runs on a generation that `rehearse.py --stages up,identity` brought up (`.github/workflows/testnet-bridge.yml`; the PoS lane
runs `deploy,fund,pos-deposit` before the handoff and `pos-return,custody` after it, `.github/workflows/testnet-bridge-pos.yml`). Each stage's
expectations and outputs are in the script's docstring; the outputs (`out/*.json`) and the three-way verdict tables are kept in the evidence.

| stage | what it checks |
|---|---|
| `deploy` | both builds deployed and readable through the gateway; the manifest against the chain (code hashes, creation blocks, `config()` is Γ); Go decodes Γ to the deployed fields; the plug-in's installation check (`NativeBridgeV2.open`: chain ID, `config()`, runtime code hash); the companion horizon is null; each verifier build refuses the other's Γ (ConfigShape) and each vault build's constructor the other's K (BadConfig(16)) |
| `limits` | a transaction of exactly L_max encoded bytes accepted by the gateway, included, and its block held by every validator; one byte over the pools' own limit refused by every validator; the gateway's large-body bound (above it refused on the declared length, unread: 400); a transaction at `userGasLimit` included and one gas above it refused at admission |
| `fund` | the driver keys (`nb2/driver.env`, mode 0600) funded from the faucet. They reach the driver only through its environment file, never a command line, and are redacted from every console line, log and result. The run deletes them at its end, on success and on failure; `--keep-keys` hands them to the next invocation (the PoS lane's first one), and the last invocation deletes them |
| `circulate` | deposit 100 (EIP-1559), mint, transfer, split 60 + 40, split 40 into 15 + 25, transfer; an origin-only token from a legacy deposit; a one-transfer token; three nested split levels; tokens with 16 and 17 certificate claims; a long history (one aggregator batch) |
| `returns` | the 60, 15 and 25 returned with their own indices while a second key's small returns rotate the K = 4 segments: exactly 100 paid; each part's replay refused while in the recent buffers (AlreadyPaid, the wallet reconciles without a send) and after eviction (the wallet finds it in a sealed segment; the old calldata, a zero history and a forged gap proof refused); a witness made stale by two rotations refused (StaleEndpoint) and paid after refresh; a too-low gas limit reverted with the vault unchanged, then paid; a return whose broadcast the gateway calls partial (HTTP 503, #1121: the transaction already in one pool) found by receipt polling, with one send |
| `evidence` | `scripts/nb2-evidence/stage.sh` against the real vault: the deposit receipt proof and the newest seal receipt through the gateway, verified by nb2ref |
| `verifier` | on every burned part (origin only with a legacy receipt, one transfer, one and two split levels, three nested levels, 16 and 17 claims, the long history): the deployed verifier's 192-byte verdict equals the plug-in's and Go's; isolated mutations (each certificate's seal signature in check order, two other UC bytes, an RSMT sibling and bitmap, the unlock recovery IDs 2 and 3 and a signature byte, a non-minimal evidence version, trailing and missing bytes) are refused, with the same rule from all three; fault injection by `eth_simulateV1` on validator 1 (0x0100 and 0x0102 missing, reverting, false, short; the helper's code replaced or removed) |
| `gas` | the real gas of every paid return beside its preflight limit, and the refusals' gas |
| `boundary` | soundness, every token the stage builds: each one the wallet's preflight admits is burned and paid within `userGasLimit`, each one it refuses is over the limit by the preflight's own gas, refused again (CapacityPreflight: the documented capacity limit, not a recovery) and unspent by the ledger afterwards (the aggregator's non-inclusion proof of its state, verified against the trust base); location: among the newest three probes the highest admitted and the lowest refused lengths are at most 2 transfers apart (the margin, from the measured gas noise between fresh tokens). Each probe's shape diagnostics and the gas drift are recorded, not judged |
| `cold` | a burned part redeemed by a wallet whose derived caches (trust history, held witnesses) were deleted; journal, token and burn kept |
| `walkthrough` | the wallet guide's walk-through with the reference command-line wallet (native-bridge-plugins `wallet/nb2-wallet.ts`) in the tools image, its key `NB2_KEY_WALK` from the driver keys: `init` (the installation check), `address`, `deposit coin 0.1`, `mint coin`, `split coin keep=0.06 back=0.04`, `status`, `plan-return back`, `burn back`, `redeem back` twice (the second answers paid with the same transaction, one send), `status`, `tokens` (only the unspent part); the transcript is `nb2/walkthrough.txt`. Whether `redeem` waited out the seal registry's lag (#1125) is recorded (`nb2/walkthrough-lag.json`; the driver's redeems record it as `registryLagSeconds`) |
| `custody` | from the vault's events: each deposit number once, each redemption paid once, Q = deposits − payouts = `state().outstanding`, balance ≥ Q, segments sealed once each in order, and Go reads the whole segment history |
| `pos-deposit`, `pos-return` | PoS lane: a deposit, mint and transfer in epoch 1; after the epoch change a transfer, a split, the burn, the three verdicts under the wallet's extended trust history, and the redeem |

## Protocol 6/7 (not run by the lanes; removed by NB2-10, #1106)

### Files

| file | what it does |
|---|---|
| `pins.json` | the bridge release's inputs: contracts and native-bridge-plugins commits, plus the Node, Go and Foundry images or releases by digest or sha256 |
| `Dockerfile.tools`, `build-bridge-image.py` | `tnops-bridge:<bft12>-<id12>` (an immutable tag per pin and image, #1092; every consumer runs the image by the ID in `artifacts/bridge-images.json`, and `:verified` is only a human alias): forge/cast, the built contracts, the plug-in driver, and dnb-tool built from the node images' bft pin (`--bft-source`, deploy/testnet/pins.json; `overlay.py` refuses an image recorded for another pin, #1075). The build refuses a source that is not at its pin or not clean, and records the image ID in `../artifacts/bridge-images.json`. |
| `deploy_bridge.py` | an operator action on a running generation: the deployment document (`dnb-tool deployment`), then `BridgeDeploy.s.sol` signed with the generation's faucet keystore. The script refuses a vault whose genesis identities differ from the chain's. It also reads the vault's CFG and writes the trust bundle, the PDR, the driver configuration and the release manifest. Everything goes under `GENERATION/bridge/`. |
| `release.py` | the bridge release manifest, `GENERATION/bridge/public/bridge-release.json` (below) |
| `overlay.py` | `GENERATION/compose.bridge.yaml`, the Compose overlay with the bridge's services |
| `RECOVERY.md` | the operator's bridge recovery runbook: roles, what depends on what, the checks after any procedure, and each failure's procedure |
| `rehearse_bridge.py` | the bridge stages of the runner rehearsal (`.github/workflows/testnet-bridge.yml`) |
| `bridge_load.py` | sustained bridge load for the host's measured envelope: parallel testers looping the round trip, sampling this generation's containers and disk (its docstring) |

### Operator steps

```
python3 deploy/testnet/bridge/build-bridge-image.py --bft-source <bft at deploy/testnet/pins.json> --contracts-source <contracts at pin> --nbp-source <native-bridge-plugins at pin>
# generation up as in ../README.md, then:
sudo python3 deploy/testnet/bridge/deploy_bridge.py /srv/<generation> --agg-conf <aggregator shard conf(s)> --agg-url <aggregator URL(s)>
sudo python3 deploy/testnet/bridge/overlay.py /srv/<generation>
cd /srv/<generation> && sudo docker compose -f compose.yaml -f compose.bridge.yaml up -d lockproof
```

### The lock-proof endpoint

A tester who locks on the EVM needs the lock's proof to mint. `dnb-tool lockproof-serve` builds that proof from the block's certificate in one validator's
archive and from that validator's `eth_getProof`. It serves the same bytes as `dnb-tool lockproof`.

```
GET /v1/lockproof?block=0x<block hash>&nonce=<lock nonce>   200 application/cbor | 400 malformed | 404 not (yet) available | 429 limited or busy | 502
GET /healthz
```

- **Stateless and read-only.** The archive is mounted read-only, and the only upstream call is one `eth_getProof`. A lookup costs the same whatever
  the archive's size: a record's directory is named by its Context and block hash, so the endpoint keeps only the archive's few Contexts and an 8-byte key
  per directory it has read. Those are a locator and never evidence. It learns new Contexts (a new epoch) by reading only directories it has not seen,
  at most once per 10 s and shared by concurrent requests. The one full read happens at start. Replacing the endpoint means starting it again on the same
  archive or on another validator's (`overlay.py --archive-of N`). The rehearsal checks that the replacement serves byte-identical proofs.
- **Rate limited.** Each client (an IPv6 client is its /64) gets 2 requests per second, with 20 per second in total, spent only by admitted requests, and 4 builds at a time. The host's nginx publishes it like the RPC gateway: 127.0.0.1:8090 inside,
  and the client named by `X-Forwarded-For` only when the request comes from the trusted proxy 172.30.89.1.
- **Fetch soon after locking.** The proof needs `eth_getProof` at the lock's block, and ureth serves that only within its proof window, which is
  `--rpc.eth-proof-window 64` blocks in `generate.py`. Past the window the endpoint answers 404. A fetched proof verifies forever (any-age), so the tester flow is:
  lock, fetch the proof, keep it.
- No prover and no service state, per owner §36 and the orchestrator's 2026-10-22 decision.

### The bridge tester

The protocol 7 tester (its CLI and its page) is removed: the native bridge v2 reference wallet replaces it (`nb2/`, above). `deploy_bridge.py`
still writes `GENERATION/bridge/public/`, the one directory to publish for testers. It holds `tester-config.json` and the four public
files that config names: the trust-base bundle, its genesis entry id, the EVM shard's PDR and the deployment document. Publish nothing else from
`GENERATION/bridge`: it also holds the driver's key (`driver.env`) and the rehearsal's wallets. The config names the endpoints a tester reaches. Set them with
`--tester-eth-url`, `--tester-redeem-eth-url`, `--tester-agg-url` and `--tester-lockproof-url`. The defaults are the package's public gateway as the
internal network names it (`http://rpc:8545` and its `/aggregator` route; no `redeemEthUrl`, since the gateway takes redemptions) and the lock-proof endpoint's
internal name; on a host, pass their public names. A host nginx `location /bridge/ { alias /srv/<generation>/bridge/public/; }` on the faucet's or the RPC's hostname serves it.

The public routes (orchestrator decision 2026-10-24): the gateway serves the aggregator on `POST /aggregator` (the state-transition SDK's JSON-RPC methods
only, 64 KiB bodies, its own limit of 10 requests a second per address and 50 overall, no authentication) and its trust-base pages on
`GET /api/v1/trustbases`, and takes redemptions as ordinary `eth_sendRawTransaction` bodies. The host nginx routes the three paths (`../nginx.conf.example`).
Still needed before external testers run the whole round trip on a host: the lock-proof endpoint's public name (a host nginx location in front of
`127.0.0.1:8090`), and the host's DNS and TLS.
