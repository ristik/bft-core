# The bridge on the testnet package (TN-B)

TN-B (#429), with B-TEST (#438) as its prerequisite, puts fake-value bridging on the public PoA testnet. This directory adds the bridge to the container package in
`deploy/testnet` without changing the package's own services. The plan, and the items that do or don't need the host, are in `briefs/tnb-without-host.md`.

Status: **part 3** (the tester). Part 1 is the bridge tools image, the post-genesis deploy and the lock-proof endpoint. Part 2 adds the bridge's round trip on the package's one
aggregator (aggregator-go on partition 7, one shard: owner decision 40): lock, mint, transfers, burn, redeem and claim, driven by native-bridge-plugins' live
driver (`tests/live/anyage.ts`) in the bridge tools image, plus the consolidated and long-history redeems, on-chain negatives and a backup and restore with the
bridge deployed. Part 3 adds the bridge tester (native-bridge-plugins `tester/`), its page and the published directory, below. Not covered here: a reset with
outstanding locks, retired-key forged histories, the proof refresh across rotations, and the public routes to the aggregator and for redemptions
(`briefs/tnb-without-host.md`).

## Files

| file | what it does |
|---|---|
| `pins.json` | the bridge release's inputs: contracts and native-bridge-plugins commits, plus the Node, Go and Foundry images or releases by digest or sha256 |
| `Dockerfile.tools`, `build-bridge-image.py` | `tnops-bridge:verified`: forge/cast, the built contracts, the plug-in driver, and dnb-tool from this checkout. The build refuses a source that is not at its pin or not clean, and records the image ID in `../artifacts/bridge-images.json`. |
| `deploy_bridge.py` | an operator action on a running generation: the deployment document (`dnb-tool deployment`), then `BridgeDeploy.s.sol` signed with the generation's faucet keystore. The script refuses a vault whose genesis identities differ from the chain's. It also reads the vault's CFG and writes the trust bundle, the PDR and the driver configuration. Everything goes under `GENERATION/bridge/`. |
| `tester/index.html` | the tester page: the fake-value disclosure, the network's endpoints (read from `tester-config.json` beside it), the tester's steps and a read of the visitor's vault credit through their EVM wallet |
| `overlay.py` | `GENERATION/compose.bridge.yaml`, the Compose overlay with the bridge's services |
| `rehearse_bridge.py` | the bridge stages of the runner rehearsal (`.github/workflows/testnet-bridge.yml`) |

## Operator steps

```
python3 deploy/testnet/bridge/build-bridge-image.py --contracts-source <contracts at pin> --nbp-source <native-bridge-plugins at pin>
# generation up as in ../README.md, then:
sudo python3 deploy/testnet/bridge/deploy_bridge.py /srv/<generation> --agg-conf <aggregator shard conf(s)> --agg-url <aggregator URL(s)>
sudo python3 deploy/testnet/bridge/overlay.py /srv/<generation>
cd /srv/<generation> && sudo docker compose -f compose.yaml -f compose.bridge.yaml up -d lockproof
```

## The rehearsal stages

`rehearse_bridge.py` runs on a generation that `rehearse.py --stages up,identity` brought up (`.github/workflows/testnet-bridge.yml`):

| stage | what it checks |
|---|---|
| `deploy` | TokenVerifier and BridgeVault deployed after genesis and readable through the public gateway; the vault's CFG |
| `lockproof` | the lock-proof endpoint (below) |
| `fund` | a driver key for this generation, in `GENERATION/bridge/driver.env` (mode 0600, never in the evidence), funded from the faucet |
| `roundtrip` | a lock, its proof from validator 1's archive, the mint, 3 transfers and the burn certified by the aggregator, the return proof verified by `eth_call`, then the redemption and the claim with the last validator stopped; it rejoins with the same blocks. The vault's balance rises by the lock and falls back after the claim. |
| `negatives` | the redeemed envelope is refused a second time, a second claim is refused, and the vault keeps the nullifier |
| `tester` | the bridge tester CLI as a tester runs it, with only its own faucet-funded key and `bridge/public/`: init, lock, mint, two transfers, burn, redeem, claim and status. A repeated mint is refused, the tester is credited exactly what it locked, and the vault pays it back. It reaches validator 1, the aggregator and the lock-proof endpoint on the internal network (no public route to the aggregator yet, below). |
| `consolidated` | the SDK's consolidation over the one shard (K = 1 anchor), redeemed and claimed, with the per-SID envelope priced as the control |
| `long-history` | a token with `--long-transfers` transfers (default 250, at most 254: one aggregator batch holds 256 state IDs, the mint, the transfers and the burn), consolidated; one gas short reverts and leaves the vault unchanged; then redeemed and claimed |
| `backup-restore` | `rehearse.py`'s quiesced backup and restore with the bridge deployed (the endpoint stopped too): the redeemed lock stays spent, and a new round trip completes on the restored generation |

The driver signs with its own key and with the fixed, publicly known keys of its recipient and submitter (`tests/live/anyage.ts`). That is fine on a
rehearsal generation, but not on a public network: anyone can spend what those addresses hold. A redeem transaction carries the whole return proof, and the public gateway
takes request bodies of at most 16 KiB (`gateway.py`). The `roundtrip` stage prints whether its proof fits. Until it does, a tester's redeem goes to an RPC without that limit.

## The lock-proof endpoint

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

## The bridge tester

`deploy_bridge.py` writes `GENERATION/bridge/public/`, the one directory to publish for testers. It holds the page, `tester-config.json` and the four public
files that config names: the trust-base bundle, its genesis entry id, the EVM shard's PDR and the deployment document. Publish nothing else from
`GENERATION/bridge`: it also holds the driver's key (`driver.env`) and the rehearsal's wallets. The config names the endpoints a tester reaches. Set them with
`--tester-eth-url`, `--tester-redeem-eth-url`, `--tester-agg-url` and `--tester-lockproof-url`; the defaults are the package's internal names, which only the
rehearsal can reach. A host nginx `location /bridge/ { alias /srv/<generation>/bridge/public/; }` on the faucet's or the RPC's hostname serves it.

Not in the package yet, and needed before external testers can run the whole round trip:
- **A public route to the aggregator.** aggregator-go listens only on the internal `validators` and `aggregator` networks, and nothing publishes it. A tester
  needs `certification_request`, `get_inclusion_proof.v2` and `get_inclusion_proofs.v1`, behind nginx with the same per-client limits as the RPC.
- **A route for redemptions.** A redemption carries the whole return proof: 7.8 KB with no transfers and 12.6 KB with three, so 16 to 26 KB as hex. That is
  more than the public gateway's 16 KiB body limit. Either the gateway takes larger `eth_sendRawTransaction` bodies, or the config's `redeemEthUrl` names
  another route.
