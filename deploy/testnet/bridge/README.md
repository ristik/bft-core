# The bridge on the testnet package (TN-B)

TN-B (#429), with B-TEST (#438) as its prerequisite, puts fake-value bridging on the public PoA testnet. This directory adds the bridge to the container package in
`deploy/testnet` without changing the package's own services. The plan, and the items that do or don't need the host, are in `briefs/tnb-without-host.md`.

Status: **part 1**. That is the bridge tools image, the post-genesis deploy and the lock-proof endpoint. The mint, transfer, burn, redeem and claim stages (part 2) use the package's one
aggregator: aggregator-go on partition 7, one shard (owner decision 40).

## Files

| file | what it does |
|---|---|
| `pins.json` | the bridge release's inputs: contracts and native-bridge-plugins commits, plus the Node, Go and Foundry images or releases by digest or sha256 |
| `Dockerfile.tools`, `build-bridge-image.py` | `tnops-bridge:verified`: forge/cast, the built contracts, the plug-in driver, and dnb-tool from this checkout. The build refuses a source that is not at its pin or not clean, and records the image ID in `../artifacts/bridge-images.json`. |
| `deploy_bridge.py` | an operator action on a running generation: the deployment document (`dnb-tool deployment`), then `BridgeDeploy.s.sol` signed with the generation's faucet keystore. The script refuses a vault whose genesis identities differ from the chain's. It also reads the vault's CFG and writes the trust bundle, the PDR and the driver configuration. Everything goes under `GENERATION/bridge/`. |
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
