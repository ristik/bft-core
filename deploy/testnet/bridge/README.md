# The bridge on the testnet package (TN-B)

TN-B (#429), with B-TEST (#438) as its prerequisite, puts fake-value bridging on the public PoA testnet. This directory adds the bridge to the container package in
`deploy/testnet` without changing the package's own services. The plan, and the items that do or don't need the host, are in `briefs/tnb-without-host.md`.

Status: **part 5** (the release manifest). Part 1 is the bridge tools image, the post-genesis deploy and the lock-proof endpoint. Part 2 adds the bridge's round trip on the package's one
aggregator (aggregator-go on partition 7, one shard: owner decision 40): lock, mint, transfers, burn, redeem and claim, driven by native-bridge-plugins' live
driver (`tests/live/anyage.ts`) in the bridge tools image, plus the consolidated and long-history redeems, on-chain negatives and a backup and restore with the
bridge deployed. Part 3 adds the bridge tester (native-bridge-plugins `tester/`), its page and the published directory, below. Part 4 adds the live negatives (#438): a
conflicting burn, replays after the validator restart and after the restore, and the vault's custody books. Part 5 adds the release manifest, below. Not covered here: a reset with
outstanding locks, retired-key forged histories, the proof refresh across rotations, and the public routes to the aggregator and for redemptions
(`briefs/tnb-without-host.md`).

## Files

| file | what it does |
|---|---|
| `pins.json` | the bridge release's inputs: contracts and native-bridge-plugins commits, plus the Node, Go and Foundry images or releases by digest or sha256 |
| `Dockerfile.tools`, `build-bridge-image.py` | `tnops-bridge:verified`: forge/cast, the built contracts, the plug-in driver, and dnb-tool from this checkout. The build refuses a source that is not at its pin or not clean, and records the image ID in `../artifacts/bridge-images.json`. |
| `deploy_bridge.py` | an operator action on a running generation: the deployment document (`dnb-tool deployment`), then `BridgeDeploy.s.sol` signed with the generation's faucet keystore. The script refuses a vault whose genesis identities differ from the chain's. It also reads the vault's CFG and writes the trust bundle, the PDR, the driver configuration and the release manifest. Everything goes under `GENERATION/bridge/`. |
| `release.py` | the bridge release manifest, `GENERATION/bridge/public/bridge-release.json` (below) |
| `tester/index.html` | the tester page: the fake-value disclosure, the network's endpoints (read from `tester-config.json` beside it), the tester's steps and a read of the visitor's vault credit through their EVM wallet |
| `overlay.py` | `GENERATION/compose.bridge.yaml`, the Compose overlay with the bridge's services |
| `RECOVERY.md` | the operator's bridge recovery runbook: roles, what depends on what, the checks after any procedure, and each failure's procedure |
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
| `deploy` | TokenVerifier and BridgeVault deployed after genesis and readable through the public gateway; the vault's CFG. The release manifest against the chain: each contract's address, code hash and deploy block, the vault's CFG, the genesis, the B1 profile, and the limits (D1 2 MiB, D3 60M, the latest block's gas limit, the proof window, the gateway's three body bounds, the SDK batch bound) |
| `lockproof` | the lock-proof endpoint (below) |
| `fund` | a driver key for this generation, in `GENERATION/bridge/driver.env` (mode 0600, never in the evidence), funded from the faucet |
| `roundtrip` | a lock, its proof from validator 1's archive, the mint, 3 transfers and the burn certified by the aggregator, the return proof verified by `eth_call`, then the redemption and the claim with the last validator stopped; it rejoins with the same blocks. The vault's balance rises by the lock and falls back after the claim. The redeem transaction fits the gateway's `eth_sendRawTransaction` bound. |
| `negatives` | after the round trip, whose release ran with a validator stopped and restarted: the redeemed envelope is refused a second time (`PartAlreadyRedeemed`), a second claim is refused (`InsufficientCredit`), and the vault keeps the nullifier. Then the driver's `negatives`: a conflicting burn of the same state to another address is never certified (the aggregator serves the first burn's proof, and the plug-in refuses to build a return proof of the conflicting one); a fresh proof of the redeemed burn, consolidated under a newer seal, is refused as `PartAlreadyRedeemed`; the same fresh proof re-signed by unknown keys (an unknown-key forgery, not a retired committee) is refused by the plug-in (`ErrQuorumNotMet`) and by the composition (`BridgeRejected`). The vault's balance does not move. |
| `tester` | the bridge tester CLI as a tester runs it, with only its own faucet-funded key and `bridge/public/`: a configuration of another generation (genesis hash) refused before the wallet exists, then init, lock, mint, two transfers, burn, redeem, claim and status. A repeated mint is refused, the tester is credited exactly what it locked, and the vault pays it back. It goes through the public gateway for everything (the chain, the redemption, and the aggregator on `/aggregator`) and reaches the lock-proof endpoint on the internal network. |
| `split` | the split lane (protocol 6) with the tester CLI: lock 100, split 40 + 60, split the 40 into 15 + 25, redeem 15 (85 remain), its retry refused (`PartAlreadyRedeemed`), the 60's negatives by the driver (the split parent returned, a changed recipient, a changed amount: `BridgeRejected` with their status; out of gas: status 0, vault unchanged) and a duplicate submission credited once, redeem 25 (the lock complete), claim; the vault pays back exactly what was locked |
| `consolidated` | the SDK's consolidation over the one shard (K = 1 anchor), redeemed and claimed, with the per-SID envelope priced as the control |
| `long-history` | a token with `--long-transfers` transfers (default 250, at most 254: one aggregator batch holds 256 state IDs, the mint, the transfers and the burn), consolidated; one gas short reverts and leaves the vault unchanged; then redeemed and claimed |
| `backup-restore` | `rehearse.py`'s quiesced backup and restore with the bridge deployed (the endpoint stopped too): the redeemed lock stays spent, the `negatives` replays are all refused again on the restored generation (the aggregator's spent state included), and a new round trip completes |
| `custody` | the vault's books from its whole event log: each lock nonce 1..`lastNonce` once; each credit once, for a lock of the same amount, with the nullifier the vault keeps; uncredited locks unspent; the counters L, D, P equal the event sums, with 0 ≤ P ≤ D ≤ L; the recipients' `claimable` sums to D − P; and the balance is L − P plus donations |

The driver signs with its own key and with the fixed, publicly known keys of its recipient and submitter (`tests/live/anyage.ts`). That is fine on a
rehearsal generation, but not on a public network: anyone can spend what those addresses hold. A redeem transaction carries the whole return proof; the public gateway
takes `eth_sendRawTransaction`, `eth_call` and `eth_estimateGas` bodies up to 4.5 MiB (`gateway.py` `MAX_RAW_TX_BODY`, `LARGE_METHODS`; every other method
16 KiB), so a redemption up to the 2 MiB envelope, and the call and the estimate a wallet makes on it first, fit as
hex. The `roundtrip` stage checks it.

## The release manifest

`deploy_bridge.py` writes `GENERATION/bridge/public/bridge-release.json`, one file that names what this generation's bridge was built and deployed from and
the limits it runs with. It holds no secret and is published with the tester's files. Each value is read from where it is in force, not restated:

| part | contents | read from |
| --- | --- | --- |
| `package` | generation, chain ID, genesis hash, validators, the node images and their source pins | the generation's `manifest.json` |
| `bridge` | the bridge tools image, its source pins (contracts, native-bridge-plugins, Node, Go, Foundry, bft-core) and dnb-tool's sha256 | `artifacts/bridge-images.json`, refused if it is not the image the deploy ran |
| `contracts` | the contracts commit; BridgeVault's and TokenVerifier's address, deploy transaction, block and code hash; the CFG | the deploy's broadcast record and the chain |
| `profile` | the vector corpus digest, the native-bridge-plugins commit, the state-transition SDK (version, tarball, integrity), the B1 profile and its sha256 | the image's checkouts, refused if the plug-ins' corpus is not the one the contracts' golden tests pin; `network/b1-profile.json` |
| `limits` | D1 the redemption envelope bound (2 MiB), D3 the ordinary block capacity (60M gas), the block gas limit, the proof window, the gateway's body bound, the lock-proof endpoint's rate, the largest lock, the SDK batch bound | the generation's files where the value is configured; otherwise the constant's definition, named beside it, at its component's pin |

The rehearsal's `deploy` stage checks it against the chain. A changed pin, image or limit shows up as a changed manifest; there is no compatibility between
releases (greenroom).

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
`--tester-eth-url`, `--tester-redeem-eth-url`, `--tester-agg-url` and `--tester-lockproof-url`. The defaults are the package's public gateway as the
internal network names it (`http://rpc:8545` and its `/aggregator` route; no `redeemEthUrl`, since the gateway takes redemptions) and the lock-proof endpoint's
internal name; on a host, pass their public names. A host nginx `location /bridge/ { alias /srv/<generation>/bridge/public/; }` on the faucet's or the RPC's hostname serves it.

The public routes (orchestrator decision 2026-10-24): the gateway serves the aggregator on `POST /aggregator` (the state-transition SDK's JSON-RPC methods
only, 64 KiB bodies, its own limit of 10 requests a second per address and 50 overall, no authentication) and its trust-base pages on
`GET /api/v1/trustbases`, and takes redemptions as ordinary `eth_sendRawTransaction` bodies. The host nginx routes the three paths (`../nginx.conf.example`).
Still needed before external testers run the whole round trip on a host: the lock-proof endpoint's public name (a host nginx location in front of
`127.0.0.1:8090`), and the host's DNS and TLS.
