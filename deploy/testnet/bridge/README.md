# NB2 v1.1 on the testnet package

Use a fresh, running UTB generation and the exact contract and plug-in commits in
[bridge/pins.json](pins.json). The release uses a single K=64, B=16 vault with
continuation. [NB2 v1.1 specification](../../../docs/design/nb2-continuation-v1.1.md)

```sh
python3 deploy/testnet/bridge/build-bridge-image.py \
  --bft-source "$BFT" --contracts-source "$CONTRACTS" --nbp-source "$PLUGINS"
go build -o /tmp/nb2-evidence ./scripts/nb2-evidence
sudo python3 deploy/testnet/bridge/nb2/deploy_nb2.py "$GENERATION" --nb2-evidence /tmp/nb2-evidence
```

The deployer is the generation's funder account (`funder-secrets/`), never the
faucet key, whose nonces belong to the faucet signer (bft-core#1287). It uses that
keystore, validates the tool and node pins, and predicts the vault address before
creating the recovery verifier. It deploys `FlatReceipts`, `FlatLineage`,
`NativeBridgeVerifier11`, `NativeBridgeRecovery11` and `NativeBridgeVault11`.
It verifies each creation block and reads the registry, all five runtime code
hashes and their immutable bindings at a recorded canonical finalized block
hash on every paired validator before publishing. If deployment fails partway
through, keep the logs and use a fresh generation for the next deployment.

Distribute the wallet files from `GENERATION/bridge/nb2/public/` over the
operator's authenticated HTTPS release channel. Pin the SHA-256 of
`nb2-release.json` in the demo wallet build and the handbook, and compare it
before opening the wallet. The channel and pinned digest select the intended
testnet deployment. The UTB pin authenticates the trust history. Binding the
release selection to an authority verifiable from that UTB pin remains a
real-value gate. [#1282](https://github.com/ristik/bft-core/issues/1282)

The public directory contains `nb2-release.json`, the exact descriptors, and
`trust-base.bundle.cbor` with `trust-base.genesis.entryid`.

| Release field | Contents |
| --- | --- |
| `package`, `bridge.sources` | Generation and immutable node and bridge tool pins. Use the recorded plug-in commit. |
| `deployment`, `profile` | Graph, constructor arguments, transactions and blocks, Γ and its domain, runtime hashes, descriptors and binding digests. |
| `trust` | Bundle, genesis EntryID, and a 15-minute freshness window (`freshnessMs: 900000`). The wallet authenticates contiguous UTB entries from the gateway. |
| `pins`, `limits` | Wallet installation pins, deployment block, effective gas and byte ceilings, and proof-source requirements. |
| `recovery`, `feeEnvelope`, `peakWindowEnvelope` | Wallet recovery inputs and the provisional T7 budgets. The fee budget adds 50% to the sampled transaction counts and included gas. Timing doubles the largest observed receipt p99 and allows one seal per advance or final window. |

The release is marked `testnet-provisional` and `realValueAuthorized: false`.
The samples set a disposable test-value envelope. Sustained peak recovery, live
oversized archive history and the combined worst-case fee and reserve remain
qualification gates. [#1269](https://github.com/ristik/bft-core/issues/1269)

## Wallet freshness and settlement

The wallet refreshes UTB history when the signed seal names a newer epoch or the
last successful sync is older than 15 minutes. Before signing a payout, it reads
the destination registry's imported epoch at a canonical finalized block and
keeps the pending return if that epoch is behind the proof.

At public cutover, disable the retired generation's checkpoint timer and keep
its journals and release for audits.

## Private wallet smoke

```sh
sudo python3 deploy/testnet/bridge/nb2/smoke_nb2.py "$GENERATION" --evidence "$EVIDENCE"
```

The smoke runs the pinned reference wallet's deposit, mint, split, transfer,
burn and redeem through the package gateway. It pays both split outputs to a
separate recipient, one by ordinary redemption and one by recovery. It checks two distinct certified payments and verifies zero
remaining custody liability. For the PoS handoff workflow, use `--phase mint`
before handoff and `--phase return` after handoff against the same wallet.
Keep the wallet's private journal under the disposable generation.
[Reference wallet guide](https://github.com/ristik/native-bridge-plugins/blob/14974d0ce275b61abc3620c021130896197978f1/docs/nb2-wallet-guide.md)

## Shared files

| file | what it does |
|---|---|
| `pins.json` | the bridge release's inputs: contracts and native-bridge-plugins commits, plus the Node, Go and Foundry images or releases by digest or sha256 |
| `Dockerfile.tools`, `build-bridge-image.py` | `tnops-bridge:<bft12>-<id12>` (an immutable tag per pin and image, #1092; every consumer runs the image by the ID in `artifacts/bridge-images.json`, and `:verified` is only a human alias): forge/cast, the built contracts, the plug-in checkout with the wallet, and dnb-tool built from the node images' bft pin (`--bft-source`, deploy/testnet/pins.json; `deploy_bridge.image` refuses an image recorded for another pin, #1075). The build refuses a source that is not at its pin or not clean, and records the image ID in `../artifacts/bridge-images.json`. |
| `deploy_bridge.py` | the tools image and how a generation runs it (`image`, `record_image`, `validators_network`, `tools`), shared by `nb2/deploy_nb2.py`, `nb2/release_nb2.py` and `sdk_clients.py`. It deploys nothing itself |
| `sdk_clients.py` | the PoS lane's `pos-sdk-clients` stage of `nb2/rehearse_nb2.py`: the public JS, Rust and Java SDKs' trust-base sessions against the roots' served history |

The protocol 6/7 bridge (TN-B #429/#438: BridgeVault and TokenVerifier, the lock-proof endpoint and its Compose overlay, the bridge tester, its
release manifest, recovery runbook, rehearsal stages, PoS stages and load driver) was removed by NB2-10 (#1106, #1139). A generation that still
runs it (`compose.bridge.yaml`) is retired with its pins; it is not migrated.
