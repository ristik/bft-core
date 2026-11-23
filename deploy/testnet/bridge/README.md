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

Keep the faucet signer stopped while deploying. The deployer uses the generation's
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
| `trust` | Bundle, genesis EntryID, and a finalized operator checkpoint with decimal-string `usableEpoch` and `rootRound`. For later certificates, the operator can export a fresh checkpoint using `deploy_nb2.py GENERATION --print-origin`. Give it to the wallet with `--trust-origin` through the authenticated channel. |
| `pins`, `limits` | Wallet installation pins, deployment block, effective gas and byte ceilings, and proof-source requirements. |
| `recovery`, `feeEnvelope`, `peakWindowEnvelope` | Wallet recovery inputs and the provisional T7 budgets. The fee budget adds 50% to the sampled transaction counts and included gas. Timing doubles the largest observed receipt p99 and allows one seal per advance or final window. |

The release is marked `testnet-provisional` and `realValueAuthorized: false`.
The samples set a disposable test-value envelope. Sustained peak recovery, live
oversized archive history and the combined worst-case fee and reserve remain
qualification gates. [#1269](https://github.com/ristik/bft-core/issues/1269)

## Public B1 checkpoint refresh

Publish `nb2-origin.json` beside the staged `nb2-release.json` over the same
authenticated HTTPS channel. The checkpoint is mutable and stays outside the
release's immutable `SHA256SUMS`. Install the job after staging the release.
The exporter validates the installed release digest, the live generation and
the registry runtime. It reads the epoch and round at a single canonical
finalized block hash. The timer checks every five seconds. After the initial
publication, a new finalized block is published only if the epoch or root
round advanced. The exporter rejects rollback and atomically replaces the
checkpoint with mode 0644, within the wallet's 4096-byte limit. The wallet
checks the same deployment binding and persists accepted successors. The
release digest stays fixed. [#1283](https://github.com/ristik/bft-core/issues/1283)

Run one export from the host to check the configuration:

```sh
sudo python3 deploy/testnet/bridge/nb2/export_origin.py \
  /srv/testnet/GENERATION /var/www/pos-staging/release "$RELEASE_SHA256"
```

For a VR package, add `--pod-cast /absolute/path/to/cast` using the operator's
pinned host Cast. The exporter enters validator pod1's network namespace to
read the loopback execution RPC. It needs host Docker and namespace access.
Use the bridge tools path above for a package with a validator Compose network.

For a periodic job, install the exporter and its imports from this checkout
in a root-owned directory, keeping their repository-relative paths. Install
the supplied `systemd/nb2-origin@.service` and `systemd/nb2-origin@.timer`
under `/etc/systemd/system`. Set these values in
`/etc/nb2-origin/GENERATION.conf` using absolute paths:

```ini
NB2_EXPORTER=/opt/nb2-origin/GENERATION/deploy/testnet/bridge/nb2/export_origin.py
NB2_RELEASE_DIR=/var/www/pos-staging/release
NB2_RELEASE_SHA256=PUT_THE_PINNED_RELEASE_DIGEST_HERE
NB2_RPC_ARGS=--pod-cast /opt/nb2-origin/GENERATION/bin/cast
```

Leave `NB2_RPC_ARGS` empty for a regular validator network. Run
`systemctl daemon-reload` and `systemctl enable --now nb2-origin@GENERATION.timer`.
Check the last export with `journalctl -u nb2-origin@GENERATION.service`.
Disable the timer when retiring the generation. The operator channel
authenticates this testnet checkpoint and the separately published release.
The proof-based source remains part of #1282.

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
[Reference wallet guide](https://github.com/ristik/native-bridge-plugins/blob/a2ce55ffe4a221ed0f25b7954084d6379528dd20/docs/nb2-wallet-guide.md)

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
