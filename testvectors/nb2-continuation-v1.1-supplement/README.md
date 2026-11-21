# NB2 continuation v1.1 replay supplement

Use this manifest alongside the [original T1 corpus](../nb2-continuation-v1.1). Every case here uses the supplement's own `gamma.bin`, generation salt and dependency pins. The signed evidence, page trees and predecessor receipts were generated for that domain and the deployed recovery address.

| Case | Replay |
| --- | --- |
| `b1-rollover` | The production ordinary verifier returns the published ABI verdict. The production recovery emits Progress, then Complete with the same verdict. The first packet contains 16 source operations and 17 distinct complete seals, including the root deposit seal. The two exact native requests are `batch-1.bin` (16) and `batch-2.bin` (1). |
| `b1-rollover-refusals` | One seal in the first native request lacks quorum. `BadStep.calldata.bin` refuses at final batch checking. `BadPage.calldata.bin` uses the same evidence, operations and native first batch with one extra authenticated page. The unused page takes precedence. Neither call emits an event. |
| `cross-cut-conflict` | Start commits two claims, the deposit and the mint. The next packet has a valid transfer followed by a synthetic conflict with the **mint claim**. The candidate preserves the complete seal, partition and shard but changes the input record. Its first-use opening carries the committed mint value. The shorter retry executes only the valid transfer using `last-usable-predecessor.cbor`. |

The `context.json`, evidence, ABI verdict and six-field compressed trace use the [original wire layout](../nb2-continuation-v1.1/README.md). The conflict directory also publishes both raw packed claims. Its trace ends at a valid Progress because the evidence suffix contains the conflict.

The Go verifier exercises the cross-packet claim-map value check. Its map control accepts the
committed mint value with the same opening and intermediate root. The end-to-end Solidity replay
through Ureth refuses earlier, when the conflicting source's local certificate fold fails to
reproduce the signed seal root. It then verifies that the shorter retry produces the expected
Progress. The focused `FlatClaimConflict.t.sol` test in unicity-pos-contracts exercises the
production `FlatSparse.claim` value check with these same published claim bytes and opening.

## Deployment and provenance

The replay deploys FlatReceipts, FlatLineage, NativeBridgeVerifier11 and NativeBridgeRecovery11 via CREATE on chain ID 31337. `deployment.json` gives the deployer, nonces, addresses and Keccak hashes of creation inputs and deployed runtime including constructor immutables. The seal registry runtime comes from the checked-in [B1 artifact](../../b1registry/seal-registry.json) at its fixed address. The harness seeds the fixture authority's registry words and consensus pins from the corpus. This is a deterministic conformance state with fixture keys and genesis, using production verifier code and actual B1 precompiles.

The JSON files in `descriptors/` are the exact opaque descriptor bytes for this test release. They identify the pinned native sources and execution rules, existing registry and primitive vector artifacts, and the SHA-256 of the Linux x86-64 `unicity-reth` release binary. The semantic profile identifies the frozen v1.1 spec. `pin-records.bin` is the ordered concatenation of the six 54-byte records in §3. It includes the lineage helper at role 256. `deployment.json` publishes the release, pins, domain and generation digests. These descriptors define the conformance deployment.

## Reproduce and replay

Use the dev server with Go 1.27.3, Forge 1.8.1, solc 0.8.37 and the pinned contracts and Ureth checkouts. Build the Solidity artifacts using the checked-in Foundry profile (Cancun, via IR, optimizer runs 1 for verifier sources, no bytecode metadata). Ureth runs Cancun with its real B1 provider.

```sh
export NB2_FLAT_BFT=/path/to/bft-core
export NB2_FLAT_SUPPLEMENT="$NB2_FLAT_BFT/testvectors/nb2-continuation-v1.1-supplement"

# ristik/unicity-pos-contracts at 36dcbc1fed6505ffaff858678116bcefc8bb9fbf
cd /path/to/unicity-pos-contracts
git submodule update --init
forge build src/nb2/verifier/flat/NativeBridgeVerifier11.sol \
  src/nb2/verifier/flat/NativeBridgeRecovery11.sol \
  --out out-replay --cache-path cache-replay --use /path/to/solc-0.8.37 -j 4 --skip test --skip script
export NB2_FLAT_FORGE_OUT="$PWD/out-replay"

# Ureth at 47cf38736c9f09def5c8fc4dee8a7798ae3988dd, in a disposable checkout
cd /path/to/ureth
cp "$NB2_FLAT_SUPPLEMENT/nb2_flat_supplement.rs" crates/unicity/execution/tests/
cargo test --locked --release -j 4 -p reth-unicity-execution --test nb2_flat_supplement -- --nocapture

cd "$NB2_FLAT_BFT"
go test -p 4 -count=1 ./nb2ref -run '^TestFlatSupplement$'
cd "$NB2_FLAT_SUPPLEMENT"
sha256sum -c MANIFEST
```

To regenerate, copy this supplement to a scratch directory and point `NB2_FLAT_SUPPLEMENT` there. Run the Cargo command once with `NB2_FLAT_SEED=1` to write the deployment identity and Γ. Then run the Go command from bft-core with `NB2_FLAT_SUPPLEMENT_OUT="$NB2_FLAT_SUPPLEMENT"` to sign and write the case files. Replay with Cargo with `NB2_FLAT_SEED` unset. The Go expected-value producer constructs state, roots, event topics and data, and verdicts independently of either verifier.
