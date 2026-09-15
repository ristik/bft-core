# F4d (#12): deterministic SealRegistry genesis generation

> **Later genesis amendment (#167, proposed):** [F4f](f4f-standard-genesis-json-bootstrap.md). The amendment adds a standard-JSON preparation/validation contract preserving arbitrary supported allocations; the single-account implementation and vectors below remain historical evidence. This note does not activate v2 or alter historical test results.

Issue: #12. Base: `integration/enshrined-evm` at `a92188fb`. Status: **implementation unit, inert**. Normative
source: `docs/design/f4a-seal-registry-contract.md` (#153) §5, with the §11 compiler amendment (#155).

The package `registrygenesis` builds the authenticated genesis of `sealRegistry/v1` from a shard
configuration, independent pins and the merged registry artifact, and checks it the way a node's startup
check would. Nothing in production imports it (`registrygenesis/inert_test.go`). `ubft engine-api genesis`
still writes an empty allocation, and no deployment configuration changes.

## 1. Inputs

| Input | Source | Checked |
| --- | --- | --- |
| registry runtime code | `registrygenesis/seal-registry-v1.json`, embedded, byte-identical to `artifacts/seal-registry-v1.json` in `ristik/unicity-pos-contracts` at `7dc63acd` (SHA-256 `56b21b59…61a9`) | profile `sealRegistry/v1`; compiler settings equal the §11 pin; system caller is `a_sys`; all 22 slot keys equal `registryproof`'s constants in order; `Keccak-256(runtimeBytecode)` equals `codeHash` |
| configuration | the shard configuration record without `seal_registry_genesis` | the parameter must be absent; `chain_id` must be a canonical base-10 `uint64` |
| pins | root epoch of the configured trust base, registry code hash, `a_sys`, `a_sr` | addresses must be the v1 constants; the code hash must be non-zero and equal the artifact's |
| EVM header parameters | gas limit, coinbase, genesis `extraData`, base fee (defaults are the CLI's) | gas limit non-zero; `extraData` at most 32 bytes |

## 2. Construction

`Generate` follows #153 §5.3, each step reading only earlier ones:

1. `baseConfig` is a copy of the record with `seal_registry_genesis` deleted; `baseConfigHash` is its
   `PartitionDescriptionRecord.Hash(SHA-256)`.
2. `G` takes network, partition, shard, chain id and shard epoch from the configuration, and root epoch,
   code hash and addresses from the pins. `genesisCommitment = SHA-256(CBOR(G))`.
3. `fullConfig` sets the parameter to the 64 lowercase hex digits of the commitment; `fullShardConfHash` is
   its hash.
4. The six §5.4 words: `layoutVersion = 1`, `genesisCommitment`, `config.shardConfHash = fullShardConfHash`,
   `assignment.epoch`, `assignment.rootEpoch`, `phase = 2`. A zero word, such as `assignment.epoch = 0`, is
   absent from the trie and from the allocation.
5. The allocation holds one account at `a_sr` with balance 0, nonce 0, the runtime code and those words.
   The state root is computed with go-ethereum's `trie`. The header follows reth's `make_genesis_header`
   at `189c0df3` for Shanghai and Cancun at timestamp 0: parent hash, difficulty, number, timestamp,
   gas used and mix hash zero; empty ommers, transactions, receipts and withdrawals roots; base fee from
   the parameters; blob gas used and excess blob gas 0; parent beacon block root zero; no requests hash.
   `evmGenesisHash` is `Keccak-256(RLP(header))`.

The output is opaque, like `registryproof.Snapshot` after #156: every accessor returns a copy, and `FullConfig`
decodes a new record each time. It provides the genesis file (the CLI template with the allocation filled in),
`registryproof.Context` for these pins, and the genesis proof material for the §4.1 keys.

`VerifyContext` is the §5.3 startup check: every `G` field is compared with a value from the configuration or
the pins before the base hash and the commitment are recomputed.

## 3. Vector

The #153 §5.4 configuration (`NetworkID 3`, `PartitionID 8`, one shard, `chain_id 1337`, shard epoch 0, one
validator), root epoch 1, the merged registry, and the default header parameters:

| Value | |
| --- | --- |
| `baseConfigHash` | `0x3582bd0f44572e45c1e46f9b5c9797991dff8a59cdf85cd12e2879d7d67c5653` (unchanged from §5.4) |
| `registryCodeHash` | `0x643b1b983696b0de1f67053daf65c33b55d304de79074b55ee6f8829715a267b` |
| `genesisCommitment` | `0xe4c40d66b7014e2bb0a26bbacf4df194343ec7d331ccb356cf0a167019647ec6` |
| `fullShardConfHash` | `0x4ba6ed4d7f56b668f781eb698b9ad1101d823050c677c8bc03b88b3b3b92a6ba` |
| registry storage root | `0xacd33a6d7f29e1775dc7f84ce6e0c87ef38e8f4a0063c0e9382b983b676fb3b9` |
| EVM genesis state root | `0xddb3133acc51b92b1aef31305df41c897f378741f0e4bb1312e3c21f221fb73d` |
| `evmGenesisHash` | `0xc6606d09de8980f7abc0861c61cf19069719181d6e2417be975039bc38b31de0` |

`testdata/genesis-vector.json` is the generated genesis file, compared byte for byte.

With #153's one-byte placeholder code, generation reproduces the design vector
(`genesisCommitment 071a4f34…eab8`, `fullShardConfHash 3a2c7364…7a6b`), which the #153 model computes
without this package.

## 4. Independent evidence from the pinned reth

`testdata/reth-genesis-vector.sh` runs the pinned reth build (`189c0df3`, a local source build, because
upstream ships no darwin-x86_64 binary) on `testdata/genesis-vector.json`, with discovery and peers disabled
and the node stopped by its own PID. `testdata/reth-genesis-vector.json` records:

- the hash `reth init` reports;
- `eth_getBlockByNumber(0)` hash and state root;
- `debug_getRawHeader` bytes;
- `eth_getProof` for `a_sr` and the 22 keys, requested by block hash.

`TestPinnedRethAgreesWithTheGeneratedGenesis` requires both hashes, the state root and the header bytes to
equal the generated values, and verifies reth's proof with `registryproof.Verify` under the generated context.
A second check: the header template over an empty allocation hashes to `0x0598047b…7789`, which `reth init`
reported for the default `ubft engine-api genesis` file with chain id 1337.

This is genesis only. Proof availability for later blocks and window expiry belong to the next unit.

**The script accepts evidence only from the process it started** (review of #157). It refuses:

- a binary whose `--version` does not report commit `189c0df3…`, or whose `web3_clientVersion` short commit is not a prefix of it (the pinned build reports `reth/v2.5.0-189c0df/…`);
- a port that already answers or already has a listener before the node starts;
- a node that exits at any point, a listener on the port that is not the node's PID, or no listener within the readiness timeout;
- a JSON-RPC response with an `error`, without a non-null `result`, or without the envelope;
- a block 0 result without a 32-byte hash and state root, an RPC genesis hash that differs from the `reth init` hash, a header that is not hex bytes, and a proof that is not for `a_sr` with exactly the 22 keys in order.

It writes to a temporary file in the same directory and replaces the retained vector only after every check passes. The vector was regenerated with the hardened script. Its hashes, state root, header and proof are unchanged, and it now also records `clientVersion`.

`TestRethVectorScriptAcceptsAnHonestPinnedRun` and `TestRethVectorScriptRefusals` run copies of the script offline against a stand-in reth, `curl` and `lsof`. No port is opened. Each refusal must exit non-zero with its targeted message, leave the previous vector byte-identical and leave no temporary file. The honest case replays the retained vector through the same stand-ins, so each refusal comes from its one deviation. The cases include a failed child while another listener answers, JSON-RPC errors on every call, null and malformed results, and a publish step that fails after validation. Disabling each of the twelve checks in turn fails at least one of these tests.

## 5. Tests

- Artifact: the pin loads; eleven tampered forms are refused (profile, three compiler settings, system caller,
  a slot key name, value or omission, runtime code, code hash, empty code).
- The vector, determinism, and the design-document vector.
- The generated genesis proof verifies; `GenesisParentEligible` holds at rounds 1, 2 (§9.2a) and 4 with the
  generated state root as the genesis input record's state, and round 0 is refused. The verifier refuses
  the proof under another code hash, genesis commitment, configuration hash, root epoch or genesis hash.
- `VerifyContext`: parameter encodings (prefix, case, truncation, absence), missing or non-canonical
  `chain_id`, a configuration changed after `G`, a commitment for another `G`, `G` over the full hash, a
  self-consistent `G` for another network, partition, shard, shard epoch, root epoch, code hash, `a_sys`,
  `a_sr` or chain id, and pins for another deployment.
- `Generate` refusals: nil configuration, parameter already set, missing, hexadecimal, padded or overflowing
  `chain_id`, an artifact whose code does not hash to its code hash, an artifact that is not the pinned
  code, wrong addresses, zero code hash, zero gas limit, oversized `extraData`.
- Every configuration and pin input changes the commitment, `fullShardConfHash`, the state root and the
  genesis hash; every header parameter changes only the genesis hash and file, leaving `G`, the commitment,
  `fullShardConfHash` and the state root unchanged.
- Inputs are not retained, accessors return copies, and `Genesis` has no exported field.

Mutation check (local, `go test` per mutation, sources restored and compared after each): 28 mutations of
the generator, the context check, the header and file templates, the accessors and the artifact checks.
27 fail at least one test. Three first forms did not compile and were rewritten. Two accessor mutations
survived until the copy test was changed to keep independent copies of its expected values. The survivor
removes the copy of the caller's `extraData`: `Generate` encodes the header before returning and keeps no
reference to the parameters, so the copy is observable only by a caller changing the slice during the call.

## 6. Not in this unit

No command or node path, no change to `ubft engine-api genesis` or any deployment configuration, no proof
acquisition or witness store (#14, #15), no activation, `v0` removal or WithSealV1 advertisement. The genesis
for a real deployment still needs its own configuration, trust-base root epoch and review. #10, #11 and #12
stay open.
