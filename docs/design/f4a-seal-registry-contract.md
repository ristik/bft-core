# F4a (#152): SealRegistry storage, initialization and parent-state proof contract

Issue: #152, under F4 (#12) and F2 (#10). Base: `integration/enshrined-evm` at `ba47a890` (the #151
merge). Status: **proposed design, revised to the review decisions of 2026-09-14** (§14). Documentation
plus a test-only executable model (`docs/design/models/f4aregistry`).

This document fixes what the SealRegistry stores, how its genesis state is authenticated, what the two
privileged steps may change, and how a Go reader authenticates a registry value from parent state. It
adds no production contract, deployment, system-call implementation, Engine API method or `v0`
removal. Activation still requires G1 to G4 of `f2-execution-prerequisites.md` together, followed by a
separately reviewed `v0`-to-`v1` switch with integrated build, follower, import and replay evidence.

It restates no accepted rule. Where D1 (`d1-canonical-root-input.md`), D2
(`d2-reth-system-call-fee-profile.md`, ADR 0004), the F2 contracts or the specification already decide
something, this document cites the decision and adds only the storage and proof detail it leaves open.
Facts about reth refer to the pinned revision `189c0df32617afc488e0f091dbface1bd72cceb4`.

## 0. Scope of the initial profile

The registry profile defined here is **`sealRegistry/v1`**. It supports exactly what the merged F2
derivation supports (`f2b-root-input-derivation-mapping.md` §4, `f2a-shard-configuration-binding.md`
"Profile"): one shard configuration, an empty transition list `D`, and an empty forced-inclusion prefix
(`g_fi = 0`, D2 §3).

**"One epoch" means both epochs.** The shard configuration epoch (`e_cert`, `e_auth`, equal to the
configuration record's `Epoch`) and the **root epoch** (`eᵣ`, `UnicitySeal.Epoch`) are each fixed for
the life of a v1 deployment. That matches the only trust-base store on this branch,
`FileTrustBaseStore`, which holds exactly one root trust base for exactly one epoch
(`shardnode/trustbase.go:19`). A root epoch change is H-series work and is refused in v1 (§6.2 O8, §10).

Every input outside the profile is refused by name. The profile is not a partial implementation of the
epoch, handoff or inbox rules; it is a smaller profile whose refusals are part of its definition. A
refusal of this kind stops the shard at that boundary rather than letting it follow a transition v1
cannot authenticate.

## 1. Requirements carried in

| Requirement | Source |
| --- | --- |
| The registry records the last imported root round, root epoch, reference time, tree root and certified EVM state, with authenticated assignment and transition records | `evm-partition.tex` Seal Feed; `appendix-evm.tex` table "Seal registry state" |
| Contracts obtain protocol authority only from state written by the system operation; permissionless verification cannot advance the clock or activate a validator set | `evm-partition.tex` rule "Seal Feed" |
| A duplicate input cannot advance cursors twice; a repeat creates no second claim | `appendix-evm.tex` Seal Transaction |
| Genesis includes the initial assignment, origin and empty cursors under a pinned genesis commitment; genesis authentication is an explicit rule, not a fabricated quorum signature | `appendix-evm.tex` Seal Transaction; D1 §6 |
| Two privileged steps: a presence-only open step first, a finalize step after the forced prefix that writes `sealRegistryCommitment`; failure or exceeding `g_sys` invalidates the block | D2 §1, §3 "Block semantics" |
| `lastAppliedRootRound` is committed state, never the observed maximum and never a zero placeholder | D1 §5; `f2c-root-input-wiring-contract.md` §6; #152 |
| Registry values are authenticated by the block's `stateRoot` and read with standard `eth_getProof`; no new header field | ADR 0004 decision 3b; D2 §3 |
| Unicity digests (SHA-256 over deterministic CBOR) and Ethereum digests (Keccak-256 over RLP) never compose | D1 §1 |
| The seal registry's upgrade rule is "protocol upgrade" | `appendix-evm.tex` table "Contracts and activation scope" |
| Minimal execution-client and Engine API divergence | #1 "Owner design constraints" |

## 2. Identity: addresses, code and version

### 2.1 Addresses and what authorizes the privileged caller

`a_sys` (the privileged origin) and `a_sr` (the registry) are fixed configuration fields
(`appendix-evm.tex` table "Enshrined EVM configuration"). The v1 profile pins the values the accepted
model already uses (`evmroot/d2import.go:48`):

| Field | Value |
| --- | --- |
| `a_sys` | `0xff00000000000000000000000000000000000001` |
| `a_sr` | `0xff00000000000000000000000000000000000002` |

Both are distinct from the stock pre-block system caller used by revm and alloy-evm,
`0xfffffffffffffffffffffffffffffffffffffffe` (`revm-handler` `SYSTEM_ADDRESS`, used by the EIP-4788
call in `alloy-evm` `block/system_calls/eip4788.rs`). revm already exposes a system call with a custom
caller (`system_call_with_caller`), so the dedicated origin adds no execution mechanism beyond the one
D2 row 1 already inventories.

**The security argument is enforcement, not the absence of a key.** Whether anyone holds a private key
for `a_sys` is not relied upon. `a_sys` is authorized because of two rules that hold regardless:

1. The execution client originates `open` and `finalize` from `a_sys` only as the block's privileged
   steps, and rejects any other transaction whose sender is `a_sys`, including one arriving through the
   pool or included by a builder (D2 rejection codes `system_origin_forged`, `system_from_pool`,
   `system_eoa_like`). Import applies the same rule to a peer's block.
2. The registry contract refuses every state-changing call whose `msg.sender` is not `a_sys` (O1, F1).

**Balances carry no meaning, and nothing claims they stay empty.** Anyone can send value to either
address, and a `SELFDESTRUCT` beneficiary transfer cannot be refused. The rules are instead: no protocol
rule reads the balance of `a_sys` or `a_sr`; the registry contract has no payable entry point and never
reads `BALANCE` or `SELFBALANCE`; the privileged calls carry value zero (D2 §1). A balance at either
address therefore changes nothing a proof reader, the client or the contract decides.

A deployment must also show that neither address collides with a precompile active under its fork
schedule, with the EIP-4788 beacon-roots address, with the builtin assignments `a_0x0100` to
`a_0x0102` (`appendix-evm.tex` table "Builtin interfaces"), or with any other genesis allocation.

### 2.2 Code identity

The registry's runtime bytecode is placed at `a_sr` in the EVM genesis allocation. Its identity is the
account's `codeHash`, `Keccak-256(runtime code)`, which the Ethereum state trie commits and which every
account proof returns. The v1 profile pins `registryCodeHash` in the genesis record (§5). A reader
accepts registry storage only from an account whose proven `codeHash` equals that pin (§7).

The code has no constructor arguments or immutables, so it is fixed before the genesis record is built
and cannot depend on anything computed later (§5.3). It must be immutable in practice as well as by
convention: no `DELEGATECALL`, `CALLCODE`, `CREATE`, `CREATE2` or `SELFDESTRUCT`, and no proxy
indirection. A changed code hash is a different registry, not an upgraded one (§11).

### 2.3 Layout version

`layoutVersion = 1` is written at genesis and never changed by either privileged step. Every slot key
embeds the layout version in its derivation (§4.1), so a future layout uses disjoint keys and cannot
reinterpret a v1 word.

## 3. Three encodings, kept apart

| Encoding | World | Used for | Defined in |
| --- | --- | --- | --- |
| **Commitment encoding**: SHA-256 over deterministic CBOR | Unicity | `rootInput` commitment (`extraData`), origin identity, `sealRegistryCommitment`, genesis commitment, shard configuration hashes | D1 §3, D2 §2, §5 here |
| **Calldata ABI**: Solidity ABI of fixed-width arguments | Ethereum | the arguments of the two privileged calls | §6.1 here |
| **Storage words**: 32-byte EVM storage values at Keccak-derived keys | Ethereum | what the registry holds and what a proof returns | §4 here |

Rules:

- A commitment digest is stored as an opaque `bytes32` word. The contract never recomputes a
  SHA-256-over-CBOR value, and the Go reader never hashes a storage word with SHA-256.
- The calldata is a **projection** of the verified structured `rootInput`, not a second encoding of it.
  The contract cannot see the header's `extraData` (the EVM has no opcode for it), so the execution
  client, not the contract, checks `extraData == SHA-256(CBOR(rootInput))` (D2 predicate 5). The client
  then derives the calldata from that same verified structure by the projection in §6.1. Build,
  import and replay use the same projection function, pinned by vectors (§13).
- ABI has no null. Where D1 distinguishes `null` from a digest (`IR.h_b`), the projection carries an
  explicit presence flag and a zero word, and storage keeps the flag (§4.2).
- A zero storage word and an absent slot are the same thing in the Ethereum state trie (zero values are
  deleted). No field may use zero to mean "not initialized"; initialization is established only by
  §7.3 step 5.

## 4. Storage layout (`sealRegistry/v1`)

### 4.1 Slot keys

```
slot(name) = Keccak-256( ASCII("unicity.seal-registry.v1/" || name) )
```

Keccak-256 is used because the key is an Ethereum-world storage key; the ASCII domain string embeds the
layout version. The contract declares no ordinary Solidity state variables. It reads and writes these
constants with `sload` and `sstore`, so compiler upgrades cannot move a field. `TestSlotKeys` in the
model prints every key and checks the set has no collision; the implementation unit publishes them as
golden vectors shared by the contract, the reth import check and the Go reader.

### 4.2 Fields

Scalars are stored as unsigned integers in a 32-byte big-endian word (the standard `uint256` word);
the profile bounds each value to `uint64` and the contract reverts on a larger calldata value.

| Name | Word | Written by | Meaning |
| --- | --- | --- | --- |
| `layoutVersion` | uint | genesis | `1` |
| `genesisCommitment` | bytes32 | genesis | `SHA-256(CBOR(G))`, §5 |
| `config.shardConfHash` | bytes32 | genesis | **`fullShardConfHash`** (§5.3), the value every accepted `O_-` names; also the v1 assignment identity (§4.3) |
| `assignment.epoch` | uint | genesis | the single supported shard configuration epoch |
| `assignment.rootEpoch` | uint | genesis | the single supported root epoch |
| `clock.rootRound` | uint | open | `r` of the bound authorization; the certified round clock (D1 §5) and `lastAppliedRootRound` |
| `origin.rootEpoch` | uint | open | `eᵣ` as imported; equal to `assignment.rootEpoch` in v1 |
| `origin.timestamp` | uint | open | `tᵣ`, seconds |
| `origin.treeRoot` | bytes32 | open | `u` |
| `origin.identity` | bytes32 | open | `SHA-256(CBOR(O_-))` (`evmroot.RootOrigin.Identity`) |
| `origin.trHash` | bytes32 | open | `O_-.TRHash` |
| `round.authorized` | uint | open | `n`, the shard round the last successful block executed |
| `input.commitment` | bytes32 | open | `SHA-256(CBOR(rootInput))`, equal to that block's `extraData` |
| `certified.round` | uint | open | `O_-.IR.n`, the last certified shard round the origin names |
| `certified.stateHash` | bytes32 | open | `O_-.IR.h` |
| `certified.hasBlockHash` | uint | open | `1` if `O_-.IR.h_b` is present, `0` if null |
| `certified.blockHash` | bytes32 | open | `O_-.IR.h_b`, or zero when the flag is `0` |
| `phase` | uint | open, finalize | `1` while open, `2` after finalize; see §6 |
| `outcomes.round` | uint | open | `n` of the block whose outcomes are being committed |
| `outcomes.commitment` | bytes32 | finalize | `sealRegistryCommitment` (D2 §3) |
| `transition.cursor` | uint | genesis | last acknowledged handoff sequence; `0` in v1 and never advanced (§10) |
| `inbox.consumed` | uint | genesis | forced-inbox consumption watermark; `0` in v1 and never advanced (§10) |

`phase` uses `1` and `2` rather than `0` and `1` so that a proven zero is never a valid phase. Genesis
writes `phase = 2`.

`certified.stateHash` is the Unicity-world certified state hash. On this branch the shard node sets
`IR.h` from the EVM block's `stateRoot` (`shardnode/round.go:677` passes `block.StateRoot` to
`BuildInputRecord`), so the two coincide in value. They remain different fields: the registry stores
what the certificate certified.

### 4.3 The assignment in v1

The partition configuration record (`types.PartitionDescriptionRecord`) includes the shard validators
(`Validators`, each with `NodeID`, `SigKey`, `Stake`), `Epoch`, `EpochStart` and `PartitionParams`.
`PartitionDescriptionRecord.Hash` hashes the whole record with bft-go-base's deterministic CBOR encoder
(`hash/hasher.go:76`, `CoreDetEncOptions`), and that hash is the `ShardConfHash` every certificate
carries (`cli/ubft/cmd/shard_node_run.go:191`). In the single-configuration profile the assignment
therefore needs no separate storage: its identity is `config.shardConfHash`, and its epochs are
`assignment.epoch` and `assignment.rootEpoch`. Storing member records, effective weights or thresholds
for builtins is deferred to the handoff design (§10).

## 5. Authenticated genesis initialization

Genesis is bound twice, for different purposes (review decision 2):

- the **certified shard configuration** binds the intended registry initialization, through a
  commitment carried in `PartitionParams` and therefore inside the `ShardConfHash` every accepted
  certificate names (#134, #135);
- the **EVM genesis block hash** binds the complete execution genesis, including every allocation and
  all state outside the registry, through the startup expected-genesis check (#89,
  `docs/engine-api-adapter.md` §4.1).

### 5.1 Names

| Name | Definition |
| --- | --- |
| `baseConfig` | the configuration record with only the `seal_registry_genesis` parameter removed (§5.2) |
| `baseConfigHash` | `baseConfig.Hash(SHA-256)` |
| `G` | the genesis record (below) |
| `genesisCommitment` | `SHA-256(CBOR(G))` |
| `fullConfig` | `baseConfig` with `seal_registry_genesis` set to the encoding of `genesisCommitment` |
| `fullShardConfHash` | `fullConfig.Hash(SHA-256)`, the value certificates carry |
| `evmGenesisHash` | the hash of the EVM genesis block built from the allocation in §5.4 |

```
G = [ "UNICITY_SEAL_REGISTRY_GENESIS",   ; text
      layoutVersion,                     ; uint, 1
      α, β,                              ; uint network, uint partition
      σ,                                 ; bytes, ShardID.Bytes()
      χ,                                 ; uint, the configured chain_id
      a_sys, a_sr,                       ; bytes(20) each
      registryCodeHash,                  ; bytes(32), Keccak-256 of the runtime code
      baseConfigHash,                    ; bytes(32)
      shardEpoch,                        ; uint, baseConfig.Epoch
      rootEpoch ]                        ; uint, the pinned root trust-base epoch
```

Deterministic CBOR as in D1 §3. The first element is a domain string, so the digest cannot collide with
another profile structure. `G` contains `baseConfigHash`, never `fullShardConfHash`, and nothing
derived from the EVM genesis block.

### 5.2 Omission and encoding rules

- **The parameter.** Key `seal_registry_genesis`. Value: `genesisCommitment` as exactly 64 lowercase
  hexadecimal characters, with no `0x` prefix and no whitespace. Any other form is refused.
- **Omission.** `baseConfig` is `fullConfig` with that one key deleted from `PartitionParams`. Every
  other field of the record, and every other `PartitionParams` entry, is byte-for-byte unchanged.
- **Non-empty map.** `chain_id` must be present in `PartitionParams` (it is already required by
  `engine-api` genesis generation). The reduced map is therefore never empty, so the difference between
  a nil map and an empty map in CBOR never arises. A configuration without `chain_id` is refused.
- **Chain id.** `G.χ` must equal `chain_id` parsed as a base-10 unsigned integer.
- **Hash.** Both configuration hashes are `PartitionDescriptionRecord.Hash(crypto.SHA256)`, exactly the
  function nodes already use for `ShardConfHash`.

### 5.3 Construction order

1. Compute `baseConfigHash` from the configuration without `seal_registry_genesis`.
2. Build `G` with `baseConfigHash`, the pinned `registryCodeHash` and `rootEpoch`; compute
   `genesisCommitment`.
3. Insert `genesisCommitment` into `PartitionParams`; compute `fullShardConfHash`.
4. Initialize registry storage with `genesisCommitment` and **`fullShardConfHash`** (§5.4).
5. Build the EVM genesis block from the allocation and pin `evmGenesisHash`.

Each step depends only on earlier steps. The registry bytecode is fixed before step 2 and `G` is fixed
at step 2, so neither can depend on `fullShardConfHash` or `evmGenesisHash`.

A node refuses to start the canonical-input path unless all of these hold, each a named refusal and
never a reset:

- the configured `seal_registry_genesis` is correctly encoded (§5.2);
- every configured `G` field equals a value that does not come from `G`, compared field by field
  before any digest is trusted: `α`, `β`, `σ`, `χ` and `shardEpoch` against the configuration record,
  and `rootEpoch`, `registryCodeHash`, `a_sys` and `a_sr` against independent pins (the configured
  root trust base's epoch, and the deployment's code hash and addresses). Hash consistency is not
  identity: a `G` for another network, with the parameter updated to its commitment, is exactly as
  self-consistent (review 5195786713, P2);
- `baseConfig`, recomputed by the omission rule from the configured record, hashes to `G.baseConfigHash`;
- `SHA-256(CBOR(G))` equals the configured parameter;
- the configured record hashes to the configured `ShardConfHash` (#134 already enforces this);
- the execution client's genesis block hash equals `evmGenesisHash` (#89);
- the proof in §7, taken at `evmGenesisHash`, returns the §5.4 storage values.

`TestGenesisRefusals` in the model covers a missing `chain_id`, three malformed encodings, a commitment
for a different `G`, a `G` built over the full hash instead of the base hash, and a configuration
changed after `G` was built.

### 5.4 Genesis storage, and the worked vector

The EVM genesis allocation sets, at `a_sr`, the runtime code and exactly these storage words:

| Name | Genesis value |
| --- | --- |
| `layoutVersion` | `1` |
| `genesisCommitment` | `genesisCommitment` |
| `config.shardConfHash` | `fullShardConfHash` |
| `assignment.epoch` | `G.shardEpoch` |
| `assignment.rootEpoch` | `G.rootEpoch` |
| `phase` | `2` |

Every other field is absent (zero). Those zeros are the genesis values of `clock.rootRound`,
`round.authorized`, `certified.*`, `transition.cursor` and `inbox.consumed`, and they are authoritative
only in combination with the non-zero words above and the pinned code hash (§7.3 step 5).

`cli/ubft/cmd/engine_api_genesis.go` currently writes `alloc` as an empty `map[string]string`. The
implementation unit must replace it with account objects carrying code and storage; this document does
not change it.

**Worked vector.** Reproduced by `go test ./docs/design/models/f4aregistry/ -run TestGenesisVector -v`.
The configuration is illustrative, and the registry code is a one-byte placeholder (`0x00`), because
no contract exists yet; the vector pins the construction, not a deployable code hash.

| Input | Value |
| --- | --- |
| configuration | `Version 1`, `NetworkID 3`, `PartitionID 8`, single shard (`ShardID.Bytes() = 0x80`), `T2Timeout 5s`, `PartitionParams {chain_id: "1337"}`, `Epoch 0`, one validator `{NodeID "validator-1", SigKey 0x02 followed by 32 zero bytes, Stake 1}` |
| `registryCodeHash` | `Keccak-256(0x00)` = `bc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a` |
| `rootEpoch` | `1` |

| Output | Value |
| --- | --- |
| `baseConfigHash` | `3582bd0f44572e45c1e46f9b5c9797991dff8a59cdf85cd12e2879d7d67c5653` |
| `CBOR(G)` | `8c 781d554e…4953 01 03 08 4180 190539 54ff00…01 54ff00…02 5820bc36…c98a 58203582…5653 00 01` (full hex in the model) |
| `genesisCommitment` | `071a4f34498689e1f26353434c92f763ddaaba8de9cc634aa68af6e1bf65eab8` |
| `seal_registry_genesis` parameter | `071a4f34498689e1f26353434c92f763ddaaba8de9cc634aa68af6e1bf65eab8` |
| `fullShardConfHash` | `3a2c73649214e56d5e98d1c2d06cff56e7a5d67037a25bcf0e43fcaff8987a6b` |

Reading `CBOR(G)`: `8c` is an array of 12; `781d…` the 29-character domain string; `01` layout version;
`03` network; `08` partition; `4180` the one-byte shard identifier; `190539` chain id 1337; two
20-byte strings for `a_sys` and `a_sr`; two 32-byte strings for the code hash and `baseConfigHash`;
`00` shard epoch; `01` root epoch. `TestEveryGenesisFieldIsCommitted` changes each of the ten variable
fields in turn and requires the commitment to change.

## 6. The privileged transitions

### 6.1 Calldata

Two entry points, each ABI-encoded with a four-byte selector.

```
open(
  uint64  n,               // TE_-.Round, the authorized shard round
  uint64  rootRound,       // O_-.r
  uint64  rootEpoch,       // O_-.eᵣ
  uint64  timestamp,       // O_-.tᵣ
  bytes32 treeRoot,        // O_-.u
  bytes32 originIdentity,  // SHA-256(CBOR(O_-))
  bytes32 trHash,          // O_-.TRHash
  bytes32 shardConfHash,   // O_-.ShardConfHash
  uint64  certifiedRound,  // O_-.IR.n
  uint64  certEpoch,       // e_cert
  uint64  authEpoch,       // e_auth
  bytes32 stateHash,       // O_-.IR.h
  bool    hasBlockHash,    // O_-.IR.h_b != null
  bytes32 blockHash,       // O_-.IR.h_b, or zero when hasBlockHash is false
  bytes32 inputCommitment, // SHA-256(CBOR(rootInput)), equal to header extraData
  uint64  transitionCount  // len(D); must be 0 in v1
)

finalize(
  uint64  n,
  bytes32 sealRegistryCommitment
)
```

The projection from the verified `rootInput` to `open` arguments is a total function of that structure
and nothing else. The builder, the importer and a replaying node compute it identically. The contract
has no other state-changing entry point. `finalize` carries the commitment computed by the client over
`DerivedSealOutcomes` (D2); in v1 the outcome list is exactly `[system]`, because the forced prefix is
empty.

### 6.2 `open` preconditions and effects

Preconditions, each a revert:

| # | Check | Reason |
| --- | --- | --- |
| O1 | `msg.sender == a_sys` | only the protocol call; every public caller reverts |
| O2 | `layoutVersion == 1` and `genesisCommitment != 0` | an uninitialized or foreign registry |
| O3 | `phase == 2` | a previous block's finalize ran; an open without finalize cannot be followed |
| O4 | `n > round.authorized` | strict; the same input cannot open twice, and a repeat cannot re-execute a round |
| O5 | `rootRound >= clock.rootRound` | D1 §5 stale-binding rule; skipped root rounds are allowed |
| O6 | `shardConfHash == config.shardConfHash` | single configuration |
| O7 | `certEpoch == assignment.epoch` and `authEpoch == assignment.epoch` | single shard configuration epoch; normal boundary only, handoff refused |
| O8 | `rootEpoch == assignment.rootEpoch` | single root epoch |
| O9 | `transitionCount == 0` | `D` unsupported |
| O10 | `hasBlockHash` is `false` implies `blockHash == 0` | the null encoding is canonical |

Effects, in order: write every `origin.*`, `certified.*`, `clock.rootRound = rootRound`,
`round.authorized = n`, `input.commitment`, `outcomes.round = n`, `outcomes.commitment = 0`, and
`phase = 1`.

**What the contract checks, and what it cannot** (review decision 3). O6 to O10 repeat refusals that
`rootinput.Derive` and the execution client make first. They are kept as bounded local invariants: a
few `sload` comparisons that limit the consequences of an adapter or client defect. Their reach is
limited to the arguments the contract receives. The contract cannot establish that those arguments are
a faithful projection of the authenticated `rootInput`: `transitionCount == 0` shows only that the
client passed zero, not that the real transition list was empty, and O6 shows only that the client
passed the expected hash, not that the certificate carried it. Projection correctness, certificate
authentication and canonical-input derivation stay with Go and the execution client, and none of them
moves into Solidity.

### 6.3 `finalize` preconditions and effects

| # | Check |
| --- | --- |
| F1 | `msg.sender == a_sys` |
| F2 | `phase == 1` |
| F3 | `n == outcomes.round` |

Effects: `outcomes.commitment = sealRegistryCommitment`, then `phase = 2`.

### 6.4 Atomic failure

The unit of atomicity is the block, not the call. Following D2 §1 and the stock precedent for mandatory
system calls (`alloy-evm` `block/system_calls/eip7002.rs` turns a revert or halt of that call into a
block validation error), the execution client treats any of these as **block invalid**:

- `open` or `finalize` reverts, halts or runs out of gas;
- their combined gas exceeds `g_sys` (D2 §3);
- `open` is not the first execution in the block, or `finalize` is missing, repeated or not immediately
  after the (empty) forced prefix;
- after the block, `phase != 2` or `outcomes.round != n` (`seal_finalize_missing`,
  `seal_registry_commitment_mismatch`).

Because an invalid block is never canonical, no partial registry write is ever part of any state a
proof can reach. O3 adds a second guarantee: even if a defective importer accepted a block whose
finalize was missing, its `phase` would stay `1` and every later `open` would revert.

A **public** call to `open` or `finalize` is an ordinary transaction that reverts under O1 or F1. It
pays for its gas, leaves a `status 0` receipt, changes no registry word, and does not invalidate the
block that contains it.

### 6.5 What never writes

Quiet rounds, repeat certificates and root timeouts produce no EVM block (D1 §6), so they never execute
`open` and never write the registry. `eth_call`, `eth_estimateGas` and tracing cannot originate a call
from `a_sys` (D2 §5) and change no canonical state.

## 7. Parent-state proof contract (Go)

### 7.1 What it answers

"What did the registry hold after the certified parent block?" The answer is the source of
`lastAppliedRootRound` for `rootinput.Derive` and `AcceptBlock`, and of the other registry values a Go
caller needs, for the block that builds on that parent.

### 7.2 Inputs, and where each comes from

| Input | Source | Not acceptable |
| --- | --- | --- |
| `parentHash` | the certified parent for the round being built, validated or replayed: the last state-changing certified block (`continuityState.anchor`, contract §3); before any post-genesis block is certified, `evmGenesisHash` for whatever round is authorized, under the eligibility rule of §7.3 | the executor's head; "latest"; a block number; a rule keyed on `n = 1` |
| configured `G`, `genesisCommitment`, `fullShardConfHash` | node configuration, verified by §5.3 | anything returned by the execution client |
| account and slot keys | `a_sr` and the fixed §4.1 key list | an address or key supplied at runtime |

### 7.3 Procedure

1. **Header.** Obtain the header by hash, from `eth_getBlockByHash(parentHash, false)` or from retained
   proof material (§8). Require the supported header shape for the pinned fork schedule (Cancun fields
   present, later-fork fields absent), recompute `Keccak-256(RLP(header))` and require it to equal
   `parentHash`. The RPC's own `hash` field is not evidence. Keep `header.stateRoot` and
   `header.number`.
2. **Account proof.** Request `eth_getProof(a_sr, keys, parentHash)`, naming the block **by hash**
   (EIP-1898), never by number or tag. Verify the account proof as a Merkle-Patricia path for
   `Keccak-256(a_sr)` from `header.stateRoot`, decode the account `[nonce, balance, storageRoot,
   codeHash]` from the proven leaf, and require `codeHash == G.registryCodeHash`. The response's
   `codeHash`, `storageHash`, `balance` and `nonce` fields are ignored in favour of the proven leaf.
3. **Storage proofs.** For each fixed key, verify the path for `Keccak-256(key)` from the proven
   `storageRoot`. A proof that validly ends at a node showing the key is absent yields zero. The
   response's `value` field is ignored in favour of the proven leaf.
4. **Decode.** A present storage value must be a canonical RLP byte string of at most 32 bytes with no
   leading zero byte; every scalar must fit `uint64`. Anything else is a refusal.
5. **Initialization.** Require `layoutVersion == 1`, `genesisCommitment` equal to the configured value,
   `config.shardConfHash` equal to `fullShardConfHash`, `assignment.epoch` and `assignment.rootEpoch`
   equal to `G`, and `phase == 2`. Only after all of these hold are zero-valued fields interpreted as
   their genesis values. A zero `layoutVersion` or `genesisCommitment` is "registry not initialized at
   this block", a refusal.
6. **Parent consistency.** Unless the parent is `evmGenesisHash`, require
   `outcomes.round == round.authorized` and `outcomes.commitment != 0`. If the parent is
   `evmGenesisHash`, apply the genesis-parent eligibility rule below instead.
7. **Result.** Return a typed value carrying the decoded fields together with `parentHash`,
   `header.number` and `header.stateRoot` as provenance. `LastAppliedRootRound` for the next derivation
   is `clock.rootRound` from this result and from nowhere else.

**Genesis as the initial certified parent.** The certified parent is the last certified block that
changed state. Until a certificate names a post-genesis block, that block is the authenticated EVM
genesis, and it stays the parent **for every authorized round**, however many rounds time out first.
A rule keyed on shard round 1 is wrong: on a root timeout, `Extend` passes a nil certification request
(`rootchain/consensus/storage/block_executor.go`, "timeout IR change request do not have BCR") and
`ShardInfo.nextRound` still increments the technical-record round (`sharding.go:547`), so the first
payload can be authorized for round 2 or later with no block certified in between (review 5195786713,
P1). The registry imposes no round-1 assumption either: O4 requires only `n > round.authorized`, which
is `0` at genesis.

`evmGenesisHash` is an eligible parent for authorized round `n` only when all of these hold, each
established from authenticated evidence:

| # | Condition | Evidence |
| --- | --- | --- |
| E1 | `n > 0`; round 0 is installation, not a payload | the authenticated technical record (`Derive`) |
| E2 | the bound certificate's input record is genesis history: `IR.h_b` null, `IR.h` and `IR.h'` equal the pinned genesis state commitment, `IR.n < n`. This is the genesis installation record, a repeat of it after timeouts, or a quiet record extending it | the authenticated, block-bound certificate |
| E3 | the parent header hashes to `evmGenesisHash` and has number 0 | §7.3 step 1 |
| E4 | the registry proven at that parent has `round.authorized = 0` and `certified.round = 0` | §7.3 steps 2 to 5 |

State-root equality alone is not the rule. E2 authenticates that the certificate names no block, E3
binds the exact block, and E4 authenticates that the parent's registry executed no round. As a
supporting property, not a check: in `sealRegistry/v1` every successful block strictly increases
`round.authorized` (O4), so no post-genesis state can equal the genesis state.

`genesisParentEligible` in `docs/design/models/f4aregistry/genesisparent_test.go` states the rule;
`TestGenesisParentDoesNotDependOnRoundOne` accepts first payloads at rounds 1, 2 and 4 and after a quiet
genesis-state round, and shows a round-1 rule would reject the later ones;
`TestGenesisParentRefusals` covers each of E1 to E4 with its premise established first.

This amends the round-1 wording inherited from D1 §2, §3 and §6, `f2b-root-input-derivation-mapping.md`
§4 and §5.1, `f2c-root-input-wiring-contract.md` §3 and §7, and the `rootinput.Derive` comment; each of
those now states the rule explicitly and refers here. D1's vector `root_inputs.first_post_genesis_payload`
stays as it is: it is one instance, at round 1, of the amended row.

### 7.4 The verifier and the wrapper around it

Review decision 4: use go-ethereum's RLP and trie proof primitives behind a small proof-reader interface
with a pinned version, subject to a dependency review in the implementation unit. The facts that review
starts from:

- go-ethereum is already in the module graph and already linked into `ubft`, reached through
  `bft-go-base/crypto` importing `go-ethereum/crypto` (`go mod why -m github.com/ethereum/go-ethereum`),
  at `v1.14.11` as an indirect dependency. Importing `trie` and `rlp` would link additional packages
  that are not linked today, so the existing dependency does not establish their size or cost.
- go-ethereum's library packages are LGPL-3.0 (`COPYING.LESSER`, and the header of `trie/proof.go`);
  bft-core is Apache-2.0. The licensing impact of the added packages is part of the review, not assumed
  from the existing `crypto` import.
- `trie.VerifyProof(rootHash, key, proofDb)` (`trie/proof.go:117` at `v1.14.11`) returns the value for a
  present key, `nil` with a `nil` error when the proof shows the key absent, and an error for a missing
  or undecodable node.

The library verifies a trie path. It does not establish that the right block, account or key was asked
about, so the wrapper owns every piece of context:

| Wrapper responsibility | Rule |
| --- | --- |
| trusted parent and header format | §7.3 step 1; the caller passes only an authenticated `parentHash` |
| account and keys | `a_sr` and the fixed key list are constants of the wrapper; no caller-supplied address or key |
| proof database | built by the wrapper, keying each supplied node by `Keccak-256(node)` computed locally, never by a hash the response names |
| size and work bounds | before verification: a maximum node count per path, a maximum encoded size per node, a maximum total response size, and exactly the fixed number of storage proofs; exceeding any is a refusal |
| code hash and layout | §7.3 steps 2 and 5 |
| absence versus malformed | a `nil` value with a `nil` error is a proven absence and decodes to zero; any error is a refusal; an unexpected extra or missing storage proof is a refusal |
| value decoding | §7.3 step 4 |

### 7.5 Refusals, and retained material versus cached values

Each refusal is distinct and named: header hash mismatch; unsupported header shape; proof unavailable;
proof exceeds bounds; account proof invalid; code hash mismatch; storage proof invalid; value not
canonical or out of range; registry not initialized; configuration mismatch; parent not finalized.

None falls back to a different block, to the current head or to zero. The distinction that matters for
anything held locally is between two kinds of stored data:

- **Unverified cached scalars** (a remembered cursor value, a previous result, a value the client
  reported) are never an input. They carry no proof and are exactly the observed state D1 §5 excludes.
- **Retained proof material** (the parent header and its account and storage proofs, §8) is a valid
  input when it is re-verified by §7.3 against the exact authenticated `parentHash` each time it is
  used. Re-verification makes it equivalent to a fresh proof, and it is what historical replay needs.

## 8. Historical replay selection and proof availability

### 8.1 Selection

For replaying the block that executed shard round `n`, every input is taken **as of that round**
(#141, contract §3): the stored authorization for round `n`, the certified parent recorded for round
`n`, and the registry read from **that parent** by §7. The current registry has moved on and is not a
substitute; using it rejects valid history (`TestAcceptBlock_TheCursorIsAsOfTheReplayedRound`).

Inside reth, import validation reads the registry from its own parent state directly and needs no
proof. The proof contract is for the Go side, which does not execute the EVM.

### 8.2 Availability is a delivery requirement

Review decision 5. On the pinned client, `get_proof` refuses any block further than
`max_proof_window()` behind its best block (`crates/rpc/rpc-eth-api/src/helpers/state.rs:37`,
`ensure_within_proof_window`). The default window is `0` (`crates/rpc/rpc-server-types/src/constants.rs:62`),
so by default only the best block can be proven; `--rpc.eth-proof-window` raises it to at most
`1_209_600` blocks (`MAX_ETH_PROOF_WINDOW`, same file).

The requirement has two parts, and the first does not substitute for the second:

1. **A supported live window.** Validators run with a non-zero proof window sized for the supported
   execution lag and recovery envelope, chosen per deployment with its rationale recorded in the
   implementation unit. A window only permits historical requests. It does not guarantee the client
   still holds the underlying state, which depends on its pruning configuration.
2. **Retained verified proof material.**

**One witness per block, named by the block whose post-state it proves.** `witness(X)` is the RLP
header of block `X` together with the account proof for `a_sr` and the storage proofs for the fixed key
list, taken at `X`'s `stateRoot`, and indexed by `X`'s hash. Two block relationships use it, and they
must not be confused:

| Operation | Needs | Because |
| --- | --- | --- |
| **replay or re-validate** a certified block `B` whose parent is `P` | `witness(P)` | `B`'s derivation reads the registry as of `B`'s parent (§8.1) |
| **build, validate or sign for** the child `C` of a certified block `B` | `witness(B)` | `C`'s derivation reads the registry as of `B` |

So `witness(B)` is first needed for the round after `B` and is needed again whenever `C` is replayed.

**Acquisition.** A node captures `witness(B)` when it applies `B`'s certificate and commits `B`, which
is when `B` becomes the certified anchor. At that moment `B` is its execution client's best block, so
even a zero proof window can serve the request. The node verifies it by §7.3 and stores it in the same
write that records `B`'s certified association: F6 (#14) requires "certified head, UC, technical record,
canonical inputs and replay cursors" to be associated atomically, and `witness(B)` belongs to that
record. `witness(evmGenesisHash)` is captured during the §5.3 startup check.

**Readiness.** A node that holds no verified `witness(B)` is not ready for `C`'s round: it does not
build, validate or sign for `C`, and reports "proof unavailable" rather than falling back. If `B` has
already left the client's window, or the state was pruned, before the node captured the witness (for
example because the node was down), the node obtains `witness(B)` from retained storage on another
node through F7 (#15) archive serving, re-verifies it by §7.3 against `B`'s authenticated hash, and
stays not ready until that succeeds. Serving witnesses to such nodes is part of F7's availability
obligation; durable local association is part of F6's.

**Bounds and retention.** Each entry is bounded by §7.4's size limits. Witnesses follow the same
published retention horizon as D2 companions (D2 §2 "Companion retention", row 7), stored alongside
them, and every reuse re-verifies by §7.3. A node keeps `witness(evmGenesisHash)` for as long as it
may run the §5.3 startup check, so startup still works after genesis has left every client's proof
window.

Retained proofs are **auxiliary witnesses, not consensus fields**. They are not hashed into `rootInput`,
`extraData`, the block or any certificate. Two different valid encodings of a proof for the same account
and keys at the same `stateRoot` authenticate the same values and change nothing a node decides. A
missing witness, after both the retained store and the client's window have been consulted, is the
named refusal "proof unavailable".

## 9. Worked examples

Illustrative values; digests are named, not computed, except in §5.4. The configuration is `α = 3`,
`β = 8`, one shard, `assignment.epoch = 0`, `assignment.rootEpoch = 1`, `g_fi = 0`.

### 9.1 Initial state (EVM block 0)

| Field | Value |
| --- | --- |
| `layoutVersion` | `1` |
| `genesisCommitment` | `071a4f34…eab8` (§5.4) |
| `config.shardConfHash` | `3a2c7364…7a6b` (§5.4) |
| `assignment.epoch` | `0` |
| `assignment.rootEpoch` | `1` |
| `phase` | `2` |
| every other field | absent (`0`) |

A proof at `evmGenesisHash` passes §7.3 steps 1 to 5 and skips step 6. Result:
`clock.rootRound = 0`, `round.authorized = 0`. The zero cursor is authoritative only because steps 2
and 5 passed.

### 9.2 First post-genesis payload, system-only (shard round 1, EVM block 1)

Authorization: a certificate at root round `r = 5`, root epoch 1, `tᵣ = 1700000000`, certifying shard
round 0 (`IR.n = 0`, epoch 0, `IR.h = S0`, `IR.h_b = null`), technical record round 1, epoch 0. No user
transactions.

- `open(n=1, rootRound=5, rootEpoch=1, timestamp=1700000000, treeRoot=U5, originIdentity=O5,
  trHash=T5, shardConfHash=3a2c…7a6b, certifiedRound=0, certEpoch=0, authEpoch=0, stateHash=S0,
  hasBlockHash=false, blockHash=0, inputCommitment=X1, transitionCount=0)`.
  O4 `1 > 0`, O5 `5 >= 0`, O6 to O10 hold.
- The forced prefix is empty.
- `finalize(n=1, R1)`, with `R1 = SHA-256(CBOR([["system", g_open, 1, "", X1]]))`.
- Post-state: `clock.rootRound = 5`, `round.authorized = 1`, `input.commitment = X1`,
  `certified.round = 0`, `certified.stateHash = S0`, `certified.hasBlockHash = 0`,
  `outcomes.round = 1`, `outcomes.commitment = R1`, `phase = 2`. Header `extraData = X1`.

The block changes state (the registry words), so its certification is a successful round, not a quiet
one (D1 §6 note on governance-shard rounds).

### 9.2a Initial timeout: first payload for shard round 2 (EVM block 1)

An alternative to §9.2. Round 1's certification times out at the root. The root repeats the genesis
input record (`IR.n = 0`, `IR.h' = IR.h = S0`, `IR.h_b = null`) at root round `r = 7`, with a
technical record for round 2. No block is certified for round 1, and the registry is untouched.

- Parent selection: E1 `2 > 0`; E2 the bound record names no block, its states are `S0` and
  `IR.n = 0 < 2`; E3 the parent header is `evmGenesisHash`, number 0; E4 the registry at genesis has
  `round.authorized = 0`, `certified.round = 0`. The parent is `evmGenesisHash`.
- `open(n=2, rootRound=7, …, certifiedRound=0, stateHash=S0, hasBlockHash=false, blockHash=0,
  inputCommitment=X2', transitionCount=0)`. O4 `2 > 0`, O5 `7 >= 0`. Then `finalize(n=2, R2')`.
- Post-state: `clock.rootRound = 7`, `round.authorized = 2`, `certified.round = 0`. The EVM block is
  number 1 and its shard round is 2.

A rule that permitted `evmGenesisHash` only for `n = 1` would give this payload no permitted parent, and
the shard would halt after a single initial timeout.

### 9.3 Ordinary block (shard round 2, EVM block 2)

Authorization: root round `r = 6`, certifying round 1 (`IR.h = S1`, `IR.h_b = B1`), technical record
round 2. Three user transfers, and one user transaction that calls `open` directly.

- `open(n=2, rootRound=6, …, certifiedRound=1, stateHash=S1, hasBlockHash=true, blockHash=B1,
  inputCommitment=X2, transitionCount=0)`, then `finalize(n=2, R2)`.
- User transactions follow. The transfers succeed. The direct call to `open` reverts under O1, has a
  `status 0` receipt, and changes no registry word; the block remains valid.
- Post-state: `clock.rootRound = 6`, `round.authorized = 2`, `certified.round = 1`,
  `certified.blockHash = B1`, `outcomes.commitment = R2`, `phase = 2`.

### 9.4 Repeat, no execution (shard round 3), then round 4

Round 3's certification times out at the root. The root issues a repeat certificate at `r = 9` with the
input record of round 2 unchanged (`IR.n = 2`, `IR.h = S2`, `IR.h_b = B2`), and a technical record for
round 4. The root never re-assigns round 3, because `ShardInfo.nextRound` increments the
technical-record round unconditionally (`rootchain/consensus/storage/sharding.go:547`, called from
`block_executor.go:126`), including when the round timed out.

- Round 3: no certified block, no `open`, the registry is unchanged. A block the leader may have built
  for round 3 is not canonical and is not built upon.
- Round 4 (EVM block 3): `open(n=4, rootRound=9, …, certifiedRound=2, stateHash=S2,
  hasBlockHash=true, blockHash=B2, inputCommitment=X4, …)`. O4 `4 > 2` (round 3 is skipped), O5
  `9 >= 6` (root rounds 7 and 8 are skipped).
- Post-state: `clock.rootRound = 9`, `round.authorized = 4`, `certified.round = 2`.

The shard round `n` and the EVM block number differ after a timeout, so no rule may use one for the
other. The clock moved once, by the one block that bound the repeat authorization, never by the repeat
itself.

### 9.5 Rejected calls

Each starts from the §9.4 post-state (`clock.rootRound = 9`, `round.authorized = 4`, `phase = 2`).

| Case | What happens | Outcome |
| --- | --- | --- |
| A user transaction calls `finalize(4, anything)` | F1 reverts | ordinary failed receipt; block valid |
| A transaction with sender `a_sys` appears in a block outside the privileged steps | the client rejects it (`system_origin_forged`) | block invalid |
| A proposer binds an authorization with `r = 8` for round 5 | Go refuses first (`rootinput.ErrNotPinned`, stale against the cursor); if built anyway, O5 reverts | block invalid (`system_failed`). An honest root does not produce this ordering, because a later technical-record round comes from a later root round; the rule is the D1 §5 fail-closed check |
| A block repeats the round-4 input | O4 `4 > 4` fails | block invalid |
| A block omits `finalize` | post-state `phase = 1` | block invalid (`seal_finalize_missing`); any following `open` would also revert at O3 |
| A block's authorization names another configuration | Go refuses (`ErrUnauthenticated` or `ErrWrongContext` from `Derive`); O6 reverts | block invalid |
| The root epoch changes to 2 | Go refuses (no trust base for root epoch 2 in the single-epoch store, `ErrUnauthenticated`); O8 reverts | block invalid; the shard stops at the boundary until an H-series profile exists |
| `D` non-empty, shard epoch handoff, or a non-empty forced prefix | Go refuses (`ErrUnsupported`); O7 or O9 reverts; the client refuses a non-empty prefix under `g_fi = 0` | block invalid |

## 10. Deferred and refused

| Behaviour | v1 disposition | Owner |
| --- | --- | --- |
| Non-empty transitions `D`, committed trust-base bodies | refused (O9, `ErrUnsupported`); `transition.cursor` stays `0` | H-series, with #10's verifier-owned transition obligation |
| Shard epoch handoff (`e_auth == e_cert + 1`) and its acknowledgement (`AckEVMRound`, D4 §1) | refused (O7) | H-series / D4 integration |
| Root epoch change | refused (O8; single-epoch trust-base store) | H1 (#18) |
| Assignment member records, effective weights, thresholds in EVM state | not stored; identity only (§4.3) | handoff design; P-series |
| Trust-base history for builtins | not stored | builtins (B-series), D6 retention |
| Forced-inclusion prefix and consumption watermark | `g_fi = 0`; non-empty prefix refused; `inbox.consumed` stays `0`; the outcome list is `[system]` | I1 to I3, with #10's FIFO/gas obligation |
| Reward cursor | not stored | T-series reward accounting |
| Code or layout upgrade | none; a different code hash or layout version is a different registry, requiring an explicit migration record (D1 §7) | a separate protocol-upgrade design |

Each deferred behaviour is refused, not approximated. When one is designed, it adds fields under new
names, or a new layout version, and states its own genesis and proof rules; it does not redefine a v1
word.

## 11. Layout and version compatibility

- A v1 reader accepts only `layoutVersion == 1` with the pinned code hash. Any other value is a refusal,
  not a best-effort decode.
- New fields in a later profile use new names, and therefore new slot keys (§4.1); they never reuse a v1
  key with a different meaning.
- A layout version change is a protocol upgrade: it needs a new genesis record or an explicit migration
  record, a new code hash, updated vectors for all three encodings, and the same reviewed activation
  path as any other fixed configuration field.
- The Solidity compiler pin in `ristik/unicity-pos-contracts` (`solc 0.8.28`, `evm_version = "cancun"`)
  affects the bytecode and therefore the code hash, not the layout. A compiler change is reviewed as a
  code-hash change.

## 12. Who checks what

| Check | Go (`rootinput`, adapter) | reth (`ureth`) | Solidity (registry) |
| --- | --- | --- | --- |
| Authorization authenticated (UC, TR, trust base, configuration) | yes (`Derive`) | no; consumes the verified input (D2 §2) | no |
| `extraData == SHA-256(CBOR(rootInput))` | yes (`AcceptBlock`) | yes (D2 predicate 5) | cannot (no opcode) |
| Header parent equals certified parent | yes (`AcceptBlock`) | yes (D2 predicate 4) | no |
| `open` first, `finalize` after the prefix, each exactly once | no | yes | O3, F2 as a second layer |
| Only the privileged steps originate from `a_sys` | no | yes (`system_origin_forged`, `system_from_pool`) | O1, F1 |
| Monotone clock and strict shard round | yes, before building (`ErrNotPinned`) | via contract revert and block invalidity | O4, O5 |
| Single configuration, both epochs, empty `D` | yes (`ErrWrongContext`, `ErrUnsupported`, single-epoch trust store) | yes | O6 to O9, as bounded invariants (§6.2) |
| Calldata is a faithful projection of the verified input | computes it for vectors and builder input | computes it for build, import and replay | cannot |
| `g_sys` budget and block invalidity on failure | no | yes | no |
| Post-state finalized (`phase`, `outcomes.round`) | yes, when reading parent state (§7.3 step 6) | yes (D2 predicate 8) | O3 |
| Registry value authenticated by `stateRoot` | yes (§7), through the wrapper of §7.4 | reads its own state | not applicable |
| Genesis pins | yes (§5.3) | chain spec contains the allocation | no |
| Proof material retained and re-verified | yes (§8.2) | serves proofs within its window | not applicable |

## 13. Required tests

In this document's model (`docs/design/models/f4aregistry`, run by `go test`):
`TestGenesisVector` (§5.4 bytes), `TestSlotKeys` (§4.1 keys, no collision), `TestGenesisRefusals`
(§5.3 refusals), `TestSelfConsistentWrongContextIsRefused` (every `G` field against its independent
expected value, each case with a self-consistent commitment), `TestEveryGenesisFieldIsCommitted`,
`TestGenesisParentDoesNotDependOnRoundOne` and `TestGenesisParentRefusals` (§7.3 genesis-parent rule),
and `TestReview153SelfConsistentWrongGenesisContext` (the review's reproducer, unchanged).

For the implementation units (inert U1 carrier, inactive U2 provision, U4 integration), listed so each is
decidable from this document:

1. Golden vectors for all three encodings: slot keys; `open`/`finalize` calldata from D1 `root_inputs`
   vectors; the §5.4 genesis construction on the deployment's real configuration and code hash; storage
   words before and after each §9 example.
2. The projection is total and identical in Go and reth: the same `rootInput` yields byte-identical
   calldata.
3. Contract: every precondition O1 to O10 and F1 to F3 has a negative that establishes its premise
   first; a public caller cannot change any word; no code path writes a field outside §4.2; value sent to
   `a_sys` or `a_sr` changes no decision.
4. Contract: a storage-layout check that the compiled contract declares no ordinary state variables, and
   a check that the runtime code contains none of the opcodes excluded in §2.2 or `BALANCE`/`SELFBALANCE`.
5. Client: a transaction with sender `a_sys` outside the privileged steps invalidates the block, on build
   and on import.
6. Proof reader: a valid proof decodes; each §7.5 refusal is reached by a proof modified in exactly one
   element; a response whose summary fields disagree with its proof nodes is decided by the nodes; a
   proven absence decodes to zero and a truncated proof is a refusal; each §7.4 bound is enforced before
   verification.
7. Proof reader: a block named by number or tag is not accepted as input; the executor head differing
   from the certified parent yields the parent's values.
8. Replay: the §9.4 history replays round 2 against the registry at block 1 (`clock.rootRound = 5`).
9. Availability: with the default proof window, a proof for a non-best parent is refused as
   "proof unavailable" unless retained material exists; retained material for the right parent is
   accepted after re-verification; retained material for another parent, or altered in one node, is
   refused; startup after genesis leaves the window uses the retained genesis proof.
10. Import: a block with `finalize` missing, repeated, or reverting is invalid; a block whose public
    transaction calls `open` is valid.
11. Dependency review for §7.4: the packages added to the `ubft` link, their licence, and the pinned
    version, recorded before the proof reader merges.

## 14. Review decisions (2026-09-14)

| Question | Decision | Applied in |
| --- | --- | --- |
| System caller | keep the dedicated `a_sys`; authorization rests on client enforcement and contract checks, not on key absence; no claim that balances stay empty | §2.1, §12, §13 items 3 to 5 |
| Genesis authentication | keep both bindings, with the explicit non-circular construction `baseConfigHash` → `G` → `genesisCommitment` → `fullShardConfHash` → storage → `evmGenesisHash`, precise omission and encoding rules, and a worked vector | §5, model |
| Contract re-checks | keep the bounded invariant checks; signature verification and derivation stay outside Solidity; state what the checks cannot prove; "one epoch" includes the root epoch | §0, §6.2, §9.5 |
| Go proof verifier | go-ethereum RLP/trie primitives behind a narrow interface, pinned, subject to dependency and licence review; the wrapper owns block, account, keys, bounds, absence and decoding | §7.4, §13 item 11 |
| Proof availability | a supported live window plus retained, re-verified historical proof material alongside D2 companions, including a retained genesis proof; auxiliary witnesses, not consensus fields; retained proofs distinguished from unverified cached values | §7.5, §8.2, §13 item 9 |

Review 5195786713 (of `c2a8398b`):

| Finding | Resolution | Applied in |
| --- | --- | --- |
| P1: genesis-parent eligibility keyed on `n = 1` strands the shard after an initial timeout | eligibility from authenticated history (E1 to E4), independent of the round number and not state-root equality alone; worked initial-timeout example; round-1 wording amended explicitly in D1, F2b, F2c and the `rootinput.Derive` comment | §7.2, §7.3, §9.2a, D1 §2/§3/§6/§9, F2b §4/§5.1, F2c §3/§7, `rootinput/rootinput.go`, model `genesisparent_test.go` |
| P2: a self-consistent `G` for another context passed the startup check | every `G` field compared with an independent expected value before digests are trusted | §5.3, model `verifyGenesisContext` and `TestSelfConsistentWrongContextIsRefused` |
| Retention indexing off-by-one | `witness(X)` names the block whose post-state it proves; replaying `B` needs `witness(P)`, building `B`'s child needs `witness(B)`; acquisition at commit, readiness, recovery through F7, atomic association with F6 | §8.2 |

Still to be settled in the implementation units, not here: the deployment's proof-window size and
retention horizon, the numeric proof bounds, and the outcome of the dependency review.

## 15. What this document does not do

It adds no contract source, no bytecode, no genesis allocation, no reth change, no Engine API method, no
Go proof reader, no retained-proof store and no call site. The model under `docs/design/models` is
test-only and is imported by nothing. The document does not remove `v0`, activate the canonical input,
or advertise any `WithSealV1` capability. It does not close #10, #12 or #152, and it authorizes no
deployment, key reassignment, issuance or PoS activation.
