# F4a (#152): SealRegistry storage, initialization and parent-state proof contract

Issue: #152, under F4 (#12) and F2 (#10). Base: `integration/enshrined-evm` at `ba47a890` (the #151
merge). Status: **proposed design**. Documentation only.

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
derivation supports (`f2b-root-input-derivation-mapping.md` §4): one shard configuration, one epoch,
an empty transition list `D`, and an empty forced-inclusion prefix (`g_fi = 0`, D2 §3). Every input
outside that profile is refused by name (§10). The profile is not a partial implementation of the
epoch, handoff or inbox rules; it is a smaller profile whose refusals are part of its definition.

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

### 2.1 Addresses

`a_sys` (the privileged origin) and `a_sr` (the registry) are fixed configuration fields
(`appendix-evm.tex` table "Enshrined EVM configuration"). The v1 profile pins the values the accepted
model already uses (`evmroot/d2import.go:48`):

| Field | Value | Property |
| --- | --- | --- |
| `a_sys` | `0xff00000000000000000000000000000000000001` | no known private key; never holds code or balance |
| `a_sr` | `0xff00000000000000000000000000000000000002` | holds the registry runtime code from genesis |

Both are distinct from the stock pre-block system caller used by revm and alloy-evm,
`0xfffffffffffffffffffffffffffffffffffffffe` (`revm-handler` `SYSTEM_ADDRESS`, used by the EIP-4788
call in `alloy-evm` `block/system_calls/eip4788.rs`). The registry trusts exactly one caller, and no
stock system call uses that caller, so no stock pre-block call can reach the registry's privileged
entry points even if it were mistakenly addressed to `a_sr`. revm already exposes a system call with a
custom caller (`system_call_with_caller`), so the distinct origin adds no execution mechanism beyond
the one D2 row 1 already inventories. §14 records this as an owner decision.

A deployment must also show that neither address collides with a precompile active under its fork
schedule, with the EIP-4788 beacon-roots address, with the builtin assignments `a_0x0100` to
`a_0x0102` (`appendix-evm.tex` table "Builtin interfaces"), or with any genesis allocation.

### 2.2 Code identity

The registry's runtime bytecode is placed at `a_sr` in the EVM genesis allocation. Its identity is the
account's `codeHash`, `Keccak-256(runtime code)`, which the Ethereum state trie commits and which every
account proof returns. The v1 profile pins `registryCodeHash` in the genesis record (§5). A reader
accepts registry storage only from an account whose proven `codeHash` equals that pin (§7).

The code must be immutable in practice as well as by convention: no `DELEGATECALL`, `CALLCODE`,
`CREATE`, `CREATE2` or `SELFDESTRUCT`, and no proxy indirection. Under Cancun, EIP-6780 already
prevents `SELFDESTRUCT` from deleting code created outside the same transaction, but the rule here does
not rely on that. A changed code hash is a different registry, not an upgraded one (§11).

### 2.3 Layout version

`layoutVersion = 1` is written at genesis and never changed by either privileged step. Every slot key
embeds the layout version in its derivation (§4.1), so a future layout uses disjoint keys and cannot
reinterpret a v1 word.

## 3. Three encodings, kept apart

The registry touches three different encodings. Confusing any two of them is the defect this section
exists to prevent.

| Encoding | World | Used for | Defined in |
| --- | --- | --- | --- |
| **Commitment encoding**: SHA-256 over deterministic CBOR | Unicity | `rootInput` commitment (`extraData`), origin identity, `sealRegistryCommitment`, genesis commitment | D1 §3, D2 §2, §5 here |
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
  §7 step 5.

## 4. Storage layout (`sealRegistry/v1`)

### 4.1 Slot keys

Each field has a fixed slot key, independent of Solidity's storage layout:

```
slot(name) = Keccak-256( ASCII("unicity.seal-registry.v1/" || name) )
```

Keccak-256 is used because the key is an Ethereum-world storage key; the ASCII domain string embeds the
layout version. The contract declares no ordinary Solidity state variables. It reads and writes these
constants with `sload` and `sstore`, so compiler upgrades cannot move a field. The implementation unit
publishes the 32-byte key of every name as golden vectors, and the contract, the reth import check and
the Go reader each test against those vectors.

### 4.2 Fields

Scalars are stored as unsigned integers in a 32-byte big-endian word (the standard `uint256` word);
the profile bounds each value to `uint64` and the contract reverts on a larger calldata value.

| Name | Word | Written by | Meaning |
| --- | --- | --- | --- |
| `layoutVersion` | uint | genesis | `1` |
| `genesisCommitment` | bytes32 | genesis | `SHA-256(CBOR(G))`, §5 |
| `config.shardConfHash` | bytes32 | genesis | the configuration commitment every accepted `O_-` must name; also the v1 assignment identity (§4.3) |
| `assignment.epoch` | uint | genesis | the single supported epoch |
| `clock.rootRound` | uint | open | `r` of the bound authorization; the certified round clock (D1 §5) and `lastAppliedRootRound` |
| `origin.rootEpoch` | uint | open | `eᵣ` |
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

`phase` uses `1` and `2` rather than `0` and `1` so that a proven zero is never a valid phase: a proof
that returns zero for `phase` means the registry was never opened after genesis or is not the registry.
Genesis writes `phase = 2`.

`certified.stateHash` is the Unicity-world certified state hash. On this branch the shard node sets
`IR.h` from the EVM block's `stateRoot` (`shardnode/round.go:677` passes `block.StateRoot` to
`BuildInputRecord`), so the two coincide in value. They remain different fields: the registry stores
what the certificate certified, and §7 compares it with a header only as a stated cross-check.

### 4.3 The assignment in v1

The partition configuration record (`types.PartitionDescriptionRecord`) includes the shard validators
(`Validators`, each with `NodeID`, `SigKey`, `Stake`), `Epoch`, `EpochStart` and `PartitionParams`.
`PartitionDescriptionRecord.Hash` hashes the whole record, and that hash is the `ShardConfHash` every
certificate carries (`cli/ubft/cmd/shard_node_run.go:191`). In the single-configuration profile the
assignment therefore needs no separate storage: its identity is `config.shardConfHash`, and its epoch is
`assignment.epoch`. Storing member records, effective weights or thresholds for builtins is deferred to
the handoff design (§10), because nothing in v1 changes them and nothing in v1 reads them from the EVM.

## 5. Authenticated genesis initialization

### 5.1 The genesis record

```
G = [ "UNICITY_SEAL_REGISTRY_GENESIS",
      layoutVersion,               ; 1
      α, β, σ, χ,                  ; network, partition, shard (bytes), EVM chain id
      a_sys, a_sr,                 ; 20-byte strings
      registryCodeHash,            ; bytes(32), Keccak-256 of the runtime code
      shardConfHash,               ; bytes(32), ShardConfHash of the configuration below (see 5.3)
      assignmentEpoch ]            ; uint

genesisCommitment = SHA-256( CBOR(G) )
```

Deterministic CBOR as in D1 §3. The first element is a domain string, so the digest cannot collide with
another profile structure.

`G` deliberately contains **nothing derived from the EVM genesis block**: no genesis block hash and no
state root. The registry's storage is part of the genesis state, so the genesis state root and block
hash depend on `genesisCommitment`. Putting either inside `G` would be circular.

### 5.2 Genesis storage

The EVM genesis allocation sets, at `a_sr`, the runtime code and exactly these storage words:

| Name | Genesis value |
| --- | --- |
| `layoutVersion` | `1` |
| `genesisCommitment` | `SHA-256(CBOR(G))` |
| `config.shardConfHash` | as in `G` |
| `assignment.epoch` | as in `G` |
| `phase` | `2` |

Every other field is absent (zero). These zeros are the genesis values of `clock.rootRound`,
`round.authorized`, `certified.*`, `transition.cursor` and `inbox.consumed`, and they are authoritative
only in combination with the two non-zero words above and the pinned code hash (§7 step 5).

`cli/ubft/cmd/engine_api_genesis.go` currently writes `alloc` as an empty `map[string]string`. The
implementation unit must replace it with account objects carrying code and storage; this document does
not change it.

### 5.3 How genesis is authenticated

Genesis is authenticated by two pins that already exist or are already certified, and by nothing
signed for the occasion:

1. **The EVM genesis block hash**, pinned in deployment configuration and checked at startup against
   the execution client (#89, `docs/engine-api-adapter.md` §4.1). The block hash commits the genesis
   header, whose `stateRoot` commits the registry account's code hash and storage. D1 §6 already makes
   this hash the `h_parent` of the first post-genesis payload.
2. **`genesisCommitment` in the partition configuration**, as a `PartitionParams` entry
   (`seal_registry_genesis`, hex of the 32 bytes). Because `PartitionDescriptionRecord.Hash` covers
   `PartitionParams`, the value is part of `ShardConfHash`, which every root certificate carries and
   which F2a binds to the configured hash on every accepted certificate (#134, #135). A node that
   accepts any certificate for this shard has therefore accepted a root-certified configuration naming
   this genesis commitment.

There is a circularity to avoid here as well: `G` contains `shardConfHash`, and `ShardConfHash` would
contain `genesisCommitment`. The v1 rule breaks it by defining `G.shardConfHash` as the hash of the
configuration record **with the `seal_registry_genesis` entry removed**. The Go reader recomputes that
reduced hash from its configured record, checks it equals `G.shardConfHash`, and separately checks the
full hash is the configured `ShardConfHash`. The storage word `config.shardConfHash` holds the **full**
hash, because that is the value certificates carry and the open step compares against (§6.2). §14 lists
this as a point for review; the alternative is to keep the genesis commitment outside the shard
configuration and rely on pin 1 alone.

A node refuses to start the canonical-input path unless: the configured `seal_registry_genesis`
decodes to 32 bytes; the configured `G` fields match its own configuration (`α`, `β`, `σ`, `χ`,
`a_sys`, `a_sr`, code hash, reduced configuration hash, epoch); and the proof in §7, taken at the
pinned genesis block, returns the §5.2 values. A mismatch is a named refusal, never a reset.

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
has no other state-changing entry point.

`transitionCount` is carried so that a non-empty `D` reaches the contract as a refusal rather than being
silently dropped by the projection. `finalize` carries the commitment computed by the client over
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
| O6 | `shardConfHash == config.shardConfHash` | single-configuration profile |
| O7 | `certEpoch == assignment.epoch` and `authEpoch == assignment.epoch` | normal boundary only; handoff refused (§10) |
| O8 | `transitionCount == 0` | `D` unsupported (§10) |
| O9 | `hasBlockHash` is `false` implies `blockHash == 0` | the null encoding is canonical |

Effects, in order: write every `origin.*`, `certified.*`, `clock.rootRound = rootRound`,
`round.authorized = n`, `input.commitment`, `outcomes.round = n`, `outcomes.commitment = 0`, and
`phase = 1`.

The contract repeats O6 to O8 although the Go derivation (`rootinput.Derive`) and the client refuse
those inputs first. The repetition is a deliberate second layer for the case where a client or adapter
defect lets such an input reach execution; its gas cost is a handful of `sload` operations. §14 records
it as a choice.

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

A **public** call to `open` or `finalize` is different: it is an ordinary transaction that reverts under
O1 or F1. It pays for its gas, leaves a `status 0` receipt, changes no registry word, and does not
invalidate the block that contains it.

### 6.5 What never writes

Quiet rounds, repeat certificates and root timeouts produce no EVM block (D1 §6), so they never execute
`open` and never write the registry. `eth_call`, `eth_estimateGas` and tracing cannot originate a call
from `a_sys` (D2 §5); a simulated call with `from = a_sys` is refused by the RPC rule, and in any case
changes no canonical state.

## 7. Parent-state proof contract (Go)

### 7.1 What it answers

"What did the registry hold after the certified parent block?" The answer is the source of
`lastAppliedRootRound` for `rootinput.Derive` and `AcceptBlock`, and of the other registry values a Go
caller needs, for the block that builds on that parent.

### 7.2 Inputs, and where each comes from

| Input | Source | Not acceptable |
| --- | --- | --- |
| `parentHash` | the certified parent for the round being built, validated or replayed: the last state-changing certified block (`continuityState.anchor`, contract §3), or the pinned genesis block hash for `n = 1` (D1 §6) | the executor's head; "latest"; a block number |
| configured `G` and `genesisCommitment` | node configuration, bound by §5.3 | anything returned by the execution client |
| slot keys | §4.1 vectors | a key computed from a name supplied at runtime |

### 7.3 Procedure

1. **Header.** Fetch the header by hash (`eth_getBlockByHash(parentHash, false)`). Recompute
   `Keccak-256(RLP(header))` from the returned fields and require it to equal `parentHash`. The RPC's
   own `hash` field is not evidence. Keep `header.stateRoot` and `header.number`.
2. **Account proof.** Call `eth_getProof(a_sr, keys, parentHash)`, naming the block **by hash** (EIP-1898
   block identifier), never by number or tag. Verify the account proof as a Merkle-Patricia path for
   `Keccak-256(a_sr)` from `header.stateRoot`, decode the account `[nonce, balance, storageRoot,
   codeHash]` from the proven leaf, and require `codeHash == G.registryCodeHash`. The response's
   `codeHash`, `storageHash`, `balance` and `nonce` fields are ignored in favour of the proven leaf.
3. **Storage proofs.** For each key, verify the path for `Keccak-256(key)` from the proven
   `storageRoot`. A valid proof of absence yields zero. The response's `value` field is ignored in
   favour of the proven leaf.
4. **Decode.** Every scalar must fit `uint64`; a larger word is a refusal.
5. **Initialization.** Require `layoutVersion == 1`, `genesisCommitment` equal to the configured value,
   `config.shardConfHash` equal to the configured `ShardConfHash`, and `phase == 2`. Only after all four
   hold are zero-valued fields interpreted as their genesis values. A zero `layoutVersion` or
   `genesisCommitment` is "registry not initialized at this block", a refusal.
6. **Parent consistency.** Unless the parent is the pinned genesis block, require
   `outcomes.round == round.authorized` and `outcomes.commitment != 0`, which is the finalized state of
   the parent's own block.
7. **Result.** Return a typed value carrying the decoded fields together with `parentHash`,
   `header.number` and `header.stateRoot` as provenance. `LastAppliedRootRound` for the next
   derivation is `clock.rootRound` from this result and from nowhere else.

The proof reader calls only standard methods (`eth_getBlockByHash`, `eth_getProof`) and needs no
change to the execution client. What it does add to the Go trusted path is Keccak-256, RLP decoding and
Merkle-Patricia proof verification. The module already requires `golang.org/x/crypto`, which provides
Keccak-256; RLP and trie-proof verification either come from `github.com/ethereum/go-ethereum` (already
in the module graph as an indirect dependency) or are written in the adapter. §14 records the choice.

### 7.4 Refusals

Each is distinct and named: header hash mismatch; proof unavailable; account proof invalid; code hash
mismatch; storage proof invalid; scalar out of range; registry not initialized; configuration mismatch;
parent not finalized. None falls back to a different block, to the current head, to cached values or to
zero.

## 8. Historical replay selection

For replaying the block that executed shard round `n`, every input is taken **as of that round**
(#141, contract §3): the stored authorization for round `n`, the certified parent recorded for round
`n`, and the registry read from **that parent** by §7. The current registry has moved on and is not a
substitute; using it rejects valid history (`TestAcceptBlock_TheCursorIsAsOfTheReplayedRound`).

Serving the proof is an availability question with a concrete limit on the pinned client. reth's
`get_proof` refuses any block further than `max_proof_window()` behind its best block
(`crates/rpc/rpc-eth-api/src/helpers/state.rs:37`, `ensure_within_proof_window`), and the default
window is `0` (`crates/rpc/rpc-server-types/src/constants.rs:62`), so by default only the best block can
be proven. The window is configurable up to `1_209_600` blocks with `--rpc.eth-proof-window`
(`MAX_ETH_PROOF_WINDOW`, same file). Consequently:

- live build and follow read the parent while it is at or near the best block, which the default
  already covers only when the parent **is** the best block, so deployments set a non-zero window;
- replay or synchronization beyond the window needs either a retained proof or a node that can serve
  historical state; a missing proof is the named refusal "proof unavailable", never a fallback;
- whether retained proofs belong in the D2 companion retention obligation (row 7) is deferred to that
  work.

Inside reth, import validation reads the registry from its own parent state directly and needs no
proof. The proof contract is for the Go side, which does not execute the EVM.

## 9. Worked examples

Illustrative values. Digests are named, not computed; the implementation unit replaces them with
vectors. The configuration is `α = 3`, `β = 8`, one shard, `assignment.epoch = 1`, `g_fi = 0`.

### 9.1 Initial state (EVM block 0)

| Field | Value |
| --- | --- |
| `layoutVersion` | `1` |
| `genesisCommitment` | `Gc = SHA-256(CBOR(G))` |
| `config.shardConfHash` | `C` |
| `assignment.epoch` | `1` |
| `phase` | `2` |
| every other field | absent (`0`) |

A proof at the pinned genesis hash passes §7 steps 1 to 5 and skips step 6. Result:
`clock.rootRound = 0`, `round.authorized = 0`. The zero cursor is authoritative only because steps 2
and 5 passed.

### 9.2 First post-genesis payload, system-only (shard round 1, EVM block 1)

Authorization: a certificate at root round `r = 5`, epoch 1, `tᵣ = 1700000000`, certifying shard round 0
(`IR.n = 0`, `IR.h = S0`, `IR.h_b = null`), technical record round 1. No user transactions.

- `open(n=1, rootRound=5, rootEpoch=1, timestamp=1700000000, treeRoot=U5, originIdentity=O5,
  trHash=T5, shardConfHash=C, certifiedRound=0, certEpoch=1, authEpoch=1, stateHash=S0,
  hasBlockHash=false, blockHash=0, inputCommitment=X1, transitionCount=0)`.
  O4 `1 > 0`, O5 `5 >= 0`, O6 to O9 hold.
- The forced prefix is empty.
- `finalize(n=1, R1)`, with `R1 = SHA-256(CBOR([["system", g_open, 1, "", X1]]))`.
- Post-state: `clock.rootRound = 5`, `round.authorized = 1`, `input.commitment = X1`,
  `certified.round = 0`, `certified.stateHash = S0`, `certified.hasBlockHash = 0`,
  `outcomes.round = 1`, `outcomes.commitment = R1`, `phase = 2`. Header `extraData = X1`.

The block changes state (the registry words), so its certification is a successful round, not a quiet
one (D1 §6 note on governance-shard rounds).

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

Two things this example establishes: the shard round `n` and the EVM block number differ after a
timeout, so no rule may use one for the other; and the clock moved once, by the one block that bound
the repeat authorization, never by the repeat itself.

### 9.5 Rejected calls

Each starts from the §9.4 post-state (`clock.rootRound = 9`, `round.authorized = 4`, `phase = 2`).

| Case | What happens | Outcome |
| --- | --- | --- |
| A user transaction calls `finalize(4, anything)` | F1 reverts | ordinary failed receipt; block valid |
| A proposer binds an authorization with `r = 8` for round 5 | Go refuses first (`rootinput.ErrNotPinned`, stale against the cursor); if built anyway, O5 reverts | block invalid (`system_failed`). An honest root does not produce this ordering, because a later technical-record round comes from a later root round; the rule is the D1 §5 fail-closed check |
| A block repeats the round-4 input | O4 `4 > 4` fails | block invalid |
| A block omits `finalize` | post-state `phase = 1` | block invalid (`seal_finalize_missing`); any following `open` would also revert at O3 |
| A block's authorization names another configuration | Go refuses (`ErrUnauthenticated` or `ErrWrongContext` from `Derive`); O6 reverts | block invalid |
| `D` non-empty, epoch handoff, or a non-empty forced prefix | Go refuses (`ErrUnsupported`); O7 or O8 reverts; the client refuses a non-empty prefix under `g_fi = 0` | block invalid |

## 10. Deferred and refused

| Behaviour | v1 disposition | Owner |
| --- | --- | --- |
| Non-empty transitions `D`, committed trust-base bodies | refused (O8, `ErrUnsupported`); `transition.cursor` stays `0` | H-series, with #10's verifier-owned transition obligation |
| Epoch handoff (`e_auth == e_cert + 1`) and its acknowledgement (`AckEVMRound`, D4 §1) | refused (O7) | H-series / D4 integration |
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
| Caller is `a_sys`; public callers refused | no | constructs the call from `a_sys`; rejects a forged sender (D2) | O1, F1 |
| Monotone clock and strict shard round | yes, before building (`ErrNotPinned`) | via contract revert and block invalidity | O4, O5 |
| Single configuration, normal epoch, empty `D` | yes (`ErrWrongContext`, `ErrUnsupported`) | yes | O6 to O8 |
| Calldata projection from the verified input | computes it for vectors and builder input | computes it for build, import and replay | trusts it |
| `g_sys` budget and block invalidity on failure | no | yes | no |
| Post-state finalized (`phase`, `outcomes.round`) | yes, when reading parent state (§7 step 6) | yes (D2 predicate 8) | O3 |
| Registry value authenticated by `stateRoot` | yes (§7) | reads its own state | not applicable |
| Genesis pins | yes (§5.3) | chain spec contains the allocation | no |

## 13. Required tests for the implementation units

These belong to later units (inert U1 carrier, inactive U2 provision, and U4 integration). They are
listed so each is decidable from this document.

1. Golden vectors for all three encodings: slot keys (§4.1); `open`/`finalize` calldata from D1
   `root_inputs` vectors; `genesisCommitment`; storage words before and after each §9 example.
2. The projection is total and identical in Go and reth: the same `rootInput` yields byte-identical
   calldata.
3. Contract: every precondition O1 to O9 and F1 to F3 has a negative that establishes its premise first;
   a public caller cannot change any word; no code path writes a field outside §4.2.
4. Contract: a storage-layout check that the compiled contract declares no ordinary state variables, and
   a check that the runtime code contains none of the opcodes excluded in §2.2.
5. Proof reader: a valid proof decodes; each §7.4 refusal is reached by a proof modified in exactly one
   element (header field, account node, code hash, storage node, out-of-range word, uninitialized
   registry, unfinalized parent); an RPC response whose summary fields disagree with its proof nodes is
   decided by the nodes.
6. Proof reader: a block named by number or tag is not accepted as input; the executor head differing
   from the certified parent yields the parent's values, not the head's.
7. Replay: the §9.4 history replays round 2 against the registry at block 1 (`clock.rootRound = 5`) and
   is refused against the current registry only if the current value is substituted.
8. Availability: with the default proof window, a proof for a non-best parent is refused as
   "proof unavailable", not answered from another block.
9. Import: a block with `finalize` missing, repeated, or reverting is invalid; a block whose public
   transaction calls `open` is valid.

## 14. Decisions for review

1. **`a_sys` value.** Dedicated `0xff00…01` (recommended, §2.1) or the stock system caller
   `0xff…fe`. The dedicated value keeps the registry's trusted caller disjoint from every stock system
   call at no additional mechanism cost.
2. **Genesis commitment in the shard configuration** (§5.3), with the reduced-hash rule to break the
   circularity; or pin 1 (the genesis block hash) alone. Recommended: both, because the configuration
   route makes the commitment root-certified in every accepted certificate.
3. **Contract re-checks O6 to O8** that Go and reth already enforce. Recommended: keep, as a second
   layer for adapter or client defects, at a small gas cost.
4. **Go proof verification dependency** (§7.3): go-ethereum's RLP and trie proof verification, confined
   to the adapter, or a hand-written verifier. `engine_api_genesis.go` records a preference for
   hand-rolled Ethereum formats over a go-ethereum dependency; a Merkle-Patricia proof verifier is a
   larger and more security-sensitive component than a genesis JSON writer, and #1 asks that the
   complete trusted path be evaluated. Recommended: go-ethereum's verifier behind a narrow interface,
   with the choice reviewed in the implementation unit.
5. **Proof availability for replay** (§8): a required non-zero `--rpc.eth-proof-window` for validators,
   and whether retained proofs join D2 row 7.

## 15. What this document does not do

It adds no contract source, no bytecode, no genesis allocation, no reth change, no Engine API method, no
Go proof reader, and no call site. It does not remove `v0`, activate the canonical input, or advertise
any `WithSealV1` capability. It does not close #10, #12 or #152, and it authorizes no deployment, key
reassignment, issuance or PoS activation.
