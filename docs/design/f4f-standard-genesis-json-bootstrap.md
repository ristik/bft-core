# F4f / F6: standard genesis JSON and configured execution origin

Refs [#167](https://github.com/ristik/bft-core/issues/167), #12, #14; coordinated with #10/#28.
Unit 1, **proposed architecture amendment**, based on `36bc16385c9d4101be02c4fd1df078f29daf4a27`.
[Claim](https://github.com/ristik/bft-core/issues/167#issuecomment-5689532048).
The owner chose standard reth genesis JSON as the single source of execution genesis, including native
UCT allocations. This document changes the design, not the running node. No allocation amount, public
issuance, activation, migration or completed v2 implementation is authorized here.

## 1. Corrections and scope

There are two separate gaps at this base:

- [`registrygenesis.buildEVMGenesis`](../../registrygenesis/registrygenesis.go) constructs only the registry
  account. The [CLI template](../../cli/ubft/cmd/engine_api_genesis.go) emits an empty `alloc`. Neither imports
  an operator's funded standard genesis JSON. This is an allocation/input limitation.
- [`NewShardInfo`](../../rootchain/consensus/storage/sharding.go) initializes `IR{Version:1}` and nil
  `RootHash`; genuine initial certificates therefore have nil state fields. F4a E2, F6a's genesis record,
  and [W3a `PublishGenesis`](../../recordwiring/readiness.go) instead require a certificate with both state
  fields equal to execution genesis S0. This is a trust/initialization mismatch, not missing network data.

The corrected model is **configuration authenticates execution genesis; the genuine root certificate and
bound technical record authenticate assignment and root progress**. These are separate authorities. No
synthetic certificate, substitution inside a signed statement or general root-chain bootstrap change is used.
Generic partitions keep their existing bootstrap. The bounded initial profile is attested execution, shard
epoch 0, one configured root epoch, no epoch transition, and the supported Cancun-at-genesis chain schedule.
A nonzero initial shard epoch is refused explicitly, not projected to zero or silently treated as a handoff.

This amendment supersedes the conflicting genesis-source and genesis-certificate requirements in D1, F2b/c,
F4a/d, F6a/b/d and the relevant specification paragraphs. Their existing vectors remain evidence for the
older design only. Unchanged rules—ordinary certificate verification, signing authority, finality coordination,
proof bounds, mandatory system operations and epoch-transition refusal—remain in force.

## 2. Two JSON APIs; one source of execution settings

These are logical interfaces for unit 2, not declarations that the APIs exist:

| Operation | Input | Output and refusal boundary |
| --- | --- | --- |
| `PrepareGenesisJSON` | base shard configuration without `seal_registry_genesis`, independent protocol pins/artifact, operator standard JSON, finite import limits | finalized standard JSON, full shard configuration, derived origin/identity; refuses reserved entries and unsupported input |
| `ValidateFinalizedGenesisJSON` | full shard configuration, independent pins/artifact, finalized standard JSON, optional expected identity, finite limits | immutable checked `GenesisOrigin`; no mutation, defaults changing meaning, account insertion or setting reset |

`GenerateFromJSON` is an acceptable implementation name for preparation. The old `Generate` fixture API may
remain explicitly separate; it is not the runtime source. JSON fields supply balances, account nonces, code,
storage, genesis header parameters and supported chain settings. No allocation map or duplicate EVM header
flags are added to the shard configuration. Derived metadata records identity, not a second set of settings.
The exact finalized JSON artifact validated by the node is the artifact supplied to reth.

Preparation follows the existing non-circular sequence:

`baseConfigHash -> G -> genesisCommitment -> fullShardConfHash -> registry storage -> full alloc -> S0 -> B0`.

G continues to identify the registry/configuration relationship; **G does not commit the entire allocation**.
User allocation is committed by S0, and S0 by B0. Do not place B0, S0 or a hash of the finalized JSON inside
`fullConfig`/G: the registry stores `fullShardConfHash`, so doing so would create a hash cycle. All source
accounts outside reserved addresses retain their balances, nonces, code and storage semantics. Native UCT
supply is the sum of the finalized native balances; this design chooses none of them.

**Reserved addresses.** Preparation rejects every input allocation at `a_sys` or `a_sr`, including an empty
or byte-identical entry. It inserts only the expected `a_sr` account (nonce 0, balance 0, pinned runtime,
exact initialized registry storage); `a_sys` remains absent. There is no overwrite/repair mode. Validation
of a finalized artifact instead requires that exact account and absent `a_sys`. A prepared file goes through
validation, not preparation again. Check the profile addresses against supported active precompiles,
EIP-4788 and reserved built-ins as F4a requires. Arbitrary user contracts elsewhere remain ordinary alloc
entries; their presence grants no protocol authority or future activation.

### 2.1 Supported input and deterministic identity

Unit 2 accepts a deliberately bounded subset of standard reth JSON; it must reject unsupported values,
never silently discard them or replace them with the old template. Accepted top-level fields are `config`,
`nonce`, `timestamp`, `extraData`, `gasLimit`, `difficulty`, `mixHash`, `coinbase`, `alloc`, `baseFeePerGas`,
`number`, `parentHash`, `gasUsed`, `blobGasUsed`, `excessBlobGas`.
Preserve supplied nonce (8 bytes), timestamp (uint64), difficulty (uint256), mixHash (32 bytes),
coinbase (20 bytes), nonzero gas limit (uint64), extraData (at most 32 bytes), and explicit base fee
(uint64; larger values are refused before the pinned reth header builder could truncate them), matching the pinned client's genesis-header construction. Do not reset these to the old
fixture defaults. Later payloads still obey normal timestamp/fork validity; a future-dated genesis grants
no exception. Number, parent hash and gas used may be omitted or explicitly zero; nonzero values are refused.
For this initial no-blob profile, blobGasUsed/excessBlobGas may be omitted or explicitly zero; nonzero
values are unsupported and refused, not silently dropped. The pinned client preserves supplied blob
quantities, so relaxing this restriction later must validate and preserve them explicitly.

Required top-level fields are `config`, `alloc`, `gasLimit` and `baseFeePerGas`. Optional nonce, timestamp,
difficulty, mixHash, coinbase and extraData normalize to standard zero/empty values when absent; optional
number, parentHash, gasUsed and both blob fields normalize to zero. These are documented standard
semantic defaults, not runtime overrides. Every supported config field listed below is required.
Nonce, timestamp, gasLimit, baseFee, difficulty, number, gasUsed and blob quantities accept unsigned JSON
integers or decimal/`0x` hexadecimal strings, with exact parsing and the specified width; optional account
nonce uses the same parser. Signs, fractions, exponents and out-of-range values are refused. Normalized
output uses minimal hexadecimal quantities. Addresses require exactly 20 bytes, mixHash/parentHash
exactly 32, code/extraData even-length hex bytes; storage keys/values are hexadecimal words up to 32
bytes, left-padded after alias detection. All accepted equivalent spellings are tested against pinned reth.

`config.chainId` must equal the configured canonical shard `chain_id`. Require the current supported schedule:
Homestead, EIP150/155/158, Byzantium, Constantinople, Petersburg, Istanbul, Berlin, London, MergeNetsplit at
block 0; Shanghai/Cancun at time 0; terminal total difficulty 0 and passed=true. Later/alternate fork or
consensus settings are refused. This restriction is supported-client compatibility, not a source of defaults.

Account objects require `balance` (unsigned 256-bit); optional `nonce` (unsigned 64-bit), `code` (bytes) and
`storage` (word-to-word map) use standard semantics. Missing optional account fields mean zero/empty.
`secretKey`, unknown fields, trailing JSON, duplicate object keys and normalized address/storage-key aliases
are refused. Balances accept ordinary reth forms: an unsigned JSON integer, an unsigned decimal string, or a
`0x` hexadecimal integer string, with exact integer parsing through 2^256-1 and no float conversion.
Accept leading zeroes where the pinned client does; normalize values, not user account meaning.
Reject signs, fractions, exponents and overflow. Nonce/header quantities, addresses, code and storage
use the pinned client's field-specific accepted forms and widths, recorded with vectors; do not impose
JSON-RPC quantity rules on balances. Strict accepted quantity/byte spellings must be vector-tested;
case/order/whitespace variants with the same accepted semantic values produce identical S0/B0. Zero-valued
storage is normalized as absent, matching the state trie. Parse limits bound total JSON bytes, accounts,
storage entries both per-account and total, per-account and total code bytes, and nesting before expensive
trie work. The following defaults are local ingestion policy, not monetary/protocol limits. Callers may
configure smaller positive limits; raising these implementation ceilings requires code review. Limit failures
produce no output artifact or partial mutation. Generated output is size-checked before return.

| Bound | Default / implementation ceiling |
| --- | --- |
| Source JSON bytes | 32 MiB |
| Finalized JSON input/output bytes | 64 MiB |
| Account count | 65,536, including the inserted registry |
| Storage entries per account / aggregate | 65,536 / 65,536, including generated registry slots |
| Code bytes per account / aggregate | 1 MiB / 8 MiB, including registry bytecode |
| JSON nesting depth | 16 |

Count decoded bytes/entries before trie construction; reserve capacity for inserted system material before
preparation. The larger finalized bound allows normalizing short storage words to standard
widths without unlimited expansion. Limits apply equally to rejected duplicate/alias input work.

Derive `ExecutionConfigIdentity` from the typed normalized supported chain configuration, in a fixed canonical
encoding documented with unit-2 vectors (including chain ID and every supported fork/consensus setting).
It is needed because the genesis header hash does not commit the full future execution configuration.
The derived identity binds full chain/shard context, full configuration hash,
registry pins, execution profile/version, ExecutionConfigIdentity and B0. S0 may be included as redundant
checked metadata. A file checksum may additionally identify artifact bytes; it is not semantic genesis
identity and need not survive pretty-printing. This metadata contains no allocation/header override.

The operator-provisioned finalized JSON is trusted configuration, like reth's configured chain file.
No second manifest or independently supplied hash is required to use it. A separately provisioned expected
digest/hash is an optional distribution/consistency check, never an alternate settings source. A peer/RPC
file cannot become trusted configuration merely by matching another peer/RPC answer. Validation recomputes
S0/B0 and configuration identity from the trusted JSON, checks local shard/protocol pins and registry proof,
and checks any supplied optional expected identity. The unit-3 startup caller then compares executor
block 0 with the checked origin by number, hash and state; the pure unit-2 validator makes no executor
calls. A mismatched fork configuration must fail even if
B0 happens to match. Runtime never inserts the registry or "fixes" the input.

## 3. GenesisOrigin and readiness

`GenesisOrigin` is an immutable validated deployment object containing full context, execution/profile
identity, B0 at number 0, S0, and verified/owned registry witness material. Its provenance is the trusted
finalized JSON bound to the local shard/protocol pins and any optional expected identity. It is not a `certifiedstore.Record`, UC, fabricated root statement or
permission to sign. Expensive parsing/proof work occurs before round/finality locks; decisive tokens bind the
validated deployment instance/version, not hashes copied from a different context.

A bootstrap readiness preparation requires all of:

1. A checked GenesisOrigin and executor head exactly B0 by number/hash/state.
2. A genuine current UC and its hash-bound TR, authenticated under configured root trust, network,
   partition/shard and full configuration; UC input is the exact initial shape: version 1, round 0, epoch 0,
   timestamp 0, nil previous state, nil state and nil block hash. TR authorizes a positive round in shard
   epoch 0. Root timeouts may advance root/TR rounds while preserving this initial input record.
3. An authenticated bootstrap-eligible history/session: no accepted ordinary certification or executed
   non-genesis head, no contradictory persisted progress, and no unresolved rollback/replacement state (§5).
4. Final revalidation under the existing finality coordination: same held UC/TR observation, current
   origin/deployment instance, progress-state version and exact executor B0. Preparation is outside locks.

The configured origin establishes B0/S0; the UC establishes no execution state yet. A locally restored signing
key stays subject to P-sign's existing restart restriction. Origin readiness must cover the actual initial
nil-state path before Build/signing; the current P-id path's nil-state special case is not sufficient.
Followers still await/verify while not ready. An initial timeout alone cannot make genesis ineligible by
changing the authorized round, nor can it authorize an executor already past B0 to build on B0 again.

## 4. Canonical input v2 and first certification

This is an **inactive versioned semantic amendment**. Existing Go/reth/companion v1 implementations do not
implement it. Root-input version 2 retains the D1 tuple field order and changes its first version element to
2. O_- keeps the actual authenticated statement. The state-hash positions encode either a 32-byte byte string
or canonical CBOR null according to exactly these classes; empty byte strings are not an alternate null:

| Origin class | IR previous state / state / block | Additional binding |
| --- | --- | --- |
| bootstrap | null / null / null | exact initial IR in §3, positive bound TR; execution parent B0 from GenesisOrigin |
| first-certified | null / S1 / B1 (32 bytes each when present) | positive certified round; B1 is the first actual executed child of configured B0 |
| ordinary | both states 32 bytes; block null iff states equal | existing certification and quiet-continuity rules |

All other shapes are refused. A repeat of the first-certified input retains its null previous state and class;
a later quiet input has previous=state=S1 and is ordinary. The first-certified class is not a second bootstrap
permission. To establish it, retain/retrieve B1's authenticated certificate/TR and raw header/witness, check
header hash B1, number 1 and **decoded header predecessor hash B0**, plus certified state/round bindings.
`registryproof.Snapshot.ParentHash()` currently returns its own subject B1; it is not the predecessor field.
A held quiet UC requires authenticated continuity to that B1 source; it cannot manufacture its header.

`h_parent` is always the actual 32-byte execution parent for a payload (B0 for first work). O_- is never edited
to replace null with S0. Origin identity and root-input commitment use the version-appropriate canonical
encoding; consumers must select it from authenticated/profile-bound v2 context. Normal v2 tuple commitments
also differ from v1 by the version element. Existing v1 readers must refuse v2, not interpret null as zeros.
The companion envelope/capability binding must distinguish v2 and retain exact authenticated UC/TR evidence;
no existing protocol is advertised as supporting it merely by this document.

### 4.1 Privileged projection

The open/finalize ABI and 22-slot layout can remain layout 1 in this bounded epoch-0 profile. Under a verified
v2 bootstrap origin only, project the *absence of a certified state* as the canonical zero `stateHash` word,
`certifiedRound=0`, `certEpoch=0`, `hasBlockHash=false`, `blockHash=0`; do not project S0 as certified state.
All actual origin/root/TR/configuration fields and input commitment are projected unchanged. This is an
explicit representation of absence for this profile, not a rewrite of the UC or a general missing-proof
fallback. First-certified and ordinary origins project their actual certified state, round and optional block.
The execution parent header supplies S0 independently. Consumers must not treat zero `certified.stateHash`
as proof of execution state; use the authenticated header/state root and the v2 origin class.

`open` remains the first privileged operation and `finalize` follows the forced prefix (empty here), with
unchanged gas/failure/accounting rules and derived outcome commitment. Their placement, projection,
root-input commitment, registry phase and replay equality must be checked in builder, follower, import and
replay. The contract alone cannot authenticate origin class; ABI compatibility is not proof of v2 execution
support. No new layout/code hash is assumed necessary, but matching pinned-contract/client vectors must
establish this before enabling it. Any required contract change gets its own version/review.

### 4.2 First BCR and the exact exit

The first successful BCR keeps signed `PreviousHash=null`, because root `ShardInfo.RootHash` is nil and
`ValidRequest` checks that relation. Its effective execution parent is S0/B0, independently authenticated by
GenesisOrigin. It reports actual B1/S1 from mandatory first-block execution; B1 must be a child, not an echo
of B0. Even if S1=S0, the signed transition null->S0 is non-quiet and names B1. No ordinary later same-state
block-naming input is introduced: its existing quiet invariant is unchanged.

Once authenticated ordinary progress is known, accepting a genuine non-bootstrap certificate permanently disqualifies bootstrap for that deployment
history, before fetching its data. The normal first case names B1: persist the supersession fact, then
canonicalize/commit and capture **B1 by identity**, even if its state equals S0. Do not use state-change alone
to skip commit/capture. Without a local pending proposal, recovery must acquire the certified B1 source and
witness independently. A valid ordinary quiet history without the source still disqualifies bootstrap and
requires recovery; missing evidence means unready, not genesis.

After B1, readiness requires a verified ordinary durable record plus continuity to the held UC and exact
executor binding. Repeat delivery of B1's certificate does not execute B1 again. The next ordinary BCR uses
S1 as previous certified state. First-certified origins remain valid in later v2 inputs when a timeout repeats
that UC, but never grant permission to choose B0 instead of the authenticated current execution anchor.

`rootchain.Node.verifyZKProof` currently skips a nil-previous-state request even when a verifier is enabled.
This amendment claims only attested initial execution and must explicitly refuse enabling a proven profile
through that bypass. Future proven-mode support must authenticate effective S0/B0 and the full first-transition
relation while retaining the signed null field. It needs a separately reviewed proof-verifier contract; no
change to generic root initialization is necessary for the present attested units.

## 5. Progress, persistence and rollback

GenesisOrigin can always be re-derived as data; **bootstrap permission cannot**. Store emptiness, missing
witnesses, an executor reset, or replay of an initial UC do not establish that this history never progressed.
This is a rule about authenticated progress known to this node, not omniscience about global progress.
Freshness/session evidence on restart is an explicit prerequisite, not a trusted local boolean. Maintain a
context-bound monotonic `ordinary-observed` fact (or a stronger persisted authenticated history)
from the first accepted non-bootstrap UC, atomically with its retained evidence, before treating it as the
current authorized target. Failed persistence leaves the process unready; no fallback to bootstrap. Existing
ordinary record publication/reload remains independently verified. A mismatched or damaged progress state
is a refusal. Bootstrap permission and progress state must not be inferred from unsigned record keys.

A fresh deployment may use its trusted initialization authorization and authenticated initial UC. A restart
must reconcile progress metadata, held authenticated history and executor identity. A replacement/rolled-back
store needs a sufficiently current trusted checkpoint and authenticated history/session establishing the
appropriate mode; absence of local records is not evidence of no progress. Whole-store rollback cannot be
detected by a marker stored on the same rolled-back disk. Without independent freshness/progress evidence,
remain unready and recover. The legacy local-key restart rule still applies separately.

Do not insert GenesisOrigin into the legacy block-0 `certifiedstore.Record` path requiring an S0-valued UC.
Unit 3 must version the changed persistent context/progress semantics explicitly and reject legacy synthetic
or incompatible genesis records under the new profile; no automatic migration. Ordinary records still verify
their genuine UC/TR, state, block, round and witness. Exact storage encoding/version and crash checkpoints
are a unit-3 review deliverable before code lands, not left to silent serialization changes.

## 6. Reviewable implementation units and evidence

| Unit | Deliverable and limits |
| --- | --- |
| 1, this PR | Design/specification amendment; no runtime or execution proof |
| 2 | Inactive standard-JSON preparation/validation API; strict bounds; full allocation trie/header/proofs; finalized identity metadata; pinned reth conformance vectors. No node readiness/wiring activation |
| 3a | v2 canonical origin/input encoding and authenticated derivation/companion acceptance; independent positive/negative vectors for all three classes; Go/reth projection and build/import/replay agreement coordinated under #10/#12 |
| 3b | Versioned configured-origin readiness/progress persistence and first-block capture/recovery; finish W3b using genuine initial certificates; preserve default path and signing gate |

Unit 2 follows accepted unit 1. Runtime v2 enablement waits for both 3a and 3b with coordinated client/contract
versions and explicit activation review. An API-only importer does not claim W3b, native issuance or full F4/F6
acceptance. The protocol-freeze evidence for v2 must include independent byte-level vectors; no current v1
fixture is relabelled v2 evidence.

Required validation:

- Multiple funded EOAs and a code/storage account survive preparation; formatting/order variants preserve
  identity, balance/code/storage/header changes change the appropriate identity, fork mismatch fails, and
  the finalized registry witness verifies. Compare full header/hash/state and account queries with pinned reth.
- Reserved entries, unknown/duplicate/aliased keys, malformed quantities/overflow, unsupported settings and
  each resource limit refuse without partial output or input mutation. Finalized validation never inserts data.
- Real root initial UC/TR and timeout repeats prove assignment while state remains null; canonical v2 retains
  null, distinct from zero bytes and S0. Test first-certified repeats and ordinary quiet successors.
- B1 header ancestry uses the actual predecessor field; forged/swapped context, code, state, round, UC/TR,
  header, profile and input commitment fail. Same execution-state first B1 still supersedes/canonicalizes.
- Crash before/after supersession persistence, no local pending proposal, missing/corrupt/rolled-back records,
  old bootstrap UC replay and unavailable B1 witness never reopen genesis. Revalidation catches concurrent
  held-UC/executor/context changes. Restored signing keys remain blocked; non-ready followers still receive.

This PR validates references and the written code-boundary inventory only. It introduces no implementation
model, runtime test, devnet or real-reth result. The evidence above is required from the named later units.
