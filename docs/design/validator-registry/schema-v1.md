# Validator registry schema v1 (VT-16)

**Status.** Normative. This document freezes every cross-repository encoding and constant of the ValidatorRegistry (VR) generation:
bft-core (Go), unicity-pos-contracts (Solidity) and ureth (Rust) implement exactly what is written here and test against the shared
vectors in `testvectors/validator-registry/`. Tracker: ristik/bft-core#1156.

**What it freezes.** The design is the approved VT-01 consolidation (`briefs/validator-registry-design-final.md`, SHA-256
`b56098fc1abc227dcbd94a6ffa12e060d14ea19e713bbeb97fd7ed812efa8d0f`, including its fidelity corrections). Where the design names a
field, a state or a rule without fixing its bytes, this document fixes them. Where the design was ambiguous, the choice taken is listed
in §16 (Freeze decisions) and in `briefs/owner-questions.md`. This document adds no rule; where it seems to, §16 says why.

**Reference implementation.** Package `vrschema/` is the executable form of this text: encoders, strict decoders, digests and the
pure transition and arithmetic functions. It generates the vectors (`go generate ./vrschema`), and `TestVectorsAreCommitted`
requires the checked-in files to be byte-identical to a fresh generation. If this text and `vrschema` disagree, that is a bug in one
of them; neither silently wins.

**Versioning.** This is schema version **1** (`unicity.vr.schema/v1`). Any change to a byte layout, a domain, a code or a constant in
§1 is a new schema version, regenerates the vectors and changes `MANIFEST.sha256`.

---

## 0. Conventions

- **Words.** An EVM word is 32 bytes, big-endian. `uintN` (N ≤ 64) in a word is right-aligned; every byte above its width is zero. An
  `address` is right-aligned (12 zero bytes). A `bool` word is exactly `0` or `1`. A reader refuses anything else.
- **Packed storage words** hold several fields from the **low-order byte** upward, in declaration order (Solidity's struct packing).
  The offset of a field is its distance in bytes from the low-order end. Every byte that no field covers is **reserved and zero**;
  readers refuse a nonzero reserved byte and a non-canonical `bool`.
- **Domains.** EVM-side digests start with a domain word `keccak256(utf8(text))`. Root-side messages are canonical CBOR arrays
  (`cbor:",toarray"`, bft-go-base `types.Cbor`, core-deterministic encoding) that start with a domain text string and a version
  integer, and are hashed with SHA-256.
- **Signatures.**
  - EVM side (registration): 65 bytes `r ‖ s ‖ v`, `v ∈ {27, 28}`, low-s, over the 32-byte digest itself (`KeyLib.verify`,
    `evmassign.verifyEVMSignature`).
  - Root side (every handoff message, rule support, VR-context PoP): bft-go-base `abcrypto` secp256k1 `SignBytes`, 65 bytes over
    SHA-256 of the signed bytes, with the recovery byte required to recover the key (as `evmassign.VerifyPoPs`). Messages are signed by
    the sender's **root key**; the only EVM-key signature is the PoP over `evmassign.PoPMessage`.
- **Lists in CBOR** are arrays, never `null`: an empty list is the empty array `0x80`. The only `null` list is candidate v6's legacy
  `Changes`. Optional structs and byte strings that this document calls absent (`Supersedes`, `Authorization`, `ReplacedAssignment`)
  keep their v5 encoding. Every strict decoder re-encodes what it read canonically and refuses a difference, so a `null` where an array
  is required is refused.
- **Vectors** are JSON: `{schema, version, file, specification, notes, vectors: [{name, op, input, expect}]}`. Byte strings are
  `0x`-prefixed lowercase hex. Integers are JSON numbers; fields that may exceed 2^53 are decimal strings where the vector says so.
  Vectors are sorted by `(op, name)`.

---

## 1. Canonical constants

`constants.json` is the machine-readable table; `vrschema/constants.go` is its source. **Kind** says what a value is:
*genesis* (pinned per generation), *schema* (an encoding constant), *rule* (a validity rule), *existing* (unchanged from today),
*local* (per-node, never consensus), **premise** (an assumption a liveness claim depends on — **never** a validity, abort or replay
rule) and *measured*.

| Constant | Value | Kind |
|---|---|---|
| schema version | 1 | schema |
| `SYSTEM_CALLER` / SealRegistry | `0xff00…0001` / `0xff00…0002` | existing |
| VR address | `0xff00000000000000000000000000000000000003` | genesis |
| VR namespace V | `0x2015195c564edf8b5942ad7bb1fe48e96d190815eb762db2ddff1d85ce73f900` (ERC-7201 `unicity.vr.registry.v1`) | schema |
| Liability namespace B | `0xb2905100cfe7c1af5dee2b1b6726fdfd755820e0f51ef675ed653be4f1102d00` (ERC-7201 `unicity.vr.liability.v1`) | schema |
| `GENESIS_RESULT` | `keccak256("unicity.vr.genesis-result.v1")` = `0xa8f78bb0…d01c12` | schema |
| `REGISTRY_NATIVE` | `keccak256("unicity.vr.registry-native.v1")` = `0x8bb02fcf…c7b9fe` | schema |
| `MEMBERS_DOMAIN` / `CHANGES_DOMAIN` / `OUTPUT_DOMAIN` | `keccak256("unicity.vr.members.v1")` / `…changes.v1` / `…output.v1` | schema |
| `VR_RESULT_DOMAIN` | `keccak256("unicity.vr.native-result.v1")` | schema |
| registration domains | `keccak256("unicity.vr.register")`, `keccak256("unicity.vr.binding")` | schema |
| PoA module tag | `keccak256("unicity.vr.poa.v1")` | schema |
| exposure domain (custody, reused by PoA) | `keccak256("unicity.p85.exposure")` | existing |
| `RECORDS_RETIREMENT_V2` | `keccak256("unicity.seal-registry/records.retirement.v2")` | schema |
| `RetirementRequested` topic | `keccak256("RetirementRequested(uint64,uint64)")` | schema |
| `LIFETIME` | 16,384 progress units, **provisional** (design §13) | rule |
| `DELAY_ROUNDS` / `DELAY_SECONDS` | 2,000 / 3,600 | rule |
| pending changes / bound per output | 32 / 8 root-side, 16 total, Σ payload 64 KiB; payload ≤ 16 KiB | rule |
| pending ForceRemove | 4 | rule |
| committee ceiling | 16 | rule |
| `MIN_EPOCH_GAP` | 100 | rule |
| `FORCE_DEADLINE`, stall deadline | `maxElectionInterval + 2·LIFETIME` | rule |
| `PARK_PERIOD` | `2·LIFETIME` = 32,768 | rule |
| composer pool / trials | 6 / 64 | rule |
| `MAX_HOLDERS` / P85 custody holder index | 8 / 0 | rule |
| `MAX_ACTIVATIONS` | 64 | rule |
| support table | 16 × 64 | rule |
| record widths, kinds 1–8 | 32 / 128 / 288 / 192 / 96 / 224 / 128 / 128 | schema |
| records per root block | 32 | existing |
| `MAX_RET` | elect 160, Ready output 5,408, Pending/NotMine 96, adoption 96, void 0 | rule |
| metadata return | ≤ 32 × 8 = 256 bytes; exact per getter (§5.5) | rule |
| metadata staticcall cap | 50,000 gas | rule |
| gas margin | measured compound worst case × 5/4 | rule |
| `MaxCandidateBytes` | 262,144 (separate from the peer-message limit) | existing |
| `T0` / `LMax` / saturation | 10 s / 9 / exponent ≥ 37 or `T > 2^40` s: `never` | rule |
| `EarliestActivation` offset | `anchorRound + 16` | rule |
| Prepare lapse / cooldown / activation floor | 24 / dead after > 48 / 24 + 8 | existing |
| retained views / buffered ahead / intents | 4 / 2 / 2 | rule |
| peer message / queue | 256 KiB / 64 per peer | rule |
| verification queue | `(1 + n_s) × 4 × 2` | rule |
| replacements per sender and view | 1 (budget or format failure only) | rule |
| `π_max` | enforced per-message verification cap; its value is fixed by VT-05b | rule |
| local timer chunk | ≤ 3,600 s, re-check after each chunk; no `time.Duration` in consensus code | rule (local) |
| recovery run / spacing / `LeaderLag(n)` | 4 / 256 / `4n + 4` | existing |
| `F_r` | `(b+1)·256 + 4` rounds | derived accounting bound (never an abort, replay or validity rule) |
| live-vote residence wait | `T(L, v)·(1+ρ)` on the local monotonic clock (§10.5) | rule (local voting policy) |
| `MAX_BASE_FEE` | `1 << 62` | existing |
| partition ceiling | 64 | rule |
| `--target-block-interval` | default 450 ms, ≥ 100 ms, < `LocalTimeout/2` | local, non-consensus |
| `MaxClockSkew` / `LocalTimeout` | 30 s / 10 s | existing |
| ρ | 10⁻⁴ | **premise** |
| `G_f` | 8, provisional | **premise** |
| `τ_tgt` | 450 ms | **premise** |
| `C_Fz` | 32 | **premise** |
| `Q_max`, `O_max`, Λ, Λ_r, δ, D, `T_req` | measured (design §13) | **premise** |

The full 32-byte values of every domain word are in `vr-layout.json` (`domains`) and in the `domain.*` vectors.

---

## 2. Storage

### 2.1 VR namespace

`V = keccak256(abi.encode(uint256(keccak256("unicity.vr.registry.v1")) - 1)) & ~bytes32(uint256(0xff))`. VR declares its state as one
struct at V (`@custom:storage-location erc7201:unicity.vr.registry.v1`). The struct below **is** the layout: its natural Solidity
packing produces exactly these slots (proved by the forge fixture, §2.8).

| Slot | Field | Encoding |
|---|---|---|
| V+0 | `network` | bytes32, the deployment network word (opaque, pinned by the genesis plan) |
| V+1 | `openOutput` | bytes32 result id, zero when none |
| V+2 | `lastAcked` | bytes32, `GENESIS_RESULT` before the first acknowledgement |
| V+3 | `pendingPair` | bytes32, zero when none |
| V+4 | `committeeLimits` | `nMin u32 @0 · nTarget u32 @4 · nMax u32 @8` |
| V+5 | `hookLimits` | `vMax u32 @0 · lMax u32 @4 · rMax u32 @8 · maxBatch u32 @12` |
| V+6 | `status` | `health u8 @0 · knownRootEpoch u64 @1 · recordCursor u64 @9 · activationCount u32 @17 · holderCount u8 @21` |
| V+7 | `activeModule` | address @0 |
| V+8 | `activeModuleCodeHash` | bytes32 |
| V+9 | `governor` | address @0 |
| V+10 | `counters` | `nextChangeId u64 @0 · identityCount u64 @8 · nativeAttempt u64 @16` |
| V+11 / V+12 | `fees.previous` | `baseFeeFloor u64 @0 · changeDenominator u64 @8` / `feeCollector` address @0 |
| V+13 / V+14 | `fees.current` | same as previous |
| V+15 | `fees.effectiveBlock` | u64 @0 |
| V+16 … V+31 | reserved | VR-internal (VT-02); no root, node or ureth reads them |
| V+32 | `outputs` | `mapping(bytes32 => Output)`: word j of R at `keccak256(abi.encode(R, V+32)) + j` |
| V+33 | `changes` | `mapping(uint64 => Change)`: `keccak256(abi.encode(uint256(id), V+33)) + j` |
| V+34 | `changePayload` | `mapping(uint64 => bytes)`: Solidity `bytes` at `keccak256(abi.encode(uint256(id), V+34))` |
| V+35 | `activations` | `mapping(uint32 => Activation)`: `keccak256(abi.encode(uint256(i), V+35)) + j` |
| V+36 | `holders` | `mapping(uint8 => Holder)`: `keccak256(abi.encode(uint256(h), V+36)) + j` |
| V+37 | `retired` | `mapping(uint8 => mapping(uint64 => mapping(uint64 => bool)))` |
| V+38 … V+63 | reserved | VR-internal mappings (identities, key owners, nonces, bindings, committee, watchdogs) |

`retired[h][id][gen]` is at `keccak256(abi.encode(uint256(gen), keccak256(abi.encode(uint256(id), keccak256(abi.encode(uint256(h), V+37))))))`.

### 2.2 Output record (`outputs[R]`, 11 words)

| Word | Content |
|---|---|
| 0 | `state u8 @0 · attempt u64 @1 · reservedProgress u64 @9 · expiresAtProgress u64 @17` |
| 1 | `predecessor` (VR `lastAcked` at reservation) |
| 2 | `sourceModule` address @0 · `native` bool @20 |
| 3 | `moduleTag` (`REGISTRY_NATIVE` iff native) |
| 4 | `membersDigest` (§4.2) |
| 5 | `kDigest` (`membersDigest` of `committee()` at reservation) |
| 6 | `changesDigest` (§4.3) |
| 7 | `snapshotDigest` |
| 8 | `policyDigest` |
| 9 | `outputCommit` (§4.4) |
| 10 | `invalidReason u8 @0 · invalidAtProgress u64 @1` |

Reader rules: an all-zero record is the unknown id; a known record has a defined state (§3.1), `expiresAtProgress ==
reservedProgress + LIFETIME` (no wrap), `native == (moduleTag == REGISTRY_NATIVE)`, and `invalidAtProgress == 0` when
`invalidReason == 0`.

### 2.3 Change record (`changes[id]`, 4 words) and payload

| Word | Content |
|---|---|
| 0 | `kind u8 @0 · state u8 @1 · rejectReason u8 @2 · notBeforeProgress u64 @3 · notBeforeTime u64 @11 · activeRootEpoch u64 @19` |
| 1 | `payloadHash = keccak256(payload)` |
| 2 | `boundTo` (result id) |
| 3 | `scheduledAt u64 @0 · payloadLength u32 @8` |

The payload bytes are `changePayload[id]` (standard Solidity `bytes` storage: a payload under 32 bytes sits left-aligned in the slot
with `2·len` in the low byte; otherwise the slot holds `2·len + 1` and the data starts at `keccak256(slot)`). Readers verify the bytes
by `payloadHash`. Reader rules: an all-zero record is unknown; `kind ∈ 1..10`, `state ∈ 1..6`, `rejectReason ≠ 0` exactly in state
Rejected, `payloadLength ≤ 16 KiB`.

### 2.4 Activations, holders, retirement bits

- `activations[i]` (i < `activationCount`): word0 `ruleId`, word1 `releaseDigest`, word2 `rootEpoch u64 @0 · notBeforeUcTime u64 @8 ·
  state u8 @16 · changeId u64 @17`. `state ∈ {1 Active, 2 Superseded, 3 Latched}`, `ruleId ≠ 0`, `changeId ≠ 0`. Append-only.
- `holders[h]` (h < `holderCount` ≤ 8): word0 `holder address @0 · registeredEpoch u64 @20`, word1 `holderCodeHash`, word2 `module`
  address. The holder address and code hash are nonzero. Entries are permanent; an entry is allocated only by a successful attach;
  P85 custody is holder 0 on the PoS-prototype generation.
- `retired[h][id][gen]`: canonical bool.

### 2.5 Fees

`F(N)` reads V+11…V+15 at N−1's post-state (§12).

### 2.6 Liability-holder layout (every holder, its own storage)

`B = keccak256(abi.encode(uint256(keccak256("unicity.vr.liability.v1")) - 1)) & ~bytes32(uint256(0xff))`.

- `B + 0`: `cursor u64 @0` (the holder's root-record cursor); the other bytes are zero.
- `B + 1`: base p of `mapping(uint64 id => mapping(uint64 generation => Facts))`; `q = keccak256(abi.encode(uint256(id), p))`,
  `s = keccak256(abi.encode(uint256(generation), q))`; the facts are words `s` and `s + 1`.
- word0: `requested bool @0 · liveExposures u32 @1 · lotReferences u32 @5 · maxLiabilityAnchor u64 @9`, bytes 17–31 reserved.
  word1: `refDigest`.
- An absent entry is all zero: not requested. A reader refuses a non-canonical bool and nonzero reserved bytes.
- Event `RetirementRequested(uint64 indexed id, uint64 indexed generation)`.

### 2.7 What the roots prove

The roots prove only VR (one account, pinned address and code hash) plus, for HolderRetirement, the SealRegistry and the holder
(§13). They read V+0…V+15, `outputs`, `changes`/`changePayload`, `activations`, `holders` and `retired`. Member words and node-id
strings are not proven: they come from VR views and are authenticated by `membersDigest`/`outputCommit` (§16 FD-16).

### 2.8 Storage-proof vectors

`storage.json` gives, per scenario (`vr`, `liability`), every slot and word, a storage-trie root and an Ethereum storage proof per slot
(secure keys `keccak256(slot)`, values `rlp(word without leading zeros)`), and one `storage.read` vector per reader call with the
expected decoded output or the refusal. The scenarios cover ids and generations 0, 1 and 2^64−1, a full word0, a nonzero reserved
byte (refused), `requested = 2` (refused), an absent entry, short and long payload bytes, and maximum-width packed fields.
`storage-flat.json` is the same storage as two flat arrays for Solidity. `storage-forge.json` is the same storage **written by the
Solidity compiler** through the typed structs of §2.1 and §2.6 (unicity-pos-contracts `test/vr/VRSchemaStorage.t.sol`);
`TestForgeStorageIsTheGoLayout` requires it to equal the Go layout slot for slot.

---

## 3. Codes

### 3.1 Output states (word0.state)

`0` None (unknown) · `1` Reserved · `2` Published · `3` Invalidated · `4` Rejected · `5` Acknowledged · `6` Recovered · `7` Closed.

### 3.2 Other codes

| Code set | Values |
|---|---|
| invalidation reason (`invalidate`, word10) | `1` LOST (economic, never a module fault) · `2` WITHDRAWN · other nonzero: output-level · `0`: the storage sentinel "not invalidated", so `invalidate(R, 0)` by the source is a no-op in every state |
| `OutputRejected` reason | `1` Expired · `2` Invalidated · `3` Invalid |
| `onResolved` resolution | `1` Acknowledged · `2` Recovered · `3` Closed |
| health | `0` Healthy · `1` Faulted · `2` Stalled · `3` Inconsistent |
| `elect` outcome | `0` Disabled · `1` NotDue · `2` Reserved · `3` NoCandidate (also the outcome of a failed contained `elect`) |
| `publish` status | `0` Published · `1` Pending · `2` NotMine · `3` PreconditionFailed |
| `packedStatus` | `0` Ready · `1` Pending · `2` NotMine · `3` NotReady (`adoptionReady` only) |
| capabilities | bit0 `LIABILITY_HOLDER` · bit1 `ADOPTION_CHECK` |
| change state | `0` None · `1` Queued · `2` Scheduled · `3` Bound · `4` Active · `5` Rejected · `6` Cancelled |
| activation state | `1` Active · `2` Superseded · `3` Latched |
| record kind | `1` SessionClosed … `5` Retirement · `6` Boundary · `7` OutputRejected · `8` HolderRetirement |
| control op (VR mode) | `1` CloseLiability · `2` HolderRetirement (v2) · `3` RejectResult (v2) · `4` RuleSupport · `5` HandoffView |

### 3.3 Verdicts and reject reasons

Codes 0–15 are **root verdicts** (candidate v6 `RegistryChanges[i].Verdict`, from the fold); codes 16 and up are **EVM-side**
activation-time reasons that appear only in `changes[id].rejectReason`.

| Code | Name | Where |
|---|---|---|
| 0 | Accepted | fold |
| 1 | Conflict | fold: a second change to one shard or partition, a stale expected hash, a second schedule of one rule, `E′ = E` |
| 2 | Duplicate | fold: same kind and payload hash as an earlier Accepted change |
| 3 | Malformed | fold: payload, PDR or PoP list not canonical |
| 4 | Invalid | fold: fails a check of design §6 |
| 5 | BadPoP | fold: a VR-context PoP fails |
| 6 | PastCutoff | fold: schedule cutoff |
| 7 | Earlier | fold: postponement to `E′ < E` |
| 8 | Latched | fold: the rule is already latched |
| 9 | Ceiling | fold: the partition ceiling |
| 16 | CodeMismatch | EVM: SetModule/SetGovernor code hash at activation |
| 17 | HolderMismatch | EVM |
| 18 | AdoptionNotReady | EVM |
| 19 | ActionFailed | EVM: a fully funded ModuleAction `onGovernance` step failed (the module is also Faulted, §14) |
| 20 | NotActive | EVM: ModuleAction names a module that is not active |
| 21 | HolderCeiling | EVM: a ninth holder |

A change rejected by a Boundary bitmap stores `rejectReason = Conflict (1)` as the generic marker for root rejection. The exact fold
verdict is read from the committed candidate's `RegistryChanges` entry. The EVM-side reasons (16 and up) keep their own meanings.

---

## 4. Digests

All EVM-side digests are `keccak256` over `abi.encode` of static words (a concatenation of words).

1. **Member** (10 words, `abi.encode` order): `id u64, generation u64, weight u64, rawWeight u64, rootNodeWord, rootKeyHash,
   evmNodeWord, evmKeyHash, payee address, exposureDigest`. `rootNodeWord = keccak256(utf8(rootNodeID))` (= `evmassign.NodeIDWord`),
   `rootKeyHash = keccak256(rootKey)` over the 33-byte compressed key; likewise for the EVM pair. `h_i = keccak256(member words)`.
2. **`membersDigest`** `= keccak256(MEMBERS_DOMAIN, n, h_1 … h_n)`, members strictly ascending by id.
3. **`changesDigest`** `= keccak256(CHANGES_DOMAIN, n_c, (id, kind, payloadHash) …)`, strictly ascending id; `n_c = 0` for none.
4. **`outputCommit`** `= keccak256(OUTPUT_DOMAIN, network, chainid, VR, resultId, predecessor, attempt, moduleTag, native,
   snapshotDigest, policyDigest, membersDigest, kDigest, changesDigest)`; `chainid` is the uint256 chain id word, `native` a bool word.
5. **Native result id** `= keccak256(VR_RESULT_DOMAIN, network, chainid, VR, lastAcked, attempt, origin)`.
6. **Registration digest** `= keccak256(DOMAIN, network, chainid, VR, msg.sender, id_or_0, keccak(rootNodeID), keccak(rootKey),
   keccak(evmNodeID), keccak(evmKey), payee, nonce)`, `DOMAIN = keccak256("unicity.vr.register")` (register, id 0) or
   `keccak256("unicity.vr.binding")` (proposeBinding). Both keys sign it (§0). Shape: node ids 1–128 bytes, 33-byte compressed keys
   (prefix 02/03) that differ, nonzero payee.
7. **PoA `exposureDigest`** = the custody exposure formula `evmassign.ExposureID` in the VR deployment domain:
   `keccak256(keccak256("unicity.p85.exposure"), network, chainid, VR, resultId, uint256(id))` (§16 FD-6).
8. **`ruleId`** `= keccak256(utf8("unicity.rule/" + name))`.
9. **Retirement dedup key (SealRegistry)** `= keccak256(RECORDS_RETIREMENT_V2, holder, id, generation)` (holder, id, generation as
   uint words).

Vectors: `digest.*`.

---

## 5. Election-module encodings

### 5.1 The ABI envelope

Every packed return is ABI `bytes`: word0 = 32 (offset), word1 = content length, then the content — always a whole number of words,
so no padding follows. VRCodec decodes the **raw returndata** and refuses, in this order:
1. `Oversize`: `returndatasize > MAX_RET[step]` (checked before any copy; a module's revert data is never copied, and the outer
   self-call's return data is ignored);
2. `Envelope`: fewer than 64 bytes, not a whole word, offset ≠ 32, or length ≠ size − 64;
3. `Length`: a content length other than the exact one for the status;
4. `Narrow` / `Bool` / `Range` / `Order` / `Count` / `ResultIdZeroness` / `Padding`: non-canonical content.

### 5.2 `elect` (exactly 64 + 96)

Content `outcome u8, ready bool, resultId`. `outcome ∈ 0..3`; `resultId ≠ 0` **iff** outcome = Reserved; `ready = 1` only with
Reserved.

### 5.3 `outputOf`

- Ready: exactly `64 + 32 + 192 + 320·n`, `1 ≤ n ≤ 16`: status word `0`; header `resultId, predecessor, attempt u64, snapshotDigest,
  policyDigest, n`; then n members (§4.1), strictly ascending id. n must equal the member count. The 16-member maximum is 5,408 bytes;
  5,409 is refused.
- Pending / NotMine: exactly 64 + 32 (status 1 or 2). Status 3 (NotReady) is not an `outputOf` status.

### 5.4 `adoptionReady` (exactly 64 + 32) and void steps

Status ∈ {0 Ready, 3 NotReady}. A void step (`attach`, `detach`, `onRecords`, `onResolved`, `onGovernance`) returns exactly 0 bytes.

### 5.5 Metadata getters

Static ABI words, never an envelope, at most 32 × 8 = 256 bytes, exact per getter: `moduleTag` 32, `capabilities` 32 (uint32),
`gasBounds` 256 (eight uint64), `maxElectionInterval` 32 (uint64), `liabilityHolder` 64 (address, bytes32). Read at queue and
activation only, each with a 50,000-gas staticcall.

### 5.6 `Context` (the `elect` argument, 8 words = 256 bytes)

`origin, progress u64, ucTime u64, knownRootEpoch u64, lastAcked, limits, dueWork u32, forceRemoved u16` with
`limits = nMin << 64 | nTarget << 32 | nMax` (bits 0–31 nMax) and `forceRemoved` bit i set iff `committee()[i]` (ascending id) has a
Scheduled ForceRemove.

### 5.7 `AttachContext` (the `attach` and `adoptionReady` argument)

12 header words, then n × 10 member words, then `initData` zero-padded to a word:
`version (=1), lastAcked, knownRootEpoch u64, progress u64, ucTime u64, identityCount u64, liabilityNamespace (= VR address),
previousModule address, previousTag, holderIndex u8 (0xff: not a holder), n (1..16), initDataLength (≤ 16 KiB)`. The members are
the committee in force with captured bindings and generations, ascending id.

Vectors: `codec.elect`, `codec.output`, `codec.adoption`, `codec.void`, `codec.metadata`, `codec.context`, `codec.attach`.

---

## 6. Change kinds

### 6.1 Payloads (`abi.encode`, strict)

| Kind | Payload |
|---|---|
| 1 SetModule | `(address module, bytes32 codeHash, bytes initData)` |
| 2 ModuleAction | `(address module, bytes action)`; PoA actions are `abi.encode(uint64 action, uint64 id)`, 1 Admit · 2 Remove · 3 ConfirmExit |
| 3 SetGovernor | `(address governor, bytes32 codeHash)` |
| 4 CommitteeLimits | `(uint32 nMin, uint32 nTarget, uint32 nMax)` |
| 5 FeeParams | `(uint64 baseFeeFloor, uint64 changeDenominator, address feeCollector)` |
| 6 ReplaceAggregatorValidators | `(uint32 partition, bytes shard, bytes32 expectedOldPdrHash, bytes successorPdr, bytes pops)` |
| 7 AddPartition | `(bytes pdr, bytes pops)` |
| 8 UpdatePartition | `(uint32 partition, bytes shard, bytes32 expectedOldPdrHash, bytes successorPdr)` |
| 9 ScheduleActivation | `(bytes32 ruleId, bytes32 releaseDigest, uint64 rootEpoch, uint64 notBeforeUcTime, string label)` |
| 10 ForceRemove | `(uint64 id)` |

Strict decoding accepts exactly `abi.encode` output: dynamic tails in field order directly after the head (canonical offsets), zero
padding, narrow integers zero-extended, and no trailing bytes. This is byte canonicality only: a `string` is any bytes (no UTF-8 rule)
and no field has a length rule beyond the 16 KiB payload bound. `shard` is bft-go-base `ShardID.Bytes()` (a non-canonical form names
no installed shard and is Invalid in the fold); `pdr`/`successorPdr` is the canonical CBOR PDR (CBOR tag 39008 around its array);
`pops` is the canonical CBOR array of `evmassign.PoP` (`[nodeId, key, signature]`), one per validator in validator order; `null`
(`0xf6`) is not an array and is Malformed, while an empty array where validators need proofs is BadPoP.
`expectedOldPdrHash` is `evmassign.PDRHash`.

**VR-context PoP** (kinds 6, 7): each validator key signs `CBOR(["UNICITY_VR_CHANGE_POP", 1, network, VR, changeId, partition, shard,
keccak256(pdr), nodeId])` with `network` the root network id (uint), VR the 20-byte address, `changeId` the id VR assigns at queue.

### 6.2 Queue-time checks (structural)

Payload ≤ 16 KiB and the exact shape; fewer than 32 pending (`TooManyPending`). Per kind, exactly the design's checks:
SetModule/SetGovernor a nonzero address and code hash (what "code present, the hash matches" needs of the payload; code presence and
metadata are VR's chain checks); CommitteeLimits `1 ≤ nMin ≤ nTarget ≤ nMax ≤ 16`; FeeParams the ureth `BlockProfile.validate`
equivalent (§12) plus a nonzero collector; ScheduleActivation `rootEpoch ≥ knownRootEpoch + 3` (`ScheduleTooEarly`) and
`notBeforeUcTime ≥ ucTime + 3,600` (`ScheduleTooSoon`); ForceRemove an id of the committee (`NotInCommittee`) and fewer than 4
pending (`TooManyForceRemoves`). Two additions, recorded as freeze decisions: a nonzero `ruleId` (FD-24) and an AddPartition PDR
whose partition id VR can read (`UnreadableScope`, FD-25). An empty ModuleAction and a label of any length are admitted. Vectors:
`change.queue`.

### 6.3 Binding selection and scopes

Every change has a **binding scope** (`ChangeScope`, design §3.5.1 "singleton per output"): its kind for 1, 3, 4 and 5; its shard
`(partition, shard bytes)` for kinds 6 **and** 8, which share it, so one output changes a shard at most once; its partition for kind
7; its `ruleId` for kind 9; none for 2 and 10. VR reads the kind 7 partition from the PDR's leading bytes without a CBOR decoder:
the tag head `d9 98 60` (39008), a shortest-form array head of at least three items, then three shortest-form unsigned integers
(version, network id, partition id ≤ 2^32−1).

Selection scans Scheduled changes in ascending id and binds while ≤ 8 root-side (kinds 6, 7, 8, 10), ≤ 16 total, Σ payload ≤ 64 KiB
and the change's scope is not yet bound in this output. A change that does not fit — including a second change of a scope — is
**deferred** and stays Scheduled for a later output; it is never bound to be rejected. A ForceRemove binds only if the chosen trial
performs it; ModuleAction never binds. Vectors: `change.binding`, `change.scope`.

---

## 7. Root records

| Kind | Width | Words |
|---|---|---|
| 1 SessionClosed | 32 | resultID |
| 2 Ack | 128 | resultID, replacedHRound u64, offset u64, firstRound u64 |
| 3 RecoveryAck | 288 | resultID, recoveryAssignmentID, jOffset, jFirstRound, jHRound, kOffset, kFirstRound, kRootEpoch, kEvmEpoch (u64) |
| 4 Closure | 192 | assignmentID, hRound u64, hRecordID, terminalRoot, exposureDigest, keyHistoryDigest |
| 5 Retirement | 96 | id u64, generation u64, refDigest (pre-VR generations only) |
| 6 **Boundary** | 224 | resultID, changesEpoch u64, installedRootEpoch u64, installedShardEpoch u64, activationRound u64, recovered bool, rejectedBitmap u16 |
| 7 **OutputRejected** | 128 | resultID, reason u8, memberId u64, readyBitmap u16 |
| 8 **HolderRetirement** | 128 | holder u8 (< 8), id u64, generation u64, refDigest |

- **Boundary:** `resultID ≠ 0`; `installedRootEpoch = changesEpoch` for a primary and `changesEpoch + 1` when `recovered`;
  bit i of `rejectedBitmap` (LSB = entry 0) is the i-th `RegistryChanges` entry; `installedShardEpoch` is K's on recovery, else J's.
- **OutputRejected:** `reason ∈ 1..3`; `memberId ≠ 0` only with Invalid (the member the admission failure names, else 0);
  `readyBitmap ≠ 0` only with Expired (bit i: the i-th successor by ascending id was ready).
- **Gas pricing inputs** (ureth `records.rs`): the admission charge stays `2000 + 16·bytes + 1000·entries`, the companion cap 16,384
  bytes and 32 entries, and `IMPORT_EXECUTION_GAS` (measured on nine-word records) still bounds the SealRegistry part, because kinds 6–8
  are at most seven words. VR's per-record work is `HookRecordGas` (design §3.3.4), measured by VT-02.

Vectors: `record.decode`, `record.width`, `record.gas`.

---

## 8. Root controls in VR mode

A VR-mode control keeps the P85 control's ten-element shape under its own tag, so the op shape is self-describing:

```
["UNICITY_VR_CONTROL", network uint, chainID bstr32, registry bstr20 (= VR), orderingEpoch uint, orderingRound uint, op uint, context, data bstr, witnessHash bstr32]
```

| Op | Context | Data | Projects |
|---|---|---|---|
| 1 CloseLiability | `[closedEpoch uint ≠ 0, bundleSemanticID bstr32]` | Closure (192) | Closure |
| 2 HolderRetirement v2 | `[evmBlockHash, evmStateRoot]` | HolderRetirement (128) | HolderRetirement |
| 3 RejectResult v2 | `[predecessorBodyID, attempt uint, evmBlockHash, evmStateRoot]` | OutputRejected (128) | OutputRejected, then SessionClosed(resultID) |
| 4 RuleSupport | `[commitments]`: 1–64 SupportCommitment (§10.4), strictly ascending by (stakingID, ruleId) | empty | none (root-only) |
| 5 HandoffView | `[intentDigest bstr32 ≠ 0, view uint ≥ 1]` | empty | none (root-only) |

Ops 4 and 5 carry no witness: `witnessHash` is 32 zero bytes. The item must re-encode to exactly the bytes read. Vectors:
`control.encode`, `control.project`.

---

## 9. Candidate v6 and Freeze v5

**Candidate v6** is `evmassign.Candidate` field for field, in the same order, with `Version = 6`, then one appended field:

```
[Version=6, Kind, Network, Predecessor, Attempt, RootMembers, OldShardEpoch, OldActiveHash, Assignment, PoPs, Supersedes, Bindings,
 Identities, Authorization, ReplacedAssignment, Changes=null, SourceRef (32 bytes, the VR resultId), RegistryChanges]
RegistryChange = [ID uint, Kind uint, Payload bstr, Verdict uint]
```

wrapped as `CBOR(["UNICITY_H3_EVM_ASSIGNMENT_CANDIDATE", candidate])`, at most 256 KiB; the digest is SHA-256 of that. `Changes` is
`null`: the evmassign changes (kinds 1, 2, 3) are derived from the Accepted entries of kinds 6, 7, 8 at verification, so payloads
appear once. `RegistryChanges`: strictly ascending ids, ≤ 16, ≤ 8 root-side, Σ payload ≤ 64 KiB, each ≤ 16 KiB, never ModuleAction,
at most one entry per binding scope (§6.3), verdict ≤ 9, and kinds 1, 3, 4, 5, 10 always Accepted. Every list field is an array,
the empty PoP list of the unsigned candidate included (§0).

**Freeze v5** companion: `CBOR(["UNICITY_VR_FREEZE", 5, [candidate bstr, ViewCertificate, RuleSupportEvidence, witness bstr]])`, the
candidate equal to the certificate's `Assembly.Candidate`, the witness over exactly one account (VR at the pinned address and code
hash), and

```
RuleSupportEvidence = [refs [bstr32], fresh [SupportCommitment], kReadiness [Readiness]]
```

- `refs`: SHA-256 of committed support-table commitments (§10.4), strictly ascending, at most 1,024;
- `fresh`: commitments strictly ascending by `(stakingID, ruleId)`, at most 1,024;
- `kReadiness`: this intent's K-member readiness messages, at most 16. Each carries at least one commitment, and all of its
  commitments name one stakingID; the list is strictly ascending by that stakingID, so a second readiness of one K member is refused.

Strict order refuses every duplicate. `DecodeFreezeV5` accepts exactly the canonical encoding.

Vectors: `handoff.candidateV6`, `handoff.freezeV5`.

---

## 10. Handoff view protocol

### 10.1 Source and Intent

```
Source = [resultId bstr32, evmBlockHash bstr32, evmBlockNumber uint, certRootRound uint, outputCommit bstr32]
Intent = [version=1, network uint, genesis bstr32, predecessorBodyID bstr32, attempt uint, anchorRound uint, Source, candidate bstr]
intentDigest = SHA-256(CBOR(["UNICITY_VR_HANDOFF_INTENT", Intent]))
```

`candidate` is the canonical v6 encoding of the unsigned candidate (PoPs empty, verdicts set). `anchorRound = max(certRootRound,
attemptOpenRound)`; `EarliestActivation = anchorRound + 16` is an earliest bound only.

### 10.2 PoP and Assembly

```
PoPOffer = [intentDigest, evmNodeID text, PoP]                  PoP = evmassign.PoP over evmassign.PoPMessage, by the EVM key
Assembly = [intentDigest, slot uint, candidate bstr, sig]       sig by the assembler's root key over
           CBOR(["UNICITY_VR_HANDOFF_ASSEMBLY", 1, intentDigest, slot, SHA-256(candidate)])
```

`slot` is the committed view number; `candidate` is the canonical v6 encoding with one PoP per member in EVM-node order.
`AssemblerOrder`: incumbents ascending by `SHA-256(intentDigest ‖ utf8(nodeID))`; the assembler of slot s is `order[s mod n]`.

### 10.3 Readiness and the certificate

```
Readiness = [intentDigest, slot uint, candidateDigest, bodyID, ruleSupportDigest, commitments [SupportCommitment], receipt bstr,
             trustBaseSig bstr, envelopeSig bstr]
envelopeSig by the member's root key over
  CBOR(["UNICITY_VR_READINESS", 1, intentDigest, slot, candidateDigest, bodyID, ruleSupportDigest, SHA-256(trustBaseSig)])
ViewCertificate = [Assembly, [Readiness]]
```

`receipt` is `q3format.EncodeReceipts` of the **singleton set** `{[nodeID, signature]}`: the member's own q3format receipt over
`ReceiptContext{network, genesis, predecessor, attempt, candidateDigest, bodyID, config}` (message `q3format.ReceiptContext.Message`),
named for the member's root node id. Freeze merges a certificate's singletons into the set `q3format.VerifyReceipts` takes; a receipt
set of another size or for another node is refused. `trustBaseSig` signs the successor trust base derived from the intent. A certificate carries **exactly one** readiness per successor member, in the order of the
candidate's identities (ascending StakingID), each naming the assembly's `(intentDigest, slot, SHA-256(candidate), bodyID)` and
carrying commitments whose `ruleSupportDigest` it states and the singleton receipt of that member.

### 10.4 Rule support

```
SupportCommitment = [network uint, stakingID bstr32, generation uint, rootKeyHash bstr32, bindingRef bstr32, ruleId bstr32, releaseDigest bstr32, sig]
sig by that binding's root key over CBOR(["UNICITY_VR_RULE_SUPPORT", 2, network, stakingID, generation, rootKeyHash, bindingRef, ruleId, releaseDigest])
commitment digest = SHA-256(CBOR(commitment))                     (the Freeze reference)
ruleSupportDigest = SHA-256(CBOR(["UNICITY_VR_RULE_SUPPORT_SET", 1, commitments]))   one member's commitments, strictly ascending ruleId
```

`bindingRef` is the registry binding ref `keccak256(abi.encode(rootNodeWord, rootKeyHash, evmNodeWord, evmKeyHash, payee))` of the signing member. A commitment counts only for the exact binding (stakingID, generation, rootKeyHash, bindingRef), so a rotation of any binding part, an EVM-key-only rotation included, invalidates it and the support table drops it on pruning.

### 10.5 HandoffView replay and timeouts

Replay-valid iff (in this order of refusal): the intent is derivable and its source valid (`IntentNotDerivable`);
`view = committedView + 1` and the backoff agrees (`NotNextView`); no Prepare committed for the attempt (`PrepareCommitted`); the only
HandoffView of its block (`NotSoleHandoffView`); block UC time ≥ `openTime(view−1) + T(L, view−1)` (`BeforeReplayFloor`; a `never`
deadline or a carry is never met). `openTime(v)` is the committed UC timestamp of the block that opened view v; view 0 opens at the
anchor block.

`T(L, v) = 10 · 2^(L + ⌊v/n⌋)` seconds, `never` when the exponent is ≥ 37 or T > 2^40; deadlines add with a carry check. Replay uses
only this committed `openTime` floor.

**Live-vote residence rule** (a voting rule every honest root applies, not a premise): a root votes for a proposal carrying
`HandoffView(I, v+1)` only once `⌈T(L, v)·1000·(1+ρ)⌉` ms have passed on its **local monotonic clock** since it first held the
opening commit of view v. A restart or re-learning resets that start to the re-learning time. A root that is not yet eligible defers its
vote; it never marks the block invalid. Only ρ (the drift bound) and the adequacy `T ≥ T_req = ⌈D(1+ρ)⌉ + 1` s are premises. Local
timers sleep in chunks of at most 3,600 s and re-check; no `time.Duration` appears in consensus code.

### 10.6 Backoff state

```
HandoffBackoff = [level u8 ≤ 9, epoch uint, attempt uint, n uint (1..16), intent bstr32, lastView uint, prepared bool, settled bool]
digest = SHA-256(CBOR(["UNICITY_VR_HANDOFF_BACKOFF", 1, HandoffBackoff]))
```

`incLevel`, `decLevel`, `ViewTimeoutSeconds` are design §5.5.3 verbatim (`vrschema/backoff.go`). `ApplyBlock` applies a committed
block's controls in payload order against the stored identity — HV (`intent = 0 ∧ v = 1` binds, or `intent = I ∧ v = lastView+1`), PR
(for the stored attempt), FZ (for the stored, prepared attempt; `level := decLevel(level, v*, n)`, settled) — and then the Open step
once: if `PlannableAttempt(control after the block, round)` is defined and differs from the stored identity, settle an unsettled
attempt (`prepared`: level kept; else `incLevel(level, lastView, n)`) and reset to the new identity with the current committee size.
Undefined (including `k = 2^64−1`, which planning reports as `ErrHandoffApproval`) is a no-op. A control for a newly opened attempt is
valid only from the next block. `PlannableAttempt`: idle → 0; aborted at k → k+1; prepared at k with round > OrderedRound + 48 →
k+1; otherwise undefined. A Freeze is in time iff its block round ≤ OrderedRound + 24.

Vectors: `handoff.*`, `backoff.*`, `view.*`.

---

## 11. Activation schedule

`ScheduleActivation` appends `{ruleId, releaseDigest, E, T, state, changeId}` (§2.4) at its Boundary; the latest non-Superseded entry
of a rule is effective. Fold verdict for a candidate with successor epoch `e`:
1. `e > E − 2` (or `E < 2`): **PastCutoff**;
2. the effective entry is Latched: **Latched**;
3. against an effective entry `E_cur`: `e > E_cur − 2` → PastCutoff; `E < E_cur` → **Earlier**; `E = E_cur` → **Conflict**; `E > E_cur`
   supersedes;
4. a second schedule of the same rule in one list: **Conflict**.

**Prepare time gate:** for every effective schedule with `E ≤ e_J + 1` (which includes J's recovery epoch), the Prepare's UC time is
≥ `notBeforeUcTime` (`ActivationNotBefore`). It is a gate, never a verdict.

**Latch, two events.** A rule latches permanently
1. **in root history** when the handoff into a root epoch `e ≥ E` commits (H committed), and
2. **in VR** when the EVM applies that handoff's `Boundary`.

The root event does not wait for VR: root history can advance while the EVM's acknowledgement import is delayed (recovery included).
The roots' fold, cutoff and support gates read the **root's committed schedule** (`FoldInput.Schedule`, root-latched entries
included); VR's `activations[]` is what ureth and EVM readers see. A node is under rule r in epoch e iff r's effective `E ≤ e`.
Vectors: `activation.latch` (H committed, Boundary delayed, then imported).
Vectors: `activation.*`, `fold.verdicts`.

---

## 12. Fee profile F(N)

- **Validity** (queue time and every stored set): ureth `BlockProfile.validate` over the generation's fixed `maxGas`, `systemGas`
  and elasticity 2 with the new floor and denominator — all nonzero (`ZeroParameter`), `systemGas < maxGas` (`NoOrdinaryCapacity`),
  `baseFeeFloor ≤ MAX_BASE_FEE = 1 << 62` (`InvalidParentBaseFee`), `(maxGas − systemGas)` even (`UnsupportedProfile`) — plus a nonzero
  collector (`ZeroFeeCollector`). `1 << 62` is accepted, `(1 << 62) + 1` refused.
- **Transition:** at the Boundary in block `B_ack`: `previous := current`, `current := new`, `effectiveBlock := B_ack + 1`.
- **Selection:** `F(N) = current` if `N ≥ effectiveBlock`, else `previous`, read at N−1's post-state.
- **ureth:** the parent reconciles under `F(N−1)` (floor ≤ base fee ≤ `MAX_BASE_FEE`); the child's base fee is
  `clamp(eip1559(parent ordinary gas, F(N).changeDenominator), F(N).baseFeeFloor, MAX_BASE_FEE)` with ureth's integer formula
  (`next_base_fee`, u128 product, increase at least 1); the beneficiary is `F(N).feeCollector`.

Vectors: `fee.validate`, `fee.nextBaseFee`, `fee.transition`.

---

## 13. HolderRetirement witness

Exactly three accounts at P; the verdict refuses, in this order: a handoff in flight (`HandoffInFlight`); `holder ≥ holderCount`
(`UnknownHolder`); the holder account's code hash ≠ `holders[holder].holderCodeHash` (`HolderCodeMismatch`); `retired[holder][id][gen]`
(`AlreadyRetired`); SealRegistry `records.count ≠ records.targetCount` (`RegistryBehind`); the v2 dedup key present
(`RetirementLogged`); holder `cursor ≠ records.count` (`HolderCursorStale`); not `requested` (`NotRequested`); `liveExposures ≠ 0`;
`lotReferences ≠ 0`; `refDigest` ≠ the data's (`RefDigestMismatch`); `maxLiabilityAnchor >` the carrying block's progress
(`LiabilityAnchorAhead`). Vectors: `retirement.verify`.

---

## 14. State machines

`vrschema/vrmodel.go` and `rootmodel.go` are the reference models the state-machine vectors are generated from.

- **Output table** (design §3.4.2): every state × event cell (`output.table`, 74 cells; the six unreachable "Boundary with pair"
  cells, where the Ack before it is an anomaly or a no-op, are omitted). A no-op writes nothing and never reverts; an anomaly sets Inconsistent, emits `RecordAnomaly` and advances the
  cursor.
- **Scope of the models.** The VR and root models are abstractions of the rules they name; anything they do not model is a required
  precondition of the implementation, cited here, and is not waived by the model's silence.
- **Reservation gates** (module and native alike), in this order: not Inconsistent; VR cursor = SealRegistry imported count
  (`CursorBehind`); no open output (`OutputOpen`); no pending pair (`PairPending`); a fresh nonzero id; native only when Faulted or
  Stalled, module only from the active module; every bound id Scheduled. Native repair also needs Scheduled boundary work to bind
  (`NoScheduledWork`) and `MIN_EPOCH_GAP` progress since the epoch's first ordinary round (`EpochGap`), design §3.6.2. A module
  reservation's due rule (design §3.7.2) and the remaining §3.6.2 preconditions (no open output, `pendingPair == 0`) are the
  module's and VR's own, outside these vectors.
- **Release:** at SessionClosed the bound changes return to Scheduled; at Boundary they become Active or Rejected by the bitmap;
  each exactly once (`Released` counts). Replay of an applied index is never re-applied; a new malformed entry is an anomaly.
- **Pointer switch** (`switch.sequence`), design §3.6.1: the code-hash and liability-holder checks; `adoptionReady` if
  `ADOPTION_CHECK`; then the old module's `onRecords` through and including the switching Boundary; detach old; set the pointer and
  metadata; attach new; allocate the holder entry only if attach succeeded (P85 custody is holder 0); the remainder of the batch to the
  new module. A refused switch (code or holder mismatch, adoption not ready) makes no module call before the rejection, and the old
  module then receives the whole batch.
- **S2a** (`s2a.*`): lapse, cooldown and pre-Freeze abort keep R (Reserved, Published, Invalidated or Rejected; a Reserved R has no
  Prepare and becomes rejectable only at its expiry); a RejectResult ordered first
  refuses a later Prepare/Freeze before the EVM imports the closure, and a repeated RejectResult is refused; Prepare first then a
  rejection only after cooldown and its due condition; a Prepare needs a defined next attempt (an exhausted counter is
  `ErrHandoffApproval`, an undefined one `NoPlannableAttempt`, and the cooldown comparison never overflows: `root.prepare`); success with Active and Rejected changes and a split Ack/Boundary import; abort
  of a retained primary closes R, a recovery abort does not; the cursor gate; Inconsistent completing a committed pair.
- **RejectResult due** (`reject.due`): Reserved/Published at `progress ≥ expiresAtProgress` → Expired; Invalidated → immediately;
  Published with a deterministic admission failure → Invalid; otherwise never.
- **Change lifecycle** (`change.lifecycle`): both delays (2,000 progress and 3,600 s, captured at queue); cancel only Queued/Scheduled;
  ModuleAction executes into the active module only, through a contained `onGovernance` step with the design §3.3.1 outcome classes:
  success makes it Active; a fully funded failure (revert, cap exhaustion, malformed or oversized return) rejects it (ActionFailed)
  **and faults the module** (Faulted, never over Inconsistent); too little gas reverts `BudgetShort` with the change still Queued and
  health unchanged; a module that is not active rejects it (NotActive) with no call and no fault. The 33rd pending change is refused.
- **Fold** (`fold.verdicts`, `fold.ackGate`, `fold.proofConfig`) over a full `FoldInput` with real PDRs and signed VR-context PoPs.
  For each change, in this order: Duplicate (same kind and payload hash as an earlier **Accepted** change); Malformed (the payload, or
  an embedded PDR or PoP list, not canonical; every embedded encoding is checked before the scope, so a Malformed change claims no
  scope and is Malformed even when its scope is already claimed); Conflict when its scope was already claimed by an earlier
  well-formed change of the list **whatever that change's verdict** (defensive: a bindable list never has one); then the kind's rules — stale expected hash Conflict;
  Invalid for design §6, including the **protocol proof-configuration predicate** (below) and a kind 6 or 8 change whose target shard
  is not in `FoldInput.Installed`, **also when an earlier Accepted AddPartition of the same list adds it** (FD-29), and an AddPartition
  whose decoded ShardID has a nonzero bit length (FD-30); Ceiling; BadPoP; PastCutoff, Earlier,
  Latched. Only an Accepted change updates the tentative state (installed PDRs, partition count, effective schedule) and enters the
  Duplicate set, so a change refused by any check, the proof predicate included, consumes nothing. The shard acknowledgement gate is
  evaluated at Freeze, not in the fold: verdicts are identical at intent, readiness and Freeze.
- **Proof configuration** (`ProofConfigValid`, kinds 6, 7 and 8, before any tentative mutation): an absent, empty or `none`
  `proof_type` is valid; otherwise it must be one of `exec`, `aggregator_rsmt_v1`, `aggregator_zk_v1`, `sp1`, `light_client`
  (`UnknownProofType`; `risc0` has no verifier); `sp1` needs a nonempty `vkey_path` and a `chain_id`; `light_client` a `chain_id`; a
  `chain_id` is the canonical decimal spelling of a uint64 (ASCII digits only, no sign, whitespace, separator or prefix, no leading
  zero except `0` itself, at most 2^64−1: `FormatUint(ParseUint(s), 10) == s`; FD-28). **Local build support never enters a verdict:** a protocol-valid type the local binary
  cannot verify (`zkverifier.IsProofTypeAvailable` false) is still Accepted; that root fences at installation (`ProofSupportMissing`),
  as for an unknown activated rule.
- **View judgments** (`view.trace`): the reference timing model in `viewtrace.go` — roots of weight 1, Byzantine roots vote for
  anything replay-valid at once, silent roots never vote, an honest root becomes eligible at `seen + ⌈T(1+ρ)⌉` (the residence rule; a
  restart replaces `seen` with the re-learning time); the next view commits no earlier than the moment strictly more than 2/3 are
  eligible. `c_v` is when the first honest root holds the opening commit, and `D = Λ + δ + π_a + π_m` is measured **from `c_v`** (Λ
  already contains the learning spread), so a view completes iff its assembler is honest and cooperating and `c_v + D` is not after
  that moment. Validity (the replay floor) is
  exact; the liveness quantities are model outputs, not guarantees. `view.replay`, `view.leaderPolicy`, `view.certificateAdmissible`
  freeze the replay rule, the proposer priority and the certificate admission rule (any retained view ≤ the committed view, until the
  first committed Freeze).

---

## 15. Vectors

| File | Content |
|---|---|
| `vr-layout.json` | §2 as data: slots, packed fields, domains |
| `constants.json` | §1 |
| `encoding.json` | `domain`, `codec`, `digest`, `record`, `change`, `control`, `handoff` |
| `statemachine.json` | `output`, `s2a`, `root`, `change`, `fold`, `backoff`, `view`, `reject`, `switch`, `activation`, `retirement` |
| `arithmetic.json` | `arith`, `fee` |
| `storage.json`, `storage-flat.json` | §2.8 (Go) |
| `storage-forge.json` | §2.8 written by forge (unicity-pos-contracts `test/vr/fixtures/`) |
| `MANIFEST.sha256` | `sha256sum` lines over every file above |

The generator derives most expectations from the reference, so they show determinism and cross-language agreement. They are not independent evidence that the text is right. The boundaries the reviews named are different: the null-versus-array list encoding, invalidation reason 0, the switch order, scoped deferral, the PDR partition head, the proof predicate, the fold's rejected-first and invalid-proof cases, root attempt exhaustion and cooldown overflow, the native-repair preconditions, the root latch and the view completion times. For those the generator checks the reference against expectations written by hand from this text, and `independent_test.go` repeats them as literal tests.

Regenerate with `go generate ./vrschema` (it keeps the imported `storage-forge.json` and re-manifests it). Consumers pin a file by its
manifest line. Consumer stubs: unicity-pos-contracts `test/vr/` (storage fixture and encoding consumer) and ureth
`crates/unicity/execution` (record and fee consumer).

---

## 16. Freeze decisions

Each is the reading most consistent with the approved chain; each is also in `briefs/owner-questions.md`.

- **FD-1 VR storage namespace.** VR uses ERC-7201 `unicity.vr.registry.v1` with the explicit map of §2.1. The design fixed only the
  liability namespace; VR is immutable without a proxy, but a namespace keeps the proven slots independent of VT-02's internal state
  (reserved ranges V+16…31 and V+38…63).
- **FD-2 `scheduledAt` moved to word3.** The design packs `kind | state | rejectReason | notBeforeProgress | notBeforeTime |
  activeRootEpoch | scheduledAt` into one word, which is 35 bytes. `scheduledAt` (with `payloadLength`) is word3.
- **FD-3 Domain texts.** Every unnamed domain is `keccak256("unicity.vr.<name>.v1")`; `GENESIS_RESULT` and `REGISTRY_NATIVE` are domain
  words, not other constants. The registration domains keep the design's exact strings without a version suffix.
- **FD-4 Code numbering** (§3): the design names the states, outcomes and verdicts; their numbers are fixed here, with root verdicts
  1–9 and EVM-only reasons 16–21 kept apart.
- **FD-5 Invalidation reason 0** is the storage sentinel "not invalidated": `invalidate(R, 0)` by the source is a no-op in every state, so
  `invalidate` stays total and never reverts for its source. 1 LOST is the only economic reason; every other nonzero reason is
  output-level.
- **FD-6 PoA `exposureDigest`.** The corrected design uses "the evmassign custody formulas with deployment = (network word, chain id,
  VR address)". The custody per-exposure formula `ExposureID` takes an assignment word; a module composing an output knows only its
  `resultId`, so the PoA digest is `ExposureID((network, chainid, VR), resultId, id)`.
- **FD-7 `ready = 1` only with Reserved** in `packedElect` (the design states `ready ∈ {0,1}`).
- **FD-8 Context and AttachContext packing** (§5.6, §5.7): the limits word, the `forceRemoved` bitmap index (committee order) and the
  AttachContext header order, version word and `0xff` "no holder" index.
- **FD-9 Record cross-field rules** (§7): `installedRootEpoch = changesEpoch (+1 on recovery)`, `memberId` only with Invalid,
  `readyBitmap` only with Expired, bitmaps are 16-bit.
- **FD-10 VR-mode control tag.** "Op 2 v2 / op 3 v2" are expressed by the tag `UNICITY_VR_CONTROL` on the unchanged ten-element shape,
  so a stateless validator knows the widths; ops 4 and 5 carry empty data and a zero witness hash; RuleSupport takes 1–64 commitments.
- **FD-11 Candidate v6 field order.** v5 fields unchanged, `Changes` null, `RegistryChanges` appended last.
- **FD-12 Postponement with `E′ = E`** is `Rejected(Conflict)`: it neither supersedes nor is earlier (a release-digest change at the
  same epoch needs a postponement). Inside one list the fold's Duplicate rule applies first.
- **FD-13 Message encodings** (§10): the Intent carries the candidate as its canonical bytes (not a nested struct), the CBOR tuples
  and domain texts, readiness ordered by StakingID in the certificate, the support-set digest over ascending ruleId, and
  `RuleSupportEvidence` as three strictly ordered, bounded lists (`kReadiness` by the one stakingID each names). `Readiness.receipt` is
  the singleton q3format receipt set, so the existing receipt-set codec decodes it and Freeze merges the singletons.
- **FD-14 VR-context PoP message** uses the root network id and the change id VR assigns at queue; a signer reads `nextChangeId`, and
  a lost race fails as BadPoP and is re-queued.
- **FD-15 Fold order and verdict mapping** (§14): Duplicate, then Malformed, then the scope Conflict, then the kind's rules; a stale
  expected hash is Conflict; an AddPartition of an already installed id is Invalid; the ceiling has its own verdict; a non-root kind
  that does not decode makes the list unbindable. The proof-configuration check is the frozen protocol predicate `ProofConfigValid`
  inside the fold, before any tentative mutation; the existing `verifyProofConfig`'s build-availability test is not part of it.
- **FD-16 Binding preimages.** Member words commit to node ids and keys by hash; the strings and keys come from VR views. Because a
  later `proposeBinding` may overwrite the staged binding while an output that captured it is open, VT-02 must keep the captured
  preimages retrievable (for example a write-once preimage store keyed by the binding words). This is a VT-02 view, not a proven slot.
- **FD-17 Reservation gate order** (§14): Inconsistent, cursor, open output, pair. With an Ack applied and its Boundary not yet, the
  output is still open, so `OutputOpen` is reported first.
- **FD-18 Backoff state encoding** and `ApplyBlock` treating an undefined identity (including attempt exhaustion) as a no-op.
- **FD-19 View judgment model** (§14) is the frozen model the trace vectors are judged by, with D measured from `c_v` as design §8.3
  defines it; it is not a liveness guarantee.
- **FD-20 Shard bytes** in payloads and keys are bft-go-base `ShardID.Bytes()`.
- **FD-21 SealRegistry v2 dedup key text** `unicity.seal-registry/records.retirement.v2`, following the existing v1 prefix.
- **FD-22 HolderRetirement check order** (§13).
- **FD-23 Network words.** EVM-side `network` is the bytes32 deployment word VR stores at V+0 (opaque, pinned); root-side `network` is
  the uint root network id.

- **FD-24 A zero `ruleId` is refused at queue** (an addition to design §3.5.3): zero is the absent activation entry for every reader.
- **FD-25 AddPartition needs a readable partition id at queue** (an addition): VR must know the partition to defer a second addition of
  it in one output (§6.3); a PDR whose leading bytes are not the canonical tag, array and three uints is refused (`UnreadableScope`).
- **FD-26 Scope claims are made by the first well-formed change of a scope** (payload and embedded PDR and PoP list canonical) in the
  fold, whatever its later verdict (so a rejected first
  schedule of a rule still makes a second one Conflict); binding selection defers instead, so this rule is defensive.
- **FD-27 Proof-configuration support is a fence, not a verdict:** a root whose build cannot verify an Accepted protocol-valid proof
  type refuses to install that configuration (`ProofSupportMissing`) and needs a build with the support.
- **FD-28 `chain_id` spelling.** The design names the parameter, not its grammar; `strconv.ParseUint` alone accepts leading zeros.
  The proof predicate accepts only the canonical decimal spelling, so one value has one accepted text. Every existing PDR and fixture
  (`3`, `1337`, `31337`, the 2^64−1 vector) already uses it.
- **FD-29 No change of a partition added in the same list** (correction, astra VT-06d/e review, 2026-11-17). A kind 6 or 8 change
  targets an installed shard: one absent from `FoldInput.Installed` is Invalid, including a shard present in the tentative state only
  because an earlier Accepted AddPartition of the same list adds it. The AddPartition stays Accepted and installs its epoch-0
  configuration; the later change is Rejected by its bitmap bit. Binding selection may still bind both (their scopes differ). The
  first frozen fold accepted such a change against the tentative addition, which the acknowledgement gate then refused at Freeze
  (the new shard has no acknowledgement fact), blocking every output; it is a correction of the v1 fold, not compatible behaviour
  for an already running generation. Put the final parameters and members in the AddPartition itself.
- **FD-30 A new partition is one unsplit shard** (correction, astra VT-06d/e F1 ruling, 2026-11-17). Kind 7 adds one PDR, so one
  shard, and the only valid one-shard scheme is the unsplit shard: an AddPartition whose decoded `ShardID` has a nonzero bit length
  (any non-empty bitstring, `ShardID.Length() != 0`; the serialized byte string of the empty id is not empty) is **Invalid**, judged
  with the other kind 7 rules: after Duplicate, Malformed and the scope Conflict, before Ceiling and the PoPs, and without changing the
  tentative state or the partition count. A canonically encoded non-empty id is not Malformed. Kind 8 keeps the shard id it names
  exactly, so an update of one shard of an installed split partition is unaffected. The first frozen fold accepted such an addition,
  which every root then failed to execute at the first block of the epoch (the sharding scheme refuses a single non-empty shard). The
  complete root-side PDR rules are: canonical decoding (else Malformed); `IsValid` (version 1, nonzero network, partition and type,
  no custom type, `TypeIDLen` a whole number of bytes at most 32 with 0 allowed, `UnitIDLen` a whole number of bytes in [64, 512],
  `ShardID.Length() < UnitIDLen`, `T2Timeout ≥ 800 ms`, valid members with unique node ids); for kind 7 also epoch 0, `EpochStart` 0, the
  root network, a partition neither installed nor reserved, not the EVM type, the empty shard, 1..256 validators in strictly increasing
  node id order with unique valid 33-byte keys and stake 1, the proof predicate, the ceiling and one VR-context PoP per validator in
  validator order; for kind 8 the same network, partition, shard and type, the same `TypeIDLen` and `UnitIDLen`, the validator list
  unchanged in order (node id, key, stake) and still nonempty with unique keys, epoch + 1, `EpochStart` 0 and the proof predicate.
---

## 17. What this does not freeze

- Gas figures (`ElectGas`, `HookRecordGas`, `STEP_BUDGET`, `OUTER_RESERVE`, `cap_*`): measured by VT-02 on the compound paths.
- `LIFETIME` stays provisional until the design §13 measurements.
- `π_max`'s value (VT-05b), the premise values marked measured, and the VR-internal storage of V+16…31 and V+38…63.
- The PoA composer's arithmetic (VT-03 vectors against an exact-rational model) and the AC-LR reward fixtures (VT-04/VT-15).
