# D1 — Clock, certificate and canonical root-input profile

Issue: [#3 D1](https://github.com/ristik/bft-core/issues/3) · Milestone: M0 ·
Prereq: [#2 R0](https://github.com/ristik/bft-core/issues/2) ·
Profile version: **v1** · Status: **proposed for freeze**

This is the implementable profile D1 owns: every field of the canonical root
input, its domain, its deterministic encoding, its authoritative source, how the
authorizing certificate is selected, and the per-round-type behaviour for
genesis / successful / quiet / repeat / canceled rounds. The executable model and
independently generated vectors are in [`evmroot/`](../../evmroot); the decision
record is [ADR 0003](../adr/0003-canonical-root-input-profile.md).

Consumers (the reth fork's privileged call, `F2`'s adapter derivation, any
offline verifier) MUST NOT invent a domain, format, parameter or transition not
fixed here. An unresolved point is a D1 revision, not an implementation choice.

Specification basis: `docs/pos/specification/evm-partition.tex` §§ Rounds and
Blocks, Round Parameters, Seal Feed, Validator Set; `appendix-evm.tex` §§ Round
Parameter Derivation, Seal Transaction, Seal registry state, Genesis State;
`bft.tex` (UnicitySeal / UnicityCertificate / TechnicalRecord).

---

## 1. Two hash worlds, kept apart

| World | Function | Encoding | Used for |
|---|---|---|---|
| **Unicity** | SHA-256 | deterministic CBOR (§3) | root-origin identity, `rootInput` / `extraData` commitment, `prevRandao`, `parentBeaconBlockRoot`, `TRHash`, `ShardConfHash`, Unicity Tree root |
| **Ethereum** | Keccak-256 | RLP | EVM block hash `h_b = Keccak256(RLP(hdr))`, parent hash `h_parent`, receipt/state trie proofs |

The two never compose. `rootInput` (a Unicity-world CBOR structure) *contains*
`h_parent` and `IR.h_b` (Ethereum-world 32-byte digests) as **opaque byte
strings**; they are carried verbatim and never re-hashed with SHA-256 as part of
forming the commitment. Equally, no Unicity digest is ever fed through Keccak.

This is the single most common way an independent reimplementation diverges, so
the vector set (`evmroot/testdata/vectors.json`) pins both a `rootInput` CBOR
byte string and its `extraData` SHA-256 for cross-checking.

## 2. Field inventory and authoritative source

`O_-` (root origin) — the signature-free import from the committed certification
statement authorizing the shard round:

| Field | Symbol | Authoritative source | Type |
|---|---|---|---|
| network id | α | `UnicitySeal.NetworkID` | uint |
| root round | r | `UnicitySeal.RootChainRoundNumber` | uint |
| root epoch | eᵣ | `UnicitySeal.Epoch` | uint |
| reference time | tᵣ | `UnicitySeal.Timestamp` (seconds) | uint |
| Unicity Tree root | u | `UnicitySeal.Hash` | bytes(32) |
| certified shard input | IR | `UnicityCertificate.InputRecord` → `(n,e,h',h,t,h_b)` | array (§3) |
| technical-record commitment | — | `UnicityCertificate.TRHash` | bytes(32) |
| configuration commitment | — | `UnicityCertificate.ShardConfHash` | bytes(32) |

`rootInput` — the canonical input the privileged seal operation receives and the
header commits:

| Field | Symbol | Source | Type |
|---|---|---|---|
| profile version | v | this profile ⇒ **1** | uint |
| network / partition / shard | α, β, σ | partition configuration (`st=8`) | uint, uint, bytes |
| authorized shard round | n | `TechnicalRecord.Round` | uint |
| certified epoch | e_cert | `O_-.IR.Epoch` (the outgoing epoch the previous IR belongs to) | uint |
| authorized epoch | e_auth | `TechnicalRecord.Epoch` (the epoch the authorized round runs under) | uint |
| last certified EVM parent hash | h_parent | previous certified block's `h_b` (Ethereum); the pinned genesis block hash for every payload authorized before any post-genesis block has been certified, whatever its authorized round (amended by F4a #153, `f4a-seal-registry-contract.md` §7.3) | bytes(32); null **only** for genesis installation (authorized round 0) |
| root origin | O_- | §2 above | array |
| technical record | TE_- | `TechnicalRecord` `(Round,Epoch,Leader,StatHash,FeeHash)` | array |
| pending transitions | D | ordered committed trust-base bodies + handoff acks the EVM is still missing | array of bytes |

### Both epochs are bound — equality is NOT imposed

`rootchain/consensus/storage/sharding.go`'s `nextBlock` handles `prevSI.TR.Epoch !=
prevSI.IR.Epoch`: the previous IR belongs to the outgoing epoch while the
technical record authorizes the successor. `rootInput` therefore binds **both**
`e_cert = O_-.IR.Epoch` and `e_auth = TE_-.Epoch` and classifies the boundary:

| Boundary | Condition | Meaning |
|---|---|---|
| **normal** | `e_auth == e_cert` | ordinary round |
| **handoff** | `e_auth == e_cert + 1` | the committed epoch handoff: this round runs the successor assignment against the last certified parent from the outgoing epoch |
| **invalid** | anything else | rejected (`RootInput.Validate`) |

`h_parent` is the actual last certified EVM parent regardless of the boundary — a
handoff does not reset it. `RootInput.Validate` also enforces `TE_-.Round == n`,
`TE_-.Epoch == e_auth` and `O_-.IR.Epoch == e_cert`. Vector group `epoch_boundary`
covers normal, handoff and both invalid directions; `root_inputs.epoch_handoff_boundary`
is a full tuple across the boundary.

Everything a historical replay needs is inside this tuple. No constituent is read
from node-local configuration, a local clock, a file or a network response
(`evm-partition.tex` "Seal Feed" rule). Vector group `root_inputs[*].self_contained`
records this for each round type.

## 3. Deterministic CBOR

RFC 8949 §4.2.1 core deterministic encoding, restricted to the kinds this profile
uses: unsigned integers (shortest form), byte strings (major 2), text strings
(major 3, the domain strings only), definite-length arrays (major 4), and the
simple value `null` (`0xf6`) for a genuinely absent optional field. No maps, no
tags, no floats, no negative integers, no indefinite lengths. Adding any of these
is a version bump.

`null` vs empty byte string is meaningful: `IR.h_b` is `null` **iff** the round
is quiet (`IR.h == IR.h'`); `h_parent` is `null` **iff** the authorized shard round is 0 (genesis installation) — the first post-genesis payload authorizes round `n ≥ 1` (round 1 unless root timeouts advanced the technical record first) and carries the real pinned genesis block hash. A present digest
is always exactly 32 bytes. `h'` and `h` are never `null` — at genesis they carry
the pinned genesis commitment.

Canonical bodies (element order is normative):

```
O_-      = [ α, r, eᵣ, tᵣ, u,
             [ n, e, h', h, t, h_b ],      ; IR (e = O_-.IR.Epoch = e_cert)
             TRHash, ShardConfHash ]

TE_-     = [ Round, Epoch, Leader, StatHash, FeeHash ]

rootInput = [ v, α, β, σ, n, e_cert, e_auth, h_parent, O_-, TE_-, [ D₀, D₁, … ] ]

extraData = SHA-256( CBOR(rootInput) )      ; 32 bytes, header extraData
```

The reference encoder is `evmroot/cbor.go` — deliberately independent of
bft-go-base's CBOR library so a match is evidence of canonicality, not of shared
defaults. `TestRootOrigin_IndependentCBOROracle` / `TestExtraData_IndependentOracle`
cross-check every canonical byte against bft-go-base's fxamacker `CoreDetEnc`
encoder as a second implementation.

## 4. Domain-separated round parameters

`r = C^r_-.r` (authorizing root round), `n` the authorized shard round.

| Field | Derivation | Notes |
|---|---|---|
| `timestamp` | `max(tᵣ, t_{b-1} + 1)` | monotone EVM counter; may run ahead of real time at sub-second cadence |
| `prevRandao` | `SHA-256( CBOR([ "UNICITY_EVM_RANDAO", r, n ]) )` | deterministic, biasable — **not** a randomness beacon |
| `parentBeaconBlockRoot` | `SHA-256( CBOR([ "UNICITY_EVM_BEACON", r, n ]) )` | derived field; never disseminated, every validator recomputes |
| `fee recipient` | configured fee collector | not round-derived |
| `withdrawals` | empty list | no external balance issuance |
| `extraData` | `SHA-256(CBOR(rootInput))` | §3 |
| `gas limit`, `base fee` | versioned execution rules (`D2`) | builder cannot override; positive base-fee floor is a validity rule |
| `leader` | `TE_-.Leader` | shard leader, not root leader |

Domain strings are ASCII, encoded as CBOR text strings **inside** the array, not
prepended to a byte blob. The array holds `(domain, r, n)` in that order.

### Difference from the prototype (`v0`, non-normative)

`engineapi/params.go` today computes `SHA-256( 0x01 ‖ UnicityTreeRoot ‖ be64(shardRound) )`
for `prevRandao` and `0x02 ‖ …` for `parentBeaconBlockRoot`. That is `v0`:
one-byte prefixes, raw concatenation, keyed by `(u, n)` not `(r, n)`, ASCII
domains absent, and **no `extraData` commitment at all**. `v1` replaces it
wholesale. There is no live deployment on `v0`, so no migration is specified;
`F2` deletes the `v0` derivation. Vector group `domains` shows `v0` and `v1`
side by side for the same inputs so an implementer can confirm which they are on.

## 5. Selecting the authorizing certificate

> The source is the certificate authorizing the proposed shard round, not the
> newest message locally observed. — `appendix-evm.tex`, Seal registry state

A node receives multiple `CertificationResponse`s: duplicates from several root
nodes, and repeat certificates after a shard timeout. An earlier draft of this
profile said "pick the highest root round you have seen for round `n`" — but that
is still local: a proposer that has seen only `C1` and a follower that has also
seen a later valid `C2` would derive different `rootInput`/`extraData` for the
same block. The rule is instead:

### The block binds one certificate; followers validate that binding

1. **Proposer.** Picks *any* certificate that is valid (verified against the
   trust base — D3), authorizes shard round `n` (`TE_-.Round == n`), and is not
   behind the proposer's own seal-registry cursor. It **binds** that certificate
   in the block: `O_-` is committed in `extraData`, and the full `UC_-`/`TE_-`
   travel in the D2 companion data (`sealCompanion.witnesses`).
2. **Follower.** Does **not** re-pick from its own view. It recomputes `extraData`
   from the companion `rootInput` (D2), then runs
   `ValidateBoundCertificate(ref, cert, n, lastAppliedRootRound)`:
   - the bound certificate must be one the follower has verified against the
     trust base;
   - `cert.AuthorizedRound == n`;
   - the bound certificate's `O_-` identity and `TRHash` match the block's
     binding;
   - `cert.RootRound >= lastAppliedRootRound` — the only view-dependent input,
     and it is **committed state** (the seal-registry cursor), identical on every
     node that processed the same certified sequence, not message-arrival order.
3. A **later valid repeat** (same `IR`, higher `r`) that the proposer did *not*
   bind is simply unused for this block; two honest nodes still agree because they
   both validate the one bound certificate. If a follower has *already applied*
   that repeat — the **seal-registry root-round cursor** (`r` recorded in state)
   moved past the bound cert's `r` — it rejects the block, and the round is
   re-proposed against a current certificate. Deterministic given committed
   state. (This is the one cursor a repeat moves; it does **not** move the
   transition or reward cursors — §6.)
4. The **parent** the block builds on and that validation checks continuity
   against is `O_-.IR.Hash` (the last **certified** state, from the bound
   certificate) — never a node's later local execution head. `RoundParams.Parent`
   in the framework is populated from the certificate, and `reconcile`
   (`shardnode/round.go`) exists precisely to bring a diverged local head back to
   the certified parent before building.
5. Before accepting a certificate for verification, `CheckNonEquivocatingCertificates`
   (Yellowpaper "Algorithm 6") still applies; an equivocating pair is fatal.

Vectors: `certificate_selection` covers `node_a`/`node_b` reaching the identical
result despite different observed sets, a stale binding rejected by the registry
cursor, an unverified binding, and a wrong-round binding.
`TestSelection_AsymmetricDeliveryAgrees` and
`TestSelection_LateRepeatDoesNotChangeAcceptedResult` are the model tests.

### Certified round clock

The **certified round clock** (`evmroot/clock.go`) records `r` from the *bound*
certificate in seal-registry state and only ever moves it forward. Protocol
deadlines compare the recorded `r` against a threshold with `>=`, never `==`, and
the trigger fires once even if the feed skipped the exact threshold value
(imports at 98 then 107 still fire a threshold of 100, exactly once — vector
group `certified_round_clock`). A certificate that would move the recorded round
**backwards** is rejected outright — the concrete symptom of arrival-order
selection.

## 6. Round types

| Kind | `IR` shape | Block committed? | Cursors advanced | `rootInput` built? |
|---|---|---|---|---|
| **genesis installation** | authorized round `n = 0`; certified `IR.Round = 0`; `IR.h'`,`IR.h` = pinned genesis commitment; `IR.h_b` = null; **`h_parent` = null** (no block yet) | the pinned genesis block is installed, not executed | origin + assignment installed; transition/reward cursors empty | yes — but it installs, it does not execute a payload |
| **first post-genesis payload** | authorized round `n ≥ 1`: round 1, or a later round when earlier assigned rounds timed out without a block (`ShardInfo.nextRound` advances the technical record on a timeout too); the certified input record is still genesis history (the genesis record, a repeat of it, or a quiet record extending it; nothing certified names a block); **`h_parent` = the real 32-byte pinned EVM genesis block hash**. Amended by F4a (#153), which states the eligibility rule in `f4a-seal-registry-contract.md` §7.3 | yes — the first executed block | root origin (new seal) | yes — committed in `extraData`; the header parent equals `h_parent` (D2 checks this exactly) |
| **successful** | `h ≠ h'`; `h_b` present (32 bytes) | yes | root origin + transition cursor (if `D` non-empty) + reward cursor, **each once** | yes — committed in `extraData` |
| **quiet** | `h = h'` ⇔ `h_b = null` | no block executed this shard round | root origin only (new seal); **not** transition/reward | yes — but no block carries it |
| **repeat** | `IR` byte-identical to previous; strictly greater `r` | no | **none** — no second reward claim for an already-imported interval | no new commitment; the earlier block's `extraData` stands |
| **canceled** | in-flight attempt, discarded at epoch handoff | no | none | the attempt's `rootInput` is **never** committed to a block |

Notes:

- A **governance-shard** successful round produces a block even with zero user
  transactions: the mandatory seal operation mutates seal-registry state, so
  `h ≠ h'`. A quiet `IR` therefore means "no block executed" (e.g. before the
  first block, or a stalled shard), never "a block ran but changed nothing".
- **genesis authentication is an explicit rule**, not a fabricated quorum
  signature over round 0.
- **repeat**: `IR.h_b` may be non-null (it repeats the last good block's hash);
  this is the one case where a non-empty block hash recurs, and
  `CheckNonEquivocatingCertificates` rule 7 permits it only here.
- **canceled**: the shard resumes from the last certified parent under the new
  `TE_-.Leader`; the canceled attempt is never revived under the new assignment.
- Certification, retries and crash recovery never authorize two committed blocks
  for one shard round.

## 7. Chain ID and configuration binding

- `χ` (EVM chain id) is **assigned and registered** against existing network
  allocations and checked network-unique. A truncated hash of some string is not
  a uniqueness proof and is not acceptable as the derivation.
- Every block is invalid unless its chain id equals the configured `χ`.
- `χ` and the full `(α, β, σ)` are bound into every certificate and bridge proof;
  a proof for one `(α,β,σ,χ)` is not interchangeable with another.
- Fixed configuration fields (`st, α, β, σ, χ`, fork schedule, system origin /
  registry addresses, builtin addresses) change only via a new chain or an
  explicit migration record. Policy fields change only through the specified
  activation path.

## 8. Transition cursor and `D`

- Seal-registry `transition cursor` = last acknowledged handoff; imports are
  **ordered with no gaps**.
- `D` in `rootInput` is exactly the ordered list of committed trust-base bodies
  and handoff acknowledgements the importing EVM has not yet applied. Each entry
  is an already-canonical committed body. Its external authentication witness
  (storage proof, endorsement) authenticates `D` but is **not** re-hashed into
  `rootInput`.
- The feed **may skip root rounds** but may **not** silently skip a configuration
  transition or double-count an imported interval. A duplicate `rootInput` cannot
  advance any cursor twice.
- A normal handoff waits for the previous EVM acknowledgement before preparing
  the next, bounding live transition backlog. A restored node replays canonical
  inputs in order or installs an authenticated checkpoint; if missing history
  exceeds the import limit it catches up before voting and never manufactures
  authority from local configuration.

## 9. Acceptance mapping

| D1 acceptance clause | Evidence |
|---|---|
| independent vectors cover alternate valid signature subsets and encodings | two **independently quorum-verified** 4-of-5 secp256k1 subsets against a real `types.RootTrustBaseV1` (threshold 4); `TestRootOrigin_TwoValidSignatureSubsetsAgree` also asserts a 3-of-5 subset **fails** `seal.Verify(tb)`; `RootOriginFromCertificate` byte-identical for both quorum subsets |
| … same commitment on all validators | `RootOriginFromCertificate` reads only committed content (no `Signatures`, no tree paths). The `O_-` projection is the signature-free view; full UC authentication (shard-tree / unicity-tree paths + `seal.Verify`) is a separate step the consumer performs — the two are not conflated |
| … a different authenticated statement | `TestRootOrigin_DifferentAuthenticatedStatementDiffers` — the IR is mutated **and re-certified** (new seal recommitted over the mutated IR, re-signed to quorum, `seal.Verify(tb)` passes) before comparing identities |
| … an independent derivation of the expected canonical bytes | `TestRootOrigin_IndependentCBOROracle`, `TestExtraData_IndependentOracle` — hand-rolled `evmroot/cbor.go` cross-checked against bft-go-base's fxamacker `CoreDetEnc` for the same logical arrays |
| genesis installation distinct from the first post-genesis payload | §6 round-type table; `RootInput.Validate` keys the parent-null rule on the **authorized round** (`ri.Round`), not `Origin.IR.Round`; vectors `root_inputs.genesis_installation` (round 0, null parent) and `root_inputs.first_post_genesis_payload` (round 1, `Origin.IR.Round` still 0, real 32-byte pinned genesis parent; one instance of the row, which since F4a #153 does not require round 1); `TestRootInput_RejectsMalformedWidths` |
| … malformed widths | `RootOrigin.Validate` / `RootInput.Validate` reject non-32-byte digests; `TestRootInput_RejectsMalformedWidths` |
| … genesis, retries, root rounds skipped by the EVM | `root_origins`/`root_inputs` genesis + repeat + `root_rounds_skipped`; round-type table §6 |
| a certified outgoing-IR / new-TR fixture imports the successor assignment, keeps the actual last certified parent | `root_inputs.epoch_handoff_boundary` (`e_cert=1`, `e_auth=2`, `h_parent` unchanged); `epoch_boundary` group; `TestRootInput_EpochBoundaryNotEqualityImposed` |
| A root-round 98-to-107 observation triggers a threshold at 100 exactly once | `certified_round_clock`; `TestCertifiedRoundClock_FiresOnceAcrossSkippedRounds` |
| Historical replay has every required input without node-local configuration | `rootInput` inventory §2; `root_inputs[*].self_contained` |
| domain and hash distinctions | `domains` (v0 vs v1); §1, §4; `TestDomainHash_*` |
| Certificates cannot be selected by latest local arrival; asymmetric-delivery / late-repeat with identical accepted block results | §5 binding rule; `certificate_selection` vectors; `TestSelection_AsymmetricDeliveryAgrees`, `TestSelection_StaleBindingRejected`, `TestSelection_LateRepeatDoesNotChangeAcceptedResult`; `TestCertifiedRoundClock_BackwardsPanics` |

## 10. Reproduce

```
go test ./evmroot/...
go run ./evmroot/cmd/d1vectors            # print the vector set
go run ./evmroot/cmd/d1vectors -update    # regenerate testdata/vectors.json (review the diff)
```
