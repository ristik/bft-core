# ADR 0011: Staking component reuse — independent implementation in a separate GPL-3.0 repository (P1)

## Status

Proposed (P1, issue #27). Freeze once reviewed by a custody/protocol-accounting
reviewer and a Solidity reviewer, neither the author, and accepted by the owner
(see "Open for owner acceptance"). Depends on ADR 0006 (D4) and ADR 0007 (D5).
[ADR 0012](0012-validator-entity-model.md) (the owner's validator-entity model)
overrides older prose here and in the assessment; see "Relation to ADR 0012".

Acceptance-cleanup revision of 2026-10-03: the alternatives were rewritten to
agree with the decision, the upstream test and component mappings were
re-verified at the pins (assessment section 3.3), and the wrong ones corrected.

## Context

The roadmap directs P1 to "pin candidate Polygon source revisions and licenses;
map usable share/commission arithmetic, withdrawal and reward logic to the new
lifecycle… compare a minimal self-bond implementation with a port. Vendor only
the justified components." It assumes a permissive upstream.

Facts as read on 2026-09-06 (public GitHub API) and re-read on 2026-10-03
(pins unchanged; `pos-contracts` `main` is still `ffa83a74`):

- `github.com/maticnetwork/contracts` — `main` @ `eef53596046eda70a53653a8e5ff79b1cbf0a4f9`
  (2024-03-01), release tag `v0.3.11` = `9564ece3a0647b0da18a1a2a51baffb5f661893f`.
  Root `LICENSE` is **GPLv3**; `package.json` declares `"license": "MIT"`.
  **Archived** by upstream ~2024-03. Solidity 0.5.17; `package.json` pins
  `openzeppelin-solidity` **2.2.0** (not 0.5.x — that is the Solidity generation).
- `github.com/0xPolygon/pos-contracts` — `main` @ `ffa83a740dff3f4764277d855faf6c9388e06d90`
  (2026-08-05, "main mirrors deployed on-chain bytecode"). Root `LICENSE` is
  **GPLv3**; `package.json` declares `"license": "MIT"`. Carries
  `StakeManager` / `ValidatorShare` / `StakingInfo`; **no `SlashingManager`**.
  `StakeManager.sol` has **no SPDX header**. OZ sources are **vendored** under
  `contracts/common/oz`; no `openzeppelin-solidity` dependency.

All of the above verified at the pins on 2026-09-08 and again on 2026-10-03.
The root `LICENSE` is the GPLv3 text at both pins; whether the whole lineage is
GPL-3.0-**only** (rather than "or later", or a mixture per file) is **not
established** by that file or by GitHub's repository badge, and is not asserted
here. Wherever this ADR or the assessment says "GPL-3.0-only" about upstream, read
"GPLv3 per the root `LICENSE`, per-file scope unresolved".

**The licence conflict is recorded, not resolved.** MIT in `package.json` against
GPLv3 at the root does not establish MIT permission; it equally means the
repository-level label is not a per-file provenance analysis. Per-file notices
and imported-dependency licences must be recorded before any file is copied.

**Withdrawn premise.** An earlier revision of this ADR reasoned that `bft-core`
is Apache-2.0 and the custody contracts are immutable, therefore the contracts
must be Apache-2.0, therefore no GPL source could ever be used. **That inference
does not hold.** Immutability is a property of deployed bytecode, not a licence
constraint, and a platform's licence does not determine a separate artifact's.

The contracts live in **`unicity-pos-contracts`**, a separate repository, for
which **GPL-3.0** is the proposed licence (issue #85: GPLv3 is an option, and no
final licence is selected; the owner decides). The boundary the conclusion rests on: separate repository,
source tree and build; **no linking**; the platform touches the deployed
contracts only across the EVM ABI and the certified-input boundary, and neither
side derives from the other's source. Under that boundary a GPL-3.0 contract set
and an Apache-2.0 platform coexist and **a GPL-3.0 source port is
licence-permitted**. Separate repositories alone are not a determination — the
owner confirms the boundary, and this ADR is an engineering assessment, not legal
advice ([ASF](https://www.apache.org/licenses/GPL-compatibility),
[FSF](https://www.gnu.org/licenses/gpl-faq.en.html#MereAggregation)).

Independently of licence, the code is solc 0.5.17 and most of its surface
(validator NFT, slot auctions, `dethrone`, delegation vouchers, Heimdall fee
token, `StateSender` state-sync, upgradeable proxies, checkpoint Merkle
verification) is unused under the initial self-bond profile, and its storage
layout is entangled with those features.

## Decision

Adopt the assessment in
[`docs/design/p1-staking-component-reuse-assessment.md`](../design/p1-staking-component-reuse-assessment.md):

1. **No source is vendored at this revision — an engineering choice, not a
   licence bar.** A GPL-3.0 port into the GPL-3.0 destination is permitted. It is
   not taken for `StakeManager`/`ValidatorShare` because fitting them to the
   self-bond profile means deleting most of each contract while keeping its
   storage assumptions and moving two compiler generations, which destroys the
   deployed-bytecode provenance that was the only reason to port. Selective reuse
   of the vendored `common/oz` primitives remains available and is not excluded.
2. **Independent implementation of the minimal self-bond set**, in
   `unicity-pos-contracts` (the separate contract repository, which already
   exists; the licence is the owner's decision, GPL-3.0 proposed), against the frozen D4/D5
   lifecycle. Not a clean-room process: no separated specification and
   implementation teams and no separation records, so provenance is documented
   rather than certified.
3. **Reference-only list** (public algorithm shapes, no upstream bytes):
   `StakeManager` delayed-unbond state machine (row 1); the `SlashingManager`
   bounty/proposer-share/remainder split (row 4; there is **no** amount cap and
   **no** per-offence dedupe upstream, see the assessment section 3.1); and the
   `ValidatorShare` exchange-rate accumulator (row 5) with the commission formula
   `reward.sub(validatorReward).mul(commissionRate).div(MAX_COMMISION_RATE)`,
   which lives in **`StakeManager._getValidatorAndDelegationReward`**, not in
   `ValidatorShare` — kept **dormant** for a future delegation upgrade, which
   carries its own historical share/commission-loss tests.
4. **Removals name their duty.** Checkpoint reward accrual, the Heimdall-signed
   slashing path, checkpoint Merkle helpers, validator NFT/auctions, the
   Heimdall fee token, `StateSender` state-sync and upgradeable proxies are
   removed. Each accounting duty they carried is re-homed — see the six
   `accounting_replacements` entries (root-certified lifecycle, assigned-weight
   reward, objective-slashing penalty, collateral attribution through rotation,
   fee accounting, validator identity bookkeeping).
5. **`SafeMath` / OZ 0.5.x** are replaced by solc ≥ 0.8 checked arithmetic plus a
   current audited library pinned in P2.
6. **Not an audit.** A compiler upgrade and a green upstream test suite are not a
   security audit; the audit owner is the roadmap X-series (X2 pre-TGE; X4/X5
   PoS).

## Deliverables

- `evmroot/p1reuse.go` — `ReuseMatrix` / `Component` / `UpstreamSource` /
  `AccountingReplacement` / `ReuseDecision` and `ReuseMatrix.Validate`, which
  enforces: 40-hex pinned revisions + SPDX ids; a **declared destination**
  (repository, SPDX, boundary, determination owner) with `vendor-port` gated by
  `portableInto(destination, source)` rather than a hard-coded Apache-2.0 table;
  every removal names its accounting duty (or is
  flagged as carrying none, with a note); every reference/port row names a
  removed upstream test and a local home; the two required accounting
  replacements are present with `governance.tex` spec refs; both audit guards
  asserted.
- `evmroot/p1matrix.go` — `BuildP1ReuseMatrix`, the populated assessment.
- `evmroot/testdata/p1-reuse-matrix.json` — golden fixture.
- `evmroot/cmd/p1matrix` — print / `-update`.
- `evmroot/p1_test.go` — `TestP1_*` acceptance invariants, negative tests, and
  `TestP1_VectorsMatchGolden`. Notably `TestP1_LicenceGateDependsOnTheDeclaredDestination`,
  which asserts a GPL-3.0 port is admitted into the GPL-3.0 destination and
  refused into a permissive one — the earlier revision hard-coded only the second
  half — and `TestP1_DispositionIsNotCalledCleanRoom`.

  **This is schema validation of the assessment's own consistency.** It checks
  that required fields are present, well-formed and mutually consistent. Green
  tests establish nothing about licence correctness, upstream provenance or
  accounting completeness, and must not be cited as if they did.

## Consequences

- **P2** (immutable native stake custody) implements payable bonding,
  per-assignment reservations and reentrancy-safe pull credits from scratch
  against the D5 `Reservation` lifecycle in `unicity-pos-contracts`; it chooses
  the toolchain and pins the audited support library.
- **P3–P4** (identity/key binding; retirement queue) build on the reservation
  and inherited-protection model, not on `StakingNFT` / `ValidatorShare` unbond
  nonces. Per ADR 0012, P3 binds only the root consensus key.
- **P5–P7** (snapshot/election contract; candidate transport; governance
  parameter execution) provide the snapshot identity and candidate fields that
  replace `StakingInfo` reads and the checkpoint account-state-root.
- **S1–S4** implement slashing against the D5 vote domain; the `SlashingManager`
  Heimdall path is not carried forward.
- **T3** owns fee accounting; there is no separate staking fee token.
- Delegation is deferred. If enabled later, the row-5 formulas are the starting
  reference and that upgrade carries mandatory historical loss tests.

## Relation to ADR 0012

ADR 0012 governs where this ADR or the assessment says otherwise:

- **Key roles.** The assessment's "distinct consensus/node roles" (row 6 and the
  `validator-identity-bookkeeping` replacement) is superseded: a validator is one
  entity authenticated only by its BFT Core consensus key, and P3 binds only that
  key. Owner/withdrawal roles are unaffected by this.
- **Forced inbox.** The assessment's withdrawal gate "forced-inbox position
  cutoff through `LiabilityDeadlineRound`" (section 1, row 1, row 3, section 5)
  depended on the I-track, which ADR 0012 defers. What replaces timely-evidence
  protection is an open owner question (ADR 0012, open question 2); the
  `Δ_hold` and pending-evidence gates stay, the inbox cutoff is a deferred
  safeguard, not a launch dependency.
- **Weights.** Weights apply at the root/validator-entity level; the EVM shard
  mirrors root weights and aggregator shards are unweighted. Nothing here assigns
  a weight to an aggregator shard.
- **Coupled changes and positive proofs.** Election output reaches the root only
  through the coupled epoch-boundary handoff, and only positive certified proofs
  are required from the EVM; this ADR adds no absence-proof or EVM-only
  rotation dependency.

## Alternatives considered

All three alternatives are licence-permitted under the declared destination
boundary (Context, "Withdrawn premise"); they are rejected, or not chosen, on
engineering grounds only.

- **Port the Polygon staking set** (`StakeManager`/`ValidatorShare`) into the
  contract repository. Not chosen: solc 0.5.17 → ≥ 0.8 modernising rewrite of
  mostly-unused code whose storage layout is entangled with the unused features,
  which forfeits the deployed-bytecode provenance that was the only reason to
  port (Decision 1). Remains available for a unit with a closer surface match.
- **Vendor a separately-housed GPL-3.0 package** (a ported package distributed
  apart from the contract repository). Not chosen: it would add a second
  distributable artifact and boundary for no engineering gain. Whether any
  ported code is ever in scope, and the artifact-licence obligations of a
  genesis package or node release that carries GPL bytecode, are the owner's
  decision (see "Open for owner acceptance"); P1 does not decide them.
- **Fork `0xPolygon/pos-contracts` and modernise in place.** Rejected: same
  rewrite as the port, and `pos-contracts` `main` tracks *deployed* Polygon
  bytecode rather than this lifecycle.
- **Keep `ValidatorShare` for a self-bond-only launch.** Rejected: roadmap P2
  says do not expose a partially implemented share API; self-bond needs none of
  the voucher/exchange-rate machinery.

## Open for owner acceptance

This ADR stays **Proposed** until the owner accepts it. These decisions are the
owner's; P1 records them and decides none (keep unresolved values symbolic):

1. **Accept the reviewed artifact/reuse boundary** of this ADR and the
   assessment: independent implementation, no vendored source, reference-only
   shapes, dormant delegation formulas (the preferred "independent minimal core").
2. **Confirm the licence boundary and destination licence.** Confirm that
   `unicity-pos-contracts` and `bft-core` are genuinely separate works (no
   linking), select the contract licence (GPL-3.0 is proposed, not selected), and
   decide whether a ported GPL package is ever in scope and what a genesis
   package or node release carrying GPL bytecode must say.
3. **Resolve the upstream licence scope** if any upstream file is ever copied: the
   root `LICENSE` (GPLv3) versus `package.json` (MIT) conflict, the missing SPDX
   header on `pos-contracts` `StakeManager.sol`, per-file notices of vendored OZ
   files.
4. **Economics for #85/P2–P7/S2:** bond/weight unit, election size and churn,
   penalties, bounties and repeat offences, protection periods, governance
   bounds and custody migration.
5. **Evidence protection without the I-track** and the enforceable real-time
   retirement floor/checkpoint policy (ADR 0012 open question 2; P4, S2, H7).
