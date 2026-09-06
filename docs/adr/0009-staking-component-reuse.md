# ADR 0009: Staking component reuse — clean-room self-bond, no source port (P1)

## Status

Proposed (P1, issue #27). Freeze once reviewed by a custody/protocol-accounting
reviewer and a Solidity reviewer, neither the author. Depends on ADR 0006 (D4)
and ADR 0007 (D5).

## Context

The roadmap directs P1 to "pin candidate Polygon source revisions and licenses;
map usable share/commission arithmetic, withdrawal and reward logic to the new
lifecycle… compare a minimal self-bond implementation with a port. Vendor only
the justified components." It assumes a permissive upstream.

Facts as read on 2026-09-06 (public GitHub API):

- `github.com/maticnetwork/contracts` — `main` @ `eef53596046eda70a53653a8e5ff79b1cbf0a4f9`
  (2024-03-01), release tag `v0.3.11` = `9564ece3a0647b0da18a1a2a51baffb5f661893f`.
  Licence **GPL-3.0-only**. **Archived** by upstream ~2024-03. Solidity 0.5.17,
  `openzeppelin-solidity` 0.5.x.
- `github.com/0xPolygon/pos-contracts` — `main` @ `ffa83a740dff3f4764277d855faf6c9388e06d90`
  (2026-08-05, "main mirrors deployed on-chain bytecode"). Licence
  **GPL-3.0-only**. Same 0.5.x `StakeManager` / `ValidatorShare` / `StakingInfo`
  units.

`bft-core` is **Apache-2.0**, and `governance.tex` §"Upgrade and Delivery
Boundaries" makes money custody, withdrawal accounting, allocation, wrapper and
vault contracts **immutable** in the initial profile. GPL-3.0 → Apache-2.0
relicensing is not permitted, so a source port into that contract set is not
available. Independently, the code is solc 0.5.17 and most of its surface
(validator NFT, slot auctions, `dethrone`, delegation vouchers, Heimdall fee
token, `StateSender` state-sync, upgradeable proxies, checkpoint Merkle
verification) is unused under the initial self-bond profile.

## Decision

Adopt the assessment in
[`docs/design/p1-staking-component-reuse-assessment.md`](../design/p1-staking-component-reuse-assessment.md):

1. **No source is vendored or ported.** Every pinned Polygon staking revision is
   GPL-3.0-only; none is copied or adapted into the Apache-2.0 contract set. A
   separately-housed GPL-3.0 ported package is an owner/governance decision about
   a new distributable artifact and is out of P1 scope.
2. **Clean-room minimal self-bond.** All M4S staking-contract code is written
   locally under Apache-2.0 in the repository chosen by P2, against the frozen
   D4/D5 lifecycle.
3. **Reference-only list** (public algorithm shapes, no upstream bytes):
   `StakeManager` delayed-unbond state machine (row 1); the `SlashingManager`
   cap/bounty/remainder penalty split and per-offence dedupe (row 4); and the
   `ValidatorShare` exchange-rate accumulator and commission formula
   `reward.sub(validatorReward).mul(commissionRate).div(MAX_COMMISION_RATE)`
   (row 5) — kept **dormant** for a future delegation upgrade, which carries its
   own historical share/commission-loss tests.
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
  enforces: 40-hex pinned revisions + SPDX ids; no `vendor-port` while sources
  are copyleft-incompatible; every removal names its accounting duty (or is
  flagged as carrying none, with a note); every reference/port row names a
  removed upstream test and a local home; the two required accounting
  replacements are present with `governance.tex` spec refs; both audit guards
  asserted.
- `evmroot/p1matrix.go` — `BuildP1ReuseMatrix`, the populated assessment.
- `evmroot/testdata/p1-reuse-matrix.json` — golden fixture.
- `evmroot/cmd/p1matrix` — print / `-update`.
- `evmroot/p1_test.go` — `TestP1_*` acceptance invariants, negative tests, and
  `TestP1_VectorsMatchGolden`.

## Consequences

- **P2** (immutable native stake custody) implements payable bonding,
  per-assignment reservations and reentrancy-safe pull credits from scratch
  against the D5 `Reservation` lifecycle; it chooses the contract repository and
  toolchain and pins the audited support library.
- **P3–P4** (identity/key binding; retirement queue) build on the reservation
  and inherited-protection model, not on `StakingNFT` / `ValidatorShare` unbond
  nonces.
- **P5–P7** (snapshot/election contract; candidate transport; governance
  parameter execution) provide the snapshot identity and candidate fields that
  replace `StakingInfo` reads and the checkpoint account-state-root.
- **S1–S4** implement slashing against the D5 vote domain; the `SlashingManager`
  Heimdall path is not carried forward.
- **T3** owns fee accounting; there is no separate staking fee token.
- Delegation is deferred. If enabled later, the row-5 formulas are the starting
  reference and that upgrade carries mandatory historical loss tests.

## Alternatives considered

- **Port the Polygon staking set.** Rejected: GPL-3.0 → Apache-2.0 is not
  permitted for the immutable-custody contract set; and even setting licence
  aside it is a solc 0.5.17 → ≥ 0.8 modernising rewrite of mostly-unused code
  with no inherited review.
- **Vendor a separately-housed GPL-3.0 package.** Not chosen here: it creates a
  new distributable artifact under a different licence and is an owner/governance
  decision, not P1's. Flagged for the owner.
- **Fork `0xPolygon/pos-contracts` and modernise in place.** Rejected: same
  licence problem, same rewrite, and `pos-contracts` `main` tracks *deployed*
  Polygon bytecode rather than this lifecycle.
- **Keep `ValidatorShare` for a self-bond-only launch.** Rejected: roadmap P2
  says do not expose a partially implemented share API; self-bond needs none of
  the voucher/exchange-rate machinery.
