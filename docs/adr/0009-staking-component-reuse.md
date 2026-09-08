# ADR 0009: Staking component reuse — independent implementation in a separate GPL-3.0 repository (P1)

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
  Root `LICENSE` is **GPLv3**; `package.json` declares `"license": "MIT"`.
  **Archived** by upstream ~2024-03. Solidity 0.5.17; `package.json` pins
  `openzeppelin-solidity` **2.2.0** (not 0.5.x — that is the Solidity generation).
- `github.com/0xPolygon/pos-contracts` — `main` @ `ffa83a740dff3f4764277d855faf6c9388e06d90`
  (2026-08-05, "main mirrors deployed on-chain bytecode"). Root `LICENSE` is
  **GPLv3**; `package.json` declares `"license": "MIT"`. Carries
  `StakeManager` / `ValidatorShare` / `StakingInfo`; **no `SlashingManager`**.
  `StakeManager.sol` has **no SPDX header**. OZ sources are **vendored** under
  `contracts/common/oz`; no `openzeppelin-solidity` dependency.

All of the above verified at the pins on 2026-09-08.

**The licence conflict is recorded, not resolved.** MIT in `package.json` against
GPLv3 at the root does not establish MIT permission; it equally means the
repository-level label is not a per-file provenance analysis. Per-file notices
and imported-dependency licences must be recorded before any file is copied.

**Withdrawn premise.** An earlier revision of this ADR reasoned that `bft-core`
is Apache-2.0 and the custody contracts are immutable, therefore the contracts
must be Apache-2.0, therefore no GPL source could ever be used. **That inference
does not hold.** Immutability is a property of deployed bytecode, not a licence
constraint, and a platform's licence does not determine a separate artifact's.

The contracts live in **`unicity-pos-contracts`**, a separate repository, under
**GPL-3.0-only**. The boundary the conclusion rests on: separate repository,
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
   `unicity-pos-contracts` under GPL-3.0-only, against the frozen D4/D5
   lifecycle. Not a clean-room process: no separated specification and
   implementation teams and no separation records, so provenance is documented
   rather than certified.
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
