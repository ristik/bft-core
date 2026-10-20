# ADR 0011: Staking component reuse — clean-room self-bond contracts (P1)

## Status

Owner-selected development direction, reconciled 2026-10-20. This records the
October 7 decisions (§4.3: clean-room implementation, inspiration only; §5:
ordinary EVM evidence) and the implementation provenance delivered in
[contracts #7](https://github.com/ristik/unicity-pos-contracts/pull/7).
It does not assert acceptance of the entire #85 architecture, an external audit,
or permission to deploy. The [canonical P85 v5 design](../design/pos-architecture.md)
is the self-contained #85 deliverable for owner acceptance.

## Decision

1. Implement native-UCT self-bond staking independently in the separate
   `ristik/unicity-pos-contracts` repository. Copy or translate no upstream
   staking source, storage layout, algorithm implementation or tests. Upstream
   systems inform the design only. Newly authored contracts and interfaces use
   **Apache-2.0**; imported general-purpose dependencies retain their licenses.
2. Preserve separate source/build/release ownership. Pin compiler, dependency
   revisions, generated ABI/bindings, bytecode and genesis artifacts explicitly;
   retain the appropriate notices with distributed artifacts. A shared ABI or
   separate repository is not itself a legal determination about derivation.
3. Use the custody/identity/closure model in the canonical design, ordinary EVM
   evidence with authenticated deadlines and protected claims, and exact-K
   recovery. No forced-inbox protection, release authority, stake-share
   delegation or legacy migration is required for this development profile.
4. Fund PoS rewards separately and pay only BFT Core validator-entity operators
   by acknowledged assigned weight. No on-chain PoA accrual or second reward for
   the coupled EVM node. Development parameters suffice; final production
   economics and external audit remain later gates.

## Why this choice

The [P1 assessment](../design/p1-staking-component-reuse-assessment.md) compares a
focused Polygon port, selective primitives and an independent implementation.
A port was a real alternative, not prohibited because the platform is Apache-2.0
or the contracts are immutable. It loses much of its value when adapting the
old compiler, checkpoint lifecycle and storage coupled to NFTs, auctions,
vouchers, state-sync and proxies. The required root-certified lifecycle and
historical liability would still need new accounting and behavioral tests.

The earlier proposal of a GPL destination was an assessment alternative, never
the selected implementation license. Upstream root GPLv3 notices versus MIT
package metadata remain unresolved per-file provenance questions **if a future
change proposes copying that source**; they do not block the selected no-port
implementation. No GPL-derived code is relabeled by this decision.

## Provenance and implementation boundary

[The contracts provenance manifest](https://github.com/ristik/unicity-pos-contracts/blob/fbf499bffa/docs/p85/PROVENANCE.md)
records specification-led implementation, no copied/translated upstream staking
source or tests, Apache-2.0 headers, OpenZeppelin `ReentrancyGuard` (MIT) and
forge-std for tests (MIT/Apache-2.0). This is an engineering clean-room direction
and an implementation record, not a claim that earlier design investigators
never read upstream code or a legal certification. Preserve that distinction.

P1's original `evmroot/p1matrix.go`, `p1reuse.go`, JSON golden and `TestP1_*` remain
**historical assessment/schema artifacts**, including their proposed GPL
Destination and `not-clean-room` disposition. They are not the current manifest,
behavior model, licensing authority or runtime policy. This docs-only revision
does not silently regenerate them. The assessment's current mapping identifies
real contract tests separately; passing schema tests or upstream tests is not
an audit.

## Relationship to the other decisions

ADR 0012's validator-entity model remains: one entity operates root and coupled
EVM nodes, with separate authenticated role keys and mirrored assigned weights;
aggregator committees are unweighted. P85's owner/EVM possession path binds those
roles without creating a second staking identity. Its exact-K exception reuses
previously authenticated unchanged bindings for recovery only.

The open evidence-choice question in the earlier assessment is settled by
ordinary EVM inclusion. A valid pair must execute by the cutoff; mempool receipt
is not protection. Authenticated closure/retirement and accepted-case holds
protect withdrawals; unseen/censored evidence does not. UC-time holds are not
minimum wall-clock guarantees. The current design contains the exact rules.

## Acceptance and remaining work

- P1's comparison, pinned upstream findings and accounting replacements remain
  in the assessment. Its implementation choice is now the recorded owner
  direction, rather than a pending GPL/Apache or inbox decision.
- #85 still requires owner acceptance of the published architecture and its
  stated limits. This revision proposes replacing the older document-only
  PR #415; it neither closes that PR nor accepts #85 on the owner's behalf.
- P2–P7/S-series completion requires their own implementation/evidence. In
  particular, prospective governance and funded rewards are specified but not
  implemented by publishing the design. Mainnet parameters/audits are separate.
