# Contributing

This repository tracks the **Enshrined EVM, native UCT and PoS delivery** program in
GitHub issues. Start at the [program index (#1)](https://github.com/ristik/bft-core/issues/1)
and [R0 (#2)](https://github.com/ristik/bft-core/issues/2).

The normative contributor and agent workflow lives in
[`docs/pos/PROCESS.md`](docs/pos/PROCESS.md). This file is the short, operational
companion: how to claim a ticket, how to name and base a branch, what a PR must contain,
and what "done" means. Where the two disagree, `docs/pos/PROCESS.md` wins.

## 1. Before you touch code

1. Read the program index, `docs/pos/PROCESS.md`, the ticket, **every** issue in the
   ticket's `## Prerequisites` list, and the specification sections it names under
   `docs/pos/specification/`.
2. Confirm the ticket is eligible: all of its hard prerequisites are **closed with their
   acceptance evidence attached** (a closed issue with no evidence does not unblock
   anything), and its native `blocked by` relationships are cleared. Optional work
   (`T8`) and PoS-only bridge conditions are conditional — check the ticket text.
3. Claim exactly one bounded unit of work: self-assign the issue **or** post a claim
   comment naming the contributor/agent and the intended scope. Agents claim under their
   controlling contributor's account and never assign other people. Post your intended
   base revision and a one-paragraph approach before editing.

## 2. Branching and PRs

- **Integration base.** All program work branches from `integration/enshrined-evm`, not
  `main`. See [`docs/adr/0002-integration-branch-policy.md`](docs/adr/0002-integration-branch-policy.md).
  Do not assume `main` contains the prototype.
- **One branch/worktree per ticket.** Name it `<lowercase-id>/<slug>`, e.g.
  `d1/canonical-root-input-profile`, `f4/seal-registry`.
- **Stacked PRs.** When a ticket depends on another that is still in review, base your
  branch on the dependency's branch and set the PR base to that branch (not
  `integration/enshrined-evm`). State the dependency explicitly in the PR description
  (`Depends on #<n>`). GitHub retargets the child PR automatically when the parent merges.
- **Never fold an unrelated change into a ticket commit.** No drive-by formatting, no
  unrelated dependency bumps.
- **Split before coding** if the ticket crosses reviewable ownership boundaries: open
  child issues/PRs and keep every acceptance criterion on the parent issue until the
  whole deliverable is integrated. A large ticket is a deliverable contract, not a
  mandate for one giant PR.

## 3. What every PR must contain

- The issue link. Use `Refs #N` for partial/companion PRs; use `Closes #N` only on the
  last PR that satisfies the **entire** deliverable.
- A description of the behavioral change and the affected protocol/storage/wire versions.
- Validation commands **and their output**, distinguishing real execution evidence from
  fakes (the fake-executor chaos/compose CI legs are not real-reth evidence).
- Migration and activation behavior where applicable.
- For cross-repository work: the implementing repository and branch, links to companion
  PRs, and pinned compatible revisions. Contract and SDK code lands in its approved home
  (see the ADR); it is not added to this repository by default.
- Independent review by someone other than the author with the relevant expertise.

### Test expectations by change type

| Change type | Required evidence |
|---|---|
| Go (any) | affected package tests plus `make build`, `go vet ./...`, `make test` |
| Consensus | adversarial weights; signature/domain/context rejection; restart and safety-state cases |
| Persistent state | forward migration and fault injection |
| Reth (fork) | builder / follower / import / replay agreement |
| Contracts | invariant, malicious-caller/reentrancy, boundary tests |
| Proof paths | independent positive **and** negative vectors |

A mock or a benchmark alone never substitutes for the integrated evidence a ticket asks for.

## 4. Definition of done

The checklist in `docs/pos/PROCESS.md` ("Definition of done") is authoritative. In short:
prerequisite deliverables accepted and linked; every ticket-specific acceptance case has
reproducible evidence; model/tests/docs/version decisions reviewed; cross-repo revisions
pinned and available; CI and independent review pass; the closing comment links final
PRs, exact commits and test/model reports and states any residual limitations.

Closing a **milestone gate** additionally records a named maintainer decision.
Production deployment, currency issuance, bridge activation and the PoS switch are each a
separate explicit authorization and are never performed by merging a PR or closing a gate.

## 5. Repository enforcement

The branch protection, required status checks and reviewer rules this workflow assumes are
**proposed, not yet configured** — see
[`docs/pos/repo-protection-proposal.md`](docs/pos/repo-protection-proposal.md). Until a
maintainer applies them, contributors self-enforce the rules above. `F1` owns turning the
required-check list into enforced, PR-triggered CI.
