# ADR 0002: Integration-branch policy for the enshrined-EVM / UCT / PoS program

## Status

Accepted on 2026-09-06 for R0 (#2), using the owner-authorized review and merge.
The integration branch is adopted; unnamed external repository homes remain decisions for
their consuming tickets and are not implicitly approved. Supersedes no earlier ADR;
`0001-executor-boundary.md` remains in force.

## Context

The program in issue #1 spans 65 roadmap tickets plus gates, and its code starting points are
pinned to a prototype branch, not to `main`:

| Line | Tip observed | Relationship |
|---|---|---|
| `main` | `ceceacd11b7a735de74ce17884a3a45e0db1748d` | default branch; **does not** contain the shard-node framework or the Engine API adapter |
| `l1` | (root-chain line) | root-chain work merged toward `main`; no EVM shard runtime |
| `engine-api-adapter` | `627318b5e6e0ca79e601d58b35fc9c46498f2731` | prototype: `shardnode/` framework, `engineapi/` adapter, EVM shard tooling, compose/chaos CI. 27 commits ahead of `main`. |

`main`, `l1` and the aggregator partitions/shards each keep their own cadence and are **not**
retargeted by this program. Independent aggregator partitions (`aggregator-go`, `rugregator`)
continue against `main`/`l1` as today.

Every D/F/H/T/Q/P/S/I/B/X ticket needs a single agreed base so that stacked design and
implementation PRs compose. Choosing `main` would strand the prototype; choosing an
ephemeral per-ticket base would make the dependency DAG unmergeable.

## Decision

### 1. `integration/enshrined-evm` is the program's long-lived base branch

- Cut from `engine-api-adapter` at `627318b5` (the observed prototype tip).
- **All** program tickets (R0, D1–D6, F1–F9, and everything downstream) branch from it and
  target it (directly, or via a stacked parent branch that itself targets it).
- It is an integration line, **not** a release branch. Merging into it records that a
  ticket's deliverable and acceptance evidence were reviewed; it authorizes no deployment.
- It never fast-forwards `main`. Promotion to `main` (or to `l1`) is a separate,
  explicit maintainer action taken per milestone gate, not a consequence of merging tickets.

### 2. `F1` reconciles and pins the real baseline

`engine-api-adapter` is a **draft** prototype, not a validated baseline. `F1` (issue #9)
owns: comparing `main`/`l1` with `engine-api-adapter` at exact commits, recording retained
/ missing / conflicting behavior, pinning the BFT, reth and configuration revisions, and
standing up PR-triggered CI for `integration/enshrined-evm`. Until `F1` closes, the base is
"the prototype as-is" and no dependent protocol implementation merges.

### 3. Prototype file links in issues are discovery aids

Issue bodies link prototype paths at `627318b5`. Some do not exist on `main`. Treat them as
"inspect against the F1 baseline", per each ticket's "Implementation starting points".

### 4. Cross-repository locations

Coordination stays in BFT Core issues; code lands in the named repository. These homes are
**recorded here for maintainer confirmation**; no external repository or maintainer has been
assigned work implicitly.

| Component | Repository (proposed) | Pinned revision at program start | Owned tickets |
|---|---|---|---|
| BFT Core (Go: consensus, shard-node framework, Engine API adapter) | `github.com/ristik/bft-core` — this repo, `integration/enshrined-evm` | `627318b5` (prototype) | R0, D1–D6, F1–F9, H*, I*, Q*, parts of P/S/B/X |
| Execution client (reth fork) | approved reth fork — **to be named by maintainer**; local inventory revision `189c0df32617afc488e0f091dbface1bd72cceb4` | `189c0df3` (inventory only) | F3–F5, D2 companion, parts of H/I/B |
| Governance / staking / bridge contracts | Solidity repository — **to be named by contract owner** before any production code | none exists yet | D5/D6 companions, P2–P8, S*, T2–T8, B* |
| Offline / SDK verification | State Transition SDK repos (`state-transition-sdk-rust`, …) | per-SDK, pinned in the consuming ticket | B2–B7, F7 |
| Specification | `github.com/unicitynetwork/unicity-yellowpaper-tex` | base `3da5c235427941c135f03779ca9e5d47611769b7` + `docs/pos/specification/repair.patch` | all D tickets amend via ADR |

The `docs/pos/specification/` snapshot in this repo is a **review copy** made available before
upstream publication. The Yellowpaper is maintained upstream; replace the snapshot with an
accepted upstream commit reference once published, and record every later normative change in
a new ADR that also updates affected issues, vectors and gates.

## Repository enforcement

Branch protection remains off by explicit owner instruction on 2026-09-06. Trusted
contributors retain the documented review and validation workflow. F1 adds CI coverage,
not protection settings. See `docs/pos/repo-protection-proposal.md`.

## Consequences

- Reviewers can rely on one base commit for the whole DAG; stacked PRs compose cleanly.
- `main` is unaffected; aggregator work is unaffected.
- The program carries the risk that `engine-api-adapter` is incomplete. `F1` is the
  explicit mitigation and is a hard prerequisite (directly or transitively) of every
  implementation ticket.
- If a maintainer prefers a different base (e.g. reconcile onto `main` first), that
  decision changes only this ADR and the `F1` scope; the ticket DAG and acceptance
  contracts are unchanged.

## Alternatives considered

- **Base on `main`.** Rejected for now: forces a large prototype-reconciliation before any
  design ticket can even be based somewhere, and `F1` already owns that reconciliation with
  proper evidence.
- **Per-ticket bases off `engine-api-adapter` directly.** Rejected: the dependency DAG
  (D4 needs D1+D3, F6 needs F2+F3+F4, …) produces unmergeable cross-diffs without a shared
  moving integration point.
- **Rename/replace `engine-api-adapter` in place.** Rejected: it is a useful historical
  reference and other readers may have it checked out; a new named branch is cheaper than
  coordinating a force-move.
