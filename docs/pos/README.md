# Enshrined EVM / UCT / PoS delivery

Start with [the contributor process](PROCESS.md) and [the roadmap](roadmap.md).
The [specification snapshot](specification/README.md) makes the repaired Yellowpaper available
for review. [The repair record](repair-plan.md) records its scope and validation.
The [M2 closure status](m2-closure-status.md) records the F7/F8/M2a evidence, pins, limits and
owner decisions without treating the remaining M2/H6 work as closed.

The [owner architecture decisions of 2026-10-01](../adr/0012-validator-entity-model.md) (validator-entity model, weights
at the root level only, coupled validator-set changes, deferred I-track, centrally run aggregator shards) amend the roadmap
below; the roadmap carries a decision section and per-ticket amendment notes.

This is a planning and reference change. It adds no consensus, reth or contract implementation,
sets no production parameters, and authorizes no deployment or currency issuance.
GitHub issues are the work tracker; this roadmap is the initial design and release baseline.
The issue index added with publication maps stable roadmap IDs to GitHub issue numbers.

## Observed code starting points

- BFT Core `main`: `ceceacd11b7a735de74ce17884a3a45e0db1748d`.
- BFT Core prototype `engine-api-adapter`: `627318b5e6e0ca79e601d58b35fc9c46498f2731`.
- Local reth: `189c0df32617afc488e0f091dbface1bd72cceb4`.

These are historical inventory observations, not approved release revisions. Current M2/T-track
source and artifact pins are recorded in the closure-status and T5 dossier documents. Other
repositories' code is coordinated here; consumers close only after linked cross-repository changes
and integration evidence are available. No external maintainer or repository has been assigned work
implicitly.
