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
GitHub issues are the work tracker; this roadmap records the stage contracts and technical baseline.
The issue index added with publication maps stable roadmap IDs to GitHub issue numbers.

## Delivery stages

The [stage contracts and milestone aliases](roadmap.md#2-stage-contracts-and-logical-milestones)
restructure future work while preserving all accepted evidence and its limits. The public network
sequence is **TN-1 #428: PoA -> TN-B #429: PoA with bridging -> TN-S #430: PoS**. DN-B private bridge and DN-S
isolated PoS integration can develop independently; TN-S #430 still waits for the TN-B #429 network milestone.

TN-1 #428 includes a public UCT faucet for gas, public RPC/transaction access, an exact disposable
manifest, independent internal review and one-server operations with a container per validator.
Testnets may reset arbitrarily: users may lose assets, there is no backwards compatibility or
continuity commitment, and greenroom continues through testnet. Correct replay of a network's own
history, authentication and custody invariants remain mandatory.

Future mainnet preparation begins only after TN-S #430. External audits X2/X3/X5, production
parameters/economics, final T5/T6 signoff/rehearsal, real-value custody, final governance authority
and T7/TGE are mainnet-only. MN-B bridge readiness precedes T7/MN-1: no TGE without bridging.
The [dependency summary](roadmap.md#recomputed-dependency-summary) separates these production
obligations from development/testnet slices. Closing readiness gates never authorizes production.

Legacy gate aliases and existing issue numbers remain valid. The stage restructure is now
applied to GitHub; the roadmap links each new stage/work ID to its allocated issue number.
The public testnet milestones are 9 (TN-1 #428), 10 (TN-B #429) and 11 (TN-S #430). The I-track remains deferred; ordinary EVM
evidence and authenticated closure/protected claims are active requirements. Funded BFT-operator
rewards are required for PoS; PoA accounting stays external.

## Observed code starting points

- BFT Core `main`: `ceceacd11b7a735de74ce17884a3a45e0db1748d`.
- BFT Core prototype `engine-api-adapter`: `627318b5e6e0ca79e601d58b35fc9c46498f2731`.
- Local reth: `189c0df32617afc488e0f091dbface1bd72cceb4`.

These are historical inventory observations, not approved release revisions. Current M2/T-track
source and artifact pins are recorded in the closure-status and T5 dossier documents. Other
repositories' code is coordinated here; consumers close only after linked cross-repository changes
and integration evidence are available. No external maintainer or repository has been assigned work
implicitly.
