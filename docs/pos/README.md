# Enshrined EVM / UCT / PoS delivery

Start with [the contributor process](PROCESS.md) and [the roadmap](roadmap.md).
The [specification snapshot](specification/README.md) makes the repaired Yellowpaper available
for review. [The repair record](repair-plan.md) records its scope and validation.

This is a planning and reference change. It adds no consensus, reth or contract implementation,
sets no production parameters, and authorizes no deployment or currency issuance.
GitHub issues are the work tracker; this roadmap is the initial design and release baseline.
The issue index added with publication maps stable roadmap IDs to GitHub issue numbers.

## Observed code starting points

- BFT Core `main`: `ceceacd11b7a735de74ce17884a3a45e0db1748d`.
- BFT Core prototype `engine-api-adapter`: `627318b5e6e0ca79e601d58b35fc9c46498f2731`.
- Local reth: `189c0df32617afc488e0f091dbface1bd72cceb4`.

These are inventory observations, not approved release revisions. R0 establishes the working
branch/repository policy; F1 reconciles and pins the actual integration baseline. Prototype
file links in issues are discovery aids and may not exist on main yet. Other repositories' code
is coordinated here; consumers close only after linked cross-repository changes and integration
evidence are available. No external maintainer or repository has been assigned work implicitly.
