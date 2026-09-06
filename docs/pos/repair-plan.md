# Repair plan: enshrined EVM, UCT and PoS

This change repairs the specification first, then rewrites `pos-development-plan.md`
against it. It does not implement or deploy consensus, execution-client or contract changes.

1. **Fix protocol foundations in the yellowpaper.** Define stake-weighted quorum rules,
   authenticated deterministic root inputs, privileged execution semantics, independent
   root/shard/block clocks, and a committed epoch handoff with an EVM acknowledgement.
2. **Fix accountability and historical trust.** Remove downtime punishment inferred from
   quorum-certificate omissions; use a simple explicitly non-performance reward policy
   initially. Tie withdrawals to actual retirement, define evidence messages and retention,
   and separate recent-key retention from weak-subjectivity checkpoints.
3. **Fix execution and bridge proofs.** Specify persistent block/UC associations, offline
   receipt and state proofs, refreshable historical backing evidence, multi-shard anchors,
   and custody liability accounting. Keep the history MMR optional.
4. **Specify bounded delivery and bootstrap.** Define a gas-safe forced-inclusion queue,
   funded bootstrap accounts, contract upgrade boundaries and feature activation gates.
5. **Rewrite development tickets in dependency order.** Deliver a private PoA foundation,
   then an audited public UCT/TGE chain; bridge and PoS follow as separately gated work.
   Gate authoritative PoS on weighted consensus, safe handoff, slashable retirement,
   objective evidence, forced inclusion and recovery. Defer downtime slashing, execution
   proofs and optional complexity without claiming their guarantees.
6. **Verify the documents.** Compile the yellowpaper, check references and changed-page
   layout, and check that every review finding maps to concrete tickets and milestone gates.

The initial design keeps one governance EVM shard paired with the BFT Core operators,
while independent aggregator partitions and shards continue at their own cadence. PoA
can launch before PoS. No existing UCT supply is migrated. Proposed allocations, economics,
wire encodings and deployment parameters remain reviewable release decisions.

## Documentation completion and validation

The Yellowpaper repairs are complete across the EVM chapter and appendix, governance,
BFT, execution-layer settlement, bridge proofs and token mint-reason dispatch. The roadmap
was then rewritten into 65 tickets with dependencies, acceptance evidence, staged release
gates, review-defect traceability and a disposition table for the earlier draft tickets.

Validation on 2026-09-05:

- The 166-page Yellowpaper compiles successfully with no unresolved references or compiled
  duplicate-label warnings. Its three horizontal overflow warnings match the baseline.
- Revised chapter and appendix pages were rendered and visually inspected, including the
  final evidence, historical-proof, mint-reason and parameter-table changes.
- `git diff --check` passes for the Yellowpaper. Every roadmap ticket has dependencies and
  acceptance criteria; the dependency graph, including milestone prerequisites, is acyclic.

This completes the documentation repair, not the protocol implementation. D1-D6 remain
mandatory implementation-design gates: canonical wire inputs, reth resource accounting,
weighted consensus, the executable pipelined epoch handoff, evidence/inbox accounting and
historical trust. Public TGE, bridging and authoritative PoS each require their own later
validation and release decisions. Runtime repositories have not been changed.
