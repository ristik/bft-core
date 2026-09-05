# Contributor and agent workflow

## Start and claim work

1. Read the program index, this process, the ticket, its prerequisite issues and the pinned
   specification. The D tickets settle wire formats and state machines before their consumers.
2. Use native GitHub blocking relationships and the ticket's full dependency list to find
   eligible work. Optional rewards and PoS-only bridge conditions are explicitly conditional.
   A closed issue is insufficient if its acceptance evidence is absent. Keep dependencies
   accurate when splitting or changing a ticket. No manually maintained ready/blocked label
   is authoritative.
3. Claim one bounded unit of work with an assignee or a claim comment identifying the developer
   or agent and intended scope. Agents use their controlling contributor's account; they do
   not assign other people. Post a short approach and the intended base revision before editing.
4. R0 approves the integration branch and reference PR. Before R0 closes, D1 exploration and
   read-only code inventories can proceed, but do not merge dependent protocol implementations.
   D2 and D3 are the first independent design tracks after D1. Audit scoping can begin early.
5. Use an isolated branch/worktree per ticket from the accepted integration base. Do not assume
   main contains the prototype. Use draft stacked PRs only with explicit base/dependency links.
   Never combine an unrelated local change into a ticket commit.

## Design, implementation and review

- Each D ticket produces an ADR/profile, enumerated invariants, compatibility/version policy,
  and executable state model or independently generated vectors with reproducible commands.
  Review must include someone other than the author with the relevant protocol expertise.
- Keep implementation PRs reviewable. A large ticket is a deliverable contract, not a mandate
  for one giant PR. Split it into child issues/PRs before coding when it crosses ownership or
  cannot be reviewed coherently; keep all acceptance criteria on the parent until integration.
- Link the exact accepted design revision and negative tests. Do not resolve undecided monetary
  allocations, wire domains, fork rules or activation authority using an undocumented default.
- Cross-repository tasks remain coordinated in BFT Core. Name the implementing repository and
  branch in the claim; link companion PRs and pin compatible revisions. Contract and SDK owners
  choose approved homes before adding production code. This planning PR does not create them.
- For Go changes run affected tests plus the repository build/vet/test checks appropriate to
  the change. The observed CI uses `make build`, `go vet ./...`, `make test`; FFI jobs are disabled
  and fake-executor chaos/compose jobs are not real-reth evidence. F1 must define PR-triggered
  mandatory checks and a pinned real-reth integration lane. Read each repository's current
  contribution instructions before running or changing its checks.
- Consensus changes require adversarial weights, signature/domain/context rejection and
  restart/safety-state cases. Persistent state changes need migration and fault injection.
  Reth changes need builder/follower/import/replay agreement. Contract changes need invariant,
  malicious-caller/reentrancy and boundary tests. Proof paths need independent positive and
  negative vectors. A mock or benchmark alone cannot replace the required integrated evidence.
- Every PR includes the issue link, behavioral change, validation commands/results, affected
  protocol/storage versions and migration/activation behavior. Independent review is required
  before merging. R0 proposes repository enforcement; this document does not claim protection
  or required checks are already configured.

## Definition of done

- [ ] Required designs and prerequisite deliverables are accepted and linked.
- [ ] All issue-specific acceptance cases have reproducible evidence.
- [ ] Implementation/model, tests, operational or API documentation and version decisions are reviewed.
- [ ] Required cross-repository revisions and integration runs are pinned and available.
- [ ] Relevant CI and independent review pass; no public-funds/finality blocker is deferred silently.
- [ ] The closing comment links final PRs, exact commits, test/model reports and any residual limits.

Reference a ticket with `Refs #N` for partial/companion PRs; use `Closes #N` only for the last
accepted change satisfying the whole deliverable. Do not close gates automatically from a PR.
Closing a milestone gate records technical readiness evidence and a named maintainer decision;
production deployment/issuance/activation remains a separate explicit authorization.

## Staged release rules

M1 is private paired execution; M2 adds real PoA rotation, recovery and evidence export.
M3 is a public UCT/TGE readiness gate under PoA. M4B is private bridge validation; M5B requires
long-history redemption and independent review before public custody. M4S includes both PoA
shadow comparison and a separate authoritative PoS testnet; M5S is authoritative PoS readiness.
Bridge and PoS are independent after M3. T8 is optional and must remain disabled if unfinished.
Do not close the private-bridge gate only because a public TGE exists; use an M3-equivalent
private test chain and never require public funds to exercise it.

D4, D5 and D6 may require multiple design iterations. Record counterexamples and amend consumers.
Uniform leader selection, self-bond staking, assigned-weight rewards and whole-token bridges are
initial simplifications; they do not waive weighted safety, historical trust or safe exits.
No fixed calendar estimates are assigned before design and ownership uncertainties are closed.
