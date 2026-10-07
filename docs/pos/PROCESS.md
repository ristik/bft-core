# Contributor and agent workflow

## Start and claim work

1. Read the program index, this process, the ticket, its prerequisite issues and the pinned
   specification. The D tickets settle wire formats and state machines before their consumers.
2. Use native GitHub blocking relationships and the ticket's full dependency list to find
   eligible work. Read the latest stage amendment and the acceptance slice consumed by each gate.
   A closed issue is insufficient if its acceptance evidence is absent. Keep dependencies
   accurate when splitting or changing a ticket. No manually maintained ready/blocked label
   is authoritative.
3. Claim one bounded unit of work with an assignee or a claim comment identifying the developer
   or agent and intended scope. Agents use their controlling contributor's account; they do
   not assign other people. Post a short approach and the intended base revision before editing.
4. R0 approves the integration branch and reference PR. Before R0 closes, D1 exploration and
   read-only code inventories can proceed, but do not merge dependent protocol implementations.
   D2 and D3 are the first independent design tracks after D1. Future production audit work waits
   until public TN-S #430 is reached; internal design/implementation review continues throughout.
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
  the change. Current focused Go CI runs formatting, build, vet, four full-suite test shards and
  a bounded race suite. Documentation-only PRs skip Go work inside reporting jobs, so required
  checks still report. Fake-executor chaos/compose and ordinary Go checks are not real-reth
  acceptance; #90 retains the pinned real-reth smoke/fault evidence obligations. Read each
  repository's current contribution instructions before running or changing its checks.
- Consensus changes require adversarial weights, signature/domain/context rejection and
  restart/safety-state cases. Persistent state changes need fault injection and correct replay of
  the exercised network history. DN/TN may reset to fresh genesis without compatibility with
  discarded formats; production continuity/migration policy is a separate mainnet requirement.
  Reth changes need builder/follower/import/replay agreement. Contract changes need invariant,
  malicious-caller/reentrancy and boundary tests. Proof paths need independent positive and
  negative vectors. A mock or benchmark alone cannot replace the required integrated evidence.
- Every PR includes the issue link, behavioral change, validation commands/results, affected
  protocol/storage versions and migration/activation behavior. Independent review is required
  before merging. Focused GitHub CI and protection of `integration/enshrined-evm` are enabled
  as of 2026-10-07. Follow the configured required checks; do not bypass protection.

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

Follow the [stage contracts, milestone aliases and dependency summary](roadmap.md#2-stage-contracts-and-logical-milestones).
DN-0/M1 and M0 remain historical acceptance. DN-1/M2 covers recoverable PoA devnet/staging;
DN-B/M4B covers the supported private bridge; DN-S/M4S covers shadow and separate isolated
authoritative PoS. Preserve each closed ticket's evidence and explicit limitations.

The public network milestones must be reached in order: **TN-1 #428 -> TN-B #429 -> TN-S #430**. TN-1 #428 includes
public access, a UCT gas faucet, exact test manifests, internal review, measured limits and initial
one-bare-metal-server operations. Independent runbook execution does not mean independent
physical hosts. TN-B #429 adds fake-value bridging with common SDK epoch/weight support and a working
exit for every admitted history. TN-S #430 adds authoritative public PoS, required funded operator
rewards, ordinary EVM evidence, protected claims and integrated bridge/PoS acceptance.

Greenroom applies through testnet: arbitrary resets, no backwards compatibility or obligation to
preserve assets, and no continuity-within-a-generation promise. State this publicly. Correct replay
of the network's own history, authenticated transitions and custody invariants are still required.
Use a fresh identity/genesis for a reset; do not disguise discarded history as a valid continuation.

Future mainnet preparation starts after TN-S #430. Production T5/T6, X1-MAIN #440, MN-POLICY #439/MN-OPS #441,
X2/X3/X5, T7/TGE, real-value custody and final governance authority belong there. Mainnet bridge
readiness MN-B/M5B precedes T7/MN-1/M3, so TGE cannot be ready without bridging. Remove the old
M3 -> M5B and T7 -> B9 ordering. Production PoS remains a separate MN-S/M5S gate and authorization.

When splitting a ticket, append an `Amended 2026-10-07 (stage restructure)` note identifying the
new acceptance owner, prerequisites and retained scope; do not rewrite away earlier obligations.
T5-TEST #431/T6-TEST #432/X1-TEST #433/P8-TEST #437 provide internal development/testnet slices. Production parents
remain open until their own obligations are met. B3/B5 private-profile closure must identify
transferred public-profile cases under B-TEST #438. A label or milestone rename is never closure evidence.

Keep full semantic prerequisites in issue bodies and recompute native blocking edges after a
split. Validate acyclicity and reachability, including removal of every I-track path to active gates.
Removing I4 -> H7 must preserve H3/P4/S2; removing I5 -> S4 must preserve H7/S2/S3. Restore I4 -> I5
inside the deferred graph. Ordinary evidence and authenticated closure/protected claims replace
the active inbox dependency; do not claim bounded censorship resistance. H4/H6 may collect their
remaining evidence in one coordinated rehearsal without circular closure conditions.

D4, D5 and D6 reference models remain accepted evidence within their recorded scope. Amend
consumers when new counterexamples affect acceptance. Self-bond staking and whole-token bridges
remain simplifications, not exemptions from weighted safety, historical trust or safe exits.
No fixed calendar estimates or production parameters are implied by this restructure.
