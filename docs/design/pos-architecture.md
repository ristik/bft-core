# P85 — PoS custody, election and recovery architecture, v5

Status: **proposed for owner acceptance**, published 2026-10-20 from the reviewed
P85 v5 development design (2026-10-07, including its review fixes and UC-time
clarification). This is the canonical self-contained deliverable for
[issue #85](https://github.com/ristik/bft-core/issues/85). It proposes superseding
the earlier document in [PR #415](https://github.com/ristik/bft-core/pull/415);
that PR remains open until the owner decides. Publication is not architecture
acceptance, deployment authorization or implementation-completion evidence.

The binding development choices are reproduced here: clean-room implementation
with Apache-2.0 new source, ordinary EVM evidence, exact-incumbent recovery,
funded BFT-operator rewards, development economics and fresh genesis.
[ADR 0011](../adr/0011-staking-component-reuse.md) and the
[P1 assessment](p1-staking-component-reuse-assessment.md) record provenance and
alternatives. Older inbox, optional-reward, GPL-destination and migration text
is superseded. The core validator-entity decisions remain in
[ADR 0012](../adr/0012-validator-entity-model.md).

## 0. Publication scope and implementation boundary

This revision preserves v5's architecture and incorporates subsequent settled
profile facts: normalized-L1 turnover with testnet D≤1/2; any-age UC verification
(no W_cert/evidence coupling); current package caps; pending-J closure staging;
and the implemented scheme-2 CBOR/SHA-256 root evidence path. It makes no new
production economic decision. DEV-DEFAULT values are examples for development,
not promises of a production profile or a description of every test fixture.

Custody, election, root records and recovery have implementation and paired-lane
evidence. Prospective GovernanceParams and funded RewardPool remain design work;
FixedPolicy currently supplies immutable parameters. Real root evidence is in
[contracts #46](https://github.com/ristik/unicity-pos-contracts/pull/46), paired
with core #654; the earlier locally defined root vote digest is obsolete.
S1's original Go builtin oracle is not an activated 0x0103 builtin. The separately
exposed EVM-domain evidence format still needs an authenticated consensus codec
or explicit exclusion; do not call that path completed real-message verification.

All component APIs below describe the intended design. Concrete implementation
selectors and remaining fixture boundaries are tracked in the contracts
`docs/p85/INTERFACE.md`; no document merge changes a runtime ABI. Current code
reference for this publication: core `a02be17ce`, contracts `316203f441`.

## 1. Decision and scope

Implement clean-room, native-UCT self-bond contracts in `unicity-pos-contracts`, with immutable custody and fixed module permissions. One validator entity operates BFT Core and its coupled EVM node, with separate signing keys and mirrored assigned weights. Aggregator committees remain unweighted. Rewards belong to PoS and go only to those BFT Core operators. PoA accounting is external: deploy no PoA reward mechanism.

Evidence protection is option A: ordinary EVM transactions. Always publish the exact last acknowledged incumbent recovery slate K with a primary candidate J. Retirement intent, exclusion, slashing, zero remaining principal and undercoverage never disable K. K preserves authority, not a promise of full backing. Slashing is a small economic penalty, not the security basis of consensus. The owner supplies the operational premise that fewer than one third of validators change at each epoch boundary and the carried-over validators remain an available quorum, retaining keys and terminal state. With weighted committees, quorum means sufficient committed voting weight, not merely a headcount majority.

Recovery must not require every incumbent to cooperate. For the exact K only, reuse authenticated incumbent key bindings and previously verified possession; do not collect fresh assignment PoPs from every K member. Root consensus authorizes the fresh recovery context. This is the narrow recovery-kind validation exception implemented by the coupled handoff path. Ordinary primary candidates still require fresh assignment PoPs from every selected member. Under the operational quorum premise, recovery can complete even if a minority refuses fresh signatures.

Keep one committed recovery per frozen parent, then let K complete acknowledgement using its retained quorum. No recovery retry ladder, larger acknowledgement codec or generic root-side election is needed. No economic rule can suppress this path. This is conditional BFT liveness under eventual synchrony, available quorum and retained state; it cannot promise progress after loss of those prerequisites. Exits still wait for finality and protection gates.

The profile excludes root evidence admission/barriers, release authorities/clearances, optional-K availability/status logic, K coverage checks, fresh-all-member recovery PoPs, legacy migration paths and optional-reward gates. External audit scheduling is a mainnet concern. Keep historical policy snapshots, key histories and ordinary nonces: those are liability data, not format versioning. Use one genesis format, one candidate format with explicit primary/recovery kinds, one storage layout and fresh genesis; no legacy decoder or migration path.

## 2. Components, state and complete mutation surface

Five immutable contracts plus the existing authenticated SealRegistry:

| Component | Owned state | Authority |
|---|---|---|
| StakeCustody | Identity/roles, lots, key tombstones/history, assignment/session references, retirement deadlines, penalty debit guards, principal/bounty/treasury credits | Only verified reservation, lifecycle, penalty and maturity transitions; only credit owners can claim |
| ElectionPolicy | Bounded live index, admitted EVM bindings and staged operator payees with delegation replay nonces, frozen election identity records/results, primary PoP slots, candidate and K bodies/proof slots, attempt cursor | Select/reserve/publish; cannot spend or release principal |
| Evidence | Verified offences, historical exposure commitments, settlement cursors, per-lot pending holds and exclusion | Fixed authenticated vote verifier; bounded, attributable penalty requests only |
| GovernanceParams | Bounded proposals, activation schedule, immutable authority and policy snapshots | Prospective parameters only; no module replacement, balance access or arbitrary slash |
| RewardPool | Explicit funding, acknowledged reward intervals with historically fixed operator payees, allocated rewards/credits, settlement cursors | Funded assigned-weight rewards; cannot access custody |
| SealRegistry | Verified origin, control lineage, progress offsets, UC time, closure/retirement/acknowledgement records | Existing verified system import only; relayers supply data, never finality |

All initializers execute atomically through the manifest-pinned deployment factory, then seal permanently. Pin compiler, dependencies, bytecode, addresses, native-unit denomination, fixed proof slots, field widths, canonical encodings and resource limits in the genesis manifest. IDs bind network, chain, deployment, operation and nonce; hashes use separate operation domains. No storage migration or upgrade selector. Protocol/wire version pins remain explicit and distinct from storage migration. Contracts check fixed callers, never `tx.origin`.

The contracts build/deployment manifest must pin Solidity `0.8.37`, EVM target `cancun`, `via_ir = true`, optimizer enabled, `bytecode_hash = "none"` and `cbor_metadata = false`. Use the one-run size profile for `src/p85/**` (also used by `src/bridge/**` in the current manifest); keep 200 runs for the SealRegistry and unrestricted sources. Pin Foundry `v1.8.1`, forge-std revision `bf647bd6046f2f7da30d0c2bf435e5c76a780c1b` and OpenZeppelin Contracts v5.4.0 revision `c64a1edb67b6e3f4a15cca8909c9482ad33a02b0`. Record resulting bytecode/code hashes and verify runtime/initcode size limits and the unchanged SealRegistry code hash and empty Solidity storage layout. Scope bounded-loop lint suppressions to the P85 sources and justify them with enforced resource ceilings. These settings are reproducibility requirements, not a relaxation of protocol rules or evidence of worst-case system gas acceptance.

The following inventory is the draft ABI and authority matrix. Except payable funding/bond and claims, methods move no native currency externally. Getters are permissionless. Each accepted state change and its replay guard commit atomically.

| Method / caller | Authentication, writes and replay guard | Balance effect |
|---|---|---|
| `initialize` / fixed factory, each module | Exact manifest, one permanent initialized bit | Forced prebalance is surplus, not funding/stake |
| Registry `import` / verified system path | Verified UC and sequential control-record IDs/predecessors; advances durable cursor | None |
| Custody `register` / owner | Root-key possession over identity/owner/domain/nonce; unique key tombstone; allocates never-reused StakingID | None |
| `bond(id)` / owner | Actual value; open generation; lot/index capacity; creates unique lot | Balance and principal increase equally |
| `proposeRootKey` / owner | New key possession/uniqueness and role nonce; stages future binding | None |
| `proposeRoles`, `acceptRoles(id,nonce,newOwner,newWithdrawal)` / current and nominated role holders | Every acceptance, including existing-withdrawal consent, binds both nominated addresses and the current role nonce; replacement resets collected consent; atomic installation advances the nonce | Existing credits keep their creditor |
| `requestRetirement` / owner | One request per generation; excludes future primary snapshots | None; no release |
| Election `admitDelegation(binding,proof)` / relayer | Owner authorization plus EVM-key possession over the exact tuple including operatorPayee; network/chain/Election address/operation, identity/generation, root/EVM bindings, role nonce, delegation nonce and expiry; stores binding/payee and consumes the identity/generation delegation nonce atomically | None; future binding/payee only |
| `elect(origin)` / system hook | Imported threshold, predecessor/attempt, policy snapshot, no unresolved result; stores frozen result | None |
| Custody `reserveCandidate` / fixed Election | Exact primary lots and K incumbent exposure references; same lineage; unique result/session; primary coverage only | Encumbrance metadata; principal counted once |
| Election `submitAssignmentPoPs` / anyone | Bounded primary proofs over exact frozen assignment/predecessor/attempt/member; unique slot, exact duplicates no-op | None |
| `finalizeCandidate` / anyone | Every primary proof, current primary coverage/eligibility; derives exact body and mandatory K commitment; one finalization bit | None |
| `reconcileCandidate` / anyone and system hook | Objective primary failure or exact Registry terminal record; revision/cursor; cannot disable K | None; invalidation alone never releases |
| Custody `applyRootRecords` / anyone and hook | Next bounded Registry prefix, exact session/candidate/attempt and exposure commitments; instantiate derived exposures before closing old references | Reclassifies principal, never pays |
| Election `syncLiveIndex` / Custody | First qualifying bond/final closed generation, membership guard | None beyond originating operation |
| Evidence `submitEvidence(pair,history)` / anyone | Authenticated bounded conflict pair, historical attribution, timely execution; canonical offence ID | Creates verified case and all affected lot holds atomically; no debit yet |
| `settleEvidence(case,batch)` / anyone | Exact next ascending lot prefix and frozen budget; advances durable cursor | Requests capped debits; removes a hold only once corresponding work settles |
| Custody `applyPenalty` / fixed Evidence | Independently reads verified case, historical exposure, remaining cap and case/lot marker | Principal decreases by exactly treasury/bounty credits created |
| Custody `mature(lots)` / anyone | Exact stored closure, progress/time and reference gates; atomically reads Evidence pending holds; unique lot release bit | Remaining principal becomes withdrawal credit |
| Custody `claim(amount,to)` / creditor | Own credit, checks-effects-interactions and reentrancy guard | Balance and credit decrease equally |
| Governance `queue`, `cancel` / fixed genesis authority | Bounded proposal/nonce, authenticated activation anchors, predecessor policy | None |
| `execute` / anyone | Timelock and interacting constraints rechecked; once per proposal | Schedules policy, no immediate historical changes |
| `activateDue` / hook | Next due policy at eligible election boundary, ordered activation cursor | None |
| RewardPool `fund()` / anyone | Actual `msg.value` credited to unallocated funding | Pool balance and available funding rise equally |
| `closeIntervals(records)` / anyone and hook | Contiguous acknowledged assignment/rate intervals and Registry progress; exact interval ID/cursor | Available funding becomes reserved interval budget |
| `settleRewards(interval,batch)` / anyone | Next ascending StakingID prefix; immutable weights/payees/budget; member settlement marker | Reserved budget becomes operator credit; final rounding residue returns to available funding |
| RewardPool `claim(amount,to)` / credited operator payee | Own credit, debit before transfer, reentrancy guard | Pool balance and credit decrease equally |

`acceptRoles(id,nonce,newOwner,newWithdrawal)` must match the pending tuple exactly. A transaction prepared for a superseded different tuple fails with `RoleTupleMismatch`, including consent from the existing withdrawal authority. Replacing a pending proposal clears all collected consent; nominated role holders must accept and the existing withdrawal authority must consent to its replacement. Successful installation advances the role nonce and leaves existing credits with their creditor.

`admitDelegation` is the sole post-genesis operator-payee nomination path; `proposeRoles/acceptRoles` does not nominate reward payees. Its canonical signed payload is `(network,chain,ElectionPolicyAddress,admitDelegation,StakingID,generation,rootNodeID,rootVerificationKey,evmNodeID,evmVerificationKey,operatorPayee,roleNonce,delegationNonce,expiry)`. Both owner authorization and EVM possession bind this full payload, including a nonzero operatorPayee. ElectionPolicy owns the staged `(binding,operatorPayee)` and next delegation nonce keyed by `(StakingID,generation)`; require and consume that nonce once in the stated operation domain. Changing the payee cannot reuse an old signature or consumed nonce. Check the current owner/role nonce and expiry at admission. A payee-only nomination uses the same mutator and unchanged keys. Manifest payees seed genesis values; subsequent nominations affect only later election snapshots and become reward destinations only through a later acknowledged assignment. Neither nomination nor a role change edits frozen records, exact K or existing credits.

Read interfaces expose position/lot/exposure/assignment records, `credit`, `snapshot`, `candidate`, `recoveryAuthorization`, `Evidence.releaseState(lot)`, case/exclusion state, `params`, `progress`, `ucTime`, closure/retirement records and reward interval/budget state. `Evidence.releaseState(lot)` combines custody reference/retirement status and authenticated deadlines with accepted-case holds and settlement state; no off-chain receipts or clearances. There is no separate `keyHistory` or `coverage` getter requirement. Reconstruct historical keys and liability from retained exposure key hashes and assignment epoch records, `exposureChain(id,generation)` and permanent `keyOwner` tombstones. Reconstruct primary coverage from `generationLots`/`exposureLots`, remaining lot principal, committed weights and `bondUnit`; this changes the read surface, not attribution or liability rules.

Only claims transfer currency out. Failed claims roll back locally and cannot trap other creditors. No proxy, delegatecall, arbitrary call, sweep, admin withdrawal, `setModule`, arbitrary penalty list or migration entry point. Unexpected transfers are surplus with no entitlement. Deployment or governance cannot reinterpret surplus as principal/reward funding.

## 3. Custody and historical liability

Each immutable deposit lot stores initial and remaining principal, StakingID/generation, category, references, captured penalty/protection policy and deadlines. Categories are free bonded F, encumbered E and draining D. Maturity moves principal into credit C. Full-generation retirement is supported; partial voluntary withdrawal, delegation, shares, NFTs, auctions, restaking and automatic compounding are excluded. New bonds create new lots. After retirement intent, no new lots enter that generation. A new generation opens only after all old lots, including zero-balance lots, have completed closure/maturity; old keys/history/credits remain.

Reserve all contributing snapshot lots, including weight-quantization dust. Later deposits are not liable for earlier assignments. Compatible consecutive assignments may reference the same lot only for the same identity on one authenticated lineage; references are not extra assets. Record nominal exposure and committed weight separately from remaining backing. K points to the incumbent's already locked exposure records even when their remaining balance is zero; it never recreates spent assets or references a previously released position. Provision union capacity for both primary and K at genesis, rather than letting runtime capacity omit K. After adding the primary references, `reserveCandidate` must leave one reference slot free on every incumbent lot (`refCount < R_max`), including lots of excluded or retiring incumbents and lots with zero remaining principal. Otherwise it reverts atomically with `ReferenceCapacity` before publication; no partial reservation survives. The reserved slot admits the derived K exposure before replaced references close, so recovery import cannot stall on reference capacity. This limits new primary reservations and never suppresses an existing exact K.

Lifecycle is `Reserved → Published → Prepare/Freeze → H → acknowledgement → reference closure → draining → maturity → claim`. A retirement request after snapshot cannot rewrite frozen primary membership. A pre-snapshot request excludes a primary but not exact K. Local timeouts, missing PoPs, relayer crashes and predicted epoch dates never release a reference. A never-prepared candidate still needs root-ordered rejection/attempt advancement before its references close. Exact pre-H Abort closes only that attempt after import; H is irreversible. Supersession adds all derived references before closing replaced ones. Session locks survive abort of a later uncommitted proposal.

Root-key rotation activates only with committed membership. On Ack import, install each acknowledged exposure's frozen root key as current even if a later nomination has been staged. Clear staging only when it matches the installed key; preserve a distinct later nomination. Thus reserving B, then staging C, then acknowledging B installs B and leaves C staged; acknowledging an unchanged current key also preserves a distinct staged key. Keep historical key-to-identity/generation/assignment intervals and permanent cross-identity key tombstones. Root and EVM keys are distinct, with no duplicate or cross-role reuse. Historical verification reconstructs authenticated history after cache eviction; it never falls back to current keys. Retain exposure commitments and records permanently in this initial layout. External archives retain bodies and witnesses while obligations or historical verification require them. There is no pruning mutator or full-history mandatory-hook scan.

The root evidence verifier authenticates actual signed VoteInfo network/domain/key/voting epoch/round and distinct canonical statements, including noncommitting votes. `offenceID = H(network,domain,key,votingEpoch,votingRound)` excludes signatures and statement order. A third conflicting statement is the same offence; another round is distinct. Historical exposure selects only attributable lots. On admission freeze the sorted lot set, offence-era rule, reporter and nominal penalty budget; settlement debits ascending lots by the minimum of case budget, remaining attributable principal and remaining per-lot lifetime penalty cap. Shared assignments never multiply the cap. The cap is against each lot's initial principal across all assignments and keys. Cumulative bounty depends only on cumulative actual debit, so chunking cannot inflate it. A zero-debit valid offence is recorded and excludes future primary eligibility. Exclusion lasts for that StakingID; no governance clearing path is provided.

A slash never edits an active trust base or K. Before Prepare, a primary member's exclusion/coverage loss invalidates that primary and requires ordered cancellation/re-election; a K-only slash leaves both the primary body and K usable. After Freeze, evidence cannot execute until EVM resumes. On resumption apply valid evidence normally; committed weights remain until a later handoff. If churn limits or replacement availability prevent removal, extend current authority and try a later election. Removing an offender is never required for chain progress.

Conservation after every successful call:

- Custody `B = F + E + D + C + U`, with nonnegative unsolicited surplus U, `F+E+D = Σ remaining`, `C = Σ credits`, and `0 ≤ remaining ≤ initial`.
- Every lot is in one category; reservations add no balance. Bond increases B/principal equally; penalty and maturity exchange principal for credits; claim decreases B/credits equally.
- Settlement cursors/debit markers and accounting update atomically. Credits cannot be slashed as if still principal. Unmet protection, references or pending valid cases prevent maturity even at zero balance.

## 4. Evidence, rounds, UC time and exact exit predicate

**Censorship assumption (selected option A).** Evidence is protected only if the complete valid pair executes as an ordinary EVM transaction by its authenticated round-progress cutoff. Sending it to a node, mempool or operator is insufficient. Assume reporters can obtain ordinary inclusion while execution is available within the evidence window; validators can defeat a report by censoring it, and a freeze can make a report late. Longer holds do not prove inclusion. Accepted cases install holds before returning and survive delayed settlement, but unseen cases do not block maturity. There is no root evidence lane, admission receipt, barrier, forced-inclusion guarantee or named release authority.

Use canonical progress `p(e,r)=offset_e+(r-firstRound_e)` for ordinary current-epoch rounds. Genesis offset is zero. If H is ordered at original round h, set the next offset to `p(e,h)+1`, with successor first round A*. Proof seal rounds, arrival time and arbitrarily high old suffix rounds cannot change offsets. While no successor ordinary progress exists, progress stays at H's endpoint. Authenticated skipped ordinary rounds count; raw round subtraction across epochs is forbidden.

Preserve unbounded old suffix recovery: no signing fence or finite suffix budget. Closure requires the exact consecutive terminal proof and available terminal state. The successor's first ordinary committed control record carries `CloseLiability(network,assignment,H.RecordID,R_H,exposureDigest,keyHistoryDigest)` and its proof/checkpoint binding. Key closure by `(epoch,H.RecordID,R_H)`, not proof encoding or terminal seal round. The first such closure fixes `p_close` and its UC time; repeat proofs cannot reset either. Until imported closure, the obligation stays open. A closure for installed but never-acknowledged J
still names J's assignment. Custody stages that closure while J is Reserved,
advances the authenticated record cursor, and applies its original progress/UC
anchors when RecoveryAck materializes J and exact K. It does not silently drop
the liability or substitute recovery-import time. Maturity/election require a
complete reconciled prefix, including no unresolved staged assignment. Invalid
records revert fail-closed; they are not skipped to keep the shard producing.
The bounded stage/recovery sequence and restart/replay must be tested.

Normal offences through h have inclusive admission cutoff `p(offence)+Δ_ev`. Every old signing context above h, including losing branches and mixed valid/invalid suffix payloads, uses that terminal assignment's recovery obligation: no expiry before closure, then inclusive cutoff `p_close+Δ_ev_suffix`. Actual signed rounds still identify offences. Later historical signatures and proofs remain verifiable but do not restart the cutoff; signature creation time is not inferable from its round. This deliberately bounds economic liability while leaving historical recovery valid. New reports after cutoff are late under option A, even if the underlying signature was created earlier. This is a specified S1/H7 accounting amendment, not an existing D5 theorem.

For each lot obligation j retain its captured protection policy, closure ID, inherited deadline d_j and final liability anchor z_j. Use the normal interval endpoint, or `max(normalEndpoint,p_close)` when the assignment/key could sign suffix recovery. Imported retirement must cover all active, prepared and session references, bind their digest, and have `p_ret ≥ max z_j`; the local ledger independently checks zero references. Never-assigned lots use an imported post-request progress/time anchor and empty exposure set.

Define:

- `roundUntil = max(p_ret+Δ_hold_ret, max_j d_j, max_j(z_j+Δ_hold_j))`.
- `evidenceUntil = max_j(z_j+Δ_ev_j)`; empty set contributes no historical deadline.
- `timeUntil = max(t_ret+T_floor_ret, max_j(t_close_j+T_floor_j))`, using UC times at or after the relevant closure/retirement, with comparable chain lineage.

`mature` requires all reference/session closures and import prefixes, current p strictly greater than both roundUntil and evidenceUntil, current quorum-approved UC time at least timeUntil, and no unsettled accepted case affecting the lot. Equality fails round gates and passes the time gate. Captured maxima cannot be shortened by later policy reductions. Missing proof/state/history/UC time fails closed for exits, not consensus recovery.

UC time is the owner's chosen wall-clock measure. Require authenticated UC binding to the executed block's root lineage and monotonic time; use no local EVM timestamp, operator-supplied time or separate clock authority. The floor means elapsed quorum-approved UC seconds, relying on honest quorum enforcement of the UC clock policy; signatures alone are not an independent physical-time oracle. No additional clock authority or anchor-freshness mechanism is introduced. D6 checkpoint acquisition must stay within the chosen floor: DEV-DEFAULT checkpoint maximum age 300 UC seconds and acquisition allowance 300 seconds are strictly below the 3,600-second floor. Raising either requires preserving positive margin.

## 5. Election, authorization and post-H recovery

The mandatory block order is verified Registry import, bounded lifecycle reconciliation, due parameter activation, threshold election, then user transactions. Incomplete mandatory prefixes disable election/maturity, not root consensus. Every paired builder, follower and replay engine executes the same order with reserved system gas. Ordinary evidence remains in user transaction order; accepted holds and strict cutoff gates determine its race with maturity.

Snapshot the first observed election threshold once: origin/progress, parent/state, parameter snapshot, predecessor/attempt, identities, bindings, operator payees and lots. Each frozen election identity record binds StakingID/generation, root/EVM NodeIDs and verification keys, assigned weight, operatorPayee and exposure references. Commit the complete record, including operatorPayee, in the assignment hash and authenticated candidate/exposure commitments carried through Prepare, root validation and acknowledged history. Later same-block changes do not affect it. Skip missed thresholds rather than inventing historical snapshots. One unresolved result at a time. Primary eligibility requires no earlier retirement/exclusion, valid root and delegated bindings, principal at least B_min and `w=floor(principal/U_bond)>0`. Rank by descending w then ascending fixed-width unsigned StakingID.

Use deterministic bounded greedy election. Starting with eligible incumbents, trim lowest ranks to target, then fill with highest-ranked outsiders up to target. Reject the complete seed if minimum size or churn constraints fail; do not search alternatives. Visit the remaining outsiders once in frozen rank order, replacing the current lowest-ranked retained incumbent only when the outsider outranks it and all trial constraints pass. Removed incumbents are not re-enqueued. Equal-weight smaller IDs win ties. Final validation precedes atomic reservation. Bootstrap is genesis-only; an empty later committee is not bootstrap.

Every trial uses the same last committed O and its committed weights v, even for excluded or retiring members. O and S are sets of StakingIDs. For each shared identity, compare the canonical binding tuple `(rootNodeID,rootVerificationKey,evmNodeID,evmVerificationKey)`; equality requires every field to match. Let `r` count shared StakingIDs with any changed binding field, once even when both root and EVM bindings change. Define `removed=|O\S|+r`, `added=|S\O|+r`, and `M=removed+added`. Enforce the membership budget on M and the strict boundary `3·max(removed,added) < min(|O|,|S|)`. Separately enforce normalized weight distance `D=Σ_i|w_i/W-v_i/V|` over the union of StakingIDs, with missing weights zero; compare by exact integer cross-products, never float. Forced exits, shrinkage, binding replacements and weight changes consume their applicable budgets. Unchanged-binding overlap includes only shared identities whose entire binding tuple matches and must carry strictly more than two thirds of both committees' committed weight; this does not itself prove those operators are online. Payee changes alone are not signing-binding replacements. Apply the same r/removed/added, M, strict-boundary, D and overlap checks to O→J and J→K, using each boundary's predecessor/successor records and weights; retain the operational availability assumption. Bootstrap has no overlap check.

PR3 must translate a primary `ReferenceCapacity` refusal into ordered `NoCandidate` with current-authority continuation, never an omitted or modified K. Failure creates an ordered `NoCandidate` reason (invalid profile/capacity, cardinality, membership churn, weight/overlap churn, reservation incompatibility) and no new reservation. Existing committed authority continues. A scheduled election or slashing event does not expire the incumbent committee. The greedy policy can miss a feasible alternative; that delays rotation, not the chain.

For primary assembly, store exact unsigned assignment and frozen exposures as Reserved. Collect each successor's fresh H3 assignment PoP, including retained members, over network/partition/shard/assignment hash/predecessor/attempt/node ID. The frozen EVM parent is excluded from this signature and bound by Prepare. Registration/delegation proofs cannot substitute here. Reject cross-role reuse and wrong contexts. Finalization derives canonical complete body from stored fields and PoPs, marks Published and writes fixed proof slots. A missing proof delays publication; ordered rejection is the release path.

**Always-present K.** In the same result store `RecoveryAuthorization{network,chain,contracts/codeHashes,resultID,snapshotDigest,baseRootBodyID,baseAssignmentHash,KRecords,KBindings,incumbentExposureDigest,capturedPolicies}`. K is exactly the last acknowledged coupled committee, preserving identities, keys, weights, operator payees and existing locked exposure references. KRecords and the authenticated exposure commitment include each incumbent assignment's operatorPayee, never the current staged nomination. Its binding authority comes from that committed assignment, not a current mutable owner consent. Owner role/key/payee changes cannot revoke recovery duties or redirect K rewards mid-session. No exclusion, minimum bond, coverage or retirement filter applies to K. K has no independent usability bit and cannot be removed. The genesis manifest supplies the authenticated initial committee, initial operator payees, possession and exposure baseline; a missing/malformed baseline is invalid configuration, not a no-K operating mode.

Prepare proves at the last certified pre-freeze EVM state P: manifest identities, primary hash/Published/coverage and mandatory K commitment. A stale pre-slash primary proof is insufficient. Root binds P, K digest and session lineage durably. No EVM mutation is needed thereafter to construct recovery. Keep the combined primary/K lot union within preallocated worst-case capacity and retain the per-incumbent-lot recovery slot required in §3; incumbent references already exist and do not require fresh collateral. K's membership, keys, weights, payees, lots and captured policy remain immutable despite retirement, exclusion or slashing.

**Recovery derivation.** If J commits H but cannot acknowledge, any relayer derives a recovery-kind candidate from P, K and current root lineage. It contains exactly K with fresh successor root/EVM epochs, current predecessor BodyID, next legal attempt, replaced assignment hash, activation/TR fields and commit-chain commitment. Non-epoch membership/key/weight/operatorPayee/configuration fields are fixed; no unrelated governance or aggregator changes. Compute assignment/candidate/change-record/BodyID/FrozenID in the accepted dependency order. It advances authority; it never restores an old epoch or rolls back H.

Root checks positive authorization proofs (or its persisted verified session commitment), installed-unacknowledged lineage, current predecessor/attempt, zero prior committed recoveries, exact derivation, identity/key/weight/payee bijection, overlap and coupled thresholds. For this recovery kind alone, authenticated prior incumbent possession plus exact unchanged keys replaces per-member fresh assignment PoPs. Do not accept a legacy PoP as though it signed the new context. Root Prepare/endorsement/H consensus binds that context; EVM recertification and acknowledgement require the actual assigned quorum. No new per-member readiness certificate or signature collection lane is introduced. Primary-kind candidates continue to require all fresh PoPs. A candidate claiming the recovery kind with any changed key/member/weight/operatorPayee/exposure or foreign session is rejected.

The carried-over quorum retains both root and EVM keys, terminal proof/state and archive material until authenticated session completion. It can complete terminal proof/bootstrap and K's EVM recertification without the unavailable minority. The same overlap can ordinarily finish J as well; recovery remains the explicit path for a failed installed successor. Fewer-than-one-third churn is not a substitute for quorum availability or state retention. Operations must maintain these premises at every boundary, including recovery.

Acknowledgement winning root order before recovery Freeze closes the session and rejects stale recovery. Freeze winning first prevents the competing acknowledgement. One committed recovery H consumes the allowance durably; restart, new attempt ID or Abort cannot reset it. Uncommitted retries do not consume it. After K commits, let its retained quorum acknowledge; do not require another election or supersession. Abort is legal only for an uncommitted attempt and never unfreezes an installed unacknowledged H. Final acknowledgement closes the authorization; sequential import still reconstructs J and K exposures before exits.

An ordinary transition uses a single-step acknowledgement; J followed by K
has root/shard deltas two and both commit IDs. The current profile caps the
supersession span at two. Root admission, folder, ureth decoder and Registry
must agree. Pending-ack admission prevents an unbounded succession of ordinary
handoffs; acknowledgement imports the bounded history itself. No preload mode
or legacy migration is required at fresh genesis.

Election/exposure arrays sort by StakingID; root members and coupling bindings by root NodeID; EVM members and primary PoPs by EVM NodeID. All reference one authenticated identity record; never positionally zip arrays with different orders. Reject duplicates, missing IDs and altered weights/payees/exposures. Recovery uses the same orders with its explicitly empty fresh-PoP field.

Bound scanning by V_max, lots by L_max, live references by R_max, bodies/proofs and all batch lengths. Merge sorting is `O(V_max log V_max)`; at most V_max replacement trials inspect bounded committee unions; snapshot work is `O(V_max·L_max·R_max)`. No historical scan in the hook. Reject configurations whose measured worst-case work exceeds reserved system gas; benchmark limits in implementation before enabling this development profile.

## 6. Explicit development economics and governance

Every value in this table is **DEV-DEFAULT, not frozen**. Let one UCT mean 10^18 native base units in the development genesis; integration must explicitly pin this denomination. Integer arithmetic is checked. Amounts/rates are base-unit integers internally.

| Parameter | DEV-DEFAULT | Immutable development-profile governance bounds |
|---|---|---|
| Bond unit U_bond; minimum B_min | 100 UCT; 100 UCT | Unit fixed for this genesis; minimum 100–10,000 UCT, an integer multiple of unit |
| Committee | N_min=4; package N_target=N_max=6 | Shared validator ceiling 16; measured package N_max=6; raising it needs a new measured profile |
| Churn | M≤4; testnet D≤1/2 | Bound is pinned configuration; D≤1/4 is a conservative production recommendation, not a universal protocol rule. Strict <1/3 key/member change and >2/3 unchanged-binding weight overlap remain |
| Election cadence | Package rehearsal: 400 ordinary progress rounds AND 300 UC seconds since last acknowledged ordinary rotation | Pin exact deployment values; the v5 longer-interval example was 100,000 rounds AND 604,800 UC seconds. Recovery bypasses cadence. Prospective governance must preserve queued/captured deadlines |
| Activation lead | 10 root rounds after accepted Prepare, subject to D4 proof readiness | 2–1,000 rounds; never a timeout-based authority expiration |
| Objective offence penalty | 1% of historically exposed initial principal, rounded down to base units | 0–2%; captured per obligation |
| Aggregate per-lot lifetime penalty cap | 5% of initial principal | 0–10%; captured on lot creation and never raised for that lot |
| Reporter bounty | 10% of actual penalty, capped at 1 UCT per case | 0–20%, cap 0–10 UCT; treasury gets remainder |
| Ordinary/suffix evidence window | 1,000 rounds | 200–10,000; relevant holds strictly exceed evidence windows. No W_cert: UC verification is any-age, independent of economic report deadlines |
| Normal, suffix and retirement hold | 2,000 rounds each | 400–20,000; each relevant hold strictly greater than its evidence window |
| UC time floor | 3,600 seconds after closure/retirement | 3,600–604,800 seconds, inherited maxima preserved |
| Governance delay | 2,000 progress rounds AND 3,600 UC seconds | 2,000–100,000 rounds AND 3,600–604,800 seconds; no shortening a queued delay |
| Rewards | 1 UCT per 1,000 ordinary progress rounds; genesis pool 10,000 UCT | Rate 0–10 UCT per 1,000 rounds; no minting or minimum funding guarantee |
| Capacity | Package V_max=16, L_max=1, N_max=6, R_max=4; maxBatch=32, records hook H=2 | Immutable deployed ceilings; measure complete union/recovery work against reserved gas. Solidity supports larger V/L test bounds (below), not authorization to deploy those with package gas |

The small penalty and cap exercise custody without treating deterrence as a
safety requirement. `D` is normalized L1 distance; `D/2` is total variation. For
equal weights replacing k of n gives D=2k/n; adding one to four gives 0.4,
removing one of four or replacing one gives 0.5. All fit the testnet bound,
subject to the separate binding/overlap rules. D≤1/4 is a conservative production
recommendation, not a hardcoded network rule. Normal handoffs replace a small
subset; rehearse over-bound refusal, pre-H abort and exact-K emergency recovery.

The current package (`deploy/testnet/pos.py`) uses V/L/N=16/1/6, H_records=2 and
3,000,000 reserved gas per record, with measured margin; contracts #32/core #601
supply the measurement guard. The one-entry validator ceiling is 16. Raising
V/L/N or adding mandatory hooks requires complete composition measurements and
matching core/ureth/contracts pins, not just the wider Solidity constructor
limits. The original body/proof examples (256 KiB/1 MiB) do not override the
actual codec/profile limits.

Custody initialization, including deployment through the fixed factory, must enforce `1 ≤ V_max ≤ 128`, `1 ≤ L_max ≤ 8`, `3 ≤ R_max ≤ 4` and `1 ≤ maxBatch ≤ 32`; out-of-range genesis fails with `InvalidGenesis`. Alternative test genesis values may be smaller only within these bounds. Check each ceiling independently, including V=129, L=9, R=5 and batch=33, and accept exact ceilings and valid smaller configurations. Resource ceilings remain immutable after deployment.

Use a fixed genesis development governance account, fixed treasury and initial operator payees explicitly listed in the manifest. Only the authenticated `admitDelegation` path nominates later operator payees; governance cannot redirect them. Governance account rotation is outside this immutable development profile; choose a new genesis if necessary. Serialize proposals by predecessor policy hash. Check bounds at queue, execution, activation and snapshot; interacting proposals are evaluated in sequence. Activate only at a future ordinary election boundary with no unresolved session; freeze reward rate and acknowledged assignment payees per interval and economic policy per obligation. No update clears exclusion/holds, rewrites candidates/history, raises old penalties or shortens old protection. Governance cannot relax continuity or K authorization. No unset economic choice blocks development implementation.

## 7. Funded PoS operator rewards

Rewards are in scope, not an optional follow-up. Fund RewardPool separately with native UCT. Only BFT Core operator reward addresses recorded in acknowledged assignments receive entitlements; the coupled EVM node has no second identity or reward allocation. Owner-authenticated `admitDelegation` may nominate a future operatorPayee as specified in §2. RewardPool derives and fixes interval payees from authenticated acknowledged assignment history, never a mutable current binding at closure or delayed settlement. A nomination affects only a later snapshot and acknowledged assignment; exact K retains its incumbent assignment's payee. Already fixed intervals and existing credits keep their original payee/creditor. PoA uses external accounting, with no contract reward accrual.

Intervals are half-open canonical ordinary-progress ranges. Split at acknowledged assignment and reward-rate boundaries. Settlement catches up only through authenticated acknowledged history. Assign each progress unit to exactly one active assignment; old suffix rounds and uncommitted candidates earn nothing. During a frozen handoff, unresolved assignment intervals wait for final acknowledgement/import. Derived J/K history determines exact boundaries; zero ordinary-progress intervals pay zero. Skipped ordinary rounds count under the same progress policy as elsewhere; no per-proposal or uptime bonus is inferred.

Close intervals strictly in chronological order. For interval length L and captured rate q base units per 1,000 rounds, nominal emission is `floor(q·L/1000)`. Fix budget `b=min(nominal,availableFunding)` once at closure. Later funding never backfills a closed exhausted interval. For each member i with assigned weight w_i and total W, entitlement is `floor(b·w_i/W)` to its recorded operator payee. Reserve b before any member settlement. Process canonical StakingID batches; return final rounding residue to available funding. Interval boundaries and budgets cannot depend on caller-selected batch sizes or claim order. Funding transaction order can affect future budgets, deliberately; settlement order within an interval cannot.

Pool invariant is `B_reward = available + reservedUnsettled + operatorCredits + surplus`. Funding raises balance/available; interval closing only reserves; settlement converts reservation to credits and returns dust; claim reduces balance/credits. No borrowing custody, fees or bridge backing; no mint authority, compounding, treasury sweep or promised yield. A drained reward pool never blocks consensus, election, penalties or exits. Slashes do not retroactively alter committed reward weights; exclusion affects later primary selection, and K may temporarily retain an excluded operator. That consequence follows the owner's economic-tickle policy.

## 8. Clean-room implementation and reference boundary

Write the contracts from this specification and independently produced behavioral tests; copy or translate no upstream staking source, storage layout or algorithm implementation. Keep a provenance log separating design inspiration from any explicitly imported general-purpose library. Choose Apache-2.0 for newly authored development contract code and interface artifacts; dependency licenses remain their own. This is an engineering clean-room direction, not a retrospective claim that prior investigators never read upstream code or a legal conclusion about provenance. No GPL port or inherited audit is assumed.

Design inspirations (no source import or inherited audit):

| Reference | Inspiration retained | Deliberate local replacement / counterexample |
|---|---|---|
| [Polygon StakeManager and SlashingManager, eef5359](https://github.com/maticnetwork/contracts/tree/eef53596046eda70a53653a8e5ff79b1cbf0a4f9/contracts/staking) | Separation of principal, rewards and penalty transfers | Native lots and objective per-offence IDs; a batch nonce alone cannot deduplicate a third conflicting vote |
| [Cosmos SDK staking v0.53.0](https://github.com/cosmos/cosmos-sdk/blob/v0.53.0/x/staking/README.md) | Historical exposure and unbonding liability | Asynchronous root acknowledgement; rotation must not shift an old offence onto a new deposit |
| [Ethereum consensus v1.5.0](https://github.com/ethereum/consensus-specs/blob/v1.5.0/specs/phase0/beacon-chain.md) | Exit distinct from withdrawability; objective signed conflicts | Root closure and UC-time floor; a retirement request during an extended assignment cannot release funds |
| [Aptos stake.move, 1d47dfc](https://github.com/aptos-labs/aptos-core/blob/1d47dfc1f1499dba071952a03eb8ddab8ca02f00/aptos-move/framework/aptos-framework/sources/stake.move) | Explicit balance stages and owner/operator separation | Certified reference closure replaces local epoch status; locally inactive funds can still back a prepared successor |

The historical P1 PR #389 merge/review is not architecture acceptance or proof of custody correctness. This publication uses local issue/PR exports and pinned source/provenance; it claims no new live GitHub or upstream-license verification. External audits, production economics and deployment planning are outside this development design. Internal review and owner architecture acceptance remain required.

## 9. Acceptance evidence and review disposition

These are required future tests, not tests executed for this design-only deliverable.

| Area | Required independent trace and expected result |
|---|---|
| Custody | Bond→primary→H→ack→replacement→retirement→maturity→claim; exact accounting after every call; request-time exit, forced transfer, callback and reverting recipient cannot bypass rules |
| Role proposal replacement | Prepare consent for tuple B, replace either nominated address at the same nonce, then submit old consent: reject; replacement clears collected consent and completed installation advances the nonce. |
| Delayed key activation | Reserve B, stage C, import B Ack: current B and staged C; B remains usable for delegation/reservation. Matching staging clears; unchanged-current Ack preserves a distinct nomination; historical liability remains attributable. |
| Recovery reference capacity | Fill incumbent references to the permitted primary limit, refuse another primary atomically with ReferenceCapacity/NoCandidate, then derive K without capacity failure before closing references, including excluded, retiring and zero-balance incumbents. Paired-node recovery and worst-case system gas remain integration obligations. |
| Evidence | Same pair reordered/re-encoded/third statement debits once; distinct rounds respect lifetime caps; old key after rotation charges only historical lots; chunking preserves total bounty; zero principal still records offence |
| Option A | Evidence executes exactly at cutoff and holds maturity through delayed settlement; next round is late; mempool receipt has no effect; freeze crossing cutoff can lose unexecuted evidence protection |
| Closure | No terminal proof after arbitrarily many old suffix rounds, then restore quorum and complete consecutive proof; no fence; reset successor rounds map identically for alternative proof seals; closure duplicates never extend deadlines |
| Exit | Missing closure/import/history prevents maturity; round equality fails, UC-time equality passes; lowering policy preserves maxima; unrelated clean lots remain claimable beside held lots |
| Election | Bootstrap, shrink, forced exit, weight-only change, canonical ties, dust, seed failure and same-block edits match an independent model; exact rational and strict one-third boundaries tested; NoCandidate preserves current authority |
| Same-identity binding churn | On both O→J and J→K, ten equal-weight shared identities with one root-only, EVM-only or simultaneous root/EVM replacement each give r=1, removed=added=1, M=2, D=0 and overlap 9/10: pass default limits; simultaneous change counts once. Three replacements give M=6 and fail M≤4 despite 9<10 and overlap 7/10. With six unchanged identities of weight 100 and four changed identities of weight 1, each change variant gives r=4, M=8, D=0 and overlap 600/604>2/3, but 12<10 fails the strict boundary (and M also fails). |
| Primary credentials | Missing/wrong/replayed context PoP cannot publish; changing predecessor/attempt requires fresh primary proofs; root/EVM key collision rejected |
| N4/N6 slash recovery | Slash incumbent A before election to below coverage, including zero; publish J excluding A plus unchanged K; J commits H and fails to acknowledge; hold EVM P fixed, derive/commit K without fresh signatures from unavailable A; retained quorum recertifies and acknowledges; import both exposures, then allow protected exits |
| Publication race | Slash K-only A after publication but before Prepare: K unchanged and primary valid; slash a primary member: reject stale proof and require cancellation/re-election; retirement before/after snapshot never revokes K |
| Recovery validation | Recovery-kind candidate with changed key/weight/member/payee/exposure, wrong P, foreign authorization or stale predecessor is rejected; missing fresh K PoPs alone is not rejection; changed-key primary still requires all proofs |
| N5 bounded recovery | Primary plus K acknowledges span two, both commit IDs preserved; second committed recovery rejected even after restart/Abort; uncommitted retries consume no allowance; once K commits its retained quorum completes without third transition |
| Root ordering | Ack wins→recovery refused; Freeze wins→competing ack refused; post-H Abort cannot roll back; delayed bounded imports materialize exposures before reference closure |
| N3 ordering | StakingID order opposite root/EVM NodeID order yields identical builder/verifier hashes; positional zip or misplaced primary PoP rejected |
| Operational premise | Reject transition at exactly one-third member/key change or overlap weight exactly two-thirds; retain state and keys across successive boundaries; separately demonstrate quorum-loss stalls are availability failures, not stake checks |
| Rewards | Assignment/rate boundaries, J/K zero-length intervals, exhausted pool, late funding, shared payee, rounding, batch/claim reorder and replay preserve pool invariant; PoA and separate EVM-node reward paths absent |
| Payee binding and delayed settlement | Publish J/K with payee A, then admit an owner-authorized nomination of B before delayed settlement. Frozen J, old intervals and exact K retain A; a later primary snapshot carrying B pays B only after acknowledgement. Credits already allocated to A remain claimable only by A. Reject altered-payee signatures, reused delegation nonces, candidate/exposure payee tampering and recovery payee changes. |
| Governance/resources | Interacting proposals, unsafe lowered floors and oversized configuration fail; builder/follower/replay agree; benchmark full bounded index and primary/K union against reserved system gas |

These acceptance rows describe required behavior, not a claim that every row
already has implementation evidence. Exact-K liveness always depends on retained
available quorum and terminal state. Ordinary evidence remains censorable.
Governance/rewards, historical retirement-to-claim and S3/S4 network evidence
must be completed in their own implementation tracks.

## 10. Implementation PR split and residual questions

Five logical implementation slices, each split into reviewable PRs as needed; cross-repository commits must identify their matching revisions. Fresh-genesis fixtures replace compatibility/migration work.

1. **Authenticated lifecycle and continuity protocol (H3/H7/S1, Q1–Q3 integration).** Implement the single primary/recovery format, exact-incumbent possession exception, authoritative binding-aware M/strict-turnover and separate weight-distance/overlap checks at both boundaries, root derivation/session count, span-two acknowledgement, proof-independent progress/closure and UC-time import. Freeze operatorPayee in authenticated identity/assignment/exposure interfaces and exact-K validation. Pair root/ureth replay and signed negative fixtures. Weighted trust-base/certificate checks must accept mirrored weights end to end before authoritative PoS.
2. **Clean-room custody, identity and evidence (P2–P4/S1/S2).** Immutable deployment, lots/roles/history, references, ordinary evidence, capped penalties, exact maturity/claims; publish interface/provenance manifest and independently checked accounting/permission properties. Freeze the owner-authenticated admitDelegation payload, ElectionPolicy payee staging storage and replay interface for PR3. Use PR1 authenticated fixtures; no root evidence or clearance APIs.
3. **Election and certified transport (P5/P6).** Bounded snapshot/selection reproducing PR1's binding-aware continuity predicates at both boundaries, primary delegated assembly, mandatory K reservation/proofs, hook ordering/gas, operator tooling and root intake. Implement the frozen payee nomination/storage interface and certified payee projection through snapshot/candidate/exposure history, preserving incumbent K payees. Demonstrate slash-before-election and frozen-P post-H recovery with an unavailable minority. Shadow PoA runs confer no live PoS authority.
4. **Governance and funded operator rewards (P7/T8).** Install explicit DEV-DEFAULT parameters/bounds, future activation, separate funded pool, chronological interval settlement from immutable acknowledged weights/payees and operator-only credits. Test delayed settlement across payee nomination, exhaustion, rounding and interacting proposals. No on-chain PoA incentives.
5. **Paired development integration (P8 and internal rev).** Fresh genesis and reproducible build/run manifest; genuine weighted rotations, restart/archives, withheld evidence, delayed terminal proof, primary failure→K acknowledgement, complete delayed custody imports and eventual exits. Execute the acceptance matrix and resource benchmarks; document operational quorum/key/state-retention duties.

**Acceptance boundary:** the evidence route, development-values policy, reward scope, clean-room direction and fresh-genesis policy are settled; owner acceptance of this complete architecture remains pending. Implementation review must validate the explicit exact-incumbent PoP exception and weighted overlap premise against actual H3/Q1–Q3 code, pin native denomination and measured gas/proof ceilings, and preserve the implemented quorum-approved UC-time semantics of the paired execution context. These are concrete integration acceptance obligations, not permission to reintroduce optional K, a release authority, migration paths or frozen production economics.

## Review fixes 2026-10-07

- Count shared-identity root/EVM binding replacements once in r and in both numerical churn predicates at O→J and J→K; retain separate weight-distance/overlap checks and add replacement vectors.
- Assign payee nomination and replay protection to admitDelegation/ElectionPolicy; authenticate frozen payees through assignment/exposure history, preserve exact K and existing credits, and add delayed-settlement coverage within the existing five-PR split.
- Accept one reserved reference slot per incumbent lot after primary reservation, with atomic `ReferenceCapacity` refusal mapped by PR3 to `NoCandidate`; this prevents capacity from blocking exact-K import without weakening recovery or replacing paired/gas acceptance.
- Accept historical keys and liability reconstruction from retained exposures/assignments, `exposureChain` and permanent `keyOwner` tombstones, with coverage reconstructed from lots, remainders, weights and `bondUnit`; separate `keyHistory`/`coverage` getters are unnecessary for the same liability semantics.
- Accept `Evidence.releaseState(lot)` as the release-status surface; combining custody deadlines/reference status with accepted-case holds keeps release checks available without enlarging custody's getter surface.
- Clarify `acceptRoles(id,nonce,newOwner,newWithdrawal)`, replacement consent reset and nonce advance on installation; exact-tuple consent prevents a superseded transaction authorizing another recipient and preserves the existing rule.
- Clarify Ack activation from the frozen exposure, clearing only matching staging and preserving a later nomination; delayed imports must install the acknowledged key regardless of mutable staging.
- Clarify factory/custody genesis lower and upper bounds for V/L/R/batches, with isolated boundary checks; bounded test genesis cannot exceed immutable development resource ceilings.
- Accept the pinned compiler/toolchain/dependency manifest and P85-only one-run optimizer profile, retaining 200 runs elsewhere and source-scoped bounded-loop lint suppressions; reproducibility and deployable size must preserve SealRegistry artifacts and enforced ceilings.

## Time clarification 2026-10-08 (root-time audit, ADR 0013)

`timeFloor` (and the evidence/hold UC-time predicates) are **UC-time holds**: the exit predicate is `T_now >= T_anchor + d` over the authenticated, non-decreasing UC seconds, with equal seconds valid. A UC-time delay bounds how soon a *certified* time can satisfy the predicate; it does not establish a minimum real-time (wall-clock) hold, because the anchor may be stale (`T(A) >= t_A - sigma` is not guaranteed) and certified time bounds future time (`<= t_cert + eps + Delta`) but not the past. Round counts are not seconds either (the root advances a round immediately on a QC). Do not read `timeFloor`, the holds or the evidence windows as wall-clock protection; a wall-clock guarantee would need a separately specified anchor-freshness mechanism, and none is added here. No new mechanism.

## Publication record and #85 acceptance map (2026-10-20)

| #85 requirement | Location and evidence boundary |
|---|---|
| Licensing/provenance and fair comparison | §8, ADR0011 and P1 assessment; contracts #7 provenance manifest; no retroactive claim about prior researchers |
| Responsibility/storage/caller matrix | §2; fixed permissions and separate custody/reward balances |
| Identities, units, reservations, snapshots, evidence, deadlines/replay | §§2–6; concrete codec/selectors remain pinned implementation artifacts |
| Happy/failure paths including stalled EVM | §§3–5 and §9; pending-J closure, exact K, abort/ack ordering and delayed settlement |
| Conservation, bounded algorithms and gas | §§3,5–7; measured package caps distinguished from wider constructor limits |
| Upstream duties/tests mapped to behavior | P1 assessment §§3,5,10; historical schema tests do not prove behavior |
| Review and bounded implementation plan | §9/§10; v5 review amendments above incorporated; this publication still requires rev3 review and owner acceptance |

The implementation provenance is retained in
[contracts PROVENANCE.md](https://github.com/ristik/unicity-pos-contracts/blob/fbf499bffa/docs/p85/PROVENANCE.md).
The original v5 proposal/review are investigation records, not required runtime
inputs. No code, fixture, profile, storage or wire pin changes in this publication.
