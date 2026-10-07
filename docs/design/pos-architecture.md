# PoS staking architecture for owner acceptance

Status: proposed architecture for development, 2026-10-07. This document specifies the intended behavior; it
does not claim the contracts or protocol changes are implemented. Owner acceptance approves this scope and its
tradeoffs. Implementation acceptance requires the evidence in section 12; production parameters and deployment
are separate decisions.

## 1. Decision and scope

Proof of stake (PoS) assigns voting weight to validators according to their own deposited native Unicity
currency (UCT), called **self-bonding**. A validator is one organizational entity operating a BFT Core consensus
node and a co-hosted Ethereum Virtual Machine (EVM) execution client, including its helper processes. Byzantine
fault tolerant (BFT) consensus orders the network's authoritative state. The BFT Core committee is called the
**root committee**. There is no separately elected or separately rewarded EVM operator.

Implement five immutable contracts in `unicity-pos-contracts`, with fixed permissions and a clean-room
implementation: inspiration from other projects, no copied or translated staking source. Use one fresh-genesis
format and storage layout. **Genesis** is the initial authenticated network configuration and state. No
migration or compatibility dispatcher is needed. Rewards are funded PoS operator entitlements. **Slashing**
deducts a penalty from bonded principal for proven misconduct; it is an economic deterrent, not a consensus
safety mechanism. Recovery always retains the exact incumbent committee.

**In scope**

- Validator identity, owner/operator/withdrawal roles, separate root and EVM keys, and self-bond custody.
- Deterministic weighted election, coupled root/EVM epoch changes, and exact-incumbent recovery.
- Full-position retirement, historical liability, protected withdrawal, ordinary EVM evidence transactions, and capped penalties.
- Funded rewards to BFT Core operators, prospective development governance, and bounded execution.
- Authenticated lifecycle imports, positive execution proofs, retained history, and paired-node integration acceptance.

**Out of scope**

- Proof of authority (PoA) reward contracts: PoA selects authorized operators without stake election; its accounting is external.
- Production economic parameters, production deployment, external audits, and scheduling external reviews; internal development/review remains required.
- The bridge, its redemption/nullifier data structures, and the end-user token profile. Native UCT custody here does not define either system.
- Third-party stake delegation, shares, non-fungible staking tokens, auctions, restaking, partial voluntary withdrawal, or automatic compounding.
- A separate EVM incentive scheme, weighted aggregator committees, and independent EVM-only rotation.
- Forced evidence inclusion, a root evidence inbox, release clearances, administrator balance access, upgrades, and migration paths.
- Aggregator correctness proofs, data availability services, endpoint discovery, and aggregator reconfiguration policy.

The validator and trust boundaries follow [ADR 0012](../adr/0012-validator-entity-model.md). For this
development profile, the ordinary-evidence and clean-room decisions below replace older open evidence-protection
questions and reuse/licensing proposals in repository documents. Older statements making PoS rewards optional do
not apply to this profile.

## 2. Roles, authority, and vocabulary

An **epoch** is an interval governed by one committed committee configuration; a **round** is a numbered voting step.
An **assignment** records identities, signing keys, voting weights, operator reward payees, and EVM configuration.
The **Unicity Trust Base** is the authenticated root committee and weights; each successor is authorized by the preceding committee. A **Unicity Certificate
(UC)** authenticates certified state and quorum-approved time. A **quorum** is sufficient distinct authorized
signing weight: for total weight `W`, root threshold is `floor(2W/3)+1`; EVM certification threshold is
`floor(W/2)+1` over the mirrored root weights. Headcounts cannot replace weights. An **aggregator shard** is a
separately configured transaction aggregation service; its committee is unweighted and its central launch
operator is trusted as described below.

| Role | Authority and obligation |
|---|---|
| Validator/operator | Runs both processes; retains their separate keys and recovery state; receives the assignment's operator rewards and bears penalties through its bonded position. |
| Owner | Registers a position, bonds native UCT, authorizes future key/role bindings, and requests retirement. This account role is distinct from a consensus signing key. |
| Withdrawal authority | Receives matured-principal credits; must consent to replacement of this role. Existing credits keep their original creditor. |
| Operator reward payee | Address nominated through owner-authenticated `admitDelegation`, frozen in the election identity record and acknowledged assignment, and captured in reward intervals; changing it affects only a later acknowledged assignment. |
| Reporter | Supplies conflicting signed votes and historical attribution through an ordinary EVM transaction; earns a bounded share of actual penalties. |
| Relayer | Supplies proofs and candidate data without finality authority; anyone may relay. |
| Development governance | Fixed genesis account that schedules bounded prospective parameters; cannot replace modules, take funds, erase evidence, or waive recovery. |
| Treasury | Fixed genesis address credited with the non-reporter share of penalties; has no custody administration power. |

A **primary candidate J** is the newly elected assignment. **Recovery slate K** is exactly the last acknowledged
coupled committee: identities, keys, weights, operator payees, and locked exposures. A **handoff session** binds
a primary and its mandatory recovery authorization to one frozen EVM parent state. **Prepare** records that parent and pauses
EVM execution; **Freeze** binds the agreed handoff context; endorsements authorize it; **H** is the irreversible
root-ordered handoff commit. **Acknowledgement** confirms successor EVM certification in root order. **Abort**
is an ordered cancellation available only before the affected attempt commits H.

Each position has a never-reused **StakingID**, an unsigned fixed-width identity number. A **generation** is one
complete bond/retire/withdraw lifecycle for that identity. A **lot** is one deposit with immutable initial
principal and recorded remaining principal. An **exposure** attributes a lot to an assignment's signing
liability. A **reference** keeps that exposure locked while a candidate, assignment, or recovery session can
still use it. **Coverage** means sufficient remaining backing for a primary assignment's reserved weight. A
**proof of possession (PoP)** demonstrates control of a signing key in a specified context. A **NodeID**
identifies a signing node; an **origin** identifies the authenticated root input to execution. A **nonce**
prevents replay; an **attempt** numbers ordered handoff proposals. A **snapshot** freezes the election inputs; a
**digest** is a cryptographic hash commitment. EVM-key delegation authorizes the co-hosted signing role; it is
not delegation of other people's stake.

The root authenticates the validator entity by its root consensus key. The EVM key is procedurally delegated,
distinct, and bound to the same identity and weight. Duplicate or cross-role keys are rejected. Rotation
activates only with committed membership; historical bindings and permanent key tombstones prevent reassignment
of an old key to another identity. Owner role changes cannot revoke already committed recovery duties.

## 3. Components and contract boundary

**SealRegistry** is the existing authenticated contract view of root-certified execution and lifecycle records.
Its verified system import is the source of finality for the five new contracts. A **system hook** is mandatory
execution performed identically by block builders, followers, and replay engines before ordinary transactions,
with reserved execution gas. A **positive execution proof** proves a specific committed state or event; no
end-user absence-proof service is required for this architecture.

| Component | Owned state | Permission boundary |
|---|---|---|
| `StakeCustody` | Identities, roles, lots, key history, references, protection deadlines, penalty debit markers, and withdrawal/treasury/bounty credits | Fixed modules request verified lifecycle or penalty changes; only creditors claim their own credits. |
| `ElectionPolicy` | Bounded live-position index, EVM bindings and staged operator payees with delegation replay nonces, frozen election identity records/snapshots, proof slots, primary/recovery bodies, and attempt cursor | Selects, reserves, and publishes; cannot spend or release principal. |
| `Evidence` | Verified offences, frozen historical exposure sets, per-lot holds, exclusions, and settlement cursors | Fixed objective verifier; only attributable bounded penalty requests. |
| `GovernanceParams` | Fixed authority, bounded proposals, activation schedule, and historical policy snapshots | Prospective parameters only; no module replacement or arbitrary penalties. |
| `RewardPool` | Explicit funding, acknowledged intervals, weights/payees, reserved budgets, and credits | Funded operator rewards only; no access to stake custody. |
| `SealRegistry` | Verified origin, ordered control lineage, progress offsets, UC time, closure/retirement/acknowledgement records | Verified system imports only; a relayer cannot declare finality. |

The genesis manifest pins compiler, dependencies, bytecode, addresses, currency denomination, field widths,
canonical encodings, proof slots, and resource ceilings. A fixed factory initializes all modules atomically and
seals initialization permanently. Operation IDs bind network, chain, deployment, operation, and nonce; separate
hash domains prevent cross-operation replay. Contracts authenticate fixed callers, never `tx.origin`. State
changes and replay markers commit atomically.

No proxy, `delegatecall`, arbitrary call, sweep, administrator withdrawal, module setter, arbitrary penalty
list, or migration entry point exists. Only claims transfer funds out. Claims debit the caller's credit before
transfer and reject reentrancy; a failed recipient reverts that claim without trapping other creditors.
Unexpected transfers remain surplus, which neither deployment nor governance can reinterpret as stake or reward
funding.

### Function, state, and event interface

These are proposed application binary interface (ABI) names and semantic event fields, not claims about deployed
signatures. `id` means StakingID; `lotID`, `caseID`, `resultID`, `sessionID`, and `intervalID` uniquely identify
their corresponding records. A cursor records the next unprocessed element of a canonical sequence. Events
describe successful state changes; state and authenticated proofs, not an unauthenticated event stream,
authorize downstream action.

| Contract / function | Caller and checks; state effect | Required event information |
|---|---|---|
| All: `initialize(manifest)` | Fixed factory; exact manifest and permanent initialized bit | `Initialized(manifestHash)` |
| Registry: `import(records)` | Verified system path; certificates and contiguous predecessor IDs; advance durable cursor | `RecordsImported(firstID,lastID,progress,ucTime)` |
| Custody: `register(rootKey,proof,roles)` | Owner; identity/domain/nonce-bound root PoP and unique key; allocate id | `Registered(id,owner,rootKey,roles)` |
| Custody: `bond(id)` payable | Owner; open generation and capacity; create lot for actual received value | `Bonded(id,generation,lotID,amount)` |
| Custody: `proposeRootKey(id,key,proof)` | Owner; possession, uniqueness, role nonce; stage future binding | `RootKeyProposed(id,key,nonce)` |
| Custody: `proposeRoles`, `acceptRoles` | Current/nominated holders; exact tuple and nonce, withdrawal consent, all required acceptance; atomic installation | `RolesProposed(id,roles,nonce)`, `RolesAccepted(id,roles,nonce)` |
| Custody: `requestRetirement(id)` | Owner; once per generation; exclude future primary snapshots, without releasing funds | `RetirementRequested(id,generation)` |
| Election: `admitDelegation(binding,proof)` | Anyone relaying owner authorization and EVM PoP over the full tuple including operatorPayee; network/chain/Election address/operation, identity/generation, root/EVM bindings, role/delegation nonces, expiry; atomically stage binding/payee and consume the identity/generation nonce | `DelegationAdmitted(id,bindingHash,operatorPayee,nonce)` |
| Election: `elect(origin)` | Hook; threshold, predecessor/attempt, policy, and no unresolved result; freeze snapshot | `ElectionFrozen(resultID,snapshotHash)` or `NoCandidate(origin,reason)` |
| Custody: `reserveCandidate(result)` | Fixed Election; exact primary lots and incumbent references, same lineage, unique session, primary coverage | `CandidateReserved(resultID,sessionID,exposureDigest)` |
| Election: `submitAssignmentPoPs(resultID,proofs)` | Anyone; bounded exact primary-context proofs; unique slots, exact duplicates are no-ops | `AssignmentProofStored(resultID,nodeID)` |
| Election: `finalizeCandidate(resultID)` | Anyone; all primary PoPs and current eligibility/coverage; derive body and mandatory recovery commitment once | `CandidatePublished(resultID,primaryHash,recoveryDigest)` |
| Election: `reconcileCandidate(resultID)` | Anyone/hook; objective primary failure or exact Registry terminal record; advance revision/cursor; never disable recovery | `CandidateReconciled(resultID,revision,status)` |
| Custody: `applyRootRecords(records)` | Anyone/hook; next bounded Registry prefix, exact session/attempt/exposure; add derived references before closing old ones | `RootRecordsApplied(firstID,lastID,referenceDigest)` |
| Election: `syncLiveIndex(id)` | Custody only; first qualifying bond or final closed generation, membership guard | `LiveIndexChanged(id,included)` |
| Evidence: `submitEvidence(pair,history)` | Anyone; objective verifier, historical attribution, timely execution, canonical offence ID; install all affected holds atomically | `EvidenceAccepted(caseID,offenceID,exposureDigest,reporter)` |
| Evidence: `settleEvidence(caseID,batch)` | Anyone; next ascending lot prefix and frozen budget; advance cursor, release only settled holds | `EvidenceSettled(caseID,cursor,actualDebit,bounty)` |
| Custody: `applyPenalty(caseID,lotID)` | Fixed Evidence; independently check verified case, historical exposure, remaining cap, and case/lot debit marker | `PenaltyApplied(caseID,lotID,debit,bounty,treasuryCredit)` |
| Custody: `mature(lots)` | Anyone; section 7 gates and Evidence holds; once per lot, principal becomes withdrawal credit | `LotMatured(lotID,creditor,amount)` |
| Custody: `claim(amount,to)` | Creditor; own balance, debit before guarded transfer | `CreditClaimed(creditor,to,amount)` |
| Governance: `queue`, `cancel` | Fixed authority; bounded proposal, nonce, authenticated anchors, predecessor policy | `ParamsQueued(proposalID,policyHash,anchors)`, `ParamsCancelled(proposalID)` |
| Governance: `execute(proposalID)` | Anyone; elapsed dual timelock and interacting constraints; schedule once | `ParamsScheduled(proposalID,policyHash)` |
| Governance: `activateDue()` | Hook; next eligible ordinary election boundary and ordered cursor | `ParamsActivated(policyHash,origin)` |
| Rewards: `fund()` payable | Anyone; only actual value increases available funding | `RewardsFunded(sender,amount)` |
| Rewards: `closeIntervals(records)` | Anyone/hook; chronological acknowledged assignment/rate intervals and exact cursor; reserve fixed budget | `RewardIntervalClosed(intervalID,start,end,budget)` |
| Rewards: `settleRewards(intervalID,batch)` | Anyone; next ascending identity prefix, fixed weights/payees/budget; once per member, return final residue | `RewardAllocated(intervalID,id,payee,amount)`, `RewardIntervalSettled(intervalID,residue)` |
| Rewards: `claim(amount,to)` | Credited operator payee; own balance, debit before guarded transfer | `RewardClaimed(payee,to,amount)` |

`admitDelegation` is the sole post-genesis operator-payee nomination path; `proposeRoles/acceptRoles` does not
nominate reward payees. Its canonical signed payload is
`(network,chain,ElectionPolicyAddress,admitDelegation,StakingID,generation,rootNodeID,rootVerificationKey,evmNodeID,evmVerificationKey,operatorPayee,roleNonce,delegationNonce,expiry)`.
Both owner authorization and EVM possession bind the full payload, including a nonzero operatorPayee.
ElectionPolicy owns the staged `(binding,operatorPayee)` and next delegation nonce keyed by
`(StakingID,generation)`; require and consume that nonce once in the stated operation domain. Changing the
payee cannot reuse an old signature or consumed nonce. Check current owner/role nonce and expiry at admission.
A payee-only nomination uses the same mutator and unchanged keys. Manifest payees seed genesis values;
subsequent nominations affect only later election snapshots and become reward destinations only through a
later acknowledged assignment. Neither nomination nor a role change edits frozen records, exact K, or existing
credits.

Permissionless getters expose `position`, `lot`, `keyHistory`, `exposure`, `credit`, `coverage`, `snapshot`,
`candidate`, `recoveryAuthorization`, `releaseState(lotID)`, `case`, `excluded`, `params`, `progress`, `ucTime`,
`closure`, `retirement`, and reward interval/budget state. `releaseState` reports authenticated closures,
deadlines, and accepted-case holds; it needs no off-chain clearance.

## 4. Registration, bonding, and handoff lifecycle

```mermaid
flowchart LR
    A[Register and bond] --> B[Elect and reserve J plus K]
    B --> C[Collect primary proofs and publish]
    C --> D[Prepare / Freeze / endorse]
    D --> H[Commit H and activate J]
    H --> E[Acknowledge J]
    H --> R[If J stalls: commit exact K once]
    R --> E2[Acknowledge K]
    E --> F[Close references]
    E2 --> F
    F --> G[Retirement and protection gates]
    G --> I[Mature to credit and claim]
```

Bond creates a new lot; all contributing snapshot lots, including weight-rounding dust, are reserved. Later
deposits never become liable for earlier assignments. Compatible consecutive assignments may reference the same
lot only for the same identity on one authenticated lineage. References are not additional assets. Record
nominal exposure and assigned weight separately from backing.

Lots are free bonded, encumbered by references, or draining after release from assignments. Maturity converts
remaining principal into a withdrawal credit. `requestRetirement` is the full-generation unbond request: it
stops new deposits and future primary eligibility but pays nothing. A request after an election snapshot cannot
rewrite its membership; no request removes K. A new generation opens only after every old lot, even a
zero-balance lot, completes closure/maturity. Historical records and unclaimed credits survive that change.

Missing PoPs, local timeouts, relayer crashes, or expected epoch dates cannot unlock principal. Even a
never-prepared candidate requires root-ordered rejection/attempt advancement to close its reservations. Imported
pre-H Abort closes only its exact attempt. A later uncommitted attempt's Abort does not release the original
session lock. Replacing a failed assignment creates all derived exposures before closing replaced references. H
cannot be rolled back.

For custody balance `B`, require after every call `B = F + E + D + C + U`: `F`, `E`, and `D` are free,
encumbered, and draining principal; `C` is all credits; `U` is unsolicited surplus. Each lot belongs to one
principal category and `0 ≤ remaining ≤ initial`. Bond raises balance and principal equally; penalty/maturity
exchange principal for credits; claim reduces balance and credits equally. Credits are no longer slashable
principal. References never multiply balances.

## 5. Election and the strict turnover rule

Mandatory block order is Registry import, bounded lifecycle reconciliation, due parameter activation, threshold
election, then user transactions. An incomplete mandatory import prefix disables election/maturity, not root
consensus. Ordinary evidence stays in user-transaction order. Freeze the first observed election threshold's
origin/progress, parent/state, policy, predecessor, attempt, identities, bindings, operator payees, and lots.
Each frozen election identity record binds StakingID/generation, root/EVM NodeIDs and verification keys,
assigned weight, operatorPayee, and exposure references. Commit the complete record, including operatorPayee,
in the assignment hash and authenticated candidate/exposure commitments carried through Prepare, root
validation, and acknowledged history. Same-block transactions cannot change that snapshot. Skip missed
thresholds; do not invent historical snapshots. Only one unresolved result is allowed.

Primary eligibility requires no prior retirement or exclusion, valid root/delegated keys, principal at least
minimum bond `B_min`, and positive weight `w = floor(principal/U_bond)`. `U_bond` is the bond unit. Rank by
descending weight, then ascending StakingID. Start with eligible incumbents, trim the lowest ranks to target,
and fill with the highest ranked outsiders. Reject an invalid complete seed; do not search alternative seeds.
Visit remaining outsiders once in frozen rank order; replace the lowest-ranked retained incumbent only if
outranked and every trial constraint passes. Removed incumbents are not re-enqueued. Validate the final result
before atomic reservation. Only genesis can bootstrap an empty committee.

Let `O` be the last committed committee with weights `v_i` and total `V`; `S` is a trial successor with weights
`w_i` and total `W`. O and S are sets of StakingIDs. Missing members have weight zero. Every trial uses the same
`O`, including retiring/excluded incumbents. For each shared identity, compare the canonical binding tuple
`(rootNodeID,rootVerificationKey,evmNodeID,evmVerificationKey)`; equality requires every field to match. Let `r`
count shared StakingIDs with any changed binding field, once even when both root and EVM bindings change.
Define `removed = |O\S| + r` and `added = |S\O| + r`. Enforce all of the following:

- Membership budget `M = removed + added` stays within policy.
- Strict turnover: `3 × max(removed, added) < min(|O|, |S|)`.
- Separately, normalized weight distance `D = Σ_i |w_i/W − v_i/V|` over the union of StakingIDs stays within policy; use exact integer cross-products, never floating point.
- Unchanged-binding overlap includes only shared identities whose entire binding tuple matches and holds **strictly more than two thirds of both committees' committed weight**. Headcount overlap alone is insufficient.
- Apply the same r/removed/added, M, strict-turnover, D, and overlap checks to both `O → J` and `J → K`, using each boundary's predecessor/successor records and weights; genesis bootstrap has no predecessor overlap test.

Payee changes alone are not signing-binding replacements. Forced exits, shrinking, binding replacements, and
weight-only changes consume the applicable budgets. Failure emits an ordered
`NoCandidate` reason (profile/capacity, size, membership churn, weight/overlap churn, or reservation
incompatibility), with no new reservation. Current authority continues. This bounded greedy procedure can miss a
feasible alternative; rotation may wait without stopping the chain.

Every primary member, including retained incumbents, supplies a fresh assignment PoP over network,
partition/shard identifiers, assignment hash, predecessor, attempt, and node identifier. A **partition/shard
identifier** selects the configured execution service. Registration/delegation proofs cannot substitute. Prepare
separately binds the frozen EVM parent, excluded from this PoP. Finalization stores the canonical body and proof
slots. Before Prepare, primary exclusion or lost coverage invalidates J and requires ordered
cancellation/re-election. A slash of a K-only member does not invalidate J or K. After Freeze, evidence waits
for resumed execution.

## 6. Exact-incumbent recovery is always published

Publish K with every J, even if an incumbent retired, was excluded, has insufficient backing, or has zero
principal. K uses existing locked exposures, never spent or previously released assets. It has no optional
availability flag, collateral threshold, or fresh owner-consent requirement. Genesis supplies authenticated
initial membership, initial operator payees, possession, and exposure records; a missing baseline is invalid
configuration. Reserve capacity for the primary/K union, up to twice maximum committee size.

Store `RecoveryAuthorization` binding network, chain, contract addresses/code hashes, result, snapshot digest,
incumbent root-body/assignment hashes, K records/bindings, exposure digest, and captured policies. K records and
the authenticated exposure commitment include each incumbent assignment's operatorPayee, never the current
staged nomination. Owner role/key/payee changes cannot revoke recovery duties or redirect K rewards mid-session.
A **root body** is the canonical committee configuration; **BodyID** is its hash. Prepare proves at the last certified
pre-freeze EVM state **P** the manifest, published J, current primary coverage, and mandatory K commitment.
Stale pre-slash primary proofs are insufficient. Root consensus durably binds P, K's digest, and session
lineage.

If J commits H but fails to acknowledge, any relayer derives a recovery-kind candidate from P, K, and current
root lineage without changing frozen EVM state. It preserves K's identities, keys, weights, operator payees,
exposures, and non-epoch configuration. It carries fresh successor root/EVM epochs, current predecessor, next legal attempt,
replaced assignment hash, activation information, the successor **technical record** (certified epoch/round
scheduling metadata), and the ordered commit-chain commitment. Canonical hashes are computed in dependency
order; the **FrozenID** hash binds body, parent, candidate, predecessor, and attempt. Recovery advances
authority; it does not undo H.

Root validation checks positive authorization proofs or its persisted verified session commitment,
installed-but-unacknowledged lineage, predecessor/attempt, unused committed-recovery allowance, exact
derivation, identity/key/weight/payee correspondence, overlap, and both committees' thresholds. For **this exact
recovery kind only**, authenticated incumbent key bindings and previously verified possession replace fresh
per-member assignment PoPs. The fresh-proof field is empty; an old PoP is not misrepresented as a signature on
new context. Root Prepare/endorsement/H consensus authorizes that context; actual assigned quorum must still
recertify and acknowledge the EVM. Any changed member, key, weight, operator payee, exposure, or foreign session
rejects the recovery kind. Primary candidates continue to require every fresh PoP. This is a required protocol validation
change.

At every boundary, carried-over validators must remain an operational quorum and retain both keys, terminal
proof/state, and archive material through authenticated completion. The overlap can ordinarily complete J too; K
is the explicit path if the installed successor fails. Recovery must work without fresh signatures from every
incumbent, including an unavailable minority. Slashing or undercoverage cannot remove this path; removal of an
offender never gates progress.

Root order resolves the race: acknowledgement before recovery Freeze closes the session and rejects recovery;
Freeze first prevents the competing acknowledgement. At most **one committed recovery per frozen parent** is
permitted. Restart, new attempt IDs, and Abort do not reset the allowance; uncommitted retries do not consume
it. Once K commits, its retained quorum finishes acknowledgement. There is no third transition or recovery
ladder. **Folded span** is the acknowledgement encoding's summary of intervening committed transitions. Ordinary
acknowledgement has span zero; J followed by K has root/EVM epoch deltas two and folded span two, retaining both
commit IDs. Root validation, proof folding, EVM decoding, and Registry imports must agree on this two-step
maximum. Imports reconstruct both exposures before exits.

## 7. Evidence, protected unbonding, and withdrawal

The fixed evidence verifier checks two distinct canonical signed `VoteInfo` statements, including votes that
never committed, for the same network, signing domain, key, voting epoch, and round. `VoteInfo` is the consensus
signed-vote payload; a domain separates signing purposes. `offenceID =
Hash(network,domain,key,votingEpoch,votingRound)` excludes signatures and pair order. Reordering, alternative
signature encoding, or a third conflicting statement cannot create a second offence; a distinct round can.
Historical keys/exposures determine liability, never current keys.

Admission freezes the sorted attributable lots, offence-era policy, reporter, and nominal penalty budget, and
atomically installs holds on all affected lots. Settlement processes ascending lot IDs, debiting the minimum of
remaining case budget, attributable principal, and remaining lifetime lot cap. The lifetime cap is against
initial principal across all assignments and keys. Shared references do not multiply it. Bounty depends on
cumulative actual debit, so batching cannot inflate payment. A valid zero-debit offence still records permanent
primary exclusion for that StakingID. No governance clearing path exists. Slashes never edit an active trust
base, K, or committed weights.

**Censorship assumption:** the complete valid evidence must execute as an ordinary EVM transaction within its
authenticated progress window. Sending it to a node, operator, or transaction mempool is insufficient. Assume
reporters obtain timely ordinary inclusion while execution is available. Validators can censor a report, and a
handoff freeze can make an unexecuted report late. Longer withdrawal holds do not guarantee inclusion. Accepted
holds survive delayed settlement; unseen reports do not prevent maturity. There is no root admission receipt,
barrier, or forced-inclusion guarantee.

Canonical ordinary progress is `p(e,r) = offset_e + (r − firstRound_e)`, for epoch `e` and round `r`. Genesis
offset is zero. If H was ordered at old round `h`, successor offset is `p(e,h)+1` and its first round is the
H-authorized activation round. Proof seal round, arrival time, and old **suffix rounds** (post-H recovery
signing rounds without ordinary state changes) do not alter offsets. Until successor ordinary progress, p stays
at H's endpoint. Authenticated skipped ordinary rounds count; raw subtraction across epochs is forbidden. Suffix
recovery has no finite round fence: an available old quorum may need arbitrarily later consecutive rounds to
produce the terminal proof.

**Liability closure** requires exact consecutive terminal proof and available terminal state. The first
successor ordinary committed control record carries `CloseLiability` binding network, assignment, H record ID,
H's terminal state root, exposure digest, and key-history digest, with proof/checkpoint binding. A
**checkpoint** is the authenticated state snapshot used for recovery. Key closure by epoch, H record ID, and
terminal root, not proof encoding or seal round. The first imported closure fixes `p_close` and UC time;
duplicates cannot restart deadlines. Missing closure leaves the obligation open.

Normal offences through h have inclusive cutoff `p(offence)+Δ_ev`, where `Δ_ev` is the captured ordinary
evidence window. Every old signed context above h, including losing branches or mixed valid/invalid suffix
payloads, uses the terminal recovery obligation: no expiry before closure, then inclusive cutoff
`p_close+Δ_ev_suffix`. Historical signatures remain verifiable afterward but cannot restart economic liability;
signed round does not reveal signature creation time.

For each lot obligation j retain its policy, inherited deadline `d_j`, and final liability anchor `z_j`: the
normal interval endpoint, or its maximum with `p_close` if suffix signing was possible. Imported retirement
covers all active, prepared, and session references, binds their digest, and has progress `p_ret ≥ max_j z_j`;
custody independently checks zero references. Never-assigned lots use an imported post-request progress/time
anchor and empty exposure set. Let `Δ_hold` be the applicable captured round hold and `T_floor` the captured
UC-time floor:

```text
roundUntil    = max(p_ret + Δ_hold_ret, max_j d_j, max_j(z_j + Δ_hold_j))
evidenceUntil = max_j(z_j + Δ_ev_j)
timeUntil     = max(t_ret + T_floor_ret, max_j(t_close_j + T_floor_j))
```

Here `t_ret` and `t_close_j` are authenticated UC times at or after retirement/closure on the same comparable
lineage; suffix obligations use their suffix window. Empty exposure sets add no historical deadline. `mature`
requires all reference/session closures and import prefixes, current p **strictly greater** than both round
deadlines, UC time **at least** `timeUntil`, and no unsettled accepted evidence affecting the lot. Equality
fails round gates and passes the time gate. Later parameter reductions cannot shorten inherited maxima. Missing
proofs, state, history, or UC time block exits, not consensus recovery. Even zero-balance lots must complete
these gates.

UC time must be monotonic and bound to the executed block's authenticated root lineage; neither local EVM
timestamp nor operator input substitutes. The elapsed-time floor relies on honest quorum enforcement of the UC
clock policy, not an independent physical clock oracle. Checkpoint age and acquisition allowance must stay below
the floor with positive margin. Retain exposure/key history permanently in this initial layout and archive proof
bodies while verification or obligations need them. Cache eviction must reconstruct authenticated history; no
pruning mutator or mandatory full-history scan exists.

## 8. Funded rewards for BFT Core operators

Fund `RewardPool` separately with native UCT. Only operator payees in acknowledged assignments receive rewards;
co-hosted EVM operation has no second entitlement. Owner-authenticated `admitDelegation` nominates a future
operatorPayee through the payload, storage, and replay rules in section 3. RewardPool derives and fixes interval
payees from authenticated acknowledged assignment history, never a mutable current binding at closure or
delayed settlement. A nomination affects only a later snapshot and acknowledged assignment; exact K retains
its incumbent assignment's payee. Existing intervals and credits keep their original payee/creditor.
PoA accrues no contract rewards. Intervals are canonical half-open ordinary-progress ranges `[start,end)`, split
at acknowledged assignment and reward-rate boundaries. Each progress unit belongs to one assignment. Suffix
rounds, uncommitted candidates, and zero-length intervals earn nothing; unresolved handoff intervals wait for
acknowledgement/import of J/K history. Skipped ordinary rounds count under the same progress policy. No separate
uptime or per-proposal bonus is inferred.

Close intervals chronologically. For length L and captured rate q base units per 1,000 rounds, nominal emission
is `floor(q×L/1000)`. Reserve `b = min(nominal,availableFunding)` once at closure. Member i earns
`floor(b×w_i/W)` for assigned weight `w_i` and total W. Settle ascending StakingID batches to fixed payees,
returning final rounding residue to available funding. Caller batching and claim order cannot change
boundaries/budgets. Later funding does not backfill closed exhausted intervals; funding transaction order
deliberately affects future budgets. Slashes do not rewrite committed reward weights; K can temporarily retain
an excluded operator and its reward entitlement.

Require `poolBalance = availableFunding + reservedUnsettled + operatorCredits + surplus`. Funding raises
balance/available; closing reserves; settlement creates credits and returns dust; claims reduce credits/balance
equally. No minting, custody borrowing, bridge/fee backing, compounding, treasury sweep, or promised yield. An
empty pool never blocks consensus, election, penalties, recovery, or exits.

## 9. DEV-DEFAULT parameters and governance

Every value below is **DEV-DEFAULT**, for development/test only, not frozen production economics. One UCT means
`10^18` native base units in development genesis; integration must pin that denomination. Arithmetic uses
checked integers. `W_cert` is the live certificate window; `V_max`, `L_max`, and `R_max` bound live identities,
lots per generation, and live references per lot.

| Parameter | DEV-DEFAULT | Immutable development-profile bounds / rule |
|---|---|---|
| Bond unit; minimum bond | 100 UCT; 100 UCT | Unit fixed at genesis; minimum 100–10,000 UCT, an integer multiple of unit |
| Committee minimum / target / maximum | 4 / 10 / 32 | Target 4–32; continuity still applies |
| Churn budgets M; D | 4; 1/4 | M 0–4; D 0–1/4; strict <1/3 turnover and >2/3 weighted overlap cannot be relaxed |
| Ordinary election cadence | 100,000 progress rounds AND 604,800 UC seconds since last acknowledged ordinary rotation | 10,000–1,000,000 rounds; 604,800–2,419,200 seconds; recovery bypasses cadence |
| Activation lead after Prepare | 10 root rounds, subject to terminal-proof readiness | 2–1,000; never timeout-based expiry of authority |
| Objective offence penalty | 1% of historically exposed initial principal, rounded down | 0–2%, captured per obligation |
| Lifetime lot penalty cap | 5% of initial principal | 0–10%, captured at lot creation; never raised for that lot |
| Reporter bounty | 10% of actual penalty, capped at 1 UCT per case | 0–20%; cap 0–10 UCT; treasury receives remainder |
| W_cert; ordinary/suffix evidence window | 100; 1,000 rounds each | W_cert fixed; evidence 200–10,000; W_cert ≤ ordinary evidence window |
| Normal / suffix / retirement hold | 2,000 rounds each | 400–20,000; each relevant hold strictly exceeds its evidence window |
| UC-time floor after closure/retirement | 3,600 seconds | 3,600–604,800; inherited maxima preserved |
| Checkpoint maximum age / acquisition allowance | 300 UC seconds / 300 seconds | Preserve positive margin below the 3,600-second floor when changing either |
| Governance delay | 2,000 progress rounds AND 3,600 UC seconds | 2,000–100,000 rounds AND 3,600–604,800 seconds; queued delay cannot shorten |
| Reward rate; genesis pool | 1 UCT per 1,000 ordinary progress rounds; 10,000 UCT | Rate 0–10 UCT per 1,000 rounds; no minting or minimum funding guarantee |
| Capacity | V_max=128; L_max=8; R_max=4; batches ≤32; body ≤256 KiB; witness ≤1 MiB | Fixed resource ceilings; primary/K union provisioned for 64 identities, not governance knobs |

For ten equal-weight members, two identity replacements use M=4 and satisfy strict one-third turnover, but produce D=0.4
and fail the default 1/4 distance cap; one replacement gives D=0.2. For four equal-weight members, one
replacement meets strict overlap but gives D=0.5 and fails the default distance cap. In that case retain
authority and defer rotation.

Serialize governance proposals by predecessor policy hash. Recheck bounds and interacting constraints at queue,
execution, activation, and snapshot. Activate only at a future ordinary election boundary without an unresolved
session. Freeze economic policy per obligation and reward rate/acknowledged assignment payees per interval.
No update clears exclusions/holds, rewrites history/candidates, increases old penalties, shortens old protection, or relaxes K authorization/continuity.
Genesis fixes governance authority and treasury and lists initial operator payees. Only authenticated
`admitDelegation` nominates later operator payees; governance cannot redirect them. Governance-account rotation
requires a new genesis in this profile.

## 10. Trust, failures, and bounded work

Consensus safety assumes authenticated keys, correct verification/execution, durable honest voting locks, and
Byzantine root weight below one third. Slashing does not establish these assumptions. Liveness additionally
needs eventual synchrony (messages eventually arrive within a usable bound), available assigned quorums, and
retained terminal state/proofs. Strict turnover is not proof of availability: loss of quorum, both signing keys,
or required state can stall progress indefinitely. An unavailable minority must not stall recovery merely by
withholding fresh K PoPs.

Each BFT Core node fully trusts its co-hosted EVM; defenses apply across validator entities and peers.
Authenticated execution context must bind to the executed block and be reproducible by another paired node.
Relayers and caches are untrusted; unavailable imports fail closed for exits. Central launch aggregators have no
transition-correctness proofs: root certification checks configured signatures, unweighted quorum, continuity,
order, and configuration, not the truth of their transitions or data availability. Users separately trust their
aggregator operator.

Election/exposure arrays sort by StakingID; root members and coupling bindings by root NodeID; EVM members and
primary PoPs by EVM NodeID. Join by authenticated identity, never array position. Reject duplicates, missing
IDs, and altered weights/payees/exposures. Bound live-index scans, lots, references, bodies, witnesses, and batches.
Sorting costs `O(V_max log V_max)`; at most V_max replacement trials inspect bounded committee unions; snapshot
work is `O(V_max×L_max×R_max)`. Historical storage may grow, but mandatory hooks do not scan it. Benchmark
worst-case work against reserved system gas before enabling this profile; reject oversized configurations.

## 11. Clean-room provenance and implementation boundary

Author contracts from this specification and independently produce behavioral tests. Copy or translate no
upstream staking source, storage layout, or algorithm implementation. Keep a provenance log distinguishing
design inspiration from explicitly imported general-purpose libraries. Newly authored development contract
code/interfaces use Apache-2.0; dependencies retain their own licenses. This is an engineering direction, not a
retrospective certification of prior investigators' separation or a legal conclusion. No upstream audit is
inherited.

| Project drawn on for inspiration | Idea retained | Local design replacing its application |
|---|---|---|
| Polygon StakeManager / SlashingManager, revision `eef53596046eda70a53653a8e5ff79b1cbf0a4f9` | Separation of principal, rewards, and penalty transfers | Native lots and canonical per-offence deduplication, not a batch nonce alone |
| Cosmos SDK staking, `v0.53.0` | Historical exposure and unbonding liability | Root-acknowledged asynchronous closure; old offences cannot charge new deposits |
| Ethereum consensus, `v1.5.0` | Exit distinct from withdrawability; objective signed conflicts | Root closure, suffix liability, and a UC-time floor |
| Aptos `stake.move`, revision `1d47dfc1f1499dba071952a03eb8ddab8ca02f00` | Explicit balance stages and owner/operator separation | Certified reference closure instead of local epoch inactivity |

The [handoff state machine](d4-epoch-handoff-state-machine.md) and [EVM assignment design](h3-evm-assignment.md)
provide protocol detail; their existing runtime implementations must be validated against this profile's changes.
Matching cross-repository revisions and independent internal reviews are required; shadow PoA confers no PoS authority.

Deliver at most five ordered implementation PRs, with fresh-genesis fixtures and matching cross-repository
revisions:

1. **Authenticated lifecycle and continuity protocol.** Own authoritative binding-aware M/strict-turnover and separate weight-distance/overlap validation at both boundaries, the primary/recovery format and exact-incumbent possession exception, session count, span-two acknowledgement, progress/closure, and UC-time import. Freeze operatorPayee in authenticated identity/assignment/exposure interfaces and exact-K validation; pair root/EVM replay and signed negative fixtures, including mirrored weighted thresholds.
2. **Clean-room custody, identity, and evidence.** Implement immutable lots/roles/history, references, ordinary evidence, capped penalties, maturity/claims, and accounting/permission evidence. Freeze the owner-authenticated admitDelegation payload, ElectionPolicy payee staging storage, and replay interface for PR3 against PR1 fixtures; publish the interface/provenance manifest.
3. **Election and certified transport.** Reproduce PR1's binding-aware continuity predicates in bounded selection at both boundaries; implement delegated assembly, mandatory K reservation/proofs, hook ordering/gas, tooling, and root intake. Implement the frozen payee nomination/storage interface and certified snapshot/candidate/exposure projection, preserving incumbent K payees. Demonstrate slash-before-election and frozen-parent recovery with an unavailable minority.
4. **Governance and funded operator rewards.** Install bounded DEV-DEFAULT parameters and prospective activation; implement a separate funded pool and chronological settlement from immutable acknowledged weights/payees. Test delayed settlement across payee nomination, exhaustion, rounding, and interacting proposals; no on-chain PoA incentives.
5. **Paired development integration and internal review.** Assemble fresh genesis and reproducible paired builds; execute the acceptance matrix, weighted rotations, restart/archive recovery, delayed evidence/proofs/imports, primary failure through K acknowledgement and exits, and resource benchmarks. Document retained-quorum/key/state duties.

## 12. Owner acceptance and implementation evidence

The owner can accept the architecture by checking these explicit decisions:

- [ ] One validator entity operates root and EVM with distinct keys, mirrored weights, and operator-only rewards; aggregators remain unweighted.
- [ ] Scope includes clean-room self-bond custody, mandatory funded PoS rewards, and coupled recovery; PoA accounting, bridge/token design, audits, and production economics are excluded.
- [ ] Epoch turnover is strictly below one third, weighted overlap exceeds two thirds in both sets, and carried-over operators must retain quorum availability, keys, and state.
- [ ] Every primary publishes exact K regardless of retirement, exclusion, slashing, undercoverage, or zero backing; only exact K reuses authenticated prior possession.
- [ ] One committed recovery per frozen parent is sufficient under that operational premise; quorum/state loss is an explicit liveness limit.
- [ ] Evidence uses ordinary EVM inclusion; censorship or freeze can defeat unexecuted reports. Slashing is economic deterrence, not the consensus security basis.
- [ ] Withdrawal needs authenticated closure, round/time protection, and settled accepted evidence; neither an expected epoch date nor retirement intent releases funds.
- [ ] Fixed modules, prospective bounded governance, separate reward funding, and DEV-DEFAULT parameters provide a concrete development contract without fixing production economics.

The following are **required future implementation evidence, not tests executed by this document**:

| Acceptance trace | Observable pass condition |
|---|---|
| Register → bond → J → H → acknowledge → replacement → retirement → maturity → claim | Exact custody conservation after every call; forced transfers, callbacks, and reverting claim recipients cannot bypass isolation or release rules. |
| Historical evidence and lot attribution | Reordered/re-encoded pairs and a third statement debit once; another round respects lifetime cap; rotated keys charge only historical lots; chunking preserves bounty; zero balance still records exclusion. |
| Evidence/maturity boundary and censorship | Cutoff equality admits and holds the lot through delayed settlement; next progress unit rejects; mempool submission has no effect; freeze can make unexecuted evidence late. |
| Closure and exit protection | Arbitrarily late suffix proof works after restored quorum; alternative proofs give identical offsets; duplicate closures do not extend deadlines; missing history/import blocks maturity; round equality fails and UC-time equality passes; unrelated clean lots remain claimable. |
| Election against an independent model | Bootstrap, shrinkage, forced exits, weight-only changes, ties, dust, invalid seed, and same-block edits match; exact one-third turnover or two-thirds overlap rejects; NoCandidate preserves authority. |
| Same-identity binding churn at both boundaries | On O→J and J→K, ten equal-weight shared identities with one root-only, EVM-only, or simultaneous root/EVM replacement give r=1, removed=added=1, M=2, D=0, and overlap 9/10: pass default limits; simultaneous change counts once. Three replacements give M=6 and fail M≤4 despite 9<10 and overlap 7/10. Six unchanged identities of weight 100 plus four changed identities of weight 1 give r=4, M=8, D=0, and overlap 600/604>2/3 for each change variant, but 12<10 fails strict turnover (and M also fails). |
| Primary proof contexts | Missing, replayed, or wrong-context PoP prevents publication; changed predecessor/attempt needs fresh proofs; root/EVM key collision rejects. |
| Recovery after slash to zero | Slash incumbent A before election; publish J excluding A plus unchanged K; commit J but withhold acknowledgement; keep P fixed, commit K without fresh A signatures, and let retained quorum acknowledge; import both exposures before protected exits. |
| Publication and root-order races | K-only slash preserves publication; primary slash invalidates stale coverage proof; retirement never revokes K; acknowledgement-first rejects recovery, Freeze-first blocks competing acknowledgement, and post-H Abort cannot rewind. |
| Recovery authorization and restart | Changed key/member/weight/payee/exposure, wrong P, foreign authorization, or stale predecessor rejects; absent fresh K PoPs alone does not; span two preserves both commit IDs; second committed recovery rejects after restart/Abort; uncommitted retries do not consume allowance. |
| Identity ordering and weighted integration | Opposite StakingID/root/EVM order produces identical builder/verifier hashes; positional joins reject; quorum, timeout, and certification paths use mirrored assigned weights end to end. |
| Operational premise | Retained quorum completes terminal proof and EVM recertification with an unavailable minority across boundaries; separate quorum/state-loss traces stall without inventing authority or using collateral as a recovery gate. |
| Rewards and pool conservation | Assignment/rate splits, zero-length J/K intervals, exhaustion, late funding, shared payee, rounding, replay, and reordered batches/claims preserve budgets; no PoA or separate EVM reward path. |
| Payee binding and delayed settlement | Publish J/K with payee A, then admit an owner-authorized nomination of B before delayed settlement. Frozen J, old intervals, and exact K retain A; a later primary snapshot carrying B pays B only after acknowledgement. Existing A credits remain claimable only by A. Reject altered-payee signatures, reused delegation nonces, candidate/exposure payee tampering, and recovery payee changes. |
| Governance and resources | Interacting/unsafe proposals and oversized inputs fail; lowering policy preserves inherited deadlines; builder/follower/replay agree; measured worst-case index and primary/K union fit reserved gas. |

Before authoritative development PoS, pin native denomination and reproducible paired revisions, validate the
recovery possession exception against actual root/EVM validation, prove weighted quorums throughout, confirm
authenticated UC-time enforcement, and measure resource ceilings. Architecture acceptance alone satisfies none
of these implementation gates.
