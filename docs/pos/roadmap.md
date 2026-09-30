# Development roadmap: enshrined EVM, UCT and Proof of Stake

Draft delivery tickets following the Unicity Yellowpaper. Ticket IDs below are the new IDs; the
migration table at the end records the disposition of the earlier work.

The target remains Setup 2: each BFT Core operator runs a paired reth execution node.
BFT Core performs consensus and certification; EVM contracts execute staking and governance.
Aggregator partitions and their shards continue independently alongside the EVM, at their own
cadence. Root rounds, shard rounds and EVM block heights are different counters.

UCT is issued natively at genesis. WUCT is an EVM wrapper; the Unicity Execution-layer token
is a separate custody-backed representation. There is no previous supply migration, ALPHA
currency or PoW issuance. TGE may precede PoS and the bridge.

The current engine-api-adapter branch is a prototype starting point, not the public-release
baseline. In particular, its single-epoch shard trust-base store, count-based QC/TC formation,
standard Engine API attributes and latest-only UC storage do not implement the repaired rules.

## 1. Delivery policy

- Complete and validate each safety dependency before activating its consumer. Private devnets,
  shadow computation, public custody and authoritative governance are separate states.
- Keep the first public chain under PoA. Add PoS only after the full epoch/evidence/retirement
  cycle works with unequal weights and failures. An operator flag alone cannot activate it.
- Use attested execution initially, with root and EVM assignments sharing the same effective
  weights. Stateless execution and succinct execution proofs are later upgrades.
- Initial rewards pay assigned weight per certified root interval. They do not measure uptime.
  Downtime slashing and jailing from missing QC signatures are disabled.
- Initial PoS may use self-bond only. Port only accounting components justified by a reuse
  assessment; importing Polygon's governance and lifecycle wholesale is not a prerequisite.
- Initial bridged tokens support whole-token transfer and burn. Their pinned type rejects
  split, merge and unregistered mint extensions everywhere. Public bridging requires a
  succinct redemption fallback for long admitted histories. A direct-only bridge is private.
- One governance EVM shard is sufficient initially. All certificate formats and tests retain
  full partition/shard context and permit independent aggregator partitions and shards.
- Protocol schedules use threshold comparisons on imported root rounds, never equality to an
  assumed tick. Round-based vesting is disclosed as such. Checkpoint freshness uses a separate
  client policy; no contract execution reads wall time.
- Custody credits are pulled using checks-effects-interactions and reentrancy guards. Pull
  accounting does not eliminate reentrancy by itself.
- Numbers, address assignments, monetary allocations and wire encodings are release decisions
  to freeze in D tickets. Draft examples are not production parameters.

Every ticket has dependencies, a concrete result and acceptance evidence. Protocol-design tickets
are blockers until they have an executable transition model or independent vectors, not just an
ADR saying that implementation will be deterministic. Implementation tickets include relevant
negative cases and crash/replay tests. An estimate should be added after its design dependencies
close; the old one-week/two-week estimates are not retained for unresolved protocol changes.

## 2. Logical milestones

| Gate | Deliverable | Required tickets and evidence |
|---|---|---|
| M0 | Implementable protocol baseline | D1-D6 approved internally, wire/transition models and independent vectors available; scope and deferred guarantees explicit. |
| M1 | Private paired PoA execution | F1-F6: authenticated system call, positive fees, idle progress, deterministic build/verify/replay and durable certified state. |
| M2 | Recoverable PoA service | F7-F9, H1-H6, X1: real epoch replacement, certificate archive/export, checkpoint recovery and mixed aggregator/EVM operation. Current M2a evidence and remaining limits are tracked in [the closure status](m2-closure-status.md); that snapshot does not close the full M2 gate. |
| M3 | Public UCT / TGE under PoA | M2, T1-T7, X2 remediation complete; exact production genesis rehearsed, funded first claims, custody/supply checks and upgrade recovery reviewed. T8 rewards optional and explicitly disabled if unfinished. |
| M4B | Private bridge round trip | M3-equivalent test chain, B1-B6; both directions and supported-profile restrictions verified. No public custody. |
| M5B | Public bridge | B7-B9 and X3 complete; every admitted history redeemable, independent SDK conformance, proof-service recovery and liability audit. |
| M4S | PoS shadow and adversarial testnet | M2 foundation, Q1-Q4, P1-P7, S1-S4, I1-I5, H7, X4; contract output observed in shadow while PoA remains authoritative. |
| M5S | Authoritative PoS | M3, M4S, P8 and X5: integrated audit closed, real weighted handoffs and evidence exercised, checkpoint and retirement protection operational. |
| Later | Optional capabilities | Separately versioned delegation, bridge split/merge, performance accounting, downtime slashing, execution proofs and history accumulator. |

M5B and M5S are independent; neither is a hidden prerequisite of the other. Development can
overlap after the shared foundation. The sequence of public releases is M3 before either.
A bridge can launch while root authority is PoA, with that assumption disclosed. A PoS chain
can launch without bridged UCT.

The TGE gate includes PoA configuration changes and recovery because the public chain must
survive key rotation and upgrades before the PoS work is complete. It does not require a
larger fleet merely to satisfy a topology milestone.

## 3. D: freeze the protocol before implementing it

### D1. Clock, certificate and canonical root-input profile

**Dependencies:** repaired evm-partition.tex and appendix-evm.tex.

Specify each root-origin field, domain, CBOR encoding, authorizing UC/technical-record selection,
signature-free canonical body and companion authentication witness. Fix genesis input, quiet,
repeat, canceled and successful rounds, transition cursor and state/header commitment. Pin
chain ID, Ethereum Keccak/RLP versus Unicity SHA-256/CBOR, and compatibility with the prototype's
different domain prefixes. Certificates cannot be selected by latest local arrival.

**Accepts when:** independent vectors cover alternate valid signature subsets and encodings,
same commitment on all validators, a different authenticated statement, genesis, retries and
root rounds skipped by the EVM. A root-round 98-to-107 observation triggers a threshold at
100 exactly once. Historical replay has every required input without node-local configuration.

### D2. Reth system-call and fee profile

**Dependencies:** D1.

Specify the privileged pre-user call, fixed origin/destination, zero value, no EOA key/nonce,
failure-as-invalid-block rule, separate system resource budget and canonical input committed
in header extraData. Define the Engine API extension, companion-data transport and import
validation. Fix how system work affects block capacity, gasUsed, receipts, tracing and the
EIP-1559 target; no implementation may choose these independently. Specify the positive
base-fee floor as a validity rule, empty withdrawals and initially disabled blob transactions.

**Accepts when:** the design traces one block through builder, follower, devp2p/sync and
reexecution, including missing companion data and a forged ordinary system sender. A gas
accounting vector closes exactly. The same pinned rules apply to eth_call/tracing where
appropriate without allowing RPC callers to authorize privileged canonical state changes.

### D3. Versioned weighted consensus and trust-base identity

**Dependencies:** D1.

Audit all quorum and timeout paths, not only signature verification: root QC/TC assembly,
timeout amplification, shard request collection, quorum-impossibility, recovery certificates
and config endorsement. Define unique signer weight, weight units, overflow bounds and
canonical trust-base body identity excluding endorsement witnesses in the new version.
Preserve legacy verification under its own version.

**Accepts when:** the inventory names every count-based path and its replacement. Independent
vectors cover greater than two-thirds root weight, greater than one-half shard weight,
the configured faulty-weight bound for timeout amplification, duplicate keys/signers,
minority stake with majority identities and sum overflow. No assumed bound on seats substitutes
for the paired EVM's actual weighted threshold.

### D4. Epoch handoff state machine

**Dependencies:** D1, D3.

Write the executable prepare/freeze/endorse/commit/activate/acknowledge and committed-abort
state machine. Specify the exact consensus rounds and message signatures that fix actual
activation and the frozen state summary, including root pipelining. No signature can depend
on unknown future state. Specify candidate attempt binding, cancellation, last certified EVM
parent, outstanding-proposal disposition, new technical record and joining-node readiness.

**Accepts when:** model exploration shows that two effective successors or old/new authorization
of the same extension cannot occur. Cases include delayed signatures, asymmetric delivery,
missed earliest activation, crash at every phase, old quorum loss and committed abort versus
late activate. An incomplete prepare cannot activate through local REST insertion or clock
passage. Under the declared synchrony/availability assumptions the model completes a handoff;
outside them it preserves safety without claiming guaranteed recovery.

### D5. Accountability, retirement and forced-inbox model

**Dependencies:** D1, D4.

Define exact slashable vote domains and the VoteInfo-to-LedgerCommitInfo hash binding. The
PoS signing preimage must bind network/domain even for non-committing votes; a supplied builtin
argument is not a signed binding. Define
collateral reservations, actual retirement acknowledgement, inherited protection periods,
timely evidence commitments and the inbox-processing watermark required before withdrawal.
Specify FIFO admission limits, available payloads, fees/credits, reserved capacity, rejection
semantics and root/EVM consumption acknowledgement.

A concrete initial admission design may use prepaid UCT credits in an immutable EVM escrow:
root admission verifies a certified deposit and consumes a unique credit in root consensus;
unused-credit refund requires a root-certified reconciliation. Define fee ownership, duplicate
deposit-proof handling and refund races. First-time users must have a documented permissionless
sponsor path if they lack credits; state this condition in the inclusion guarantee. A different
design is acceptable only with equivalent bounded cost and no trusted fee operator.

**Accepts when:** accounting and state-machine vectors show no unbacked admission, double spend
or refund of reserved credits; no poisoned nonce/fee/balance entry stalls the queue; and
timely evidence survives delayed execution without premature withdrawal. The published K
derivation includes the maximum backlog, declared gas limits and origin-observation lag.
An HTTP acknowledgement alone is never treated as an enqueue certificate.

### D6. Historical trust, proof and custody profile

**Dependencies:** D1, D4-D5.

Define the trusted-checkpoint contents and distribution/freshness policy separately from the
round-denominated certificate-admission window and key cache. Live certificate age must fit
inside the evidence window, which itself fits inside retirement protection. Derive protection assumptions
from round pacing, churn and retirement; document what an offline client must refresh.
Define EVM proof export, historical header ancestry, refreshable lock witnesses and shared-seal
multi-shard anchors. Freeze bridge type restrictions, configuration/hash bindings and direct/
succinct semantic relation. Define native supply and bridge liability accounting.

**Accepts when:** hand-checked proof/accounting vectors distinguish native UCT, WUCT and bridged
claims; an old block is authenticated without trusting retired signatures alone; fresh lock
evidence leaves token identity unchanged; and a history touching two aggregator shards verifies
with one seal plus the necessary paths. No claim of constant-size arbitrarily old proofs or
globally observable Execution-layer supply remains.

## 4. F: private execution foundation

### F1. Reconcile the prototype and establish a regression baseline

**Dependencies:** D1-D2.

Reconcile engine-api-adapter with the chosen main/l1 baseline without assuming the branch is
complete. Record pinned BFT and reth revisions, configuration hashes and current limitations.
Retain meaningful existing conformance and crash-recovery tests.

**Accepts when:** the existing Go suite and paired devnet pass at the selected baseline; known
protocol gaps have ticket owners; a version/spec mismatch is detected before voting. Merging
alone is not evidence of production readiness.

### F2. Implement canonical root-input derivation and verification

**Dependencies:** F1, D1.

Extend the executor boundary to pass canonical root input and authenticated witness material,
without reading ambient state during execution. Verify the authorizing certificate, technical
record, full context and transition chain. Commit canonical input through the D2 header rule.

**Accepts when:** D1 vectors match an independent implementation; different valid signer subsets
produce identical input/state; omitted, wrong-parent, stale, wrong-epoch, wrong-shard and
tampered transition data are rejected before certification. Duplicate/repeat imports are idempotent.

### F3. Implement the privileged call in reth

**Dependencies:** F2, D2.

Implement construction, execution, replay, synchronization and RPC/tracing semantics for the
protocol call. Add the required Engine API and companion-data support. Authenticate input at
the node boundary and enforce its commitment and position in execution; do not simulate this
by signing an ordinary transaction with a shared private key.

**Accepts when:** an ordinary transaction cannot impersonate or repeat the call; call failure
and missing data invalidate a block; a nonzero-base-fee block with the system call and paid
user transactions builds and replays identically. A syncing node obtains and verifies companion
data before declaring the block valid. The same rule is tested with a malicious builder.

### F4. SealRegistry and system-only block progress

**Dependencies:** F3.

Implement latest origin, certified clock, trust-base bodies, assignment and transition cursors.
Initial genesis state is explicitly authenticated. Permissionless verification does not mutate
the privileged clock or assignment. Produce successful system-only blocks at the configured
EVM cadence, while root timeouts/repeats remain non-execution outcomes.

**Accepts when:** an idle devnet advances the registry; jumps across root rounds are handled;
attempted public clock advancement fails; imports scale with bounded input/validator data,
not all historical rounds; no QC-signature participation counters are used for economics.

### F5. Fee rules, work budgets and block attributes

**Dependencies:** F3-F4.

Implement the custom fee floor, fee recipient, user/system work accounting, disabled issuance
and blob policy, and versioned attribute derivation. Correct every follower-side check.

**Accepts when:** the fee floor persists after many empty/system-only blocks; changing the initial
genesis base fee alone is demonstrably insufficient; wrong recipients or gas/header rules are
rejected. System work plus forced and ordinary capacity cannot exceed the configured total.

### F6. Atomic certification storage and crash recovery

**Dependencies:** F2-F4.

Replace latest-only JSON persistence with transactional storage. Persist certified EVM head,
UC/technical record, root input, companion witnesses and replay cursor coherently. Persist
necessary non-equivocation state before signing. Separate pending execution from finality.

**Accepts when:** faults before/after proposal submission, UC receipt, execution commit and database
write recover without a second conflicting vote, loss of certified block association or falsely
finalized pending payload. Both retained-executor-data and replacement-host recovery paths have
explicit behavior. Old file-store migration is documented before any public state exists.

### F7. Archive and offline execution-proof export

**Dependencies:** F6, D6.

Index certificates by full context and EVM block hash. Expose APIs for certified headers,
transactions/receipts, account/storage proofs and canonical root-input witnesses. Export versioned
offline bundles, including successful-event semantics and historical ancestry. Define archive
retention and pruning contracts; provide an archive-backed recovery route for replaced disks.

**Accepts when:** independently verified bundles cover a successful event, reverted transaction,
wrong emitter/log index, wrong receipt root, old block beyond live key admission and refreshed
permanent storage. Restart and configured execution-state pruning preserve the promised export
service. Unavailable data produces a typed failure, never a partial success.

**Status (2026-09-30):** the receipt-complete archive, MintReasonBundleV1 extraction and offline
verifier have a passing paired-devnet demo (evidence C in [the closure status](m2-closure-status.md)).
The verifier receives the authentic trust base for the UC's epoch as an input; the accepted
verification premise requires no ancestry proof or trust-body chain. F7's broad public account /
storage export and permanent-storage service remain open.

### F8. Mixed-cadence partition integration

**Dependencies:** F4-F6.

Run the governance EVM beside at least two aggregator shards, and exercise an additional
aggregator partition through the existing certification interface. Preserve consistency-proof
verification and existing root-selected shard leaders.

**Accepts when:** slow or stopped EVM execution does not prevent unrelated aggregator certification;
fast root leader rotation does not change an in-flight EVM leader; independent shard timeouts
and invalid consistency proofs behave correctly. Reports distinguish the three round counters.

**Status (2026-09-30):** the mixed lane passed with three aggregator shards, including a non-default
shard ID, EVM stop/restart, reconnect and one root handoff; independent timeout and invalid-proof
checks are in-process tests (evidence B in [the closure status](m2-closure-status.md)).

### F9. Proof-serving availability and resource bounds

**Dependencies:** F7-F8.

Implement bounded witness transfer, peer retry, archive discovery and metrics for lag, missing
companion data and unavailable historical proofs. Benchmark worst-case permitted execution and
proof verification against timeouts; deployment limits derive from measurements.

**Accepts when:** loss of one proof-serving peer and bounded malformed-witness load do not cause
unbounded memory/CPU growth or false certification. Published bounds cover verification work,
payload availability and recovery, not merely process counts.

## 5. H: epoch and checkpoint foundation under PoA

### H1. Authenticated multi-epoch trust-base storage

**Dependencies:** F6, D3-D4.

Replace the single-epoch shard store with chained, version-aware trust-base discovery and
validation. Persist canonical bodies and witnesses separately, keyed by epoch and active round
interval. Retain keys needed by historical evidence independently of the ordinary admission cache.

**Accepts when:** nodes cross several real PoA epochs, reject gaps and invalid predecessor proofs,
and recover after missing multiple transitions. Different signature subsets cannot change a
new-version trust-base identity. Legacy networks retain their existing semantics.

### H2. Root prepare/commit handoff and configuration intake

**Dependencies:** H1, D4.

Implement the D4 transition as consensus state. REST/gossip only proposes authenticated change
data. Protect durable endorsement state and enforce committed prepare/abort/activate ordering.

**Accepts when:** the executable model's negative/crash cases pass against running root nodes.
A locally inserted future trust base cannot become authoritative without the committed handoff.
Every old-quorum signature used for activation is bound to the same agreed boundary and body.

### H3. EVM assignment handoff and acknowledgement

**Dependencies:** H2, F4.

Drain or cancel outstanding old-assignment EVM work, persist the last certified parent and new
technical record, then import the acknowledgement before new-assignment user transactions.
Only one unacknowledged governance handoff may be prepared at a time.

**Accepts when:** membership changes while an EVM block is building cannot certify that proposal
after cancellation; the successor resumes from the agreed parent. Root rounds can advance while
the EVM acknowledgement lags. Other aggregator assignments remain unchanged.

### H4. Joining readiness and recovery

**Dependencies:** H2-H3, F7.

Specify state availability and readiness evidence for newly assigned paired nodes. Implement
root/EVM state synchronization from authenticated snapshots and archives, including key rotation.

**Accepts when:** an unready node cannot claim successful execution to satisfy the rollout gate;
a replacement host catches up and joins across an epoch boundary. Root and EVM keys retain
their documented owner/consensus/node role bindings.

### H5. Checkpoint production and client verification

**Dependencies:** H1-H4, D6.

Produce checkpoint bundles containing network identity, committed root/configuration context,
EVM head and authenticated transition history. Implement freshness checks for node bootstrap,
offline SDK recipients and proof consumers without introducing wall time into EVM execution.

**Accepts when:** a node/recipient using a fresh checkpoint verifies legitimate history; an expired
checkpoint requires refresh; a conflicting history signed only by retired keys is rejected.
Tests exercise altered pacing/churn assumptions and publish the derivation of the freshness limit.

### H6. Upgrade rehearsal before public currency

**Dependencies:** F9, H4-H5.

Rehearse execution-version activation, key rotation, archive-backed restore and interrupted
handoff on a private PoA network. Define support/version pinning and recovery authority.

**Accepts when:** measured interruption fits operational objectives, existing certified history
remains verifiable, and the exact recovery runbook is executed by someone other than its author.
No rollback procedure reorganizes a certified monetary transaction.

### H7. PoS retirement acknowledgement integration

**Dependencies:** H3, P4, S2, I4.

Connect committed root retirement, EVM acknowledgement, pending successor reservations and
inbox evidence watermark to custody withdrawal eligibility.

**Accepts when:** an unbond request just after snapshot, key rotation, canceled successor,
indefinite epoch extension and delayed evidence processing cannot unlock assigned or accused
collateral. Merely exceeding an operational extension target never permits withdrawal.

## 6. T: public UCT under PoA

### T1. Genesis manifest and funded first transaction

**Dependencies:** F4-F5, D6.

Generate reproducible code/storage/balance allocations, including disclosed funded bootstrap
EOAs. Include the registry genesis commitment, fee collector and allocation contracts.
Pin supply, chain identity, fork profile, reserved addresses and future activation permissions.

**Accepts when:** independent builds yield the same genesis; allocations sum exactly to S0;
a fresh bootstrap EOA pays for the first claim under production fee rules without a faucet,
privileged balance edit or pre-existing currency.

### T2. Immutable allocation and WUCT contracts

**Dependencies:** T1.

Use the owner-approved immutable timestamp vesting vault and canonical wrapper. Vesting is linear
from `start` over `duration`, with a `cliff`, immutable recipient and fixed principal; release is
pull-based and donations stay outside the principal. The contract uses EVM `block.timestamp`, whose
deterministic value can run ahead of wall time under the certified block clock, so this is not a
wall-clock service guarantee. Custody upgrades and undeclared administrative drains are absent.

**Accepts when:** funded recipients claim at the declared timestamp thresholds; repeated releases
never exceed principal and terminal release is exact; wrapper backing holds across
deposits/withdrawals/reentrancy attempts.

### T3. FeeCollector and independent Treasury

**Dependencies:** F5, T1.

Use the owner-approved revenue-only collector: its immutable 100/0 split assigns all unallocated
revenue to a pull balance for the fixed treasury and none to T8 rewards. The fee beneficiary is the
FeeCollector. It has no per-assignment attribution, settlement loop or governance path; T8 remains
disabled. The split is permissionless, and only the treasury can withdraw its credit.

**Accepts when:** treasury liabilities never exceed collector balance; all amounts reconcile with
the configured fee beneficiary and balance changes; a failing claimant cannot affect others.

### T4. Supply and custody invariant tooling

**Dependencies:** T2-T3, D2.

Define native supply as all account balances, with every enabled native destruction rule
accounted. Burned base fee is `baseFeePerGas × ordinary receipt gas`; reserved system-call gas is
excluded. Test this fee rule and the pinned EVM's SELFDESTRUCT behavior rather than asserting
that an opcode scan of project contracts proves the only possible sink. Track WUCT and native
custody separately and keep disabled issuance/blob rules enforced.

**Accepts when:** a controlled full-state devnet reconciles genesis, transfers and all permitted
burn cases exactly; deliberate mint/burn accounting errors are detected. Public monitoring
states its coverage and does not claim globally observed peer-to-peer token supply.

### T5. Immutable-code and future-activation review

**Dependencies:** T1-T4, H6.

Review predeploy addresses, custody/policy authority separation, construction/storage layout,
chain-ID allocation, compiler pinning and migration procedures. PoS/bridge contracts may be
deployed later, but reserved addresses confer no preexisting permission.

**Accepts when:** a reviewer independent of the authors signs off the genesis manifest and code
permissions. A defective immutable contract has a documented recovery/migration boundary; no
secret proxy or shared system private key is required by the deployment.

### T6. Reproducible public deployment rehearsal

**Dependencies:** T5, M2.

Run the exact proposed public genesis and builds in a fresh environment, including initial
distribution, realistic transactions, finality RPC, archival proof export and PoA rotation.

**Accepts when:** exchange/wallet integration uses certified finalized state; an uncertified
candidate is never shown as finalized; bootstrap and recovery require only documented artifacts.

### T7. TGE gate pack

**Dependencies:** T6, X2.

Collect build hashes, allocation and fee decisions, audit remediation, proof-retention policy,
PoA authority disclosure and operational signoffs. Launch is a separately authorized deployment
action; completing documentation or testnet tickets does not imply publishing.

**Accepts when:** every M3 gate has linked evidence and a named release decision. PoS, bridge and
unfinished reward functions remain explicitly disabled.

### T8. Optional simple assignment rewards

**Dependencies:** T3, H3; required before enabling rewards, not before TGE.

Implement the yellowpaper's assigned-weight interval formula, equal under PoA. Use authenticated
assignment/rate boundaries and exactly-once cursors; carry rounding remainder in the pool and
exclude outstanding credits from available emission. There are no signer participation counters.

**Accepts when:** delayed imports, repeated UCs, rate changes and extended epochs reconcile exactly;
settlement work is bounded; reward plus unclaimed credits never exceeds allocated funds.
Published behavior admits that an assigned but idle validator can receive this initial reward.

## 7. Q and P: weighted consensus and staking

### Q1. Weighted root quorum formation and pacemaker

**Dependencies:** D3, D5, H2.

Implement unique-weight accumulation in QC/TC assembly, verification and timeout amplification,
including all inventory paths. Implement the versioned network/domain-bound vote signing
preimage from D5, including non-committing votes. Use checked arithmetic and authenticated epoch weights.

**Accepts when:** adversarial unequal-weight vectors pass; a majority of identities with little
stake cannot form root quorum; sufficient weight can form it with fewer identities. Invalid,
duplicate and cross-epoch signatures do not count. Actual network progress exercises both QC
and timeout paths.

### Q2. Weighted shard requests and impossibility certificates

**Dependencies:** Q1, D3.

Update request buffers, trust-base interfaces and verification of matching requests and
quorum-not-possible proofs. Calculate remaining possible weight, not missing node count.

**Accepts when:** paired EVM thresholds match the active root weights; impossibility cannot be
claimed while unreceived honest weight could still form a majority; independent aggregator
assignments preserve their configured unit/weighted behavior and consistency-proof validation.

### Q3. Weight activation and compatibility

**Dependencies:** Q1-Q2, H3.

Activate the new version only through an agreed configuration boundary. Reject unsafe totals,
zero-effective members, duplicate key identities and unready incompatible nodes.

**Accepts when:** unit-stake PoA regression tests remain green; mixed old/new versions cannot
silently certify under different thresholds; certificates from either version are verified with
their own rules. Threshold and body-hash transitions survive restart.

### Q4. Weighted adversarial integration gate

**Dependencies:** Q3, F8.

Run fault schedules against skewed stake distributions, including concentrated honest weight,
many small Byzantine identities, withheld votes and changing weights across epochs.

**Accepts when:** valid progress occurs under the stated weighted assumptions and invalid state/
configuration never finalizes in the tested schedules. The report distinguishes protocol
assumptions from client bugs and records limitations of testing versus the D4 model.

### P1. Staking component reuse assessment

**Dependencies:** D4-D5.

Pin candidate Polygon source revisions and licenses; map usable share/commission arithmetic,
withdrawal and reward logic to the new lifecycle. Delete checkpoint/bridge coupling only after
identifying any accounting duties it carried. Compare a minimal self-bond implementation with
a port. Vendor only the justified components.

**Accepts when:** a reuse matrix identifies every retained dependency and removed test obligation.
Root-certified lifecycle and assigned-weight rewards have explicit accounting replacements.
Neither compiler modernization nor upstream test success is treated as a security audit.

### P2. Immutable native stake custody

**Dependencies:** P1, T2, D5.

Implement payable bonding, per-assignment reservations, fixed slash/exit permissions and
reentrancy-safe pull credits. Keep election policy separate from custody. Initial self-bond-only
mode rejects delegation calls; do not expose a partially implemented share API.

**Accepts when:** no policy/admin can arbitrarily withdraw or slash; collateral cannot back
incompatible spendable obligations; native balances reconcile after bonding, penalties and claims.
If delegation is enabled later, its own historical share/commission loss tests are mandatory.

### P3. Identity, possession and historical key binding

**Dependencies:** P2.

Register stable staking identity, owner key and distinct consensus/node roles. Require proof of
possession and unique active bindings. Activate rotation only through the committed assignment;
retain old bindings and collateral attribution.

**Accepts when:** copied keys, duplicate identities and mismatched node derivation are rejected;
owner rotation cannot erase a prior consensus offense; proof verification uses the offense epoch.

### P4. Retirement queue and protected claims

**Dependencies:** P2-P3, D5.

Record unbond requests without releasing active/future reservations. Start protection after
authenticated retirement, inherit the maximum applicable protection across parameter changes,
and hold unresolved timely evidence. Specify the ordering of evidence drain before withdrawals.

**Accepts when:** post-snapshot exit, long epoch extension, pending candidate, canceled transition,
delayed acknowledgement and parameter reduction cannot permit premature claims. Mature clean
retirement remains withdrawable even if an unrelated recipient reverts.

### P5. Deterministic snapshot and election contract

**Dependencies:** P2-P4, F4.

Run the bounded snapshot/election operation after origin import and before user transactions at
the first observed root threshold. Select by effective weight with canonical tie-breaking; fix
candidate attempt, version, parent body hash, snapshot identity and earliest activation bound.

**Accepts when:** independent randomized election tests match, including ties, fractional unit
conversion, empty/undersized sets and threshold jumps. Same-block user transactions cannot
change the already-taken snapshot. A pending candidate cannot be overwritten by local agent timing.

### P6. Certified candidate transport and adoption agents

**Dependencies:** P5, H2-H3.

Make the candidate body available and prove its hash at the fixed contract slot. Agents verify
the complete chain/configuration/state binding and propose it to root consensus. Gather
endorsements only for the root-selected handoff body.

**Accepts when:** verification works from supplied proofs without an execution client; different
agents agree on the certified candidate; stale attempts, wrong contracts, uncommitted roots and
wrong predecessor hashes are rejected. Agent failure invokes committed extension/abort rules.

### P7. Governance parameter execution and economic integration

**Dependencies:** P4-P6, S2, T8 if rewards enabled.

Check state-dependent constraints at proposal, execution, election/activation and withdrawal.
Preserve pending obligations through timelocked updates. Connect actual acknowledged assignments
to emission/fee accounting and make inactive optional features fail closed.

**Accepts when:** interacting pending proposals cannot bypass invariants; pool exhaustion stops
new rewards without trapping principal; changes to pacing/retention trigger checkpoint-policy
review and cannot weaken existing custody protection.

### P8. Authoritative switch ceremony

**Dependencies:** M4S, X5, T7.

Construct the exact activation record that replaces PoA authority with certified contract output.
Rehearse on the integrated testnet using production formats and unequal stakes.

**Accepts when:** successive contract-elected sets actually drive root and paired EVM epochs;
old PoA/config API credentials cannot choose a different set; rotation, evidence, retirement
and recovery all work after the switch. Public activation requires its own release authorization.

## 8. S: objective evidence

### S1. Consensus-signature verification primitive

**Dependencies:** D5, H1.

Implement the builtin over complete canonical voting metadata and signed commit information.
Authenticate the VoteInfo hash binding and extract voting epoch/round, not committed seal round.
Pin domain, conflict identity, malformed-input limits and signature canonicalization.

**Accepts when:** root signing-path vectors cover committing and non-committing votes, epoch
boundaries and different voting rounds referring to the same committed state. Payload substitution,
wrong domains and duplicate/malleated representations cannot fabricate an offense.

### S2. Objective slashing and liability holds

**Dependencies:** S1, P3-P4.

Implement the precise double-sign relation, historical collateral attribution, duplicate offense
guard, capped penalty and bounded bounty. Process timely inbox evidence before releasing affected
claims. Downtime/QC-omission inputs are unsupported.

**Accepts when:** genuine conflicting votes debit the correct active/retiring collateral once;
rotation/unbonding cannot evade liability; honest repeated votes are not penalized. Total payouts
and penalties stay within attributable funds.

### S3. Evidence retention, discovery and submission

**Dependencies:** S1-S2, F7.

Persist relevant signed messages and historical bindings, and provide bounded retrieval/submission.
Define retention after retirement and after queued cases. Keep evidence key availability separate
from ordinary bridge certificate admission.

**Accepts when:** a third party can assemble and submit a real testnet offense after validator
rotation; ordinary trust-base cache eviction does not prevent verification of a timely case.

### S4. End-to-end slashing exercise

**Dependencies:** S2-S3, I4-I5, H7.

Deliberately double-sign in a controlled testnet, censor the evidence at an EVM leader, then use
the root inbox and verify retirement remains blocked until evidence executes.

**Accepts when:** the offense is processed, correct collateral and bounty are credited, no honest
validator is slashed and a duplicate costs no additional principal. Repeat with a delayed EVM
and root epoch extension. Root-quorum loss is recorded as a recovery limitation, not success.

## 9. I: bounded forced inclusion

### I1. Certified admission and available payload queue

**Dependencies:** D5, F8, H2.

Implement the consensus enqueue record, authenticated prepaid-credit or approved alternative
accounting, per-entry and total bounds, sequence numbers and payload dissemination. Define
the certified data extension explicitly rather than hiding it in an unrelated statistics field.

**Accepts when:** nodes with different local request arrival orders commit one ordered queue;
unavailable payloads and unbacked admission do not receive enqueue votes. Replay/refund races
cannot reuse one admission credit. First-time sponsored admission is exercised.

### I2. Deterministic FIFO execution and capacity reservation

**Dependencies:** I1, F3-F5.

Drain the required prefix after root import and before ordinary transactions. Reserve forced gas;
derive K from worst-case allowed entry size/backlog and observation delay. Implement deterministic
skip/reject outcomes for invalid entries and normal receipts for executable reverts.

**Accepts when:** oversized load, same nonce, nonce gaps, balance loss, fee-cap changes and reverts
cannot poison future blocks. An ordinary transaction cannot invalidate a due item by being
placed ahead of it. A leader omitting a due valid item is rejected.

### I3. Root consumption acknowledgements and recovery

**Dependencies:** I2, F6, H3.

Certify consumed positions/results through EVM state and propagate them to root queue accounting.
Implement exactly-once charges, retention and credit reconciliation across handoffs and restarts.

**Accepts when:** neither premature dequeue nor double execution/charging is possible after
crashes, duplicate certificates, canceled EVM proposals and epoch changes.

### I4. Timely evidence and withdrawal watermark

**Dependencies:** I3, S2, P4.

Commit complete evidence payloads within the evidence window and expose the processed watermark
that custody must observe before withdrawal. Define bounded batches of evidence adjudication.

**Accepts when:** expiry of an execution allowance never releases collateral while a timely
unprocessed case can affect it; unrelated malformed evidence cannot impose an unbounded free
hold without the protocol's bounded admission/processing rules.

### I5. Censorship and saturation gate

**Dependencies:** I4, H7.

Exercise a censoring EVM leader, root enqueue delay, saturated admitted queue, unavailable peers
and newcomer-sponsored transactions. Measure the promised bound only from certified enqueue.

**Accepts when:** eligible valid transactions execute within the derived K under the stated
availability assumptions; invalid entries terminate with authenticated outcomes. The user-facing
guarantee excludes mere local submission and root-quorum failure.

## 10. B: custody bridge as a separate release

### B1. Certificate and inclusion builtins

**Dependencies:** D6, F3-F4, H1; Q3 before use under PoS.

Implement complete UC/shared-seal verification and RSMT inclusion with full network/partition/
shard/configuration binding, unique signature weights, active epoch intervals and live age checks.
Use the existing native/reference libraries where correct, but verify signatures cryptographically.
Calibrate bounds and gas with independent Go/Rust vectors.

**Accepts when:** malformed paths, short quorum, duplicates, wrong shard/configuration, old/future
rounds and overflowing input are rejected consistently. Different local node configuration cannot
change contract verification results. No historical accumulator is required.

### B2. Supported-profile TokenVerifier and feasibility spike

**Dependencies:** B1, D6.

First benchmark fresh, long and cross-shard whole-token histories against actual SDK data.
Implement strict canonical decoding, original predicate context, mint-type dispatch and bounded
metering. The initial pinned type rejects split/merge and unregistered mint extensions at issuance,
receipt and redemption, including nested attempts to smuggle unsupported provenance.

**Accepts when:** independently reviewed semantic vectors pass in direct verifier and both SDKs;
all accepted histories follow the launch profile. Measured costs determine direct budgets and
succinct proving capacity. Resource exhaustion is an explicit outcome, not a partially written state.

### B3. Shared-seal multi-shard proof assembly

**Dependencies:** B1-B2, F8-F9.

Implement proof-service snapshots and SDK assembly for one root seal plus authenticated partition/
shard paths and per-leaf proofs. Preserve historical request time and routing/configuration.
Specify archival obligations and authenticated lineage when an aggregator shard splits.

**Accepts when:** one token history spans multiple shards, an unrelated partition cannot substitute
a root, and proof refresh works after an aggregator shard split. The service can reconstruct a
common certified anchor even when the EVM was not certified in that root round.

### B4. Native BridgeVault and permanent lock interface

**Dependencies:** B2, T2-T5.

Implement native locking, monotone nonce, immutable configuration and Solidity mapping layout
for permanent lock digests. Separate outstanding backing, redemption credits and unexpected
transfers. Implement the nullifier accumulator and reentrancy-safe pull claims.

**Accepts when:** lock digest and storage-slot vectors match SDKs; cumulative paid <= credited
redemptions <= locked; balance equals outstanding backing plus credits plus unexpected value.
Replay, duplicate burns and a reverting recipient cannot consume others' backing.

### B5. Refreshable mint backing and offline SDKs

**Dependencies:** B4, F7, H5.

Register the enshrined immutable lock-reference reason in both SDKs and token specification.
Carry UC/state proof as replaceable verification witness, outside signed/certified token identity.
Verify account/storage paths, chain configuration, checkpoint and historical authentication.

**Accepts when:** mint backing verifies offline from a complete bundle; a much later fresh proof
verifies the same unchanged token; a retired-key-only forged history fails. Old and fresh witnesses
cannot alter amount, nonce, recipient, vault or token identifier.

### B6. Direct redemption and private round trip

**Dependencies:** B3-B5.

Verify the same supported-profile burn relation, discharge backing against permanent local lock
digests, consume the nullifier and credit native claims. Update wallet/relayer retry logic for
old/future anchors and concurrent nullifier roots.

**Accepts when:** lock, mint, transfer, burn, redeem and claim conserve liabilities across all
intermediate stages. Expired anchors can be refreshed; no equality with global circulating supply
is asserted. This ticket alone authorizes no public bridge launch.

### B7. Succinct fallback with the same semantic relation

**Dependencies:** B2-B6.

Implement and audit the prover relation and EVM verifier for histories beyond the direct budget.
A root-chain SP1 integration is not automatically an EVM verifier or a token-redemption circuit.
Bind the live trusted context, all shard paths, configuration, lock references, nullifier
transition and public release commitments.

**Accepts when:** direct and succinct paths agree on shared in-budget semantic vectors, while
long admitted histories redeem through the succinct path. Wrong public bindings and unsupported
token shapes fail. Proving cost, capacity and proof refresh after stale anchors are measured.

### B8. Proof-service and prover recovery

**Dependencies:** B7, F9.

Make proof production replaceable, publish reconstruction data and archive interfaces, and
rehearse loss of the original relayer/prover. Retain sufficient lock/state evidence for future
recipients without rewriting immutable token history.

**Accepts when:** a second implementation/service reconstructs the accumulator from events and
redeems a long history with no trusted operator. Retention failures have actionable diagnostics.
Wallets explain admitted profile restrictions and required checkpoint refresh.

### B9. Public bridge gate pack

**Dependencies:** B8, X3, T7.

Freeze the type/configuration/vault/verifier identities and audit evidence. Verify both directions,
maximum admitted shape handling, fees, retries, storage-proof interoperability and deployment
immutability. Define migration boundaries for a future split-capable type or changed relation.

**Accepts when:** every admitted history has a functioning redemption path; no remaining ticket
is required to release existing user backing. If succinct verification is unfinished, M5B stays
closed rather than launching one way or promising a future exit.

## 11. X: review, assurance and release evidence

### X1. Foundation failure matrix

**Dependencies:** F7-F9, H1-H6.

Maintain a compact matrix connecting each root/execution/certificate/transition failure to the
test or model establishing its behavior. Include asymmetric delivery and client replacement,
not only process kills. Run sustained load at the selected production resource limits.

**Accepts when:** M2 evidence covers finality, data availability, replay, handoff and mixed-cadence
operation; failures have reproducible diagnostics. Fleet size is chosen for the fault model,
not as a substitute for coverage.

### X2. Pre-TGE audit and remediation

**Dependencies:** M2, T1-T6; scope preparation begins during D.

Audit privileged execution, authentication/canonicalization, fee validity, genesis bootstrap,
immutable money contracts, proof export and PoA handoff/recovery. Remediate before T7.

**Accepts when:** findings affecting public funds/finality are closed or the affected feature is
disabled with a rechecked gate. A contracts-only audit does not satisfy this scope.

### X3. Bridge audit and remediation

**Dependencies:** B1-B8.

Audit both proof relations and SDKs, all context bindings, checkpoint assumptions, native custody,
type restrictions, nullifiers, long-history liveness, retries and archival reconstruction.

**Accepts when:** M5B blockers are closed and independently generated negative vectors pass.
An audit of an upstream prover or generic SDK does not replace review of the assembled bridge.

### X4. PoS shadow comparison and long-running fault exercise

**Dependencies:** Q4, P7, S4, I5, H7.

Observe contract candidates and modeled handoffs while PoA stays authoritative. Separately run
an authoritative PoS testnet; shadow equality alone cannot test activation, penalties or exits.
Cover multiple replacements, rotations, evidence windows, pool exhaustion and restart.

**Accepts when:** shadow divergence is zero for a declared interval and integrated testnet evidence
covers real post-switch behavior. The test report records assumptions, limits and every enabled
optional feature.

### X5. Integrated PoS audit and activation gate

**Dependencies:** X4; scope preparation begins during D3-D5.

Audit weighted BFT paths, handoff proof/model, key and collateral lifecycle, governance permissions,
root inbox, evidence and checkpoint recovery together. Rehearse the activation record and
post-activation recovery. Define the disclosed procedure for failure beyond the root fault bound.

**Accepts when:** all authoritative-PoS blockers are remediated; P8 can reference concrete approved
artifacts. Governance cannot bypass custody or consensus thresholds. Disabling an unready
security dependency does not qualify the remaining system for M5S.

## 12. Traceability and deferred work

| Review defect | Specification location | Required tickets |
|---|---|---|
| Count versus stake quorums | EVM Validity; BFT dynamic trust base | D3, Q1-Q4 |
| Ordinary zero-price system transaction | EVM Seal Feed; appendix Seal Transaction | D1-D2, F2-F5 |
| Unsynchronized snapshots/activation | Governance Election and Trust Base Derivation | D4, H1-H7, P5-P6 |
| Local UC bytes/signature subset determinism | EVM Seal Feed; appendix rootInput | D1, F2-F4 |
| QC omission treated as downtime | Governance Rewards and Slashing | D5, T8, S1-S4; downtime disabled |
| Unsafe unbonding/epoch extension | Governance Economic Invariants | D5, P2-P4, H7, I4 |
| Key cache mistaken for weak subjectivity | EVM Historical Trust; appendix Proof Export | D6, H1, H5, S3, B5 |
| Poisonable/unavailable forced queue | appendix Forced Inclusion | D5, I1-I5 |
| Wrong signed-vote/round binding | appendix Evidence | D5, S1-S4 |
| No gas-funded genesis claimant | appendix Genesis State | T1, T6 |
| Missing historical execution export | EVM Execution Evidence; appendix Proof Export | D6, F6-F9 |
| One shard root assumed for all leaves | bridging Shared Anchor | D6, B1-B3 |
| Old immutable backing witness | enshrined Backing Reason | D6, B5 |
| Bridge balance/circulation equality | enshrined Custody Accounting | T4, B4, B6 |
| Checks only at governance submission | Governance Economic Invariants | P7 |
| Proven mode omits protocol context | EVM Validity; appendix Certification Request | D1-D2; future proof-mode gate |
| Upgrade, clock, randomness and supply claims | EVM Parameters/Currency; Governance Delivery | D1-D2, T2-T5 |
| Direct verifier cannot redeem long histories | enshrined Initial Profile and Settlement | B2, B7-B9 |

### Earlier-ticket disposition

| Earlier work | Replacement |
|---|---|
| F1 framework/storage/topology | F1, F6-F9, H6, X1; topology growth is operational, not a release dependency |
| F2 genesis/configuration | D1-D2, T1, T5-T6 |
| F3 system transaction/registry | D1-D2, F2-F5, H1-H3 |
| F3.7 participation counters | Removed; T8 assignment rewards. Performance accounting is a future protocol |
| T1 money contracts and T2 rewards | T1-T8; rewards can be disabled at TGE |
| B1 builtins | B1 plus S1; separated by actual consumers |
| B2 TokenVerifier/split port | B2-B3 with a restricted launch type; split support requires a new reviewed relation |
| B3 vault/SDK/succinct path | B4-B9; succinct fallback is mandatory for public unbounded histories |
| P1 Polygon port | P1 assessment, P2-P4 custody/key/exit implementation; delegation optional |
| P2 epoch/slashing | P5-P7, S1-S4, H7; downtime slashing removed |
| P3 fixed-stake relaxation/agent gossip | D3-D4, Q1-Q4, H1-H3, P6; actual consensus integration required |
| P4 forced inclusion | D5, I1-I5; admission, availability, fees, invalidation and acknowledgements explicit |
| X1 yellowpaper changes | Repaired specification plus D1-D6 release-profile freeze |
| X2 audits and X3 operations | X1-X5, H4-H6, F9; independent bridge and PoS gates |

The history MMR remains optional. Initial old-event proofs may contain a linear header ancestry;
fresh permanent-storage proofs avoid that cost for lock backing. This is an explicit cost/
availability tradeoff, not a claim that all historical authentication is free.

Delegation, split/merge support for bridged tokens, measured performance rewards, downtime
penalties, execution validity proofs and additional EVM shards each need a separately versioned
specification, implementation, migration analysis and activation gate. None is silently enabled
by a configuration flag or by importing an upstream contract.

Uniform root leader selection may remain initially once all weighted safety/liveness paths
are validated. Assess its fairness and timeout behavior under skewed weights in Q4; do not
describe signature-count consensus as already stake-weighted.

This roadmap ends at reviewable, validated release artifacts. It does not itself authorize
deployment, issuance, public bridge activation or a production PoS switch.
