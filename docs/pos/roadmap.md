# Development roadmap: enshrined EVM, UCT and Proof of Stake

Delivery tickets following the Unicity Yellowpaper. Stable technical IDs and accepted evidence
are retained. The stage contracts below restructure future work; they do not expand historical
closure claims or reopen accepted deliverables. The earlier-ticket disposition remains at the end.

The target remains Setup 2: each BFT Core operator runs a paired reth execution node.
BFT Core performs consensus and certification; EVM contracts execute staking and governance.
Aggregator partitions and their shards continue independently alongside the EVM, at their own
cadence. Root rounds, shard rounds and EVM block heights are different counters.

UCT is issued natively at genesis. WUCT is an EVM wrapper; the Unicity Execution-layer token
is a separate custody-backed representation. There is no previous supply migration, ALPHA
currency or PoW issuance. Public testnets progress from PoA to PoA with bridging to PoS.
All functionality through public PoS testnet precedes future mainnet preparation. No TGE is
ready without mainnet bridge readiness; production PoS activation remains separately gated.

The current engine-api-adapter branch is a prototype starting point, not the public-release
baseline. In particular, its single-epoch shard trust-base store, count-based QC/TC formation,
standard Engine API attributes and latest-only UC storage do not implement the repaired rules.

## 0. Owner architecture decisions (2026-10-01)

The owner decisions of 2026-10-01 are recorded in [ADR 0012](../adr/0012-validator-entity-model.md) and the
[specification amendment](specification/amendments/0012-validator-entity-model.md). They govern where a ticket below says
otherwise; each affected ticket carries an "Amended 2026-10-01" note rather than a rewrite, so the earlier text stays reviewable.

- **Validator = one entity**, authenticated at the top level only by its BFT Core consensus key (listed in the current Unicity
  Trust Base entry; each new entry is signed by the previous set). It co-hosts an EVM node (reth) and helper processes and **fully
  trusts that EVM node**. The co-hosted BFT Core and EVM processes **share no private keys**; EVM and signing-authority keys are
  delegated and procedural. PoA now, PoS later, both at this level only.
- **Validator-set changes are always coupled:** one root handoff changes the BFT Core committee and the EVM assignment together.
  EVM-only rotation is not a supported operation (code may support it; runbooks and lanes do not use it). Supersession of a failed
  successor stays. (H2, H3)
- **Proofs:** only certified **positive** execution proofs are required from the EVM. Absence proofs are not a requirement; existing
  code may stay and gets no further work. (F7, D6)
- **Weights:** PoS weights apply at the root/validator-entity level only. The EVM shard mirrors root weights; **aggregator shards are
  unweighted**. Q2 and Q3 shrink accordingly; P3 binds only the root key. (D3, Q2, Q3, P3)
- **I-track deferred:** bounded forced inclusion (I1-I5) is deferred, not deleted (section 9).
- **Aggregator shards run centrally at launch** (aggregator-go is production; rugregator is experimental) **without consistency
  proofs** (`proof_type` none). The root certifies the presented transitions; see the disclosure below. Data availability and backup,
  endpoint discovery and liveness are solved by aggregator-go or the payment gateway and are out of scope at this layer. (F8)
- **New aggregator partitions and shard splits happen only at a BFT Core epoch boundary**, ordered by root consensus and carried by
  the same epoch-boundary handoff record; there is no per-root-node HTTP PUT. The source of a change is an operator (PoA) at
  launch and later possibly EVM smart contracts (slot auctions and the like); the data structures and flows are to be prepared now. (H2, H3, F8)
- **Broad F7** (public RPC, SDK, account/storage proofs, permanent-storage service) moves to the bridge track, B5
  ([#66](https://github.com/ristik/bft-core/issues/66)); F7's receipt-complete archive and positive-proof export stay in M2.

### Trust-assumption disclosure: aggregator shards at launch

The authoritative text, with code references, is in [ADR 0012](../adr/0012-validator-entity-model.md#trust-assumption-disclosure-aggregator-shards-at-launch).
In short, with `proof_type` none and a central operator the root checks, for each certified aggregator round: signatures from the
shard's configured keys, a count majority (unweighted, one vote per key) on one input record, continuity with the last certified
state (previous hash, round, epoch, timestamp), and the binding of the certificate to the configuration installed at genesis or by a
committed root handoff. It does **not** check the correctness of the state (SMT) transition, which goes through a no-op verifier, or
the availability of the data behind a certified root; with a centrally run shard the operator holds the configured keys, so the
quorum attests only that the operator signed. Aggregator shards are unweighted. Relying clients trust the operator for the
correctness and availability of transitions, and the root for the signature quorum, continuity, ordering and configuration binding.

## 1. Delivery policy

- Complete and validate each safety dependency before activating its consumer. Private devnets,
  shadow computation, public custody and authoritative governance are separate states.
- Keep the first public chain under PoA. Add PoS only after the full epoch/evidence/retirement
  cycle works with unequal weights and failures. An operator flag alone cannot activate it.
- Use attested execution initially, with root and EVM assignments sharing the same effective
  weights (the EVM shard mirrors the root weights; aggregator shards are unweighted: section 0). Stateless execution and succinct execution proofs are later upgrades.
- Funded rewards for BFT Core validator-entity operators are required PoS functionality.
  PoA accounting remains external; there are no separate EVM-node incentives. Final production
  economics are deferred. Downtime slashing and jailing from missing QC signatures are disabled.
- Initial PoS may use self-bond only. Use the approved clean-room implementation direction,
  with established designs as inspiration and explicit provenance for anything actually reused.
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
- Pin exact development/testnet values, addresses, formats and bounds in each exercised release.
  Production allocations, economics and final authority are mainnet decisions after TN-S #430.
  Draft examples and development defaults are not production parameters.

Every ticket has dependencies, a concrete result and acceptance evidence. Protocol-design tickets
are blockers until they have an executable transition model or independent vectors, not just an
ADR saying that implementation will be deterministic. Implementation tickets include relevant
negative cases and crash/replay tests. An estimate should be added after its design dependencies
close; the old one-week/two-week estimates are not retained for unresolved protocol changes.

## 2. Stage contracts and logical milestones

The 2026-10-07 stage decision governs future delivery wherever older ticket text differs.
Retain every accepted PR, model, vector and lane report with its original scope and limits.
An old passing run validates a new release only where its artifact/configuration bindings still
hold. In particular, M2a is partial foundation acceptance, Q2 is component evidence, and private
bridge evidence does not establish a rotating public profile.

| Stage | Entry and acceptance contract | Not prerequisites |
|---|---|---|
| DN: devnet / staging | Reviewed designs; compatible pinned clients; disposable manifest; enabled capabilities work across real paired clients with negative, restart/replay and recovery evidence; internal independent review. | Production economics/authority, X2/X3/X5 external audits, TGE, real-value custody and compatibility with abandoned formats. |
| TN: public testnet | Accepted relevant DN capability; exact test parameters/builds; public access, gas distribution, operations and independent internal release review. Closure records an actually exercised public network, a declared observation/fault campaign, measured bounds and defect disposition. | Production allocations, external audits, final governance authority, production signoff or multi-host topology at TN-1 #428. |
| MN: mainnet | Begin future preparation only after TN-S #430 is reached. Use testnet feedback to freeze production artifacts/economics, complete external audits/remediation, independent production signoff and production operations/authority policy. | Readiness never itself authorizes deployment, issuance, real-value custody or an authoritative production PoS switch. |

**Greenroom continues through public testnet.** Testnets may be reset arbitrarily; there is no
backwards compatibility, continuity-within-a-generation or asset-persistence commitment, and
users may lose all assets. Publish that limitation with the network and faucet. Correctness still
requires that a network replay its own history, authenticate its transitions and conserve custody
while it runs. A fresh genesis/reset identifies a new network; it is not a fabricated continuation.
Do not add migration/layout-version maintenance for discarded development/testnet formats.
Mainnet needs a reviewed continuity/upgrade policy rather than this disposable-network assumption.

**Initial operations fit one bare-metal server**, with a container per validator and its paired
execution/helpers, separate keys, explicit limits, public/admin endpoint separation, backups,
monitoring and incident ownership. Exercise process failure and restore/reset and disclose the
shared whole-host failure mode. A second operator must be able to execute the runbook; this does
not require a second physical host. Grow organically; independent physical failure domains and
production survival/recovery objectives belong to MN-OPS #441, not TN-1 #428 acceptance.

| GitHub milestone | Stage / legacy alias | Gate | Required scope |
|---|---|---|---|
| 1 (closed) | M0 — Implementable protocol baseline | #40 (closed) | Historical accepted D1-D6 models/vectors; retained limits. |
| 2 (closed) | DN-0 — Private paired PoA foundation / M1 | #41 (closed) | Historical F1-F6 acceptance and transferred obligations remain intact. |
| 3 | DN-1 — Recoverable PoA devnet and staging / M2 | #43 | DN-0, F7-F9, H1-H6, development X1. [M2a closure status](m2-closure-status.md) remains scoped evidence, not full DN-1 closure. |
| 9 | TN-1 #428 — Public PoA testnet | #428 | DN-1; T5-TEST #431, T6-TEST #432, X1-TEST #433; TN-OPS #434; public UCT FAUCET #435; X-TEST #436 internal review; public network acceptance. |
| 5 | DN-B — Private bridge integration / M4B | #73 | DN-1, reviewed disposable T6-TEST #432 manifest, B1-B6 supported private profile. |
| 10 | TN-B #429 — Public PoA bridge testnet | #429 | TN-1 #428 reached; DN-B, B7/B8, B-TEST #438 public proof/history/service acceptance and common SDK #421 capabilities. Fake-value assets only. |
| 7 | DN-S — PoS shadow and isolated authoritative integration / M4S | #59 | DN-1, Q1-Q4, P1-P7, S1-S4, H7, required T8, P8-TEST #437, X4; ordinary EVM evidence, I-track deferred. |
| 11 | TN-S #430 — Public PoS testnet | #430 | TN-B #429 reached as a network milestone plus DN-S; weighted public PoS, funded rewards, protected exits, bridge/SDK integration and internal review. |
| 6 | MN-B — Mainnet bridge readiness / M5B | #74 | After TN-S #430: exact production base/T6, public bridge evidence, X3 remediation and B9. Readiness precedes TGE; no live funds prerequisite. |
| 4 | MN-1 — Mainnet PoA / UCT readiness / M3 | #72 | After TN-S #430: MN-POLICY #439, production T5/T6, X1-MAIN #440, MN-OPS #441, X2, MN-B and T7. No TGE without bridging. |
| 8 | MN-S — Mainnet PoS readiness / M5S | #75 | TN-S #430, MN-1, final PoS policy/authority, X5 and production P8; separate activation authorization. |
| None | Deferred I1-I5 and optional later capabilities | Separate future decision | Keep evidence and reference scope; no active stage gate depends on I1-I5. |

Stage codes are stable references. The tracker restructure is applied; allocated issue and
milestone numbers are recorded above. Existing issue and milestone numbers are retained. Closed T1-T4 and
Q2 membership/evidence stays historical even where its milestone now names a later stage.

### Acceptance slices retained as separate tickets

| Work ID / GitHub issue | Acceptance boundary |
|---|---|
| T5-TEST #431 | Independent internal development/testnet genesis, code and permission review; replaces production T5 as B4's prerequisite. |
| T6-TEST #432 | Clean disposable deployment, funded transaction and independent recovery/rotation/reset rehearsal; replaces production T6 at DN-B. |
| X1-TEST #433 | Testnet failure matrix and measured limits on the chosen one-server topology; refresh at TN-B #429/TN-S #430. |
| TN-OPS #434 | Public RPC/transaction access, endpoint/key isolation, monitoring, archives, incident ownership and independently usable runbooks. |
| FAUCET #435 | Public test UCT dispensing so a fresh wallet can pay gas; funding/refill ownership, rate/abuse controls, failure handling and reset/network binding. |
| X-TEST #436 | Independent internal review of the assembled TN-1 #428 release; TN-B #429/TN-S #430 repeat integrated review in their own gate acceptance. |
| P8-TEST #437 | Activation implementation and isolated authoritative testnet rehearsal before X4; production P8 #61 remains mainnet-only. |
| B-TEST #438 | Broader B3/B5 public-profile slices, common SDK evolution, independent conformance, long-history exits and proof-service recovery. |
| MN-POLICY #439 | Production allocations, fees/limits, economics and final authority/control/continuity policy after TN-S #430; retains P7/T8 production slices. |
| X1-MAIN #440 | Original X1 production-limit sustained-load and foundation evidence, after TN-S #430 and parameter selection. |
| MN-OPS #441 | Production key custody, independent failure domains, availability/recovery/continuity policy and independent operational signoff. |

A private B3/B5 slice may close only with explicit unsupported cases and a link to the transferred
B-TEST #438 acceptance. B-TEST #438 requires working redemption for every admitted history, including
histories exceeding the direct budget. SDK #421 is common functionality, not a bridge-private
trust workaround; actual SDK implementation tickets, tested versions and epoch/weight support
must be linked before its consumed capabilities are accepted. It does not block EVM-only TN-1 #428
or the explicitly fixed-base private bridge profile.

### Recomputed dependency summary

Arrows mean prerequisite -> consumer. The tracker manifest contains the exact full graph and
its acyclic native transitive reduction; this is the stage-level summary, including split work.
All safety prerequisites remain in the full lists even when native edges are transitively reduced.

```text
DN-0 + development X1 (F/H recovery evidence) -> DN-1
H6 + T4 -> T5-TEST #431; DN-1 + T5-TEST #431 -> T6-TEST #432
T6-TEST #432 -> TN-OPS #434 + FAUCET #435 + X1-TEST #433 -> X-TEST #436 -> TN-1 #428
T5-TEST #431 + B2 -> B4 -> B5; B3 + B5 -> B6
T6-TEST #432 + B6 -> DN-B
DN-B + B7/B8 + SDK #421 -> B-TEST #438; TN-1 #428 + B-TEST #438 -> TN-B #429
H3 + P4 + S2 -> H7; S2 + S3 + H7 -> S4
T8 + P6 + S2 -> P7; #399 + Q3/F8 -> Q4
DN-1 + Q4 + P7 + S4 -> P8-TEST #437 -> X4 -> DN-S
TN-B #429 + DN-S -> TN-S #430
TN-S #430 -> MN-POLICY #439 -> production T5 -> production T6 -> X2
TN-S #430 + production T6 + B-TEST #438 -> X3 -> B9 -> MN-B
production T6 + MN-POLICY #439 + X1-TEST #433 -> X1-MAIN #440 -> MN-OPS #441
X2 + MN-B + MN-OPS #441 -> T7 -> MN-1
TN-S #430 + MN-POLICY #439 -> X5; X5 + T7 -> production P8
MN-1 + production P8 -> MN-S
```

DN-B and DN-S implementation can progress independently. Public network order is strictly
**TN-1 #428 -> TN-B #429 -> TN-S #430**; TN-S #430 depends on TN-B #429 having been reached, not on mainnet.
The old M3 -> M5B and T7 -> B9 edges are removed: production bridge readiness #74 now blocks
T7 #46, which blocks MN-1 #72. Retaining both historical gates avoids a cycle and preserves
separate custody and issuance reviews. Neither readiness gate requires already deployed real value.

Removing I4 -> H7 restores H3/P4/S2 as H7 prerequisites; removing I5 -> S4 restores H7/S2/S3.
Within the deferred graph, I4 -> I5 is restored explicitly because H7 no longer carries I4.
Ordinary EVM evidence, authenticated lifecycle/closure and protected claims remain required;
there is no bounded censorship-resistance promise. Accepted design, signature verification,
historical liability and delayed-EVM negative cases remain on the active path.

Run H4's remaining acceptance and H6's independent rehearsal as one coordinated activity.
Prerequisites gate final acceptance, not execution of that shared evidence run; do not add a
reverse H6 -> H4 edge or require H4 closure before collecting its remaining H6-run evidence.

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

**Amended 2026-10-01:** the weighted arithmetic stands but applies at the root/validator-entity level; the EVM shard's threshold is
taken over the mirrored root weights and aggregator shards stay unweighted (ADR 0012). "Greater than one-half shard weight" above
reads as the EVM shard.

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

**Amended 2026-10-01:** broad F7 (public RPC, SDK, account/storage proof export, permanent-storage service) is carried by B5
([#66](https://github.com/ristik/bft-core/issues/66)); the M2 deliverable is the receipt-complete archive and the positive-proof
export above. Only certified positive execution proofs are required; absence proofs are not a requirement and get no further work.

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

**Amended 2026-10-01:** aggregator shards run centrally at launch with `proof_type` none; "preserve consistency-proof
verification" means the verification path stays available for any shard that configures a proof type, not that launch shards
produce proofs. The launch trust assumption is the disclosure in section 0. New aggregator partitions and shard splits are
introduced only at an epoch boundary through the root-ordered handoff record (H2/H3), never by per-node HTTP PUT.

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

**Amended 2026-10-01:** configuration changes, including new aggregator partitions and shard splits, are ordered by root consensus
and carried by this same epoch-boundary handoff record; REST accepts a proposal but never installs one on a single node. The source
of a change is an operator (PoA) at launch, later possibly EVM contracts; the data structures and flows are to be prepared now.

### H3. EVM assignment handoff and acknowledgement

**Dependencies:** H2, F4.

Drain or cancel outstanding old-assignment EVM work, persist the last certified parent and new
technical record, then import the acknowledgement before new-assignment user transactions.
Only one unacknowledged governance handoff may be prepared at a time.

**Accepts when:** membership changes while an EVM block is building cannot certify that proposal
after cancellation; the successor resumes from the agreed parent. Root rounds can advance while
the EVM acknowledgement lags. Other aggregator assignments remain unchanged.

**Amended 2026-10-01:** validator-set changes are always coupled: one handoff changes the BFT Core committee and the EVM
assignment together (each successor root entity bound to one delegated EVM validator). EVM-only rotation is not a supported
operation; supersession of a failed successor stays.

### H4. Joining readiness and recovery

**Dependencies:** H2-H3, F7.

Specify state availability and readiness evidence for newly assigned paired nodes. Implement
root/EVM state synchronization from authenticated snapshots and archives, including key rotation.

**Accepts when:** an unready node cannot claim successful execution to satisfy the rollout gate;
a replacement host catches up and joins across an epoch boundary. Root and EVM keys retain
their documented owner/consensus/node role bindings.

**Amended 2026-10-07 (stage restructure):** DN-1 acceptance retains joining/recovery safety and the existing evidence. Schedule the remaining operator cases with H6 #23 as one acceptance activity: H6 execution may use the implemented H4 path before H4's final closure. Do not add H6 as a blocker of H4 or wait for H4 closure to run the shared rehearsal. Keep closure evidence separate and close prerequisites in order. Later public access/one-server operations are TN-OPS #434.

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

**Amended 2026-10-07 (stage restructure):** DN-1 independent private rehearsal remains required, with disposable values and correct replay of the exercised history. Coordinate the remaining H4 acceptance in the same run; prerequisite acceptance gates closure, not permission to execute that shared evidence run. No production compatibility, multi-host survival or production signoff is implied. Public-testnet operations move to TN-OPS #434; final production operations to MN-OPS #441.

### H7. PoS retirement acknowledgement integration

**Dependencies:** H3, P4, S2, I4.

Connect committed root retirement, EVM acknowledgement, pending successor reservations and
inbox evidence watermark to custody withdrawal eligibility.

**Accepts when:** an unbond request just after snapshot, key rotation, canceled successor,
indefinite epoch extension and delayed evidence processing cannot unlock assigned or accused
collateral. Merely exceeding an operational extension target never permits withdrawal.

**Amended 2026-10-01 (I-track deferred):** the I4 dependency and the "inbox evidence watermark" in H7 are suspended while the
I-track is deferred. How collateral withdrawal is protected against unprocessed evidence without the watermark is an open question
(see section 9); H7 is not closed by this change.

**Amended 2026-10-07 (stage restructure):** Remove deferred I4 #35 from active prerequisites. The active full prerequisites are H3 #20, P4 #32 and S2 #34, with accepted #85 design inherited via custody. Implement authenticated retirement/closure, pending-successor handling and protected claims with ordinary EVM evidence. Evidence inclusion has no forced-inclusion guarantee; document censorship and delayed-EVM assumptions. Replacing the dependency does not close H7 or waive its negative cases.

## 6. T: native UCT tooling and staged production readiness

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

**Amended 2026-10-07 (stage restructure):** Retain this issue for the final production immutable-code/genesis/future-activation signoff, after TN-S #430 and MN-POLICY #439. Development/testnet internal review transfers to T5-TEST #431, which replaces this issue as B4's blocker. Existing dossier evidence remains reusable only for matching artifacts; no final production allocation or signoff is required by DN/TN gates.

### T6. Reproducible production deployment rehearsal

**Dependencies:** T5, M2.

Run the exact proposed public genesis and builds in a fresh environment, including initial
distribution, realistic transactions, finality RPC, archival proof export and PoA rotation.

**Accepts when:** exchange/wallet integration uses certified finalized state; an uncertified
candidate is never shown as finalized; bootstrap and recovery require only documented artifacts.

**Amended 2026-10-07 (stage restructure):** Retain exact production deployment/recovery rehearsal here, after TN-S #430, final T5 #39 and DN-1 #43, using selected production artifacts and independent production signoff. The disposable development/testnet-manifest rehearsal transfers to T6-TEST #432, replacing #44 as a DN-B prerequisite. Preserve all existing rehearsal evidence with its artifact limits.

### T7. TGE gate pack

**Dependencies:** T6, X2.

Collect build hashes, allocation and fee decisions, audit remediation, proof-retention policy,
PoA authority disclosure and operational signoffs. Launch is a separately authorized deployment
action; completing documentation or testnet tickets does not imply publishing.

**Accepts when:** every M3 gate has linked evidence and a named release decision. PoS, bridge and
unfinished reward functions remain explicitly disabled.

**Amended 2026-10-07 (stage restructure):** Mainnet-only TGE pack after TN-S #430, production T6/X2, X1-MAIN #440, MN-OPS #441 and MN-B #74 readiness. Bridge readiness is mandatory; the earlier acceptance text requiring bridging to stay disabled is superseded. PoA may remain the initial production authority, while any production PoS switch requires MN-S. No issuance is authorized by ticket closure; final governance/allocations/economics must match the production manifest.

### T8. Funded PoS operator rewards

**Dependencies:** T3, H3; required before enabling rewards, not before TGE.

Implement the yellowpaper's assigned-weight interval formula, equal under PoA. Use authenticated
assignment/rate boundaries and exactly-once cursors; carry rounding remainder in the pool and
exclude outstanding credits from available emission. There are no signer participation counters.

**Accepts when:** delayed imports, repeated UCs, rate changes and extended epochs reconcile exactly;
settlement work is bounded; reward plus unclaimed credits never exceeds allocated funds.
Published behavior admits that an assigned but idle validator can receive this initial reward.

**Amended 2026-10-07 (stage restructure):** Funded rewards to BFT Core validator-entity operators are required PoS functionality and gate P7/DN-S; they are not optional for TN-S #430. No separate EVM-node incentives and no on-chain PoA reward requirement. Preserve bounded funded accounting, exhaustion, idempotence and conservation; use development values now. Final funding/rates/economics transfer to MN-POLICY #439 and production reviews.

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

**Amended 2026-10-07 (stage restructure):** DN-S weighted consensus work retains merged evidence and outstanding live acceptance, including #399 weighted liveness. Production economics and compatibility with abandoned development/testnet formats do not gate this work. Preserve deterministic replay/authenticated weight transitions for the network exercised.

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

**Amended 2026-10-01 (Q2, Q3):** weights exist only at the root/validator-entity level. Q2 shrinks to the EVM shard, whose
thresholds mirror the active root weights; aggregator shards are unweighted and keep their unit behavior, so no weighted
aggregator-shard certificates are needed. Q3 shrinks to activating root weights (and the mirrored EVM weights) at an agreed
configuration boundary.

**Amended 2026-10-07 (stage restructure):** DN-S integration remains required across root, paired EVM, signing authorities, aggregator-facing configuration and CLI. Greenroom/no backwards compatibility supersedes preservation of abandoned layouts. Preserve deterministic authenticated activation and replay of a network's own history. Closed Q2 component work does not establish Q3/Q4 live acceptance.

### Q4. Weighted adversarial integration gate

**Dependencies:** Q3, F8.

Run fault schedules against skewed stake distributions, including concentrated honest weight,
many small Byzantine identities, withheld votes and changing weights across epochs.

**Accepts when:** valid progress occurs under the stated weighted assumptions and invalid state/
configuration never finalizes in the tested schedules. The report distinguishes protocol
assumptions from client bugs and records limitations of testing versus the D4 model.

**Amended 2026-10-07 (stage restructure):** DN-S weighted adversarial evidence retains coupled real-client, crash/replay, admission and resource cases; #399 is an explicit prerequisite. Root-only component evidence cannot close the integrated gate. Measure development/test bounds now and refresh enabled public weighted/bridge cases at TN-S #430.

### P1. Staking component reuse assessment

**Dependencies:** D4-D5.

Pin candidate Polygon source revisions and licenses; map usable share/commission arithmetic,
withdrawal and reward logic to the new lifecycle. Delete checkpoint/bridge coupling only after
identifying any accounting duties it carried. Compare a minimal self-bond implementation with
a port. Vendor only the justified components.

**Accepts when:** a reuse matrix identifies every retained dependency and removed test obligation.
Root-certified lifecycle and assigned-weight rewards have explicit accounting replacements.
Neither compiler modernization nor upstream test success is treated as a security audit.

**Amended 2026-10-07 (stage restructure):** Retain the assessment and accepted evidence; reconcile remaining closure against the approved clean-room implementation direction (inspiration from established designs, no required Polygon port). #85 must provide accepted self-contained architecture and traceability. Production parameters and external review scheduling do not block DN-S design acceptance; preserve provenance obligations for anything actually reused.

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

**Amended 2026-10-01:** P3 binds only the root key: a stable staking identity, its owner key and the validator's BFT Core consensus
key, with possession proof and unique active bindings. EVM and signing-authority keys are delegated and procedural, are not
separate staking-registry roles, and are never shared with the co-hosted BFT Core process.

### P4. Retirement queue and protected claims

**Dependencies:** P2-P3, D5.

Record unbond requests without releasing active/future reservations. Start protection after
authenticated retirement, inherit the maximum applicable protection across parameter changes,
and hold unresolved timely evidence. Specify the ordering of evidence drain before withdrawals.

**Accepts when:** post-snapshot exit, long epoch extension, pending candidate, canceled transition,
delayed acknowledgement and parameter reduction cannot permit premature claims. Mature clean
retirement remains withdrawable even if an unrelated recipient reverts.

**Amended 2026-10-07 (stage restructure):** DN-S implementation/test acceptance uses ordinary paid EVM evidence and authenticated root lifecycle/closure records, not a forced-inbox watermark. Preserve reservations, inherited protection, pending-case settlement and safe claims through delayed EVM execution, rotation, abort and restart. Do not claim bounded censorship resistance. Parameter values are disposable development inputs; production policy is MN-POLICY #439.

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

**Amended 2026-10-07 (stage restructure):** DN-S/TN-S #430 governance functionality uses bounded development authority and exact test parameters. T8 #47 funded operator rewards is now mandatory, alongside P4-P6/S2. Final production authority, succession and economics transfer to MN-POLICY #439, X5 and production P8; the implementation must already enforce parameter constraints and inherited custody obligations.

### P8. Production authoritative switch ceremony

**Dependencies:** M4S, X5, T7.

Construct the exact activation record that replaces PoA authority with certified contract output.
Rehearse on the integrated testnet using production formats and unequal stakes.

**Accepts when:** successive contract-elected sets actually drive root and paired EVM epochs;
old PoA/config API credentials cannot choose a different set; rotation, evidence, retirement
and recovery all work after the switch. Public activation requires its own release authorization.

**Amended 2026-10-07 (stage restructure):** Retain only the production switch ceremony and exact production activation/recovery signoff here, after DN-S #59, X5 #60 and T7 #46. Implementation and isolated/testnet activation rehearsal transfer to P8-TEST #437; this issue no longer gates that work. Public TN-S #430 is reached before any of these production preparations. A production switch needs separate authorization.

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

**Amended 2026-10-07 (stage restructure):** Ordinary paid EVM evidence is the active route. Require real S1 signature verification, authenticated historical liability, objective offence deduplication and protected retirement/claims; no forced-inbox watermark is an active prerequisite. Review censorship/delayed-inclusion assumptions explicitly. Slashing or undercoverage must not remove the exact-incumbent recovery slate; retain the operational carried-over-quorum and less-than-one-third-change assumptions in acceptance.

### S3. Evidence retention, discovery and submission

**Dependencies:** S1-S2, F7.

Persist relevant signed messages and historical bindings, and provide bounded retrieval/submission.
Define retention after retirement and after queued cases. Keep evidence key availability separate
from ordinary bridge certificate admission.

**Accepts when:** a third party can assemble and submit a real testnet offense after validator
rotation; ordinary trust-base cache eviction does not prevent verification of a timely case.

### S4. End-to-end slashing exercise

**Dependencies:** S2-S3, I4-I5 (suspended while the I-track is deferred, section 9), H7.

Deliberately double-sign in a controlled testnet, censor the evidence at an EVM leader, then use
the root inbox and verify retirement remains blocked until evidence executes.

**Accepts when:** the offense is processed, correct collateral and bounty are credited, no honest
validator is slashed and a duplicate costs no additional principal. Repeat with a delayed EVM
and root epoch extension. Root-quorum loss is recorded as a recovery limitation, not success.

**Amended 2026-10-01 (S4, I-track deferred):** the I4-I5 dependency and the "censor the evidence at an EVM leader, then use the
root inbox" scenario are suspended with the I-track; the rest of the exercise stands. See the open question in section 9.

**Amended 2026-10-07 (stage restructure):** Remove deferred I5 #56 (and textual I4 #35) from active prerequisites. Active full prerequisites are S2 #34, S3 #55 and H7 #36. Exercise ordinary EVM evidence with delayed inclusion/execution, authenticated retirement/closure and protected claims; no root-inbox censorship guarantee. Real signatures, duplicate/false-evidence rejection, key rotation and delayed-EVM/root-extension cases remain required.

## 9. I: bounded forced inclusion

> **Status: DEFERRED (owner decision, 2026-10-01; [ADR 0012](../adr/0012-validator-entity-model.md)). Not deleted.** Forced
> inclusion defends access against a censoring EVM producer. Under the validator-entity model a node fully trusts its co-hosted EVM
> node, only positive proofs are required and PoS weights stay at the root level, so I1-I5 are not a prerequisite of the PoA launch
> (M3) or of PoS shadow (M4S): the M4S gate above no longer lists them. Their dependents H7 (I4), S4 (I4-I5) and X4 (I5) carry an
> amendment note below, because each used the I-track as a safeguard (the inbox evidence watermark and the censored-evidence
> scenario) and **what replaces that safeguard is an open question for the owner and the H7/S2 reviewers**; this change does not
> decide it. The tickets below stay as the reference scope; they are reinstated only by a new owner decision with its own activation
> gate, and authoritative PoS (M5S) must re-decide before it relies on forced inclusion. The D5 design is kept.

**Amended 2026-10-07 (stage restructure):** ordinary paid EVM evidence is the active route.
The earlier unresolved-route paragraph is superseded; the detailed authenticated closure and
protected-claim design must still be accepted and implemented under P-DESIGN #85, P4, S2 and H7.
Do not promise bounded censorship resistance. I1-I5 remain deferred and outside active DN/TN/MN
milestones, with no path to active gates. Preserve the deferred I4 -> I5 dependency explicitly.
Slashing/undercoverage must not remove the exact-incumbent recovery slate; retain the
less-than-one-third-change and operational carried-over-quorum assumptions in the accepted design.

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

**Amended 2026-10-07 (stage restructure):** DN-B integrated acceptance requires real paired-client activation, replay and bounded measurements; Go/Rust kernel or fixture contract evidence alone is insufficient. Q3 remains required before using the builtins under weighted PoS and is inherited by DN-S/TN-S #430. The fixed unit-weight SDK private profile does not itself establish rotating public bridge readiness.

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

**Amended 2026-10-07 (stage restructure):** Retain supported private-profile proof assembly and B1/B2/F8/F9 prerequisites for DN-B. Transfer broader public shared-seal multi-shard/shard-split refresh acceptance to B-TEST #438 where that profile is admitted. A reduced private closure must enumerate unsupported/rejected cases and link the transferred tests; it must not claim the broader acceptance above is complete.

### B4. Native BridgeVault and permanent lock interface

**Dependencies:** B2, T2-T5.

Implement native locking, monotone nonce, immutable configuration and Solidity mapping layout
for permanent lock digests. Separate outstanding backing, redemption credits and unexpected
transfers. Implement the nullifier accumulator and reentrancy-safe pull claims.

**Accepts when:** lock digest and storage-slot vectors match SDKs; cumulative paid <= credited
redemptions <= locked; balance equals outstanding backing plus credits plus unexpected value.
Replay, duplicate burns and a reverting recipient cannot consume others' backing.

**Amended 2026-10-07 (stage restructure):** DN-B vault development replaces production T5 #39 with T5-TEST #431 internal review; B2 and T2-T4 remain prerequisites (including their transitive paths). Preserve immutable locking, internal efficient nullifier tracking, conservation, replay/duplicate-burn and reentrancy cases. End-user non-inclusion proofs are not a required service. Assembled public-profile review is B-TEST #438; external custody audit remains X3.

### B5. Refreshable mint backing and offline SDKs

**Dependencies:** B4, F7, H5.

**Amended 2026-10-01:** B5 also carries broad F7: the public RPC, SDK, account/storage proof export and permanent-storage service
that were deferred from M2 (ADR 0012; M2 keeps the receipt-complete archive and the positive-proof export).

Register the enshrined immutable lock-reference reason in both SDKs and token specification.
Carry UC/state proof as replaceable verification witness, outside signed/certified token identity.
Verify account/storage paths, chain configuration, checkpoint and historical authentication.

**Accepts when:** mint backing verifies offline from a complete bundle; a much later fresh proof
verifies the same unchanged token; a retired-key-only forged history fails. Old and fresh witnesses
cannot alter amount, nonce, recipient, vault or token identifier.

**Amended 2026-10-07 (stage restructure):** Retain fixed-base private offline backing/SDK integration for DN-B, with explicit supported history and trust limitations. Broader public RPC/account/storage proof service, rotation/trust evolution and full-profile history/recovery acceptance transfer to B-TEST #438. Keep tokens self-contained via the vault locking proof in the mint reason; use external SDK plug-ins. Common #421 capabilities, not component-private authority workarounds, gate public rotating/weighted use. Existing F7/H5 evidence remains a prerequisite with its limits.

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

**Amended 2026-10-07 (stage restructure):** Implement and internally review the full supported-profile succinct fallback before TN-B #429. The external audit slice belongs to X3 #70 after TN-S #430; it does not block fake-value tests. Every admitted history needs a functioning redemption path even when the direct budget is exceeded. Revalidate exact production artifacts for MN-B.

### B8. Proof-service and prover recovery

**Dependencies:** B7, F9.

Make proof production replaceable, publish reconstruction data and archive interfaces, and
rehearse loss of the original relayer/prover. Retain sufficient lock/state evidence for future
recipients without rewriting immutable token history.

**Accepts when:** a second implementation/service reconstructs the accumulator from events and
redeems a long history with no trusted operator. Retention failures have actionable diagnostics.
Wallets explain admitted profile restrictions and required checkpoint refresh.

**Amended 2026-10-07 (stage restructure):** TN-B #429 acceptance requires long-history redemption and replacement proof-service/prover recovery after B7. Preserve archive reconstruction and independent conformance evidence, scoped to the selected test profile; production revalidation/signoff remains B9/X3/MN-B.

### B9. Mainnet bridge gate pack

**Dependencies:** B8, X3, T7.

Freeze the type/configuration/vault/verifier identities and audit evidence. Verify both directions,
maximum admitted shape handling, fees, retries, storage-proof interoperability and deployment
immutability. Define migration boundaries for a future split-capable type or changed relation.

**Accepts when:** every admitted history has a functioning redemption path; no remaining ticket
is required to release existing user backing. If succinct verification is unfinished, M5B stays
closed rather than launching one way or promising a future exit.

**Amended 2026-10-07 (stage restructure):** Mainnet-only B9 bridge readiness pack now depends on B8 #69, X3 #70 and production T6 #44, not T7 #46. Freeze exact production vault/type/verifier/configuration and custody/exit evidence before issuance; use rehearsed artifacts without requiring live public funds. MN-B #74 then gates T7, removing the former launch-order cycle. Real-value deployment/custody still requires separate authorization.

## 11. X: review, assurance and release evidence

### X1. Foundation failure matrix

**Dependencies:** F7-F9, H1-H6.

Maintain a compact matrix connecting each root/execution/certificate/transition failure to the
test or model establishing its behavior. Include asymmetric delivery and client replacement,
not only process kills. Run sustained load at the selected production resource limits.

**Accepts when:** M2 evidence covers finality, data availability, replay, handoff and mixed-cadence
operation; failures have reproducible diagnostics. Fleet size is chosen for the fault model,
not as a substitute for coverage.

**Amended 2026-10-07 (stage restructure):** This issue retains the DN-1 foundation matrix at selected development bounds. Public-testnet resource/failure evidence transfers to X1-TEST #433; the original sustained load at selected production limits transfers to X1-MAIN #440. Both remain explicit obligations. #43 consumes only the development slice. Historical single-host results are not production capacity acceptance.

### X2. Pre-TGE audit and remediation

**Dependencies:** M2, T1-T6; scope preparation begins during D.

Audit privileged execution, authentication/canonicalization, fee validity, genesis bootstrap,
immutable money contracts, proof export and PoA handoff/recovery. Remediate before T7.

**Accepts when:** findings affecting public funds/finality are closed or the affected feature is
disabled with a rechecked gate. A contracts-only audit does not satisfy this scope.

**Amended 2026-10-07 (stage restructure):** Mainnet-only X2. Begin the production audit/remediation after TN-S #430 and exact production T6 #44. Internal independent testnet review is X-TEST #436 plus the TN-B #429/TN-S #430 gate reviews; none requires this audit. Preserve all original audit correctness scope for enabled production functionality.

### X3. Bridge audit and remediation

**Dependencies:** B1-B8.

Audit both proof relations and SDKs, all context bindings, checkpoint assumptions, native custody,
type restrictions, nullifiers, long-history liveness, retries and archival reconstruction.

**Accepts when:** M5B blockers are closed and independently generated negative vectors pass.
An audit of an upstream prover or generic SDK does not replace review of the assembled bridge.

**Amended 2026-10-07 (stage restructure):** Mainnet-only X3 audit/remediation starts after public TN-S #430, production T6 #44 and public bridge profile B-TEST #438, while retaining B1-B8 correctness scope. Internal bridge review and working exits already gate TN-B #429; audit scheduling must not block that network milestone.

### X4. PoS shadow comparison and long-running fault exercise

**Dependencies:** Q4, P7, S4, I5 (suspended while the I-track is deferred, section 9), H7.

Observe contract candidates and modeled handoffs while PoA stays authoritative. Separately run
an authoritative PoS testnet; shadow equality alone cannot test activation, penalties or exits.
Cover multiple replacements, rotations, evidence windows, pool exhaustion and restart.

**Accepts when:** shadow divergence is zero for a declared interval and integrated testnet evidence
covers real post-switch behavior. The test report records assumptions, limits and every enabled
optional feature.

**Amended 2026-10-01 (X4, I-track deferred):** the I5 dependency is suspended with the I-track; no inbox/forced-inclusion case is part of the
exercise until it is reinstated (section 9).

**Amended 2026-10-07 (stage restructure):** DN-S X4 combines PoA-authoritative shadow comparison and separate isolated authoritative PoS runs. Add P8-TEST #437 for actual activation mechanics; retain Q4 #51, P7 #54, S4 #57 and H7 #36. I5 is deferred and not an active blocker. Test ordinary EVM evidence, protected exits and funded rewards. External X5, production P8 and TGE do not block this work.

### X5. Integrated PoS audit and activation gate

**Dependencies:** X4; scope preparation begins during D3-D5.

Audit weighted BFT paths, handoff proof/model, key and collateral lifecycle, governance permissions,
root inbox, evidence and checkpoint recovery together. Rehearse the activation record and
post-activation recovery. Define the disclosed procedure for failure beyond the root fault bound.

**Accepts when:** all authoritative-PoS blockers are remediated; P8 can reference concrete approved
artifacts. Governance cannot bypass custody or consensus thresholds. Disabling an unready
security dependency does not qualify the remaining system for M5S.

**Amended 2026-10-07 (stage restructure):** Mainnet-only integrated PoS audit after public TN-S #430 and MN-POLICY #439, retaining X4 evidence and all enabled consensus/custody/governance/recovery scope. Replace deferred root-inbox assumptions with reviewed ordinary EVM evidence and authenticated closure/protected exits. External review does not block DN-S/TN-S #430; final production authority and economics remain required here.

## 12. Traceability and deferred work

| Review defect | Specification location | Required tickets |
|---|---|---|
| Count versus stake quorums | EVM Validity; BFT dynamic trust base | D3, Q1-Q4 |
| Ordinary zero-price system transaction | EVM Seal Feed; appendix Seal Transaction | D1-D2, F2-F5 |
| Unsynchronized snapshots/activation | Governance Election and Trust Base Derivation | D4, H1-H7, P5-P6 |
| Local UC bytes/signature subset determinism | EVM Seal Feed; appendix rootInput | D1, F2-F4 |
| QC omission treated as downtime | Governance Rewards and Slashing | D5, T8, S1-S4; downtime disabled |
| Unsafe unbonding/epoch extension | Governance Economic Invariants | D5, P2-P4, H7, I4 (I4 suspended: I-track deferred, open question in section 9) |
| Key cache mistaken for weak subjectivity | EVM Historical Trust; appendix Proof Export | D6, H1, H5, S3, B5 |
| Poisonable/unavailable forced queue | appendix Forced Inclusion | D5, I1-I5 (I-track deferred 2026-10-01) |
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
| T1 money contracts and T2 rewards | T1-T8; PoA accounting external, funded operator rewards required for PoS |
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
