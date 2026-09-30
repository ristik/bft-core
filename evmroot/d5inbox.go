package evmroot

// D5 part 3: forced-inbox admission with authenticated prepaid UCT credits,
// a three-state entry lifecycle (pending -> tentatively executed ->
// certified-consumed + archived), exactly-once charging, refund
// reconciliation bound to the original owner and outcome, FIFO progress
// past poisoned entries, an entry-count/fragmentation-aware inclusion bound
// K, and an executable sponsor path.
//
// Normative source: docs/design/d5-accountability-retirement-inbox.md §4,
// docs/pos/specification/appendix-evm.tex §"Forced Inclusion".

// --- authenticated credits ---------------------------------------------------

// CertifiedDeposit is a deposit whose identity and amount the root has
// certified. DepositID is that certified identity — NOT a hash of the proof
// serialization, so a re-encoded proof for the same deposit is the same
// identity.
type CertifiedDeposit struct {
	DepositID string
	Owner     string
	Amount    uint64
	Certified bool
}

// creditState tracks one credit through admission and reconciliation.
type creditState struct {
	creditID    string
	owner       string
	fromDeposit string
	consumedBy  uint64 // queue seq the admission bound it to when consumed is true
	consumed    bool   // kept separately so the full uint64 sequence space is valid
	reconciled  bool
}

// CreditEscrow is the immutable EVM escrow. Every credit carries its owner
// and originating deposit; a refund can only return value to that owner and
// only when the root has certified the credit's entry was never consumed.
type CreditEscrow struct {
	seenDeposit map[string]struct{}     // certified DepositID -> applied
	available   map[string]uint64       // owner -> unallocated credit count
	credits     map[string]*creditState // creditID -> state
	seenGrant   map[string]struct{}     // certified sponsor GrantID -> used
}

func NewCreditEscrow() *CreditEscrow {
	return &CreditEscrow{
		seenDeposit: map[string]struct{}{},
		available:   map[string]uint64{},
		credits:     map[string]*creditState{},
		seenGrant:   map[string]struct{}{},
	}
}

// DepositResult is the outcome of a deposit / grant / reconciliation.
type DepositResult struct {
	Applied bool
	Reason  string
}

// ApplyDeposit credits `Amount` unallocated credits to the deposit's owner.
// It requires a certified deposit and dedups on the certified DepositID, so
// a re-serialized proof for the same deposit adds nothing.
func (e *CreditEscrow) ApplyDeposit(d CertifiedDeposit) DepositResult {
	if !d.Certified || d.DepositID == "" || d.Owner == "" || d.Amount == 0 {
		return DepositResult{false, "deposit is not certified or is malformed"}
	}
	if _, seen := e.seenDeposit[d.DepositID]; seen {
		return DepositResult{false, "certified deposit already applied"}
	}
	e.seenDeposit[d.DepositID] = struct{}{}
	e.available[d.Owner] += d.Amount
	return DepositResult{Applied: true}
}

// SponsorGrant is a certified grant letting a sponsor fund a first-time
// user's credits — the executable permissionless newcomer path the
// inclusion guarantee is conditional on.
type SponsorGrant struct {
	GrantID   string
	Sponsor   string
	Recipient string
	Amount    uint64
	Certified bool
}

// GrantSponsoredCredit applies a certified sponsor grant: the sponsor's
// available credits are debited and the recipient's are credited. Dedups on
// GrantID.
func (e *CreditEscrow) GrantSponsoredCredit(g SponsorGrant) DepositResult {
	if !g.Certified || g.GrantID == "" || g.Sponsor == "" || g.Recipient == "" || g.Amount == 0 {
		return DepositResult{false, "sponsor grant is not certified or is malformed"}
	}
	if _, seen := e.seenGrant[g.GrantID]; seen {
		return DepositResult{false, "sponsor grant already used"}
	}
	if e.available[g.Sponsor] < g.Amount {
		return DepositResult{false, "sponsor has insufficient credits"}
	}
	e.seenGrant[g.GrantID] = struct{}{}
	e.available[g.Sponsor] -= g.Amount
	e.available[g.Recipient] += g.Amount
	return DepositResult{Applied: true}
}

// mintCredit allocates one available credit to `owner`, returning its id.
func (e *CreditEscrow) mintCredit(creditID, owner string) bool {
	if e.available[owner] == 0 {
		return false
	}
	if _, dup := e.credits[creditID]; dup {
		return false
	}
	e.available[owner]--
	e.credits[creditID] = &creditState{creditID: creditID, owner: owner}
	return true
}

// RefundStatement is a root-certified statement that a specific credit's
// admission was rolled back and its value must return to its owner.
type RefundStatement struct {
	CreditID            string
	Owner               string
	RootCertifiedUnused bool
}

// ReconcileUnusedCredit is the certified admission rollback and the refund
// as ONE bound transition. It applies only when: the statement is
// root-certified; the forced inbox it rolls back is supplied AND is the one
// this escrow backs (`q.escrow == e`) — a queue from another
// escrow/admission domain cannot stand in, even if it happens to hold an
// entry with the same seq and credit id; the credit exists; the statement's
// owner matches the credit's recorded owner; the credit has not already
// been reconciled; and — if the credit was consumed into a queue entry —
// that entry is still pending. A pending entry is permanently revoked here
// (dropped from the live queue, its per-sender slot released) so the same
// paid credit can never also back an executed entry. A tentatively-executed
// or certified-consumed entry cannot be rolled back and its credit is not
// refundable. Every check runs BEFORE any mutation. Applied at most once.
//
// In a deployment the queue identity is the authenticated
// network/partition/queue domain; here `q.escrow == e` is the model's
// stand-in for that binding.
func (e *CreditEscrow) ReconcileUnusedCredit(s RefundStatement, q *ForcedInbox) DepositResult {
	if !s.RootCertifiedUnused {
		return DepositResult{false, "no root-certified reconciliation"}
	}
	if q == nil {
		return DepositResult{false, "reconciliation must be applied against the forced inbox it rolls back"}
	}
	if q.escrow != e {
		return DepositResult{false, "forced inbox belongs to a different escrow / admission domain"}
	}
	c, ok := e.credits[s.CreditID]
	if !ok {
		return DepositResult{false, "unknown credit"}
	}
	if c.owner != s.Owner {
		return DepositResult{false, "refund owner does not match the credit's recorded owner"}
	}
	if c.reconciled {
		return DepositResult{false, "credit already reconciled"}
	}
	if c.consumed {
		switch q.entryState(c.consumedBy) {
		case entryCertifiedConsumed:
			return DepositResult{false, "credit backs a certified-consumed entry — nothing to refund"}
		case entryTentativelyExecuted:
			return DepositResult{false, "credit's entry is tentatively executed — awaiting a consumption certificate, not refundable"}
		}
		if !q.RevokeEntry(c.consumedBy, s.CreditID) {
			return DepositResult{false, "credit's admission is not a pending live entry in this queue"}
		}
	}
	c.reconciled = true
	c.consumedBy = 0
	c.consumed = false
	e.available[c.owner]++
	return DepositResult{Applied: true}
}

// --- the queue -------------------------------------------------------------

type entryLifecycle uint8

const (
	entryPending entryLifecycle = iota
	entryTentativelyExecuted
	entryCertifiedConsumed
)

// InboxEntry is one admitted forced-inclusion request.
type InboxEntry struct {
	Seq            uint64
	Sender         string
	CreditID       string
	PayloadDigest  []byte
	DeclaredGas    uint64
	AdmissionRound uint64
	state          entryLifecycle
}

// AdmissionLimits are the root-checked bounds. No application logic runs at
// admission and no future balance is predicted.
type AdmissionLimits struct {
	MaxEncodedBytes uint64
	GFI             uint64 // reserved forced-execution budget; every declared gas <= GFI
	PerSenderQueue  int
	GlobalQueue     int
}

// ForcedInbox is the bounded ordered queue for the governance shard. It
// keeps three views: the live executable queue (pending +
// tentatively-executed), per-sender occupancy of the live queue, and an
// archive of certified-consumed entries (retained for proof export, never
// re-executed).
type ForcedInbox struct {
	escrow       *CreditEscrow
	limits       AdmissionLimits
	nextSeq      uint64
	seqExhausted bool
	live         []InboxEntry          // seq-ordered; pending or tentatively executed
	archive      map[uint64]InboxEntry // certified-consumed, by seq
	perSender    map[string]int        // live-queue occupancy
	watermark    uint64                // highest seq certified-consumed
	acked        bool                  // whether any consumption has been acknowledged
}

func NewForcedInbox(escrow *CreditEscrow, limits AdmissionLimits) *ForcedInbox {
	return &ForcedInbox{escrow: escrow, limits: limits, archive: map[uint64]InboxEntry{}, perSender: map[string]int{}}
}

func (q *ForcedInbox) entryState(seq uint64) entryLifecycle {
	for _, e := range q.live {
		if e.Seq == seq {
			return e.state
		}
	}
	if _, ok := q.archive[seq]; ok {
		return entryCertifiedConsumed
	}
	return entryPending
}

// AvailableCapacity is how many more entries `sender` can currently admit.
func (q *ForcedInbox) AvailableCapacity(sender string) int {
	perSender := q.limits.PerSenderQueue - q.perSender[sender]
	global := q.limits.GlobalQueue - len(q.live)
	if global < perSender {
		perSender = global
	}
	if perSender < 0 {
		return 0
	}
	return perSender
}

// AdmitResult is the outcome of an admission attempt.
type AdmitResult struct {
	Admitted bool
	Seq      uint64
	Code     string
}

// EnqueueCertificate is the only proof of admission. An HTTP acknowledgement
// or a shard-statistics field is not one.
type EnqueueCertificate struct {
	Seq            uint64
	PayloadDigest  []byte
	AdmissionRound uint64
}

// Admit runs the root admission checks in order and, on success, mints and
// consumes exactly one unique credit for `sender` and appends a pending
// FIFO entry.
func (q *ForcedInbox) Admit(sender, creditID string, encodedBytes, declaredGas uint64, payloadDigest []byte, payloadPresent bool, admissionRound uint64, credentialsSyntaxOK, supportedTxType, networkOK bool) (AdmitResult, *EnqueueCertificate) {
	switch {
	case !networkOK:
		return AdmitResult{Code: "wrong_network"}, nil
	case !credentialsSyntaxOK:
		return AdmitResult{Code: "bad_signature_syntax"}, nil
	case !supportedTxType:
		return AdmitResult{Code: "unsupported_tx_type"}, nil
	case encodedBytes > q.limits.MaxEncodedBytes:
		return AdmitResult{Code: "too_large"}, nil
	case declaredGas == 0 || declaredGas > q.limits.GFI:
		return AdmitResult{Code: "declared_gas_over_g_fi"}, nil
	case !payloadPresent:
		return AdmitResult{Code: "payload_not_disseminated"}, nil
	case q.perSender[sender] >= q.limits.PerSenderQueue:
		return AdmitResult{Code: "per_sender_queue_full"}, nil
	case len(q.live) >= q.limits.GlobalQueue:
		return AdmitResult{Code: "global_queue_full"}, nil
	case q.seqExhausted:
		return AdmitResult{Code: "sequence_exhausted"}, nil
	}
	if c, ok := q.escrow.credits[creditID]; ok {
		if c.reconciled {
			return AdmitResult{Code: "credit_already_reconciled"}, nil
		}
		return AdmitResult{Code: "credit_already_consumed"}, nil
	}
	if !q.escrow.mintCredit(creditID, sender) {
		return AdmitResult{Code: "no_credit"}, nil
	}

	seq := q.nextSeq
	if seq == ^uint64(0) {
		q.seqExhausted = true
	} else {
		q.nextSeq = seq + 1
	}
	credit := q.escrow.credits[creditID]
	credit.consumedBy = seq
	credit.consumed = true
	q.live = append(q.live, InboxEntry{
		Seq: seq, Sender: sender, CreditID: creditID, PayloadDigest: payloadDigest,
		DeclaredGas: declaredGas, AdmissionRound: admissionRound, state: entryPending,
	})
	q.perSender[sender]++
	return AdmitResult{Admitted: true, Seq: seq}, &EnqueueCertificate{Seq: seq, PayloadDigest: payloadDigest, AdmissionRound: admissionRound}
}

// EntryOutcome is the deterministic result of processing one FIFO entry.
type EntryOutcome struct {
	Seq          uint64
	Executed     bool   // reached the EVM (may still have reverted)
	Reason       string // authenticated rejection reason for a poisoned entry
	AlreadyFinal bool   // skipped: this entry was already certified-consumed
}

// PoisonKind classifies an entry invalid at its deterministic turn.
type PoisonKind string

const (
	PoisonNone            PoisonKind = ""
	PoisonNonceUsed       PoisonKind = "nonce_already_used"
	PoisonInsufficient    PoisonKind = "insufficient_balance"
	PoisonFeeCapBelowBase PoisonKind = "fee_cap_below_base_fee"
	PoisonIncompatible    PoisonKind = "incompatible_activated_rules"
	PoisonHigherNonce     PoisonKind = "higher_nonce_not_ready"
)

// ProcessDuePrefix tentatively executes the pending FIFO prefix whose
// combined declared gas fits g_fi. An entry already certified-consumed is
// skipped (AlreadyFinal) and never re-executed — this is what a crash/
// replay hits. A poisoned entry is marked executed-with-reason and does not
// stall the queue.
func (q *ForcedInbox) ProcessDuePrefix(poison map[uint64]PoisonKind) []EntryOutcome {
	var out []EntryOutcome
	var gas uint64
	for i := range q.live {
		e := &q.live[i]
		if e.state == entryCertifiedConsumed {
			out = append(out, EntryOutcome{Seq: e.Seq, AlreadyFinal: true})
			continue
		}
		if gas+e.DeclaredGas > q.limits.GFI {
			break
		}
		gas += e.DeclaredGas
		oc := EntryOutcome{Seq: e.Seq}
		if p := poison[e.Seq]; p != PoisonNone {
			oc.Reason = string(p)
		} else {
			oc.Executed = true
		}
		e.state = entryTentativelyExecuted
		out = append(out, oc)
	}
	return out
}

// AcknowledgeConsumption advances the certified-consumption watermark to
// `throughSeq` exactly once, moving every live entry with seq <= throughSeq
// into the archive and RELEASING its per-sender / global queue slot. A
// repeat call with the same or a lower value is a no-op.
func (q *ForcedInbox) AcknowledgeConsumption(throughSeq uint64) bool {
	if q.acked && throughSeq <= q.watermark {
		return false
	}
	kept := q.live[:0]
	for _, e := range q.live {
		if e.Seq <= throughSeq {
			e.state = entryCertifiedConsumed
			q.archive[e.Seq] = e
			q.perSender[e.Sender]--
		} else {
			kept = append(kept, e)
		}
	}
	q.live = kept
	q.watermark = throughSeq
	q.acked = true
	return true
}

// RevokeEntry permanently removes a still-pending entry from the live queue
// as part of a root-certified admission rollback (see
// CreditEscrow.ReconcileUnusedCredit): it drops the entry and releases its
// per-sender / global slot. It matches on BOTH seq and creditID, so a
// stale seq or an unrelated queue cannot revoke the wrong entry. It refuses
// an entry that is already tentatively executed or certified-consumed —
// those outcomes cannot be rolled back. A revoked entry is neither live nor
// archived, so it no longer blocks PositionCutoffSatisfied: its admission
// was resolved by the certified rollback. Returns false if (seq, creditID)
// is not a pending live entry.
func (q *ForcedInbox) RevokeEntry(seq uint64, creditID string) bool {
	for i := range q.live {
		if q.live[i].Seq != seq || q.live[i].CreditID != creditID {
			continue
		}
		if q.live[i].state != entryPending {
			return false
		}
		sender := q.live[i].Sender
		q.live = append(q.live[:i], q.live[i+1:]...)
		q.perSender[sender]--
		return true
	}
	return false
}

// Watermark is the acknowledged consumption position.
func (q *ForcedInbox) Watermark() uint64 { return q.watermark }

// PositionCutoffSatisfied is the withdrawal linkage: every entry admitted
// at or before `deadlineRound` (a root round) must be certified-consumed.
// An empty interval (nothing admitted through deadlineRound) is trivially
// satisfied.
func (q *ForcedInbox) PositionCutoffSatisfied(deadlineRound uint64) bool {
	for _, e := range q.live {
		if e.AdmissionRound <= deadlineRound {
			return false // still live => not yet certified-consumed
		}
	}
	return true
}

// --- inclusion bound K --------------------------------------------------

// InclusionBoundK is the published worst-case number of produced EVM blocks
// before an admitted entry is processed. FIFO entries are indivisible, so
// the adversary makes every entry as large as the declared limit allows:
//
//	entriesPerBlock = max(1, g_fi / declaredGasLimit)
//	blocksForBacklog = ceil( (maxBacklogEntries + 1) / entriesPerBlock )
//	K = blocksForBacklog + originObservationLagBlocks + rootRoundAllowanceBlocks
//
// All three added terms are in PRODUCED EVM BLOCKS. maxBacklogEntries is the
// admission-bounded backlog (global queue size); declaredGasLimit is the
// per-entry gas cap. The +1 counts the entry itself. Every quantity is
// bounded by admission limits, so no term overflows.
func InclusionBoundK(maxBacklogEntries, declaredGasLimit, gFI, originObservationLagBlocks, rootRoundAllowanceBlocks uint64) uint64 {
	if gFI == 0 || declaredGasLimit == 0 {
		return 0
	}
	entriesPerBlock := gFI / declaredGasLimit
	if entriesPerBlock == 0 {
		entriesPerBlock = 1
	}
	blocksForBacklog := (maxBacklogEntries + 1 + entriesPerBlock - 1) / entriesPerBlock
	return blocksForBacklog + originObservationLagBlocks + rootRoundAllowanceBlocks
}

// SponsorPathAvailable reports whether the executable permissionless
// newcomer path is wired: a first-time user with no credits can be funded
// through a certified SponsorGrant (GrantSponsoredCredit). This replaces the
// former SponsorPathDocumented constant.
func SponsorPathAvailable() bool { return true }
