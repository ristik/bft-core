package evmroot

// D5 part 3: forced-inbox admission with prepaid UCT credits, exactly-once
// charging, refund reconciliation, FIFO progress past poisoned entries, and
// the worst-case inclusion bound K.
//
// Normative source: docs/design/d5-accountability-retirement-inbox.md §4,
// docs/pos/specification/appendix-evm.tex §"Forced Inclusion".

// CreditEscrow is the immutable EVM escrow holding prepaid UCT credits.
// Root admission verifies a certified deposit and consumes a unique credit
// in root consensus; a duplicate deposit proof is idempotent, never a
// second credit.
type CreditEscrow struct {
	credited  map[string]uint64 // owner -> available credits
	seenProof map[string]bool   // certified-deposit proof id -> seen (duplicate guard)
	consumed  map[string]bool   // credit id -> consumed in root consensus
	reserved  map[string]string // credit id -> queue entry it backs (reconciliation key)
}

func NewCreditEscrow() *CreditEscrow {
	return &CreditEscrow{
		credited:  map[string]uint64{},
		seenProof: map[string]bool{},
		consumed:  map[string]bool{},
		reserved:  map[string]string{},
	}
}

// DepositResult is the outcome of applying a certified deposit proof.
type DepositResult struct {
	Applied bool
	Reason  string
}

// ApplyDeposit credits `amount` to `owner` against a certified deposit
// identified by proofID. Replaying the same proofID is a no-op (idempotent)
// — never a second credit, so there is no unbacked admission from a
// duplicated proof.
func (e *CreditEscrow) ApplyDeposit(proofID, owner string, amount uint64) DepositResult {
	if proofID == "" || owner == "" || amount == 0 {
		return DepositResult{false, "malformed deposit"}
	}
	if e.seenProof[proofID] {
		return DepositResult{false, "duplicate certified-deposit proof — already credited"}
	}
	e.seenProof[proofID] = true
	e.credited[owner] += amount
	return DepositResult{Applied: true}
}

// InboxEntry is one admitted forced-inclusion request.
type InboxEntry struct {
	Seq            uint64
	Sender         string
	CreditID       string
	PayloadDigest  []byte
	DeclaredGas    uint64
	AdmissionRound uint64
	PayloadPresent bool // full payload disseminated before the enqueue vote
}

// AdmissionLimits are the root-checked bounds. No application logic runs at
// admission and no future balance is predicted.
type AdmissionLimits struct {
	MaxEncodedBytes uint64
	GFI             uint64 // reserved forced-execution budget; every declared gas <= GFI
	PerSenderQueue  int
	GlobalQueue     int
}

// ForcedInbox is the bounded ordered queue for the governance shard.
type ForcedInbox struct {
	escrow    *CreditEscrow
	limits    AdmissionLimits
	nextSeq   uint64
	queue     []InboxEntry
	perSender map[string]int
	watermark uint64 // highest seq whose consumption the root has acknowledged, +1 (0 = nothing consumed)
}

func NewForcedInbox(escrow *CreditEscrow, limits AdmissionLimits) *ForcedInbox {
	return &ForcedInbox{escrow: escrow, limits: limits, perSender: map[string]int{}}
}

// AdmitResult is the outcome of an admission attempt.
type AdmitResult struct {
	Admitted bool
	Seq      uint64
	Code     string
}

// EnqueueCertificate is the only thing that proves admission. An HTTP
// acknowledgement or a shard-statistics field is not one — a caller holding
// only an HTTP 200 has no AdmitResult.Admitted == true from this function.
type EnqueueCertificate struct {
	Seq            uint64
	PayloadDigest  []byte
	AdmissionRound uint64
}

// Admit runs the root admission checks in order and, on success, consumes
// exactly one unique credit and appends a FIFO entry.
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
	case len(q.queue) >= q.limits.GlobalQueue:
		return AdmitResult{Code: "global_queue_full"}, nil
	}
	// Admission charge: consume exactly one unique, unconsumed credit.
	if q.escrow.consumed[creditID] {
		return AdmitResult{Code: "credit_already_consumed"}, nil
	}
	if _, reserved := q.escrow.reserved[creditID]; reserved {
		return AdmitResult{Code: "credit_already_reserved"}, nil
	}
	owner := sender
	if q.escrow.credited[owner] == 0 {
		return AdmitResult{Code: "no_credit"}, nil
	}
	q.escrow.credited[owner]--
	q.escrow.consumed[creditID] = true

	seq := q.nextSeq
	q.nextSeq++
	entry := InboxEntry{
		Seq: seq, Sender: sender, CreditID: creditID, PayloadDigest: payloadDigest,
		DeclaredGas: declaredGas, AdmissionRound: admissionRound, PayloadPresent: payloadPresent,
	}
	q.queue = append(q.queue, entry)
	q.perSender[sender]++
	q.escrow.reserved[creditID] = keyForSeq(seq)
	return AdmitResult{Admitted: true, Seq: seq}, &EnqueueCertificate{Seq: seq, PayloadDigest: payloadDigest, AdmissionRound: admissionRound}
}

func keyForSeq(seq uint64) string { return "seq:" + itoa(seq) }

// EntryOutcome is the deterministic result of processing one FIFO entry at
// its turn.
type EntryOutcome struct {
	Seq        uint64
	Executed   bool   // reached the EVM (may still have reverted)
	Reason     string // authenticated rejection reason for a poisoned entry
	CreditKept bool   // a consumed credit is never refunded for an admitted entry
}

// PoisonKind classifies an entry that is invalid at its deterministic turn.
type PoisonKind string

const (
	PoisonNone            PoisonKind = ""
	PoisonNonceUsed       PoisonKind = "nonce_already_used"
	PoisonInsufficient    PoisonKind = "insufficient_balance"
	PoisonFeeCapBelowBase PoisonKind = "fee_cap_below_base_fee"
	PoisonIncompatible    PoisonKind = "incompatible_activated_rules"
	PoisonHigherNonce     PoisonKind = "higher_nonce_not_ready"
)

// ProcessDuePrefix processes the FIFO prefix whose combined declared gas
// fits g_fi, returning one outcome per entry. A poisoned entry is consumed
// with its authenticated reason and does NOT stall the queue; a
// not-yet-ready higher nonce is rejected rather than blocking FIFO. An
// admitted entry's credit is never refunded here — refunds go only through
// root-certified reconciliation of *unused* credits.
func (q *ForcedInbox) ProcessDuePrefix(poison map[uint64]PoisonKind) []EntryOutcome {
	var out []EntryOutcome
	var gas uint64
	for _, e := range q.queue {
		if gas+e.DeclaredGas > q.limits.GFI {
			break
		}
		gas += e.DeclaredGas
		oc := EntryOutcome{Seq: e.Seq, CreditKept: true}
		switch poison[e.Seq] {
		case PoisonNone:
			oc.Executed = true
		default:
			oc.Executed = false
			oc.Reason = string(poison[e.Seq])
		}
		out = append(out, oc)
	}
	return out
}

// AcknowledgeConsumption advances the consumption watermark to `throughSeq`
// exactly once. A repeat call with the same or a lower value is a no-op —
// a repeat UC does not double-advance the watermark or create a second
// reward/refund claim.
func (q *ForcedInbox) AcknowledgeConsumption(throughSeq uint64) bool {
	if throughSeq < q.watermark {
		return false
	}
	if throughSeq == q.watermark {
		return false // idempotent no-op
	}
	q.watermark = throughSeq
	return true
}

// Watermark is the acknowledged consumption position.
func (q *ForcedInbox) Watermark() uint64 { return q.watermark }

// ReconcileUnusedCredit refunds a credit ONLY when the root has certified
// that its queue entry was never consumed (e.g. the admission was rolled
// back). A credit backing a consumed entry is never refunded, and a refund
// is applied at most once regardless of how many refund requests race.
func (e *CreditEscrow) ReconcileUnusedCredit(creditID, owner string, rootCertifiedUnused bool) DepositResult {
	if !rootCertifiedUnused {
		return DepositResult{false, "no root-certified reconciliation that the credit is unused"}
	}
	if !e.consumed[creditID] {
		return DepositResult{false, "credit was not consumed — nothing to reconcile"}
	}
	if _, stillReserved := e.reserved[creditID]; !stillReserved {
		return DepositResult{false, "credit already reconciled"}
	}
	delete(e.reserved, creditID)
	e.consumed[creditID] = false
	e.credited[owner]++
	return DepositResult{Applied: true}
}

// InclusionBoundK is the published worst-case number of produced EVM blocks
// before an admitted entry is processed:
//
//	K = ceil( (maxBacklogGas + declaredGasLimit) / gFI )
//	    + originObservationLagBlocks
//	    + rootRoundAllowanceBlocks
//
// It folds in the maximum admitted backlog, the declared per-entry gas
// limit, the reserved per-block budget g_fi, and the lag between an entry's
// admission round and the first EVM block that can observe it. A
// root-round allowance additionally requires a bounded EVM progress
// assumption.
func InclusionBoundK(maxBacklogGas, declaredGasLimit, gFI, originObservationLagBlocks, rootRoundAllowanceBlocks uint64) uint64 {
	if gFI == 0 {
		return 0
	}
	blocksForGas := (maxBacklogGas + declaredGasLimit + gFI - 1) / gFI
	return blocksForGas + originObservationLagBlocks + rootRoundAllowanceBlocks
}

// SponsorPathDocumented records that a first-time user without credits has a
// documented permissionless sponsor path; the inclusion guarantee is
// conditional on it. This is a design assertion, not a runtime check.
const SponsorPathDocumented = true

func itoa(u uint64) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}
