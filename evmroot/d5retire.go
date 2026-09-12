package evmroot

// D5 part 2: collateral reservation lifecycle, actual retirement
// acknowledgement, inherited protection, and the evidence / inbox-watermark
// gates on withdrawal.
//
// Normative source: docs/design/d5-accountability-retirement-inbox.md §3,
// docs/pos/specification/governance.tex §"Economic Invariants".

// ProtectionParams are the round-denominated timing parameters. The
// ordering constraint is mandatory:
//
//	W_cert <= Δ_ev < Δ_hold   and   Δ_hold > Δ_ev + Δ_incl + Δ_exec
type ProtectionParams struct {
	WCert     uint64 // live certificate admission window
	DeltaEv   uint64 // evidence commitment window
	DeltaIncl uint64
	DeltaExec uint64
	DeltaHold uint64 // protection after acknowledged retirement
}

// Valid reports whether the parameters satisfy the mandatory ordering.
func (p ProtectionParams) Valid() bool {
	return p.WCert <= p.DeltaEv &&
		p.DeltaEv < p.DeltaHold &&
		p.DeltaHold > p.DeltaEv+p.DeltaIncl+p.DeltaExec
}

// ReservationPhase is the collateral lifecycle.
type ReservationPhase uint8

const (
	Bonded ReservationPhase = iota
	RetirementRequested
	Draining // acknowledged retirement; protection running
	Released
)

func (r ReservationPhase) String() string {
	return [...]string{"bonded", "retirement_requested", "draining", "released"}[r]
}

// Reservation is one validator's bonded collateral through retirement.
type Reservation struct {
	Phase ReservationPhase

	// Set when retirement is *acknowledged* (not merely requested): the
	// authenticated acknowledgement that the stake no longer backs any
	// active OR prepared successor assignment.
	RetirementRound uint64 // R_ret

	// Inherited protection: the latest R_ret + Δ_hold this key was ever
	// subject to across rotations/delegation changes. Key rotation and
	// queued withdrawals cannot remove liability for an earlier offense.
	InheritedProtectionUntil uint64

	// LiabilityDeadlineRound is the root round through which every
	// forced-inbox entry that could carry evidence against this key must be
	// certified-consumed before withdrawal. It is a ROOT ROUND; the linkage
	// to inbox sequence positions is ForcedInbox.PositionCutoffSatisfied,
	// not a raw watermark comparison.
	LiabilityDeadlineRound uint64
}

// RequestRetirement moves Bonded -> RetirementRequested. It does not start
// the protection clock; only an acknowledgement does.
func (r *Reservation) RequestRetirement() bool {
	if r.Phase != Bonded {
		return false
	}
	r.Phase = RetirementRequested
	return true
}

// AcknowledgeRetirement records R_ret: the authenticated acknowledgement
// that the stake no longer backs any active or prepared successor
// assignment. Only from RetirementRequested. backsPreparedSuccessor must be
// false — an acknowledgement while a prepared successor still relies on the
// stake is invalid.
func (r *Reservation) AcknowledgeRetirement(round uint64, backsActiveOrPrepared bool) bool {
	if r.Phase != RetirementRequested || backsActiveOrPrepared {
		return false
	}
	r.Phase = Draining
	r.RetirementRound = round
	return true
}

// WithdrawBlock explains why a withdrawal is (not) allowed at the given
// root round.
type WithdrawBlock struct {
	Allowed bool
	Reason  string
}

// CanWithdraw evaluates every gate at root round `now`:
//
//   - phase must be Draining;
//   - now >= max(R_ret + Δ_hold, inherited protection);
//   - positionCutoffSatisfied: every forced-inbox entry admitted at or
//     before LiabilityDeadlineRound is certified-consumed (an empty
//     interval satisfies this trivially) — from
//     ForcedInbox.PositionCutoffSatisfied(r.LiabilityDeadlineRound), never a
//     raw sequence/round comparison;
//   - no timely-queued evidence against this key may be pending.
//
// Exceeding Δ_incl/Δ_exec never unlocks an unresolved liability.
func (r *Reservation) CanWithdraw(now uint64, p ProtectionParams, positionCutoffSatisfied, timelyEvidencePending bool) WithdrawBlock {
	if r.Phase != Draining {
		return WithdrawBlock{false, "reservation is not in the draining phase"}
	}
	protectionUntil := r.RetirementRound + p.DeltaHold
	if r.InheritedProtectionUntil > protectionUntil {
		protectionUntil = r.InheritedProtectionUntil
	}
	if now < protectionUntil {
		return WithdrawBlock{false, "protection period has not elapsed"}
	}
	if !positionCutoffSatisfied {
		return WithdrawBlock{false, "forced-inbox entries admitted through the liability deadline are not all certified-consumed"}
	}
	if timelyEvidencePending {
		return WithdrawBlock{false, "a timely-queued evidence case against this key is still unprocessed"}
	}
	return WithdrawBlock{true, ""}
}

// EvidenceTimely reports whether an evidence case is timely: executed
// within Δ_ev root rounds of the offense, OR its complete payload was
// committed to the forced inbox within that window. A bare local submission
// or an unavailable payload hash does not preserve timeliness.
func EvidenceTimely(offenseRound, execRound uint64, p ProtectionParams, inboxCommitRound uint64, payloadAvailable bool) bool {
	if execRound >= offenseRound && execRound-offenseRound <= p.DeltaEv {
		return true
	}
	if payloadAvailable && inboxCommitRound >= offenseRound && inboxCommitRound-offenseRound <= p.DeltaEv {
		return true
	}
	return false
}
