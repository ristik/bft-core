package vrschema

import "errors"

// RootModel is the reference model of the root side of S1/S2a (design section 8.1): the control state of the handoff attempt, the
// resolved set and the records the root projects. It judges validity only; who proposes what is policy.
type RootModel struct {
	Epoch    uint64
	Control  ControlState
	Resolved map[Word]bool
	Prepared Word // the result the live Prepare names
	Retained bool // a Freeze retained the primary candidate of Prepared
	Out      []LogRecord
}

// NewRootModel is an idle root at epoch e.
func NewRootModel(epoch uint64) *RootModel {
	return &RootModel{Epoch: epoch, Resolved: map[Word]bool{}}
}

// Root refusals.
var (
	ErrNotQuiet     = errors.New("NotQuiet")
	ErrResolved     = errors.New("Resolved")
	ErrNotDue       = errors.New("NotDue")
	ErrLapsed       = errors.New("PrepareLapsed")
	ErrNoPrepare    = errors.New("NoPrepare")
	ErrNotPublished = errors.New("NotPublishedAtP")
)

// Quiet is the control state at which a fresh Prepare or a RejectResult may be ordered: idle, aborted, or a Prepare dead after its
// cooldown (round > OrderedRound + 48).
func (r *RootModel) Quiet(round uint64) bool {
	switch r.Control.Kind {
	case CtlIdle, CtlAborted:
		return true
	case CtlPrepared:
		// overflow-checked: a Prepare ordered within 48 rounds of 2^64 - 1 never becomes dead
		return r.Control.OrderedRound <= ^uint64(0)-PrepareCooldown && round > r.Control.OrderedRound+PrepareCooldown
	}
	return false
}

// ErrNoAttempt refuses a Prepare when the next attempt is undefined.
var ErrNoAttempt = errors.New("NoPlannableAttempt")

// Prepare orders a Prepare for R at a quiet state; the attempt must be defined by the checked planning helper (an exhausted attempt
// counter is ErrHandoffApproval), and nothing changes on a refusal.
func (r *RootModel) Prepare(res Word, round uint64) error {
	if !r.Quiet(round) {
		return ErrNotQuiet
	}
	if r.Resolved[res] {
		return ErrResolved
	}
	k, ok, err := PlannableAttempt(r.Control, round)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNoAttempt
	}
	r.Control = ControlState{Kind: CtlPrepared, Attempt: k, OrderedRound: round}
	r.Prepared, r.Retained = res, false
	return nil
}

// Freeze orders a Freeze for the live Prepare: in time (round <= OrderedRound + 24), R not resolved, and R Published and open at P.
func (r *RootModel) Freeze(round uint64, publishedAtP bool) error {
	switch {
	case r.Control.Kind != CtlPrepared:
		return ErrNoPrepare
	case !FreezeInTime(r.Control.OrderedRound, round):
		return ErrLapsed
	case r.Resolved[r.Prepared]:
		return ErrResolved
	case !publishedAtP:
		return ErrNotPublished
	}
	r.Control.Kind, r.Retained = CtlFrozen, true
	return nil
}

// Abort ends the attempt. An attempt whose Freeze retained a primary candidate projects SessionClosed(R); a pre-Freeze or recovery
// Abort projects nothing for R.
func (r *RootModel) Abort(recovery bool) {
	if r.Retained && !recovery {
		r.Out = append(r.Out, LogRecord{Kind: RecSessionClosed, ResultID: r.Prepared})
		r.Resolved[r.Prepared] = true
	}
	r.Control = ControlState{Kind: CtlAborted, Attempt: r.Control.Attempt}
	r.Retained = false
}

// Reject orders RejectResult(R): quiet, unresolved and due; it projects OutputRejected then SessionClosed and resolves R.
func (r *RootModel) Reject(res Word, round uint64, due bool) error {
	switch {
	case !r.Quiet(round):
		return ErrNotQuiet
	case r.Resolved[res]:
		return ErrResolved
	case !due:
		return ErrNotDue
	}
	r.Resolved[res] = true
	r.Out = append(r.Out, LogRecord{Kind: RecOutputRejected, ResultID: res}, LogRecord{Kind: RecSessionClosed, ResultID: res})
	return nil
}

// Commit is H committed and acknowledged: Ack (or RecoveryAck) immediately followed by the Boundary of the same result.
func (r *RootModel) Commit(recovered bool, bitmap uint16) error {
	if r.Control.Kind != CtlFrozen {
		return ErrNoPrepare
	}
	k := RecAck
	if recovered {
		k = RecRecoveryAck
	}
	r.Out = append(r.Out, LogRecord{Kind: k, ResultID: r.Prepared}, LogRecord{Kind: RecBoundary, ResultID: r.Prepared, Recovered: recovered, RejectedBitmap: bitmap})
	r.Resolved[r.Prepared] = true
	r.Epoch++
	r.Control, r.Retained = ControlState{}, false
	return nil
}

// RejectDue is the RejectResult v2 due table: Reserved or Published when progress >= expiresAtProgress (Expired); Invalidated
// immediately (Invalidated); Published with a deterministic admission failure (Invalid); never otherwise.
func RejectDue(state uint8, progress, expiresAt uint64, admissionFails bool) (uint8, bool) {
	switch state {
	case OutReserved, OutPublished:
		if progress >= expiresAt {
			return RejExpired, true
		}
		if state == OutPublished && admissionFails {
			return RejInvalid, true
		}
	case OutInvalidated:
		return RejInvalidated, true
	}
	return 0, false
}
