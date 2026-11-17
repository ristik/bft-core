package vradmit

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// RejectState is what a RejectResult v2 witness proves at the rejection parent: R's output state from VR, and the SealRegistry's
// canonical progress (the clock VR stamps reservedProgress and expiresAtProgress in).
type RejectState struct {
	Output   OutputState
	Progress uint64
}

// ErrReject reports a RejectResult v2 that is not due, names another reason or carries fields its reason does not allow.
var ErrReject = errors.New("vradmit: RejectResult v2 refused")

// AdmissionFailsAtP reports the deterministic admission failures the proven output state alone establishes for a Published R (the
// "Invalid" row of the due table, design section 5.6): another network word, VR Inconsistent at P, a predecessor that is not the root's
// acknowledged result, or a K digest that is not the acknowledged committee's. Member-content failures need the captured preimages and
// are judged at the Freeze; a Freeze refused for them leaves R to expire.
func AdmissionFailsAtP(s OutputState, d Deployment, acknowledged, ackCommitteeDigest vrschema.Word) bool {
	o := s.Output
	return s.Network != d.NetworkWord || s.Status.Health == vrschema.HealthInconsistent || o.Predecessor != acknowledged ||
		o.KDigest != ackCommitteeDigest
}

// VerifyReject is the RejectResult v2 due table (design section 5.6) over the proven state: the reason the data names must be the one
// the table gives (Expired for a Reserved or Published R at progress >= expiresAtProgress, counted from reservation and never reset;
// Invalidated immediately; Invalid for a Published R with a deterministic admission failure); memberId is zero (the failures judged
// here name no member) and readyBitmap is carried only by an expiry. A network word other than the deployment's is not a refusal here:
// it is one of the proven admission failures, so it makes a Published R due as Invalid (and a Reserved or Published R past its
// expiry due as Expired); the witness itself is pinned by the certified root, VR's address and code hash (review #1172, astra 4). The control-state rules (quiet state, unresolved R, the root's next
// attempt) are the executor's.
func VerifyReject(s RejectState, data vrschema.OutputRejected, d Deployment, acknowledged, ackCommitteeDigest vrschema.Word) error {
	if s.Output.ResultID != data.ResultID || data.ResultID == (vrschema.Word{}) {
		return fmt.Errorf("%w: the witness is of another result", ErrReject)
	}
	o := s.Output.Output
	fails := o.State == vrschema.OutPublished && AdmissionFailsAtP(s.Output, d, acknowledged, ackCommitteeDigest)
	reason, due := vrschema.RejectDue(o.State, s.Progress, o.ExpiresAtProgress, fails)
	switch {
	case !due:
		return fmt.Errorf("%w: R in state %s is not due at progress %d (expires at %d)", ErrReject, vrschema.OutputStateNames[o.State], s.Progress, o.ExpiresAtProgress)
	case data.Reason != reason:
		return fmt.Errorf("%w: reason %d, the due table gives %d", ErrReject, data.Reason, reason)
	case data.MemberID != 0:
		return fmt.Errorf("%w: memberId %d names a member no proven failure names", ErrReject, data.MemberID)
	case data.Reason != vrschema.RejExpired && data.ReadyBitmap != 0:
		return fmt.Errorf("%w: a ready bitmap outside an expiry", ErrReject)
	}
	return nil
}

// ProjectReject is the record pair of one RejectResult v2: OutputRejected(data), then SessionClosed(resultId).
func ProjectReject(data vrschema.OutputRejected) [][2]any {
	return [][2]any{{vrschema.RecOutputRejected, data.Encode()}, {vrschema.RecSessionClosed, append([]byte(nil), data.ResultID[:]...)}}
}

// VerifyRetirement is control op 2 v2 over the decoded three-account witness, in the frozen check order (schema section 13).
func VerifyRetirement(w vrschema.RetirementWitness, h vrschema.HolderRetirement) error {
	if h.Holder >= vrschema.MaxHolders {
		return vrschema.ErrRetHolder
	}
	return vrschema.VerifyHolderRetirement(w, h)
}
