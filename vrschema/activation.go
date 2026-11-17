package vrschema

import "errors"

// ScheduleActivation payload decoded.
type Schedule struct {
	RuleID          Word   `json:"-"`
	ReleaseDigest   Word   `json:"-"`
	RootEpoch       uint64 `json:"rootEpoch"`
	NotBeforeUcTime uint64 `json:"notBeforeUcTime"`
	Label           string `json:"label"`
}

// DecodeSchedule decodes a kind 9 payload.
func DecodeSchedule(payload []byte) (Schedule, error) {
	v, err := DecodeChangePayload(KindScheduleActivation, payload)
	if err != nil {
		return Schedule{}, err
	}
	return Schedule{RuleID: v[0].(Word), ReleaseDigest: v[1].(Word), RootEpoch: v[2].(uint64), NotBeforeUcTime: v[3].(uint64), Label: v[4].(string)}, nil
}

// Effective returns the effective entry of each rule: the latest non-Superseded entry. The list is append-only, so later entries win.
func Effective(entries []Activation) map[Word]Activation {
	out := map[Word]Activation{}
	for _, a := range entries {
		if a.State != ActSuperseded {
			out[a.RuleID] = a
		}
	}
	return out
}

// ScheduleVerdict is the fold verdict of a kind 9 change against the effective schedule (latched entries included) for a candidate
// whose successor epoch is successorEpoch:
//   - the rule is latched: Latched;
//   - cutoff: successorEpoch <= E - 2, else PastCutoff (for a postponement, against the current effective E as well);
//   - postponement: E' > E supersedes; E' < E is Earlier; E' = E is Conflict.
func ScheduleVerdict(s Schedule, successorEpoch uint64, effective map[Word]Activation) uint8 {
	if s.RootEpoch < 2 || successorEpoch > s.RootEpoch-2 {
		return VerdictPastCutoff
	}
	if cur, ok := effective[s.RuleID]; ok {
		if cur.State == ActLatched {
			return VerdictLatched
		}
		if cur.RootEpoch < 2 || successorEpoch > cur.RootEpoch-2 {
			return VerdictPastCutoff
		}
		if s.RootEpoch < cur.RootEpoch {
			return VerdictEarlier
		}
		if s.RootEpoch == cur.RootEpoch {
			return VerdictConflict // E' = E: neither a postponement nor earlier (freeze decision FD-12)
		}
	}
	return VerdictAccepted
}

// ErrActivationTime is the Prepare time gate refusal.
var ErrActivationTime = errors.New("ActivationNotBefore")

// PrepareTimeGate: for every effective schedule with E <= e_J + 1 (the successor epoch and its possible recovery epoch), the Prepare's
// UC time is at least the schedule's notBeforeUcTime. It is a Prepare gate, never a verdict.
func PrepareTimeGate(successorEpoch, ucTime uint64, effective map[Word]Activation) error {
	for _, a := range effective {
		if a.RootEpoch <= successorEpoch+1 && ucTime < a.NotBeforeUcTime {
			return ErrActivationTime
		}
	}
	return nil
}

// Latch marks permanently, at the Boundary installing root epoch e, every effective entry with E <= e.
func Latch(entries []Activation, installedRootEpoch uint64) []Activation {
	out := append([]Activation(nil), entries...)
	eff := Effective(out)
	for i, a := range out {
		if a.State == ActActive && a.RootEpoch <= installedRootEpoch && eff[a.RuleID] == a {
			out[i].State = ActLatched
		}
	}
	return out
}

// AppendSchedule appends an accepted schedule at its Boundary, superseding the rule's earlier effective entry.
func AppendSchedule(entries []Activation, s Schedule, changeID uint64) ([]Activation, error) {
	if len(entries) >= MaxActivations {
		return entries, ErrOversize
	}
	out := append([]Activation(nil), entries...)
	for i, a := range out {
		if a.RuleID == s.RuleID && a.State == ActActive {
			out[i].State = ActSuperseded
		}
	}
	return append(out, Activation{RuleID: s.RuleID, ReleaseDigest: s.ReleaseDigest, RootEpoch: s.RootEpoch, NotBeforeUcTime: s.NotBeforeUcTime,
		State: ActActive, ChangeID: changeID}), nil
}

// RuleRequired reports whether a block of root epoch e is under rule r: its effective entry has E <= e.
func RuleRequired(effective map[Word]Activation, rule Word, epoch uint64) bool {
	a, ok := effective[rule]
	return ok && a.RootEpoch <= epoch
}
