package storage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrHandoffRecord = errors.New("invalid root handoff record")
	ErrAbortAfterH   = errors.New("root handoff Abort follows committed H")
	ErrHandoffSuffix = errors.New("nonempty old-epoch handoff suffix")
	ErrHandoffFrozen = errors.New("EVM certification frozen by root handoff")
	// ErrFreezeBeforePrepare refuses a Freeze when no Prepare of this attempt is ordered: the root binds the frozen EVM parent at
	// the Prepare record, so the endorsements a Freeze carries can only follow it.
	ErrFreezeBeforePrepare = errors.New("root handoff Freeze without an ordered Prepare")
	// ErrFreezeParentUnbound refuses a Freeze whose frozen parent is not the parent the Prepare bound.
	ErrFreezeParentUnbound = errors.New("root handoff Freeze names a frozen parent other than the one bound at Prepare")
	// ErrPrepareActivationFloor refuses a Prepare whose activation round leaves less than PrepareActivationFloorRounds after it.
	ErrPrepareActivationFloor = errors.New("root handoff Prepare activation is closer than the endorsement window allows")
	// ErrPrepareNoEVMParent refuses a Prepare when the designated EVM shard has no certified input record to bind.
	ErrPrepareNoEVMParent = errors.New("root handoff Prepare without a certified EVM parent to bind")
	// ErrAssignmentAckPending refuses another handoff while the installed EVM
	// assignment has no certified acknowledgement, unless it supersedes that
	// assignment on the same frozen parent.
	// ErrNothingToSupersede is the acknowledged case of ErrSupersessionInvalid: the installed assignment already
	// has its certified acknowledgement, so there is no pending assignment to replace.
	ErrNothingToSupersede   = errors.New("EVM assignment already acknowledged: nothing to supersede")
	ErrSupersessionInvalid  = errors.New("EVM assignment supersession does not extend the committed unacknowledged chain")
	ErrAssignmentAckPending = errors.New("EVM assignment acknowledgement pending: only a supersession may follow")
	// ErrSupersessionChainTooLong refuses a supersession that would make the unacknowledged chain longer than
	// handoff.MaxSupersessionSpan: the whole chain is folded into one acknowledgement (and decoded by the engine) under that same
	// bound, so a longer chain admitted here could never be acknowledged.
	ErrSupersessionChainTooLong = errors.New("EVM assignment supersession would make the unacknowledged chain longer than the supersession span")
)

// ChainTooLongAdvice is what the operator is told when the unacknowledged chain is at its limit: only an acknowledged assignment resets
// it, and an unacknowledged one can only be superseded.
const ChainTooLongAdvice = "get the installed assignment acknowledged first (the EVM must certify its acknowledgement block) before proposing another change"

// CheckSupersessionChainLength is the one rule for how long the unacknowledged chain may get: committed is the number of committed,
// unacknowledged steps the new supersession would extend, and the chain after it (committed+1 steps) must not exceed
// handoff.MaxSupersessionSpan. Root block validation and the operator's planner both use it.
func CheckSupersessionChainLength(committed int) error {
	if committed < 0 || uint64(committed)+1 > handoff.MaxSupersessionSpan {
		return fmt.Errorf("%w: %d committed unacknowledged steps, the chain may not exceed %d; "+ChainTooLongAdvice, ErrSupersessionChainTooLong, committed, handoff.MaxSupersessionSpan)
	}
	return nil
}

type handoffAuthority interface {
	Predecessor() []byte
	VerifyFreeze(evmroot.OrderedHandoffRecord, []byte) ([]byte, error)
	VerifyAbort(evmroot.OrderedHandoffRecord, []byte) error
	// CurrentRoot is the old root committee, which a coupled candidate is checked against (no EVM-only change).
	CurrentRoot() []evmassign.RootMember
}

func recordNumber(v any) (uint64, bool) { n, ok := v.(uint64); return n, ok }
func recordBytes(v any) ([]byte, bool)  { b, ok := v.([]byte); return b, ok }

func decodeOrderedRecord(data []byte) (evmroot.OrderedHandoffRecord, error) {
	var r evmroot.OrderedHandoffRecord
	if len(data) == 0 || len(data) > 16*1024 {
		return r, ErrHandoffRecord
	}
	var fields []any
	if err := types.Cbor.Unmarshal(data, &fields); err != nil || len(fields) != 9 || fields[0] != "UNICITY_ORDERED_HANDOFF_RECORD" {
		return r, ErrHandoffRecord
	}
	version, ok := recordNumber(fields[1])
	if !ok || version != 1 {
		return r, ErrHandoffRecord
	}
	r.Network, ok = recordNumber(fields[2])
	if !ok {
		return r, ErrHandoffRecord
	}
	r.Epoch, ok = recordNumber(fields[3])
	if !ok {
		return r, ErrHandoffRecord
	}
	r.PredecessorBodyID, ok = recordBytes(fields[4])
	if !ok || len(r.PredecessorBodyID) != 32 {
		return r, ErrHandoffRecord
	}
	r.Attempt, ok = recordNumber(fields[5])
	if !ok {
		return r, ErrHandoffRecord
	}
	r.Kind, ok = fields[6].(string)
	if !ok {
		return r, ErrHandoffRecord
	}
	r.OrderedRound, ok = recordNumber(fields[7])
	if !ok || r.OrderedRound == 0 {
		return r, ErrHandoffRecord
	}
	payload, ok := fields[8].([]any)
	if !ok || len(payload) != 4 {
		return r, ErrHandoffRecord
	}
	r.FrozenID, ok = recordBytes(payload[0])
	if !ok || len(r.FrozenID) != 32 {
		return r, ErrHandoffRecord
	}
	r.NextBodyID, ok = recordBytes(payload[1])
	if !ok || len(r.NextBodyID) != 32 {
		return r, ErrHandoffRecord
	}
	r.ActivationRound, ok = recordNumber(payload[2])
	if !ok {
		return r, ErrHandoffRecord
	}
	r.SuccessorTRHash, ok = recordBytes(payload[3])
	if !ok || len(r.SuccessorTRHash) != 32 {
		return r, ErrHandoffRecord
	}
	if !bytes.Equal(data, r.Bytes()) {
		return r, ErrHandoffRecord
	}
	return r, nil
}

// DecodeOrderedHandoffRecord parses and checks the canonical ordered record.
func DecodeOrderedHandoffRecord(data []byte) (evmroot.OrderedHandoffRecord, error) {
	return decodeOrderedRecord(data)
}

// A Prepare record carries no signatures: any single leader can order one for a body no root endorsed. It freezes the EVM shard from
// its round, so the freeze must end by itself when no Freeze for that attempt follows, or one faulty leader could pause the EVM
// indefinitely. The lapse is a pure function of the Prepare's ordered round and the round of the block being executed, so every
// root, on every branch, agrees on it.
//
// PrepareFreezeLapseRounds is how long a Prepare freezes the EVM without a Freeze. The Prepare comes FIRST: the operator's plan is
// held by the validators as an unsigned intent, the Prepare is ordered for it, and only then (once the Prepare is committed) are the
// endorsements collected and the Freeze ordered. An honest operator needs about 6 to 8 rounds for that (the Prepare commits 2-3
// rounds after it is ordered, the operator polls about once a round, the endorsements reach the leader within a round); 24 leaves
// roughly three times that for a faulty leader or two in the rotation. After the lapse the EVM certifies again and the attempt is
// dead: a fresh Prepare, with the next attempt number (the lapse is treated like an abort for numbering), needs a new plan.
//
// HandoffActivationMarginRounds is the margin the protocol leaves between a record and the activation round it must still commit before.
// It is one number used twice, so the two cannot drift apart: in PrepareActivationFloorRounds (the whole lapse window plus this margin,
// so a Freeze ordered at the very end of the window still commits before activation) and in the leader's Commit adjustment
// (CommitActivationRound: the activation is never nearer than this many rounds after the Commit is ordered).
//
// PrepareActivationFloorRounds is the least distance from a Prepare to its activation round: the whole lapse window plus
// HandoffActivationMarginRounds, so a Freeze ordered at the very end of the window still commits before activation. It is enforced here, by
// block validation, not only by the leader that picks the activation round.
//
// PrepareCooldownRounds is the pause before that fresh Prepare may be ordered. It bounds what a faulty leader can do by repeating the
// attack: the EVM is frozen at most PrepareFreezeLapseRounds in every PrepareFreezeLapseRounds+PrepareCooldownRounds (50%), where
// without it the freeze could be renewed the moment it lapsed. That is a residual, deliberately kept simple: a faulty leader that
// leads one round in n can still halve EVM availability; removing it needs a signed Prepare, which is a protocol change.
const (
	PrepareFreezeLapseRounds      = 24
	PrepareCooldownRounds         = 24
	HandoffActivationMarginRounds = 8
	PrepareActivationFloorRounds  = PrepareFreezeLapseRounds + HandoffActivationMarginRounds
)

// prepareActivationFloor is PrepareActivationFloorRounds; it is a variable only so that the storage tests, whose compressed timelines
// activate within a few rounds of the Prepare, can lower it. Production never changes it.
var prepareActivationFloor uint64 = PrepareActivationFloorRounds

// PrepareLapsed reports whether a prepared control state's freeze has lapsed at the given block round: no Freeze followed within
// PrepareFreezeLapseRounds of the Prepare.
func PrepareLapsed(c *evmroot.ControlState, round uint64) bool {
	return c != nil && c.Phase == "prepared" && round > c.OrderedRound+PrepareFreezeLapseRounds
}

// PrepareMayFollowLapse reports whether a fresh Prepare (next attempt) may be ordered over a lapsed Prepare at this round.
func PrepareMayFollowLapse(c *evmroot.ControlState, round uint64) bool {
	return PrepareLapsed(c, round) && round > c.OrderedRound+PrepareFreezeLapseRounds+PrepareCooldownRounds
}

func applyHandoffRecord(previous *evmroot.ControlState, data []byte, network, epoch, round uint64, authority handoffAuthority, companion []byte) (*evmroot.ControlState, error) {
	if previous == nil {
		return nil, ErrNetworkProfile
	}
	r, err := decodeOrderedRecord(data)
	if err != nil {
		return nil, err
	}
	if r.Network != network || r.Epoch != epoch || r.OrderedRound != round || previous.Network != network || previous.Epoch != epoch {
		return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "the record's network, epoch or ordered round is not this block's")
	}
	if previous.Phase == "committed" && r.Kind == "abort" {
		return nil, errors.Join(ErrHandoffRecord, ErrAbortAfterH)
	}
	if authority == nil {
		return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "no handoff authority")
	}
	if !bytes.Equal(r.PredecessorBodyID, authority.Predecessor()) {
		return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "the record's predecessor body is not the root's current body")
	}
	if previous.Phase == "committed" {
		return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "the epoch change is already committed")
	}
	// A Prepare whose freeze lapsed is dead (the EVM certifies again); a fresh Prepare may follow it, with the next attempt number,
	// once the cooldown has passed. A Freeze for the lapsed attempt is refused below.
	lapsed := PrepareLapsed(previous, round)
	if lapsed && r.Kind == "prepare" && !PrepareMayFollowLapse(previous, round) {
		return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "a Prepare may not follow a lapsed one before the cooldown has passed")
	}
	if (previous.Phase == "idle" || previous.Phase == "aborted") && r.Kind == "freeze" {
		return nil, errors.Join(ErrHandoffRecord, ErrFreezeBeforePrepare)
	}
	if previous.Phase == "idle" || previous.Phase == "aborted" || (lapsed && r.Kind == "prepare") {
		if r.Kind != "prepare" {
			return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "only a Prepare may open an attempt (got "+r.Kind+")")
		}
		if len(companion) != 0 {
			return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "a Prepare carries no companion")
		}
		if (previous.Phase == "idle" && r.Attempt != 0) ||
			(previous.Phase != "idle" && (previous.Attempt == ^uint64(0) || r.Attempt != previous.Attempt+1)) {
			return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, fmt.Sprintf("the Prepare's attempt %d does not follow the previous attempt %d from phase %s", r.Attempt, previous.Attempt, previous.Phase))
		}
		if bytes.Equal(r.NextBodyID, make([]byte, 32)) {
			return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "the Prepare names no next body")
		}
		if r.ActivationRound < r.OrderedRound {
			return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "the Prepare's activation round is below its ordered round")
		}
		if r.ActivationRound < r.OrderedRound+prepareActivationFloor {
			return nil, errors.Join(ErrHandoffRecord, ErrPrepareActivationFloor)
		}
		return &evmroot.ControlState{Network: network, Epoch: epoch, PredecessorBodyID: bytes.Clone(r.PredecessorBodyID), Attempt: r.Attempt, Phase: "prepared", OrderedRound: round, RecordBytes: bytes.Clone(data), PreviousDigest: previous.Digest()}, nil
	}
	if !bytes.Equal(r.PredecessorBodyID, previous.PredecessorBodyID) || r.Attempt != previous.Attempt {
		return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "the record is not of the open attempt")
	}
	old, err := decodeOrderedRecord(previous.RecordBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: previous record: %v", ErrHandoffRecord, err)
	}
	phase := ""
	frozenParent := bytes.Clone(previous.FrozenParent)
	switch r.Kind {
	case "freeze":
		if previous.Phase != "prepared" || lapsed || !bytes.Equal(r.NextBodyID, old.NextBodyID) || bytes.Equal(r.FrozenID, make([]byte, 32)) || r.ActivationRound != old.ActivationRound {
			return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, fmt.Sprintf("the Freeze does not match its Prepare (phase %s, lapsed %t)", previous.Phase, lapsed))
		}
		frozenParent, err = authority.VerifyFreeze(r, companion)
		if err != nil {
			return nil, errors.Join(ErrHandoffRecord, err)
		}
		if len(frozenParent) != 32 {
			return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, "the Freeze names no frozen parent")
		}
		// The frozen parent is the one the root bound when it ordered the Prepare, not one the operator or the endorsers chose.
		if !bytes.Equal(frozenParent, previous.FrozenParent) {
			return nil, errors.Join(ErrHandoffRecord, ErrFreezeParentUnbound)
		}
		phase = "endorsed"
	case "commit":
		if len(companion) != 0 || previous.Phase != "endorsed" || len(frozenParent) != 32 || !r.Valid() || !bytes.Equal(r.FrozenID, old.FrozenID) || !bytes.Equal(r.NextBodyID, old.NextBodyID) || r.ActivationRound < old.ActivationRound || bytes.Equal(r.SuccessorTRHash, make([]byte, 32)) {
			return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, fmt.Sprintf("the Commit does not match its Freeze (phase %s)", previous.Phase))
		}
		phase = "committed"
	case "abort":
		if previous.Phase != "prepared" && previous.Phase != "endorsed" ||
			!bytes.Equal(r.NextBodyID, old.NextBodyID) || r.ActivationRound != old.ActivationRound {
			return nil, fmt.Errorf("%w: %s", ErrHandoffRecord, fmt.Sprintf("the Abort does not match its Prepare (phase %s)", previous.Phase))
		}
		if err := authority.VerifyAbort(r, companion); err != nil {
			return nil, errors.Join(ErrHandoffRecord, err)
		}
		phase = "aborted"
	default:
		return nil, fmt.Errorf("%w: a %s record cannot follow phase %s", ErrHandoffRecord, r.Kind, previous.Phase)
	}
	return &evmroot.ControlState{Network: network, Epoch: epoch, PredecessorBodyID: bytes.Clone(r.PredecessorBodyID), Attempt: r.Attempt, Phase: phase, OrderedRound: round, RecordBytes: bytes.Clone(data), PreviousDigest: previous.Digest(), FrozenParent: frozenParent}, nil
}

// CommitActivationRound is the activation round of a Commit ordered at `round` for a handoff whose Prepare asked for `previous`: the
// Prepare's, unless that is nearer than HandoffActivationMarginRounds after the Commit, in which case the margin. ok is false when the
// round is so large that the margin would overflow.
func CommitActivationRound(previous, round uint64) (activation uint64, ok bool) {
	if round > ^uint64(0)-HandoffActivationMarginRounds {
		return 0, false
	}
	return max(previous, round+HandoffActivationMarginRounds), true
}
