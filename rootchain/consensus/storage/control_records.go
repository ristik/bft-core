package storage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrHandoffRecord = errors.New("invalid root handoff record")
	ErrAbortAfterH   = errors.New("root handoff Abort follows committed H")
	ErrHandoffSuffix = errors.New("nonempty old-epoch handoff suffix")
	ErrHandoffFrozen = errors.New("EVM certification frozen by root handoff")
	// ErrAssignmentAckPending refuses another handoff while the installed EVM
	// assignment has no certified acknowledgement, unless it supersedes that
	// assignment on the same frozen parent.
	// ErrNothingToSupersede is the acknowledged case of ErrSupersessionInvalid: the installed assignment already
	// has its certified acknowledgement, so there is no pending assignment to replace.
	ErrNothingToSupersede   = errors.New("EVM assignment already acknowledged: nothing to supersede")
	ErrSupersessionInvalid  = errors.New("EVM assignment supersession does not extend the committed unacknowledged chain")
	ErrAssignmentAckPending = errors.New("EVM assignment acknowledgement pending: only a supersession may follow")
)

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
// PrepareFreezeLapseRounds is how long a Prepare freezes the EVM without a Freeze. An honest handoff orders Freeze in the round after
// Prepare (the plan is endorsed before Prepare is ordered), and the Prepare already reserves 8 rounds before activation, so a Freeze
// that needs more than three times that has lost its leaders for the better part of a minute (rounds are ~1 s, partitions 1-3 s) and
// is better restarted. After the lapse the EVM certifies again and the plan is dead: a fresh Prepare, with the next attempt number
// (the lapse is treated like an abort for numbering), is needed.
//
// PrepareCooldownRounds is the pause before that fresh Prepare may be ordered. It bounds what a faulty leader can do by repeating the
// attack: the EVM is frozen at most PrepareFreezeLapseRounds in every PrepareFreezeLapseRounds+PrepareCooldownRounds (50%), where
// without it the freeze could be renewed the moment it lapsed. That is a residual, deliberately kept simple: a faulty leader that
// leads one round in n can still halve EVM availability; removing it needs a signed Prepare, which is a protocol change.
const (
	PrepareFreezeLapseRounds = 24
	PrepareCooldownRounds    = 24
)

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
		return nil, ErrHandoffRecord
	}
	if previous.Phase == "committed" && r.Kind == "abort" {
		return nil, errors.Join(ErrHandoffRecord, ErrAbortAfterH)
	}
	if authority == nil || !bytes.Equal(r.PredecessorBodyID, authority.Predecessor()) || previous.Phase == "committed" {
		return nil, ErrHandoffRecord
	}
	// A Prepare whose freeze lapsed is dead (the EVM certifies again); a fresh Prepare may follow it, with the next attempt number,
	// once the cooldown has passed. A Freeze for the lapsed attempt is refused below.
	lapsed := PrepareLapsed(previous, round)
	if lapsed && r.Kind == "prepare" && !PrepareMayFollowLapse(previous, round) {
		return nil, ErrHandoffRecord
	}
	if previous.Phase == "idle" || previous.Phase == "aborted" || (lapsed && r.Kind == "prepare") {
		if r.Kind != "prepare" || len(companion) != 0 ||
			(previous.Phase == "idle" && r.Attempt != 0) ||
			(previous.Phase != "idle" && (previous.Attempt == ^uint64(0) || r.Attempt != previous.Attempt+1)) {
			return nil, ErrHandoffRecord
		}
		if bytes.Equal(r.NextBodyID, make([]byte, 32)) || r.ActivationRound < r.OrderedRound {
			return nil, ErrHandoffRecord
		}
		return &evmroot.ControlState{Network: network, Epoch: epoch, PredecessorBodyID: bytes.Clone(r.PredecessorBodyID), Attempt: r.Attempt, Phase: "prepared", OrderedRound: round, RecordBytes: bytes.Clone(data), PreviousDigest: previous.Digest()}, nil
	}
	if !bytes.Equal(r.PredecessorBodyID, previous.PredecessorBodyID) || r.Attempt != previous.Attempt {
		return nil, ErrHandoffRecord
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
			return nil, ErrHandoffRecord
		}
		frozenParent, err = authority.VerifyFreeze(r, companion)
		if err != nil {
			return nil, errors.Join(ErrHandoffRecord, err)
		}
		if len(frozenParent) != 32 {
			return nil, ErrHandoffRecord
		}
		phase = "endorsed"
	case "commit":
		if len(companion) != 0 || previous.Phase != "endorsed" || len(frozenParent) != 32 || !r.Valid() || !bytes.Equal(r.FrozenID, old.FrozenID) || !bytes.Equal(r.NextBodyID, old.NextBodyID) || r.ActivationRound < old.ActivationRound || bytes.Equal(r.SuccessorTRHash, make([]byte, 32)) {
			return nil, ErrHandoffRecord
		}
		phase = "committed"
	case "abort":
		if previous.Phase != "prepared" && previous.Phase != "endorsed" ||
			!bytes.Equal(r.NextBodyID, old.NextBodyID) || r.ActivationRound != old.ActivationRound {
			return nil, ErrHandoffRecord
		}
		if authority.VerifyAbort(r, companion) != nil {
			return nil, ErrHandoffRecord
		}
		phase = "aborted"
	default:
		return nil, ErrHandoffRecord
	}
	return &evmroot.ControlState{Network: network, Epoch: epoch, PredecessorBodyID: bytes.Clone(r.PredecessorBodyID), Attempt: r.Attempt, Phase: phase, OrderedRound: round, RecordBytes: bytes.Clone(data), PreviousDigest: previous.Digest(), FrozenParent: frozenParent}, nil
}
