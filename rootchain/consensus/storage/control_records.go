package storage

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrHandoffRecord = errors.New("invalid root handoff record")
	ErrHandoffSuffix = errors.New("nonempty old-epoch handoff suffix")
)

type handoffAuthority interface {
	Predecessor() []byte
	VerifyFreeze(evmroot.OrderedHandoffRecord, []byte) ([]byte, error)
	VerifyAbort(evmroot.OrderedHandoffRecord, []byte) error
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
	if authority == nil || !bytes.Equal(r.PredecessorBodyID, authority.Predecessor()) || previous.Phase == "committed" {
		return nil, ErrHandoffRecord
	}
	if previous.Phase == "idle" || previous.Phase == "aborted" {
		if r.Kind != "prepare" || len(companion) != 0 ||
			(previous.Phase == "idle" && r.Attempt != 0) ||
			(previous.Phase == "aborted" && (previous.Attempt == ^uint64(0) || r.Attempt != previous.Attempt+1)) {
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
		if previous.Phase != "prepared" || !bytes.Equal(r.NextBodyID, old.NextBodyID) || bytes.Equal(r.FrozenID, make([]byte, 32)) || r.ActivationRound != old.ActivationRound {
			return nil, ErrHandoffRecord
		}
		frozenParent, err = authority.VerifyFreeze(r, companion)
		if err != nil || len(frozenParent) != 32 {
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
