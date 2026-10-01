package evmassign

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// Change kinds carried in Candidate.Changes. Only ChangeReplaceShardValidators is defined: the other numbers are reserved
// tag numbers only (no payload layout is fixed) and are rejected as unsupported, so a later definition is additive.
const (
	ChangeReplaceShardValidators uint64 = 1
	ChangeAddPartition           uint64 = 2 // reserved
	ChangeSplitShard             uint64 = 3 // reserved
)

// MaxChanges bounds the aggregator changes of one handoff.
const MaxChanges = 8

// changePayloadVersion is the version byte of a ReplaceShardValidators payload; an unknown version is refused.
const changePayloadVersion uint64 = 1

var (
	// ErrChange reports a malformed, duplicated, oversized or unsupported change.
	ErrChange = errors.New("evmassign: invalid shard change")
	// ErrUnsupportedChange refuses a change kind that is reserved but not implemented (AddPartition, SplitShard, unknown).
	ErrUnsupportedChange = errors.New("evmassign: unsupported shard change kind")
	// ErrSourceRef refuses a non-empty SourceRef: the contract-driven source is reserved and not accepted yet.
	ErrSourceRef = errors.New("evmassign: source reference is reserved and must be empty")
)

// Change is one aggregator configuration change committed with the handoff. The payload is opaque per kind.
type Change struct {
	_       struct{} `cbor:",toarray"`
	Kind    uint64
	Payload []byte
}

// ReplaceShardValidators replaces the validator (node-key) set of one existing aggregator shard. The successor must equal
// the installed configuration in every non-membership setting (ConfigHash), so proof_type and every other parameter are
// unchanged by construction; its epoch is the installed one plus one. Every successor key proves possession.
type ReplaceShardValidators struct {
	_                  struct{} `cbor:",toarray"`
	Version            uint64
	Partition          uint64
	Shard              []byte
	ExpectedOldPDRHash []byte // full hash of the installed configuration being replaced
	Successor          []byte // canonical CBOR of the successor PDR, EpochStart zero
	PoPs               []PoP
}

// EncodeReplaceShardValidators returns the payload of a ChangeReplaceShardValidators change.
func EncodeReplaceShardValidators(partition types.PartitionID, shard types.ShardID, current, succ *types.PartitionDescriptionRecord, pops []PoP) (Change, error) {
	if current == nil || succ == nil {
		return Change{}, ErrChange
	}
	old, err := PDRHash(current)
	if err != nil {
		return Change{}, err
	}
	raw, err := types.Cbor.Marshal(succ)
	if err != nil {
		return Change{}, err
	}
	payload, err := types.Cbor.Marshal(ReplaceShardValidators{Version: changePayloadVersion, Partition: uint64(partition), Shard: bytes.Clone(shard.Bytes()),
		ExpectedOldPDRHash: old[:], Successor: raw, PoPs: pops})
	if err != nil {
		return Change{}, err
	}
	return Change{Kind: ChangeReplaceShardValidators, Payload: payload}, nil
}

// DecodeReplaceShardValidators parses a canonical payload.
func DecodeReplaceShardValidators(payload []byte) (ReplaceShardValidators, *types.PartitionDescriptionRecord, error) {
	var r ReplaceShardValidators
	if len(payload) == 0 || len(payload) > MaxCandidateBytes || types.Cbor.Unmarshal(payload, &r) != nil {
		return r, nil, ErrChange
	}
	again, err := types.Cbor.Marshal(r)
	if err != nil || !bytes.Equal(again, payload) || r.Version != changePayloadVersion || len(r.ExpectedOldPDRHash) != 32 {
		return r, nil, ErrChange
	}
	var succ types.PartitionDescriptionRecord
	if len(r.Successor) == 0 || types.Cbor.Unmarshal(r.Successor, &succ) != nil {
		return r, nil, ErrChange
	}
	if again, err := types.Cbor.Marshal(&succ); err != nil || !bytes.Equal(again, r.Successor) {
		return r, nil, ErrChange
	}
	if succ.PartitionID != types.PartitionID(r.Partition) || !bytes.Equal(succ.ShardID.Bytes(), r.Shard) {
		return r, nil, fmt.Errorf("%w: successor names another shard", ErrChange)
	}
	return r, &succ, nil
}

// DecodedChange is a validated ReplaceShardValidators with its parsed successor.
type DecodedChange struct {
	Replace   ReplaceShardValidators
	Successor *types.PartitionDescriptionRecord
}

// Key identifies the shard the change targets.
func (d DecodedChange) Key() types.PartitionShardID {
	return types.PartitionShardID{PartitionID: d.Successor.PartitionID, ShardID: d.Successor.ShardID.Key()}
}

// ValidateChanges checks everything about the changes that needs no installed configuration: bounded count, supported kinds
// only, canonical payloads, at most one change per shard, the EVM shard and the control partition are not targets, an empty
// SourceRef, a well-formed successor and a possession proof from every successor key. controlPartition is the reserved
// control partition id.
func ValidateChanges(changes []Change, sourceRef []byte, c PoPContext, controlPartition types.PartitionID) ([]DecodedChange, error) {
	if len(sourceRef) != 0 {
		return nil, ErrSourceRef
	}
	if len(changes) > MaxChanges {
		return nil, fmt.Errorf("%w: %d changes", ErrChange, len(changes))
	}
	seen := map[types.PartitionShardID]struct{}{}
	out := make([]DecodedChange, 0, len(changes))
	for i, ch := range changes {
		if ch.Kind != ChangeReplaceShardValidators {
			return nil, fmt.Errorf("%w: change %d has kind %d", ErrUnsupportedChange, i, ch.Kind)
		}
		r, succ, err := DecodeReplaceShardValidators(ch.Payload)
		if err != nil {
			return nil, fmt.Errorf("change %d: %w", i, err)
		}
		if succ.PartitionTypeID == EVMPartitionTypeID || succ.PartitionID == controlPartition {
			return nil, fmt.Errorf("%w: change %d targets the EVM or control partition", ErrChange, i)
		}
		d := DecodedChange{Replace: r, Successor: succ}
		if _, dup := seen[d.Key()]; dup {
			return nil, fmt.Errorf("%w: two changes for one shard", ErrChange)
		}
		seen[d.Key()] = struct{}{}
		if err := ValidateAssignment(succ); err != nil {
			return nil, fmt.Errorf("change %d: %w", i, err)
		}
		if err := VerifyPoPs(c, succ, r.PoPs); err != nil {
			return nil, fmt.Errorf("change %d: %w", i, err)
		}
		out = append(out, d)
	}
	return out, nil
}

// VerifyChangeInstalled checks one change against the authenticated installed configuration of its shard: it replaces exactly
// that configuration (expected hash), and the successor is that configuration with only validators and epoch changed.
func VerifyChangeInstalled(d DecodedChange, installed *types.PartitionDescriptionRecord) error {
	if installed == nil {
		return fmt.Errorf("%w: the target shard has no installed configuration", ErrChange)
	}
	if installed.PartitionTypeID == EVMPartitionTypeID {
		return fmt.Errorf("%w: the EVM shard changes only through the assignment", ErrChange)
	}
	old, err := PDRHash(installed)
	if err != nil {
		return err
	}
	if !bytes.Equal(old[:], d.Replace.ExpectedOldPDRHash) {
		return fmt.Errorf("%w: installed configuration differs from the expected one", ErrContext)
	}
	return ValidateSuccessor(installed, d.Successor)
}
