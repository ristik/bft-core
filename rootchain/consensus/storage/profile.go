package storage

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	ProfileLegacy  uint64 = 1
	ProfileHandoff uint64 = 2
)

var ErrNetworkProfile = errors.New("unsupported or mismatched root network profile")
var ErrControlCheckpoint = errors.New("invalid authenticated control checkpoint")

func profileVersion(v []uint64) (uint64, error) {
	if len(v) > 1 {
		return 0, fmt.Errorf("%w: multiple profile versions", ErrNetworkProfile)
	}
	if len(v) == 0 || v[0] == 0 {
		return ProfileLegacy, nil
	}
	if v[0] != ProfileLegacy && v[0] != ProfileHandoff {
		return 0, fmt.Errorf("%w: version %d", ErrNetworkProfile, v[0])
	}
	return v[0], nil
}

func initialControl(network types.NetworkID) *evmroot.ControlState {
	return &evmroot.ControlState{Network: uint64(network), Epoch: 1, PredecessorBodyID: make([]byte, 32), Phase: "idle"}
}

func checkProfile(v uint64, state ShardStates) error {
	if (v == ProfileHandoff) != (state.Control != nil) {
		return ErrNetworkProfile
	}
	if state.Control != nil && state.Control.Network == 0 {
		return ErrNetworkProfile
	}
	if state.Control != nil {
		if err := validateControl(state.Control); err != nil {
			return err
		}
	}
	return nil
}

func validateControl(c *evmroot.ControlState) error {
	if c == nil || c.Network == 0 || c.Epoch == 0 || len(c.PredecessorBodyID) != 32 {
		return ErrControlCheckpoint
	}
	if c.Phase == "idle" {
		if c.Attempt != 0 || c.OrderedRound != 0 || len(c.RecordBytes) != 0 || len(c.PreviousDigest) != 0 || len(c.FrozenParent) != 0 {
			return ErrControlCheckpoint
		}
		return nil
	}
	if len(c.PreviousDigest) != 32 {
		return ErrControlCheckpoint
	}
	r, err := decodeOrderedRecord(c.RecordBytes)
	if err != nil || r.Network != c.Network || r.Epoch != c.Epoch || r.Attempt != c.Attempt || r.OrderedRound != c.OrderedRound || !bytes.Equal(r.PredecessorBodyID, c.PredecessorBodyID) {
		return ErrControlCheckpoint
	}
	switch c.Phase {
	case "prepared":
		if r.Kind != "prepare" || len(c.FrozenParent) != 0 {
			return ErrControlCheckpoint
		}
	case "frozen", "endorsed":
		if r.Kind != "freeze" || len(c.FrozenParent) != 32 {
			return ErrControlCheckpoint
		}
	case "committed":
		if r.Kind != "commit" || !r.Valid() || len(c.FrozenParent) != 32 {
			return ErrControlCheckpoint
		}
	case "aborted":
		if r.Kind != "abort" || (len(c.FrozenParent) != 0 && len(c.FrozenParent) != 32) {
			return ErrControlCheckpoint
		}
	default:
		return ErrControlCheckpoint
	}
	return nil
}

func checkStoredRoot(block *ExecutedBlock, profile uint64) error {
	if block == nil || block.BlockData == nil || (profile == ProfileHandoff && block.BlockData.GetVersion() != 2) || (profile == ProfileLegacy && block.BlockData.GetVersion() != 1) {
		return ErrNetworkProfile
	}
	if err := checkProfile(profile, block.ShardState); err != nil {
		return err
	}
	if profile == ProfileHandoff && block.BlockData.Epoch != block.ShardState.Control.Epoch &&
		!(isEpochAnchorRoot(block) && block.BlockData.Epoch == block.ShardState.Control.Epoch+1 &&
			bytes.Equal(block.BlockData.Anchor.StateRoot, block.RootHash)) {
		return ErrNetworkProfile
	}
	if profile != ProfileHandoff {
		return nil
	}
	for _, shard := range block.ShardState.States {
		feeHash, err := shard.feeHash(crypto.SHA256)
		if err != nil || !bytes.Equal(feeHash, shard.TR.FeeHash) {
			return ErrNetworkProfile
		}
		statHash, err := shard.statHash(crypto.SHA256)
		if err != nil || !bytes.Equal(statHash, shard.TR.StatHash) {
			return ErrNetworkProfile
		}
	}
	ut, _, err := block.ShardState.UnicityTree(crypto.SHA256)
	if err != nil || !bytes.Equal(ut.RootHash(), block.RootHash) {
		return ErrNetworkProfile
	}
	if block.CommitQc != nil && block.CommitQc.LedgerCommitInfo != nil && !bytes.Equal(block.RootHash, block.CommitQc.LedgerCommitInfo.Hash) {
		return ErrNetworkProfile
	}
	return nil
}

func checkStoredSuffix(parent, child *ExecutedBlock) error {
	if isEpochAnchorRoot(parent) {
		return nil
	}
	control := parent.ShardState.Control
	if control == nil || control.Phase != "committed" {
		return nil
	}
	if child.BlockData.Payload == nil || !child.BlockData.Payload.IsEmpty() || len(child.ShardState.Changed) != 0 || child.ShardState.Control == nil || !bytes.Equal(child.ShardState.Control.Bytes(), control.Bytes()) || !bytes.Equal(child.RootHash, parent.RootHash) || len(child.ShardState.States) != len(parent.ShardState.States) {
		return ErrHandoffSuffix
	}
	for key, previous := range parent.ShardState.States {
		current := child.ShardState.States[key]
		if current == nil {
			return ErrHandoffSuffix
		}
		before, err := previous.MarshalCBOR()
		if err != nil {
			return err
		}
		after, err := current.MarshalCBOR()
		if err != nil || !bytes.Equal(before, after) {
			return ErrHandoffSuffix
		}
	}
	return nil
}
