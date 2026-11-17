package vradmit

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// FoldContext is the committed root state the verdicts read; it changes only at a committed handoff (design section 3.5.4), so the
// fold gives the same verdicts at intent, at Freeze and on replay.
type FoldContext struct {
	Network            uint64
	SuccessorRootEpoch uint64
	Installed          map[types.PartitionShardID]*types.PartitionDescriptionRecord
	EVMPartition       types.PartitionID
	ControlPartition   types.PartitionID
	Schedule           []vrschema.Activation
}

// Input is the vrschema FoldInput of the committed state: the installed configurations keyed by (partition, ShardID.Bytes()), the
// reserved partition ids (0xFFFFFFFF, 0xFFFFFFFE, the EVM and the control partition) and the ceiling of 64.
func (f FoldContext) Input() vrschema.FoldInput {
	in := vrschema.FoldInput{Network: f.Network, SuccessorRootEpoch: f.SuccessorRootEpoch, Installed: map[vrschema.ShardKey]*types.PartitionDescriptionRecord{},
		ReservedPartitions: []uint32{0xFFFFFFFF, 0xFFFFFFFE, uint32(f.EVMPartition), uint32(f.ControlPartition)},
		PartitionCeiling:   vrschema.PartitionCeiling, Schedule: append([]vrschema.Activation(nil), f.Schedule...)}
	for _, pdr := range f.Installed {
		if pdr == nil {
			continue
		}
		in.Installed[vrschema.ShardKey{Partition: uint32(pdr.PartitionID), Shard: string(pdr.ShardID.Bytes())}] = pdr
	}
	return in
}

// ErrProofSupportMissing is the installation fence of FD-27: an Accepted, protocol-valid proof configuration this root's build cannot
// verify. The root refuses to install it and needs a build with the support; it never rejects the change.
var ErrProofSupportMissing = errors.New("ProofSupportMissing")

// InstallFence is the local fence before a root installs an Accepted configuration: local build capability never decides a verdict
// (FD-27), but a root that cannot verify the proof type stops here. available is the local build's support (zkverifier).
func InstallFence(pdr *types.PartitionDescriptionRecord, available func(proofType string) bool) error {
	if pdr == nil {
		return nil
	}
	pt := pdr.PartitionParams[vrschema.ParamProofType]
	if pt == "" || pt == "none" {
		return nil
	}
	if vrschema.ProofConfigValid(pdr.PartitionParams) != nil {
		return fmt.Errorf("%w: an invalid proof configuration was never Accepted", ErrProofSupportMissing)
	}
	if !available(pt) {
		return fmt.Errorf("%w: proof type %q", ErrProofSupportMissing, pt)
	}
	return nil
}

// Change is one Accepted root-side change of a verified candidate, decoded for the install paths of kinds 6, 7 and 8 (VT-06a/d/e):
// the evmassign changes of kinds 1 to 3 are derived from them at verification, never carried twice.
type Change struct {
	ID        uint64
	Kind      uint8
	Shard     vrschema.ShardKey
	Successor *types.PartitionDescriptionRecord
}

// AcceptedChanges decodes the Accepted root-side entries (the fold has judged every one of them canonical).
func AcceptedChanges(rc []vrschema.RegistryChange, verdicts []uint8) ([]Change, error) {
	var out []Change
	for i, c := range rc {
		k := uint8(c.Kind)
		if verdicts[i] != vrschema.VerdictAccepted || (k != vrschema.KindReplaceAggregator && k != vrschema.KindAddPartition && k != vrschema.KindUpdatePartition) {
			continue
		}
		v, err := vrschema.DecodeChangePayload(k, c.Payload)
		if err != nil {
			return nil, err
		}
		var raw []byte
		if k == vrschema.KindAddPartition {
			raw = v[0].([]byte)
		} else {
			raw = v[3].([]byte)
		}
		var pdr types.PartitionDescriptionRecord
		if err := types.Cbor.Unmarshal(raw, &pdr); err != nil {
			return nil, err
		}
		out = append(out, Change{ID: c.ID, Kind: k, Shard: vrschema.ShardKey{Partition: uint32(pdr.PartitionID), Shard: string(pdr.ShardID.Bytes())}, Successor: &pdr})
	}
	return out, nil
}
