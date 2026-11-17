package vradmit

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
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
// the evmassign changes of kinds 1 to 3 are derived from them at verification, never carried twice. Derived is that candidate change
// kind (vrschema.DerivedChangeKind: 1 ReplaceShardValidators, 2 AddPartition, 3 UpdatePartition). Expected is the PDRHash of the
// configuration a kind 6 or 8 change replaces (zero for an addition).
type Change struct {
	ID        uint64
	Kind      uint8
	Derived   uint64
	Shard     vrschema.ShardKey
	Expected  vrschema.Word
	Successor *types.PartitionDescriptionRecord
}

// Key is the shard the change installs.
func (c Change) Key() types.PartitionShardID {
	return types.PartitionShardID{PartitionID: c.Successor.PartitionID, ShardID: c.Successor.ShardID.Key()}
}

// AcceptedChanges decodes the Accepted root-side entries (the fold has judged every one of them canonical). The verdicts are the fold's,
// index by index; a list of another length is refused.
func AcceptedChanges(rc []vrschema.RegistryChange, verdicts []uint8) ([]Change, error) {
	if len(verdicts) != len(rc) {
		return nil, fmt.Errorf("%w: %d verdicts for %d changes", ErrInstall, len(verdicts), len(rc))
	}
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
		var expected vrschema.Word
		if k == vrschema.KindAddPartition {
			raw = v[0].([]byte)
		} else {
			raw, expected = v[3].([]byte), v[2].(vrschema.Word)
		}
		var pdr types.PartitionDescriptionRecord
		if err := types.Cbor.Unmarshal(raw, &pdr); err != nil {
			return nil, err
		}
		shard := vrschema.ShardKey{Partition: uint32(pdr.PartitionID), Shard: string(pdr.ShardID.Bytes())}
		if k != vrschema.KindAddPartition {
			if named := (vrschema.ShardKey{Partition: uint32(v[0].(uint64)), Shard: string(v[1].([]byte))}); named != shard {
				return nil, fmt.Errorf("%w: change %d names shard %v and carries the configuration of %v", ErrInstall, c.ID, named, shard)
			}
		}
		out = append(out, Change{ID: c.ID, Kind: k, Derived: vrschema.DerivedChangeKind[k], Shard: shard, Expected: expected, Successor: &pdr})
	}
	return out, nil
}

// CommittedChanges is AcceptedChanges over a committed candidate v6, whose verdicts are the ones its Freeze admitted (VerifyRegistryOutput
// required them to equal FoldVerdicts): the install paths read them from the retained candidate, never re-fold.
func CommittedChanges(c vrschema.CandidateV6) ([]Change, error) {
	verdicts := make([]uint8, len(c.RegistryChanges))
	for i, rc := range c.RegistryChanges {
		if rc.Verdict > uint64(vrschema.VerdictCeiling) {
			return nil, fmt.Errorf("%w: change %d carries verdict %d", ErrInstall, rc.ID, rc.Verdict)
		}
		verdicts[i] = uint8(rc.Verdict)
	}
	return AcceptedChanges(c.RegistryChanges, verdicts)
}

// ErrInstall refuses to install a committed root-side change against the authenticated installed configurations (design section 6):
// the configuration it replaces is not the installed one, the partition it adds exists, or the result is not a configuration of the
// activation round. A committed change was judged against the same installed state by every root at its Freeze, so a refusal here is
// corrupt or missing history and stops the root; it is never a verdict.
var ErrInstall = errors.New("vradmit: committed root-side change cannot be installed")

// Install is what the committed root-side changes of one handoff install at its committed activation round (design sections 6.1 and
// 6.2), checked against the configurations installed when they activate (the shard configurations of the ordering round):
//   - an AddPartition names a partition with no installed shard and not added earlier in the list, which is neither an EVM nor a
//     reserved partition, and its configuration is the unsplit shard (FD-30) at epoch 0;
//   - a kind 6 or 8 change replaces exactly the installed configuration of a non-EVM shard (the expected hash, epoch + 1), never one the
//     same list adds (FD-29: the fold gives it Invalid).
//
// Each change installs its carried configuration with EpochStart = activation, in list order; a shard is touched at most once. Every
// installed configuration passes the proof-support fence (FD-27); available is the local build's support.
//
// The fold judged every committed change against the same installed state at the Freeze, so a refusal here is corrupt or missing
// history and stops the root (ErrInstall); it is never a verdict.
func Install(changes []Change, installed map[types.PartitionShardID]*types.PartitionDescriptionRecord, reserved []types.PartitionID,
	activation uint64, available func(proofType string) bool) ([]*types.PartitionDescriptionRecord, error) {
	if len(changes) == 0 {
		return nil, nil
	}
	if activation == 0 {
		return nil, fmt.Errorf("%w: no activation round", ErrInstall)
	}
	added := map[types.PartitionID]bool{}
	touched := map[types.PartitionShardID]bool{}
	out := make([]*types.PartitionDescriptionRecord, 0, len(changes))
	for _, c := range changes {
		if c.Successor == nil || c.Successor.EpochStart != 0 {
			return nil, fmt.Errorf("%w: change %d is not a successor configuration awaiting its activation round", ErrInstall, c.ID)
		}
		key := c.Key()
		if touched[key] {
			return nil, fmt.Errorf("%w: change %d: a second change of shard %v", ErrInstall, c.ID, c.Shard)
		}
		switch c.Kind {
		case vrschema.KindAddPartition:
			for k := range installed {
				if k.PartitionID == key.PartitionID {
					return nil, fmt.Errorf("%w: AddPartition %d: partition %d is installed", ErrInstall, c.ID, key.PartitionID)
				}
			}
			if added[key.PartitionID] || c.Successor.Epoch != 0 || c.Successor.PartitionTypeID == evmassign.EVMPartitionTypeID || c.Successor.ShardID.Length() != 0 {
				return nil, fmt.Errorf("%w: AddPartition %d is not a new non-EVM unsplit configuration at epoch 0", ErrInstall, c.ID)
			}
			for _, r := range reserved {
				if r == key.PartitionID {
					return nil, fmt.Errorf("%w: AddPartition %d: partition %d is reserved", ErrInstall, c.ID, r)
				}
			}
			added[key.PartitionID] = true
		case vrschema.KindReplaceAggregator, vrschema.KindUpdatePartition:
			cur := installed[key]
			if cur == nil || cur.PartitionTypeID == evmassign.EVMPartitionTypeID {
				return nil, fmt.Errorf("%w: change %d: no installed non-EVM configuration of shard %v", ErrInstall, c.ID, c.Shard)
			}
			h, err := evmassign.PDRHash(cur)
			if err != nil {
				return nil, errors.Join(ErrInstall, err)
			}
			if h != c.Expected || cur.Epoch == ^uint64(0) || c.Successor.Epoch != cur.Epoch+1 {
				return nil, fmt.Errorf("%w: change %d: the installed configuration of shard %v is not the one it replaces", ErrInstall, c.ID, c.Shard)
			}
		default:
			return nil, fmt.Errorf("%w: change %d of kind %d", ErrInstall, c.ID, c.Kind)
		}
		if err := InstallFence(c.Successor, available); err != nil {
			return nil, err
		}
		a, err := evmassign.Activate(c.Successor, activation)
		if err != nil {
			return nil, errors.Join(ErrInstall, err)
		}
		touched[key] = true
		out = append(out, a)
	}
	return out, nil
}
