package storage

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Live partition configuration from the validator registry (VT-06d AddPartition and VT-06e UpdatePartition, ristik/bft-core#1162 and
// #1163; design sections 3.5, 5.1 and 6). A committed VR handoff installs, at its activation round and together with the EVM assignment,
// the configurations its Accepted root-side changes name: the candidate change kinds derived from VR kinds 6 (ReplaceShardValidators), 7
// (AddPartition) and 8 (UpdatePartition). They are read from the retained candidate v6 only, with the verdicts its Freeze admitted, so
// every root, a replay and a recovery derive the same configurations from the same committed bytes.

// committedCandidate is the committed candidate of a handoff as the install paths read it. On a P85 chain it is the retained (or
// delivered) evmassign preimage itself. On a VR chain the successor body binds the candidate v6 (schema section 9: its digest is SHA-256 of
// the v6 encoding), so the view is its v5 encoding (vradmit.V5Of), which the EVM install, lifecycle and provenance paths decode, the
// digest is that of the v6 bytes, and registry holds its Accepted root-side changes.
type committedCandidate struct {
	view     []byte
	digest   [32]byte
	registry []vradmit.Change
	vr       bool
}

// resolveCommittedCandidate reads a committed candidate of either generation: a canonical candidate v6 is a VR handoff's, anything else
// is the evmassign preimage, decoded by its readers as before.
func resolveCommittedCandidate(preimage []byte) (committedCandidate, error) {
	c6, err := vrschema.DecodeCandidateV6(preimage)
	if err != nil {
		return committedCandidate{view: preimage, digest: sha256.Sum256(preimage)}, nil
	}
	view, err := vradmit.V5Of(c6).Encode()
	if err != nil {
		return committedCandidate{}, errors.Join(ErrAssignmentHistory, err)
	}
	registry, err := vradmit.CommittedChanges(c6)
	if err != nil {
		return committedCandidate{}, errors.Join(ErrAssignmentHistory, err)
	}
	return committedCandidate{view: view, digest: sha256.Sum256(preimage), registry: registry, vr: true}, nil
}

// ResolveCommittedCandidate is the one rule for a committed candidate preimage of either generation (HandoffCommittedPreimage): view is
// the evmassign encoding its readers decode (the v5 view of a candidate v6, else the preimage itself) and digest the SHA-256 the
// successor body's change-record hash binds (of the v6 bytes on a VR handoff).
func ResolveCommittedCandidate(preimage []byte) (view []byte, digest [32]byte, err error) {
	cc, err := resolveCommittedCandidate(preimage)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return cc.view, cc.digest, nil
}

// decodeCommittedCandidate is the evmassign candidate a committed preimage of either generation describes (its v5 view on a VR chain).
func decodeCommittedCandidate(preimage []byte) (evmassign.Candidate, error) {
	cc, err := resolveCommittedCandidate(preimage)
	if err != nil {
		return evmassign.Candidate{}, err
	}
	return evmassign.DecodeCandidate(cc.view)
}

// vrCandidateSource retains the canonical candidate v6 of an admitted Freeze v5 by its successor body id (BoltDB, the frontier store,
// and the block store, which is its own executor's candidate source).
type vrCandidateSource interface {
	HandoffVRCandidate(bodyID []byte) ([]byte, error)
}

var _ vrCandidateSource = (*BlockStore)(nil)

// retainedCommittedPreimage is the committed candidate retained for a successor body: the candidate v6 when a Freeze v5 retained one (the
// v5 view retained beside it must be exactly its view), else the evmassign preimage, else nil (a root-only handoff).
func retainedCommittedPreimage(src any, bodyID []byte) ([]byte, error) {
	if a, ok := src.(vrCandidateSource); ok {
		v6, err := a.HandoffVRCandidate(bodyID)
		if err != nil {
			return nil, errors.Join(ErrAssignmentHistory, err)
		}
		if len(v6) != 0 {
			cc, err := resolveCommittedCandidate(v6)
			if err != nil || !cc.vr {
				return nil, fmt.Errorf("%w: the retained candidate v6 does not decode", ErrAssignmentHistory)
			}
			if c, ok := src.(candidateSource); ok {
				v5, err := c.HandoffCandidate(bodyID)
				if err != nil {
					return nil, errors.Join(ErrAssignmentHistory, err)
				}
				if len(v5) != 0 && !bytes.Equal(v5, cc.view) {
					return nil, fmt.Errorf("%w: the retained v5 view is not the view of the retained candidate v6", ErrAssignmentHistory)
				}
			}
			return v6, nil
		}
	}
	if c, ok := src.(candidateSource); ok {
		return c.HandoffCandidate(bodyID)
	}
	return nil, nil
}

// vrReservedPartitions are the partitions an AddPartition never installs (the fold's reserved list, design section 3.5.4): the root
// control and leader partitions and the designated EVM partition.
func vrReservedPartitions(evm types.PartitionID) []types.PartitionID {
	return []types.PartitionID{rctypes.ControlPartition, rctypes.LeaderPartition, evmroot.D4ControlPartition, evm}
}

// vrProofSupport is the local build's proof verification support, the fence before installing an Accepted configuration (FD-27).
func vrProofSupport(proofType string) bool {
	return zkverifier.IsProofTypeAvailable(zkverifier.ProofType(proofType))
}

// installRegistryChanges is the state-dependent half of a committed VR handoff's root-side changes (vradmit.Install): against the
// configurations installed at the ordering round and the shard states of the old checkpoint, each kind 6 or 8 change targets a shard
// whose last configuration is acknowledged (the acknowledgement gate held at the Freeze and is monotone), and each AddPartition a new
// partition. It returns the configurations to install at the activation round.
func installRegistryChanges(cc committedCandidate, c evmassign.Candidate, record evmroot.OrderedHandoffRecord, evm types.PartitionID,
	states map[types.PartitionShardID]*ShardInfo, configs map[types.PartitionShardID]*types.PartitionDescriptionRecord) ([]*types.PartitionDescriptionRecord, error) {
	if len(cc.registry) == 0 {
		return nil, nil
	}
	if c.Supersedes != nil {
		return nil, fmt.Errorf("%w: %w: a supersession carries no root-side changes", ErrAssignmentHistory, evmassign.ErrChange)
	}
	for _, ch := range cc.registry {
		if ch.Kind == vrschema.KindAddPartition {
			continue
		}
		if si := states[ch.Key()]; si != nil && si.TR.Epoch != si.IR.Epoch {
			return nil, fmt.Errorf("%w: shard %s has an unacknowledged configuration", ErrAssignmentAckPending, ch.Key())
		}
	}
	out, err := vradmit.Install(cc.registry, configs, vrReservedPartitions(evm), record.ActivationRound, vrProofSupport)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	return out, nil
}

// vrDerivedShards names the existing shards whose configuration a committed VR handoff replaces (kinds 6 and 8): their technical
// record advances at the activation boundary, as an aggregator replacement's does. A partition the handoff adds has no shard state yet;
// the first block of the epoch creates it from the installed configuration.
func vrDerivedShards(cc committedCandidate, out map[types.PartitionShardID]struct{}) {
	for _, ch := range cc.registry {
		if ch.Kind != vrschema.KindAddPartition {
			out[ch.Key()] = struct{}{}
		}
	}
}

// registryChangeOf is the Accepted root-side change of a committed preimage that touches the given shard: a kind 6 or 8 change of the
// shard, or an AddPartition of its partition. ok is false when there is none (always on a P85 preimage).
func registryChangeOf(preimage []byte, partition types.PartitionID, shard types.ShardID) (vradmit.Change, bool, error) {
	cc, err := resolveCommittedCandidate(preimage)
	if err != nil {
		return vradmit.Change{}, false, err
	}
	key := types.PartitionShardID{PartitionID: partition, ShardID: shard.Key()}
	for _, ch := range cc.registry {
		if ch.Key() == key || (ch.Kind == vrschema.KindAddPartition && ch.Successor.PartitionID == partition) {
			return ch, true, nil
		}
	}
	return vradmit.Change{}, false, nil
}

// RegistryActivationFromVerifiedV3 is the request activation of a non-EVM shard whose configuration a VR handoff's Accepted kind 6 or 8
// change replaces (design section 6): the committed candidate v6 is authenticated exactly as for the EVM assignment
// (ActivationFromVerifiedV3: record, body, change-record hash, the root committee and coupling), the change must replace exactly the
// configuration previous authorises (expected hash, epoch + 1), and the successor is in force from the committed activation round under
// the activation's root identity, with unit weights. H commits no successor technical record for it: the record is derived from the
// verified parent (derivedTR), as at the boundary. ok is false when the candidate does not change this shard (a continuation applies);
// an AddPartition of the shard's own partition is an error (the partition exists).
func RegistryActivationFromVerifiedV3(previous *RequestActivation, entry VerifiedActivation, record evmroot.OrderedHandoffRecord, preimage []byte,
	hashAlg crypto.Hash, version uint64) (*RequestActivation, bool, error) {
	if previous == nil || previous.pdr == nil || entry == nil || version == 0 {
		return nil, false, fmt.Errorf("%w: incomplete activation", ErrAssignmentHistory)
	}
	ch, ok, err := registryChangeOf(preimage, previous.pdr.PartitionID, previous.pdr.ShardID)
	if err != nil || !ok {
		return nil, false, err
	}
	if _, err := ActivationFromVerifiedV3(entry, record, preimage, hashAlg, version); err != nil {
		return nil, false, err
	}
	if ch.Kind == vrschema.KindAddPartition {
		return nil, false, fmt.Errorf("%w: epoch %d adds partition %d, which this history already holds", ErrAssignmentHistory, entry.Epoch(), ch.Successor.PartitionID)
	}
	h, err := evmassign.PDRHash(previous.pdr)
	if err != nil {
		return nil, false, errors.Join(ErrAssignmentHistory, err)
	}
	if h != ch.Expected || previous.pdr.Epoch == ^uint64(0) || ch.Successor.Epoch != previous.pdr.Epoch+1 || record.ActivationRound <= previous.start {
		return nil, false, fmt.Errorf("%w: epoch %d: VR change %d does not replace the configuration in force", ErrAssignmentHistory, entry.Epoch(), ch.ID)
	}
	activated, err := evmassign.Activate(ch.Successor, record.ActivationRound)
	if err != nil {
		return nil, false, errors.Join(ErrAssignmentHistory, err)
	}
	body := entry.BodyID()
	act, err := newRequestActivation(activated, hashAlg, quorumweight.PolicyUnit, nil, entry.Epoch(), body[:], record.ActivationRound, nil, version)
	if err != nil {
		return nil, false, err
	}
	act.derivedTR = true
	return act, true, nil
}

// NewPartitionRequestAnchor is the trusted anchor of a partition a VR handoff's Accepted AddPartition added: the committed candidate v6 is
// authenticated as for the EVM assignment, and pdr (the configuration the anchor source holds) must be exactly the committed addition
// activated at the activation round. The anchor is in force from that handoff's root identity; a partition has no history before it.
func NewPartitionRequestAnchor(pdr *types.PartitionDescriptionRecord, entry VerifiedActivation, record evmroot.OrderedHandoffRecord, preimage []byte,
	hashAlg crypto.Hash, version uint64) (*RequestActivation, error) {
	if pdr == nil || entry == nil {
		return nil, fmt.Errorf("%w: incomplete anchor", ErrAssignmentHistory)
	}
	ch, ok, err := registryChangeOf(preimage, pdr.PartitionID, pdr.ShardID)
	if err != nil {
		return nil, err
	}
	if !ok || ch.Kind != vrschema.KindAddPartition {
		return nil, fmt.Errorf("%w: epoch %d does not add partition %d", ErrAssignmentHistory, entry.Epoch(), pdr.PartitionID)
	}
	if _, err := ActivationFromVerifiedV3(entry, record, preimage, hashAlg, version); err != nil {
		return nil, err
	}
	activated, err := evmassign.Activate(ch.Successor, record.ActivationRound)
	if err != nil {
		return nil, errors.Join(ErrAssignmentHistory, err)
	}
	want, err1 := activated.Hash(hashAlg)
	got, err2 := pdr.Hash(hashAlg)
	if err := errors.Join(err1, err2); err != nil || !bytes.Equal(want, got) {
		return nil, errors.Join(fmt.Errorf("%w: the anchor is not the configuration epoch %d added", ErrAssignmentHistory, entry.Epoch()), err)
	}
	body := entry.BodyID()
	return newRequestActivation(activated, hashAlg, quorumweight.PolicyUnit, nil, entry.Epoch(), body[:], 0, nil, version)
}
