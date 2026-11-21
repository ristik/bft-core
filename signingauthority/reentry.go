package signingauthority

import (
	"bytes"
	"errors"
	"math"
	"slices"

	"github.com/unicitynetwork/bft-core/activationproof"
	"github.com/unicitynetwork/bft-core/evmassign"
)

// recoveryExclusion records the authenticated primary that removed this authority. It is held only
// until the next activation, which must replace that exact primary on its unacknowledged parent.
type recoveryExclusion struct {
	shardEpoch    uint64
	shardConfHash []byte
	recordID      []byte
	frozenParent  []byte
	assignment    [32]byte
	authorization [32]byte
}

// excludedByPrimary is called after the transition has authenticated its checkpoint and candidate
// against the installed signing scope and found that the successor omits this node.
func excludedByPrimary(step activationproof.Step, enroll Enrollment, pub []byte, shardEpoch uint64, hash []byte) *recoveryExclusion {
	candidate, err := evmassign.DecodeCommittedCandidate(step.Bundle.Candidate)
	if err != nil || candidate.Kind != evmassign.KindPrimary || candidate.Supersedes != nil ||
		candidate.OldShardEpoch != enroll.ShardEpoch || !bytes.Equal(candidate.OldActiveHash, enroll.ShardConfHash) ||
		enroll.ShardEpoch == math.MaxUint64 || shardEpoch != enroll.ShardEpoch+1 {
		return nil
	}
	auth := candidate.Authorization
	if auth == nil || auth.Network != candidate.Network || !bytes.Equal(auth.BaseRootBodyID, candidate.Predecessor) ||
		!slices.ContainsFunc(auth.K, func(id evmassign.Identity) bool {
			return id.EVMNodeID == enroll.NodeID && bytes.Equal(id.EVMKey, pub)
		}) {
		return nil
	}
	digest, err := auth.Digest()
	if err != nil {
		return nil
	}
	assignment, err := candidate.AssignmentID()
	if err != nil {
		return nil
	}
	handoff, _, ok := step.Entry.Handoff()
	frozen := step.Bundle.Snapshot.Control.FrozenParent
	if !ok || len(handoff.RecordID) != 32 || len(frozen) != 32 {
		return nil
	}
	return &recoveryExclusion{shardEpoch: shardEpoch, shardConfHash: bytes.Clone(hash),
		recordID: bytes.Clone(handoff.RecordID), frozenParent: bytes.Clone(frozen), assignment: assignment, authorization: digest}
}

func (r *recoveryExclusion) verify(prev, next *activationproof.Lineage, step activationproof.Step, enroll Enrollment, pub []byte) (*scopeChange, error) {
	// Verify even a non-recovery successor before consuming eligibility. An unauthenticated
	// candidate or snapshot supplied with a valid envelope must not discard a real recovery.
	transition, err := activationproof.ShardTransition(prev, step, enroll.PartitionID, enroll.ShardID, r.shardConfHash)
	if err != nil {
		return nil, errors.Join(ErrLineageUnverified, err)
	}
	candidate, err := evmassign.DecodeCommittedCandidate(step.Bundle.Candidate)
	if err != nil || candidate.Kind != evmassign.KindRecovery || transition.Conf == nil ||
		candidate.OldShardEpoch != r.shardEpoch || !bytes.Equal(candidate.OldActiveHash, r.shardConfHash) ||
		r.shardEpoch == math.MaxUint64 || transition.Conf.Epoch != r.shardEpoch+1 ||
		!bytes.Equal(candidate.ReplacedAssignment, r.assignment[:]) {
		return nil, nil
	}
	if evmassign.VerifyKind(candidate, transition.Conf) != nil {
		return nil, nil
	}
	digest, err := candidate.Authorization.Digest()
	if err != nil || digest != r.authorization {
		return nil, nil
	}
	chain := evmassign.Chain{BaseRootEpoch: *enroll.RootEpoch, BaseShardEpoch: enroll.ShardEpoch,
		BaseActiveHash: enroll.ShardConfHash, Steps: []evmassign.ChainStep{{RecordID: r.recordID}}}
	if evmassign.VerifyChain(candidate.Supersedes, chain) != nil ||
		!bytes.Equal(step.Bundle.Snapshot.Control.FrozenParent, r.frozenParent) {
		return nil, nil
	}
	for _, shard := range step.Bundle.Snapshot.ShardInfo {
		if shard.Partition == enroll.PartitionID && shard.Shard.Equal(enroll.ShardID) &&
			shard.IR.Epoch == enroll.ShardEpoch && shard.IRTR.Epoch == r.shardEpoch &&
			bytes.Equal(shard.IR.BlockHash, r.frozenParent) {
			scope, err := scopeForTransition(next, step, enroll, pub, transition)
			if err != nil || scope.retire {
				return nil, err
			}
			return scope, nil
		}
	}
	return nil, nil
}
