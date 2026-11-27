package signingauthority

import (
	"bytes"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/activationproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

// verifyPendingJoinSuccessor derives a new first-enrollment target from the
// verified activation. A pending authority holds no configuration hash, so
// ShardTransition authenticates the predecessor hash from the checkpoint.
func verifyPendingJoinSuccessor(prev, next *activationproof.Lineage, step activationproof.Step, enroll Enrollment) (*scopeChange, error) {
	pre := checkpointConfHash(step, enroll.PartitionID, enroll.ShardID)
	transition, err := activationproof.ShardTransition(prev, step, enroll.PartitionID, enroll.ShardID, pre)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	trust, err := next.Trust(step.Epoch)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	return &scopeChange{trust: trust, conf: transition.Conf}, nil
}

// pendingJoinEpochLocked checks the authenticated configuration before publishing the new scope.
func (a *Authority) pendingJoinEpochLocked(conf *types.PartitionDescriptionRecord, pub []byte) (uint64, error) {
	enroll := a.enroll
	if conf == nil {
		return enroll.ShardEpoch, nil
	}
	if err := a.checkJoinChainIDLocked(conf); err != nil {
		return 0, err
	}
	for _, member := range conf.Validators {
		if member.NodeID == enroll.NodeID && bytes.Equal(member.SigKey, pub) {
			return 0, fmt.Errorf("%w: shard epoch %d names this authority; complete enrollment for that configuration", ErrContextMismatch, conf.Epoch)
		}
	}
	if conf.Epoch == math.MaxUint64 {
		return 0, fmt.Errorf("%w: cannot move pending join scope from %d to the successor of %d", ErrContextMismatch, enroll.ShardEpoch, conf.Epoch)
	}
	// A host provisioned at genesis can be catching up to an initial target it already knows.
	return max(enroll.ShardEpoch, conf.Epoch+1), nil
}

// checkJoinChainIDLocked checks the verified pin first so a contradiction latches the fault even
// when the B1 profile also disagrees. The B1 check applies before a P85 identity is pinned.
func (a *Authority) checkJoinChainIDLocked(conf *types.PartitionDescriptionRecord) error {
	if a.joinChainID == 0 && a.posB1Chain == 0 && a.pos == nil {
		return nil
	}
	chain, ok := confChainID(conf)
	if err := a.checkPosChainLocked(chain, ok); err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: shard configuration has no valid execution chain ID", ErrContextMismatch)
	}
	for _, profileChain := range [...]uint64{a.joinChainID, a.posB1Chain} {
		if profileChain != 0 && chain != profileChain {
			return fmt.Errorf("%w: shard configuration execution chain ID %d differs from B1 profile %d", ErrContextMismatch, chain, profileChain)
		}
	}
	return nil
}
