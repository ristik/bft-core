package signingauthority

import (
	"bytes"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/activationproof"
)

// verifyPendingJoinSuccessor derives a new first-enrollment target from the
// verified activation. A pending authority holds no configuration hash, so
// ShardTransition authenticates the predecessor hash from the checkpoint.
func verifyPendingJoinSuccessor(prev, next *activationproof.Lineage, step activationproof.Step, enroll Enrollment, pub []byte) (*scopeChange, error) {
	pre := checkpointConfHash(step, enroll.PartitionID, enroll.ShardID)
	transition, err := activationproof.ShardTransition(prev, step, enroll.PartitionID, enroll.ShardID, pre)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	shardEpoch := enroll.ShardEpoch
	if conf := transition.Conf; conf != nil {
		for _, member := range conf.Validators {
			if member.NodeID == enroll.NodeID && bytes.Equal(member.SigKey, pub) {
				return nil, fmt.Errorf("%w: shard epoch %d names this authority; complete enrollment for that configuration", ErrContextMismatch, conf.Epoch)
			}
		}
		if conf.Epoch == math.MaxUint64 {
			return nil, fmt.Errorf("%w: cannot move pending join scope from %d to the successor of %d", ErrContextMismatch, shardEpoch, conf.Epoch)
		}
		// A host provisioned at genesis can be catching up to an initial target it already knows.
		shardEpoch = max(shardEpoch, conf.Epoch+1)
	}
	trust, err := next.Trust(step.Epoch)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	return &scopeChange{shardEpoch: shardEpoch, trust: trust}, nil
}
