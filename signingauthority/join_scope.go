package signingauthority

import (
	"bytes"
	"fmt"
	"math"

	"github.com/unicitynetwork/bft-core/activationproof"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// verifyPendingJoinSuccessor derives a new first-enrollment target from the
// verified activation. A pending authority holds no configuration hash, so
// ShardTransition authenticates the predecessor hash from the checkpoint.
func verifyPendingJoinSuccessor(prev, next *activationproof.Lineage, step activationproof.Step, enroll Enrollment, pub []byte, chainID uint64, pos *PosPolicy) (*scopeChange, error) {
	pre := checkpointConfHash(step, enroll.PartitionID, enroll.ShardID)
	transition, err := activationproof.ShardTransition(prev, step, enroll.PartitionID, enroll.ShardID, pre)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrLineageUnverified, err)
	}
	shardEpoch := enroll.ShardEpoch
	if conf := transition.Conf; conf != nil {
		if err := checkJoinChainID(conf, chainID, pos); err != nil {
			return nil, err
		}
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

// checkJoinChainID compares the assignment with both configured sources of the
// execution chain ID. The B1 check also applies before the P85 identity is pinned.
func checkJoinChainID(conf *types.PartitionDescriptionRecord, profileChain uint64, pos *PosPolicy) error {
	if profileChain == 0 && pos == nil {
		return nil
	}
	chain, ok := zkverifier.ParseChainIDFromParams(conf.PartitionParams)
	if !ok || chain == 0 {
		return fmt.Errorf("%w: shard configuration has no valid execution chain ID", ErrContextMismatch)
	}
	if profileChain != 0 && chain != profileChain {
		return fmt.Errorf("%w: shard configuration execution chain ID %d differs from B1 profile %d", ErrContextMismatch, chain, profileChain)
	}
	if pos != nil && vrschema.U64(chain) != pos.ChainID {
		return fmt.Errorf("%w: shard configuration execution chain ID %d differs from P85 pin", ErrContextMismatch, chain)
	}
	return nil
}
