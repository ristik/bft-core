package consensus

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrLeaderPolicy is returned for an epoch whose leader policy is not one this binary implements. There is no fallback to
// another selection.
var ErrLeaderPolicy = errors.New("unknown leader policy")

// leaderPolicies resolves the authenticated leader policy of an epoch (the trust base store).
type leaderPolicies interface {
	LeaderPolicy(epoch uint64) (string, error)
}

// newEpochLeader is the one place a root epoch's leader selector is chosen, for the startup of a restored epoch and for the live
// installation of a successor alike. The policy is a per-epoch property resolved from the authenticated history: legacy epochs
// keep the selector built by legacy, an epoch that activated root-wrr-v1 gets the weighted selector from its start round and
// members. A missing history entry or an unknown policy is an error, never an implicit legacy choice.
func newEpochLeader(policies leaderPolicies, epoch, start uint64, nodes []*types.NodeInfo, legacy func() (Leader, error)) (Leader, error) {
	policy, err := policies.LeaderPolicy(epoch)
	if err != nil {
		return nil, err
	}
	switch policy {
	case trustbase.LeaderPolicyLegacy:
		return legacy()
	case trustbase.LeaderPolicyWeightedV1:
		return leader.NewWeighted(start, nodes)
	}
	return nil, fmt.Errorf("%w: %q for epoch %d", ErrLeaderPolicy, policy, epoch)
}
