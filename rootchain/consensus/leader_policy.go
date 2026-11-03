package consensus

import (
	"errors"
	"fmt"
	"slices"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
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
// members, an epoch of root-reputation-v1 gets the selector reputation builds. A missing history entry or an unknown policy is an error, never an implicit legacy choice.
func newEpochLeader(policies leaderPolicies, epoch, start uint64, nodes []*types.NodeInfo, legacy, reputation func() (Leader, error)) (Leader, error) {
	policy, err := policies.LeaderPolicy(epoch)
	if err != nil {
		return nil, err
	}
	switch policy {
	case trustbase.LeaderPolicyLegacy:
		return legacy()
	case trustbase.LeaderPolicyWeightedV1:
		return leader.NewWeighted(start, nodes)
	case trustbase.LeaderPolicyReputationV1:
		return reputation()
	}
	return nil, fmt.Errorf("%w: %q for epoch %d", ErrLeaderPolicy, policy, epoch)
}

// ErrReputationProfile is root-reputation-v1 where its inputs do not hold: stake-weighted votes under the handoff profile (other profiles
// count a vote as one, so a stake threshold would misjudge a sample) and a verified successor genesis to bind the ring to.
var ErrReputationProfile = errors.New("root-reputation-v1 needs an epoch anchor under the handoff profile")

// ErrReputationScheme is root-reputation-v1 in an epoch whose QCs are not strictly verified. A scheme 1 QC can carry a signature key that was
// never verified (an invalid signature of a known member counts for nothing, and its entry stays), so a Byzantine proposer could add a dead
// member to a certified sample and defeat the exclusion the schedule relies on. Only scheme 2 makes Signatures' keys verified voters.
var ErrReputationScheme = errors.New("root-reputation-v1 needs a scheme 2 epoch")

// signingConfigs resolves the authenticated signing configuration of an epoch (the trust base store).
type signingConfigs interface {
	SigningConfig(epoch uint64) (votesig.Config, error)
}

// reputationLeader is the one constructor of root-reputation-v1, for every install and restart. head reads the block store current at the
// time of the lookup: a recovery replaces the store.
func reputationLeader(profile uint64, anchor *rctypes.EpochAnchor, trust *types.RootTrustBaseV1, signing signingConfigs, store func() *storage.BlockStore) (Leader, error) {
	if profile != storage.ProfileHandoff || anchor == nil || trust == nil {
		return nil, ErrReputationProfile
	}
	cfg, err := signing.SigningConfig(anchor.Epoch)
	if err != nil {
		return nil, err
	}
	if cfg.Scheme != votesig.SchemeDomainBound {
		return nil, fmt.Errorf("%w: epoch %d signs under scheme %d", ErrReputationScheme, anchor.Epoch, cfg.Scheme)
	}
	return leader.NewEpochReputation(anchor.GenesisID, anchor.Epoch, anchor.Slot+1, trust.QuorumThreshold, trust.RootNodes, func() (leader.LeaderHead, error) {
		round, state, sealed := store().LeaderHead()
		return leader.LeaderHead{Round: round, State: state, Sealed: sealed}, nil
	})
}

// trustLeaderInputs names an epoch's policy and committee to execution, from the authenticated trust-base history.
type trustLeaderInputs struct {
	store interface {
		leaderPolicies
		GetByEpoch(epoch uint64) (*types.RootTrustBaseV1, error)
	}
}

func (t trustLeaderInputs) LeaderCommittee(epoch uint64) ([]string, bool, error) {
	policy, err := t.store.LeaderPolicy(epoch)
	if err != nil {
		return nil, false, err
	}
	if policy != trustbase.LeaderPolicyReputationV1 {
		return nil, false, nil
	}
	trust, err := t.store.GetByEpoch(epoch)
	if err != nil {
		return nil, false, err
	}
	committee := make([]string, 0, len(trust.RootNodes))
	for _, n := range trust.RootNodes {
		committee = append(committee, n.NodeID)
	}
	slices.Sort(committee)
	return committee, true, nil
}
