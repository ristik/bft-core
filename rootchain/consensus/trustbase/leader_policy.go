package trustbase

import (
	"errors"
	"fmt"
)

const (
	// LeaderPolicyLegacy is the leader selection of every epoch that has no activation: the existing reputation selector for
	// a genesis epoch and the canonical-order rotation of a handoff epoch.
	LeaderPolicyLegacy = "legacy"
	// LeaderPolicyWeightedV1 is the fixed-epoch weighted proposer-priority selector (leader.Weighted).
	LeaderPolicyWeightedV1 = "root-wrr-v1"
)

// ErrLeaderPolicyHistory is returned when the leader policy of an epoch cannot be established from the authenticated history:
// an unknown policy or epoch, or an activation that does not fit the recorded ones.
var ErrLeaderPolicyHistory = errors.New("leader policy history")

// leaderPolicyRegistry is the history of the epochs that activated a leader policy, the same per-epoch dispatch as the signing
// registry: the policy is a property of the root epoch and is meant to change at the same boundary as the epoch's weights and
// signing scheme. An epoch with no activation at or below it is legacy. A store bound to the verified history (BindSigningAuthority)
// takes every epoch's policy from it, as it does the signing configuration: the committed ProtocolConfig of the epoch is the one
// activation, and ActivateLeaderPolicy is refused. Production has no caller of ActivateLeaderPolicy
// (TestNoProductionCallerOfActivateLeaderPolicy); it is the seam for tests of the selection rules.
type leaderPolicyRegistry struct {
	byEpoch map[uint64]string
}

// ActivateLeaderPolicy records that the given epoch is the first to select leaders with the policy. The epoch's trust base must
// be installed; only LeaderPolicyWeightedV1 is an activation; the policy never goes back (an activation below a recorded one is
// refused); installing the same record again is a no-op and a different record for the same epoch is refused.
func (s *TrustBaseStore) ActivateLeaderPolicy(epoch uint64, policy string) error {
	if policy != LeaderPolicyWeightedV1 {
		return fmt.Errorf("%w: %q is not an activatable policy", ErrLeaderPolicyHistory, policy)
	}
	if _, err := s.GetByEpoch(epoch); err != nil {
		return fmt.Errorf("%w: epoch %d has no trust base: %w", ErrLeaderPolicyHistory, epoch, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signing.authority != nil {
		return fmt.Errorf("%w: the store takes its policies from the verified history", ErrLeaderPolicyHistory)
	}
	if s.leaderPolicy.byEpoch == nil {
		s.leaderPolicy.byEpoch = make(map[uint64]string)
	}
	if prev, ok := s.leaderPolicy.byEpoch[epoch]; ok {
		if prev != policy {
			return fmt.Errorf("%w: epoch %d already activated with another policy", ErrLeaderPolicyHistory, epoch)
		}
		return nil
	}
	for e := range s.leaderPolicy.byEpoch {
		if e > epoch {
			return fmt.Errorf("%w: epoch %d is below the recorded activation at epoch %d", ErrLeaderPolicyHistory, epoch, e)
		}
	}
	s.leaderPolicy.byEpoch[epoch] = policy
	return nil
}

// LeaderPolicy is the leader policy of the epoch: the activation record of the latest activated epoch at or below it, or
// LeaderPolicyLegacy when none is. It is an error for an epoch with no installed trust base: missing history is not an
// implicit legacy choice.
func (s *TrustBaseStore) LeaderPolicy(epoch uint64) (string, error) {
	if _, err := s.GetByEpoch(epoch); err != nil {
		return "", fmt.Errorf("%w: epoch %d: %w", ErrLeaderPolicyHistory, epoch, err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if a := s.signing.authority; a != nil {
		policy, err := a.LeaderPolicy(epoch)
		if err != nil {
			return "", fmt.Errorf("%w: epoch %d: %w", ErrLeaderPolicyHistory, epoch, err)
		}
		return policy, nil
	}
	policy, found, latest := LeaderPolicyLegacy, false, uint64(0)
	for e, p := range s.leaderPolicy.byEpoch {
		if e <= epoch && (!found || e > latest) {
			policy, found, latest = p, true, e
		}
	}
	return policy, nil
}
