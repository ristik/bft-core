package shardnode

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

type noopCommitObserver struct{}

func (noopCommitObserver) ObserveCommit(CertifiedCommit) {}

// TestNodeSetCommitObserverInstallsTheNodeGate: a node without recovery has no gate on its round, and a
// commit observer that decides under Node.FinalityGate would then not be serialized with the round's commits.
// Attaching the observer installs the node's gate; a gate recovery already installed is kept (#14 W2, review of
// #162).
func TestNodeSetCommitObserverInstallsTheNodeGate(t *testing.T) {
	t.Run("without recovery", func(t *testing.T) {
		round := NewRound("node", types.PartitionID(8), types.ShardID{}, nil, nil, nil, nil, nil)
		n := &Node{round: round, recoveryDeps: RecoveryDeps{Gate: NewFinalityGate()}}
		require.Nil(t, round.finality, "premise: without recovery the round takes no gate")

		n.SetCommitObserver(noopCommitObserver{})
		require.NotNil(t, n.FinalityGate())
		require.Same(t, n.FinalityGate(), round.finality)
		require.NotNil(t, round.commitObserver)
	})

	t.Run("with a gate already installed", func(t *testing.T) {
		round := NewRound("node", types.PartitionID(8), types.ShardID{}, nil, nil, nil, nil, nil)
		installed := NewFinalityGate()
		round.SetFinalityGate(installed)
		n := &Node{round: round, recoveryDeps: RecoveryDeps{Gate: NewFinalityGate()}}

		n.SetCommitObserver(noopCommitObserver{})
		require.Same(t, installed, round.finality, "an installed gate is not replaced")
	})
}
