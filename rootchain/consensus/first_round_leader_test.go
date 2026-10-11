package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// A root installed from an epoch anchor enters the epoch's first round without a QC or a TC. Nothing else triggers its proposal
// (the pacemaker's maturity event belongs to the leader of the NEXT round), so unless Run starts the round itself the epoch begins with a
// round timeout (#559).
func TestTheLeaderOfAnAnchoredEpochsFirstRoundProposesWithoutATimeout(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 4)
	probe := firstReplica(replicas)
	leader, err := probe.manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- replicas[leader].manager.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	proposal := replicas[leader].net.WaitRootProposal(t) // waits one second, far below the round timeout
	require.EqualValues(t, anchor.Slot+1, proposal.Block.Round)
	require.Nil(t, proposal.Block.Qc, "the first block of the epoch has no QC")
	require.NotNil(t, proposal.Block.Anchor, "its parent is the epoch anchor")
}
