package consensus

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"go.etcd.io/bbolt"
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

func TestLegacyProposalAdoptionFencesStaleEpochAnchorOnStartup(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 4)
	id, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)
	replica := replicas[id]
	old := &abdrc.ProposalMsg{Block: &drctypes.BlockData{
		Version: drctypes.VersionHandoff, Author: id.String(), Epoch: anchor.Epoch, Round: anchor.Slot + 1,
		Timestamp: 10000, Anchor: anchor, Payload: &drctypes.Payload{Version: drctypes.VersionHandoff},
	}}
	require.NoError(t, old.Sign(replica.manager.safety.signer))

	// The old executable could send its first proposal before recording a
	// newer QC or TC. Its Bolt format had no proposal key.
	require.NoError(t, replica.db.Close())
	legacy, err := bbolt.Open(replica.dbPath, 0600, nil)
	require.NoError(t, err)
	require.NoError(t, legacy.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte("safety")).Delete([]byte("proposal"))
	}))
	require.NoError(t, legacy.Close())

	for range 2 {
		db, err := storage.NewBoltStorage(replica.dbPath)
		require.NoError(t, err)
		net := testnetwork.NewRootMockNetwork()
		restarted, err := NewConsensusManager(id, replica.store, replica.manager.orchestration,
			net, replica.manager.safety.signer, db, observability.Default(t),
			WithConsensusParams(*replica.manager.params), WithRecoveryProfile2(replica.history))
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		require.NoError(t, restarted.startContext(ctx))
		require.Equal(t, anchor.Slot+1, restarted.pacemaker.GetCurrentRound())
		restarted.beginContext(ctx)
		require.Empty(t, net.SentMessages(network.ProtocolRootProposal), "the local anchor slot is fenced before processing any network traffic")
		cancel()
		restarted.pacemaker.Stop()
		require.NoError(t, db.Close())
	}
}
