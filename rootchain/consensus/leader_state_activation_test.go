package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

type reputationInputs struct {
	committee  []string
	reputation bool
}

func (r reputationInputs) LeaderCommittee(uint64) ([]string, bool, error) {
	return r.committee, r.reputation, nil
}

// On a real activation: the anchor keeps the outgoing root and has no ring of the new epoch, and the epoch's first executed ordinary block
// starts one from the anchor's genesis, whatever round it is proposed at. Under any other policy no leaf appears and the root is unchanged.
func TestLeaderRingStartsAtTheAnchorChild(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	anchor := c.activateAll()
	committee := make([]string, 0, len(c.f.NewNodes))
	for _, n := range c.f.NewNodes {
		committee = append(committee, n.PeerConf.ID.String())
	}
	child := func(round uint64) *rctypes.BlockData {
		return &rctypes.BlockData{Version: 3, Epoch: anchor.Epoch, Round: round, Anchor: anchor, Payload: &rctypes.Payload{Version: 3}}
	}
	store := c.replicas[0].manager.blockStore
	_, ring, sealed := store.LeaderHead()
	require.Nil(t, ring, "the installed anchor holds no ring of the new epoch")
	require.True(t, sealed, "and keeps the outgoing terminal control state")

	store.SetLeaderInputs(reputationInputs{committee: committee})
	_, err := store.Add(child(anchor.Slot+1), c.replicas[0].manager.irReqVerifier)
	require.NoError(t, err)
	plain, err := store.Block(anchor.Slot + 1)
	require.NoError(t, err)
	require.Nil(t, plain.ShardState.Leader, "another policy has no leaf")

	other := c.replicas[1].manager.blockStore
	other.SetLeaderInputs(reputationInputs{committee: committee, reputation: true})
	_, err = other.Add(child(anchor.Slot+1), c.replicas[1].manager.irReqVerifier)
	require.NoError(t, err)
	early, err := other.Block(anchor.Slot + 1)
	require.NoError(t, err)
	require.NotEqual(t, plain.RootHash, early.RootHash, "the state root binds the leaf")
	require.Equal(t, anchor.GenesisID, early.ShardState.Leader.Genesis)
	require.Equal(t, anchor.Epoch, early.ShardState.Leader.Epoch)
	require.EqualValues(t, anchor.Slot+1, early.ShardState.Leader.Start)
	require.EqualValues(t, 20, early.ShardState.Leader.Lag, "4n+4 of the committee")
	require.Equal(t, []rctypes.LeaderRecord{{Round: anchor.Slot}, {Round: anchor.Slot + 1}}, early.ShardState.Leader.Records)

	third := c.replicas[2].manager.blockStore
	third.SetLeaderInputs(reputationInputs{committee: committee, reputation: true})
	_, err = third.Add(child(anchor.Slot+40), c.replicas[2].manager.irReqVerifier)
	require.NoError(t, err)
	late, err := third.Block(anchor.Slot + 40)
	require.NoError(t, err)
	require.EqualValues(t, anchor.Slot+1, late.ShardState.Leader.Start, "a first child well after A: the start is still A")
	require.Equal(t, []rctypes.LeaderRecord{{Round: anchor.Slot}, {Round: anchor.Slot + 40}}, late.ShardState.Leader.Records)
}
