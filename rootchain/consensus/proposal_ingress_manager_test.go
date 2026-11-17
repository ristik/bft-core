package consensus

import (
	"context"
	"crypto"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	testlogger "github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testtrust "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	testnode "github.com/unicitynetwork/bft-core/rootchain/testutils"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// #1113 (astra on #1183): a trust base stored while the root runs (PUT /api/v1/trustbases) admits its committee at once, without waiting
// for the installed trust base to change.
func TestKnownRootFollowsTrustBaseStoreWrites(t *testing.T) {
	a, b := testnode.NewTestNode(t), testnode.NewTestNode(t)
	first := testtrust.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{a.PeerConf.ID.String(): a.Signer}).(*types.RootTrustBaseV1)
	store, err := tbstore.NewTrustBaseStore(memorydb.New(), testlogger.New(t))
	require.NoError(t, err)
	require.NoError(t, store.Store(first))
	cm := &ConsensusManager{trustBaseStore: store}
	cm.trustBase.Store(first)
	require.True(t, cm.KnownRoot(a.PeerConf.ID))
	require.False(t, cm.KnownRoot(b.PeerConf.ID))

	prev, err := first.Hash(crypto.SHA256)
	require.NoError(t, err)
	verifier, err := b.Signer.Verifier()
	require.NoError(t, err)
	second, err := types.NewTrustBase(5, []*types.NodeInfo{testtrust.NewNodeInfoFromVerifier(t, b.PeerConf.ID.String(), verifier)},
		types.WithEpoch(2), types.WithEpochStart(10), types.WithPreviousTrustBaseHash(prev))
	require.NoError(t, err)
	require.NoError(t, second.Sign(a.PeerConf.ID.String(), a.Signer))
	require.NoError(t, store.Store(second)) // same write used by PUT /api/v1/trustbases
	require.Same(t, first, cm.trustBase.Load(), "the installed epoch has not changed")
	require.True(t, cm.KnownRoot(b.PeerConf.ID), "a newly stored adjacent committee must be admitted before this root advances")
}

// #1113 (astra on #1183): every root, not only the next leader, publishes the leaders of its current and next round as the round
// moves; a follower advanced by timeout certificates gives the protected share to the actual leader and takes it from the former one.
func TestFollowerRefreshesProposerPriorityAcrossTimeouts(t *testing.T) {
	replicas, anchor, _ := newAnchorReplicas(t, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	selector := firstReplica(replicas).manager.leaderSelector
	var leaders [3]peer.ID
	for i := range leaders {
		var err error
		leaders[i], err = selector.GetLeaderForRound(anchor.Slot + 1 + uint64(i))
		require.NoError(t, err)
	}
	var receiver *anchorReplica
	for id, r := range replicas {
		if id != leaders[0] && id != leaders[1] && id != leaders[2] {
			receiver = r
			break
		}
	}
	require.NotNil(t, receiver)
	receiver.manager.refreshProposers() // as the loop does before each event
	require.True(t, receiver.manager.EligibleProposer(leaders[0]))
	require.True(t, receiver.manager.EligibleProposer(leaders[1]))
	require.False(t, receiver.manager.EligibleProposer(leaders[2]))

	for step := uint64(1); step <= 2; step++ {
		round := anchor.Slot + step
		var votes []*abdrc.TimeoutMsg
		for _, r := range replicas {
			r.net.ResetSentMessages(network.ProtocolRootTimeout)
			r.manager.onLocalTimeout(ctx)
			msgs := r.net.SentMessages(network.ProtocolRootTimeout)
			require.NotEmpty(t, msgs)
			votes = append(votes, msgs[0].Message.(*abdrc.TimeoutMsg))
		}
		for _, v := range votes {
			if receiver.manager.pacemaker.GetCurrentRound() > round {
				break
			}
			require.NoError(t, receiver.manager.onTimeoutMsg(ctx, v))
		}
		require.Equal(t, round+1, receiver.manager.pacemaker.GetCurrentRound())
		receiver.manager.timeoutUnknownLeader(ctx)
		receiver.manager.refreshProposers() // the loop's call before the next event
		tc := receiver.manager.pacemaker.LastRoundTC()
		require.NotNil(t, tc)
		for _, r := range replicas {
			r.manager.processTC(ctx, tc)
		}
	}
	require.True(t, receiver.manager.EligibleProposer(leaders[2]), "the actual current leader must get protected capacity on a follower")
	require.False(t, receiver.manager.EligibleProposer(leaders[0]), "the former leader must no longer receive priority")
}
