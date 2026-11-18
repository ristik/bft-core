package consensus

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	testlogger "github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testobs "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testtrust "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/leader"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	testnode "github.com/unicitynetwork/bft-core/rootchain/testutils"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// #1113 (astra on #1183, round 3): a successor trust base stored while the root runs (PUT /api/v1/trustbases) changes what the legacy
// selector names for the next round; the publication follows it without a round change.
func TestProposerPriorityFollowsStoredSuccessor(t *testing.T) {
	a, b := testnode.NewTestNode(t), testnode.NewTestNode(t)
	first := testtrust.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{a.PeerConf.ID.String(): a.Signer}).(*types.RootTrustBaseV1)
	store, err := tbstore.NewTrustBaseStore(memorydb.New(), testlogger.New(t))
	require.NoError(t, err)
	require.NoError(t, store.Store(first))
	selector, err := leader.NewReputationBased(10, 1, store)
	require.NoError(t, err)
	require.NoError(t, selector.UpdateWithTrustBase(first, 1)) // initial startup
	pm, err := NewPacemaker(time.Second, 10*time.Second, testobs.Default(t))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer pm.Stop()
	pm.Reset(ctx, 8, nil, nil) // round 9; later timeout rounds use the legacy fallback
	cm := &ConsensusManager{pacemaker: pm, leaderSelector: selector, trustBaseStore: store}
	cm.trustBase.Store(first)
	current, err := selector.GetLeaderForRound(9)
	require.NoError(t, err)
	next, err := selector.GetLeaderForRound(10)
	require.NoError(t, err)
	require.Equal(t, a.PeerConf.ID, current)
	require.Equal(t, a.PeerConf.ID, next)
	cm.refreshProposers()
	require.True(t, cm.EligibleProposer(a.PeerConf.ID))
	require.False(t, cm.EligibleProposer(b.PeerConf.ID))

	prev, err := first.Hash(crypto.SHA256)
	require.NoError(t, err)
	verifier, err := b.Signer.Verifier()
	require.NoError(t, err)
	second, err := types.NewTrustBase(5, []*types.NodeInfo{testtrust.NewNodeInfoFromVerifier(t, b.PeerConf.ID.String(), verifier)},
		types.WithEpoch(2), types.WithEpochStart(10), types.WithPreviousTrustBaseHash(prev))
	require.NoError(t, err)
	require.NoError(t, second.Sign(a.PeerConf.ID.String(), a.Signer))
	require.NoError(t, store.Store(second)) // same write as PUT /api/v1/trustbases
	require.Same(t, first, cm.trustBase.Load())
	require.True(t, cm.KnownRoot(b.PeerConf.ID))
	next, err = cm.leaderAfter(9)
	require.NoError(t, err)
	require.Equal(t, b.PeerConf.ID, next, "real selector now names the successor's leader")
	require.EqualValues(t, 9, pm.GetCurrentRound())
	cm.refreshProposers() // the loop's refresh before the next event
	require.True(t, cm.EligibleProposer(b.PeerConf.ID), "the newly stored successor's next leader has the protected share")
}

// #1113 (astra on #1183, round 3): a recovery clears even a complete publication, and the next refresh publishes the recovered leaders.
func TestRecoveryClearsProposerPublication(t *testing.T) {
	cm, state, qc4, _, _ := recoveryTreeSetup(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-cm.ucSink:
			}
		}
	}()
	cm.recovery = &recoveryState{}
	_, err := cm.recovery.Set(qc4)
	require.NoError(t, err)
	cm.proposers.Store(&proposerSet{round: 5, ids: [2]peer.ID{"stale-current", "stale-next"}})
	require.NoError(t, cm.onStateResponse(ctx, state))
	require.False(t, cm.recovery.InRecovery())
	require.EqualValues(t, 5, cm.pacemaker.GetCurrentRound())
	require.Nil(t, cm.proposers.Load(), "recovery clears even a completely known publication")
	cm.refreshProposers()
	current, err := cm.leaderSelector.GetLeaderForRound(5)
	require.NoError(t, err)
	next, err := cm.leaderAfter(5)
	require.NoError(t, err)
	require.True(t, cm.EligibleProposer(current))
	require.True(t, cm.EligibleProposer(next))
	require.False(t, cm.EligibleProposer("stale-current"))
	require.False(t, cm.EligibleProposer("stale-next"))
}
