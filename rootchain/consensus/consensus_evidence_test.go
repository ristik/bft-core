package consensus

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	abdrctu "github.com/unicitynetwork/bft-core/rootchain/consensus/testutils"
	"github.com/unicitynetwork/bft-core/rootevidence"
)

// The evidence tap sees a vote before the stale-round filter: consensus refuses the vote, the observer still received it.
func TestOnVoteMsg_EvidenceTapPrecedesTheFilters(t *testing.T) {
	cms, _ := createConsensusManagers(t, 1, nil)
	cm := cms[0]
	cm.pacemaker.Reset(context.Background(), 8, nil, nil)
	defer cm.pacemaker.Stop()

	journal, err := rootevidence.NewJournal(memorydb.New(), 0)
	require.NoError(t, err)
	obs := rootevidence.NewObserver(journal, cm.trustBaseStore, nil, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go obs.Run(ctx)
	cm.evidence = obs

	// only the round matters to the filter; the content is a legacy-form vote the observer cannot keep
	vote := &abdrc.VoteMsg{VoteInfo: abdrctu.NewDummyRootRoundInfo(7), LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: []byte{1}}, Author: cm.id.String()}
	err = cm.onVoteMsg(context.Background(), vote)
	require.EqualError(t, err, `stale vote for round 7 from `+cm.id.String())
	// the legacy form is not kept as evidence: the observer counts it as rejected, which shows it was offered at all
	require.Eventually(t, func() bool { return obs.Stats().Rejected == 1 }, 5*time.Second, 10*time.Millisecond)
	require.True(t, obs.Healthy())
}
