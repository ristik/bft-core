package consensus

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// retentionFixture is an ingress root, not running: its methods are driven directly, and what it sends to the other root is recorded.
type retentionFixture struct {
	cm    *ConsensusManager
	other peer.ID
	nodes []*testutils.TestNode
	mu    sync.Mutex
	sent  []*abdrc.IrChangeReqMsg
	ctx   context.Context
	shard types.PartitionShardID
}

func newRetentionFixture(t *testing.T) *retentionFixture {
	t.Helper()
	nodes, infos := testutils.CreateTestNodes(t, 2)
	cms, net := createConsensusManagers(t, 2, infos)
	f := &retentionFixture{cm: cms[1], other: cms[0].id, nodes: nodes, ctx: context.Background(),
		shard: types.PartitionShardID{PartitionID: partitionID, ShardID: types.ShardID{}.Key()}}
	f.cm.leaderSelector = constLeader{leader: f.other, nodes: f.cm.Validators()}
	net.SetFirewall(func(from, to peer.ID, msg any) bool {
		if m, ok := msg.(*abdrc.IrChangeReqMsg); ok && from == f.cm.id && to == f.other {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.sent = append(f.sent, m)
		}
		return true
	})
	f.nextRound() // a running manager is always in a round
	return f
}

func (f *retentionFixture) request(t *testing.T) *drctypes.IRChangeReq {
	t.Helper()
	si, err := f.cm.ShardInfo(partitionID, types.ShardID{})
	require.NoError(t, err)
	return &drctypes.IRChangeReq{Partition: partitionID, CertReason: drctypes.Quorum, Requests: buildBlockCertificationRequest(t, f.nodes, si.LastCR)}
}

func (f *retentionFixture) nextRound() {
	f.cm.pacemaker.startNewRound(f.ctx, f.cm.pacemaker.GetCurrentRound()+1)
	f.cm.timeoutUnknownLeader(f.ctx)
}

func (f *retentionFixture) sends() []*abdrc.IrChangeReqMsg {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*abdrc.IrChangeReqMsg(nil), f.sent...)
}

// A lost forward needs no shard retry: the same signed request goes out once per round, byte for byte, whatever else happens to it.
func TestRetainedRequestIsSentOncePerRoundUnchanged(t *testing.T) {
	f := newRetentionFixture(t)
	require.NoError(t, f.cm.retainRequest(f.ctx, f.request(t)))
	require.Len(t, f.sends(), 1, "sent on acceptance")
	f.cm.forwardRetained(f.ctx)
	f.cm.forwardRetained(f.ctx)
	require.Len(t, f.sends(), 1, "at most one send per round")
	for i := 2; i <= 4; i++ {
		f.nextRound()
		f.cm.forwardRetained(f.ctx)
		require.Len(t, f.sends(), i)
	}
	first, err := types.Cbor.Marshal(f.sends()[0])
	require.NoError(t, err)
	last, err := types.Cbor.Marshal(f.sends()[3])
	require.NoError(t, err)
	require.Equal(t, first, last, "the shard's proof and the signature are byte-identical")
}

// More than the shard's ten duplicate retries with no repeat UC: one entry, and each still leaves a working retry behind.
func TestRetainedRequestSurvivesDuplicateTriggers(t *testing.T) {
	f := newRetentionFixture(t)
	req := f.request(t)
	for range 12 {
		require.NoError(t, f.cm.retainRequest(f.ctx, req))
	}
	require.Len(t, f.cm.retained, 1)
	require.Len(t, f.sends(), 1, "duplicates in one round add no send")
	f.nextRound()
	require.Len(t, f.sends(), 2, "the retry does not depend on the shard")
}

// When this node is the next leader the copy goes to the proposal buffer, and a proposal clearing that buffer does not end it.
func TestRetainedRequestOutlivesTheProposalBuffer(t *testing.T) {
	f := newRetentionFixture(t)
	f.cm.leaderSelector = constLeader{leader: f.cm.id, nodes: f.cm.Validators()}
	require.NoError(t, f.cm.retainRequest(f.ctx, f.request(t)))
	require.True(t, f.cm.irReqBuffer.IsChangeInBuffer(partitionID, types.ShardID{}))
	payload := f.cm.irReqBuffer.GeneratePayload(f.cm.pacemaker.GetCurrentRound()+1, nil, func(types.PartitionID, types.ShardID) *types.InputRecord { return nil })
	require.Len(t, payload.Requests, 1)
	require.False(t, f.cm.irReqBuffer.IsChangeInBuffer(partitionID, types.ShardID{}), "the proposal cleared the buffer")
	require.Contains(t, f.cm.retained, f.shard, "an uncommitted proposal is no reason to let go")
	f.nextRound()
	require.True(t, f.cm.irReqBuffer.IsChangeInBuffer(partitionID, types.ShardID{}), "the next round puts it back")
}

func TestRetainedRequestWaitsForAKnownLeader(t *testing.T) {
	f := newRetentionFixture(t)
	f.cm.leaderSelector = unknownLeader{}
	require.NoError(t, f.cm.retainRequest(f.ctx, f.request(t)))
	require.Empty(t, f.sends())
	require.Contains(t, f.cm.retained, f.shard, "an unknown next leader is not a reason to lose it")
	f.cm.leaderSelector = constLeader{leader: f.other, nodes: f.cm.Validators()}
	f.nextRound()
	require.Len(t, f.sends(), 1, "retried once the leader is known")
}

type unknownLeader struct{ constLeader }

func (unknownLeader) GetLeaderForRound(uint64) (peer.ID, error) {
	return "", drctypes.ErrHistoryUnavailable
}

func TestRetainedRequestDroppedWhenTheVerifierSaysStale(t *testing.T) {
	f := newRetentionFixture(t)
	require.NoError(t, f.cm.retainRequest(f.ctx, f.request(t)))
	// the shard's last certificate moved on: the proof is built on another seal
	si, err := f.cm.ShardInfo(partitionID, types.ShardID{})
	require.NoError(t, err)
	f.cm.retained[f.shard].msg.IrChangeReq.Requests[0].InputRecord.Timestamp = si.LastCR.UC.UnicitySeal.Timestamp + 1
	sent := len(f.sends())
	f.nextRound()
	require.NotContains(t, f.cm.retained, f.shard)
	require.Len(t, f.sends(), sent, "and it is not sent")
}

// Only a verdict on the request drops it. A view that cannot be resolved, and a change pending in the pipeline, say nothing about it.
func TestRetainedRequestKeptOnTransientFailure(t *testing.T) {
	f := newRetentionFixture(t)
	require.NoError(t, f.cm.retainRequest(f.ctx, f.request(t)))
	sentinel := errors.New("the view is not resolvable now")
	f.cm.SetViewResolver(failingResolver{sentinel})
	verdict, err := f.cm.judgeRetained(f.cm.retained[f.shard].msg.IrChangeReq)
	require.Equal(t, retainedUnknown, verdict)
	require.ErrorIs(t, err, sentinel)
	f.nextRound()
	require.Contains(t, f.cm.retained, f.shard)

	require.Equal(t, retainedValid, viewVerdict(nil))
	require.Equal(t, retainedStale, viewVerdict(fmt.Errorf("x: %w", storage.ErrStaleRequestContext)))
	require.Equal(t, retainedUnknown, viewVerdict(storage.ErrDuplicateChangeReq), "its own change in an uncommitted proposal")
	require.Equal(t, retainedUnknown, viewVerdict(errors.New("shard has pending changes in pipeline")))

	missing := &drctypes.IRChangeReq{Partition: partitionID + 1, CertReason: drctypes.Quorum}
	f.cm.SetViewResolver(nil)
	verdict, err = f.cm.judgeRetained(missing)
	require.Equal(t, retainedUnknown, verdict, "no committed state to judge it")
	require.ErrorIs(t, err, ErrRequestStateUnavailable)
}

type failingResolver struct{ err error }

func (r failingResolver) ResolveView(types.PartitionID, types.ShardID, uint64, storage.RequestPurpose) (*storage.RequestRoundView, error) {
	return nil, r.err
}

func TestRetainedRequestRefusesEquivocation(t *testing.T) {
	f := newRetentionFixture(t)
	held := f.request(t)
	require.NoError(t, f.cm.retainRequest(f.ctx, held))
	other := f.request(t) // another valid proof with a different input record
	require.ErrorIs(t, f.cm.retainRequest(f.ctx, other), ErrEquivocation)
	require.Same(t, held, f.cm.retained[f.shard].msg.IrChangeReq, "a valid pending request is not overwritten")

	// the held one going stale makes room
	si, err := f.cm.ShardInfo(partitionID, types.ShardID{})
	require.NoError(t, err)
	held.Requests[0].InputRecord.Timestamp = si.LastCR.UC.UnicitySeal.Timestamp + 1
	require.NoError(t, f.cm.retainRequest(f.ctx, other))
	require.Same(t, other, f.cm.retained[f.shard].msg.IrChangeReq)
}

func TestRetainRefusesAStaleRequest(t *testing.T) {
	f := newRetentionFixture(t)
	req := f.request(t)
	si, err := f.cm.ShardInfo(partitionID, types.ShardID{})
	require.NoError(t, err)
	req.Requests[0].InputRecord.Timestamp = si.LastCR.UC.UnicitySeal.Timestamp + 1
	require.Error(t, f.cm.retainRequest(f.ctx, req))
	require.Empty(t, f.cm.retained)
	require.Empty(t, f.sends())
}

// No root queue crosses an epoch: the shard resubmits under the successor.
func TestEpochInstallDropsRetainedRequests(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	for _, r := range c.replicas {
		r.manager.retained = map[types.PartitionShardID]*retainedRequest{{PartitionID: 1}: {}}
	}
	c.activateAll()
	for _, r := range c.replicas {
		require.Empty(t, r.manager.retained)
	}
}
