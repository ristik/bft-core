package consensus

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
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

// requireSends waits for exactly n sends: the mock network delivers from a goroutine, so a count read at once can lag, and it waits a little
// longer so that one send too many still fails.
func (f *retentionFixture) requireSends(t *testing.T, n int) {
	t.Helper()
	require.Eventually(t, func() bool { return len(f.sends()) >= n }, 5*time.Second, 2*time.Millisecond, "fewer than %d sends", n)
	time.Sleep(50 * time.Millisecond)
	require.Len(t, f.sends(), n)
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
	f.requireSends(t, 1)
	f.cm.forwardRetained(f.ctx)
	f.cm.forwardRetained(f.ctx)
	f.requireSends(t, 1)
	for i := 2; i <= 4; i++ {
		f.nextRound()
		f.cm.forwardRetained(f.ctx)
		f.requireSends(t, i)
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
	f.requireSends(t, 1)
	f.nextRound()
	f.requireSends(t, 2)
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
	f.requireSends(t, 0)
	require.Contains(t, f.cm.retained, f.shard, "an unknown next leader is not a reason to lose it")
	f.cm.leaderSelector = constLeader{leader: f.other, nodes: f.cm.Validators()}
	f.nextRound()
	f.requireSends(t, 1)
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
	f.requireSends(t, 1) // the send on acceptance: settled before the count that follows
	f.nextRound()
	require.NotContains(t, f.cm.retained, f.shard)
	f.requireSends(t, 1)
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
	require.Equal(t, retainedRefused, viewVerdict(fmt.Errorf("x: %w", storage.ErrStaleRequestContext)))
	require.Equal(t, retainedRefused, viewVerdict(fmt.Errorf("x: %w", quorumweight.ErrQuorumNotReached)))
	require.Equal(t, retainedRefused, viewVerdict(fmt.Errorf("x: %w", quorumweight.ErrInvalidSignature)))
	require.Equal(t, retainedRefused, viewVerdict(fmt.Errorf("x: %w", ErrProofInvalid)))
	require.Equal(t, retainedRefused, viewVerdict(errors.New("anything else the verifier refuses")), "the default is refusal")
	require.Equal(t, retainedUnknown, viewVerdict(storage.ErrDuplicateChangeReq), "its own change in an uncommitted proposal")
	require.Equal(t, retainedUnknown, viewVerdict(fmt.Errorf("x: %w", storage.ErrPendingChange)))
	require.Equal(t, retainedUnknown, viewVerdict(fmt.Errorf("x: %w", storage.ErrRequestNotActive)))

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
	f.requireSends(t, 0)
}

// Only the freeze is a verdict: a failed read of the frozen shard says nothing about the request.
func TestFrozenVerdict(t *testing.T) {
	require.Equal(t, retainedRefused, frozenVerdict(fmt.Errorf("x: %w", storage.ErrHandoffFrozen)))
	require.Equal(t, retainedUnknown, frozenVerdict(errors.New("the store cannot read the frozen shard")))
}

// Rev's binding condition, through the entry point: a shard request arriving while the next leader is unknown is not refused and not lost.
func TestShardRequestIsKeptWhileTheNextLeaderIsUnknown(t *testing.T) {
	f := newRetentionFixture(t)
	f.cm.leaderSelector = unknownLeader{}
	req := f.request(t)
	require.NoError(t, f.cm.onPartitionIRChangeReq(f.ctx, &IRChangeRequest{Partition: req.Partition, Shard: req.Shard, Reason: Quorum, Requests: req.Requests}))
	require.Contains(t, f.cm.retained, f.shard, "held")
	f.requireSends(t, 0)
	f.cm.leaderSelector = constLeader{leader: f.other, nodes: f.cm.Validators()}
	f.nextRound()
	f.requireSends(t, 1)
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

// frozenRetentionFixture is a handoff-profile root that is the next leader and holds a request the verifier accepts, so only the freeze check
// stands between it and the proposal buffer: on this route nothing else asks (the other route's recipient refuses it itself).
func frozenRetentionFixture(t *testing.T) (*ConsensusManager, *drctypes.IRChangeReq, types.PartitionShardID, *retainedRequest) {
	t.Helper()
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	r := c.replicas[0]
	selectRuntimeRequestHistory(t, r)
	anchor := c.activateAll()
	cm := r.manager
	// two successor blocks and the QC of the second, as in TestQ3InstallPreservesSelectedRequestHistory: a high QC with a block, which the freeze check reads
	parent, err := cm.blockStore.Block(anchor.Slot)
	require.NoError(t, err)
	first := &drctypes.BlockData{Version: 3, Epoch: 2, Round: 7, Anchor: anchor, Payload: &drctypes.Payload{Version: 3}}
	b7, err := parent.Extend(first, cm.irReqVerifier, r.orchestration, crypto.SHA256, cm.log, cm.blockStore.LeaderInputs())
	require.NoError(t, err)
	second := &drctypes.BlockData{Version: 3, Epoch: 2, Round: 8, Payload: &drctypes.Payload{Version: 3},
		Qc: &drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{RoundNumber: 7, Epoch: 2, CurrentRootHash: b7.RootHash}, Signatures: map[string]hex.Bytes{r.id().String(): {1}}}}
	b8, err := b7.Extend(second, cm.irReqVerifier, r.orchestration, crypto.SHA256, cm.log, cm.blockStore.LeaderInputs())
	require.NoError(t, err)
	_, err = cm.blockStore.Add(first, cm.irReqVerifier)
	require.NoError(t, err)
	_, err = cm.blockStore.Add(second, cm.irReqVerifier)
	require.NoError(t, err)
	_, err = cm.blockStore.ProcessQc(&drctypes.QuorumCert{VoteInfo: &drctypes.RoundInfo{RoundNumber: 8, ParentRoundNumber: 7, Epoch: 2, CurrentRootHash: b8.RootHash},
		LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, Epoch: 2, Timestamp: 99, RootChainRoundNumber: 7, Hash: b7.RootHash}, Signatures: map[string]hex.Bytes{r.id().String(): {1}}})
	require.NoError(t, err)
	view, enabled, err := cm.RequestView(q3fixture.PartitionID, types.ShardID{})
	require.NoError(t, err)
	require.True(t, enabled)
	tr := view.ExpectedTR()
	uc, err := view.PreviousUC()
	require.NoError(t, err)
	req := &drctypes.IRChangeReq{Partition: q3fixture.PartitionID, Shard: types.ShardID{}, CertReason: drctypes.Quorum}
	for _, id := range view.Context().NodeIDs() {
		bcr := &certification.BlockCertificationRequest{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}, NodeID: id, InputRecord: &types.InputRecord{
			Version: 1, Epoch: tr.Epoch, RoundNumber: tr.Round, PreviousHash: view.PreviousStateHash(), Hash: bytes.Repeat([]byte{0x81}, 32), BlockHash: bytes.Repeat([]byte{0x82}, 32),
			SummaryValue: []byte{3}, Timestamp: uc.UnicitySeal.Timestamp}}
		require.NoError(t, bcr.Sign(c.f.EVMSigners[id]))
		req.Requests = append(req.Requests, bcr)
	}
	cm.leaderSelector = constLeader{leader: cm.id, nodes: cm.Validators()}
	key := types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}
	entry := &retainedRequest{msg: &abdrc.IrChangeReqMsg{Author: cm.id.String(), IrChangeReq: req}}
	cm.retained = map[types.PartitionShardID]*retainedRequest{key: entry}
	return cm, req, key, entry
}

func freezeShardAtHighQC(t *testing.T, cm *ConsensusManager, key types.PartitionShardID) {
	t.Helper()
	block, err := cm.blockStore.Block(cm.blockStore.GetHighQc().GetRound())
	require.NoError(t, err)
	parent := bytes.Repeat([]byte{0x42}, 32)
	block.ShardState.States[key].IR.BlockHash = parent
	require.NotNil(t, block.ShardState.Control)
	block.ShardState.Control.Phase, block.ShardState.Control.FrozenParent = "endorsed", parent
	frozen, active, err := cm.blockStore.FrozenShardAt(block.GetRound())
	require.NoError(t, err)
	require.True(t, active)
	require.Equal(t, key, frozen)
}

// sendRetained buffers directly when this root leads next, so judgeRetained's freeze check is the only one before buffering (the proposer filters too, later).
func TestRetainedRequestOfAFrozenShardIsDroppedAndNotBufferedByTheNextLeader(t *testing.T) {
	t.Run("not frozen: this route buffers it", func(t *testing.T) {
		cm, _, key, _ := frozenRetentionFixture(t)
		cm.forwardRetained(context.Background())
		require.Contains(t, cm.retained, key)
		require.True(t, cm.irReqBuffer.IsChangeInBuffer(q3fixture.PartitionID, types.ShardID{}), "without this the frozen case below proves nothing")
	})
	t.Run("frozen: dropped, not buffered", func(t *testing.T) {
		cm, req, key, _ := frozenRetentionFixture(t)
		freezeShardAtHighQC(t, cm, key)
		cm.forwardRetained(context.Background())
		_, kept := cm.retained[key]
		buffered := cm.irReqBuffer.IsChangeInBuffer(q3fixture.PartitionID, types.ShardID{})
		require.Equal(t, [2]bool{false, false}, [2]bool{kept, buffered}, "[kept, buffered]")
		verdict, err := cm.judgeRetained(req)
		require.Equal(t, retainedRefused, verdict)
		require.ErrorIs(t, err, storage.ErrHandoffFrozen)
	})
}

// The legacy switch of the active trust base: like the other two epoch paths, no root queue crosses it.
func TestLegacyTrustBaseSwitchDropsRetainedRequests(t *testing.T) {
	f := newRetentionFixture(t)
	require.NoError(t, f.cm.retainRequest(f.ctx, f.request(t)))
	f.cm.updateTrustBase()
	require.Contains(t, f.cm.retained, f.shard, "no switch: kept")
	active := *f.cm.trustBase.Load()
	stored := active.Epoch
	active.Epoch++ // the active base differs from the store's for this round: the next update switches
	f.cm.trustBase.Store(&active)
	f.cm.updateTrustBase()
	require.Equal(t, stored, f.cm.trustBase.Load().Epoch, "the switch happened")
	require.Empty(t, f.cm.retained)
}
