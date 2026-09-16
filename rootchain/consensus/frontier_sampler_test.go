package consensus

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/libp2p/go-libp2p/core/peer"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	rctest "github.com/unicitynetwork/bft-core/rootchain/testutils"
)

type frontierFaultStore struct {
	PersistentStore
	reader        frontierSafetyReader
	failSafety    atomic.Bool
	failBlock     atomic.Bool
	failVote      atomic.Bool
	failTC        atomic.Bool
	failRead      atomic.Bool
	safetyGate    chan struct{}
	safetyEntered chan struct{}
	voteGate      chan struct{}
	voteEntered   chan struct{}
}

type frontierFailVoteNet struct {
	RootNet
	fail atomic.Bool
}

func (n *frontierFailVoteNet) Send(ctx context.Context, msg any, receivers ...peer.ID) error {
	if _, ok := msg.(*abdrc.VoteMsg); ok && n.fail.Load() {
		return errors.New("recovered vote send fail")
	}
	return n.RootNet.Send(ctx, msg, receivers...)
}

func (s *frontierFaultStore) ReadSafetySnapshot() (storage.SafetySnapshot, error) {
	if s.safetyGate != nil {
		select {
		case s.safetyEntered <- struct{}{}:
		default:
		}
		<-s.safetyGate
	}
	if s.failRead.Load() {
		return storage.SafetySnapshot{}, errors.New("checked safety read fail")
	}
	return s.reader.ReadSafetySnapshot()
}
func (s *frontierFaultStore) SetHighestVotedRound(r uint64) error {
	if s.failSafety.Load() {
		return errors.New("safety fail")
	}
	return s.PersistentStore.SetHighestVotedRound(r)
}
func (s *frontierFaultStore) SetHighestQcRound(q, v uint64) error {
	if s.voteGate != nil {
		select {
		case s.voteEntered <- struct{}{}:
		default:
		}
		<-s.voteGate
	}
	if s.failSafety.Load() {
		return errors.New("safety fail")
	}
	return s.PersistentStore.SetHighestQcRound(q, v)
}
func (s *frontierFaultStore) WriteBlock(b *storage.ExecutedBlock, root bool) error {
	if s.failBlock.Load() {
		return errors.New("block fail")
	}
	return s.PersistentStore.WriteBlock(b, root)
}
func (s *frontierFaultStore) WriteVote(v any) error {
	if s.failVote.Load() {
		return errors.New("vote fail")
	}
	return s.PersistentStore.WriteVote(v)
}
func (s *frontierFaultStore) WriteTC(tc *drctypes.TimeoutCert) error {
	if s.failTC.Load() {
		return errors.New("tc fail")
	}
	return s.PersistentStore.WriteTC(tc)
}

type frontierHarness struct {
	cm         *ConsensusManager
	net        *testnetwork.MockNet
	pdr        *types.PartitionDescriptionRecord
	trust      *types.RootTrustBaseV1
	store      *frontierFaultStore
	shardNodes []*rctest.TestNode
	cancel     context.CancelFunc
	done       chan error
	author     string
	rootSigner abcrypto.Signer
}

func newFrontierHarness(t *testing.T) *frontierHarness {
	return newFrontierHarnessWithSigner(t, nil, false)
}

func newFrontierHarnessWithSigner(t *testing.T, wrap func(abcrypto.Signer) abcrypto.Signer, signing bool) *frontierHarness {
	t.Helper()
	rootNode := rctest.NewTestNode(t)
	shardNodes, shardInfos := rctest.CreateTestNodes(t, 3)
	rootSigners := map[string]abcrypto.Signer{rootNode.PeerConf.ID.String(): rootNode.Signer}
	tb := trustbase.NewTrustBaseFromSigners(t, rootSigners).(*types.RootTrustBaseV1)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partitionID, ShardID: shardID, PartitionTypeID: 999, TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 5 * time.Second, Validators: shardInfos, Epoch: 0, EpochStart: 1}
	observe := testobservability.Default(t)
	db, orchestration := createStorage(t, pdr, rootSigners, observe)
	reader := db.(frontierSafetyReader)
	store := &frontierFaultStore{PersistentStore: db, reader: reader}
	tbs, err := tbstore.NewTrustBaseStore(memorydb.New(), observe.Logger())
	require.NoError(t, err)
	require.NoError(t, tbs.Store(tb))
	net := testnetwork.NewRootMockNetwork()
	managerSigner := abcrypto.Signer(rootNode.Signer)
	if wrap != nil {
		managerSigner = wrap(managerSigner)
	}
	opts := []Option{
		WithConsensusParams(Parameters{BlockRate: 300 * time.Millisecond, LocalTimeout: 800 * time.Millisecond, HashAlgorithm: crypto.SHA256}),
		WithFrontierSampler(FrontierSamplerConfig{TrustBase: tb, QueueSize: 1, MaxPending: 2}),
	}
	if signing {
		opts = append(opts, WithFrontierSigning())
	}
	cm, err := NewConsensusManager(rootNode.PeerConf.ID, tbs, orchestration, net, managerSigner, store, observe, opts...)
	require.NoError(t, err)
	return &frontierHarness{cm: cm, net: net, pdr: pdr, trust: tb, store: store, shardNodes: shardNodes, author: rootNode.PeerConf.ID.String(), rootSigner: rootNode.Signer}
}

func (h *frontierHarness) request(t *testing.T) FrontierRequest {
	t.Helper()
	hash, err := h.pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	return FrontierRequest{NetworkID: h.pdr.NetworkID, PartitionID: h.pdr.PartitionID, ShardID: h.pdr.ShardID, FullShardConfHash: hash}
}
func (h *frontierHarness) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan error, 1)
	go func() { h.done <- h.cm.Run(ctx) }()
	require.Eventually(t, func() bool { return h.cm.frontier.eligible.Load() }, time.Second, time.Millisecond)
	t.Cleanup(func() {
		if h.done == nil {
			return
		}
		cancel()
		select {
		case <-h.done:
		case <-time.After(time.Second):
			t.Error("manager did not stop")
		}
	})
}
func (h *frontierHarness) stop(t *testing.T) {
	t.Helper()
	h.cancel()
	select {
	case <-h.done:
	case <-time.After(time.Second):
		t.Fatal("manager did not stop")
	}
	h.done = nil
}
func (h *frontierHarness) commitRoundTwo(t *testing.T) {
	t.Helper()
	proposal2 := rctest.MockAwaitMessage[*abdrc.ProposalMsg](t, h.net, network.ProtocolRootProposal)
	h.net.WaitReceive(t, proposal2)
	vote2 := rctest.MockAwaitMessage[*abdrc.VoteMsg](t, h.net, network.ProtocolRootVote)
	h.net.WaitReceive(t, vote2)
	proposal3 := rctest.MockAwaitMessage[*abdrc.ProposalMsg](t, h.net, network.ProtocolRootProposal)
	h.net.WaitReceive(t, proposal3)
	vote3 := rctest.MockAwaitMessage[*abdrc.VoteMsg](t, h.net, network.ProtocolRootVote)
	h.net.WaitReceive(t, vote3)
	_ = rctest.MockAwaitMessage[*abdrc.ProposalMsg](t, h.net, network.ProtocolRootProposal)
}

func TestFrontierSamplerRealLoopLifecycleAndVerifiedSample(t *testing.T) {
	h := newFrontierHarness(t)
	_, err := h.cm.SampleFrontier(context.Background(), h.request(t))
	require.ErrorIs(t, err, ErrFrontierUnavailable)
	h.start(t)
	require.Error(t, h.cm.Run(context.Background()), "enabled manager must reject a second Run owner")
	si, err := h.cm.ShardInfo(partitionID, shardID)
	require.NoError(t, err)
	require.NoError(t, h.cm.RequestCertification(context.Background(), IRChangeRequest{Partition: partitionID, Shard: shardID, Reason: Quorum, Requests: buildBlockCertificationRequest(t, h.shardNodes, si.LastCR)}))
	h.commitRoundTwo(t)
	sample, err := h.cm.SampleFrontier(context.Background(), h.request(t))
	require.NoError(t, err)
	require.Equal(t, uint64(2), sample.View.CommittedRootRound)
	require.Equal(t, FrontierCommitQC, sample.CoveringQC)
	require.Equal(t, uint64(1), sample.View.LastCR.UC.InputRecord.RoundNumber, "ordinary committed assignment is a valid diagnostic sample")
	require.NotEmpty(t, sample.View.LastCR.UC.InputRecord.BlockHash)
	require.NotEmpty(t, sample.View.LastCR.UC.InputRecord.Hash)
	require.GreaterOrEqual(t, sample.View.CommitQC.GetRound(), sample.Safety.HighestQCRound)
	sealRound, sealTime := sample.View.LastCR.UC.UnicitySeal.RootChainRoundNumber, sample.View.LastCR.UC.UnicitySeal.Timestamp
	sample.View.LastCR.Technical.StatHash[0] ^= 0xff
	again, err := h.cm.SampleFrontier(context.Background(), h.request(t))
	require.NoError(t, err)
	require.Equal(t, sealRound, again.View.LastCR.UC.UnicitySeal.RootChainRoundNumber)
	require.Equal(t, sealTime, again.View.LastCR.UC.UnicitySeal.Timestamp)
	require.NotEqual(t, sample.View.LastCR.Technical.StatHash, again.View.LastCR.Technical.StatHash)

	// Candidate validation is table-tested against the genuine QC produced by
	// the loop above. An invalid newer high QC cannot displace a valid commit QC,
	// while the same genuine QC remains usable through the high-QC slot.
	invalidHigh := cloneFrontierQC(t, sample.View.CommitQC)
	invalidHigh.VoteInfo.RoundNumber++
	require.Equal(t, FrontierCommitQC, selectFrontierQCCandidate(sample.View.CommitQC, invalidHigh, h.trust, sample.Safety.HighestQCRound, sample.View.CommittedRootRound))
	require.Equal(t, FrontierHighQC, selectFrontierQCCandidate(nil, sample.View.CommitQC, h.trust, sample.Safety.HighestQCRound, sample.View.CommittedRootRound))

	tests := []struct {
		name   string
		mutate func(*drctypes.QuorumCert)
	}{
		{"genesis", func(q *drctypes.QuorumCert) { q.VoteInfo.RoundNumber = drctypes.GenesisRootRound }},
		{"overflow", func(q *drctypes.QuorumCert) { q.VoteInfo.RoundNumber = ^uint64(0) }},
		{"foreign network", func(q *drctypes.QuorumCert) { q.LedgerCommitInfo.NetworkID++ }},
		{"foreign epoch", func(q *drctypes.QuorumCert) { q.VoteInfo.Epoch++ }},
		{"invalid signature", func(q *drctypes.QuorumCert) {
			for id := range q.Signatures {
				q.Signatures[id][0] ^= 0xff
				break
			}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			qc := cloneFrontierQC(t, sample.View.CommitQC)
			tc.mutate(qc)
			require.Error(t, verifyFrontierQC(qc, h.trust, sample.Safety.HighestQCRound, sample.View.CommittedRootRound))
		})
	}

	h.stop(t)
	_, err = h.cm.SampleFrontier(context.Background(), h.request(t))
	require.ErrorIs(t, err, ErrFrontierStopped)
}

func cloneFrontierQC(t *testing.T, qc *drctypes.QuorumCert) *drctypes.QuorumCert {
	t.Helper()
	b, err := types.Cbor.Marshal(qc)
	require.NoError(t, err)
	var clone drctypes.QuorumCert
	require.NoError(t, types.Cbor.Unmarshal(b, &clone))
	return &clone
}

func TestFrontierSamplerRejectsWeightedTrust(t *testing.T) {
	h := newFrontierHarness(t)
	weighted := *h.trust
	weighted.RootNodes = append([]*types.NodeInfo(nil), h.trust.RootNodes...)
	source := weighted.RootNodes[0]
	weighted.RootNodes[0] = &types.NodeInfo{NodeID: source.NodeID, SigKey: bytes.Clone(source.SigKey), Stake: 2}
	_, err := newFrontierSampler(FrontierSamplerConfig{TrustBase: &weighted, QueueSize: 1, MaxPending: 1}, h.store)
	require.Error(t, err)
}

func TestFrontierSamplerRecoveryRefusalAndCleanReplay(t *testing.T) {
	var stores []*frontierFaultStore
	cms, rootNet := createConsensusManagersWithOptions(t, 4, nil, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(FrontierSamplerConfig{TrustBase: tb, QueueSize: 2, MaxPending: 4})}
	}, func(store PersistentStore) PersistentStore {
		wrapped := &frontierFaultStore{PersistentStore: store, reader: store.(frontierSafetyReader)}
		stores = append(stores, wrapped)
		return wrapped
	})
	for _, cm := range cms {
		cm.leaderSelector = constLeader{leader: cms[0].id, nodes: cms[0].Validators()}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var running atomic.Int32
	run := func(cm *ConsensusManager) {
		running.Add(1)
		go func() {
			defer running.Add(-1)
			require.ErrorIs(t, cm.Run(ctx), context.Canceled)
		}()
	}
	for _, cm := range cms[:3] {
		run(cm)
	}
	t.Cleanup(func() {
		cancel()
		require.Eventually(t, func() bool { return running.Load() == 0 }, 3*time.Second, 20*time.Millisecond)
	})
	require.Eventually(t, func() bool { return cms[0].pacemaker.GetCurrentRound() >= 6 }, 5*time.Second, 20*time.Millisecond)

	late := cms[3]
	lateID := late.id
	rootNet.SetFirewall(func(from, to peer.ID, msg any) bool {
		_, state := msg.(*abdrc.StateMsg)
		return state && to == lateID
	})
	run(late)
	require.Eventually(t, late.recovery.InRecovery, 2*time.Second, 10*time.Millisecond)
	recoveryRound := late.recovery.ToRound()

	req := frontierRequestForManager(t, late)
	requestCtx, requestCancel := context.WithTimeout(context.Background(), time.Second)
	_, err := late.SampleFrontier(requestCtx, req)
	requestCancel()
	require.ErrorIs(t, err, ErrFrontierUnavailable, "incomplete recovery must refuse sampling")

	lateStore := stores[3]
	lateStore.voteGate = make(chan struct{})
	lateStore.voteEntered = make(chan struct{}, 1)
	var releaseVote sync.Once
	release := func() { releaseVote.Do(func() { close(lateStore.voteGate) }) }
	t.Cleanup(release)
	rootNet.SetFirewall(func(from, to peer.ID, msg any) bool { return false })
	select {
	case <-lateStore.voteEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("recovery trigger replay did not reach MakeVote persistence")
	}
	queued := make(chan error, 1)
	go func() {
		_, sampleErr := late.SampleFrontier(context.Background(), req)
		queued <- sampleErr
	}()
	select {
	case sampleErr := <-queued:
		t.Fatalf("sample published inside recovery MakeVote: %v", sampleErr)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	require.Eventually(t, func() bool { return !late.recovery.InRecovery() }, 3*time.Second, 20*time.Millisecond)
	select {
	case sampleErr := <-queued:
		// The immediate post-replay frontier can be conservatively unavailable
		// until a QC covers the just-persisted vote, but it must publish only now.
		if sampleErr != nil {
			require.ErrorIs(t, sampleErr, ErrFrontierUnavailable)
		}
	case <-time.After(time.Second):
		t.Fatal("queued recovery sample was not released")
	}
	var sample *FrontierSample
	require.Eventually(t, func() bool {
		requestCtx, requestCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer requestCancel()
		var sampleErr error
		sample, sampleErr = late.SampleFrontier(requestCtx, req)
		return sampleErr == nil
	}, 4*time.Second, 25*time.Millisecond, "clean recovery must publish only after trigger replay completes")
	require.GreaterOrEqual(t, sample.Safety.HighestVotedRound, recoveryRound, "replayed proposal MakeVote must be persisted before sampling")
	require.GreaterOrEqual(t, sample.View.CommitQC.GetRound(), sample.Safety.HighestQCRound)
}

func frontierRequestForManager(t *testing.T, cm *ConsensusManager) FrontierRequest {
	t.Helper()
	pdr, err := cm.orchestration.ShardConfig(partitionID, shardID, 1)
	require.NoError(t, err)
	hash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	return FrontierRequest{NetworkID: pdr.NetworkID, PartitionID: pdr.PartitionID, ShardID: pdr.ShardID, FullShardConfHash: hash}
}

func TestFrontierSamplerPostWriteRecoveryFailureStaysSticky(t *testing.T) {
	var stores []*frontierFaultStore
	cms, rootNet := createConsensusManagersWithOptions(t, 4, nil, func(tb *types.RootTrustBaseV1) []Option {
		return []Option{WithFrontierSampler(FrontierSamplerConfig{TrustBase: tb, QueueSize: 1, MaxPending: 2})}
	}, func(store PersistentStore) PersistentStore {
		wrapped := &frontierFaultStore{PersistentStore: store, reader: store.(frontierSafetyReader)}
		stores = append(stores, wrapped)
		return wrapped
	})
	for _, cm := range cms {
		cm.leaderSelector = constLeader{leader: cms[0].id, nodes: cms[0].Validators()}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var running atomic.Int32
	run := func(cm *ConsensusManager) {
		running.Add(1)
		go func() { defer running.Add(-1); _ = cm.Run(ctx) }()
	}
	for _, cm := range cms[:3] {
		run(cm)
	}
	t.Cleanup(func() {
		cancel()
		require.Eventually(t, func() bool { return running.Load() == 0 }, 3*time.Second, 20*time.Millisecond)
	})
	require.Eventually(t, func() bool { return cms[0].pacemaker.GetCurrentRound() >= 6 }, 5*time.Second, 20*time.Millisecond)
	late := cms[3]
	failingNet := &frontierFailVoteNet{RootNet: late.net}
	late.net = failingNet
	rootNet.SetFirewall(func(from, to peer.ID, msg any) bool {
		_, state := msg.(*abdrc.StateMsg)
		return state && to == late.id
	})
	run(late)
	require.Eventually(t, late.recovery.InRecovery, 2*time.Second, 10*time.Millisecond)
	failingNet.fail.Store(true)
	rootNet.SetFirewall(func(from, to peer.ID, msg any) bool { return false })
	require.Eventually(t, func() bool { return late.frontier.faulted.Load() }, 3*time.Second, 10*time.Millisecond, "post-write recovered-vote send failure must latch")
	failingNet.fail.Store(false)
	// The replacement root and safety write succeeded, but a later non-I/O
	// continuation failure still leaves persistence status uncertain.
	time.Sleep(100 * time.Millisecond)
	_, err := late.SampleFrontier(context.Background(), frontierRequestForManager(t, late))
	require.ErrorIs(t, err, ErrFrontierUnavailable)
}

func TestFrontierSamplerStickyWriteFaultThroughRealLoop(t *testing.T) {
	for _, tc := range []struct {
		name string
		arm  func(*frontierFaultStore)
	}{
		{"safety", func(s *frontierFaultStore) { s.failSafety.Store(true) }},
		{"block", func(s *frontierFaultStore) { s.failBlock.Store(true) }},
		{"vote", func(s *frontierFaultStore) { s.failVote.Store(true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newFrontierHarness(t)
			h.start(t)
			tc.arm(h.store)
			proposal := rctest.MockAwaitMessage[*abdrc.ProposalMsg](t, h.net, network.ProtocolRootProposal)
			h.net.WaitReceive(t, proposal)
			require.Eventually(t, func() bool { return h.cm.frontier.faulted.Load() }, time.Second, time.Millisecond)
			h.store.failSafety.Store(false)
			h.store.failBlock.Store(false)
			h.store.failVote.Store(false)
			_, err := h.cm.SampleFrontier(context.Background(), h.request(t))
			require.ErrorIs(t, err, ErrFrontierUnavailable)
		})
	}
}

func TestFrontierSamplerCancellationQueueAndPendingBounds(t *testing.T) {
	h := newFrontierHarness(t)
	h.start(t)
	h.commitRoundTwo(t)
	h.store.safetyGate = make(chan struct{})
	h.store.safetyEntered = make(chan struct{}, 1)
	ctx1, cancel1 := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := h.cm.SampleFrontier(ctx1, h.request(t)); first <- err }()
	select {
	case <-h.store.safetyEntered:
	case <-time.After(time.Second):
		t.Fatal("loop did not enter checked safety read")
	}
	second := make(chan error, 1)
	go func() { _, err := h.cm.SampleFrontier(context.Background(), h.request(t)); second <- err }()
	require.Eventually(t, func() bool { return len(h.cm.frontier.pending) == 2 }, time.Second, time.Millisecond)
	_, err := h.cm.SampleFrontier(context.Background(), h.request(t))
	require.ErrorIs(t, err, ErrFrontierBusy)
	cancel1()
	close(h.store.safetyGate)
	require.ErrorIs(t, <-first, context.Canceled)
	require.NoError(t, <-second)
}

func TestFrontierSamplerTimeoutWriteFailureIsStickyThroughLoop(t *testing.T) {
	h := newFrontierHarness(t)
	h.start(t)
	_ = rctest.MockAwaitMessage[*abdrc.ProposalMsg](t, h.net, network.ProtocolRootProposal) // deliberately do not vote
	timeoutVote := rctest.MockAwaitMessage[*abdrc.TimeoutMsg](t, h.net, network.ProtocolRootTimeout)
	h.store.failTC.Store(true)
	h.net.WaitReceive(t, timeoutVote)
	require.Eventually(t, func() bool { return h.cm.frontier.faulted.Load() }, time.Second, time.Millisecond)
	h.store.failTC.Store(false)
	_, err := h.cm.SampleFrontier(context.Background(), h.request(t))
	require.ErrorIs(t, err, ErrFrontierUnavailable)
}
