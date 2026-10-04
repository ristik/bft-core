package consensus

import (
	"bytes"
	"crypto"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// viewOpts vary what a resolved view builds on. The zero value is the shard of newViewTarget at shard round 0.
type viewOpts struct {
	shardRound uint64        // advances the last certified shard round (and with it the anchor)
	t2         time.Duration // a different configuration is a different assignment
	ucRound    uint64        // root round of the previous UC
	round      uint64        // target root round
	purpose    storage.RequestPurpose
	pending    *types.InputRecord
}

// viewOf resolves the view of the shard of nodes/infos under opts, through the exported snapshot API only.
func viewOf(t *testing.T, infos []*types.NodeInfo, o viewOpts) *storage.RequestRoundView {
	t.Helper()
	if o.t2 == 0 {
		o.t2 = 2500 * time.Millisecond
	}
	if o.ucRound == 0 {
		o.ucRound = 10
	}
	if o.round == 0 {
		o.round = 12
	}
	if o.purpose == 0 {
		o.purpose = storage.PurposeCertify
	}
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 1, PartitionTypeID: 1, ShardID: types.ShardID{},
		UnitIDLen: 256, TypeIDLen: 32, T2Timeout: o.t2, Validators: infos}
	si, err := storage.NewShardInfo(pdr, crypto.SHA256)
	require.NoError(t, err)
	si.RootHash = bytes.Repeat([]byte{0x5C + byte(o.shardRound)}, 32)
	si.TR.Round += o.shardRound
	ir := &types.InputRecord{Version: 1, RoundNumber: si.TR.Round, PreviousHash: []byte{1}, Hash: si.RootHash, BlockHash: []byte{2}, SummaryValue: []byte{3}, Timestamp: 1000}
	si.LastCR = &certification.CertificationResponse{Partition: 1, Technical: si.TR, UC: types.UnicityCertificate{Version: 1, InputRecord: ir,
		UnicitySeal: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: o.ucRound, Timestamp: 1000, Hash: []byte{4}}}}
	body, parent := bytes.Repeat([]byte{0xA0}, 32), bytes.Repeat([]byte{0x9D, byte(o.shardRound)}, 16)
	anchor, err := storage.NewRequestAnchor(pdr, crypto.SHA256, 3, body, 7)
	require.NoError(t, err)
	snap, err := storage.NewRequestSnapshot(5, crypto.SHA256, si, parent, o.pending, anchor)
	require.NoError(t, err)
	digest, err := si.LastCR.UC.Hash(crypto.SHA256)
	require.NoError(t, err)
	view, err := storage.ResolveRequestContext(storage.RequestQuery{Network: 5, Partition: 1, Shard: types.ShardID{}, RootEpoch: 3, RootRound: o.round,
		RootBodyID: body, Version: 7, ParentID: parent, PrevUCDigest: digest, Purpose: o.purpose}, snap)
	require.NoError(t, err)
	return view
}

type fixture struct {
	nodes []*testutils.TestNode
	infos []*types.NodeInfo
}

func newFixture(t *testing.T) *fixture {
	nodes, infos := testutils.CreateTestNodes(t, 3)
	return &fixture{nodes: nodes, infos: infos}
}

// proof is a quorum proof of the first two nodes for the given state hash, built on the view's expected record.
func (f *fixture) proof(t *testing.T, v *storage.RequestRoundView, hash byte) *drctypes.IRChangeReq {
	t.Helper()
	tr := v.ExpectedTR()
	var reqs []*certification.BlockCertificationRequest
	for i := 0; i < 2; i++ {
		req := &certification.BlockCertificationRequest{PartitionID: 1, ShardID: types.ShardID{}, NodeID: f.infos[i].NodeID, InputRecord: &types.InputRecord{
			Version: 1, RoundNumber: tr.Round, PreviousHash: v.PreviousStateHash(), Hash: []byte{hash}, BlockHash: []byte{8}, SummaryValue: []byte{3}, Timestamp: 1000}}
		require.NoError(t, req.Sign(f.nodes[i].Signer))
		reqs = append(reqs, req)
	}
	return &drctypes.IRChangeReq{Partition: 1, Shard: types.ShardID{}, CertReason: drctypes.Quorum, Requests: reqs}
}

func newViewVerifier(t *testing.T) *IRChangeReqVerifier {
	ver, err := NewIRChangeReqVerifier(&Parameters{BlockRate: 900 * time.Millisecond}, &MockState{})
	require.NoError(t, err)
	return ver
}

// fixedResolver answers every query with one view or one error, and counts the queries.
type fixedResolver struct {
	view    *storage.RequestRoundView
	err     error
	queries []storage.RequestPurpose
	rounds  []uint64
}

func (r *fixedResolver) ResolveView(_ types.PartitionID, _ types.ShardID, round uint64, p storage.RequestPurpose) (*storage.RequestRoundView, error) {
	r.queries, r.rounds = append(r.queries, p), append(r.rounds, round)
	return r.view, r.err
}

var shard1 = types.ShardID{}

func inBuffer(b *IrReqBuffer) bool { return b.IsChangeInBuffer(1, shard1) }

func noneInProgress(types.PartitionID, types.ShardID) *types.InputRecord { return nil }

func TestAddViewRefusalsLeaveTheBufferUnchanged(t *testing.T) {
	f := newFixture(t)
	v := viewOf(t, f.infos, viewOpts{})
	ver := newViewVerifier(t)
	b := NewIrReqBuffer(logger.New(t))

	require.ErrorIs(t, b.AddView(nil, f.proof(t, v, 9), ver), drctypes.ErrInvalidRequest)
	require.ErrorIs(t, b.AddView(v, nil, ver), drctypes.ErrInvalidRequest)
	timeout := &drctypes.IRChangeReq{Partition: 1, CertReason: drctypes.T2Timeout}
	require.ErrorContains(t, b.AddView(v, timeout, ver), "timeout can only be proposed by leader")
	one := f.proof(t, v, 9)
	one.Requests = one.Requests[:1]
	require.ErrorIs(t, b.AddView(v, one, ver), quorumweight.ErrQuorumNotReached, "a proof short of the quorum is refused by the verifier")
	require.False(t, inBuffer(b))

	p2 := NewIrReqBuffer(logger.New(t), 2)
	require.ErrorIs(t, p2.AddView(v, &drctypes.IRChangeReq{Partition: drctypes.ControlPartition, CertReason: drctypes.Quorum}, ver), drctypes.ErrControlPartition)

	// a collection view of the assignment in force (no successor committed) is not collection-only
	coll := viewOf(t, f.infos, viewOpts{purpose: storage.PurposeCollect})
	require.False(t, coll.CollectionOnly())
	require.NoError(t, b.AddView(coll, f.proof(t, coll, 9), ver))
}

func TestAddViewBuffersOwnedTaggedCopyAndComparesWithinOneView(t *testing.T) {
	f := newFixture(t)
	v := viewOf(t, f.infos, viewOpts{})
	ver := newViewVerifier(t)
	b := NewIrReqBuffer(logger.New(t))

	p := f.proof(t, v, 9)
	require.NoError(t, b.AddView(v, p, ver))
	require.True(t, inBuffer(b))
	entry := b.irChgReqBuffer[types.PartitionShardID{PartitionID: 1, ShardID: shard1.Key()}]
	require.Equal(t, v.AssignmentKey(), entry.assignKey)
	require.Equal(t, v.RoundTag(), entry.roundTag)
	require.Equal(t, v.ViewKey(), entry.viewKey)
	require.Len(t, entry.proofDigest, 32)
	require.NotSame(t, p, entry.Req, "the buffer owns a copy of the proof")
	p.Requests[0].InputRecord.Hash[0] ^= 0xFF
	require.EqualValues(t, 9, entry.Req.Requests[0].InputRecord.Hash[0], "mutating the caller's proof does not change the buffered one")

	require.NoError(t, b.AddView(v, f.proof(t, v, 9), ver), "the same result under the same view is a duplicate")
	require.ErrorContains(t, b.AddView(v, f.proof(t, v, 7), ver), "equivocating request", "another result under the same view is equivocation")
	timeoutReason := f.proof(t, v, 9)
	timeoutReason.CertReason = drctypes.QuorumNotPossible
	require.Error(t, b.AddView(v, timeoutReason, ver))
}

// A proof buffered under an earlier shard round, anchor or assignment is retired before the comparison: it neither makes fresh
// work look equivocating nor survives it. A failed fresh add retires nothing.
func TestAddViewRetiresStaleEntriesBeforeTheEquivocationCheck(t *testing.T) {
	f := newFixture(t)
	ver := newViewVerifier(t)
	old := viewOf(t, f.infos, viewOpts{})
	for name, fresh := range map[string]*storage.RequestRoundView{
		"advanced shard round/anchor": viewOf(t, f.infos, viewOpts{shardRound: 1}),
		"another assignment":          viewOf(t, f.infos, viewOpts{t2: 4 * time.Second}),
	} {
		t.Run(name, func(t *testing.T) {
			b := NewIrReqBuffer(logger.New(t))
			require.NoError(t, b.AddView(old, f.proof(t, old, 9), ver))
			key := types.PartitionShardID{PartitionID: 1, ShardID: shard1.Key()}
			oldDigest := b.irChgReqBuffer[key].proofDigest

			bad := f.proof(t, fresh, 7)
			bad.Requests = bad.Requests[:1]
			require.ErrorIs(t, b.AddView(fresh, bad, ver), quorumweight.ErrQuorumNotReached)
			require.Equal(t, oldDigest, b.irChgReqBuffer[key].proofDigest, "a refused add retires nothing")

			require.NoError(t, b.AddView(fresh, f.proof(t, fresh, 7), ver), "different result under the fresh view is not equivocation")
			require.Equal(t, fresh.ViewKey(), b.irChgReqBuffer[key].viewKey)
			require.Equal(t, fresh.RoundTag(), b.irChgReqBuffer[key].roundTag)
			require.NotEqual(t, oldDigest, b.irChgReqBuffer[key].proofDigest)
		})
	}
	require.NotEqual(t, old.AssignmentKey(), viewOf(t, f.infos, viewOpts{t2: 4 * time.Second}).AssignmentKey())
	require.Equal(t, old.AssignmentKey(), viewOf(t, f.infos, viewOpts{shardRound: 1}).AssignmentKey())
	require.NotEqual(t, old.RoundTag(), viewOf(t, f.infos, viewOpts{shardRound: 1}).RoundTag())
}

func TestGeneratePayloadViewKeepsOnlyFreshlyVerifiedEntries(t *testing.T) {
	f := newFixture(t)
	ver := newViewVerifier(t)
	old := viewOf(t, f.infos, viewOpts{})
	fresh := viewOf(t, f.infos, viewOpts{shardRound: 1})
	timeouts := []*types.UnicityCertificate{{InputRecord: &types.InputRecord{}, UnicityTreeCertificate: &types.UnicityTreeCertificate{Partition: 1}, UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: 10}}}

	// a proof buffered under the old view survives to the proposal of the fresh round: it is discarded, enters no payload and
	// does not suppress the eligible timeout
	b := NewIrReqBuffer(logger.New(t))
	require.NoError(t, b.AddView(old, f.proof(t, old, 9), ver))
	res := &fixedResolver{view: fresh}
	payload, err := b.GeneratePayloadView(12, timeouts, noneInProgress, res, ver)
	require.NoError(t, err)
	require.Len(t, payload.Requests, 1)
	require.Equal(t, drctypes.T2Timeout, payload.Requests[0].CertReason, "the stale proof suppressed nothing")
	require.Empty(t, payload.Requests[0].Requests, "a timeout proof stays empty")
	require.Equal(t, []storage.RequestPurpose{storage.PurposeCertify}, res.queries)
	require.False(t, inBuffer(b), "the buffer is cleared once the payload is done")

	// a proof verified under the fresh view enters the payload and suppresses the timeout
	b = NewIrReqBuffer(logger.New(t))
	require.NoError(t, b.AddView(fresh, f.proof(t, fresh, 9), ver))
	payload, err = b.GeneratePayloadView(12, timeouts, noneInProgress, res, ver)
	require.NoError(t, err)
	require.Len(t, payload.Requests, 1)
	require.Equal(t, drctypes.Quorum, payload.Requests[0].CertReason)

	// eligibility is rechecked even when the assignment is unchanged: a change in the pipeline now blocks the entry
	b = NewIrReqBuffer(logger.New(t))
	require.NoError(t, b.AddView(old, f.proof(t, old, 9), ver))
	pending := viewOf(t, f.infos, viewOpts{pending: &types.InputRecord{Version: 1, RoundNumber: 1, Hash: []byte{1}}})
	payload, err = b.GeneratePayloadView(12, nil, noneInProgress, &fixedResolver{view: pending}, ver)
	require.NoError(t, err)
	require.Empty(t, payload.Requests, "the pending change makes the buffered proof ineligible")

	// the in-progress check of the pipeline is kept for fresh entries too
	b = NewIrReqBuffer(logger.New(t))
	require.NoError(t, b.AddView(fresh, f.proof(t, fresh, 9), ver))
	payload, err = b.GeneratePayloadView(12, timeouts, func(types.PartitionID, types.ShardID) *types.InputRecord { return &types.InputRecord{} }, res, ver)
	require.NoError(t, err)
	require.Empty(t, payload.Requests)

	// control partition timeouts and nil UCs are skipped in the handoff profile
	b = NewIrReqBuffer(logger.New(t), 2)
	control := []*types.UnicityCertificate{nil, {InputRecord: &types.InputRecord{}, UnicityTreeCertificate: &types.UnicityTreeCertificate{Partition: drctypes.ControlPartition}, UnicitySeal: &types.UnicitySeal{}}}
	payload, err = b.GeneratePayloadView(12, control, noneInProgress, res, ver)
	require.NoError(t, err)
	require.Empty(t, payload.Requests)
}

// An unresolvable view aborts the proposal with the history error: the buffer stays as it was, no timeout is dropped and
// nothing is answered from other state.
func TestGeneratePayloadViewAbortsWhenAViewCannotBeResolved(t *testing.T) {
	f := newFixture(t)
	ver := newViewVerifier(t)
	v := viewOf(t, f.infos, viewOpts{})
	b := NewIrReqBuffer(logger.New(t))
	require.NoError(t, b.AddView(v, f.proof(t, v, 9), ver))

	payload, err := b.GeneratePayloadView(12, nil, noneInProgress, &fixedResolver{err: storage.ErrAssignmentHistory}, ver)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	require.Nil(t, payload)
	require.True(t, inBuffer(b), "the buffer is not cleared by an aborted proposal")
	payload, err = b.GeneratePayloadView(12, nil, noneInProgress, &fixedResolver{view: v}, ver)
	require.NoError(t, err)
	require.Len(t, payload.Requests, 1, "the same entry is proposed once the history is back")
}

func TestT2TimeoutsUnderViewsAreElapsedRoundsOfTheViewsPreviousUC(t *testing.T) {
	f := newFixture(t)
	const t2 = 6 // uint64(2500ms / 450ms) + 1
	ucs := func() []*types.UnicityCertificate {
		return []*types.UnicityCertificate{{InputRecord: &types.InputRecord{}, UnicityTreeCertificate: &types.UnicityTreeCertificate{Partition: 1}, UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: 999}}}
	}
	gen := func(profile uint64, state *MockState) *PartitionTimeoutGenerator {
		state.certificates = ucs()
		g, err := NewLucBasedT2TimeoutGenerator(&Parameters{BlockRate: 900 * time.Millisecond, NetworkProfileVersion: profile}, state)
		require.NoError(t, err)
		return g
	}

	early := viewOf(t, f.infos, viewOpts{round: 10 + t2 - 1, purpose: storage.PurposeTimeout})
	due := viewOf(t, f.infos, viewOpts{round: 10 + t2, purpose: storage.PurposeTimeout})
	got, err := gen(0, &MockState{}).GetT2TimeoutsView(10+t2-1, &fixedResolver{view: early})
	require.NoError(t, err)
	require.Empty(t, got, "one round short")
	res := &fixedResolver{view: due}
	got, err = gen(0, &MockState{}).GetT2TimeoutsView(10+t2, res)
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.EqualValues(t, 10, got[0].GetRootRoundNumber(), "the view's previous UC, not the state's certificate list, supplies the frozen anchor")
	require.Equal(t, []storage.RequestPurpose{storage.PurposeTimeout}, res.queries)

	// a longer configured T2 under another assignment is later; weights and keys never enter
	slow := viewOf(t, f.infos, viewOpts{round: 10 + t2, purpose: storage.PurposeTimeout, t2: 10 * time.Second})
	got, err = gen(0, &MockState{}).GetT2TimeoutsView(10+t2, &fixedResolver{view: slow})
	require.NoError(t, err)
	require.Empty(t, got)

	// pipeline and view-level pending changes exclude the shard
	got, err = gen(0, &MockState{inProgress: []types.PartitionID{1}, irInProgress: &types.InputRecord{}}).GetT2TimeoutsView(10+t2, &fixedResolver{view: due})
	require.NoError(t, err)
	require.Empty(t, got)
	pend := viewOf(t, f.infos, viewOpts{round: 10 + t2, purpose: storage.PurposeTimeout, pending: &types.InputRecord{Version: 1, RoundNumber: 1, Hash: []byte{1}}})
	got, err = gen(0, &MockState{}).GetT2TimeoutsView(10+t2, &fixedResolver{view: pend})
	require.NoError(t, err)
	require.Empty(t, got)

	// the previous UC's own round is not before it: no error, and nothing is due yet
	same := viewOf(t, f.infos, viewOpts{round: 10, purpose: storage.PurposeTimeout})
	got, err = gen(0, &MockState{}).GetT2TimeoutsView(10, &fixedResolver{view: same})
	require.NoError(t, err)
	require.Empty(t, got)

	// a target round before the previous UC is refused before any subtraction
	got, err = gen(0, &MockState{}).GetT2TimeoutsView(9, &fixedResolver{view: due})
	require.ErrorIs(t, err, storage.ErrStaleRequestContext)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	require.Empty(t, got)

	// no history: reported, never a timeout from other state
	got, err = gen(0, &MockState{}).GetT2TimeoutsView(10+t2, &fixedResolver{err: storage.ErrAssignmentHistory})
	require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	require.Empty(t, got)
	require.False(t, errors.Is(err, storage.ErrStaleRequestContext))

	// control partition exclusion and no-UC exclusion are kept
	ctl := &MockState{certificates: []*types.UnicityCertificate{nil, {InputRecord: &types.InputRecord{}, UnicityTreeCertificate: &types.UnicityTreeCertificate{Partition: drctypes.ControlPartition}, UnicitySeal: &types.UnicitySeal{}}}}
	g, err := NewLucBasedT2TimeoutGenerator(&Parameters{BlockRate: 900 * time.Millisecond, NetworkProfileVersion: 2}, ctl)
	require.NoError(t, err)
	got, err = g.GetT2TimeoutsView(10+t2, &fixedResolver{err: errors.New("must not be asked")})
	require.NoError(t, err)
	require.Empty(t, got)
}

// The manager buffers under the view resolved for the next proposal; a resolution failure buffers nothing.
func TestManagerBuffersUnderTheViewOfTheNextProposal(t *testing.T) {
	f := newFixture(t)
	v := viewOf(t, f.infos, viewOpts{})
	pm := &Pacemaker{}
	pm.currentRound.Store(11)
	res := &fixedResolver{view: v}
	x := &ConsensusManager{irReqBuffer: NewIrReqBuffer(logger.New(t)), pacemaker: pm, irReqVerifier: newViewVerifier(t)}
	x.SetViewResolver(res)
	require.NoError(t, x.bufferIRChange(f.proof(t, v, 9)))
	require.True(t, inBuffer(x.irReqBuffer))
	require.Equal(t, []uint64{12}, res.rounds)
	require.Equal(t, []storage.RequestPurpose{storage.PurposeCertify}, res.queries)

	x.irReqBuffer = NewIrReqBuffer(logger.New(t))
	res.err = storage.ErrAssignmentHistory
	require.ErrorIs(t, x.bufferIRChange(f.proof(t, v, 9)), storage.ErrAssignmentHistory)
	require.False(t, inBuffer(x.irReqBuffer))
}

func TestRequestViewResolverResolvesFromTheSuppliedParentOnly(t *testing.T) {
	_, err := NewRequestViewResolver(nil, crypto.SHA256, func(types.PartitionID, types.ShardID) (*storage.ShardInfo, []byte, *types.InputRecord, error) {
		return nil, nil, nil, nil
	}, nil)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	_, err = NewRequestViewResolver(&fakeHistory{}, crypto.SHA256, nil, nil)
	require.Error(t, err)
	r, err := NewRequestViewResolver(&fakeHistory{}, crypto.SHA256, func(types.PartitionID, types.ShardID) (*storage.ShardInfo, []byte, *types.InputRecord, error) {
		return nil, nil, nil, errors.New("no parent")
	}, nil)
	require.NoError(t, err)
	_, err = r.ResolveView(1, shard1, 12, storage.PurposeCertify)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory, "a missing parent is missing history, never a fallback")
	r, err = NewRequestViewResolver(&fakeHistory{}, crypto.SHA256, func(types.PartitionID, types.ShardID) (*storage.ShardInfo, []byte, *types.InputRecord, error) {
		return nil, nil, nil, nil
	}, nil)
	require.NoError(t, err)
	_, err = r.ResolveView(1, shard1, 12, storage.PurposeCertify)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory)
}

func TestRecoveryKeepsTheRequestHistoryOfTheViewBranch(t *testing.T) {
	old, fresh := newViewVerifier(t), newViewVerifier(t)
	carryRequestHistory(nil, fresh)
	require.Nil(t, fresh.RequestHistory(), "production has none and keeps the legacy dispatch")
	carryRequestHistory(old, fresh)
	require.Nil(t, fresh.RequestHistory())
	h := &fakeHistory{}
	old.SetRequestHistory(h)
	carryRequestHistory(old, fresh)
	require.Same(t, h, fresh.RequestHistory(), "recovery does not drop the committed history")
	carryRequestHistory(old, nil)
}

// acceptAll is a verifier that admits anything: the buffer's own guards must hold without relying on the real verifier.
type acceptAll struct{}

func (acceptAll) VerifyIRChangeReqView(v *storage.RequestRoundView, req *drctypes.IRChangeReq) (*storage.VerifiedRequest, error) {
	return &storage.VerifiedRequest{IR: &types.InputRecord{Version: 1}, ViewKey: []byte{1}, ProofDigest: []byte{2}}, nil
}

func TestAddViewGuardsHoldWithoutTheVerifier(t *testing.T) {
	f := newFixture(t)
	v := viewOf(t, f.infos, viewOpts{})
	b := NewIrReqBuffer(logger.New(t))
	require.ErrorIs(t, b.AddView(nil, f.proof(t, v, 9), acceptAll{}), drctypes.ErrInvalidRequest)
	require.ErrorIs(t, b.AddView(v, nil, acceptAll{}), drctypes.ErrInvalidRequest)
	require.False(t, inBuffer(b))
}

// With nothing buffered, a change in the pipeline alone keeps the timeout out of the payload.
func TestGeneratePayloadViewSuppressesTimeoutsOfShardsInProgress(t *testing.T) {
	f := newFixture(t)
	v := viewOf(t, f.infos, viewOpts{})
	timeouts := []*types.UnicityCertificate{{InputRecord: &types.InputRecord{}, UnicityTreeCertificate: &types.UnicityTreeCertificate{Partition: 1}, UnicitySeal: &types.UnicitySeal{RootChainRoundNumber: 10}}}
	b := NewIrReqBuffer(logger.New(t))
	busy := func(types.PartitionID, types.ShardID) *types.InputRecord { return &types.InputRecord{} }
	payload, err := b.GeneratePayloadView(12, timeouts, busy, &fixedResolver{view: v}, newViewVerifier(t))
	require.NoError(t, err)
	require.Empty(t, payload.Requests)
	payload, err = b.GeneratePayloadView(12, timeouts, noneInProgress, &fixedResolver{view: v}, newViewVerifier(t))
	require.NoError(t, err)
	require.Len(t, payload.Requests, 1)
}
