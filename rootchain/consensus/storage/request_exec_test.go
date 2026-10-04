package storage

import (
	"bytes"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

type fixedHistory struct {
	chain []*RequestActivation
	err   error
}

func (h fixedHistory) Chain(types.PartitionID, types.ShardID) ([]*RequestActivation, error) {
	return h.chain, h.err
}
func (h fixedHistory) Network() uint64 { return fxNetwork }
func (h fixedHistory) Version() uint64 { return fxVersion }
func (h fixedHistory) RootIdentity(uint64) (uint64, []byte, error) {
	return 3, fxBody0, nil
}

// viewVerifier is the view-aware verifier of the executor tests. Its legacy method fails the test: the view branch must never
// fall back to the round-only verifier.
type viewVerifier struct {
	t       *testing.T
	history RequestHistory
	pending *types.InputRecord
	tamper  bool
	calls   int
}

func (v *viewVerifier) VerifyIRChangeReq(uint64, *drctypes.IRChangeReq) (*types.InputRecord, error) {
	v.t.Fatal("the legacy round-only verifier was used under a request history")
	return nil, nil
}
func (v *viewVerifier) RequestHistory() RequestHistory { return v.history }
func (v *viewVerifier) PendingChange(types.PartitionID, types.ShardID) *types.InputRecord {
	return v.pending
}
func (v *viewVerifier) VerifyIRChangeReqView(view *RequestRoundView, req *drctypes.IRChangeReq) (*VerifiedRequest, error) {
	v.calls++
	res, err := view.VerifyIRChangeReq(req, t2Rounds)
	if err == nil && v.tamper {
		res.ViewKey = append([]byte{0xFF}, res.ViewKey...)
	}
	return res, err
}

// execFixture is a unit-weight EVM shard of three identities executing under the view branch: the committed ShardInfo of
// the parent block has no say in who may sign.
type execFixture struct {
	f      *viewFixture
	pdr    *types.PartitionDescriptionRecord
	parent *ExecutedBlock
	key    types.PartitionShardID
	orc    mockOrchestration
	hist   fixedHistory
}

func newExecFixture(t *testing.T) *execFixture {
	f := newViewFixture(t)
	pdr, _ := f.pdr(0, 1, 3, fxBody0, f.member(0, 0, 1), f.member(1, 1, 1), f.member(2, 2, 1))
	parent := genesisBlockWithShard(t, pdr)
	key := types.PartitionShardID{PartitionID: 1, ShardID: types.ShardID{}.Key()}
	st := f.shardAt(pdr, certificationTR(5, 0, f.id(0)))
	si := parent.ShardState.States[key]
	si.RootHash, si.TR, si.LastCR, si.IR = st.RootHash, st.TR, st.LastCR, st.IR
	si.LastCR.UC.UnicitySeal.RootChainRoundNumber = 1 // the block executes at root round 2
	anchor, err := NewRequestAnchor(pdr, crypto.SHA256, 3, fxBody0, fxVersion)
	require.NoError(t, err)
	return &execFixture{f: f, pdr: pdr, parent: parent, key: key, orc: orchestrationOf(pdr), hist: fixedHistory{chain: []*RequestActivation{anchor}}}
}

func certificationTR(round, epoch uint64, leader string) certification.TechnicalRecord {
	return certification.TechnicalRecord{Round: round, Epoch: epoch, Leader: leader}
}

func (e *execFixture) req(idx, keyIdx int, epoch uint64) *certification.BlockCertificationRequest {
	r := &certification.BlockCertificationRequest{PartitionID: 1, ShardID: types.ShardID{}, NodeID: e.f.id(idx), InputRecord: &types.InputRecord{
		Version: 1, RoundNumber: 5, Epoch: epoch, PreviousHash: e.parent.ShardState.States[e.key].RootHash, Hash: []byte{9}, BlockHash: []byte{8},
		SummaryValue: []byte{3}, Timestamp: fxTimestamp}}
	require.NoError(e.f.t, r.Sign(e.f.nodes[keyIdx].Signer))
	return r
}

func (e *execFixture) block(reqs ...*certification.BlockCertificationRequest) *drctypes.BlockData {
	return &drctypes.BlockData{Author: "test", Round: drctypes.GenesisRootRound + 1, Epoch: 0, Timestamp: 12, Payload: &drctypes.Payload{
		Requests: []*drctypes.IRChangeReq{{Partition: 1, CertReason: drctypes.Quorum, Requests: reqs}}}}
}

func (e *execFixture) extend(t *testing.T, v *viewVerifier, reqs ...*certification.BlockCertificationRequest) (*ExecutedBlock, error) {
	return e.parent.Extend(e.block(reqs...), v, e.orc, crypto.SHA256, logger.New(t))
}

func TestExecutionJudgesRequestsUnderTheResolvedView(t *testing.T) {
	e := newExecFixture(t)
	v := &viewVerifier{t: t, history: e.hist}

	t.Run("a quorum of members executes", func(t *testing.T) {
		child, err := e.extend(t, v, e.req(0, 0, 0), e.req(1, 1, 0))
		require.NoError(t, err)
		require.Equal(t, 1, v.calls)
		require.Contains(t, child.ShardState.Changed, e.key)
		require.EqualValues(t, 6, child.ShardState.States[e.key].TR.Round)
		require.Equal(t, []byte{9}, []byte(child.ShardState.States[e.key].IR.Hash))
	})

	t.Run("a signer outside the view is ignored and changes nothing", func(t *testing.T) {
		before := v.calls
		child, err := e.extend(t, v, e.req(0, 0, 0), e.req(4, 4, 0))
		require.NoError(t, err)
		require.Equal(t, before, v.calls, "ineligible requests are not verified")
		require.NotContains(t, child.ShardState.Changed, e.key)
		require.EqualValues(t, 5, child.ShardState.States[e.key].TR.Round)
	})

	t.Run("a request of another epoch is ignored and changes nothing", func(t *testing.T) {
		child, err := e.extend(t, v, e.req(0, 0, 3), e.req(1, 1, 3))
		require.NoError(t, err)
		require.NotContains(t, child.ShardState.Changed, e.key)
		require.EqualValues(t, 5, child.ShardState.States[e.key].TR.Round)
	})

	t.Run("a proof short of quorum invalidates the block", func(t *testing.T) {
		child, err := e.extend(t, v, e.req(0, 0, 0))
		require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
		require.Nil(t, child)
	})

	t.Run("unavailable history fails closed", func(t *testing.T) {
		missing := errors.New("no history")
		_, err := e.extend(t, &viewVerifier{t: t, history: fixedHistory{err: missing}}, e.req(0, 0, 0), e.req(1, 1, 0))
		require.ErrorIs(t, err, ErrAssignmentHistory)
		require.ErrorIs(t, err, missing)
		_, err = e.extend(t, &viewVerifier{t: t, history: fixedHistory{chain: e.hist.chain[:0]}}, e.req(0, 0, 0), e.req(1, 1, 0))
		require.ErrorIs(t, err, ErrAssignmentHistory)
	})

	t.Run("a verifier that judged another view is refused", func(t *testing.T) {
		_, err := e.extend(t, &viewVerifier{t: t, history: e.hist, tamper: true}, e.req(0, 0, 0), e.req(1, 1, 0))
		require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	})

	t.Run("a change already in the pipeline is part of the snapshot", func(t *testing.T) {
		first, err := e.extend(t, v, e.req(0, 0, 0), e.req(1, 1, 0))
		require.NoError(t, err)
		pending := first.ShardState.States[e.key].IR
		_, err = e.extend(t, &viewVerifier{t: t, history: e.hist, pending: pending}, e.req(0, 0, 0), e.req(1, 1, 0))
		require.ErrorIs(t, err, ErrDuplicateChangeReq)
	})

	t.Run("a verifier without history keeps the legacy dispatch", func(t *testing.T) {
		called := false
		legacy := mockIRVerifier{verify: func(uint64, *drctypes.IRChangeReq) (*types.InputRecord, error) {
			called = true
			return e.req(0, 0, 0).InputRecord, nil
		}}
		_, err := e.parent.Extend(e.block(e.req(0, 0, 0)), legacy, e.orc, crypto.SHA256, logger.New(t))
		require.NoError(t, err)
		require.True(t, called)
		// a view-capable verifier whose history is nil is dispatched to the legacy branch as well
		nilHistory := &viewVerifier{t: t}
		require.Nil(t, viewDispatch(nilHistory))
		require.NotNil(t, viewDispatch(v))
	})
}

// A committed handoff authenticates to the activation the resolver reads: the root identity, the activation round and the
// committed successor record come from the verified record, and a record that does not match its body or candidate is refused.
func TestActivationFromHandoffAuthenticatesTheCommittedRecord(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	b := f.build(t, f.candidate(t))
	record := b.freeze
	record.Kind = "commit"
	a, err := ActivationFromHandoff(record, b.body, b.preimage, f.parent, crypto.SHA256, fxVersion)
	require.NoError(t, err)
	require.Equal(t, record.ActivationRound, a.start)
	require.Equal(t, record.Epoch+1, a.rootEpoch)
	require.Equal(t, record.NextBodyID, a.rootBody)
	require.Equal(t, record.SuccessorTRHash, a.trHash)
	require.Equal(t, quorumweight.PolicyUnit, a.ctx.Policy(), "production activations are unit-weighted")

	wrong := record
	wrong.NextBodyID = bytes.Repeat([]byte{2}, 32)
	_, err = ActivationFromHandoff(wrong, b.body, b.preimage, f.parent, crypto.SHA256, fxVersion)
	require.ErrorIs(t, err, ErrAssignmentHistory)
	_, err = ActivationFromHandoff(record, b.body, b.preimage, f.parent, crypto.SHA256, 0)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
}
