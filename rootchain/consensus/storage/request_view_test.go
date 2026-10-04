package storage

import (
	"bytes"
	"crypto"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

const (
	fxNetwork   = 5
	fxVersion   = 7
	fxActivate  = 20 // A*
	fxUCRound   = 10 // root round of the previous UC
	fxTimestamp = 1000
)

var (
	fxBody0 = bytes.Repeat([]byte{0xA0}, 32) // root body of the anchor assignment
	fxBody1 = bytes.Repeat([]byte{0xB1}, 32) // root body of the successor assignment
)

// viewFixture is an EVM shard (type 8) whose assignment moves from epoch 0 to epoch 1 at root round A*. Six keys exist: the
// old set uses 0..3, the successor rotates one and retires one (see rotated).
type viewFixture struct {
	t     *testing.T
	nodes []*testutils.TestNode // sorted by node id
	infos []*types.NodeInfo
}

func newViewFixture(t *testing.T) *viewFixture {
	t.Helper()
	nodes, _ := testutils.CreateTestNodes(t, 6)
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].NodeInfo(t).NodeID < nodes[j].NodeInfo(t).NodeID })
	f := &viewFixture{t: t, nodes: nodes}
	for _, n := range nodes {
		f.infos = append(f.infos, n.NodeInfo(t))
	}
	return f
}

func (f *viewFixture) id(i int) string { return f.infos[i].NodeID }

// member is the validator of node key keyOf under the identity of node idOf, with the given weight.
func (f *viewFixture) member(idOf, keyOf int, stake uint64) *types.NodeInfo {
	return &types.NodeInfo{NodeID: f.id(idOf), SigKey: bytes.Clone(f.infos[keyOf].SigKey), Stake: stake}
}

// pdr is the type-8 configuration of an epoch with its coupled root assignment (fresh root keys, equal weights).
func (f *viewFixture) pdr(epoch, start, rootEpoch uint64, body []byte, validators ...*types.NodeInfo) (*types.PartitionDescriptionRecord, *quorumweight.Coupling) {
	f.t.Helper()
	sort.Slice(validators, func(i, j int) bool { return validators[i].NodeID < validators[j].NodeID })
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: fxNetwork, PartitionID: 1, PartitionTypeID: evmassign.EVMPartitionTypeID,
		ShardID: types.ShardID{}, UnitIDLen: 256, TypeIDLen: 32, T2Timeout: 2500 * time.Millisecond, Epoch: epoch, EpochStart: start, Validators: validators}
	var root []evmassign.RootMember
	var bind []evmassign.Binding
	for _, v := range validators {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(f.t, err)
		ver, err := s.Verifier()
		require.NoError(f.t, err)
		key, err := ver.MarshalPublicKey()
		require.NoError(f.t, err)
		root = append(root, evmassign.RootMember{NodeID: "root-" + v.NodeID, Key: key, Weight: v.Stake})
		bind = append(bind, evmassign.Binding{RootNodeID: "root-" + v.NodeID, EVMNodeID: v.NodeID})
	}
	return pdr, &quorumweight.Coupling{RootEpoch: rootEpoch, RootBodyID: body, Root: root, Bindings: bind}
}

func (f *viewFixture) weighted(pdr *types.PartitionDescriptionRecord, c *quorumweight.Coupling, rootEpoch uint64, body []byte, start uint64, trHash []byte) *RequestActivation {
	f.t.Helper()
	a, err := newRequestActivation(pdr, crypto.SHA256, quorumweight.PolicyEVMWeighted, c, rootEpoch, body, start, trHash, fxVersion)
	require.NoError(f.t, err)
	return a
}

// shardAt is the verified parent state of the shard: configuration conf installed, last certified record lastTR under the
// UC of root round fxUCRound. It is built on a unit copy so NewShardInfo accepts it, then bound to conf's hash.
func (f *viewFixture) shardAt(conf *types.PartitionDescriptionRecord, lastTR certification.TechnicalRecord) *ShardInfo {
	f.t.Helper()
	unit := *conf
	unit.Validators = nil
	for _, v := range conf.Validators {
		unit.Validators = append(unit.Validators, &types.NodeInfo{NodeID: v.NodeID, SigKey: v.SigKey, Stake: 1})
	}
	si, err := NewShardInfo(&unit, crypto.SHA256)
	require.NoError(f.t, err)
	h, err := conf.Hash(crypto.SHA256)
	require.NoError(f.t, err)
	si.ShardConfHash = h
	si.RootHash = bytes.Repeat([]byte{0x5C}, 32)
	var herr error
	lastTR.StatHash, herr = si.statHash(crypto.SHA256)
	require.NoError(f.t, herr)
	lastTR.FeeHash, herr = si.feeHash(crypto.SHA256)
	require.NoError(f.t, herr)
	si.TR = lastTR
	ir := &types.InputRecord{Version: 1, RoundNumber: lastTR.Round, Epoch: lastTR.Epoch, PreviousHash: []byte{1}, Hash: si.RootHash, BlockHash: []byte{2},
		SummaryValue: []byte{3}, Timestamp: fxTimestamp}
	si.IR = ir
	si.LastCR = &certification.CertificationResponse{Partition: conf.PartitionID, Shard: conf.ShardID, Technical: lastTR,
		UC: types.UnicityCertificate{Version: 1, InputRecord: ir, UnicitySeal: &types.UnicitySeal{Version: 1, NetworkID: fxNetwork,
			RootChainRoundNumber: fxUCRound, Timestamp: fxTimestamp, Hash: []byte{4}}}}
	return si
}

func (f *viewFixture) tr(epoch, round uint64, si *ShardInfo) certification.TechnicalRecord {
	return certification.TechnicalRecord{Round: round, Epoch: epoch, Leader: f.id(0), StatHash: bytes.Clone(si.TR.StatHash), FeeHash: bytes.Clone(si.TR.FeeHash)}
}

// scenario is the lagging-boundary fixture: weights (6,1,1,1) at epoch 0 and (1,6,1,1) at epoch 1 for the same four keys.
type scenario struct {
	f        *viewFixture
	pdr0     *types.PartitionDescriptionRecord
	pdr1     *types.PartitionDescriptionRecord
	anchor   *RequestActivation
	succ     *RequestActivation
	parent   *ShardInfo // committed state, still at epoch 0
	succTR   certification.TechnicalRecord
	trHash   []byte
	parentID []byte
}

func newScenario(t *testing.T, w0, w1 []uint64, mk1 func(f *viewFixture, w []uint64) []*types.NodeInfo) *scenario {
	t.Helper()
	f := newViewFixture(t)
	var v0 []*types.NodeInfo
	for i, w := range w0 {
		v0 = append(v0, f.member(i, i, w))
	}
	pdr0, c0 := f.pdr(0, 1, 3, fxBody0, v0...)
	var v1 []*types.NodeInfo
	if mk1 != nil {
		v1 = mk1(f, w1)
	} else {
		for i, w := range w1 {
			v1 = append(v1, f.member(i, i, w))
		}
	}
	pdr1, c1 := f.pdr(1, fxActivate, 4, fxBody1, v1...)
	s := &scenario{f: f, pdr0: pdr0, pdr1: pdr1, parentID: bytes.Repeat([]byte{0x9D}, 32)}
	base := f.shardAt(pdr0, certification.TechnicalRecord{Round: 5, Epoch: 0, Leader: f.id(0)})
	base.TR = f.tr(0, 5, base)
	s.parent = f.shardAt(pdr0, base.TR)
	var err error
	s.succTR, err = successorTechnicalRecordWith(s.parent, pdr1, crypto.SHA256, resetMembers)
	require.NoError(t, err)
	s.trHash, err = s.succTR.Hash()
	require.NoError(t, err)
	s.anchor = f.weighted(pdr0, c0, 3, fxBody0, 0, nil)
	s.anchor.start = 0
	s.succ = f.weighted(pdr1, c1, 4, fxBody1, fxActivate, s.trHash)
	return s
}

func (s *scenario) snapshot(parent *ShardInfo, pending *types.InputRecord) *RequestSnapshot {
	s.f.t.Helper()
	snap, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, parent, s.parentID, pending, s.anchor, s.succ)
	require.NoError(s.f.t, err)
	return snap
}

func (s *scenario) query(snap *RequestSnapshot, round uint64, epoch uint64, body []byte, p RequestPurpose) RequestQuery {
	return RequestQuery{Network: fxNetwork, Partition: 1, Shard: types.ShardID{}, RootEpoch: epoch, RootRound: round, RootBodyID: body, Version: fxVersion,
		ParentID: s.parentID, PrevUCDigest: snap.parent.ucDigest, Purpose: p}
}

// request is a block certification request of node idx (signing with key keyIdx) built on the view's expected record.
func (s *scenario) request(v *RequestRoundView, idx, keyIdx int, ir byte) *certification.BlockCertificationRequest {
	s.f.t.Helper()
	tr := v.ExpectedTR()
	req := &certification.BlockCertificationRequest{PartitionID: 1, ShardID: types.ShardID{}, NodeID: s.f.id(idx), InputRecord: &types.InputRecord{
		Version: 1, RoundNumber: tr.Round, Epoch: tr.Epoch, PreviousHash: v.PreviousStateHash(), Hash: []byte{ir}, BlockHash: []byte{ir, ir}, SummaryValue: []byte{3},
		Timestamp: fxTimestamp}}
	require.NoError(s.f.t, req.Sign(s.f.nodes[keyIdx].Signer))
	return req
}

func quorumProof(reqs ...*certification.BlockCertificationRequest) *rctypes.IRChangeReq {
	return &rctypes.IRChangeReq{Partition: 1, Shard: types.ShardID{}, CertReason: rctypes.Quorum, Requests: reqs}
}

func (s *scenario) resolve(snap *RequestSnapshot, round uint64, epoch uint64, body []byte, p RequestPurpose) (*RequestRoundView, error) {
	return ResolveRequestContext(s.query(snap, round, epoch, body, p), snap)
}

func (s *scenario) mustResolve(snap *RequestSnapshot, round uint64, epoch uint64, body []byte, p RequestPurpose) *RequestRoundView {
	s.f.t.Helper()
	v, err := s.resolve(snap, round, epoch, body, p)
	require.NoError(s.f.t, err)
	return v
}

const t2Rounds = 6

// Fixture 3 of the design: old weights (6,1,1,1), successor (1,6,1,1) for the same four keys. The committed state is
// deliberately behind the activation throughout.
func TestRetainedKeyWeightChangeAcrossTheBoundary(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)

	// before A*: the old assignment, W=9 Q=5, key 0 weighs 6 and certifies alone
	old := s.mustResolve(snap, fxActivate-1, 3, fxBody0, PurposeCertify)
	require.EqualValues(t, 9, old.Context().TotalWeight())
	require.EqualValues(t, 5, old.Context().Threshold())
	oldProof := quorumProof(s.request(old, 0, 0, 1))
	res, err := old.VerifyIRChangeReq(oldProof, t2Rounds)
	require.NoError(t, err)
	require.Equal(t, old.ViewKey(), res.ViewKey)
	_, err = old.VerifyIRChangeReq(quorumProof(s.request(old, 1, 1, 1), s.request(old, 2, 2, 1), s.request(old, 3, 3, 1)), t2Rounds)
	require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached, "three light identities weigh 3 of 5")

	// at A*, with the committed state still at epoch 0: the successor assignment, key 0 weighs 1 and key 1 weighs 6
	nw := s.mustResolve(snap, fxActivate, 4, fxBody1, PurposeCertify)
	require.EqualValues(t, 9, nw.Context().TotalWeight())
	w0, _ := nw.Context().SignerWeight(s.f.id(0))
	w1, _ := nw.Context().SignerWeight(s.f.id(1))
	require.EqualValues(t, 1, w0, "no old/new weight mixing: the retained key weighs what the successor says")
	require.EqualValues(t, 6, w1)
	require.EqualValues(t, 1, nw.ExpectedTR().Epoch)
	require.Equal(t, s.succTR.Round, nw.ExpectedTR().Round)
	require.NotEqual(t, old.AssignmentKey(), nw.AssignmentKey())

	// the old-epoch A-only proof worked historically and is stale now; the old view does not become eligible again
	require.ErrorIs(t, nw.ValidRequest(oldProof.Requests[0]), ErrStaleRequestContext)
	_, err = nw.VerifyIRChangeReq(oldProof, t2Rounds)
	require.ErrorIs(t, err, ErrStaleRequestContext)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)

	// a fresh successor request of key 0 alone cannot certify; key 1 alone does
	_, err = nw.VerifyIRChangeReq(quorumProof(s.request(nw, 0, 0, 2)), t2Rounds)
	require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
	res, err = nw.VerifyIRChangeReq(quorumProof(s.request(nw, 1, 1, 2)), t2Rounds)
	require.NoError(t, err)
	require.Equal(t, nw.ViewKey(), res.ViewKey)
	require.NotEqual(t, old.ViewKey(), res.ViewKey)
	// and the successor's three light identities (weight 1+1+1) are not a quorum of 9
	_, err = nw.VerifyIRChangeReq(quorumProof(s.request(nw, 0, 0, 2), s.request(nw, 2, 2, 2), s.request(nw, 3, 3, 2)), t2Rounds)
	require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached)
}

// The successor rotates the key of identity 2 (new key from node 5) and retires identity 3, adding identity 4.
func rotateAndRetire(f *viewFixture, w []uint64) []*types.NodeInfo {
	return []*types.NodeInfo{f.member(0, 0, w[0]), f.member(1, 1, w[1]), f.member(2, 5, w[2]), f.member(4, 4, w[3])}
}

func TestRotatedAndRetiredKeysAreRefusedUnderTheSuccessorOnly(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 2, 1, 1}, rotateAndRetire)
	snap := s.snapshot(s.parent, nil)
	old := s.mustResolve(snap, fxActivate-1, 3, fxBody0, PurposeCertify)
	nw := s.mustResolve(snap, fxActivate, 4, fxBody1, PurposeCertify)

	// identity 3 is valid before the boundary, retired after it
	require.NoError(t, old.ValidRequest(s.request(old, 3, 3, 1)))
	retired := s.request(nw, 3, 3, 1)
	err := nw.ValidRequest(retired)
	require.ErrorIs(t, err, ErrNodeNotInTrustBase)
	require.ErrorIs(t, err, quorumweight.ErrUnknownSigner)

	// identity 2 keeps its id and changes its key: the retired key is refused, the new one is accepted
	require.NoError(t, old.ValidRequest(s.request(old, 2, 2, 1)))
	err = nw.ValidRequest(s.request(nw, 2, 2, 1))
	require.ErrorIs(t, err, quorumweight.ErrInvalidSignature)
	require.NoError(t, nw.ValidRequest(s.request(nw, 2, 5, 1)))

	// the added identity is unknown to the old view
	err = old.ValidRequest(s.request(old, 4, 4, 1))
	require.ErrorIs(t, err, quorumweight.ErrUnknownSigner)
	require.NoError(t, nw.ValidRequest(s.request(nw, 4, 4, 1)))

	// a proof carrying a retired signer is refused whole, with no result
	res, err := nw.VerifyIRChangeReq(quorumProof(s.request(nw, 0, 0, 1), s.request(nw, 3, 3, 1), s.request(nw, 1, 1, 1)), t2Rounds)
	require.ErrorIs(t, err, ErrNodeNotInTrustBase)
	require.Nil(t, res)
}

func TestCollectionMayResolveTheSuccessorButNeverCertifies(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)

	col := s.mustResolve(snap, fxActivate-3, 4, fxBody1, PurposeCollect)
	require.True(t, col.CollectionOnly())
	require.EqualValues(t, 1, col.ExpectedTR().Epoch)
	require.NoError(t, col.ValidRequest(s.request(col, 1, 1, 1)), "requests can be collected under the committed successor")
	_, err := col.VerifyIRChangeReq(quorumProof(s.request(col, 1, 1, 1)), t2Rounds)
	require.ErrorIs(t, err, ErrRequestNotActive)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)

	for _, p := range []RequestPurpose{PurposeCertify, PurposeExecute, PurposeTimeout} {
		_, err := s.resolve(snap, fxActivate-3, 4, fxBody1, p)
		require.ErrorIs(t, err, ErrRequestNotActive, "purpose %d", p)
		require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	}
	// the same target names the old identity: that is the old assignment, not an error
	require.False(t, s.mustResolve(snap, fxActivate-3, 3, fxBody0, PurposeCertify).CollectionOnly())
	// collection and certification of one target are different views
	require.NotEqual(t, col.ViewKey(), s.mustResolve(snap, fxActivate-3, 3, fxBody0, PurposeCollect).ViewKey())
}

// The supplied identities never select anything: each one that differs from the resolved one is refused alone.
func TestResolverRefusesEachInconsistentIdentityByItself(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)
	base := s.query(snap, fxActivate, 4, fxBody1, PurposeExecute)
	_, err := ResolveRequestContext(base, snap)
	require.NoError(t, err)

	flip := func(b []byte) []byte { c := bytes.Clone(b); c[0] ^= 0xFF; return c }
	for name, mut := range map[string]func(q *RequestQuery){
		"root body":    func(q *RequestQuery) { q.RootBodyID = flip(q.RootBodyID) },
		"root epoch":   func(q *RequestQuery) { q.RootEpoch = 9 },
		"version":      func(q *RequestQuery) { q.Version = fxVersion + 1 },
		"parent":       func(q *RequestQuery) { q.ParentID = flip(q.ParentID) },
		"previous UC":  func(q *RequestQuery) { q.PrevUCDigest = flip(q.PrevUCDigest) },
		"network":      func(q *RequestQuery) { q.Network++ },
		"partition":    func(q *RequestQuery) { q.Partition++ },
		"empty body":   func(q *RequestQuery) { q.RootBodyID = nil },
		"no purpose":   func(q *RequestQuery) { q.Purpose = 0 },
		"no round":     func(q *RequestQuery) { q.RootRound = 0 },
		"empty parent": func(q *RequestQuery) { q.ParentID = nil },
	} {
		q := base
		mut(&q)
		_, err := ResolveRequestContext(q, snap)
		require.ErrorIs(t, err, quorumweight.ErrRequestContext, name)
	}
	_, err = ResolveRequestContext(base, nil)
	require.ErrorIs(t, err, ErrAssignmentHistory)
}

func TestSnapshotRefusesMissingOrInconsistentHistory(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	mk := func(parent *ShardInfo, id []byte, chain ...*RequestActivation) error {
		_, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, parent, id, nil, chain...)
		return err
	}
	require.NoError(t, mk(s.parent, s.parentID, s.anchor, s.succ))
	// no verified parent, no parent identity, no history, no anchor
	require.ErrorIs(t, mk(nil, s.parentID, s.anchor), ErrAssignmentHistory)
	require.ErrorIs(t, mk(s.parent, nil, s.anchor), ErrAssignmentHistory)
	require.ErrorIs(t, mk(s.parent, s.parentID), ErrAssignmentHistory)
	require.ErrorIs(t, mk(s.parent, s.parentID, s.succ), ErrAssignmentHistory, "history must begin at a trusted anchor")
	noUC := *s.parent
	noUC.LastCR = nil
	require.ErrorIs(t, mk(&noUC, s.parentID, s.anchor, s.succ), ErrAssignmentHistory)
	// the parent runs an epoch the history does not know
	ahead := *s.parent
	ahead.TR.Epoch = 2
	require.ErrorIs(t, mk(&ahead, s.parentID, s.anchor, s.succ), ErrAssignmentHistory)
	// the installed configuration is not the one history has for its epoch (the PDR hash differs)
	other := *s.parent
	other.ShardConfHash = bytes.Repeat([]byte{1}, 32)
	require.ErrorIs(t, mk(&other, s.parentID, s.anchor, s.succ), quorumweight.ErrRequestContext)
	// same epoch, different body is not a successor: epochs must be consecutive and activation rounds rise
	dup := *s.succ
	dup.start = 0
	require.ErrorIs(t, mk(s.parent, s.parentID, s.anchor, &dup), ErrAssignmentHistory)
	skip := *s.succ
	skip.pdr = s.anchor.pdr
	require.ErrorIs(t, mk(s.parent, s.parentID, s.anchor, &skip), ErrAssignmentHistory)
}

// The successor technical record is derived and compared with the committed digest; a different digest, or a parent that
// has already installed another record, is refused.
func TestSuccessorTechnicalRecordMustBeTheCommittedOne(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	bad := *s.succ
	bad.trHash = bytes.Repeat([]byte{7}, 32)
	snap, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, s.parent, s.parentID, nil, s.anchor, &bad)
	require.NoError(t, err)
	_, err = s.resolve(snap, fxActivate, 4, fxBody1, PurposeExecute)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	// before A* the old assignment never looks at the successor digest
	_, err = s.resolve(snap, fxActivate-1, 3, fxBody0, PurposeExecute)
	require.NoError(t, err)

	// a parent that already installed some other successor record
	moved := *s.parent
	moved.TR = s.succTR
	moved.TR.Round++
	moved.ShardConfHash = s.succ.confHash
	snap2, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, &moved, s.parentID, nil, s.anchor, s.succ)
	require.NoError(t, err)
	_, err = s.resolve(snap2, fxActivate, 4, fxBody1, PurposeExecute)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
}

// Delayed first successor block, then restart: the first block may be proposed many rounds after A*, and a restarted node
// rebuilds the snapshot from the same committed history. The expected record never depends on the proposal round, and the
// parent may be the lagging committed state, the executing state that installed the assignment, or the state after the
// first successor UC.
func TestDelayedFirstSuccessorBlockAndRestartAtActivation(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)
	atA := s.mustResolve(snap, fxActivate, 4, fxBody1, PurposeExecute)
	late := s.mustResolve(snap, fxActivate+7, 4, fxBody1, PurposeExecute)
	require.Equal(t, atA.ExpectedTR(), late.ExpectedTR())
	require.Equal(t, atA.AssignmentKey(), late.AssignmentKey())
	require.NotEqual(t, atA.ViewKey(), late.ViewKey(), "another proposal round is another view")
	// T2 depends on elapsed root rounds only: weights and the assignment do not enter
	require.Equal(t, 2500*time.Millisecond, late.T2Timeout())

	// restart: new objects from the same committed data
	again := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil) // fresh random keys: a different network, so keys differ
	require.NotEqual(t, atA.AssignmentKey(), again.mustResolve(again.snapshot(again.parent, nil), fxActivate, 4, fxBody1, PurposeExecute).AssignmentKey())
	rebuilt, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, s.parent, s.parentID, nil, s.anchor, s.succ)
	require.NoError(t, err)
	r := s.mustResolve(rebuilt, fxActivate+7, 4, fxBody1, PurposeExecute)
	require.Equal(t, late.ViewKey(), r.ViewKey())

	// the executing state that already installed the assignment (record advanced, last certified record still old)
	installed := *s.parent
	installed.TR = s.succTR
	installed.ShardConfHash = s.succ.confHash
	exec := s.mustResolve(s.snapshot(&installed, nil), fxActivate+7, 4, fxBody1, PurposeExecute)
	require.Equal(t, late.ExpectedTR(), exec.ExpectedTR())
	require.Equal(t, late.AssignmentKey(), exec.AssignmentKey())

	// after the first successor UC the last certified record is the successor's
	done := s.f.shardAt(s.pdr1, s.succTR)
	done.LastCR.UC.UnicitySeal.RootChainRoundNumber = fxActivate + 1
	post := s.mustResolve(s.snapshot(done, nil), fxActivate+9, 4, fxBody1, PurposeExecute)
	require.Equal(t, s.succTR.Epoch, post.ExpectedTR().Epoch)
	require.Equal(t, s.succTR.Round, post.ExpectedTR().Round)
	// a parent that is neither epoch's neighbour of the assignment in force is stale
	far := s.f.shardAt(s.pdr0, certification.TechnicalRecord{Round: 5, Epoch: 0, Leader: s.f.id(0)})
	far.LastCR.Technical.Epoch = 5
	far.TR.Epoch = 0
	_, err = s.resolve(s.snapshot(far, nil), fxActivate+9, 4, fxBody1, PurposeExecute)
	require.ErrorIs(t, err, ErrStaleRequestContext)
}

// Replay targets the verified historical parent: before the boundary the old assignment, after it the new one, and a replayed
// old proof never becomes eligible now.
func TestReplayBeforeAndAfterTheBoundary(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)
	before := s.mustResolve(snap, fxActivate-2, 3, fxBody0, PurposeReplay)
	require.EqualValues(t, 0, before.ExpectedTR().Epoch)
	proof := quorumProof(s.request(before, 0, 0, 1))
	_, err := before.VerifyIRChangeReq(proof, t2Rounds)
	require.NoError(t, err, "history replays under its own context")

	done := s.f.shardAt(s.pdr1, s.succTR)
	done.LastCR.UC.UnicitySeal.RootChainRoundNumber = fxActivate + 1
	snap2 := s.snapshot(done, nil)
	after := s.mustResolve(snap2, fxActivate+4, 4, fxBody1, PurposeReplay)
	require.EqualValues(t, 1, after.ExpectedTR().Epoch)
	_, err = after.VerifyIRChangeReq(proof, t2Rounds)
	require.ErrorIs(t, err, ErrStaleRequestContext, "the old proof is not eligible under the successor")
	// replay of the boundary parent before A* does not resolve the successor under the successor's name either
	_, err = s.resolve(snap, fxActivate-2, 4, fxBody1, PurposeReplay)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
}

func TestPendingChangeIsPartOfTheSnapshotAndTheViewKey(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	free := s.mustResolve(s.snapshot(s.parent, nil), fxActivate-1, 3, fxBody0, PurposeCertify)
	req := quorumProof(s.request(free, 0, 0, 1), s.request(free, 1, 1, 1), s.request(free, 2, 2, 1))
	res, err := free.VerifyIRChangeReq(req, t2Rounds)
	require.NoError(t, err)

	same := res.IR
	busy := s.mustResolve(s.snapshot(s.parent, same), fxActivate-1, 3, fxBody0, PurposeCertify)
	require.NotEqual(t, free.ViewKey(), busy.ViewKey())
	_, err = busy.VerifyIRChangeReq(req, t2Rounds)
	require.ErrorIs(t, err, ErrDuplicateChangeReq)
	other := *same
	other.Hash = []byte{0xEE}
	other.BlockHash = []byte{0xEF}
	pending := s.mustResolve(s.snapshot(s.parent, &other), fxActivate-1, 3, fxBody0, PurposeCertify)
	_, err = pending.VerifyIRChangeReq(req, t2Rounds)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrDuplicateChangeReq)
}

// Every field the view returns is a copy, and every input the snapshot took is copied on entry.
func TestViewAndSnapshotOwnTheirData(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	pending := &types.InputRecord{Version: 1, Hash: []byte{1}, PreviousHash: []byte{2}, BlockHash: []byte{3}, SummaryValue: []byte{4}}
	snap := s.snapshot(s.parent, pending)
	view := s.mustResolve(snap, fxActivate, 4, fxBody1, PurposeExecute)
	key, akey, tr, prev := view.ViewKey(), view.AssignmentKey(), view.ExpectedTR(), view.PreviousStateHash()
	req := s.request(view, 1, 1, 1)
	require.NoError(t, view.ValidRequest(req))

	// inputs mutated after the snapshot was built
	s.parent.RootHash[0] ^= 0xFF
	s.parent.LastCR.UC.UnicitySeal.Timestamp++
	s.parent.TR.StatHash[0] ^= 0xFF
	pending.Hash[0] ^= 0xFF
	s.pdr1.Validators[1].SigKey[0] ^= 0xFF
	s.pdr1.Validators[1].Stake = 99
	s.pdr1.T2Timeout = time.Hour
	// getters mutated
	view.ViewKey()[0] ^= 0xFF
	view.AssignmentKey()[0] ^= 0xFF
	view.PreviousStateHash()[0] ^= 0xFF
	exp := view.ExpectedTR()
	exp.StatHash[0] ^= 0xFF
	exp.Round = 99
	pdr, err := view.PDR()
	require.NoError(t, err)
	pdr.Validators[0].Stake = 77
	pdr.Validators[0].SigKey[0] ^= 0xFF
	uc, err := view.PreviousUC()
	require.NoError(t, err)
	uc.UnicitySeal.Timestamp = 5
	uc.InputRecord.Hash[0] ^= 0xFF
	ids := view.Context().NodeIDs()
	ids[0] = "x"

	require.Equal(t, key, view.ViewKey())
	require.Equal(t, akey, view.AssignmentKey())
	require.Equal(t, tr, view.ExpectedTR())
	require.Equal(t, prev, view.PreviousStateHash())
	require.Equal(t, 2500*time.Millisecond, view.T2Timeout())
	require.NoError(t, view.ValidRequest(req), "the context keeps verifying with its own copy of the key")
	w, err := view.Context().SignerWeight(s.f.id(1))
	require.NoError(t, err)
	require.EqualValues(t, 6, w)
	again, err := view.PDR()
	require.NoError(t, err)
	require.EqualValues(t, 6, again.Validators[1].Stake)
	// a view resolved from the same snapshot after the caller scribbled is the same view
	require.Equal(t, key, s.mustResolve(snap, fxActivate, 4, fxBody1, PurposeExecute).ViewKey())
}

func TestProofForARoundBeforeThePreviousUCIsStale(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)
	v := s.mustResolve(snap, fxUCRound-1, 3, fxBody0, PurposeCertify)
	_, err := v.VerifyIRChangeReq(quorumProof(s.request(v, 0, 0, 1), s.request(v, 1, 1, 1), s.request(v, 2, 2, 1)), t2Rounds)
	require.ErrorIs(t, err, ErrStaleRequestContext)
}

func TestProofOfAnotherShardIsNotJudgedUnderThisView(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	v := s.mustResolve(s.snapshot(s.parent, nil), fxActivate-1, 3, fxBody0, PurposeCertify)
	other := quorumProof(s.request(v, 0, 0, 1))
	other.Partition = 2
	_, err := v.VerifyIRChangeReq(other, t2Rounds)
	require.ErrorIs(t, err, rctypes.ErrInvalidRequest)
	foreign := s.request(v, 0, 0, 1)
	foreign.PartitionID = 2
	require.NoError(t, foreign.Sign(s.f.nodes[0].Signer))
	require.ErrorIs(t, v.ValidRequest(foreign), rctypes.ErrInvalidRequest)
	require.ErrorIs(t, v.ValidRequest(nil), certification.ErrBlockCertificationRequestIsNil)
	_, err = v.VerifyIRChangeReq(nil, t2Rounds)
	require.ErrorIs(t, err, rctypes.ErrInvalidRequest)
}

// Every component the keys claim to bind changes them, one at a time.
func TestKeysBindEveryComponent(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	round := uint64(fxActivate - 1)
	base := s.mustResolve(s.snapshot(s.parent, nil), round, 3, fxBody0, PurposeCertify)

	variant := func(mutate func(p *ShardInfo), parentID []byte, anchor *RequestActivation) *RequestRoundView {
		p := *s.parent
		cr := *s.parent.LastCR
		seal := *cr.UC.UnicitySeal
		cr.UC.UnicitySeal = &seal
		p.LastCR = &cr
		p.RootHash = bytes.Clone(p.RootHash)
		if mutate != nil {
			mutate(&p)
		}
		id := s.parentID
		if parentID != nil {
			id = parentID
		}
		a := s.anchor
		if anchor != nil {
			a = anchor
		}
		snap, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, &p, id, nil, a, s.succ)
		require.NoError(t, err)
		q := s.query(snap, round, 3, fxBody0, PurposeCertify)
		q.ParentID = id
		if anchor != nil {
			q.Version, q.RootBodyID, q.RootEpoch = anchor.version, anchor.rootBody, anchor.rootEpoch
		}
		v, err := ResolveRequestContext(q, snap)
		require.NoError(t, err)
		return v
	}
	otherVersion, err := newRequestActivation(s.pdr0, crypto.SHA256, quorumweight.PolicyEVMWeighted, couplingOf(t, s), 3, fxBody0, 0, nil, fxVersion+1)
	require.NoError(t, err)
	otherBody, err := newRequestActivation(s.pdr0, crypto.SHA256, quorumweight.PolicyEVMWeighted, couplingOf(t, s), 3, bytes.Repeat([]byte{0xC3}, 32), 0, nil, fxVersion)
	require.NoError(t, err)
	otherRootEpoch, err := newRequestActivation(s.pdr0, crypto.SHA256, quorumweight.PolicyEVMWeighted, couplingOf(t, s), 2, fxBody0, 0, nil, fxVersion)
	require.NoError(t, err)

	for name, v := range map[string]*RequestRoundView{
		"parent block":   variant(nil, bytes.Repeat([]byte{0x11}, 32), nil),
		"previous UC":    variant(func(p *ShardInfo) { p.LastCR.UC.UnicitySeal.Hash = []byte{0x77} }, nil, nil),
		"state hash":     variant(func(p *ShardInfo) { p.RootHash[0] ^= 1 }, nil, nil),
		"technical rec.": variant(func(p *ShardInfo) { p.LastCR.Technical.Leader = "other" }, nil, nil),
		"version":        variant(nil, nil, otherVersion),
		"root body":      variant(nil, nil, otherBody),
		"root epoch":     variant(nil, nil, otherRootEpoch),
	} {
		require.NotEqual(t, base.ViewKey(), v.ViewKey(), name)
	}
	// the assignment alone is bound by version, root body and root epoch, not by the target
	require.NotEqual(t, base.AssignmentKey(), variant(nil, nil, otherVersion).AssignmentKey())
	require.NotEqual(t, base.AssignmentKey(), variant(nil, nil, otherBody).AssignmentKey())
	require.NotEqual(t, base.AssignmentKey(), variant(nil, nil, otherRootEpoch).AssignmentKey())
	require.Equal(t, base.AssignmentKey(), variant(nil, bytes.Repeat([]byte{0x11}, 32), nil).AssignmentKey())
	require.Equal(t, base.AssignmentKey(), variant(func(p *ShardInfo) { p.RootHash[0] ^= 1 }, nil, nil).AssignmentKey())
	// the same target resolved twice is the same view
	require.Equal(t, base.ViewKey(), variant(nil, nil, nil).ViewKey())
}

// couplingOf rebuilds a coupling for the scenario's epoch-0 configuration.
func couplingOf(t *testing.T, s *scenario) *quorumweight.Coupling {
	t.Helper()
	_, c := s.f.pdr(0, 1, 3, fxBody0, s.pdr0.Validators...)
	return c
}

// Each continuity field of a request is checked by itself: round, state hash and timestamp (epoch is covered by the boundary
// tests), and a wrong signature or a request of another shard.
func TestRequestAdmissionChecksEachContinuityField(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	v := s.mustResolve(s.snapshot(s.parent, nil), fxActivate-1, 3, fxBody0, PurposeCertify)
	require.NoError(t, v.ValidRequest(s.request(v, 0, 0, 1)))
	for name, mut := range map[string]func(r *certification.BlockCertificationRequest){
		"round":      func(r *certification.BlockCertificationRequest) { r.InputRecord.RoundNumber++ },
		"epoch":      func(r *certification.BlockCertificationRequest) { r.InputRecord.Epoch++ },
		"state hash": func(r *certification.BlockCertificationRequest) { r.InputRecord.PreviousHash = []byte{0xAB} },
		"timestamp":  func(r *certification.BlockCertificationRequest) { r.InputRecord.Timestamp++ },
	} {
		r := s.request(v, 0, 0, 1)
		mut(r)
		require.NoError(t, r.Sign(s.f.nodes[0].Signer))
		require.ErrorIs(t, v.ValidRequest(r), ErrStaleRequestContext, name)
	}
	forged := s.request(v, 0, 1, 1) // identity 0 signed by key 1
	require.ErrorIs(t, v.ValidRequest(forged), quorumweight.ErrInvalidSignature)
}

func TestHistoryMustBeginAtAnAnchorAndATimeoutProofOfAnotherShardIsRefused(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	late := *s.anchor
	late.start = 5
	_, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, s.parent, s.parentID, nil, &late, s.succ)
	require.ErrorIs(t, err, ErrAssignmentHistory)

	v := s.mustResolve(s.snapshot(s.parent, nil), fxUCRound+t2Rounds, 3, fxBody0, PurposeTimeout)
	_, err = v.VerifyIRChangeReq(&rctypes.IRChangeReq{Partition: 1, CertReason: rctypes.T2Timeout}, t2Rounds)
	require.NoError(t, err)
	_, err = v.VerifyIRChangeReq(&rctypes.IRChangeReq{Partition: 2, CertReason: rctypes.T2Timeout}, t2Rounds)
	require.ErrorIs(t, err, rctypes.ErrInvalidRequest, "an empty timeout proof names its shard, and it is not this view's")
}

// The snapshot's network is bound to its authenticated history and previous UC, never asserted beside them.
func TestSnapshotNetworkMustMatchTheAuthenticatedHistory(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	_, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, s.parent, s.parentID, nil, s.anchor, s.succ)
	require.NoError(t, err, "control")

	// only the network argument changes
	snap, err := NewRequestSnapshot(fxNetwork+1, crypto.SHA256, s.parent, s.parentID, nil, s.anchor, s.succ)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	require.Nil(t, snap)

	// only the previous UC's network changes
	other := *s.parent
	lastCR := *s.parent.LastCR
	seal := *lastCR.UC.UnicitySeal
	seal.NetworkID++
	lastCR.UC.UnicitySeal = &seal
	other.LastCR = &lastCR
	snap, err = NewRequestSnapshot(fxNetwork, crypto.SHA256, &other, s.parentID, nil, s.anchor, s.succ)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	require.Nil(t, snap)

	// an unsealed previous UC has no network to bind
	unsealed := *s.parent
	noSeal := *s.parent.LastCR
	noSeal.UC.UnicitySeal = nil
	unsealed.LastCR = &noSeal
	_, err = NewRequestSnapshot(fxNetwork, crypto.SHA256, &unsealed, s.parentID, nil, s.anchor, s.succ)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)

	// only an activation's network changes
	foreign := *s.pdr0
	foreign.NetworkID = fxNetwork + 1
	h, err := foreign.Hash(crypto.SHA256)
	require.NoError(t, err)
	a := *s.anchor
	a.pdr, a.confHash = &foreign, h
	bound := *s.parent // its configuration hash is the foreign one's, so no other check can refuse
	bound.ShardConfHash = h
	_, err = NewRequestSnapshot(fxNetwork, crypto.SHA256, &bound, s.parentID, nil, &a)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
}

// Certified technical records are owned: mutating the caller's copy after the snapshot or view was built changes neither, for a
// historical (non-boundary) view, a boundary view and a fresh resolution.
func TestViewOwnsCertifiedTechnicalRecords(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	snap := s.snapshot(s.parent, nil)
	hist := s.mustResolve(snap, fxActivate-1, 3, fxBody0, PurposeCertify)
	key, tr := hist.ViewKey(), hist.ExpectedTR()
	wantStat := bytes.Clone(tr.StatHash)
	boundary := s.mustResolve(snap, fxActivate, 4, fxBody1, PurposeExecute)
	bKey, bTR := boundary.ViewKey(), boundary.ExpectedTR()

	// TR and LastCR.Technical share their backing arrays in this fixture, so each is changed exactly once
	s.parent.LastCR.Technical.StatHash[0] ^= 0xFF
	s.parent.LastCR.Technical.FeeHash[0] ^= 0xFF
	require.Equal(t, tr, hist.ExpectedTR(), "the historical view does not alias the caller's record")
	require.Equal(t, key, hist.ViewKey())
	require.Equal(t, bTR, boundary.ExpectedTR())
	require.Equal(t, bKey, boundary.ViewKey())
	require.Equal(t, bKey, s.mustResolve(snap, fxActivate, 4, fxBody1, PurposeExecute).ViewKey(), "the derived successor record is built from the frozen copy, not the caller's state")
	again := s.mustResolve(snap, fxActivate-1, 3, fxBody0, PurposeCertify)
	require.Equal(t, key, again.ViewKey(), "re-resolution from the same snapshot is unchanged")
	require.Equal(t, tr, again.ExpectedTR())

	// the executing state that already installed the assignment: its record is the view's expected one
	installed := *s.parent
	installed.TR = cloneTR(s.succTR)
	installed.ShardConfHash = s.succ.confHash
	isnap := s.snapshot(&installed, nil)
	inst := s.mustResolve(isnap, fxActivate, 4, fxBody1, PurposeExecute)
	instKey, instTR := inst.ViewKey(), inst.ExpectedTR()
	installed.TR.StatHash[0] ^= 0xFF
	installed.TR.FeeHash[0] ^= 0xFF
	require.Equal(t, instTR, inst.ExpectedTR())
	require.Equal(t, instKey, inst.ViewKey())
	require.Equal(t, instKey, s.mustResolve(isnap, fxActivate, 4, fxBody1, PurposeExecute).ViewKey())

	// the getter's copy is the caller's too
	got := hist.ExpectedTR()
	got.StatHash[0] ^= 0xFF
	require.Equal(t, wantStat, hist.ExpectedTR().StatHash)
}

// Direct admission carries ErrInvalidRequest on malformed and continuity refusals, keeps the underlying and continuity
// identities, and leaves the unknown-signer and bad-signature identities separate.
func TestViewAdmissionSentinels(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{1, 1, 1, 1}, nil)
	v := s.mustResolve(s.snapshot(s.parent, nil), fxActivate-1, 3, fxBody0, PurposeCertify)
	require.NoError(t, v.ValidRequest(s.request(v, 0, 0, 1)), "control")

	t.Run("nil request", func(t *testing.T) {
		err := v.ValidRequest(nil)
		require.ErrorIs(t, err, rctypes.ErrInvalidRequest)
		require.ErrorIs(t, err, certification.ErrBlockCertificationRequestIsNil)
	})
	t.Run("nil input record", func(t *testing.T) {
		req := s.request(v, 0, 0, 1)
		req.InputRecord = nil
		err := v.ValidRequest(req)
		require.ErrorIs(t, err, rctypes.ErrInvalidRequest)
		require.ErrorIs(t, err, types.ErrInputRecordIsNil)
	})
	t.Run("another shard", func(t *testing.T) {
		req := s.request(v, 0, 0, 1)
		req.PartitionID = 2
		require.NoError(t, req.Sign(s.f.nodes[0].Signer))
		require.ErrorIs(t, v.ValidRequest(req), rctypes.ErrInvalidRequest)
	})
	for name, mutate := range map[string]func(*certification.BlockCertificationRequest){
		"round":     func(r *certification.BlockCertificationRequest) { r.InputRecord.RoundNumber++ },
		"epoch":     func(r *certification.BlockCertificationRequest) { r.InputRecord.Epoch++ },
		"state":     func(r *certification.BlockCertificationRequest) { r.InputRecord.PreviousHash = []byte("other") },
		"timestamp": func(r *certification.BlockCertificationRequest) { r.InputRecord.Timestamp++ },
	} {
		t.Run("continuity "+name, func(t *testing.T) {
			req := s.request(v, 0, 0, 1)
			mutate(req)
			require.NoError(t, req.Sign(s.f.nodes[0].Signer))
			err := v.ValidRequest(req)
			require.ErrorIs(t, err, rctypes.ErrInvalidRequest)
			require.ErrorIs(t, err, ErrStaleRequestContext)
		})
	}
	t.Run("unknown signer keeps its identity", func(t *testing.T) {
		req := s.request(v, 0, 0, 1)
		req.NodeID = s.f.id(5)
		err := v.ValidRequest(req)
		require.ErrorIs(t, err, ErrNodeNotInTrustBase)
		require.NotErrorIs(t, err, rctypes.ErrInvalidRequest)
	})
	t.Run("bad signature keeps its identity", func(t *testing.T) {
		req := s.request(v, 0, 1, 1) // signed with another member's key
		err := v.ValidRequest(req)
		require.ErrorIs(t, err, quorumweight.ErrInvalidSignature)
		require.NotErrorIs(t, err, rctypes.ErrInvalidRequest)
	})
}
