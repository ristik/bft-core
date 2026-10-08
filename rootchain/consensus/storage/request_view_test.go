package storage

import (
	"bytes"
	"crypto"
	"maps"
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

// installed is the verified parent after production installation of the successor (successorTechnicalRecord + nextEpoch, as
// activateEVMAssignment does) followed by the given number of real root timeouts (nextRoundWith without a request) while the
// acknowledgement is pending: epoch and configuration fixed, round and leader advancing, accumulators rolled once.
func (s *scenario) installed(repeats int) *ShardInfo {
	s.f.t.Helper()
	advanced := *s.parent
	advanced.Fees = maps.Clone(s.parent.Fees)
	advanced.TR = s.succTR
	next, err := advanced.nextEpochWith(s.pdr1, crypto.SHA256, resetMembers)
	require.NoError(s.f.t, err)
	for i := 0; i < repeats; i++ {
		require.NoError(s.f.t, next.nextRoundWith(nil, s.pdr1, crypto.SHA256, resetMembers))
	}
	return next
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

	// an installed parent is judged by its own epoch, configuration and commitments, not by the immutable digest of the record it
	// installed: a digest that no longer matches the (moved) record is not what is compared once installed
	inst := s.installed(0)
	snap2, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, inst, s.parentID, nil, s.anchor, &bad)
	require.NoError(t, err)
	v, err := s.resolve(snap2, fxActivate, 4, fxBody1, PurposeExecute)
	require.NoError(t, err)
	require.Equal(t, inst.TR, v.ExpectedTR())

	// but the predecessor case keeps the complete digest check, with the same bad digest
	_, err = s.resolve(snap, fxActivate, 4, fxBody1, PurposeExecute)
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
	exec := s.mustResolve(s.snapshot(s.installed(0), nil), fxActivate+7, 4, fxBody1, PurposeExecute)
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
	installed := *s.installed(0)
	installed.TR = cloneTR(installed.TR)
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
	require.Equal(t, wantStat, []byte(hist.ExpectedTR().StatHash))
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

// The isolated weighted anchor is the weighted activation of a coupled EVM assignment and nothing else: it needs its coupling, takes
// its weights from the authenticated assignment, and an aggregator shard cannot select the weighted policy.
func TestIsolatedWeightedRequestAnchor(t *testing.T) {
	f := newViewFixture(t)
	pdr, c := f.pdr(0, 1, 3, fxBody0, f.member(0, 0, 6), f.member(1, 1, 1), f.member(2, 2, 1), f.member(3, 3, 1))

	a, err := NewIsolatedWeightedRequestAnchor(pdr, crypto.SHA256, c, 3, fxBody0, fxVersion)
	require.NoError(t, err)
	require.NotNil(t, a)

	_, err = NewIsolatedWeightedRequestAnchor(pdr, crypto.SHA256, nil, 3, fxBody0, fxVersion)
	require.ErrorIs(t, err, quorumweight.ErrCouplingRequired, "no coupling evidence, no weighted context")
	_, err = NewIsolatedWeightedRequestAnchor(pdr, crypto.SHA256, c, 3, nil, fxVersion)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext, "an incomplete activation")
	_, err = NewIsolatedWeightedRequestAnchor(pdr, crypto.SHA256, c, 3, fxBody0, 0)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)

	// the authorizing identity is the coupling's: each argument alone disagreeing is refused, the equal pair is the control
	_, err = NewIsolatedWeightedRequestAnchor(pdr, crypto.SHA256, c, 3, fxBody0, fxVersion)
	require.NoError(t, err, "control: the authorizing root equals the coupling's")
	_, err = NewIsolatedWeightedRequestAnchor(pdr, crypto.SHA256, c, 4, fxBody0, fxVersion)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext, "root epoch differs from the coupling's")
	_, err = NewIsolatedWeightedRequestAnchor(pdr, crypto.SHA256, c, 3, fxBody1, fxVersion)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext, "root body differs from the coupling's")

	// the weights of the activation are the assignment's: an aggregator shard cannot select the weighted policy
	unit, _ := f.pdr(0, 1, 3, fxBody0, f.member(0, 0, 1), f.member(1, 1, 1), f.member(2, 2, 1), f.member(3, 3, 1))
	unit.PartitionTypeID = 1
	_, err = NewIsolatedWeightedRequestAnchor(unit, crypto.SHA256, c, 3, fxBody0, fxVersion)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext, "a request cannot pick its own policy")
}

// The acknowledgement is pending across several root timeouts: the installed parent's record moves (round, leader) while its epoch,
// configuration and commitments do not. The view builds on the parent's current record, keeps W=9/Q=5 and the assignment, and a fresh
// request under the new round is accepted while the previous round's is stale.
func TestExpectedTRPendingAckRepeatUC(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	var firstKey, firstAssignment []byte
	var prev *RequestRoundView
	var seenLeaders = map[string]bool{}
	for repeats := 0; repeats <= 4; repeats++ {
		inst := s.installed(repeats)
		snap := s.snapshot(inst, nil)
		for _, purpose := range []RequestPurpose{PurposeCollect, PurposeCertify, PurposeExecute, PurposeTimeout, PurposeReplay} {
			round := uint64(fxActivate + 7)
			v := s.mustResolve(snap, round, 4, fxBody1, purpose)
			require.Equal(t, inst.TR, v.ExpectedTR(), "purpose %d builds on the parent's current record", purpose)
			require.EqualValues(t, 9, v.Context().TotalWeight())
			require.EqualValues(t, 5, v.Context().Threshold())
		}
		v := s.mustResolve(snap, fxActivate+7, 4, fxBody1, PurposeCertify)
		seenLeaders[v.ExpectedTR().Leader] = true
		require.EqualValues(t, s.succTR.Round+uint64(repeats), v.ExpectedTR().Round)
		if repeats == 0 {
			firstKey, firstAssignment = v.ViewKey(), v.AssignmentKey()
		} else {
			require.NotEqual(t, firstKey, v.ViewKey(), "another expected record is another view")
			require.Equal(t, firstAssignment, v.AssignmentKey(), "the assignment does not move with the timeouts")
			require.NotEqual(t, prev.RoundTag(), v.RoundTag())
			// the previous round's proof is stale now; a fresh heavy-signer proof is accepted
			stale := quorumProof(s.request(prev, 1, 1, 2))
			_, err := v.VerifyIRChangeReq(stale, t2Rounds)
			require.ErrorIs(t, err, ErrStaleRequestContext)
			res, err := v.VerifyIRChangeReq(quorumProof(s.request(v, 1, 1, 2)), t2Rounds)
			require.NoError(t, err)
			require.Equal(t, v.ViewKey(), res.ViewKey)
		}
		prev = v

		// restart: the same parent rebuilt into new objects with an empty cache is the same view
		again, err := NewRequestViewCache().Resolve(s.query(snap, fxActivate+7, 4, fxBody1, PurposeCertify), s.snapshot(s.installed(repeats), nil))
		require.NoError(t, err)
		require.Equal(t, v.ViewKey(), again.ViewKey())
	}
	require.Greater(t, len(seenLeaders), 1, "the leader changed across the timeouts")
}

// Each way the installed parent can fail to be the authenticated one is refused on its own, with a typed error and no view; a refusal
// never populates the cache, and does not evict a view already in it.
func TestExpectedTRInstalledParentRefusals(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	flip := func(b []byte) []byte { c := bytes.Clone(b); c[0] ^= 1; return c }
	for name, tc := range map[string]struct {
		mutate func(*ShardInfo)
		cause  error
	}{
		"a one-byte stat hash mismatch":              {func(si *ShardInfo) { si.TR.StatHash = flip(si.TR.StatHash) }, quorumweight.ErrRequestContext},
		"a one-byte fee hash mismatch":               {func(si *ShardInfo) { si.TR.FeeHash = flip(si.TR.FeeHash) }, quorumweight.ErrRequestContext},
		"a regressed round":                          {func(si *ShardInfo) { si.TR.Round = si.LastCR.Technical.Round }, quorumweight.ErrRequestContext},
		"accumulators that moved without the record": {func(si *ShardInfo) { si.Stat.Blocks++ }, quorumweight.ErrRequestContext},
	} {
		t.Run(name, func(t *testing.T) {
			inst := s.installed(2)
			tc.mutate(inst)
			snap, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, inst, s.parentID, nil, s.anchor, s.succ)
			require.NoError(t, err)
			cache := NewRequestViewCache()
			v, err := cache.Resolve(s.query(snap, fxActivate+7, 4, fxBody1, PurposeExecute), snap)
			require.ErrorIs(t, err, tc.cause)
			require.Nil(t, v)
			require.Zero(t, cache.Len(), "a refusal populates nothing")

			// with a good view already cached, the refusal does not disturb it
			good := s.snapshot(s.installed(2), nil)
			_, err = cache.Resolve(s.query(good, fxActivate+7, 4, fxBody1, PurposeExecute), good)
			require.NoError(t, err)
			_, err = cache.Resolve(s.query(snap, fxActivate+7, 4, fxBody1, PurposeExecute), snap)
			require.ErrorIs(t, err, tc.cause)
			require.Equal(t, 1, cache.Len())
		})
	}

	// the epoch and configuration of the installed record, judged by expectedTR itself (the snapshot constructor already ties the
	// parent's configuration to the epoch it is in)
	snap := s.snapshot(s.installed(1), nil)
	_, err := expectedTR(snap, 1)
	require.NoError(t, err, "control")
	for name, epoch := range map[string]uint64{"an unrelated epoch": 7, "a future epoch": 2} {
		stale := *snap
		stale.parent.tr.Epoch = epoch
		_, err := expectedTR(&stale, 1)
		require.ErrorIs(t, err, ErrStaleRequestContext, name)
		snap = s.snapshot(s.installed(1), nil)
	}
	other := s.snapshot(s.installed(1), nil)
	other.parent.confHash = flip(other.parent.confHash)
	_, err = expectedTR(other, 1)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext, "a configuration other than the selected assignment's")
}

// continuationOf is what RequestContinuationFromVerifiedV3 builds, without its history proof: the previous assignment under the next root
// interval, the configuration, the immutable context and the original commitment copied.
func continuationOf(t *testing.T, prev *RequestActivation, rootEpoch uint64, body []byte, start uint64) *RequestActivation {
	t.Helper()
	pdr, err := clonePDR(prev.pdr)
	require.NoError(t, err)
	return &RequestActivation{pdr: pdr, confHash: bytes.Clone(prev.confHash), ctx: prev.ctx, rootEpoch: rootEpoch, rootBody: bytes.Clone(body), start: start,
		trHash: bytes.Clone(prev.trHash), version: prev.version, continuation: true, predecessorRootBody: bytes.Clone(prev.rootBody)}
}

var fxBody2 = bytes.Repeat([]byte{0xC2}, 32)

// A shard that no activation touches (an aggregator) keeps its unit assignment across root epochs: each root interval is a continuation with its
// own authorising identity, resolved with the exact identity equality, at the same shard epoch, configuration, context and quorum.
func TestContinuationKeepsAnUnchangedUnitShardResolvableAcrossRootIntervals(t *testing.T) {
	f := newViewFixture(t)
	var v0 []*types.NodeInfo
	for i := 0; i < 4; i++ {
		v0 = append(v0, f.member(i, i, 1))
	}
	pdr, _ := f.pdr(0, 1, 3, fxBody0, v0...)
	anchor, err := newRequestActivation(pdr, crypto.SHA256, quorumweight.PolicyUnit, nil, 3, fxBody0, 0, nil, fxVersion)
	require.NoError(t, err)
	c1 := continuationOf(t, anchor, 4, fxBody1, fxActivate)
	c2 := continuationOf(t, c1, 5, fxBody2, fxActivate+10)
	s := &scenario{f: f, pdr0: pdr, anchor: anchor, succ: c1, parentID: bytes.Repeat([]byte{0x9D}, 32)}
	s.parent = f.shardAt(pdr, f.tr(0, 5, f.shardAt(pdr, certification.TechnicalRecord{Round: 5, Leader: f.id(0)})))
	snap, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, s.parent, s.parentID, nil, anchor, c1, c2)
	require.NoError(t, err)

	type interval struct {
		round, epoch uint64
		body         []byte
	}
	var keys [][]byte
	for _, iv := range []interval{{fxActivate - 1, 3, fxBody0}, {fxActivate, 4, fxBody1}, {fxActivate + 4, 4, fxBody1}, {fxActivate + 10, 5, fxBody2}, {fxActivate + 15, 5, fxBody2}} {
		for _, purpose := range []RequestPurpose{PurposeCertify, PurposeExecute, PurposeTimeout} {
			v := s.mustResolve(snap, iv.round, iv.epoch, iv.body, purpose)
			require.EqualValues(t, 0, v.ExpectedTR().Epoch, "the shard epoch does not move with a root interval")
			require.EqualValues(t, 4, v.Context().TotalWeight(), "PolicyUnit: W=N")
			require.EqualValues(t, 3, v.Context().Threshold(), "Q=floor(N/2)+1")
			_, err := v.VerifyIRChangeReq(quorumProof(s.request(v, 0, 0, 1)), t2Rounds)
			require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached, "one signer of four")
			res, err := v.VerifyIRChangeReq(quorumProof(s.request(v, 0, 0, 1), s.request(v, 1, 1, 1), s.request(v, 2, 2, 1)), t2Rounds)
			require.NoError(t, err, "three signers of four")
			require.Equal(t, v.ViewKey(), res.ViewKey)
		}
		keys = append(keys, s.mustResolve(snap, iv.round, iv.epoch, iv.body, PurposeCertify).AssignmentKey())
	}
	require.NotEqual(t, keys[0], keys[1], "another root interval is another authorization")
	require.Equal(t, keys[1], keys[2])
	require.NotEqual(t, keys[2], keys[3])
	require.Equal(t, keys[3], keys[4])

	// exact identity equality is kept: the old root identity does not authorise a later round, and a later epoch cannot be named early
	_, err = s.resolve(snap, fxActivate+4, 3, fxBody0, PurposeCertify)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	_, err = s.resolve(snap, fxActivate+4, 5, fxBody2, PurposeCertify)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)
	_, err = s.resolve(snap, fxActivate+4, 4, fxBody2, PurposeCertify)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext, "a root body of another lineage at the right epoch")

	// a continuation named before its first round is collection-only; certification cannot use it early
	early := s.mustResolve(snap, fxActivate+9, 5, fxBody2, PurposeCollect)
	require.True(t, early.CollectionOnly())
	_, err = s.resolve(snap, fxActivate+9, 5, fxBody2, PurposeCertify)
	require.ErrorIs(t, err, ErrRequestNotActive)
	// replay of the history before the boundary keeps its own root interval
	old := s.mustResolve(snap, fxActivate-2, 3, fxBody0, PurposeReplay)
	require.NotEqual(t, old.AssignmentKey(), keys[1])
}

// A weighted EVM assignment survives root-only epochs unchanged: the continuation keeps the original context, coupling and weights (it never
// re-mirrors the new root committee), and #461's installed-parent rule still runs against the original assignment's commitment.
func TestContinuationKeepsAWeightedAssignmentAndTheInstalledParentRule(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{6, 1, 1, 1}, nil)
	cont := continuationOf(t, s.succ, 5, fxBody2, fxActivate+10)
	inst := s.installed(3)
	snap, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, inst, s.parentID, nil, s.anchor, s.succ, cont)
	require.NoError(t, err)

	for _, round := range []uint64{fxActivate + 12, fxActivate + 30} {
		v := s.mustResolve(snap, round, 5, fxBody2, PurposeExecute)
		require.EqualValues(t, 9, v.Context().TotalWeight())
		require.EqualValues(t, 5, v.Context().Threshold())
		w, _ := v.Context().SignerWeight(s.f.id(0))
		require.EqualValues(t, 6, w, "the heavy member stays heavy")
		require.Equal(t, inst.TR, v.ExpectedTR(), "the pending-ack record is the installed parent's, however many continuations followed")
		_, err := v.VerifyIRChangeReq(quorumProof(s.request(v, 0, 0, 2)), t2Rounds)
		require.NoError(t, err, "the heavy signer alone")
		_, err = v.VerifyIRChangeReq(quorumProof(s.request(v, 1, 1, 2), s.request(v, 2, 2, 2), s.request(v, 3, 3, 2)), t2Rounds)
		require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached, "three light signers")
	}
	atSucc := s.mustResolve(snap, fxActivate+2, 4, fxBody1, PurposeExecute)
	atCont := s.mustResolve(snap, fxActivate+12, 5, fxBody2, PurposeExecute)
	require.Equal(t, s.succ.ctx.Identity(), atCont.Context().Identity(), "the request context identity is stable")
	require.NotEqual(t, atSucc.AssignmentKey(), atCont.AssignmentKey(), "the authorization identity is not")

	// the tampered installed parent is still refused through a continuation
	bad := s.installed(3)
	bad.TR.FeeHash = append([]byte{bad.TR.FeeHash[0] ^ 1}, bad.TR.FeeHash[1:]...)
	badSnap, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, bad, s.parentID, nil, s.anchor, s.succ, cont)
	require.NoError(t, err)
	_, err = s.resolve(badSnap, fxActivate+12, 5, fxBody2, PurposeExecute)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext)

	// the predecessor case: before the parent installs, the complete original digest is checked through the continuation
	pre := s.snapshotWith(s.parent, s.anchor, s.succ, cont)
	v := s.mustResolve(pre, fxActivate+12, 5, fxBody2, PurposeExecute)
	require.Equal(t, s.succTR, v.ExpectedTR())
	wrong := *s.succ
	wrong.trHash = bytes.Repeat([]byte{7}, 32)
	wrongCont := continuationOf(t, &wrong, 5, fxBody2, fxActivate+10)
	badPre, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, s.parent, s.parentID, nil, s.anchor, &wrong, wrongCont)
	require.NoError(t, err)
	_, err = s.resolve(badPre, fxActivate+12, 5, fxBody2, PurposeExecute)
	require.ErrorIs(t, err, quorumweight.ErrRequestContext, "the original commitment, not a copy of a wrong one")
}

func (s *scenario) snapshotWith(parent *ShardInfo, chain ...*RequestActivation) *RequestSnapshot {
	s.f.t.Helper()
	snap, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, parent, s.parentID, nil, chain...)
	require.NoError(s.f.t, err)
	return snap
}

// A snapshot admits a continuation only as the marked, adjacent, identical-assignment next root interval; every other repetition of a shard
// epoch is refused, each way alone.
func TestSnapshotRefusesAMalformedContinuationChain(t *testing.T) {
	s := newScenario(t, []uint64{1, 1, 1, 1}, []uint64{6, 1, 1, 1}, nil)
	mk := func() *RequestActivation { return continuationOf(t, s.succ, 5, fxBody2, fxActivate+10) }
	build := func(chain ...*RequestActivation) error {
		_, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, s.installed(1), s.parentID, nil, chain...)
		return err
	}
	require.NoError(t, build(s.anchor, s.succ, mk()), "control")

	for name, mutate := range map[string]func(*RequestActivation){
		"unmarked, so a repeated shard epoch": func(c *RequestActivation) { c.continuation = false },
		"not the next root epoch":             func(c *RequestActivation) { c.rootEpoch = 7 },
		"another predecessor body":            func(c *RequestActivation) { c.predecessorRootBody = bytes.Repeat([]byte{1}, 32) },
		"a start that does not rise":          func(c *RequestActivation) { c.start = s.succ.start },
		"another request version":             func(c *RequestActivation) { c.version++ },
		"another original commitment":         func(c *RequestActivation) { c.trHash = bytes.Repeat([]byte{3}, 32) },
		"another configuration": func(c *RequestActivation) {
			c.pdr.T2Timeout++
			c.confHash = bytes.Repeat([]byte{4}, 32)
		},
		"another context": func(c *RequestActivation) { c.ctx = s.anchor.ctx },
	} {
		c := mk()
		mutate(c)
		err := build(s.anchor, s.succ, c)
		require.ErrorIs(t, err, ErrAssignmentHistory, name)
	}
	require.ErrorIs(t, build(continuationOf(t, s.anchor, 4, fxBody1, fxActivate)), ErrAssignmentHistory, "a history cannot begin with a continuation")
	first := continuationOf(t, s.anchor, 4, fxBody1, fxActivate)
	first.start, first.rootEpoch = 0, 1 // even one that looks like an anchor, followed by a valid real activation
	require.ErrorIs(t, build(first, s.succ), ErrAssignmentHistory, "the first record is a non-continuation anchor")
	require.ErrorIs(t, build(s.anchor, mk()), ErrAssignmentHistory, "a continuation of an assignment that is not in the chain")
}

// The interval after an acknowledgement block executes but before it is committed: real requests with fees and statistics have moved the
// parent's accumulators and its record's FeeHash/StatHash, none of which is the install-time commitment. The view builds on the parent's
// updated record; a one-byte change of either updated commitment is still refused, and so is accumulators that moved without the record.
func TestExpectedTRAfterExecutedRequestsInTheInstalledState(t *testing.T) {
	s := newScenario(t, []uint64{6, 1, 1, 1}, []uint64{1, 6, 1, 1}, nil)
	inst := s.installed(1)
	install := bytes.Clone(inst.TR.FeeHash)
	req := &certification.BlockCertificationRequest{PartitionID: 1, ShardID: types.ShardID{}, NodeID: s.f.id(1), BlockSize: 100, StateSize: 50,
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: inst.TR.Round, Epoch: inst.TR.Epoch, PreviousHash: []byte{1}, Hash: []byte{2}, SumOfEarnedFees: 25}}
	require.NoError(t, inst.nextRoundWith(req, s.pdr1, crypto.SHA256, resetMembers))
	require.NotEqual(t, install, inst.TR.FeeHash, "premise: the executed request moved the fee commitment")
	require.NotZero(t, inst.Stat.Blocks)

	resolve := func(si *ShardInfo) (*RequestRoundView, error) {
		snap, err := NewRequestSnapshot(fxNetwork, crypto.SHA256, si, s.parentID, nil, s.anchor, s.succ)
		require.NoError(t, err)
		return s.resolve(snap, fxActivate+9, 4, fxBody1, PurposeExecute)
	}
	v, err := resolve(inst)
	require.NoError(t, err)
	require.Equal(t, inst.TR, v.ExpectedTR(), "the updated record, not the install-time one")

	for name, mutate := range map[string]func(*ShardInfo){
		"the updated fee hash":                           func(si *ShardInfo) { si.TR.FeeHash[0] ^= 1 },
		"the updated stat hash":                          func(si *ShardInfo) { si.TR.StatHash[0] ^= 1 },
		"the install-time fee hash (a stale commitment)": func(si *ShardInfo) { si.TR.FeeHash = bytes.Clone(install) },
		"fees that moved without the record":             func(si *ShardInfo) { si.Fees[s.f.id(1)]++ },
	} {
		bad := *inst
		bad.TR = cloneTR(inst.TR)
		bad.Fees = maps.Clone(inst.Fees)
		mutate(&bad)
		view, err := resolve(&bad)
		require.ErrorIs(t, err, quorumweight.ErrRequestContext, name)
		require.Nil(t, view, name)
	}
}
