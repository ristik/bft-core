package storage

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

type fakeAuthority struct {
	facts ClosureFacts
	err   error
	seen  []byte
}

func (a *fakeAuthority) VerifyClosure(witness []byte, closedEpoch uint64) (ClosureFacts, error) {
	a.seen = witness
	return a.facts, a.err
}

type fakeWitnesses map[[32]byte][]byte

func (w fakeWitnesses) Witness(h [32]byte) ([]byte, error) {
	if b, ok := w[h]; ok {
		return b, nil
	}
	return nil, errors.New("missing")
}

func fid(i uint64, weight uint64) evmassign.Identity {
	sid := make([]byte, 32)
	sid[31] = byte(i)
	payee := make([]byte, 20)
	payee[0] = byte(i)
	ld := evmassign.LotsDigest([]uint64{i})
	rk, ek := make([]byte, 33), make([]byte, 33)
	rk[0], ek[0] = 2, 2
	rk[1], ek[1] = byte(i), byte(i)+100
	return evmassign.Identity{StakingID: sid, Generation: 1, RootNodeID: "r", RootKey: rk, EVMNodeID: "e", EVMKey: ek, Weight: weight, OperatorPayee: payee, ExposureDigest: ld[:]}
}

type closeFx struct {
	svc     *PosServices
	auth    *fakeAuthority
	witness []byte
	ctl     rctypes.PosControl
	block   *rctypes.BlockData
	step    posStep
}

func word(v uint64) []byte {
	w := make([]byte, 32)
	for i := 0; i < 8; i++ {
		w[31-i] = byte(v >> (8 * i))
	}
	return w
}

func newCloseFx(t *testing.T) *closeFx {
	t.Helper()
	dep := PosDeployment{RootNetwork: 7, Deployment: evmassign.Deployment{NetworkWord: [32]byte{1}, ChainID: [32]byte{31: 9}, Custody: [20]byte{19: 5}}}
	ids := []evmassign.Identity{fid(1, 6), fid(2, 1)}
	asg := [32]byte{0xa5}
	ed, err := evmassign.AssignmentExposureDigest(dep.Deployment, asg, ids)
	require.NoError(t, err)
	kd, err := evmassign.KeyHistoryDigest(ids)
	require.NoError(t, err)
	hRec, tRoot := [32]byte{0x4a}, [32]byte{0x7e}
	facts := ClosureFacts{ClosedEpoch: 1, BundleID: [32]byte{0xb0}, HRecordID: hRec, HRound: 100, TerminalRoot: tRoot, AssignmentID: asg, Closed: ids}
	data := append(append(append(append(append(asg[:len(asg):len(asg)], word(100)...), hRec[:]...), tRoot[:]...), ed[:]...), kd[:]...)
	witness := []byte("canonical bundle")
	f := &closeFx{auth: &fakeAuthority{facts: facts}, witness: witness}
	f.svc = &PosServices{Deployment: dep, Authority: f.auth, Witnesses: fakeWitnesses{sha256.Sum256(witness): witness}}
	f.ctl = rctypes.PosControl{Network: 7, ChainID: dep.ChainID, Custody: dep.Custody, OrderingEpoch: 2, OrderingRound: 105, Op: rctypes.OpCloseLiability,
		Close: &rctypes.CloseContext{ClosedEpoch: 1, BundleSemanticID: facts.BundleID}, Data: data, WitnessHash: sha256.Sum256(witness)}
	st := rootrecords.NewState(1, 1)
	st, err = st.Commit(100, 2, 101, true, [32]byte{0xb1})
	require.NoError(t, err)
	st, err = st.Block(2, 105)
	require.NoError(t, err)
	f.step = posStep{on: true, state: st}
	f.block = &rctypes.BlockData{Epoch: 2, Round: 105, Timestamp: 1_500, Payload: &rctypes.Payload{PosControls: []rctypes.PosControl{f.ctl}}}
	return f
}

func (f *closeFx) run() error {
	f.block.Payload.PosControls = []rctypes.PosControl{f.ctl}
	_, err := f.step.controls(f.block, f.svc, posEnv{})
	return err
}

func TestCloseLiabilityProjectsOnceFromAVerifiedBundle(t *testing.T) {
	f := newCloseFx(t)
	require.NoError(t, f.run())
	require.Len(t, f.step.records, 1)
	r := f.step.records[0]
	require.Equal(t, rootrecords.KindClosure, r.Kind)
	require.Equal(t, f.ctl.Data, r.Data)
	require.EqualValues(t, 1_500, r.UCTime)
	require.Empty(t, f.step.state.Awaiting)
	require.True(t, f.step.changed)
	require.Equal(t, f.witness, f.auth.seen, "the authority verified the retained bytes the control committed to")
	// the first closure is the only one
	require.ErrorIs(t, f.run(), ErrPosControlRefused)
	require.Len(t, f.step.records, 1)
}

func TestCloseLiabilityRefusals(t *testing.T) {
	flip := func(b []byte, i int) []byte { c := append([]byte(nil), b...); c[i] ^= 1; return c }
	cases := map[string]func(f *closeFx){
		"another network":           func(f *closeFx) { f.ctl.Network++ },
		"another chain":             func(f *closeFx) { f.ctl.ChainID[31]++ },
		"another custody":           func(f *closeFx) { f.ctl.Custody[19]++ },
		"another ordering round":    func(f *closeFx) { f.ctl.OrderingRound++ },
		"another ordering epoch":    func(f *closeFx) { f.ctl.OrderingEpoch++ },
		"an epoch no handoff ended": func(f *closeFx) { f.ctl.Close.ClosedEpoch = 5 },
		"a bundle of another epoch": func(f *closeFx) { f.auth.facts.ClosedEpoch = 3 },
		"another bundle":            func(f *closeFx) { f.ctl.Close.BundleSemanticID[0]++ },
		"another assignment":        func(f *closeFx) { f.ctl.Data = flip(f.ctl.Data, 0) },
		"another H round":           func(f *closeFx) { f.ctl.Data = flip(f.ctl.Data, 63) },
		"a bundle of another H round than the control and the root": func(f *closeFx) { f.auth.facts.HRound = 101 },
		"a control and a bundle that agree on a round the root did not record": func(f *closeFx) {
			f.ctl.Data = append(append(append([]byte(nil), f.ctl.Data[:32]...), word(101)...), f.ctl.Data[64:]...)
			f.auth.facts.HRound = 101
		},
		"another H record":                             func(f *closeFx) { f.ctl.Data = flip(f.ctl.Data, 64) },
		"another terminal root":                        func(f *closeFx) { f.ctl.Data = flip(f.ctl.Data, 96) },
		"a forged exposure digest":                     func(f *closeFx) { f.ctl.Data = flip(f.ctl.Data, 128) },
		"a forged key digest":                          func(f *closeFx) { f.ctl.Data = flip(f.ctl.Data, 160) },
		"the authority rejects":                        func(f *closeFx) { f.auth.err = errors.New("bad terminal proof") },
		"another witness":                              func(f *closeFx) { f.ctl.WitnessHash[0]++ },
		"identities that do not match the digests":     func(f *closeFx) { f.auth.facts.Closed = []evmassign.Identity{fid(1, 6), fid(2, 2)} },
		"identities the digests cannot be formed from": func(f *closeFx) { f.auth.facts.Closed = []evmassign.Identity{fid(2, 1), fid(1, 6)} },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := newCloseFx(t)
			mut(f)
			err := f.run()
			require.Error(t, err)
			if name == "another witness" {
				require.ErrorIs(t, err, ErrWitnessUnavailable)
			} else {
				require.ErrorIs(t, err, ErrPosControlRefused)
			}
			require.Empty(t, f.step.records, "a refused control projects nothing")
			require.Len(t, f.step.state.Awaiting, 1, "and leaves the closure outstanding")
		})
	}
}

func TestCloseLiabilityWitnessBytesMustHashToTheCommitment(t *testing.T) {
	f := newCloseFx(t)
	f.svc.Witnesses = fakeWitnesses{f.ctl.WitnessHash: []byte("not the bundle")}
	require.ErrorIs(t, f.run(), ErrPosControlRefused)
}

func TestControlsAreRefusedWithoutServicesOrASourceState(t *testing.T) {
	f := newCloseFx(t)
	f.svc = nil
	require.ErrorIs(t, f.run(), ErrPosControls)
	f = newCloseFx(t)
	f.step.on = false
	require.ErrorIs(t, f.run(), ErrPosControls)
	f = newCloseFx(t)
	f.svc.Authority = nil
	require.ErrorIs(t, f.run(), ErrPosControls)
	// no control, nothing to serve
	f = newCloseFx(t)
	f.block.Payload.PosControls = nil
	f.svc = nil
	_, err := f.step.controls(f.block, f.svc, posEnv{})
	require.NoError(t, err)
}

type fakeEVM struct {
	roots  map[[32]byte][32]byte
	retire RetirementFacts
	reject RejectFacts
	err    error
	seen   []byte
}

func (e *fakeEVM) StateRoot(h [32]byte) ([32]byte, error) {
	if r, ok := e.roots[h]; ok {
		return r, nil
	}
	return [32]byte{}, errors.New("uncertified")
}
func (e *fakeEVM) VerifyRetirement(w []byte, root [32]byte, id, gen uint64) (RetirementFacts, error) {
	e.seen = w
	return e.retire, e.err
}
func (e *fakeEVM) VerifyReject(w []byte, root [32]byte) (RejectFacts, error) {
	e.seen = w
	return e.reject, e.err
}

type evmFx struct {
	svc   *PosServices
	evm   *fakeEVM
	step  posStep
	env   posEnv
	block *rctypes.BlockData
	ctl   rctypes.PosControl
}

var (
	pBlock = [32]byte{0xe1}
	pRoot  = [32]byte{0xe2}
)

func newEVMFx(t *testing.T, op uint64) *evmFx {
	t.Helper()
	witness := []byte("accounts")
	evm := &fakeEVM{roots: map[[32]byte][32]byte{pBlock: pRoot}}
	dep := PosDeployment{RootNetwork: 7, Deployment: evmassign.Deployment{NetworkWord: [32]byte{1}, ChainID: [32]byte{31: 9}, Custody: [20]byte{19: 5}}}
	f := &evmFx{evm: evm}
	f.svc = &PosServices{Deployment: dep, Authority: &fakeAuthority{}, Witnesses: fakeWitnesses{sha256.Sum256(witness): witness}, EVM: evm}
	st := rootrecords.NewState(1, 1)
	f.step = posStep{on: true, state: st}
	f.env = posEnv{Control: &evmroot.ControlState{Network: 7, Epoch: 1, PredecessorBodyID: bytes32(0x77), Phase: "idle"}, LatestEVM: pBlock, LatestEVMOK: true}
	f.block = &rctypes.BlockData{Epoch: 1, Round: 50, Timestamp: 2_000, Payload: &rctypes.Payload{}}
	f.ctl = rctypes.PosControl{Network: 7, ChainID: dep.ChainID, Custody: dep.Custody, OrderingEpoch: 1, OrderingRound: 50, Op: op, WitnessHash: sha256.Sum256(witness)}
	switch op {
	case rctypes.OpRetirement:
		ref := [32]byte{0xc4}
		f.ctl.Retire = &rctypes.RetireContext{EVMBlockHash: pBlock, EVMStateRoot: pRoot}
		f.ctl.Data = append(append(word(3), word(2)...), ref[:]...)
		evm.retire = RetirementFacts{ID: 3, Generation: 2, RefDigest: ref, MaxLiabilityAnchor: 40, Requested: true, NotImported: true,
			NoLiveExposures: true, NoLotReferences: true, RecordsCaughtUp: true}
	case rctypes.OpRejectResult:
		res := [32]byte{0x5e}
		f.ctl.Reject = &rctypes.RejectContext{PredecessorBodyID: [32]byte{0x77}, Attempt: 0, EVMBlockHash: pBlock, EVMStateRoot: pRoot}
		f.ctl.Data = res[:]
		evm.reject = RejectFacts{ResultID: res, PredecessorBodyID: [32]byte{0x77}, Attempt: 0, Unresolved: true, NoInstalledSession: true}
	}
	return f
}

func bytes32(b byte) []byte { x := [32]byte{b}; return x[:] }

func (f *evmFx) run() (*evmroot.ControlState, error) {
	f.block.Payload.PosControls = []rctypes.PosControl{f.ctl}
	return f.step.controls(f.block, f.svc, f.env)
}

func TestRetirementProjectsFromCertifiedCustodyState(t *testing.T) {
	f := newEVMFx(t, rctypes.OpRetirement)
	f.step.state = mustProgress(t, f.step.state)
	replaced, err := f.run()
	require.NoError(t, err)
	require.Nil(t, replaced)
	require.Len(t, f.step.records, 1)
	r := f.step.records[0]
	require.Equal(t, rootrecords.KindRetirement, r.Kind)
	require.Equal(t, f.ctl.Data, r.Data)
	require.EqualValues(t, 2_000, r.UCTime)
	require.Equal(t, []byte("accounts"), f.evm.seen)
	ref, ok := f.step.state.IsRetired(3, 2)
	require.True(t, ok)
	require.Equal(t, [32]byte{0xc4}, ref)
	// the same request again returns the existing outcome and emits nothing
	_, err = f.run()
	require.NoError(t, err)
	require.Len(t, f.step.records, 1)
}

func mustProgress(t *testing.T, s rootrecords.State) rootrecords.State { return s }

func TestRetirementRefusals(t *testing.T) {
	cases := map[string]func(f *evmFx){
		"P is not the latest certified":        func(f *evmFx) { f.env.LatestEVM = [32]byte{0xff} },
		"no certified EVM in the parent":       func(f *evmFx) { f.env.LatestEVMOK = false },
		"a state root that is not the block's": func(f *evmFx) { f.ctl.Retire.EVMStateRoot[0]++ },
		"a handoff in flight":                  func(f *evmFx) { f.env.InFlight = true },
		"another identity":                     func(f *evmFx) { f.evm.retire.ID = 4 },
		"another generation":                   func(f *evmFx) { f.evm.retire.Generation = 3 },
		"a refDigest that is not custody's":    func(f *evmFx) { f.evm.retire.RefDigest[0]++ },
		"no request at P":                      func(f *evmFx) { f.evm.retire.Requested = false },
		"already retired in the registry":      func(f *evmFx) { f.evm.retire.NotImported = false },
		"a live exposure":                      func(f *evmFx) { f.evm.retire.NoLiveExposures = false },
		"a lot reference":                      func(f *evmFx) { f.evm.retire.NoLotReferences = false },
		"records not caught up":                func(f *evmFx) { f.evm.retire.RecordsCaughtUp = false },
		"progress below the liability anchor":  func(f *evmFx) { f.evm.retire.MaxLiabilityAnchor = 1 << 40 },
		"the proof verifier rejects":           func(f *evmFx) { f.evm.err = errors.New("bad proof") },
		"a witness that is not available":      func(f *evmFx) { f.ctl.WitnessHash[0]++ },
		"a retirement id above uint64": func(f *evmFx) {
			f.ctl.Data[0] = 1
			f.evm.retire.ID = 0
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := newEVMFx(t, rctypes.OpRetirement)
			mut(f)
			_, err := f.run()
			require.Error(t, err)
			if name == "a witness that is not available" {
				require.ErrorIs(t, err, ErrWitnessUnavailable)
			} else if name == "progress below the liability anchor" {
				require.ErrorIs(t, err, rootrecords.ErrRetireEarly)
			} else {
				require.ErrorIs(t, err, ErrPosControlRefused)
			}
			require.Empty(t, f.step.records)
			_, retired := f.step.state.IsRetired(3, 2)
			require.False(t, retired)
		})
	}
	t.Run("a conflicting repeat", func(t *testing.T) {
		f := newEVMFx(t, rctypes.OpRetirement)
		_, err := f.run()
		require.NoError(t, err)
		f.evm.retire.RefDigest[1]++
		copy(f.ctl.Data[64:], f.evm.retire.RefDigest[:])
		_, err = f.run()
		require.ErrorIs(t, err, rootrecords.ErrRetirementConflict)
		require.Len(t, f.step.records, 1)
	})
	t.Run("no EVM authority", func(t *testing.T) {
		f := newEVMFx(t, rctypes.OpRetirement)
		f.svc.EVM = nil
		_, err := f.run()
		require.ErrorIs(t, err, ErrPosControls)
	})
}

func TestRejectResultClosesTheSessionAndMovesTheAttemptCursor(t *testing.T) {
	f := newEVMFx(t, rctypes.OpRejectResult)
	before := f.env.Control.Digest()
	replaced, err := f.run()
	require.NoError(t, err)
	require.NotNil(t, replaced)
	require.Equal(t, "aborted", replaced.Phase)
	require.EqualValues(t, 0, replaced.Attempt)
	require.EqualValues(t, 50, replaced.OrderedRound)
	require.Equal(t, before, replaced.PreviousDigest)
	require.Equal(t, bytes32(0x77), replaced.PredecessorBodyID)
	require.Len(t, f.step.records, 1)
	require.Equal(t, rootrecords.KindSessionClosed, f.step.records[0].Kind)
	require.Equal(t, f.ctl.Data, f.step.records[0].Data)
	require.EqualValues(t, 2_000, f.step.records[0].UCTime)

	// the next attempt is attempt one, and a second rejection of attempt zero is stale
	f.env.Control = replaced
	_, err = f.run()
	require.ErrorIs(t, err, ErrPosControlRefused)
	f.ctl.Reject.Attempt, f.evm.reject.Attempt = 1, 1
	next, err := f.run()
	require.NoError(t, err)
	require.EqualValues(t, 1, next.Attempt)
}

func TestRejectResultRefusals(t *testing.T) {
	cases := map[string]func(f *evmFx){
		"a prepared handoff":  func(f *evmFx) { f.env.Control.Phase = "prepared" },
		"an endorsed handoff": func(f *evmFx) { f.env.Control.Phase = "endorsed" },
		"a committed handoff": func(f *evmFx) { f.env.Control.Phase = "committed" },
		"a pending primary":   func(f *evmFx) { f.step.state.Pending = []rootrecords.PendingH{{Epoch: 1, HRound: 9}} },
		"another predecessor than the control state's": func(f *evmFx) {
			f.ctl.Reject.PredecessorBodyID[0]++
			f.evm.reject.PredecessorBodyID[0]++
		},
		"a stale attempt":                      func(f *evmFx) { f.ctl.Reject.Attempt = 3 },
		"P is not the latest certified":        func(f *evmFx) { f.env.LatestEVM = [32]byte{0xff} },
		"a state root that is not the block's": func(f *evmFx) { f.ctl.Reject.EVMStateRoot[0]++ },
		"another result in the proof":          func(f *evmFx) { f.evm.reject.ResultID[0]++ },
		"another predecessor in the proof":     func(f *evmFx) { f.evm.reject.PredecessorBodyID[0]++ },
		"another attempt in the proof":         func(f *evmFx) { f.evm.reject.Attempt = 1 },
		"an already resolved result":           func(f *evmFx) { f.evm.reject.Unresolved = false },
		"a competing installed session":        func(f *evmFx) { f.evm.reject.NoInstalledSession = false },
		"the proof verifier rejects":           func(f *evmFx) { f.evm.err = errors.New("bad proof") },
		"no handoff control state":             func(f *evmFx) { f.env.Control = nil },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			f := newEVMFx(t, rctypes.OpRejectResult)
			mut(f)
			replaced, err := f.run()
			require.Error(t, err)
			if name == "no handoff control state" {
				require.ErrorIs(t, err, ErrPosControls)
			} else {
				require.ErrorIs(t, err, ErrPosControlRefused)
			}
			require.Nil(t, replaced)
			require.Empty(t, f.step.records)
		})
	}
}

func TestControlsInOneBlockAreCappedAtTheRecordLimit(t *testing.T) {
	f := newEVMFx(t, rctypes.OpRetirement)
	for i := 0; i < maxBlockRecords+1; i++ {
		f.step.records = append(f.step.records, rootrecords.Record{})
	}
	f.block.Payload.PosControls = nil
	_, err := f.step.controls(f.block, f.svc, f.env)
	require.ErrorIs(t, err, ErrPosControlRefused)
}

func TestAbortClosesTheSessionOfARetainedPrimaryOnly(t *testing.T) {
	f := newAssignmentFixture(t)
	primary := f.candidate(t)
	recovery := primary
	recovery.Kind, recovery.PoPs, recovery.ReplacedAssignment = evmassign.KindRecovery, nil, bytes.Repeat([]byte{1}, 32)
	pEnc, err := primary.Encode()
	require.NoError(t, err)
	rEnc, err := recovery.Encode()
	require.NoError(t, err)
	body := bytes.Repeat([]byte{4}, 32)
	abort := evmroot.OrderedHandoffRecord{Kind: "abort", NextBodyID: body}
	newStep := func() *posStep { return &posStep{on: true, state: rootrecords.NewState(1, 1)} }

	p := newStep()
	require.NoError(t, p.abort(fixedCandidates{string(body): pEnc}, abort, 20, 3_000))
	require.Len(t, p.records, 1)
	want := primary.ResultID()
	require.Equal(t, rootrecords.KindSessionClosed, p.records[0].Kind)
	require.Equal(t, want[:], p.records[0].Data)
	require.EqualValues(t, 3_000, p.records[0].UCTime)

	p = newStep()
	require.NoError(t, p.abort(fixedCandidates{string(body): rEnc}, abort, 20, 3_000))
	require.Empty(t, p.records, "the abort of a recovery attempt only advances that attempt")

	p = newStep()
	require.NoError(t, p.abort(fixedCandidates{}, abort, 20, 3_000))
	require.Empty(t, p.records, "no retained candidate names no result")
	require.NoError(t, p.abort(nil, abort, 20, 3_000))
	require.Empty(t, p.records)

	require.ErrorIs(t, newStep().abort(fixedCandidates{string(body): {1}}, abort, 20, 3_000), ErrPosSource)
	off := &posStep{}
	require.NoError(t, off.abort(fixedCandidates{string(body): pEnc}, abort, 20, 3_000))
	require.Empty(t, off.records)
	require.ErrorIs(t, newStep().abort(fixedCandidates{string(body): pEnc}, abort, 20, 0), ErrPosSource, "an abort without committed time")
}

type fakeProposer struct {
	build func(epoch, oe, or uint64) (rctypes.PosControl, error)
	calls int
}

func (p *fakeProposer) Closure(epoch, oe, or uint64) (rctypes.PosControl, error) {
	p.calls++
	return p.build(epoch, oe, or)
}

func TestClosureIsMandatoryInTheSuccessorsFirstOrdinaryBlock(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	h := f.commitAssignment(t)
	assignment, err := h.candidate.AssignmentID()
	require.NoError(t, err)

	dep := PosDeployment{RootNetwork: 5, Deployment: evmassign.Deployment{NetworkWord: [32]byte{1}, ChainID: [32]byte{31: 9}, Custody: [20]byte{19: 5}}}
	closed := []evmassign.Identity{fid(1, 6), fid(2, 1)}
	ed, err := evmassign.AssignmentExposureDigest(dep.Deployment, assignment, closed)
	require.NoError(t, err)
	kd, err := evmassign.KeyHistoryDigest(closed)
	require.NoError(t, err)
	hRec, tRoot := [32]byte{0x4a}, [32]byte{0x7e}
	witness := []byte("bundle")
	facts := ClosureFacts{ClosedEpoch: 1, BundleID: [32]byte{0xb0}, HRecordID: hRec, HRound: 4, TerminalRoot: tRoot, AssignmentID: assignment, Closed: closed}
	data := append(append(append(append(append(assignment[:len(assignment):len(assignment)], word(4)...), hRec[:]...), tRoot[:]...), ed[:]...), kd[:]...)
	control := func(epoch, oe, or uint64) (rctypes.PosControl, error) {
		return rctypes.PosControl{Network: 5, ChainID: dep.ChainID, Custody: dep.Custody, OrderingEpoch: oe, OrderingRound: or, Op: rctypes.OpCloseLiability,
			Close: &rctypes.CloseContext{ClosedEpoch: epoch, BundleSemanticID: facts.BundleID}, Data: data, WitnessHash: sha256.Sum256(witness)}, nil
	}
	proposer := &fakeProposer{build: control}
	svc := &PosServices{Deployment: dep, Authority: &fakeAuthority{facts: facts}, Witnesses: fakeWitnesses{sha256.Sum256(witness): witness}, Proposer: proposer}

	// the proposer sees the duty on the suffix's state: the first ordinary round of epoch 2 awaits epoch 1's closure
	f.store.SetPosServices(svc)
	cs, err := f.store.ClosureControls(5, 2, 7)
	require.NoError(t, err)
	require.Len(t, cs, 1)
	require.EqualValues(t, 1, cs[0].Close.ClosedEpoch)
	require.EqualValues(t, 7, cs[0].OrderingRound)
	none, err := f.store.ClosureControls(5, 1, 6)
	require.NoError(t, err)
	require.Empty(t, none, "a suffix round of the old epoch needs none")
	proposer.build = func(uint64, uint64, uint64) (rctypes.PosControl, error) {
		return rctypes.PosControl{}, errors.New("no bundle")
	}
	_, err = f.store.ClosureControls(5, 2, 7)
	require.ErrorIs(t, err, ErrWitnessUnavailable)
	proposer.build = control
	f.store.SetPosServices(&PosServices{Deployment: dep, Authority: svc.Authority, Witnesses: svc.Witnesses})
	_, err = f.store.ClosureControls(5, 2, 7)
	require.ErrorIs(t, err, ErrWitnessUnavailable, "the duty without anyone to build the closure")
	none, err = f.store.ClosureControls(5, 1, 6)
	require.NoError(t, err, "no duty at this round, so no proposer is needed")
	require.Empty(t, none)
	f.store.SetPosServices(nil)
	none, err = f.store.ClosureControls(5, 2, 7)
	require.NoError(t, err)
	require.Empty(t, none, "no services, no duty")

	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	s.SetPosServices(svc)
	bare := &rctypes.BlockData{Version: 2, Round: 7, Epoch: 2, Timestamp: 1_000, Payload: &rctypes.Payload{Version: 2}, Anchor: anchor}
	_, err = s.Add(bare, nil)
	require.ErrorIs(t, err, ErrClosureMissing)

	c, err := control(1, 2, 7)
	require.NoError(t, err)
	with := &rctypes.BlockData{Version: 2, Round: 7, Epoch: 2, Timestamp: 1_000, Payload: &rctypes.Payload{Version: 2, PosControls: []rctypes.PosControl{c}}, Anchor: anchor}
	_, err = s.Add(with, nil)
	require.NoError(t, err)
	b7 := mustBlock(t, s, 7)
	require.Len(t, b7.ShardState.Records, 1)
	require.Equal(t, rootrecords.KindClosure, b7.ShardState.Records[0].Kind)
	require.Equal(t, data, b7.ShardState.Records[0].Data)
	require.Empty(t, posOfBlock(t, b7).Awaiting)

	// afterwards an empty block is fine: the duty is discharged
	prior := b7
	_, err = s.Add(&rctypes.BlockData{Version: 2, Round: 8, Epoch: 2, Timestamp: 1_001, Payload: &rctypes.Payload{Version: 2},
		Qc: &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 7, Epoch: 2, CurrentRootHash: prior.RootHash}}}, nil)
	require.NoError(t, err)
}

func TestAnAwaitingClosureMakesAControlFreeBlockInvalidOnlyWhereTheDutyIsEnforced(t *testing.T) {
	f := newCloseFx(t)
	f.block.Payload.PosControls = nil
	_, err := f.step.controls(f.block, f.svc, posEnv{})
	require.ErrorIs(t, err, ErrClosureMissing)

	// without an authority the chain is not enforcing the duty
	f = newCloseFx(t)
	f.block.Payload.PosControls = nil
	f.svc.Authority = nil
	_, err = f.step.controls(f.block, f.svc, posEnv{})
	require.NoError(t, err)
	f.svc = nil
	_, err = f.step.controls(f.block, f.svc, posEnv{})
	require.NoError(t, err)

	// a block that closes one of two outstanding epochs still owes the other
	f = newCloseFx(t)
	f.step.state.Awaiting = append(f.step.state.Awaiting, rootrecords.Awaiting{Epoch: 2, HRound: 101})
	require.ErrorIs(t, f.run(), ErrClosureMissing)
	require.Len(t, f.step.records, 1, "the closure that was given is projected before the duty is judged")
}
