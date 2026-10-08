package storage

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
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
	return f.step.controls(f.block, f.svc)
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
	require.NoError(t, f.step.controls(f.block, f.svc))
}

func TestRetirementAndRejectAreNotExecutedYet(t *testing.T) {
	f := newCloseFx(t)
	f.ctl.Op, f.ctl.Close = rctypes.OpRetirement, nil
	f.ctl.Retire = &rctypes.RetireContext{}
	require.ErrorIs(t, f.run(), ErrPosControlRefused)
}
