package storage_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
	"github.com/unicitynetwork/bft-core/rootchain/posreject"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The VR-mode RejectResult v2 builder (#1311) over the fixture's certified VR state: the root's own posreject in VR mode, as
// enableVRHandoff wires it.
func (f *vxFixture) rejectBuilder(t *testing.T, ready uint16) *posreject.Service {
	return f.rejectBuilderLog(t, ready, nil)
}

func (f *vxFixture) rejectBuilderLog(t *testing.T, ready uint16, log *slog.Logger) *posreject.Service {
	t.Helper()
	pins := f.pins
	svc, err := posreject.New(posreject.Config{
		Deployment: storage.PosDeployment{RootNetwork: vxNetwork,
			Deployment: evmassign.Deployment{NetworkWord: f.dep.NetworkWord, ChainID: f.dep.ChainID, Custody: f.dep.Registry}},
		VR:     &pins,
		Proofs: func([32]byte) evmstate.ProofSource { return f.world },
		Ready:  func([32]byte) uint16 { return ready },
		Log:    log,
	})
	require.NoError(t, err)
	return svc
}

// rejectionContext is what RejectionParent names for a child of the fixture's genesis: the certified EVM state, the root's authority and
// its next attempt.
func (f *vxFixture) rejectionContext(attempt uint64) storage.RejectionContext {
	rc := storage.RejectionContext{Parent: storage.EVMParent{StateRoot: f.world.Root()}, Predecessor: f.body, Attempt: attempt}
	copy(rc.Parent.BlockHash[:], f.parentEV)
	return rc
}

// built prepares the rejection for the context and returns it stamped at the round, its witness retained as the leader retains it.
func (f *vxFixture) built(t *testing.T, b *posreject.Service, rc storage.RejectionContext, round uint64) (rctypes.PosControl, bool) {
	t.Helper()
	b.Prepare(rc)
	b.Wait()
	p, ok := b.Ready(rc)
	if !ok {
		return rctypes.PosControl{}, false
	}
	f.witnesses[p.Control.WitnessHash] = p.Witness
	c := p.Control
	c.OrderingEpoch, c.OrderingRound = 1, round
	return c, true
}

// A due output (progress at expiresAtProgress) is built from certified VR state alone and every root's executor accepts it: OutputRejected
// (Expired, the builder's presence bitmap) then SessionClosed, R resolved, the attempt aborted; the next attempt opens and a Prepare of
// it is admitted (the next election proceeds); the builder then offers nothing more for R.
func TestVRRejectBuilderDueIsBuiltAndExecuted(t *testing.T) {
	f := newVXFixture(t)
	f.progress = 100 + vrschema.Lifetime
	f.attempt = 1 // the fixture's candidate is the root's attempt 1, the one after the rejection
	f.build()
	g := f.genesis()
	b := f.rejectBuilder(t, 0b0111)
	c, ok := f.built(t, b, f.rejectionContext(0), 11)
	require.True(t, ok, "due: built")
	require.True(t, c.Registry, "under the VR tag")
	data, err := vrschema.DecodeOutputRejected(c.Data)
	require.NoError(t, err)
	require.Equal(t, vrschema.OutputRejected{ResultID: f.r, Reason: vrschema.RejExpired, ReadyBitmap: 0b0111}, data)
	require.Equal(t, [][32]byte{[32]byte(f.r)}, b.Pending())

	rej := f.must(g, f.block(g, 11, 1_010, nil, c))
	recs := rej.ShardState.Records
	require.Len(t, recs, 2)
	require.Equal(t, rootrecords.KindOutputRejected, recs[0].Kind)
	require.Equal(t, data.Encode(), recs[0].Data)
	require.Equal(t, rootrecords.KindSessionClosed, recs[1].Kind)
	require.True(t, posState(t, rej).IsResolved(f.r))
	require.Equal(t, "aborted", rej.ShardState.Control.Phase)
	require.EqualValues(t, 1, rootState(t, rej).Backoff.Attempt, "attempt 1 opens")

	// the chain proceeds: the next attempt's Prepare is admitted over the rejection
	next := f.must(rej, f.block(rej, 12, 1_011, [][]byte{f.record("prepare", 1, 12).Bytes()}))
	require.True(t, rootState(t, next).Backoff.Prepared)

	b.Resolved([32]byte(f.r))
	_, ok = b.Ready(f.rejectionContext(0))
	require.False(t, ok, "a resolved result is offered no more")
}

// #1303: the root that builds an expiry rejection logs the ready bitmap it built with the result id.
func TestVRRejectBuilderLogsTheBitmapItBuilt(t *testing.T) {
	f := newVXFixture(t)
	f.progress = 100 + vrschema.Lifetime
	f.attempt = 1
	f.build()
	var buf bytes.Buffer
	b := f.rejectBuilderLog(t, 0b0101, slog.New(slog.NewTextHandler(&buf, nil)))
	_, ok := f.built(t, b, f.rejectionContext(0), 11)
	require.True(t, ok)
	require.Contains(t, buf.String(), "result="+fmt.Sprintf("%x", f.r[:]))
	require.Contains(t, buf.String(), "registry=true reason=1 readyBitmap=0x0005")
}

// An output one progress unit before its expiry is not built; neither is anything when VR has no open output.
func TestVRRejectBuilderNotYetDueIsNotBuilt(t *testing.T) {
	f := newVXFixture(t)
	f.progress = 100 + vrschema.Lifetime - 1
	f.writeWorld()
	b := f.rejectBuilder(t, 0)
	_, ok := f.built(t, b, f.rejectionContext(0), 11)
	require.False(t, ok, "not yet due")
	require.Empty(t, b.Pending())

	f.state.OpenOutput = vrschema.Word{}
	f.progress = 100 + vrschema.Lifetime
	f.writeWorld()
	b = f.rejectBuilder(t, 0)
	_, ok = f.built(t, b, f.rejectionContext(0), 11)
	require.False(t, ok, "no open output")
}

// A witness of another EVM state than the parent certified is never offered: the builder checks it against the certified root first.
func TestVRRejectBuilderChecksTheWitnessAgainstTheCertifiedRoot(t *testing.T) {
	f := newVXFixture(t)
	f.progress = 100 + vrschema.Lifetime
	f.writeWorld()
	rc := f.rejectionContext(0)
	rc.Parent.StateRoot[0] ^= 1
	_, ok := f.built(t, f.rejectBuilder(t, 0), rc, 11)
	require.False(t, ok)
}

// Voters refuse a wrong or forged RejectResult v2 however the leader made it: a witness of another EVM state (a VR that moved), a
// forged witness under the control's hash, another reason than the due table's, another attempt, and a state root the parent did not
// certify.
func TestVRRejectBuilderForgedOrWrongIsRefusedByVoters(t *testing.T) {
	f := newVXFixture(t)
	f.progress = 100 + vrschema.Lifetime
	f.writeWorld()
	g := f.genesis()
	good, ok := f.built(t, f.rejectBuilder(t, 0), f.rejectionContext(0), 11)
	require.True(t, ok)
	_ = f.must(g, f.block(g, 11, 1_010, nil, good)) // the honest one is accepted

	exec := func(c rctypes.PosControl) error {
		_, err := f.exec(g, f.block(g, 11, 1_010, nil, c))
		return err
	}
	t.Run("a witness of another EVM state", func(t *testing.T) {
		other := newVXFixture(t)
		other.progress = 100 + vrschema.Lifetime + 7
		other.writeWorld()
		oc, ok := other.built(t, other.rejectBuilder(t, 0), other.rejectionContext(0), 11)
		require.True(t, ok)
		w := other.witnesses[oc.WitnessHash]
		c := good
		c.WitnessHash = sha256.Sum256(w)
		f.witnesses[c.WitnessHash] = w
		require.ErrorIs(t, exec(c), storage.ErrVRControlRefused)
	})
	t.Run("a forged witness under the control's hash", func(t *testing.T) {
		forged := append([]byte(nil), f.witnesses[good.WitnessHash]...)
		forged[len(forged)/2] ^= 0xff
		c := good
		c.WitnessHash = sha256.Sum256(forged)
		f.witnesses[c.WitnessHash] = forged
		require.ErrorIs(t, exec(c), storage.ErrVRControlRefused)
		// and the retained bytes are not the committed ones
		c = good
		saved := f.witnesses[good.WitnessHash]
		f.witnesses[good.WitnessHash] = forged
		require.Error(t, exec(c))
		f.witnesses[good.WitnessHash] = saved
	})
	t.Run("another reason", func(t *testing.T) {
		c := good
		c.Data = vrschema.OutputRejected{ResultID: f.r, Reason: vrschema.RejInvalidated}.Encode()
		require.ErrorIs(t, exec(c), vradmit.ErrReject)
	})
	t.Run("another attempt", func(t *testing.T) {
		c := good
		r := *good.Reject
		r.Attempt = 1
		c.Reject = &r
		require.ErrorIs(t, exec(c), storage.ErrRejectAttempt)
	})
	t.Run("a state root the parent did not certify", func(t *testing.T) {
		c := good
		r := *good.Reject
		r.EVMStateRoot[0] ^= 1
		c.Reject = &r
		require.ErrorIs(t, exec(c), storage.ErrNotLatestEVM)
	})
}
