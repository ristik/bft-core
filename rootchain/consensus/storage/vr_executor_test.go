package storage_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/rootrecords"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// A VR-mode primary handoff through the real block executor: the Prepare is PR of the stored attempt, the Freeze v5 is admitted by
// registry-mode admission over the real VR witness at the frozen parent, its certificate's view drives FZ, the Boundary is staged with the
// candidate's rejectedBitmap, and the block retains the derived body, the merged receipts and both candidate encodings.
func TestVRPrimaryFreezeThroughTheExecutor(t *testing.T) {
	f := newVXFixture(t)
	g := f.genesis()
	require.Equal(t, uint8(0), rootState(t, g).Backoff.Level)

	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	s := rootState(t, prep)
	require.True(t, s.Backoff.Prepared, "PR")
	require.EqualValues(t, 1_010, s.PrepareUCTime, "the activation time gate reads the Prepare's committed UC time")
	require.Equal(t, f.parentEV, prep.ShardState.Control.FrozenParent)

	fz := f.must(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)}))
	require.Equal(t, "endorsed", fz.ShardState.Control.Phase)
	s = rootState(t, fz)
	require.True(t, s.Backoff.Settled, "FZ settles the attempt")
	require.Equal(t, uint8(0), s.Backoff.Level, "decLevel(0, 0, 4) = 0")
	require.Equal(t, f.r, s.StagedResult)
	require.Equal(t, f.q3.Identity(), s.StagedBody)
	require.Zero(t, s.StagedBitmap, "the one change is Accepted")
	require.Zero(t, f.auth.FreezeCalls, "a Freeze v5 is not judged by the old-set endorsement")
	body, receipts, v5, v6, ok := storage.VRRetainedForTest(fz)
	require.True(t, ok)
	require.Equal(t, f.q3.Encode(), body)
	require.Equal(t, f.candRaw, v6)
	c5, err := evmassign.DecodeCandidate(v5)
	require.NoError(t, err, "the v5 view is what the install, lifecycle and acknowledgement paths decode")
	require.Equal(t, f.r, vrschema.Word(c5.ResultID()))
	require.NotEmpty(t, receipts)
	require.Len(t, f.intents.queries, 1)
	require.Equal(t, f.candRaw, f.intents.queries[0].Candidate, "the intent is derived over the certified candidate")
}

// A success decrements relative to the clamped effective level: at L = 2 with a certificate of view 1 (n = 4) the level becomes
// decLevel(2, 1, 4) = 1.
func TestVRFreezeOfALaterViewDecrementsFromTheEffectiveLevel(t *testing.T) {
	f := newVXFixture(t)
	g := f.genesis()
	s := rootState(t, g)
	s.Backoff.Level = 2
	raw, err := s.Encode()
	require.NoError(t, err)
	g.ShardState.Control.VR = raw
	view := rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: 11,
		Op: rctypes.OpHandoffView, View: &rctypes.ViewContext{IntentDigest: f.intent, View: 1}}
	_, err = f.exec(g, f.block(g, 11, 1_039, nil, view))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "T(2, 0) = 40 s")
	b1 := f.must(g, f.block(g, 11, 1_040, nil, view))
	prep := f.must(b1, f.block(b1, 12, 1_041, [][]byte{f.record("prepare", 0, 12).Bytes()}))
	fz := f.must(prep, f.block(prep, 13, 1_042, [][]byte{f.record("freeze", 0, 13).Bytes(), f.freezeV5(1)}))
	require.Equal(t, uint8(1), rootState(t, fz).Backoff.Level)
	require.True(t, rootState(t, fz).Backoff.Settled)
}

// HandoffView through the executor: the replay rule over the committed backoff and the derivable intent, the HV transition and the view's
// open time; refused before the replay floor, for a non-derivable intent, out of order and after a Prepare.
func TestVRHandoffViewThroughTheExecutor(t *testing.T) {
	f := newVXFixture(t)
	g := f.genesis()
	view := func(round, v uint64) rctypes.PosControl {
		return rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: round,
			Op: rctypes.OpHandoffView, View: &rctypes.ViewContext{IntentDigest: f.intent, View: v}}
	}
	// T(0, 0) = 10 s from the anchor's UC time 1000
	_, err := f.exec(g, f.block(g, 11, 1_009, nil, view(11, 1)))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "before the replay floor")
	_, err = f.exec(g, f.block(g, 11, 1_010, nil, view(11, 2)))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "not the next view")
	f.intents.ok = false
	_, err = f.exec(g, f.block(g, 11, 1_010, nil, view(11, 1)))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "no derivable intent")
	f.intents.ok = true

	b1 := f.must(g, f.block(g, 11, 1_010, nil, view(11, 1)))
	s := rootState(t, b1)
	require.Equal(t, f.intent[:], []byte(s.Backoff.Intent), "view 1 binds the intent")
	require.EqualValues(t, 1, s.Backoff.LastView)
	require.EqualValues(t, 1_010, s.OpenUCTime)
	_, err = f.exec(b1, f.block(b1, 12, 1_019, nil, view(12, 2)))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "T(0, 1) = 10 s after view 1 opened")
	b2 := f.must(b1, f.block(b1, 12, 1_020, nil, view(12, 2)))
	require.EqualValues(t, 2, rootState(t, b2).Backoff.LastView)

	// a Prepare committed for the attempt ends the views
	prep := f.must(b2, f.block(b2, 13, 1_021, [][]byte{f.record("prepare", 0, 13).Bytes()}))
	_, err = f.exec(prep, f.block(prep, 14, 1_100, nil, view(14, 3)))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "PrepareCommitted")
}

// The backoff through the executor: a Prepare that lapses and cools down opens the next attempt in the first block past the cooldown,
// settles the prepared attempt with its level unchanged, and only then admits a Prepare of the new attempt (the plannedAttempt alignment);
// a Prepare of a not yet opened attempt is refused.
func TestVRBackoffLapseCooldownAndTheNextAttempt(t *testing.T) {
	f := newVXFixture(t)
	g := f.genesis()
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	b := prep
	for r := uint64(12); r <= 59; r++ { // OrderedRound + 48 = 59: still in the cooldown
		b = f.must(b, f.block(b, r, 1_010+r, nil))
	}
	s := rootState(t, b)
	require.EqualValues(t, 0, s.Backoff.Attempt, "no next attempt during the cooldown")
	_, err := f.exec(b, f.block(b, 60, 1_100, [][]byte{f.record("prepare", 1, 60).Bytes()}))
	require.ErrorIs(t, err, storage.ErrVRMode, "the first block past the cooldown opens attempt 1 only at its end")
	b60 := f.must(b, f.block(b, 60, 1_100, nil))
	s = rootState(t, b60)
	require.EqualValues(t, 1, s.Backoff.Attempt, "Open at the end of the first block past the cooldown")
	require.Equal(t, uint8(0), s.Backoff.Level, "a prepared attempt settles with its level unchanged")
	require.False(t, s.Backoff.Prepared)
	require.Zero(t, s.PrepareUCTime)
	next := f.must(b60, f.block(b60, 61, 1_101, [][]byte{f.record("prepare", 1, 61).Bytes()}))
	require.True(t, rootState(t, next).Backoff.Prepared)
}

// rejectControl is the RejectResult v2 of R for the parent's certified EVM state.
func (f *vxFixture) rejectControl(t *testing.T, round, attempt uint64, data vrschema.OutputRejected) rctypes.PosControl {
	witness, _, err := vrstate.BuildRejectWitness(context.Background(), f.world, f.pins, f.r)
	require.NoError(t, err)
	h := sha256.Sum256(witness)
	f.witnesses[h] = witness
	root := f.world.Root()
	var bh [32]byte
	copy(bh[:], f.parentEV)
	return rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: round,
		Op: rctypes.OpRejectResult, Reject: &rctypes.RejectContext{PredecessorBodyID: f.body, Attempt: attempt, EVMBlockHash: bh, EVMStateRoot: root},
		Data: data.Encode(), WitnessHash: h}
}

// RejectResult v2 through the executor at an idle root, over the real two-account witness: an expired R projects OutputRejected and
// SessionClosed at one anchor, resolves R, aborts the root's attempt 0, and the Open step settles it with incLevel; a second rejection, a
// later Freeze of R, a rejection that is not due and a rejection naming another reason are refused.
func TestVRRejectResultThroughTheExecutor(t *testing.T) {
	f := newVXFixture(t)
	f.progress = 100 + vrschema.Lifetime // the expiry, counted from reservation
	f.writeWorld()
	g := f.genesis()
	expired := vrschema.OutputRejected{ResultID: f.r, Reason: vrschema.RejExpired}

	_, err := f.exec(g, f.block(g, 11, 1_010, nil, f.rejectControl(t, 11, 0, vrschema.OutputRejected{ResultID: f.r, Reason: vrschema.RejInvalid})))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "the due table gives Expired")
	_, err = f.exec(g, f.block(g, 11, 1_010, nil, f.rejectControl(t, 11, 1, expired)))
	require.ErrorIs(t, err, storage.ErrRejectAttempt, "the root's next attempt is 0 at idle")

	b := f.must(g, f.block(g, 11, 1_010, nil, f.rejectControl(t, 11, 0, expired)))
	recs := b.ShardState.Records
	require.Len(t, recs, 2)
	require.Equal(t, rootrecords.KindOutputRejected, recs[0].Kind)
	require.Equal(t, expired.Encode(), recs[0].Data)
	require.Equal(t, rootrecords.KindSessionClosed, recs[1].Kind)
	require.Equal(t, f.r[:], recs[1].Data)
	require.Equal(t, recs[0].Progress, recs[1].Progress)
	require.True(t, posState(t, b).IsResolved(f.r))
	require.Equal(t, "aborted", b.ShardState.Control.Phase)
	s := rootState(t, b)
	require.EqualValues(t, 1, s.Backoff.Attempt, "aborted at 0: attempt 1 opens")
	require.Equal(t, uint8(1), s.Backoff.Level, "the unprepared attempt settles with incLevel(0, 0, 4) = 1")

	_, err = f.exec(b, f.block(b, 12, 1_011, nil, f.rejectControl(t, 12, 1, expired)))
	require.ErrorIs(t, err, storage.ErrResolvedResult, "a resolved result is never rejected again")

	// not due one progress unit before the expiry
	f2 := newVXFixture(t)
	f2.progress = 100 + vrschema.Lifetime - 1
	f2.writeWorld()
	g2 := f2.genesis()
	_, err = f2.exec(g2, f2.block(g2, 11, 1_010, nil, f2.rejectControl(t, 11, 0, expired)))
	require.ErrorIs(t, err, storage.ErrVRControlRefused)
	require.ErrorIs(t, err, vradmit.ErrReject)
}

// A rejection is refused once a Prepare protects the attempt, and a Freeze of R is refused after its rejection (S2a: RejectResult first
// refuses a later Freeze, even before the EVM imports the closure).
func TestVRRejectFirstRefusesALaterFreezeAndAPrepareProtectsTheAttempt(t *testing.T) {
	f := newVXFixture(t)
	f.progress, f.attempt = 100+vrschema.Lifetime, 1 // the candidate of the root's attempt 1, the one after the rejection
	f.build()
	g := f.genesis()
	expired := vrschema.OutputRejected{ResultID: f.r, Reason: vrschema.RejExpired}
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	_, err := f.exec(prep, f.block(prep, 12, 1_011, nil, f.rejectControl(t, 12, 1, expired)))
	require.ErrorIs(t, err, storage.ErrRejectNotQuiet, "a Prepare ordered first protects the attempt")

	rej := f.must(g, f.block(g, 11, 1_010, nil, f.rejectControl(t, 11, 0, expired)))
	p1 := f.must(rej, f.block(rej, 12, 1_011, [][]byte{f.record("prepare", 1, 12).Bytes()})) // attempt 1 opened at the end of block 11
	_, err = f.exec(p1, f.block(p1, 13, 1_012, [][]byte{f.record("freeze", 1, 13).Bytes(), f.freezeV5(0)}))
	require.ErrorIs(t, err, vradmit.ErrResolved, "the resolved R gets no Freeze")
}

// Freeze v5 admission refusals through the executor, each one input away from the admitted control.
func TestVRFreezeRefusalsThroughTheExecutor(t *testing.T) {
	cases := map[string]struct {
		mut  func(f *vxFixture) []byte // returns the companion
		want error
	}{
		"the witness is of another state root": {func(f *vxFixture) []byte {
			c := f.freezeV5(0)
			f.state.Output.Attempt++ // VR moved after the witness was taken: the frozen parent's root is no longer the witness's
			f.writeWorld()
			return c
		}, storage.ErrVRFreeze},
		"VR is Inconsistent at P": {func(f *vxFixture) []byte {
			f.state.Status.Health = vrschema.HealthInconsistent
			f.writeWorld()
			return f.freezeV5(0)
		}, vradmit.ErrInconsistent},
		"R is not published": {func(f *vxFixture) []byte {
			f.state.Output.State = vrschema.OutReserved
			f.writeWorld()
			return f.freezeV5(0)
		}, vradmit.ErrNotOpen},
		"no derivable intent":                                   {func(f *vxFixture) []byte { f.intents.ok = false; return f.freezeV5(0) }, storage.ErrVRFreeze},
		"a body that does not link":                             {func(f *vxFixture) []byte { f.auth.Link = bytes.Repeat([]byte{0x12}, 32); return f.freezeV5(0) }, storage.ErrVRFreeze},
		"a certificate of an uncommitted view":                  {func(f *vxFixture) []byte { return f.freezeV5(1) }, vradmit.ErrCertificate},
		"a companion other than Freeze v5 or an exact recovery": {func(f *vxFixture) []byte { return []byte{0x81, 0x04} }, storage.ErrVRFreeze},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			f := newVXFixture(t)
			companion := c.mut(f)
			g := f.genesis()
			prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
			_, err := f.exec(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), companion}))
			require.ErrorIs(t, err, c.want)
			require.ErrorIs(t, err, storage.ErrHandoffRecord)
		})
	}
}

// The VR mode is the control state's: a P85 control on a VR chain and a VR control on a P85 chain are refused; the closure duty is on.
func TestVRModeIsTheControlStates(t *testing.T) {
	f := newVXFixture(t)
	g := f.genesis()
	p85 := rctypes.PosControl{Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: 11,
		Op: rctypes.OpRejectResult, Reject: &rctypes.RejectContext{PredecessorBodyID: f.body}, Data: f.r[:], WitnessHash: [32]byte{1}}
	_, err := f.exec(g, f.block(g, 11, 1_010, nil, p85))
	require.ErrorIs(t, err, storage.ErrVRMode)

	pre := f.genesis()
	pre.ShardState.Control.VR = nil
	view := rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: 11,
		Op: rctypes.OpHandoffView, View: &rctypes.ViewContext{IntentDigest: f.intent, View: 1}}
	_, err = f.exec(pre, f.block(pre, 11, 1_010, nil, view))
	require.ErrorIs(t, err, storage.ErrVRMode)

	// a VR chain without the VR services refuses even an empty block
	svc := f.svc.Registry
	f.svc.Registry = nil
	_, err = f.exec(g, f.block(g, 11, 1_010, nil))
	require.ErrorIs(t, err, storage.ErrVRMode)
	f.svc.Registry = svc
}

// Replay determinism: the same blocks executed again from the same parents give the same root hashes and control digests, and executing a
// child never changes its parent (forks never share state).
func TestVRReplayIsDeterministic(t *testing.T) {
	run := func() [][]byte {
		f := newVXFixture(t)
		g := f.genesis()
		before := g.ShardState.Control.Digest()
		view := rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: 11,
			Op: rctypes.OpHandoffView, View: &rctypes.ViewContext{IntentDigest: f.intent, View: 1}}
		b1 := f.must(g, f.block(g, 11, 1_010, nil, view))
		again := f.must(g, f.block(g, 11, 1_010, nil, view))
		require.Equal(t, b1.RootHash, again.RootHash)
		require.Equal(t, before, g.ShardState.Control.Digest(), "the parent is unchanged")
		b2 := f.must(b1, f.block(b1, 12, 1_020, [][]byte{f.record("prepare", 0, 12).Bytes()}))
		b3 := f.must(b2, f.block(b2, 13, 1_030, [][]byte{f.record("freeze", 0, 13).Bytes(), f.freezeV5(1)}))
		return [][]byte{b1.RootHash, b1.ShardState.Control.Digest(), b2.RootHash, b2.ShardState.Control.Digest(), b3.RootHash, b3.ShardState.Control.Digest()}
	}
	require.Equal(t, run(), run())
}

// The control digest commits the VR root state: two states that differ only in it differ in the digest, and a P85 state keeps its encoding.
func TestVRRootStateIsInTheControlDigest(t *testing.T) {
	f := newVXFixture(t)
	g := f.genesis()
	c := *g.ShardState.Control
	d := c.Digest()
	s := rootState(t, g)
	s.Backoff.Level = 1
	raw, err := s.Encode()
	require.NoError(t, err)
	c.VR = raw
	require.NotEqual(t, d, c.Digest())
	c.VR = nil
	p85 := c.Bytes()
	c.UnackedParent = nil
	require.Equal(t, p85, c.Bytes())
}
