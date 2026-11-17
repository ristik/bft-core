package storage_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
)

// The real intent derivation (VT-05b: vrschedule.Intents over vrhandoff) inside the real executor, replacing the fixture's fixed intent:
// R's committed source certified at root round 5 (UC time 950), VR's output at the certified EVM state observed, the canonical intent and
// its successor body derived by every root, and the whole primary handoff (HandoffView, Prepare, Freeze v5, H) judged against them.

type vxReal struct {
	*vxFixture
	p     *vrschedule.Intents
	in    vrhandoff.Intent
	d     [32]byte
	bc    vrhandoff.BodyContext
	cfg   q3format.ProtocolConfig
	g     *storage.ExecutedBlock
	cand  []byte
	body  q3format.BodyV3
	cert  vrschema.ViewCertificate
	fzRaw []byte
}

func (f *vxFixture) output() vrhandoff.Output {
	changes := []vrschema.RegistryChange{{ID: 4, Kind: f.cand.RegistryChanges[0].Kind, Payload: f.cand.RegistryChanges[0].Payload}}
	return vrhandoff.Output{State: f.state, Members: append(append([]evmassign.Identity(nil), f.j[2:]...), f.j[:2]...), Changes: changes}
}

func newVXReal(t *testing.T) *vxReal {
	f := &vxReal{vxFixture: newVXFixture(t), cfg: q3format.Q3Config(vxNetwork, [32]byte{0x99})}
	sources, err := vrschedule.NewSources("")
	require.NoError(t, err)
	_, err = sources.Record(vrschedule.SourceEntry{Source: vrhandoff.Source{ResultID: f.r[:], EVMBlockHash: bytes.Repeat([]byte{0xe6}, 32), EVMBlockNumber: 40,
		CertRootRound: 5, OutputCommit: f.state.Output.OutputCommit[:]}, CertUCTime: 950})
	require.NoError(t, err)
	outputs := vrschedule.NewOutputs()
	out := f.output()
	outputs.Put(f.world.Root(), &out)
	f.p = &vrschedule.Intents{Deployment: f.dep, Pins: f.pins, Config: func() (q3format.ProtocolConfig, error) { return f.cfg, nil }, Sources: sources, Outputs: outputs}
	f.svc.Registry.Intents = f.p
	f.g = f.genesis()

	q, err := storage.VRQueryForTest(f.g, f.orch, f.svc, f.auth)
	require.NoError(t, err)
	d, ok, err := f.p.Derive(q)
	require.NoError(t, err)
	require.True(t, ok, "the intent is derivable over the committed state")
	f.in, f.d, f.bc = d.Intent, d.Digest, d.Body
	require.EqualValues(t, 5, d.AnchorRound, "max(certRootRound 5, attemptOpenRound 0)")
	require.EqualValues(t, 950, d.AnchorUCTime, "openTime(0) is the anchor block's committed UC time")
	return f
}

// certificate makes the view's certificate: sticky PoPs by J's EVM keys, the assembly by the view's assembler, readiness of every member.
func (f *vxReal) certificate(view uint64) {
	t := f.t
	var pops []vrhandoff.PoPOffer
	for _, m := range f.j {
		for _, x := range f.members {
			if x.evm == m.EVMNodeID {
				p, err := vrhandoff.SignPoP(f.in, m, x.ek.signer)
				require.NoError(t, err)
				pops = append(pops, p)
			}
		}
	}
	_, raw, cd, err := vrhandoff.Assemble(f.in, pops)
	require.NoError(t, err)
	ids := []string{}
	for _, m := range f.k {
		ids = append(ids, m.RootNodeID)
	}
	who := vrhandoff.Assembler(f.d, ids, view)
	var a vrhandoff.Assembly
	for _, m := range f.k {
		if m.RootNodeID == who {
			a, err = vrhandoff.SignAssembly(f.in, view, raw, f.signer(m.StakingID).signer)
			require.NoError(t, err)
		}
	}
	f.body, err = vrhandoff.DeriveBody(f.in, 1, cd, f.bc)
	require.NoError(t, err)
	_, tb, err := vrhandoff.TrustBase(f.in, 1)
	require.NoError(t, err)
	rs := map[string]vrhandoff.Readiness{}
	for _, m := range f.j {
		r, err := vrhandoff.SignReadiness(f.in, a, f.body, m.RootNodeID, tb, nil, f.signer(m.StakingID).signer)
		require.NoError(t, err)
		rs[m.RootNodeID] = r
	}
	f.cert, err = vrhandoff.Certificate(a, f.j, rs, f.body.Identity())
	require.NoError(t, err)
	f.cand = raw
	witness, _, err := vrstate.BuildOutputWitness(context.Background(), f.world, f.pins, f.r)
	require.NoError(t, err)
	f.fzRaw, err = vrschema.FreezeV5{Candidate: raw, Certificate: f.cert, Witness: witness}.Encode()
	require.NoError(t, err)
}

func (f *vxReal) rec(kind string, round uint64) evmroot.OrderedHandoffRecord {
	id := f.body.Identity()
	r := evmroot.OrderedHandoffRecord{Network: vxNetwork, Epoch: 1, Attempt: 0, OrderedRound: round, ActivationRound: 200, PredecessorBodyID: f.body0(),
		NextBodyID: id[:], FrozenID: make([]byte, 32), SuccessorTRHash: make([]byte, 32), Kind: kind}
	if kind == "freeze" {
		cd := sha256.Sum256(f.cand)
		r.FrozenID = evmroot.D4FrozenID(id[:], f.body.StateSummary, f.parentEV, cd[:], 0, f.body0())
	}
	return r
}

func (f *vxReal) body0() []byte { return bytes.Clone(f.vxFixture.body[:]) }

func (f *vxReal) view(round, v uint64) rctypes.PosControl {
	return rctypes.PosControl{Registry: true, Network: vxNetwork, ChainID: f.dep.ChainID, Custody: f.dep.Registry, OrderingEpoch: 1, OrderingRound: round,
		Op: rctypes.OpHandoffView, View: &rctypes.ViewContext{IntentDigest: f.d, View: v}}
}

// The whole primary handoff through the executor with the derived intent: HandoffView's replay floor from the anchor's UC time, the Freeze
// v5 of the later view's certificate, H with the successor technical record; replay gives identical blocks, and a second root whose
// output cache was served the members in another order judges identically.
func TestVRHandoffWithTheDerivedIntent(t *testing.T) {
	f := newVXReal(t)
	g := f.g
	_, err := f.exec(g, f.block(g, 11, 959, nil, f.view(11, 1)))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "T(0, 0) = 10 s after openTime(0) = 950")
	wrong := f.view(11, 1)
	wrong.View.IntentDigest = [32]byte{7}
	_, err = f.exec(g, f.block(g, 11, 960, nil, wrong))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "a HandoffView of another intent")
	b1 := f.must(g, f.block(g, 11, 960, nil, f.view(11, 1)))
	require.Equal(t, f.d[:], []byte(rootState(t, b1).Backoff.Intent))

	f.certificate(1)
	prep := f.must(b1, f.block(b1, 12, 961, [][]byte{f.rec("prepare", 12).Bytes()}))
	fz := f.must(prep, f.block(prep, 13, 962, [][]byte{f.rec("freeze", 13).Bytes(), f.fzRaw}))
	require.Equal(t, "endorsed", fz.ShardState.Control.Phase)
	s := rootState(t, fz)
	require.Equal(t, f.r, s.StagedResult)
	require.Equal(t, f.body.Identity(), s.StagedBody)
	body, _, v5, v6, ok := storage.VRRetainedForTest(fz)
	require.True(t, ok)
	require.Equal(t, f.body.Encode(), body, "the body is derived, never carried")
	require.Equal(t, f.cand, v6)
	f.candidates[string(s.StagedBody[:])] = v5

	commit := f.rec("commit", 14)
	commit.FrozenID = f.rec("freeze", 13).FrozenID
	tr, err := storage.ExpectedCommitTRForTest(f.candidates, commit, fz.ShardState.States[vxShard])
	require.NoError(t, err)
	fromV6, err := storage.AssignmentSuccessorTRHash(fz.ShardState.States[vxShard], f.cand, commit.ActivationRound, crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, tr, fromV6, "the leader's H over the candidate v6 names the record the executor derives from the retained view")
	commit.SuccessorTRHash = tr
	h := f.must(fz, f.block(fz, 14, 963, [][]byte{commit.Bytes()}))
	require.Equal(t, "committed", h.ShardState.Control.Phase)

	// replay
	again := f.must(f.must(f.must(f.must(g, f.block(g, 11, 960, nil, f.view(11, 1))), f.block(b1, 12, 961, [][]byte{f.rec("prepare", 12).Bytes()})),
		f.block(prep, 13, 962, [][]byte{f.rec("freeze", 13).Bytes(), f.fzRaw})), f.block(fz, 14, 963, [][]byte{commit.Bytes()}))
	require.Equal(t, h.RootHash, again.RootHash, "replay is deterministic")

	// a Freeze whose candidate is not the derived intent's is refused even though VR's digests bind it (another authorization chain id)
	c, err := vrschema.DecodeCandidateV6(f.cand)
	require.NoError(t, err)
	c.Authorization.Chain++
	forged, err := c.Encode()
	require.NoError(t, err)
	fv, err := vrschema.DecodeFreezeV5(f.fzRaw)
	require.NoError(t, err)
	fv.Candidate, fv.Certificate.Assembly.Candidate = forged, forged
	raw, err := fv.Encode()
	require.NoError(t, err)
	_, err = f.exec(prep, f.block(prep, 13, 962, [][]byte{f.rec("freeze", 13).Bytes(), raw}))
	require.ErrorIs(t, err, storage.ErrVRFreeze)

	// an unobserved source is unavailable, never false
	empty, err := vrschedule.NewSources("")
	require.NoError(t, err)
	f.p.Sources = empty
	_, err = f.exec(prep, f.block(prep, 13, 962, [][]byte{f.rec("freeze", 13).Bytes(), f.fzRaw}))
	require.ErrorIs(t, err, storage.ErrVRUnavailable)
}

// An attempt opened after the source's certifying block anchors the intent at that opening (anchorRound = max(certRootRound,
// attemptOpenRound)): a pre-Freeze Abort at round 12 opens attempt 1 at the end of its block, the derived intent's anchor is round 12 and
// openTime(0) its UC time, and HandoffView(1)'s replay floor counts from there.
func TestVRIntentAnchorsAtAnAttemptOpenedAfterItsSource(t *testing.T) {
	f := newVXReal(t)
	g := f.g
	f.certificate(0)
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.rec("prepare", 11).Bytes()}))
	abort := f.rec("abort", 12)
	ab := f.must(prep, f.block(prep, 12, 1_020, [][]byte{abort.Bytes()}))
	s := rootState(t, ab)
	require.EqualValues(t, 1, s.Backoff.Attempt)
	require.EqualValues(t, 12, s.AttemptOpenRound)
	require.EqualValues(t, 1_020, s.AttemptOpenUCTime)
	q, err := storage.VRQueryForTest(ab, f.orch, f.svc, f.auth)
	require.NoError(t, err)
	d, ok, err := f.p.Derive(q)
	require.NoError(t, err)
	require.True(t, ok)
	require.EqualValues(t, 12, d.AnchorRound, "the attempt opened after the source's certifying round 5")
	require.EqualValues(t, 1_020, d.AnchorUCTime)
	require.EqualValues(t, 1, d.Intent.Attempt)
	require.NotEqual(t, f.d, d.Digest, "a new attempt is a new intent")
	view := f.view(13, 1)
	view.View.IntentDigest = d.Digest
	_, err = f.exec(ab, f.block(ab, 13, 1_029, nil, view))
	require.ErrorIs(t, err, storage.ErrVRControlRefused, "T(0, 0) = 10 s from openTime(0) = 1020")
	f.must(ab, f.block(ab, 13, 1_030, nil, view))
}
