package q3active_test

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/q3install"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestActivationPublishesOneSnapshotAfterEveryParticipant(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	rt := p.start()
	require.NoError(t, rt.Recover(ctx))
	require.Nil(t, rt.Snapshot(), "nothing is published before the first activation")

	require.NoError(t, rt.Activate(ctx, p.bundle()))

	s := rt.Snapshot()
	require.NotNil(t, s)
	require.EqualValues(t, 2, s.Epoch())
	require.EqualValues(t, 7, s.Start())
	require.Equal(t, f.Claim, s.Claim())
	require.EqualValues(t, 9, s.Total())
	require.EqualValues(t, 7, s.Threshold(), "W=9, Q=7")
	require.Equal(t, votesig.Config{Scheme: votesig.SchemeDomainBound, Network: 5, Genesis: f.Genesis}, s.Signing())
	require.Equal(t, weightvalidation.ModeWeighted, s.Mode())
	weights := map[string]uint64{}
	for _, m := range s.Members() {
		weights[m.NodeID] = m.Weight
	}
	for i, m := range f.Members {
		require.Equal(t, f.Members[i].Weight, weights[m.NodeID])
	}
	s.Members()[0].Weight = 99
	require.NotEqual(t, uint64(99), s.Members()[0].Weight, "the snapshot hands out copies")
	require.Equal(t, 1, p.root.Installs)
	require.NoError(t, rt.Gate(ctx, f.Claim))
}

func TestNothingIsActiveBeforeTheJournalIsComplete(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	rt := p.start()
	g := rt.Trust(nil)
	var seen int
	p.root.OnInstall = func(q3format.Entry) {
		seen++
		// the history already holds the epoch (the root install needs its signing configuration) but nothing is usable
		cfg, err := rt.Signing(2)
		require.NoError(t, err)
		require.Equal(t, votesig.SchemeDomainBound, cfg.Scheme)
		require.ErrorIs(t, rt.Admit(2), q3active.ErrNotActive)
		require.ErrorIs(t, rt.Admit(2), q3install.ErrIncomplete)
		_, err = rt.Mode(2)
		require.ErrorIs(t, err, q3active.ErrNotActive)
		_, err = g.GetByEpoch(ctx, 2)
		require.ErrorIs(t, err, q3active.ErrNotActive)
		_, err = g.RootTrustBase(ctx, 2)
		require.ErrorIs(t, err, q3active.ErrNotActive)
		require.Nil(t, rt.Snapshot())
		got, ok := rt.Activated(2)
		require.True(t, ok, "the verified entry is visible to the installers")
		require.Equal(t, f.Claim, got.Claim())
	}
	require.NoError(t, rt.Activate(ctx, p.bundle()))
	require.Equal(t, 1, seen)
	require.NoError(t, rt.Admit(2))
}

func TestAnEpochTheHistoryDoesNotHoldIsNeverLegacy(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	rt := p.start()
	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Activate(ctx, p.bundle()))
	g := rt.Trust(nil)
	for _, epoch := range []uint64{0, 3, 9} {
		require.ErrorIs(t, rt.Admit(epoch), q3format.ErrUnknownEpoch)
		_, err := rt.Mode(epoch)
		require.ErrorIs(t, err, q3format.ErrUnknownEpoch)
		_, err = rt.Signing(epoch)
		require.ErrorIs(t, err, q3format.ErrUnknownEpoch)
		_, err = g.GetByEpoch(ctx, epoch)
		require.ErrorIs(t, err, q3format.ErrUnknownEpoch)
		_, err = weightvalidation.ModeFor(g, epoch)
		require.ErrorIs(t, err, q3format.ErrUnknownEpoch)
		_, ok := rt.Activated(epoch)
		require.False(t, ok)
	}
	// the verified legacy epoch keeps its explicit scheme 1 and unit rules
	cfg, err := rt.Signing(1)
	require.NoError(t, err)
	require.Equal(t, votesig.Config{Scheme: votesig.SchemeLegacy, Network: 5}, cfg)
	require.NoError(t, rt.Admit(1))
	m, err := rt.Mode(1)
	require.NoError(t, err)
	require.Equal(t, weightvalidation.ModeUnit, m)
	_, ok := rt.Activated(1)
	require.False(t, ok, "the genesis epoch is not an activation")
}

func TestRestartRebuildsTheHistoryFromTheJournalAndCompletesOrChecks(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	// the safety module is not wired to the runtime: the installation cannot complete
	p.SkipBinding = "safety"
	rt := p.start()
	err := rt.Activate(ctx, p.bundle())
	require.ErrorIs(t, err, q3active.ErrNotBound)
	require.ErrorIs(t, rt.Admit(2), q3active.ErrNotActive)
	require.Equal(t, 1, p.root.Installs, "the root step finished before the refusal")

	// restart: the history is rebuilt from the journal's staged bundle, and nothing is admitted until Recover finishes the install
	p.SkipBinding = ""
	rt = p.start()
	e, ok := rt.Activated(2)
	require.True(t, ok, "the staged lineage is replayed and authenticated at start")
	require.Equal(t, f.Claim, e.Claim())
	require.ErrorIs(t, rt.Admit(2), q3active.ErrNotActive)
	require.Nil(t, rt.Snapshot())
	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Admit(2))
	require.NotNil(t, rt.Snapshot())
	require.Equal(t, 1, p.root.Installs, "the finished root step is not repeated")

	// restart after completion: the volatile snapshot is rebuilt before the stores are checked, and nothing is installed again
	rt = p.start()
	require.Nil(t, rt.Snapshot())
	require.ErrorIs(t, rt.Admit(2), q3active.ErrNotActive, "nothing is admitted before recovery")
	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Admit(2))
	m, err := rt.Mode(2)
	require.NoError(t, err)
	require.Equal(t, weightvalidation.ModeWeighted, m)
	require.EqualValues(t, 2, rt.Snapshot().Epoch())
	require.Equal(t, 1, p.root.Installs)
}

func TestRecoverRefusesWhenAStoreNoLongerHoldsTheActivation(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	require.NoError(t, p.start().Activate(ctx, p.bundle()))
	p.root.Held = map[uint64]q3format.Claim{} // the manager's stores lost the epoch
	rt := p.start()
	err := rt.Recover(ctx)
	require.ErrorIs(t, err, q3install.ErrStoreConflict)
	require.ErrorIs(t, rt.Admit(2), q3active.ErrNotActive)
}

func TestActivationRefusals(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})

	t.Run("before the participants attach", func(t *testing.T) {
		p := newProcess(t, f)
		rt, err := q3active.New(q3active.Config{DB: p.DB, Genesis: f.Old})
		require.NoError(t, err)
		require.ErrorIs(t, rt.Activate(ctx, p.bundle()), q3active.ErrNotAttached)
		require.ErrorIs(t, rt.Recover(ctx), q3active.ErrNotAttached)
		it := p.DB.First()
		defer it.Close()
		require.False(t, it.Valid(), "nothing was staged by an activation that was refused before it began")
		require.ErrorIs(t, rt.Attach(q3active.Participants{}), q3install.ErrComponents)
	})
	t.Run("participants attach once", func(t *testing.T) {
		p := newProcess(t, f)
		rt := p.start()
		require.ErrorIs(t, rt.Attach(q3active.Participants{Root: p.root, Safety: p.safety, Shard: p.shard, Authority: p.authority}), q3active.ErrNotAttached)
	})
	for _, c := range []string{"safety", "shard", "authority"} {
		t.Run("an unbound "+c+" cannot complete", func(t *testing.T) {
			p := newProcess(t, f)
			p.SkipBinding = c
			rt := p.start()
			require.ErrorIs(t, rt.Activate(ctx, p.bundle()), q3active.ErrNotBound)
			require.ErrorIs(t, rt.Admit(2), q3active.ErrNotActive)
			require.Nil(t, rt.Snapshot())
		})
	}
	t.Run("a root install failure leaves nothing admitted", func(t *testing.T) {
		p := newProcess(t, f)
		boom := errors.New("disk full")
		p.root.FailWith = boom
		rt := p.start()
		require.ErrorIs(t, rt.Activate(ctx, p.bundle()), boom)
		require.ErrorIs(t, rt.Admit(2), q3active.ErrNotActive)
		require.Nil(t, rt.Snapshot())
	})
	t.Run("a bundle needs its envelope and checkpoint", func(t *testing.T) {
		p := newProcess(t, f)
		rt := p.start()
		require.ErrorIs(t, rt.Activate(ctx, q3active.Bundle{Snapshot: f.Snapshot}), q3active.ErrBundle)
		require.ErrorIs(t, rt.Activate(ctx, q3active.Bundle{Envelope: f.EnvelopeBytes}), q3active.ErrBundle)
		require.ErrorIs(t, rt.Admit(2), q3format.ErrUnknownEpoch)
	})
	t.Run("an old commit signed below the threshold", func(t *testing.T) {
		weak := q3fixture.New(t, q3fixture.Options{SignedBy: 2})
		p := newProcess(t, weak)
		rt := p.start()
		err := rt.Activate(ctx, p.bundle())
		require.ErrorIs(t, err, q3format.ErrActivation)
		require.ErrorIs(t, err, q3install.ErrBundle)
		_, ok := rt.Activated(2)
		require.False(t, ok, "nothing a failed verification saw reaches the history")
		require.Equal(t, 0, p.root.Installs)
	})
	t.Run("an envelope of another chain", func(t *testing.T) {
		other := q3fixture.New(t, q3fixture.Options{})
		p := newProcess(t, f) // this chain's genesis, the other chain's activation
		rt := p.start()
		err := rt.Activate(ctx, q3active.Bundle{Envelope: other.EnvelopeBytes, Snapshot: other.Snapshot})
		require.ErrorIs(t, err, q3install.ErrBundle)
		require.ErrorIs(t, err, q3format.ErrGenesis, "the other chain's genesis is not this history's")
		_, ok := rt.Activated(2)
		require.False(t, ok)
	})
	t.Run("a second activation of the same epoch with another bundle", func(t *testing.T) {
		p := newProcess(t, f)
		rt := p.start()
		require.NoError(t, rt.Activate(ctx, p.bundle()))
		other := q3fixture.New(t, q3fixture.Options{})
		err := rt.Activate(ctx, q3active.Bundle{Envelope: other.EnvelopeBytes, Snapshot: other.Snapshot})
		require.ErrorIs(t, err, q3install.ErrBundle)
		require.ErrorIs(t, err, q3format.ErrConflict, "the retained envelope of the epoch is another claim")
		require.Equal(t, 1, p.root.Installs)
	})
}

func TestStagedBundlesAreAuthenticatedAtStart(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})

	stage := func(t *testing.T, claim q3format.Claim, bundle []byte) *process {
		t.Helper()
		p := newProcess(t, f)
		comps := map[q3install.Step]q3install.Component{}
		for _, s := range q3install.Steps {
			comps[s] = noopComponent{}
		}
		j, err := q3install.Open(q3install.Config{DB: p.DB, Components: comps, Bundles: func([]byte, q3format.Claim) error { return nil }})
		require.NoError(t, err)
		require.NoError(t, j.Install(ctx, claim, bundle))
		return p
	}

	t.Run("a staged bundle that is not a bundle", func(t *testing.T) {
		p := stage(t, f.Claim, []byte("not a bundle"))
		_, err := q3active.New(q3active.Config{DB: p.DB, Genesis: f.Old})
		require.ErrorIs(t, err, q3active.ErrHistory)
		require.ErrorIs(t, err, q3active.ErrBundle)
	})
	t.Run("a staged bundle whose commit is not authenticated", func(t *testing.T) {
		weak := q3fixture.New(t, q3fixture.Options{SignedBy: 2})
		raw, err := q3active.EncodeBundle(q3active.Bundle{Envelope: weak.EnvelopeBytes, Snapshot: weak.Snapshot})
		require.NoError(t, err)
		p := stage(t, weak.Claim, raw)
		_, err = q3active.New(q3active.Config{DB: p.DB, Genesis: weak.Old})
		require.ErrorIs(t, err, q3active.ErrHistory)
		require.ErrorIs(t, err, q3format.ErrActivation)
	})
	t.Run("a staged record that is not the one its envelope derives", func(t *testing.T) {
		raw, err := q3active.EncodeBundle(q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot})
		require.NoError(t, err)
		forged := f.Claim
		forged.Start++
		p := stage(t, forged, raw)
		_, err = q3active.New(q3active.Config{DB: p.DB, Genesis: f.Old})
		require.ErrorIs(t, err, q3active.ErrHistory)
	})
	t.Run("a staged lineage of another genesis", func(t *testing.T) {
		other := q3fixture.New(t, q3fixture.Options{})
		raw, err := q3active.EncodeBundle(q3active.Bundle{Envelope: other.EnvelopeBytes, Snapshot: other.Snapshot})
		require.NoError(t, err)
		p := stage(t, other.Claim, raw)
		_, err = q3active.New(q3active.Config{DB: p.DB, Genesis: f.Old})
		require.ErrorIs(t, err, q3active.ErrHistory)
	})
	t.Run("acceptance control", func(t *testing.T) {
		raw, err := q3active.EncodeBundle(q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot})
		require.NoError(t, err)
		p := stage(t, f.Claim, raw)
		rt, err := q3active.New(q3active.Config{DB: p.DB, Genesis: f.Old})
		require.NoError(t, err)
		_, ok := rt.Activated(2)
		require.True(t, ok)
	})
	t.Run("an incomplete configuration", func(t *testing.T) {
		_, err := q3active.New(q3active.Config{})
		require.ErrorIs(t, err, q3install.ErrComponents)
		_, err = q3active.New(q3active.Config{DB: memorydb.New()})
		require.ErrorIs(t, err, q3install.ErrComponents, "no genesis trust base to root the history in")
		_, err = q3active.New(q3active.Config{Genesis: f.Old})
		require.ErrorIs(t, err, q3install.ErrComponents, "no journal store")
	})
}

func TestGuardedTrustServesTheVerifiedHistory(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	rt := p.start()
	require.NoError(t, rt.Activate(ctx, p.bundle()))

	t.Run("an activated epoch is the history's projection, never the base's", func(t *testing.T) {
		g := rt.Trust(staticTrust{epoch: map[uint64]*types.RootTrustBaseV1{2: f.Old}}) // a base that would hand out another committee
		tb, err := g.GetByEpoch(ctx, 2)
		require.NoError(t, err)
		require.EqualValues(t, 2, tb.Epoch)
		require.EqualValues(t, 7, tb.QuorumThreshold)
		var total uint64
		for _, n := range tb.RootNodes {
			total += n.Stake
		}
		require.EqualValues(t, 9, total)
		tb.RootNodes[0].Stake = 1000
		again, err := g.GetByEpoch(ctx, 2)
		require.NoError(t, err)
		require.NotEqual(t, uint64(1000), again.RootNodes[0].Stake, "a caller cannot alter the history's projection")
	})
	t.Run("a legacy epoch is the base after it agrees with the history", func(t *testing.T) {
		g := rt.Trust(staticTrust{epoch: map[uint64]*types.RootTrustBaseV1{1: f.Old}})
		tb, err := g.GetByEpoch(ctx, 1)
		require.NoError(t, err)
		require.Same(t, f.Old, tb)
		bent := *f.Old
		bent.QuorumThreshold = 1
		_, err = rt.Trust(staticTrust{epoch: map[uint64]*types.RootTrustBaseV1{1: &bent}}).GetByEpoch(ctx, 1)
		require.ErrorIs(t, err, q3active.ErrConflict)
		heavier := *f.Old
		heavier.RootNodes = nil
		for i, n := range f.Old.RootNodes {
			stake := n.Stake
			if i == 0 {
				stake++ // the same members and keys, one weight changed
			}
			heavier.RootNodes = append(heavier.RootNodes, &types.NodeInfo{NodeID: n.NodeID, SigKey: n.SigKey, Stake: stake})
		}
		_, err = rt.Trust(staticTrust{epoch: map[uint64]*types.RootTrustBaseV1{1: &heavier}}).GetByEpoch(ctx, 1)
		require.ErrorIs(t, err, q3active.ErrConflict, "one member's weight differs")
		other := q3fixture.New(t, q3fixture.Options{})
		_, err = rt.Trust(staticTrust{epoch: map[uint64]*types.RootTrustBaseV1{1: other.Old}}).GetByEpoch(ctx, 1)
		require.ErrorIs(t, err, q3active.ErrConflict, "another committee of the same epoch")
		_, err = rt.Trust(staticTrust{}).GetByEpoch(ctx, 1)
		require.ErrorIs(t, err, errNoSuchEpoch, "a base that lacks the epoch is an error, not the history's view")
		_, err = rt.Trust(staticTrust{epoch: map[uint64]*types.RootTrustBaseV1{1: &bent}}).RootTrustBase(ctx, 1)
		require.ErrorIs(t, err, q3active.ErrConflict, "the verified trust base is the same refusal")
	})
	t.Run("without a base the history serves the legacy epoch too", func(t *testing.T) {
		tb, err := rt.Trust(nil).GetByEpoch(ctx, 1)
		require.NoError(t, err)
		require.EqualValues(t, 1, tb.Epoch)
	})
	t.Run("the mode rides with the trust base", func(t *testing.T) {
		g := rt.Trust(nil)
		w, err := g.RootTrustBase(ctx, 2)
		require.NoError(t, err)
		require.Equal(t, weightvalidation.ModeWeighted, weightvalidation.ModeOfTrustBase(w))
		u, err := g.RootTrustBase(ctx, 1)
		require.NoError(t, err)
		require.Equal(t, weightvalidation.ModeUnit, weightvalidation.ModeOfTrustBase(u))
		m, err := weightvalidation.ModeFor(g, 2)
		require.NoError(t, err)
		require.Equal(t, weightvalidation.ModeWeighted, m)
		_, err = g.RootTrustBase(ctx, 7)
		require.ErrorIs(t, err, q3format.ErrUnknownEpoch)
	})
	t.Run("binding", func(t *testing.T) {
		g := rt.Trust(nil)
		require.True(t, g.BoundTo(rt))
		other := newProcess(t, f)
		require.False(t, g.BoundTo(other.start()), "another runtime")
		require.False(t, g.BoundTo(nil))
		require.False(t, g.BoundTo("rt"))
		require.False(t, g.BoundTo((*q3active.Runtime)(nil)))
	})
}

func TestSnapshotsNeverGoBack(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	rt := p.start()
	require.NoError(t, rt.Activate(ctx, p.bundle()))
	first := rt.Snapshot()
	// a restart re-publishes the same record: the handle is replaced by an equal one, never by another record
	rt = p.start()
	require.NoError(t, rt.Recover(ctx))
	require.Equal(t, first.Claim(), rt.Snapshot().Claim())
	require.Equal(t, first.ConfigID(), rt.Snapshot().ConfigID())
}

// errNoSuchEpoch is the base's own refusal of an epoch it lacks.
var errNoSuchEpoch = errors.New("no such epoch")

type staticTrust struct {
	epoch map[uint64]*types.RootTrustBaseV1
}

func (s staticTrust) GetByEpoch(_ context.Context, e uint64) (*types.RootTrustBaseV1, error) {
	if tb, ok := s.epoch[e]; ok {
		return tb, nil
	}
	return nil, errNoSuchEpoch
}

type noopComponent struct{}

func (noopComponent) Install(context.Context, q3install.Activation) error { return nil }
func (noopComponent) Verify(context.Context, q3install.Activation) error  { return nil }

type staticHistory map[uint64]trusthistorystore.Record

func (h staticHistory) ByEpoch(epoch uint64) (trusthistorystore.Record, error) {
	if r, ok := h[epoch]; ok {
		return r, nil
	}
	return trusthistorystore.Record{}, trusthistorystore.ErrNotFound
}

func TestLineageServesTheVerifiedProjectionOfAnActivatedEpoch(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	rt := p.start()
	base := staticHistory{1: {Epoch: 1, V1: f.Old}}
	lineage := rt.Lineage(base)
	var beforeInstall error
	p.root.OnInstall = func(q3format.Entry) { _, beforeInstall = lineage.ByEpoch(2) }
	require.NoError(t, rt.Activate(ctx, p.bundle()))
	require.ErrorIs(t, beforeInstall, q3active.ErrNotActive, "an epoch whose installation is incomplete is not served")

	t.Run("an activated epoch is the history's own projection, with its weights", func(t *testing.T) {
		rec, err := lineage.ByEpoch(2)
		require.NoError(t, err)
		require.Nil(t, rec.V1)
		require.Nil(t, rec.V2)
		require.NotNil(t, rec.Verified)
		require.EqualValues(t, 2, rec.Epoch)
		require.EqualValues(t, 7, rec.Start)
		require.EqualValues(t, 7, rec.Verified.QuorumThreshold)
		var total uint64
		for _, n := range rec.Verified.RootNodes {
			total += n.Stake
		}
		require.EqualValues(t, 9, total)
		require.Equal(t, epoch2(t, rt).BodyID(), rec.BodyID)
		rec.Verified.RootNodes[0].Stake = 1000
		again, err := lineage.ByEpoch(2)
		require.NoError(t, err)
		require.NotEqual(t, uint64(1000), again.Verified.RootNodes[0].Stake, "the served projection is a copy")
	})
	t.Run("the genesis epoch is the base's record once it agrees with the history", func(t *testing.T) {
		rec, err := lineage.ByEpoch(1)
		require.NoError(t, err)
		require.Same(t, f.Old, rec.V1)
	})
	t.Run("the base never answers where the history disagrees or holds nothing", func(t *testing.T) {
		bent := *f.Old
		bent.QuorumThreshold = 1
		for name, rec := range map[string]trusthistorystore.Record{
			"another committee":     {Epoch: 1, V1: &bent},
			"a V2 body":             {Epoch: 1, V1: f.Old, V2: &evmroot.TrustBaseBodyV2{}},
			"a verified projection": {Epoch: 1, V1: f.Old, Verified: f.Old},
			"no V1":                 {Epoch: 1},
		} {
			_, err := rt.Lineage(staticHistory{1: rec}).ByEpoch(1)
			require.ErrorIs(t, err, q3active.ErrConflict, name)
		}
		_, err := rt.Lineage(nil).ByEpoch(1)
		require.ErrorIs(t, err, trusthistorystore.ErrNotFound, "no base, no genesis record")
		_, err = rt.Lineage(staticHistory{}).ByEpoch(1)
		require.ErrorIs(t, err, trusthistorystore.ErrNotFound)
	})
	t.Run("an epoch the history does not hold is refused, whatever the base says", func(t *testing.T) {
		_, err := rt.Lineage(staticHistory{3: {Epoch: 3, V1: f.Old}}).ByEpoch(3)
		require.ErrorIs(t, err, q3format.ErrUnknownEpoch)
	})
}

type retainedCandidates map[string][]byte

func (r retainedCandidates) HandoffCandidate(id []byte) ([]byte, error) { return r[string(id)], nil }

// The request history is the anchor followed by the weighted assignment the verified history activated, served only once the
// activation is installed, and for the designated shard alone; a committed assignment whose candidate is not retained is missing
// history, never the anchor alone.
func TestRequestHistoryServesTheActivatedAssignmentOfItsShard(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	p := newProcess(t, f)
	rt := p.start()
	id := f.Body.Identity()
	config := func(c q3active.CandidateSource) q3active.RequestHistoryConfig {
		return q3active.RequestHistoryConfig{Candidates: c, HashAlg: crypto.SHA256, Network: q3fixture.Network, Version: 1,
			Anchor: func(types.PartitionID, types.ShardID) (*types.PartitionDescriptionRecord, error) {
				return f.ShardConf, nil
			}}
	}
	retained := retainedCandidates{string(id[:]): f.Candidate}
	hist, err := rt.RequestHistory(config(retained))
	require.NoError(t, err)

	var incompleteChain, incompleteRoot error
	p.root.OnInstall = func(q3format.Entry) {
		_, incompleteChain = hist.Chain(q3fixture.PartitionID, types.ShardID{})
		_, _, incompleteRoot = hist.RootIdentity(7)
	}
	require.NoError(t, rt.Activate(ctx, p.bundle()))
	require.ErrorIs(t, incompleteChain, q3active.ErrNotActive, "an installation that is not complete serves no history")
	require.ErrorIs(t, incompleteRoot, q3active.ErrNotActive)
	require.ErrorIs(t, incompleteChain, q3active.ErrRequestHistory)

	chain, err := hist.Chain(q3fixture.PartitionID, types.ShardID{})
	require.NoError(t, err)
	require.Len(t, chain, 2, "the anchor and the activated assignment")

	t.Run("another shard's history is its anchor alone", func(t *testing.T) {
		chain, err := hist.Chain(q3fixture.PartitionID+1, types.ShardID{})
		require.NoError(t, err)
		require.Len(t, chain, 1)
	})
	t.Run("a committed assignment whose candidate is not retained is missing history", func(t *testing.T) {
		missing, err := rt.RequestHistory(config(retainedCandidates{}))
		require.NoError(t, err)
		_, err = missing.Chain(q3fixture.PartitionID, types.ShardID{})
		require.ErrorIs(t, err, q3active.ErrRequestHistory)
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	})
	t.Run("a retained candidate that is not the committed one is refused", func(t *testing.T) {
		other := append([]byte(nil), f.Candidate...)
		other[len(other)/2] ^= 1
		bad, err := rt.RequestHistory(config(retainedCandidates{string(id[:]): other}))
		require.NoError(t, err)
		_, err = bad.Chain(q3fixture.PartitionID, types.ShardID{})
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	})
	t.Run("the root identity follows the verified intervals", func(t *testing.T) {
		epoch, body, err := hist.RootIdentity(7)
		require.NoError(t, err)
		require.EqualValues(t, 2, epoch)
		require.Equal(t, id[:], body)
		epoch, _, err = hist.RootIdentity(6)
		require.NoError(t, err)
		require.EqualValues(t, 1, epoch, "before the boundary the genesis epoch authorises")
	})
	t.Run("an incomplete configuration", func(t *testing.T) {
		for name, c := range map[string]q3active.RequestHistoryConfig{
			"no candidates": {HashAlg: crypto.SHA256, Network: 5, Version: 1, Anchor: config(retained).Anchor},
			"no anchor":     {Candidates: retained, HashAlg: crypto.SHA256, Network: 5, Version: 1},
			"no network":    {Candidates: retained, HashAlg: crypto.SHA256, Version: 1, Anchor: config(retained).Anchor},
			"no version":    {Candidates: retained, HashAlg: crypto.SHA256, Network: 5, Anchor: config(retained).Anchor},
			"no hash":       {Candidates: retained, Network: 5, Version: 1, Anchor: config(retained).Anchor},
		} {
			_, err := rt.RequestHistory(c)
			require.ErrorIs(t, err, q3active.ErrRequestHistory, name)
		}
	})
}
