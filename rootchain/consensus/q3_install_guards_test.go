package consensus

import (
	"bytes"
	"context"
	"crypto"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"testing"

	"github.com/stretchr/testify/require"
	basetypes "github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3format"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

// Isolated refusals of the V3 install and of the check that the stores hold it. Each activation here is of the same chain (the same
// old committee and genesis) as the first, so its proof authenticates under the same old keys and only the property under test is wrong.
type guardWorld struct {
	f, other     *q3fixture.Fixture
	activated    q3format.Entry // the first activation
	otherEntry   q3format.Entry // another activation of the same chain, with other weights
	verifiedBoth *q3format.History
}

func newGuardWorld(t *testing.T) *guardWorld {
	t.Helper()
	f := q3fixture.New(t, q3fixture.Options{})
	other := q3fixture.New(t, q3fixture.Options{Chain: f, Weights: []uint64{5, 2, 1, 1}})
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	a, err := h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	b, err := h.VerifyEnvelope(other.Envelope)
	require.NoError(t, err)
	require.NotEqual(t, a.Tip().Claim(), b.Tip().Claim())
	return &guardWorld{f: f, other: other, activated: a.Tip(), otherEntry: b.Tip(), verifiedBoth: a}
}

// replica is a manager whose trust store is bound to the history that holds the first activation, with nothing installed yet.
func (w *guardWorld) replica(t *testing.T) *q3Replica {
	t.Helper()
	r := newQ3Replica(t, w.f, w.f.NewNodes[0])
	r.mustOpen(false)
	t.Cleanup(r.close)
	require.NoError(t, r.trust.BindSigningAuthority(w.verifiedBoth))
	return r
}

func TestInstallVerifiedEpochIsolatedRefusals(t *testing.T) {
	w := newGuardWorld(t)

	t.Run("not the handoff profile", func(t *testing.T) {
		r := w.replica(t)
		r.manager.params.NetworkProfileVersion = 0
		_, err := r.manager.InstallVerifiedEpoch(w.activated, w.f.Proof, w.f.Snapshot, nil)
		require.ErrorIs(t, err, ErrNotStopped)
		require.ErrorContains(t, err, "not the handoff profile")
	})
	t.Run("running consensus", func(t *testing.T) {
		r := w.replica(t)
		r.manager.pacemaker.Reset(context.Background(), 3, nil, nil)
		_, err := r.manager.InstallVerifiedEpoch(w.activated, w.f.Proof, w.f.Snapshot, nil)
		require.ErrorIs(t, err, ErrNotStopped)
		require.ErrorContains(t, err, "consensus is running")
	})
	t.Run("a snapshot with no shards", func(t *testing.T) {
		r := w.replica(t)
		empty := *w.f.Snapshot
		empty.ShardInfo = nil
		_, err := r.manager.InstallVerifiedEpoch(w.activated, w.f.Proof, &empty, nil)
		require.ErrorIs(t, err, ErrNoCheckpoint)
		require.ErrorContains(t, err, "no shards")
	})
	t.Run("the old committee's valid proof of another record", func(t *testing.T) {
		r := w.replica(t)
		_, err := r.manager.InstallVerifiedEpoch(w.activated, w.other.Proof, w.f.Snapshot, nil)
		require.ErrorIs(t, err, ErrNotVerifiedEpoch, "it authenticates under the old keys and is still not the activation's proof")
		_, err = r.trust.GetByEpoch(2)
		require.ErrorIs(t, err, tbstore.ErrNotFound)
	})
	t.Run("a proof signed by another old committee", func(t *testing.T) {
		stranger := q3fixture.New(t, q3fixture.Options{})
		r := w.replica(t)
		_, err := r.manager.InstallVerifiedEpoch(w.activated, stranger.Proof, w.f.Snapshot, nil)
		require.ErrorIs(t, err, handoff.ErrProof)
		require.ErrorContains(t, err, "old handoff commit proof")
	})
	t.Run("another record's epoch anchor is already durable", func(t *testing.T) {
		r := w.replica(t)
		_, err := r.manager.InstallVerifiedEpoch(w.activated, w.f.Proof, w.f.Snapshot, nil)
		require.NoError(t, err)
		require.NoError(t, r.trust.BindSigningAuthority(w.verifiedBoth), "the same authority again")
		_, err = r.manager.InstallVerifiedEpoch(w.otherEntry, w.other.Proof, w.other.Snapshot, nil)
		require.ErrorIs(t, err, rctypes.ErrEpochAnchor, "epoch 2 is anchored by the other activation")
	})
}

func TestInstallVerifiedEpochRefusesWhenALaterEpochIsAnchored(t *testing.T) {
	w := newGuardWorld(t)
	r := w.replica(t)
	_, g, ok := w.activated.Handoff()
	require.True(t, ok)
	// the later anchor even carries this activation's genesis identity: only its epoch makes it another record's
	require.NoError(t, r.db.InstallEpochAnchorSafety(&rctypes.EpochAnchor{Epoch: 3, Slot: 30, GenesisID: g.ID(), StateRoot: bytes.Repeat([]byte{8}, 32)}))
	_, err := r.manager.InstallVerifiedEpoch(w.activated, w.f.Proof, w.f.Snapshot, nil)
	require.ErrorIs(t, err, rctypes.ErrEpochAnchor)
	_, err = r.trust.GetByEpoch(2)
	require.ErrorIs(t, err, tbstore.ErrNotFound, "nothing was installed")
}

func TestHoldsVerifiedEpochChecksTheCommitteeAndTheDurableAnchor(t *testing.T) {
	w := newGuardWorld(t)

	t.Run("the stored committee is another activation's", func(t *testing.T) {
		r := w.replica(t)
		_, err := r.manager.InstallVerifiedEpoch(w.activated, w.f.Proof, w.f.Snapshot, nil)
		require.NoError(t, err)
		require.NoError(t, r.manager.HoldsVerifiedEpoch(w.activated))
		err = r.manager.HoldsVerifiedEpoch(w.otherEntry)
		require.ErrorIs(t, err, ErrNotVerifiedEpoch)
		require.ErrorContains(t, err, "stored trust base")
	})
	t.Run("a committee with no durable anchor", func(t *testing.T) {
		r := w.replica(t)
		installCommittee(t, r, w.activated)
		err := r.manager.HoldsVerifiedEpoch(w.activated)
		require.ErrorIs(t, err, ErrNotVerifiedEpoch)
		require.ErrorContains(t, err, "durable epoch anchor")
	})
	t.Run("the durable anchor is another record's of the epoch", func(t *testing.T) {
		r := w.replica(t)
		installCommittee(t, r, w.activated)
		require.NoError(t, r.db.InstallEpochAnchorSafety(&rctypes.EpochAnchor{Epoch: 2, Slot: 6, GenesisID: bytes.Repeat([]byte{9}, 32), StateRoot: bytes.Repeat([]byte{8}, 32)}))
		err := r.manager.HoldsVerifiedEpoch(w.activated)
		require.ErrorIs(t, err, ErrNotVerifiedEpoch)
		require.ErrorContains(t, err, "durable epoch anchor")
	})
	t.Run("an anchor of a later epoch means the epoch has been succeeded", func(t *testing.T) {
		r := w.replica(t)
		_, err := r.manager.InstallVerifiedEpoch(w.activated, w.f.Proof, w.f.Snapshot, nil)
		require.NoError(t, err)
		require.NoError(t, r.db.InstallEpochAnchorSafety(&rctypes.EpochAnchor{Epoch: 3, Slot: 30, GenesisID: bytes.Repeat([]byte{9}, 32), StateRoot: bytes.Repeat([]byte{8}, 32)}))
		require.NoError(t, r.manager.HoldsVerifiedEpoch(w.activated))
	})
	t.Run("no verified activation", func(t *testing.T) {
		r := w.replica(t)
		require.ErrorIs(t, r.manager.HoldsVerifiedEpoch(q3format.Entry{}), ErrNotVerifiedEpoch)
		genesis, err := w.verifiedBoth.ForEpoch(1)
		require.NoError(t, err)
		require.ErrorIs(t, r.manager.HoldsVerifiedEpoch(genesis), ErrNotVerifiedEpoch)
	})
}

func TestSameCommitteeComparesEveryField(t *testing.T) {
	w := newGuardWorld(t)
	base := func() *basetypes.RootTrustBaseV1 { return w.activated.Projection() }
	require.True(t, sameCommittee(base(), base()))
	for name, mutate := range map[string]func(*basetypes.RootTrustBaseV1){
		"network":    func(tb *basetypes.RootTrustBaseV1) { tb.NetworkID++ },
		"epoch":      func(tb *basetypes.RootTrustBaseV1) { tb.Epoch++ },
		"start":      func(tb *basetypes.RootTrustBaseV1) { tb.EpochStart++ },
		"threshold":  func(tb *basetypes.RootTrustBaseV1) { tb.QuorumThreshold++ },
		"a member":   func(tb *basetypes.RootTrustBaseV1) { tb.RootNodes = tb.RootNodes[:len(tb.RootNodes)-1] },
		"a node id":  func(tb *basetypes.RootTrustBaseV1) { tb.RootNodes[1].NodeID += "x" },
		"a weight":   func(tb *basetypes.RootTrustBaseV1) { tb.RootNodes[1].Stake++ },
		"a key":      func(tb *basetypes.RootTrustBaseV1) { tb.RootNodes[1].SigKey[0] ^= 0xFF },
		"a nil node": func(tb *basetypes.RootTrustBaseV1) { tb.RootNodes[1] = nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base()
			mutate(changed)
			require.False(t, sameCommittee(base(), changed))
			require.False(t, sameCommittee(changed, base()))
		})
	}
	require.False(t, sameCommittee(nil, base()))
	require.False(t, sameCommittee(base(), nil))
}

// fakeQ3 is the verified history as the manager sees it: which epochs are activations.
type fakeQ3 struct{ entries map[uint64]q3format.Entry }

func (f fakeQ3) Admit(uint64) error                                                 { return nil }
func (f fakeQ3) Lineage(base abdrc.HistoricalTrustBases) abdrc.HistoricalTrustBases { return base }
func (f fakeQ3) Activated(epoch uint64) (q3format.Entry, bool) {
	e, ok := f.entries[epoch]
	return e, ok
}

func TestQ3ActivatedNamesAnAnchorOfAnActivatedEpochOnly(t *testing.T) {
	w := newGuardWorld(t)
	_, g, ok := w.activated.Handoff()
	require.True(t, ok)
	anchor := func() *rctypes.EpochAnchor {
		return &rctypes.EpochAnchor{Epoch: 2, Slot: g.Start - 1, GenesisID: g.ID(), StateRoot: g.Root}
	}
	authority := fakeQ3{entries: map[uint64]q3format.Entry{2: w.activated}}
	require.True(t, q3Activated(authority, anchor()))
	require.False(t, q3Activated(nil, anchor()), "no history")
	require.False(t, q3Activated(authority, nil), "no anchor")
	require.False(t, q3Activated(fakeQ3{}, anchor()), "an epoch the history does not hold as an activation")
	other := anchor()
	other.GenesisID = make([]byte, 32)
	require.False(t, q3Activated(authority, other), "an anchor of the epoch with another genesis identity falls through to the V2 lineage check")
	later := anchor()
	later.Epoch = 3
	require.False(t, q3Activated(authority, later))
	genesis, err := w.verifiedBoth.ForEpoch(1)
	require.NoError(t, err)
	require.False(t, q3Activated(fakeQ3{entries: map[uint64]q3format.Entry{2: genesis}}, anchor()), "a legacy entry has no handoff to name")
}

func TestTheManagerGivesItsSafetyModuleTheActivationGateOnlyWithTheVerifiedHistory(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{})
	r := c.replicas[0]
	require.True(t, r.manager.safety.BoundTo(r.rt))
	require.False(t, r.manager.safety.BoundTo(c.replicas[1].rt), "another process's runtime")
	r.close()
	require.NoError(t, r.open(false), "before activation a binary without the history starts")
	require.False(t, r.manager.safety.BoundTo(r.rt), "and its module has no gate")
}

// installCommittee puts the entry's committee into the replica's trust store, as the install's trust step does, without anchoring.
func installCommittee(t *testing.T, r *q3Replica, e q3format.Entry) {
	t.Helper()
	old, err := r.trust.GetByEpoch(e.Epoch() - 1)
	require.NoError(t, err)
	previous, err := old.Hash(crypto.SHA256)
	require.NoError(t, err)
	projection := e.Projection()
	projection.PreviousEntryHash = previous
	cfg, ok := e.Config()
	require.True(t, ok)
	_, err = r.trust.InstallVerified(projection, votesig.Config{Scheme: cfg.SigningScheme, Network: cfg.Network, Genesis: cfg.Genesis})
	require.NoError(t, err)
}
