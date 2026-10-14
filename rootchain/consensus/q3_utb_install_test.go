package consensus

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/q3format"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-core/utbstore"
)

type utbWorld struct {
	f       *q3fixture.Fixture
	history *q3format.History
	entry   q3format.Entry
}

func newUTBWorld(t *testing.T) *utbWorld {
	t.Helper()
	f := q3fixture.New(t, q3fixture.Options{UTB: true})
	h, err := f.NewHistory(t).VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	return &utbWorld{f: f, history: h, entry: h.Tip()}
}

func (w *utbWorld) store(t *testing.T) *utbstore.Store {
	chain, err := w.history.UTBUnsigned()
	require.NoError(t, err)
	id, err := chain[0].EntryID()
	require.NoError(t, err)
	s, err := utbstore.Open(memorydb.New(), chain[0], id)
	require.NoError(t, err)
	return s
}

func (w *utbWorld) replica(t *testing.T) *q3Replica {
	r := newQ3Replica(t, w.f, w.f.NewNodes[0])
	r.mustOpen(false)
	t.Cleanup(r.close)
	require.NoError(t, r.trust.BindSigningAuthority(w.history))
	return r
}

// The install of an epoch whose predecessor is a UTB epoch retains the endorsed entry before the epoch is visible.
func TestInstallVerifiedEpochRetainsTheEndorsedEntry(t *testing.T) {
	w := newUTBWorld(t)
	r := w.replica(t)
	r.manager.utbStore = w.store(t)
	_, err := r.manager.InstallVerifiedEpoch(w.entry, w.f.Proof, w.f.Snapshot, nil)
	require.NoError(t, err)

	tip := r.manager.utbStore.Tip()
	require.EqualValues(t, 2, tip.Epoch)
	raw, err := r.manager.utbStore.Get(2)
	require.NoError(t, err)
	genesis, err := r.manager.utbStore.Entry(1)
	require.NoError(t, err)
	stored, err := r.manager.utbStore.Entry(2)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	require.NoError(t, stored.VerifySuccessor(genesis), "the retained entry is signed by the old committee")

	_, err = r.manager.InstallVerifiedEpoch(w.entry, w.f.Proof, w.f.Snapshot, nil)
	if err == nil { // an installed epoch is accepted again or refused as already anchored; either way the entry is unchanged
		again, _ := r.manager.utbStore.Get(2)
		require.Equal(t, raw, again)
	}
}

func TestInstallVerifiedEpochRefusesWithoutTheEntryStoreOrWithAnotherChain(t *testing.T) {
	w := newUTBWorld(t)
	t.Run("no entry store", func(t *testing.T) {
		r := w.replica(t)
		_, err := r.manager.InstallVerifiedEpoch(w.entry, w.f.Proof, w.f.Snapshot, nil)
		require.ErrorIs(t, err, ErrUTBStoreMissing)
		_, err = r.trust.GetByEpoch(2)
		require.ErrorIs(t, err, tbstore.ErrNotFound, "nothing was installed")
	})
	t.Run("a store of another chain", func(t *testing.T) {
		other := q3fixture.New(t, q3fixture.Options{UTB: true})
		otherHistory, err := other.NewHistory(t).VerifyEnvelope(other.Envelope)
		require.NoError(t, err)
		chain, err := otherHistory.UTBUnsigned()
		require.NoError(t, err)
		id, _ := chain[0].EntryID()
		s, err := utbstore.Open(memorydb.New(), chain[0], id)
		require.NoError(t, err)
		r := w.replica(t)
		r.manager.utbStore = s
		_, err = r.manager.InstallVerifiedEpoch(w.entry, w.f.Proof, w.f.Snapshot, nil)
		require.ErrorIs(t, err, ErrUTBMismatch, "the endorsement links to a predecessor this store does not hold")
		_, err = r.trust.GetByEpoch(2)
		require.ErrorIs(t, err, tbstore.ErrNotFound)
		require.EqualValues(t, 1, s.Tip().Epoch, "nothing was retained")
	})
	t.Run("a proof without the endorsement", func(t *testing.T) {
		r := w.replica(t)
		r.manager.utbStore = w.store(t)
		stripped := w.f.Proof
		qc := *stripped.CommitQC
		qc.UTB = nil
		stripped.CommitQC = &qc
		_, err := r.manager.InstallVerifiedEpoch(w.entry, stripped, w.f.Snapshot, nil)
		require.ErrorIs(t, err, handoff.ErrProof)
		require.EqualValues(t, 1, r.manager.utbStore.Tip().Epoch)
	})
	t.Run("a proof endorsing another entry", func(t *testing.T) {
		r := w.replica(t)
		r.manager.utbStore = w.store(t)
		forged := w.f.Proof
		qc := *w.f.Proof.CommitQC
		cert := *qc.UTB
		cert.Unsigned = append([]byte(nil), cert.Unsigned...)
		cert.Unsigned[len(cert.Unsigned)-3] ^= 1
		qc.UTB = &cert
		forged.CommitQC = &qc
		_, err := r.manager.InstallVerifiedEpoch(w.entry, forged, w.f.Snapshot, nil)
		require.Error(t, err, "the signatures no longer cover the entry")
		require.EqualValues(t, 1, r.manager.utbStore.Tip().Epoch)
	})
}
