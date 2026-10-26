package configuredprogress

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// The store's own guards of a selection (bft-core#876), pinned one by one with the pair left unverifiable where a guard has to answer before the pair is looked at: a guard
// that stops answering then surfaces as a different class of error.

func selectionRequest(item frontier.Coverage, uc, tr []byte) ArchiveSelectionRequest {
	return ArchiveSelectionRequest{BlockHash: item.Anchor.Subject.BlockHash, Prior: PairID(item.Material.ResultingUC, item.Material.ResultingTR), NewDigest: [32]byte{9}, UC: uc, TR: tr}
}

// A block whose coverage committed but was not pruned yet (the crash between AdvanceFrontier and PruneFrontier) is still a journal candidate: only the coverage and
// anchor guards refuse it, and the coverage row is not touched.
func TestSelectionRefusesABlockCoveredButNotYetPruned(t *testing.T) {
	s, c, _, item, limits := frontierTestSetup(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{item}))
	image, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	present := false
	for _, e := range image.Candidates {
		present = present || string(e.Candidate.Hash) == string(item.Anchor.Subject.BlockHash[:])
	}
	require.True(t, present, "premise: the covered block is still in the journal (not pruned)")
	err = s.SelectArchiveRepresentation(ctx, c, limits, selectionRequest(item, []byte("not a pair"), []byte("not a pair")))
	require.ErrorIs(t, err, ErrConflict, "a covered block refuses a selection before its pair is looked at")
	cov, err := s.LoadCoverage(ctx, c, limits, 0, 4)
	require.NoError(t, err)
	require.Len(t, cov, 1)
	require.Equal(t, item.Anchor.Acks[0].ManifestDigest, cov[0].Acks[0].ManifestDigest, "the coverage row still names the manifest it was committed with")
}

// At or below the coverage base (a restored journal) with the candidate still present: the base guard refuses.
func TestSelectionRefusesAtOrBelowTheCoverageBase(t *testing.T) {
	s, c, _, item, limits := frontierTestSetup(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	// a restored journal: the verified restore pin at the candidate's own height makes it the coverage base (the pin is written the way the restore writes it)
	state, _, err := s.Load(ctx, c)
	require.NoError(t, err)
	payload, err := marshal(restoreAnchorWire{Version: journalVersion, Descriptor: state.i.descriptorDigest[:], Height: item.Anchor.Height, Hash: item.Anchor.Subject.BlockHash[:],
		StateRoot: item.Anchor.StateRoot[:], RootRound: item.Anchor.Round})
	require.NoError(t, err)
	raw, err := encodeEnvelope(restoreAnchorKind, payload, 4096)
	require.NoError(t, err)
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketName).Put(restoreAnchorKey, raw) }))
	err = s.SelectArchiveRepresentation(ctx, c, limits, selectionRequest(item, []byte("not a pair"), []byte("not a pair")))
	require.ErrorIs(t, err, ErrConflict, "the base guard answers before the pair is looked at")
	require.ErrorContains(t, err, "coverage base")
}

// The store authenticates the pair itself, whatever the caller checked: a VALID, signed certificate of another input record (here only the timestamp differs) is a conflict.
func TestSelectionRefusesAnotherInputRecordOnItsOwn(t *testing.T) {
	s, f, c, _, item, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	var cur types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(item.Material.ResultingUC, &cur))
	ir := *cur.InputRecord
	ir.Timestamp++
	other := f.observation(&ir, 2, 6)
	uc, err := types.Cbor.Marshal(other.Certificate())
	require.NoError(t, err)
	tr, err := types.Cbor.Marshal(other.TechnicalRecord())
	require.NoError(t, err)
	err = s.SelectArchiveRepresentation(ctx, c, limits, selectionRequest(item, uc, tr))
	require.ErrorIs(t, err, ErrConflict)
	require.ErrorContains(t, err, "complete input record")
	// and nothing was stored
	_, ok := s.ArchiveDigestOf(ctx, c, limits, item.Anchor.Subject.BlockHash)
	require.False(t, ok)
	// control: the association's own pair re-offered is not another representation but binds (the identical pair is accepted)
	require.NoError(t, s.SelectArchiveRepresentation(ctx, c, limits, selectionRequest(item, item.Material.ResultingUC, item.Material.ResultingTR)))
}
