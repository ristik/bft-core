package configuredprogress

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

var testJournalLimits = JournalLimits{Candidates: 3, Observations: 5, Bytes: 16 << 20}

func admitJournal(t *testing.T, s *Store, f *fixture, o rootinput.VerifiedObservationV2) {
	t.Helper()
	p, _, err := s.PrepareObservation(context.Background(), f.ctx, o)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
}

func candidateB1(f *fixture, auth rootinput.VerifiedObservationV2) JournalCandidate {
	b, parent := f.c.Blocks[1], f.c.Blocks[0]
	return JournalCandidate{Round: b.Round, Number: b.Number, ParentNumber: parent.Number,
		Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes(), ParentHash: parent.Hash.Bytes(), ParentState: parent.StateRoot.Bytes(),
		Raw: []byte{0x81, 0x42, 0x00, 0xff}, BlockSize: 4, StateSize: 11,
		AuthorizingUC: auth.Certificate(), AuthorizingTR: auth.TechnicalRecord()}
}

func openJournal(t *testing.T, f *fixture, limits JournalLimits) (*Store, string) {
	t.Helper()
	s, path := f.open(3)
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	require.NoError(t, s.EnableJournal(context.Background(), f.ctx, limits))
	return s, path
}

func TestJournalReopenSeparatesOriginalAuthorizationAndResultingCertificate(t *testing.T) {
	f := newFixture(t, 2)
	s, path := openJournal(t, f, testJournalLimits)
	bootstrap := f.bootstrap(1, 4)
	admitJournal(t, s, f, bootstrap)
	candidate := candidateB1(f, bootstrap)
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, candidate))
	before, err := s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.NoError(t, err)
	require.Len(t, before.Candidates, 1)
	require.False(t, before.Candidates[0].Certified)
	first := f.first(1, 2, 5)
	admitJournal(t, s, f, first)
	require.NoError(t, s.Close())
	s, err = OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	defer s.Close()
	require.NoError(t, s.EnableJournal(context.Background(), f.ctx, testJournalLimits))
	after, err := s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.NoError(t, err)
	require.Len(t, after.Candidates, 1)
	require.Len(t, after.Observations, 2)
	require.True(t, after.Candidates[0].Certified)
	require.Equal(t, candidate.Raw, after.Candidates[0].Candidate.Raw)
	require.Equal(t, bootstrap.Certificate().GetRootRoundNumber(), after.Candidates[0].Candidate.AuthorizingUC.GetRootRoundNumber())
	require.Equal(t, first.Certificate().GetRootRoundNumber(), after.Candidates[0].ResultingUC.GetRootRoundNumber())
	require.NotEqual(t, after.Candidates[0].Candidate.AuthorizingUC.GetRootRoundNumber(), after.Candidates[0].ResultingUC.GetRootRoundNumber())
}

func TestJournalUCBeforePayloadAndFullHistoryCapacity(t *testing.T) {
	f := newFixture(t, 2)
	limits := JournalLimits{Candidates: 1, Observations: 3, Bytes: 16 << 20}
	s, _ := openJournal(t, f, limits)
	defer s.Close()
	bootstrap := f.bootstrap(1, 4)
	admitJournal(t, s, f, bootstrap)
	first := f.first(1, 2, 5)
	admitJournal(t, s, f, first)
	image, err := s.LoadJournal(context.Background(), f.ctx, limits)
	require.NoError(t, err)
	require.True(t, image.Observations[1].Unresolved)
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, limits, candidateB1(f, bootstrap)))
	image, err = s.LoadJournal(context.Background(), f.ctx, limits)
	require.NoError(t, err)
	require.False(t, image.Observations[1].Unresolved)
	require.True(t, image.Candidates[0].Certified)
	branch := candidateB1(f, bootstrap)
	branch.Hash = bytes.Repeat([]byte{0xab}, 32)
	require.ErrorIs(t, s.PutJournalCandidate(context.Background(), f.ctx, limits, branch), ErrBounds)
	image, err = s.LoadJournal(context.Background(), f.ctx, limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 1)
}

func TestJournalKeepsSameHeightBranchesAndQuietTail(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := openJournal(t, f, testJournalLimits)
	defer s.Close()
	bootstrap := f.bootstrap(1, 4)
	admitJournal(t, s, f, bootstrap)
	canonical := candidateB1(f, bootstrap)
	canonical.LocallyBuilt = true
	branch := candidateB1(f, bootstrap)
	branch.Hash = bytes.Repeat([]byte{0xb2}, 32)
	branch.Raw = []byte{0x81, 0x42, 0xa1, 0xb2}
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, canonical))
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, branch))
	conflictingLocal := branch
	conflictingLocal.Hash = bytes.Repeat([]byte{0xc3}, 32)
	conflictingLocal.LocallyBuilt = true
	require.ErrorIs(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, conflictingLocal), ErrConflict)
	first := f.first(1, 2, 5)
	admitJournal(t, s, f, first)
	quietIR := &types.InputRecord{Version: 1, RoundNumber: 2, PreviousHash: f.c.Blocks[1].StateRoot.Bytes(), Hash: f.c.Blocks[1].StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_003}
	quiet := f.observation(quietIR, 3, 6)
	admitJournal(t, s, f, quiet)
	image, err := s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 2)
	require.Len(t, image.Observations, 3)
	require.True(t, image.Candidates[0].Certified || image.Candidates[1].Certified)
	require.NotEqual(t, image.Candidates[0].Certified, image.Candidates[1].Certified)
	require.Empty(t, image.Observations[2].TargetHash, "quiet tail carries no block hash")
}

func TestJournalFaultBoundariesLeaveNoSignatureAuthorityOrPartialCertification(t *testing.T) {
	f := newFixture(t, 2)
	s, path := openJournal(t, f, testJournalLimits)
	bootstrap := f.bootstrap(1, 4)
	admitJournal(t, s, f, bootstrap)
	candidate := candidateB1(f, bootstrap)
	for _, point := range []string{"before-candidate-put", "before-candidate-commit"} {
		s.checkpoint = func(name string) error {
			if name == point {
				return errors.New("injected crash")
			}
			return nil
		}
		require.ErrorContains(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, candidate), "injected crash")
		image, err := s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
		require.NoError(t, err)
		require.Empty(t, image.Candidates)
	}
	s.checkpoint = nil
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, candidate))
	first := f.first(1, 2, 5)
	for _, point := range []string{"before-journal-observation-put", "before-journal-observation-commit", "before-observation-commit"} {
		s.checkpoint = func(name string) error {
			if name == point {
				return errors.New("injected crash")
			}
			return nil
		}
		p, _, err := s.PrepareObservation(context.Background(), f.ctx, first)
		require.NoError(t, err)
		_, _, err = s.CommitObservation(p)
		require.ErrorContains(t, err, "injected crash")
		image, err := s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
		require.NoError(t, err)
		require.False(t, image.Candidates[0].Certified)
		require.Len(t, image.Observations, 1)
	}
	require.NoError(t, s.Close())
	s, err := OpenConfiguredV2(path, Settings{Retain: 3})
	require.NoError(t, err)
	defer s.Close()
	require.NoError(t, s.EnableJournal(context.Background(), f.ctx, testJournalLimits))
	image, err := s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.NoError(t, err)
	require.False(t, image.Candidates[0].Certified)
	admitJournal(t, s, f, first)
	image, err = s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.NoError(t, err)
	require.True(t, image.Candidates[0].Certified)
}

func TestJournalRejectsCorruptForeignAndVersionedRecords(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := openJournal(t, f, testJournalLimits)
	defer s.Close()
	bootstrap := f.bootstrap(1, 4)
	admitJournal(t, s, f, bootstrap)
	candidate := candidateB1(f, bootstrap)
	require.NoError(t, s.PutJournalCandidate(context.Background(), f.ctx, testJournalLimits, candidate))
	wrong := f.ctx
	wrong.Observation.NetworkID = 9
	_, err := s.LoadJournal(context.Background(), wrong, testJournalLimits)
	require.Error(t, err)
	key := journalCandidateKey(candidate.Hash)
	original := []byte(nil)
	require.NoError(t, s.db.View(func(tx *bolt.Tx) error { original = bytes.Clone(tx.Bucket(bucketName).Get(key)); return nil }))
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		raw := bytes.Clone(original)
		raw[len(raw)-1] ^= 1
		return tx.Bucket(bucketName).Put(key, raw)
	}))
	_, err = s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.Error(t, err)
	w, err := decodeCandidate(original)
	require.NoError(t, err)
	w.Version++
	versioned, err := encodeCandidate(w)
	require.NoError(t, err)
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketName).Put(key, versioned) }))
	_, err = s.LoadJournal(context.Background(), f.ctx, testJournalLimits)
	require.ErrorIs(t, err, ErrContext)
}
