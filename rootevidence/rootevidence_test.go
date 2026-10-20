package rootevidence

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/keyvaluedb/boltdb"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

func TestObserve(t *testing.T) {
	f := newFixture(t)

	t.Run("a committing and a non-committing statement are normalized with their original signatures", func(t *testing.T) {
		for _, committing := range []bool{true, false} {
			v := f.vote(t, "1", 2, 12, committing, 0x5e)
			o, err := Observe(v, f.store)
			require.NoError(t, err)
			require.Equal(t, Slot{"1", 2, 12}, o.Slot())
			require.EqualValues(t, 11, o.S.Parent)
			require.Equal(t, []byte(v.Signature), o.S.Signature)
			require.Equal(t, committing, o.S.Committing)
			if committing {
				require.Equal(t, []byte(v.SealSignature), o.S.SealSignature)
				require.EqualValues(t, 11, o.S.CommitRound)
				require.EqualValues(t, 2, o.S.CommitEpoch)
			} else {
				require.Empty(t, o.S.SealSignature)
				require.Empty(t, o.S.CommitHash)
			}
			require.NotEmpty(t, o.S.PV)
			require.NotEmpty(t, o.Key)
		}
	})

	t.Run("the transport context is not part of the statement", func(t *testing.T) {
		// no high QC at all: the vote does not verify as a consensus message, its signed statement is genuine and is kept
		v := f.vote(t, "1", 2, 12, true, 0x5e)
		require.Error(t, v.Verify(f.store))
		_, err := Observe(v, f.store)
		require.NoError(t, err)
	})

	t.Run("refused: a forged signature, a legacy vote, another author's signature", func(t *testing.T) {
		v := f.vote(t, "1", 2, 12, true, 0x5e)
		v.Signature[10] ^= 1
		_, err := Observe(v, f.store)
		require.ErrorIs(t, err, votesig.ErrBadSignature)

		v = f.vote(t, "1", 2, 12, true, 0x5e)
		v.SealSignature[10] ^= 1
		_, err = Observe(v, f.store)
		require.ErrorIs(t, err, votesig.ErrBadSignature, "the seal signature is checked on its own")

		v = f.vote(t, "1", 2, 12, false, 0x5e)
		v.Author = "2"
		_, err = Observe(v, f.store)
		require.ErrorIs(t, err, votesig.ErrBadSignature)

		v = f.vote(t, "1", 2, 12, false, 0x5e)
		v.Scheme, v.SealSignature = 0, nil
		_, err = Observe(v, f.store)
		require.ErrorIs(t, err, votesig.ErrScheme)

		_, err = Observe(nil, f.store)
		require.ErrorIs(t, err, ErrUnsupported)
		_, err = Observe(&abdrc.VoteMsg{}, f.store)
		require.ErrorIs(t, err, ErrUnsupported)
	})

	t.Run("an epoch that is not domain-bound is not kept", func(t *testing.T) {
		v := f.vote(t, "1", 1, 5, false, 0x5e) // epoch 1 signs with the legacy scheme
		_, err := Observe(v, f.store)
		require.Error(t, err)
	})
}

func newJournal(t *testing.T, budget uint64) *Journal {
	t.Helper()
	j, err := NewJournal(memorydb.New(), budget)
	require.NoError(t, err)
	return j
}

func TestJournalSlots(t *testing.T) {
	f := newFixture(t)
	j := newJournal(t, 0)
	a := f.observe(t, "1", 2, 12, true, 0x01)
	b := f.observe(t, "1", 2, 12, true, 0x02)
	c := f.observe(t, "1", 2, 12, true, 0x03)

	res, err := j.Record(a)
	require.NoError(t, err)
	require.Equal(t, Stored, res)
	res, err = j.Record(a)
	require.NoError(t, err)
	require.Equal(t, Duplicate, res, "replay is idempotent")
	rec, err := j.Get(a.Slot())
	require.NoError(t, err)
	require.False(t, rec.Paired())

	res, err = j.Record(b)
	require.NoError(t, err)
	require.Equal(t, Paired, res)
	res, err = j.Record(b)
	require.NoError(t, err)
	require.Equal(t, Duplicate, res)
	res, err = j.Record(a)
	require.NoError(t, err)
	require.Equal(t, Duplicate, res, "the other half again")
	res, err = j.Record(c)
	require.NoError(t, err)
	require.Equal(t, AlreadyPaired, res, "a third variant adds no offence and is not kept")

	rec, err = j.Get(a.Slot())
	require.NoError(t, err)
	require.True(t, rec.Paired())
	require.Equal(t, a.S.Digest(), rec.First.Digest())
	require.Equal(t, b.S.Digest(), rec.Second.Digest())
	require.EqualValues(t, 1, rec.FirstSeq)
	require.EqualValues(t, 2, rec.PairSeq)

	// other slots are independent: another author, another round, another epoch
	for _, o := range []*Observation{f.observe(t, "2", 2, 12, true, 0x02), f.observe(t, "1", 2, 13, true, 0x02)} {
		res, err = j.Record(o)
		require.NoError(t, err)
		require.Equal(t, Stored, res)
	}
}

func TestJournalSurvivesRestart(t *testing.T) {
	f := newFixture(t)
	path := filepath.Join(t.TempDir(), "evidence.db")
	db, err := boltdb.New(path)
	require.NoError(t, err)
	j, err := NewJournal(db, 0)
	require.NoError(t, err)
	a, b := f.observe(t, "1", 2, 12, true, 0x01), f.observe(t, "1", 2, 12, true, 0x02)
	_, err = j.Record(a)
	require.NoError(t, err)
	_, err = j.Record(b)
	require.NoError(t, err)
	require.NoError(t, db.Close())

	db, err = boltdb.New(path)
	require.NoError(t, err)
	defer db.Close()
	j, err = NewJournal(db, 0)
	require.NoError(t, err)
	rec, err := j.Get(a.Slot())
	require.NoError(t, err)
	require.NotNil(t, rec)
	require.True(t, rec.Paired())
	next, err := j.NextSeq()
	require.NoError(t, err)
	require.EqualValues(t, 2, next, "sequence numbers continue across a restart")
	res, err := j.Record(f.observe(t, "2", 2, 12, false, 0x01))
	require.NoError(t, err)
	require.Equal(t, Stored, res)
	next, _ = j.NextSeq()
	require.EqualValues(t, 3, next)
}

func TestJournalBudget(t *testing.T) {
	f := newFixture(t)
	first := f.observe(t, "1", 2, 12, true, 0x01)
	j := newJournal(t, 0)
	_, err := j.Record(first)
	require.NoError(t, err)
	one, err := j.Used()
	require.NoError(t, err)
	require.NotZero(t, one)

	j = newJournal(t, one+one/2) // room for one statement and a half
	_, err = j.Record(first)
	require.NoError(t, err)
	_, err = j.Record(f.observe(t, "2", 2, 12, true, 0x01))
	require.ErrorIs(t, err, ErrBudget)
	rec, err := j.Get(Slot{"2", 2, 12})
	require.NoError(t, err)
	require.Nil(t, rec, "a refused observation leaves no trace")
	next, _ := j.NextSeq()
	require.EqualValues(t, 1, next)
	// the held record is untouched and a pruned one frees its room
	require.NoError(t, j.Delete(first.Slot()))
	used, _ := j.Used()
	require.Zero(t, used)
	_, err = j.Record(f.observe(t, "2", 2, 12, true, 0x01))
	require.NoError(t, err)
}

func TestExportPagesAndGaps(t *testing.T) {
	f := newFixture(t)
	j := newJournal(t, 0)
	for r := uint64(10); r < 10+MaxPageRecords+6; r++ {
		_, err := j.Record(f.observe(t, "1", 2, r, false, 0x01))
		require.NoError(t, err)
	}
	p, err := j.Export(0, 0)
	require.NoError(t, err)
	require.Len(t, p.Records, MaxPageRecords, "a page is clamped")
	require.True(t, p.More)
	require.False(t, p.Gap)
	require.EqualValues(t, 1, p.OldestSeq)
	require.EqualValues(t, MaxPageRecords, p.NextSeq)

	p2, err := j.Export(p.NextSeq, 0)
	require.NoError(t, err)
	require.Len(t, p2.Records, 6)
	require.False(t, p2.More)
	require.EqualValues(t, MaxPageRecords+6, p2.NextSeq)

	end, err := j.Export(p2.NextSeq, 0)
	require.NoError(t, err)
	require.Empty(t, end.Records)
	require.False(t, end.Gap, "an empty tail is complete")

	small, err := j.Export(0, 5)
	require.NoError(t, err)
	require.Len(t, small.Records, 5)

	// pruned events are a declared gap, never an apparently complete empty page
	for r := uint64(10); r < 20; r++ {
		require.NoError(t, j.Delete(Slot{"1", 2, r}))
	}
	g, err := j.Export(0, 0)
	require.NoError(t, err)
	require.True(t, g.Gap)
	require.EqualValues(t, 11, g.OldestSeq)
	require.Len(t, g.Records, MaxPageRecords+6-10)
	require.EqualValues(t, MaxPageRecords+6, g.NextSeq, "the cursor moves on past the gap")
}

func TestObserverTapIsIndependentOfConsensusAdmission(t *testing.T) {
	f := newFixture(t)
	j := newJournal(t, 0)
	o := NewObserver(j, f.store, nil, 8)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go o.Run(ctx)

	// the two halves of an offence: neither carries a high QC (not admissible to consensus), and they arrive in any order
	o.Offer(f.vote(t, "3", 2, 15, true, 0x0b))
	o.Offer(f.vote(t, "3", 2, 15, true, 0x0a))
	require.Eventually(t, func() bool {
		rec, err := j.Get(Slot{"3", 2, 15})
		return err == nil && rec != nil && rec.Paired()
	}, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, Stats{Kept: 2}, o.Stats())
	require.True(t, o.Healthy())

	// a vote that does not verify is counted, never kept
	bad := f.vote(t, "3", 2, 16, false, 0x01)
	bad.Signature[5] ^= 1
	o.Offer(bad)
	require.Eventually(t, func() bool { return o.Stats().Rejected == 1 }, 5*time.Second, 10*time.Millisecond)
	rec, err := j.Get(Slot{"3", 2, 16})
	require.NoError(t, err)
	require.Nil(t, rec)

	// a nil observer is a valid tap
	var none *Observer
	none.Offer(f.vote(t, "3", 2, 17, false, 0x01))
	require.Zero(t, none.Gaps())
}

func TestObserverOverflowAndFailureAreExplicitGaps(t *testing.T) {
	f := newFixture(t)

	// no worker: the queue fills and the overflow is counted, the caller never blocks
	o := NewObserver(newJournal(t, 0), f.store, nil, 2)
	for i := 0; i < 5; i++ {
		o.Offer(f.vote(t, "1", 2, uint64(10+i), false, 0x01))
	}
	require.EqualValues(t, 3, o.Stats().Dropped)
	require.False(t, o.Healthy())

	// a journal that cannot take the record: counted, not kept, not silent
	j := newJournal(t, 10) // smaller than any record
	o = NewObserver(j, f.store, nil, 4)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go o.Run(ctx)
	o.Offer(f.vote(t, "1", 2, 10, false, 0x01))
	require.Eventually(t, func() bool { return o.Stats().Failed == 1 }, 5*time.Second, 10*time.Millisecond)
	require.False(t, o.Healthy())
}

func TestRetention(t *testing.T) {
	terms := Terms{EvidenceWindow: 100, SuffixEvidenceWindow: 50}
	cur := Assignment{OffsetSet: true, Offset: 1000, FirstRound: 10, HKnown: true, HRound: 40, Closed: true, PClose: 2000}
	for _, c := range []struct {
		name     string
		a        Assignment
		progress uint64
		round    uint64
		prune    bool
	}{
		{"ordinary: the cutoff is inclusive", cur, 1000 + 5 + 100, 15, false},
		{"ordinary: one past the cutoff", cur, 1000 + 5 + 100 + 1, 15, true},
		{"ordinary: the last ordinary round H is ordinary", cur, 1000 + 30 + 100 + 1, 40, true},
		{"suffix: the cutoff is inclusive", cur, 2000 + 50, 41, false},
		{"suffix: one past", cur, 2000 + 50 + 1, 41, true},
		{"suffix: no expiry before the closure however late", func() Assignment { a := cur; a.Closed = false; return a }(), 1 << 40, 41, false},
		{"H unknown: the vote may become a suffix vote, however late", func() Assignment { a := cur; a.HKnown = false; return a }(), 1 << 40, 15, false},
		{"not activated", Assignment{}, 1 << 40, 15, false},
		{"before the first round: never admissible", cur, 0, 9, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, reason := Retention(c.a, terms, c.progress, c.round)
			require.Equal(t, c.prune, got, reason)
			require.NotEmpty(t, reason)
		})
	}
}

func TestJournalPrune(t *testing.T) {
	f := newFixture(t)
	j := newJournal(t, 0)
	for r := uint64(10); r < 15; r++ {
		_, err := j.Record(f.observe(t, "1", 2, r, false, 0x01))
		require.NoError(t, err)
	}
	boom := errors.New("view unavailable")
	n, err := j.Prune(func(r *SlotRecord) (bool, error) {
		switch r.Round {
		case 10, 11:
			return true, nil
		case 12:
			return true, boom // an unverifiable view keeps the record
		}
		return false, nil
	})
	require.ErrorIs(t, err, boom)
	require.Equal(t, 2, n)
	for r, want := range map[uint64]bool{10: false, 11: false, 12: true, 13: true, 14: true} {
		rec, gerr := j.Get(Slot{"1", 2, r})
		require.NoError(t, gerr)
		require.Equal(t, want, rec != nil, "round %d", r)
	}
}
