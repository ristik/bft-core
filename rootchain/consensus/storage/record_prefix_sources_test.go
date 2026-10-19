package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

// sources is a SourcedRecordFetcher over per-root behaviours; asked records which root was asked, in order.
type sources struct {
	roots []RecordFetcher
	asked []int
}

func (s *sources) Sources() int { return len(s.roots) }

func (s *sources) RecordsFromSource(ctx context.Context, i int, from uint64, max int) ([]rootrecords.Record, error) {
	s.asked = append(s.asked, i)
	return s.roots[i].Records(ctx, from, max)
}

// Records is the plain interface: the first non-empty answer in order, which is what #647 is about.
func (s *sources) Records(ctx context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	for _, r := range s.roots {
		if b, err := r.Records(ctx, from, max); err == nil && len(b) > 0 {
			return b, nil
		}
	}
	return nil, errors.New("none")
}

func reID(r *rootrecords.Record) {
	r.ID = rootrecords.RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data)
}

// lies builds the ways one root can serve something that is not the checkpoint's log.
func lies(honest []rootrecords.Record) map[string]RecordFetcher {
	wrongTip := chainOf(len(honest))
	wrongTip[len(honest)-1].Progress++
	reID(&wrongTip[len(honest)-1])
	broken := chainOf(len(honest))
	broken[len(honest)/2].Predecessor[0] ^= 1
	return map[string]RecordFetcher{
		"a chain that ends at another tip":     &sliceFetcher{recs: wrongTip},
		"a chain that does not link":           &sliceFetcher{recs: broken},
		"more records than were asked for":     oversized{sliceFetcher{recs: honest}},
		"an error":                             &sliceFetcher{err: errors.New("connection refused")},
		"nothing":                              &sliceFetcher{},
		"a good first page and a lying second": &pagesThenLie{good: honest, bad: wrongTip, goodPages: 1},
	}
}

// pagesThenLie serves the honest records for its first pages and then a chain that continues with a different record.
type pagesThenLie struct {
	good, bad []rootrecords.Record
	goodPages int
	served    int
}

func (p *pagesThenLie) Records(_ context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	src := p.good
	if p.served >= p.goodPages {
		src = p.bad
	}
	p.served++
	end := min(from+uint64(max), uint64(len(src)))
	if from >= end {
		return nil, nil
	}
	return append([]rootrecords.Record(nil), src[from:end]...), nil
}

// A root earlier in the order that lies no longer blocks the fetch: the next root is asked, within the same bound, and nothing the liar served is written.
func TestPrefixFetchSkipsARootWhoseRecordsDoNotVerify(t *testing.T) {
	defer func(d, b time.Duration) { prefixTimeout, prefixBackoff = d, b }(prefixTimeout, prefixBackoff)
	prefixTimeout, prefixBackoff = 5*time.Second, time.Millisecond
	honest := chainOf(600) // three pages
	control := &evmroot.ControlState{Pos: stateOver(honest).Bytes()}

	for name, liar := range lies(honest) {
		t.Run(name, func(t *testing.T) {
			prefixRotation.Store(0) // the liar is the first root asked
			db := newBolt(t)
			src := &sources{roots: []RecordFetcher{liar, &sliceFetcher{recs: honest}}}
			s := &BlockStore{storage: db, prefixSource: src}
			require.NoError(t, s.ensureRetainedPrefix(control))
			requireLiarThenHonest(t, src.asked)
			n, err := db.RecordCount()
			require.NoError(t, err)
			require.EqualValues(t, 600, n)
			got, err := db.Records(599, 1)
			require.NoError(t, err)
			require.Equal(t, honest[599].ID, got[0].ID, "what is retained is the honest log")
		})
	}

	t.Run("a closure naming another closed epoch than the checkpoint's", func(t *testing.T) {
		prefixRotation.Store(0)
		good := chainOf(3)
		data := make([]byte, 192)
		data[63] = 77
		c := rootrecords.Record{Index: 3, Predecessor: good[2].ID, Kind: rootrecords.KindClosure, Progress: 50, UCTime: 500, Data: data, ClosedEpoch: 4}
		reID(&c)
		good = append(good, c)
		lie := append([]rootrecords.Record(nil), good...)
		lie[3].ClosedEpoch = 5 // the identifier does not cover it
		st := stateOver(good)
		st.Closed = []rootrecords.Awaiting{{Epoch: 4, HRound: 77}}
		db := newBolt(t)
		src := &sources{roots: []RecordFetcher{&sliceFetcher{recs: lie}, &sliceFetcher{recs: good}}}
		s := &BlockStore{storage: db, prefixSource: src}
		require.NoError(t, s.ensureRetainedPrefix(&evmroot.ControlState{Pos: st.Bytes()}))
		requireLiarThenHonest(t, src.asked)
		n, _ := db.RecordCount()
		require.EqualValues(t, 4, n)
	})

	t.Run("a partly retained log is completed from the honest root", func(t *testing.T) {
		prefixRotation.Store(0)
		db := newBolt(t)
		require.NoError(t, db.AppendRecords(honest[:120]))
		wrong := chainOf(600)
		wrong[599].Progress++
		reID(&wrong[599])
		s := &BlockStore{storage: db, prefixSource: &sources{roots: []RecordFetcher{&sliceFetcher{recs: wrong}, &sliceFetcher{recs: honest}}}}
		require.NoError(t, s.ensureRetainedPrefix(control))
		n, _ := db.RecordCount()
		require.EqualValues(t, 600, n)
	})
}

// Every root lying is a refusal at the bound, with the sentinel, and nothing written - not even the pages that verified before the lie.
func TestPrefixFetchWithAllRootsLyingWritesNothing(t *testing.T) {
	defer func(d, b time.Duration) { prefixTimeout, prefixBackoff = d, b }(prefixTimeout, prefixBackoff)
	prefixTimeout, prefixBackoff = 100*time.Millisecond, time.Millisecond
	honest := chainOf(600)
	control := &evmroot.ControlState{Pos: stateOver(honest).Bytes()}
	all := lies(honest)
	liars := []RecordFetcher{all["a chain that ends at another tip"], all["a chain that does not link"], all["a good first page and a lying second"], all["an error"]}

	db := newBolt(t)
	require.NoError(t, db.AppendRecords(honest[:50]))
	src := &sources{roots: liars}
	s := &BlockStore{storage: db, prefixSource: src}
	err := s.ensureRetainedPrefix(control)
	require.ErrorIs(t, err, ErrRecordPrefixMissing)
	require.ErrorIs(t, err, ErrRecordPrefixConflict, "the lies are reported, not hidden behind the timeout")
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.GreaterOrEqual(t, len(src.asked), len(liars), "every root was asked")
	n, e := db.RecordCount()
	require.NoError(t, e)
	require.EqualValues(t, 50, n, "nothing past what was retained")

	// one source that lies: the same
	db = newBolt(t)
	s = &BlockStore{storage: db, prefixSource: &sources{roots: liars[:1]}}
	require.ErrorIs(t, s.ensureRetainedPrefix(control), ErrRecordPrefixMissing)
	n, _ = db.RecordCount()
	require.Zero(t, n)
}

// Each fetch starts at another root, so a root that lies or is slow is not the first one asked by every retry.
func TestPrefixFetchRotatesItsStartingRoot(t *testing.T) {
	defer func(d, b time.Duration) { prefixTimeout, prefixBackoff = d, b }(prefixTimeout, prefixBackoff)
	prefixTimeout, prefixBackoff = 5*time.Second, time.Millisecond
	honest := chainOf(10)
	control := &evmroot.ControlState{Pos: stateOver(honest).Bytes()}
	prefixRotation.Store(0)
	var firsts []int
	for i := 0; i < 3; i++ {
		src := &sources{roots: []RecordFetcher{&sliceFetcher{recs: honest}, &sliceFetcher{recs: honest}, &sliceFetcher{recs: honest}}}
		s := &BlockStore{storage: newBolt(t), prefixSource: src}
		require.NoError(t, s.ensureRetainedPrefix(control))
		firsts = append(firsts, src.asked[0])
	}
	require.Equal(t, []int{0, 1, 2}, firsts)
}

// A plain fetcher (no per-root access) keeps the earlier behaviour: its first answer is verified and a lie is a conflict.
func TestPrefixFetchWithAPlainFetcherIsUnchanged(t *testing.T) {
	honest := chainOf(300)
	wrong := chainOf(300)
	wrong[299].Progress++
	reID(&wrong[299])
	db := newBolt(t)
	s := &BlockStore{storage: db, prefixSource: &sliceFetcher{recs: wrong}}
	require.ErrorIs(t, s.ensureRetainedPrefix(&evmroot.ControlState{Pos: stateOver(honest).Bytes()}), ErrRecordPrefixConflict)
	n, _ := db.RecordCount()
	require.Zero(t, n)
}

// requireLiarThenHonest: root 0 (the liar) was asked first, then root 1 took over for good.
func requireLiarThenHonest(t *testing.T, asked []int) {
	t.Helper()
	require.NotEmpty(t, asked)
	require.Equal(t, 0, asked[0], "the liar is asked first")
	switched := false
	for _, a := range asked {
		if a == 1 {
			switched = true
		}
		require.False(t, switched && a == 0, "no return to the liar once the honest root is being used: %v", asked)
	}
	require.True(t, switched, "the honest root was asked: %v", asked)
}
