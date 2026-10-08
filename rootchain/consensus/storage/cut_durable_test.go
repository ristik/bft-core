package storage

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

func keyOfBlock(t *testing.T, b *ExecutedBlock) CutKey {
	t.Helper()
	e, err := cutEntryOf(b)
	require.NoError(t, err)
	require.NotNil(t, e)
	return e.Key
}

// Cuts of an ordinary pre-H origin, of the H checkpoint and of a late empty suffix stay served across the epoch install, a restart of
// the store, the replacement of the block tree and more than the cache bound of later cuts.
func TestCutsOfEveryOriginSurviveTheEpochInstallRestartsAndTheCacheBound(t *testing.T) {
	f := newAssignmentFixture(t)
	f.useRealOrchestration(t)
	f.seedFees(t)
	var ordinary CutKey
	f.afterFreeze = func(t *testing.T) {
		ordinary = keyOfBlock(t, mustBlock(t, f.store, 2))
		commitRound(t, f.store, 2)
	}
	h := f.commitAssignment(t)
	hKey := keyOfBlock(t, f.store.blockTree.Root()) // the block that carries the committed handoff record
	require.EqualValues(t, 4, f.store.blockTree.Root().GetRound())
	commitRound(t, f.store, 5)
	suffix := keyOfBlock(t, f.store.blockTree.Root())
	require.EqualValues(t, 5, suffix.Round)
	require.NotEqual(t, hKey.TreeRoot, ordinary.TreeRoot, "the ordinary origin's tree differs from H's")
	require.Equal(t, hKey.TreeRoot, suffix.TreeRoot, "an unchanged-state suffix has H's tree, at its own round")
	require.NotEqual(t, hKey, suffix, "and is a distinct, original origin")

	served := func(s *BlockStore, when string) {
		t.Helper()
		for name, k := range map[string]CutKey{"ordinary pre-H": ordinary, "H checkpoint": hKey, "late suffix": suffix} {
			cut, err := s.ControlCut(k)
			require.NoError(t, err, "%s %s", name, when)
			require.NotNil(t, cut.Control, "%s %s", name, when)
		}
	}
	served(f.store, "before the install")

	anchor, err := f.store.InstallEpochAnchor(h.head, h.verified, h.genesis)
	require.NoError(t, err)
	served(f.store, "after the install replaced the block tree")

	restart := func() *BlockStore {
		s, err := New(crypto.SHA256, f.store.storage, f.orch, logger.New(t), ProfileHandoff)
		require.NoError(t, err)
		return s
	}
	s := restart()
	served(s, "after a restart in the new epoch")
	f.addSuccessorBlock(t, s, 7, anchor)

	// the cache bound limits memory, not availability
	for i := uint64(0); i < MaxRetainedCuts+10; i++ {
		s.blockTree.cuts.put(CutKey{Network: 5, Epoch: 2, Round: 1_000 + i}, ControlCut{})
	}
	require.Len(t, s.blockTree.cuts.order, MaxRetainedCuts)
	_, hot := s.blockTree.cuts.get(ordinary)
	require.False(t, hot, "evicted from memory")
	served(s, "after the cache evicted them")
	served(restart(), "after a second restart")

	// another epoch's cut of an overlapping round is not this one's
	elsewhere := ordinary
	elsewhere.Epoch++
	_, err = s.ControlCut(elsewhere)
	require.ErrorIs(t, err, ErrCutUnavailable)
	wrongTree := hKey
	wrongTree.TreeRoot[0] ^= 1
	_, err = s.ControlCut(wrongTree)
	require.ErrorIs(t, err, ErrCutUnavailable)
}

type sliceFetcher struct {
	recs  []rootrecords.Record
	calls int
	err   error
}

func (f *sliceFetcher) Records(_ context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	end := min(from+uint64(max), uint64(len(f.recs)))
	if from >= end {
		return nil, nil
	}
	return append([]rootrecords.Record(nil), f.recs[from:end]...), nil
}

func chainOf(n int) []rootrecords.Record {
	var out []rootrecords.Record
	var prev [32]byte
	for i := 0; i < n; i++ {
		r := rootrecords.Record{Index: uint64(i), Predecessor: prev, Kind: rootrecords.KindSessionClosed, Progress: uint64(10 + i), UCTime: uint64(100 + i), Data: make([]byte, 32)}
		r.ID = rootrecords.RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data)
		prev = r.ID
		out = append(out, r)
	}
	return out
}

func stateOver(recs []rootrecords.Record) rootrecords.State {
	s := rootrecords.NewState(1, 2)
	s.Count = uint64(len(recs))
	if len(recs) > 0 {
		s.Tip = recs[len(recs)-1].ID
	}
	return s
}

// A root that installs a checkpoint without the log it commits fetches the missing prefix, verified against the checkpoint's own
// state; it never starts on a cursor alone, on a conflicting log, or on a prefix that ends elsewhere.
func TestInstallRequiresTheRetainedPrefixTheCheckpointCommits(t *testing.T) {
	recs := chainOf(300)
	state := stateOver(recs)
	control := func(s rootrecords.State) *evmroot.ControlState { return &evmroot.ControlState{Pos: s.Bytes()} }

	newStore := func(t *testing.T, fetcher RecordFetcher, retained []rootrecords.Record) (*BlockStore, BoltDB) {
		db := newBolt(t)
		if len(retained) > 0 {
			require.NoError(t, db.AppendRecords(retained))
		}
		s := &BlockStore{storage: db}
		s.prefixSource = fetcher
		return s, db
	}

	t.Run("a complete prefix needs nothing", func(t *testing.T) {
		f := &sliceFetcher{recs: recs}
		s, _ := newStore(t, f, recs)
		require.NoError(t, s.ensureRetainedPrefix(control(state)))
		require.Zero(t, f.calls)
	})
	t.Run("a longer retained log is checked at the committed length", func(t *testing.T) {
		s, _ := newStore(t, nil, recs)
		require.NoError(t, s.ensureRetainedPrefix(control(stateOver(recs[:100]))))
	})
	t.Run("a missing prefix is fetched in bounded pages and retained", func(t *testing.T) {
		f := &sliceFetcher{recs: recs}
		s, db := newStore(t, f, nil)
		require.NoError(t, s.ensureRetainedPrefix(control(state)))
		require.Equal(t, 2, f.calls, "300 records in pages of %d", prefixPage)
		n, err := db.RecordCount()
		require.NoError(t, err)
		require.EqualValues(t, 300, n)
		// subsequent appends extend that prefix
		next := rootrecords.Record{Index: 300, Predecessor: recs[299].ID, Kind: rootrecords.KindSessionClosed, Progress: 999, UCTime: 999, Data: make([]byte, 32)}
		next.ID = rootrecords.RecordID(next.Index, next.Predecessor, next.Kind, next.Progress, next.UCTime, next.Data)
		require.NoError(t, db.AppendRecords([]rootrecords.Record{next}))
	})
	t.Run("a partly retained prefix is completed from its tip", func(t *testing.T) {
		f := &sliceFetcher{recs: recs}
		s, db := newStore(t, f, recs[:120])
		require.NoError(t, s.ensureRetainedPrefix(control(state)))
		n, err := db.RecordCount()
		require.NoError(t, err)
		require.EqualValues(t, 300, n)
	})
	t.Run("no way to fetch is a refusal, not a start", func(t *testing.T) {
		s, db := newStore(t, nil, recs[:120])
		require.ErrorIs(t, s.ensureRetainedPrefix(control(state)), ErrRecordPrefixMissing)
		n, _ := db.RecordCount()
		require.EqualValues(t, 120, n)
	})
	t.Run("an unavailable source is a refusal", func(t *testing.T) {
		s, _ := newStore(t, &sliceFetcher{err: errors.New("down")}, nil)
		require.ErrorIs(t, s.ensureRetainedPrefix(control(state)), ErrRecordPrefixMissing)
	})
	t.Run("a retained log with another tip conflicts", func(t *testing.T) {
		other := chainOf(300)
		other[299].Progress++
		other[299].ID = rootrecords.RecordID(299, other[299].Predecessor, other[299].Kind, other[299].Progress, other[299].UCTime, other[299].Data)
		s, _ := newStore(t, nil, other)
		require.ErrorIs(t, s.ensureRetainedPrefix(control(state)), ErrRecordPrefixConflict)
	})
	t.Run("fetched records that end at another tip are refused and nothing is retained", func(t *testing.T) {
		wrong := chainOf(300)
		wrong[299].Progress++
		wrong[299].ID = rootrecords.RecordID(299, wrong[299].Predecessor, wrong[299].Kind, wrong[299].Progress, wrong[299].UCTime, wrong[299].Data)
		s, db := newStore(t, &sliceFetcher{recs: wrong}, nil)
		require.ErrorIs(t, s.ensureRetainedPrefix(control(state)), ErrRecordPrefixConflict)
		n, _ := db.RecordCount()
		require.Zero(t, n)
	})
	t.Run("fetched records that do not chain are refused", func(t *testing.T) {
		broken := chainOf(300)
		broken[150].Predecessor[0] ^= 1
		s, db := newStore(t, &sliceFetcher{recs: broken}, nil)
		require.ErrorIs(t, s.ensureRetainedPrefix(control(state)), ErrRecordPrefixConflict)
		n, _ := db.RecordCount()
		require.Zero(t, n)
	})
	t.Run("a response larger than the request is refused", func(t *testing.T) {
		s, db := newStore(t, oversized{sliceFetcher{recs: recs}}, nil)
		require.ErrorIs(t, s.ensureRetainedPrefix(control(state)), ErrRecordPrefixMissing)
		n, _ := db.RecordCount()
		require.Zero(t, n)
	})
	t.Run("a closure naming another closed epoch than the checkpoint's is refused", func(t *testing.T) {
		withClosure := chainOf(3)
		data := make([]byte, 192)
		data[63] = 77 // the H round the closure names
		c := rootrecords.Record{Index: 3, Predecessor: withClosure[2].ID, Kind: rootrecords.KindClosure, Progress: 50, UCTime: 500, Data: data, ClosedEpoch: 4}
		c.ID = rootrecords.RecordID(c.Index, c.Predecessor, c.Kind, c.Progress, c.UCTime, c.Data)
		withClosure = append(withClosure, c)
		st := stateOver(withClosure)
		st.Closed = []rootrecords.Awaiting{{Epoch: 4, HRound: 77}}
		s, db := newStore(t, &sliceFetcher{recs: withClosure}, nil)
		require.NoError(t, s.ensureRetainedPrefix(control(st)), "the checkpoint agrees")

		withClosure[3].ClosedEpoch = 5 // the identifier does not cover it
		st.Closed = []rootrecords.Awaiting{{Epoch: 4, HRound: 77}}
		s, db = newStore(t, &sliceFetcher{recs: withClosure}, nil)
		require.ErrorIs(t, s.ensureRetainedPrefix(control(st)), ErrRecordPrefixConflict)
		n, _ := db.RecordCount()
		require.Zero(t, n)
	})
	t.Run("a checkpoint with no records needs no log", func(t *testing.T) {
		s, _ := newStore(t, nil, nil)
		require.NoError(t, s.ensureRetainedPrefix(control(stateOver(nil))))
		require.NoError(t, s.ensureRetainedPrefix(&evmroot.ControlState{}))
		require.NoError(t, s.ensureRetainedPrefix(nil))
	})
}

func entryAt(t *testing.T, network, epoch, round uint64, salt byte) CutEntry {
	t.Helper()
	b := cutBlock(epoch, round, rootrecords.NewState(1, 1).Bytes())
	b.ShardState.Control.Network = network
	b.ShardState.Control.PreviousDigest = bytes32of(salt)
	e, err := cutEntryOf(b)
	require.NoError(t, err)
	return *e
}

func bytes32of(b byte) []byte { x := make([]byte, 32); x[0] = b; return x }

func TestCutsAreExportedInBoundedPagesAndRestoredAllOrNothing(t *testing.T) {
	src := newBolt(t)
	var all []CutEntry
	for i := uint64(1); i <= 150; i++ {
		e := entryAt(t, 5, 1+i/100, i, byte(i)) // epochs 1 and 2 overlap in numeric rounds below 100? no: distinct rounds, two epochs
		all = append(all, e)
		require.NoError(t, src.PutCut(e))
	}
	var paged []CutEntry
	var after *CutKey
	for {
		page, err := src.CutPage(after, 1_000)
		require.NoError(t, err)
		require.LessOrEqual(t, len(page), MaxCutPage)
		if len(page) == 0 {
			break
		}
		paged = append(paged, page...)
		last := page[len(page)-1].Key
		after = &last
	}
	require.Len(t, paged, len(all))

	dst := newBolt(t)
	for i := 0; i < len(paged); i += MaxCutPage {
		end := min(i+MaxCutPage, len(paged))
		require.NoError(t, RestoreCuts(dst, paged[i:end], nil))
	}
	for _, e := range all {
		got, err := dst.GetCut(e.Key)
		require.NoError(t, err)
		require.Equal(t, e.Cut.Control.Digest(), got.Control.Digest())
	}
	require.NoError(t, RestoreCuts(dst, paged[:10], nil), "a repeat is idempotent")

	// a page with one cut that does not lead to its key's root keeps nothing of it
	fresh := newBolt(t)
	bad := append([]CutEntry(nil), paged[:5]...)
	bad[3].Key.TreeRoot[0] ^= 1
	require.ErrorIs(t, RestoreCuts(fresh, bad, nil), ErrCutCorrupt)
	_, err := fresh.GetCut(paged[0].Key)
	require.ErrorIs(t, err, ErrCutUnavailable)
	// a cut the original authority does not certify is refused, whole page
	require.Error(t, RestoreCuts(fresh, paged[:5], func(e CutEntry) error {
		if e.Key == paged[2].Key {
			return errors.New("not certified by the committee of its epoch")
		}
		return nil
	}))
	_, err = fresh.GetCut(paged[0].Key)
	require.ErrorIs(t, err, ErrCutUnavailable)
	// oversize pages are refused
	require.ErrorIs(t, RestoreCuts(fresh, make([]CutEntry, MaxCutPage+1), nil), ErrCutCorrupt)
}

func TestACutThatDoesNotLeadToItsKeyIsNeverStored(t *testing.T) {
	db := newBolt(t)
	e := entryAt(t, 5, 1, 9, 1)
	wrongRoot := e
	wrongRoot.Key.TreeRoot[0] ^= 1
	require.ErrorIs(t, db.PutCut(wrongRoot), ErrCutCorrupt)
	wrongNetwork := e
	wrongNetwork.Key.Network = 6 // the same tree, claimed under another deployment
	require.ErrorIs(t, db.PutCut(wrongNetwork), ErrCutCorrupt)
	_, err := db.GetCut(e.Key)
	require.ErrorIs(t, err, ErrCutUnavailable)
	require.NoError(t, db.PutCut(e))
	require.NoError(t, db.PutCut(e), "the same cut again is a no-op")
}

// oversized answers every request with the whole log
type oversized struct{ sliceFetcher }

func (o oversized) Records(_ context.Context, _ uint64, _ int) ([]rootrecords.Record, error) {
	return o.recs, nil
}
