package recordsfeed

import (
	"bytes"
	"context"
	"crypto"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

func id32(b byte) [32]byte { return [32]byte{b, b, b, b} }

func closureData(hRound uint64) []byte {
	a, h, r, e, k := id32(1), id32(2), id32(3), id32(4), id32(5)
	var w [32]byte
	binary.BigEndian.PutUint64(w[24:], hRound)
	return bytes.Join([][]byte{a[:], w[:], h[:], r[:], e[:], k[:]}, nil)
}

// chain is a root's source log and the source state that commits it: epoch 1 hands off at H = 100 to epoch 2 (first round 101), whose
// first block closes epoch 1 (a Closure at index 0), followed by n SessionClosed records.
type chain struct {
	state   rootrecords.State
	records []rootrecords.Record
}

func buildChain(t *testing.T, n int) chain {
	t.Helper()
	s := rootrecords.NewState(1, 1)
	s, err := s.Commit(100, 2, 101, true, id32(9))
	require.NoError(t, err)
	s, err = s.Block(2, 105)
	require.NoError(t, err)
	var recs []rootrecords.Record
	var rec rootrecords.Record
	s, rec, err = s.Close(1, closureData(100), 105, 1_500)
	require.NoError(t, err)
	recs = append(recs, rec)
	for i := 0; i < n; i++ {
		var rid [32]byte
		binary.BigEndian.PutUint64(rid[:], uint64(i)+1)
		s, rec, err = s.SessionClosed(rid, 106+uint64(i), 1_501+uint64(i))
		require.NoError(t, err)
		recs = append(recs, rec)
	}
	return chain{state: s, records: recs}
}

// cutOf is the committed block's control state and the tree path of its leaf, and the origin that block's certificate names.
func (c chain) cutOf(t *testing.T, round, refTime uint64) (Cut, evmroot.RootOriginV2) {
	t.Helper()
	control := &evmroot.ControlState{Network: 5, Epoch: 2, Phase: "idle", PreviousDigest: make([]byte, 32), Pos: c.state.Bytes()}
	other := make([]byte, 32)
	other[0] = 7
	tree, err := types.NewUnicityTree(crypto.SHA256, []*types.UnicityTreeData{
		{Partition: evmroot.D4ControlPartition, ShardTreeRoot: control.Digest()},
		{Partition: 7, ShardTreeRoot: other},
	})
	require.NoError(t, err)
	path, err := tree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	return Cut{Control: control, Path: path}, evmroot.RootOriginV2{NetworkID: 5, RootRound: round, RootEpoch: 2, ReferenceTime: refTime, UnicityTreeRoot: tree.RootHash()}
}

type fakeRemote struct {
	cut        Cut
	cutErr     error
	records    []rootrecords.Record
	recordsErr error
	calls      int
	tamper     func(from uint64, batch []rootrecords.Record) []rootrecords.Record
}

func (f *fakeRemote) Cut(context.Context, uint64) (Cut, error) { return f.cut, f.cutErr }

func (f *fakeRemote) Records(_ context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	f.calls++
	if f.recordsErr != nil {
		return nil, f.recordsErr
	}
	end := min(from+uint64(max), uint64(len(f.records)))
	if from >= end {
		return nil, nil
	}
	batch := append([]rootrecords.Record(nil), f.records[from:end]...)
	for i := range batch {
		batch[i].Data = bytes.Clone(batch[i].Data)
	}
	if f.tamper != nil {
		batch = f.tamper(from, batch)
	}
	return batch, nil
}

func TestACutIsVerifiedAgainstTheOriginsTreeRootAndYieldsTheCursor(t *testing.T) {
	c := buildChain(t, 3)
	cut, origin := c.cutOf(t, 110, 1_600)
	state, cursor, err := VerifyCut(cut, origin)
	require.NoError(t, err)
	require.Equal(t, c.state.Digest(), state.Digest())
	wantProgress, err := c.state.Progress(110)
	require.NoError(t, err)
	require.Equal(t, rootrecords.Cursor{Progress: wantProgress, UCTime: 1_600, TargetCount: 4, TargetTip: c.records[3].ID}, cursor)
}

func TestACutIsRefusedUnlessEveryLinkToTheOriginHolds(t *testing.T) {
	c := buildChain(t, 3)
	good, origin := c.cutOf(t, 110, 1_600)
	cloneCut := func() Cut {
		ctl := *good.Control
		ctl.Pos = bytes.Clone(ctl.Pos)
		path := *good.Path
		return Cut{Control: &ctl, Path: &path}
	}
	other := buildChain(t, 5)
	otherCut, otherOrigin := other.cutOf(t, 110, 1_600)

	// a control state with garbage where the source state goes, placed honestly in a tree of its own
	garbage := &evmroot.ControlState{Network: 5, Epoch: 2, Phase: "idle", PreviousDigest: make([]byte, 32), Pos: []byte{1, 2, 3}}
	gtree, err := types.NewUnicityTree(crypto.SHA256, []*types.UnicityTreeData{{Partition: evmroot.D4ControlPartition, ShardTreeRoot: garbage.Digest()}})
	require.NoError(t, err)
	gpath, err := gtree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)
	noPos := &evmroot.ControlState{Network: 5, Epoch: 2, Phase: "idle", PreviousDigest: make([]byte, 32)}
	ntree, err := types.NewUnicityTree(crypto.SHA256, []*types.UnicityTreeData{{Partition: evmroot.D4ControlPartition, ShardTreeRoot: noPos.Digest()}})
	require.NoError(t, err)
	npath, err := ntree.Certificate(evmroot.D4ControlPartition)
	require.NoError(t, err)

	cases := map[string]func() (Cut, evmroot.RootOriginV2){
		"a tampered source state": func() (Cut, evmroot.RootOriginV2) {
			c := cloneCut()
			c.Control.Pos[len(c.Control.Pos)-1] ^= 1
			return c, origin
		},
		"a tampered control field": func() (Cut, evmroot.RootOriginV2) {
			c := cloneCut()
			c.Control.Epoch++
			return c, origin
		},
		"another block's tree root": func() (Cut, evmroot.RootOriginV2) {
			o := origin
			o.UnicityTreeRoot = bytes.Clone(origin.UnicityTreeRoot)
			o.UnicityTreeRoot[0] ^= 1
			return cloneCut(), o
		},
		"a path of a tree with another sibling": func() (Cut, evmroot.RootOriginV2) {
			sibling := make([]byte, 32)
			sibling[0] = 99
			tree, err := types.NewUnicityTree(crypto.SHA256, []*types.UnicityTreeData{
				{Partition: evmroot.D4ControlPartition, ShardTreeRoot: good.Control.Digest()},
				{Partition: 7, ShardTreeRoot: sibling},
			})
			require.NoError(t, err)
			path, err := tree.Certificate(evmroot.D4ControlPartition)
			require.NoError(t, err)
			return Cut{Control: good.Control, Path: path}, origin
		},
		"another chain's cut under this origin": func() (Cut, evmroot.RootOriginV2) { return otherCut, origin },
		"no control state":                      func() (Cut, evmroot.RootOriginV2) { return Cut{Path: good.Path}, origin },
		"no path":                               func() (Cut, evmroot.RootOriginV2) { return Cut{Control: good.Control}, origin },
		"an origin without a tree root": func() (Cut, evmroot.RootOriginV2) {
			o := origin
			o.UnicityTreeRoot = nil
			return good, o
		},
		"a state that is not the canonical source state": func() (Cut, evmroot.RootOriginV2) {
			o := origin
			o.UnicityTreeRoot = gtree.RootHash()
			return Cut{Control: garbage, Path: gpath}, o
		},
		"a control state without a source state": func() (Cut, evmroot.RootOriginV2) {
			o := origin
			o.UnicityTreeRoot = ntree.RootHash()
			return Cut{Control: noPos, Path: npath}, o
		},
		"a round before the epoch's first": func() (Cut, evmroot.RootOriginV2) {
			_, o := c.cutOf(t, 50, 1_600)
			return good, o
		},
		"a UC time before the log's last record": func() (Cut, evmroot.RootOriginV2) {
			_, o := c.cutOf(t, 110, 1_000)
			return good, o
		},
	}
	_ = otherOrigin
	for name, build := range cases {
		cut, o := build()
		_, _, err := VerifyCut(cut, o)
		require.ErrorIs(t, err, ErrAuth, name)
	}
}

func TestTheSourceVerifiesAndRetainsTheLogTheCutAuthenticates(t *testing.T) {
	c := buildChain(t, 300) // more than one batch
	cut, origin := c.cutOf(t, 500, 9_000)
	remote := &fakeRemote{cut: cut, records: c.records}
	src := NewSource(remote)
	_, err := src.Record(0)
	require.ErrorIs(t, err, ErrUnavailable, "nothing is believed before a cut")

	cursor, err := src.Cursor(context.Background(), origin)
	require.NoError(t, err)
	require.EqualValues(t, 301, cursor.TargetCount)
	require.Equal(t, 2, remote.calls, "301 records in batches of %d", MaxBatch)
	for i := range c.records {
		r, err := src.Record(uint64(i))
		require.NoError(t, err)
		require.Equal(t, c.records[i], r)
	}
	_, err = src.Record(301)
	require.ErrorIs(t, err, ErrUnavailable)

	// a later origin of the same log fetches only what is new
	more := buildChain(t, 310)
	cut2, origin2 := more.cutOf(t, 600, 9_100)
	remote.cut, remote.records = cut2, more.records
	_, err = src.Cursor(context.Background(), origin2)
	require.NoError(t, err)
	require.Equal(t, 3, remote.calls, "only the ten new records were fetched")
	// a log that is the same count again costs nothing
	_, err = src.Cursor(context.Background(), origin2)
	require.NoError(t, err)
	require.Equal(t, 3, remote.calls)
}

func TestAnEmptyLogIsAuthenticatedAsEmptyWithoutAFetch(t *testing.T) {
	s := rootrecords.NewState(1, 1)
	c := chain{state: s}
	cut, origin := c.cutOf(t, 10, 100)
	remote := &fakeRemote{cut: cut}
	cursor, err := NewSource(remote).Cursor(context.Background(), origin)
	require.NoError(t, err)
	require.Zero(t, cursor.TargetCount)
	require.Zero(t, remote.calls)
}

func TestARootCannotSubstituteWhatItServes(t *testing.T) {
	c := buildChain(t, 5)
	cut, origin := c.cutOf(t, 200, 9_000)
	for name, tamper := range map[string]func(uint64, []rootrecords.Record) []rootrecords.Record{
		"changed content under its identifier":  func(_ uint64, b []rootrecords.Record) []rootrecords.Record { b[2].Progress++; return b },
		"a rewritten identifier":                func(_ uint64, b []rootrecords.Record) []rootrecords.Record { b[2].ID[0] ^= 1; return b },
		"a broken link":                         func(_ uint64, b []rootrecords.Record) []rootrecords.Record { b[3].Predecessor[0] ^= 1; return b },
		"a skipped record":                      func(_ uint64, b []rootrecords.Record) []rootrecords.Record { return append(b[:2], b[3:]...) },
		"a closure naming another closed epoch": func(_ uint64, b []rootrecords.Record) []rootrecords.Record { b[0].ClosedEpoch = 7; return b },
		"a closed epoch on a session close":     func(_ uint64, b []rootrecords.Record) []rootrecords.Record { b[1].ClosedEpoch = 1; return b },
		"too many records":                      func(_ uint64, b []rootrecords.Record) []rootrecords.Record { return append(b, b[0]) },
	} {
		remote := &fakeRemote{cut: cut, records: c.records, tamper: tamper}
		src := NewSource(remote)
		_, err := src.Cursor(context.Background(), origin)
		require.Error(t, err, name)
		require.False(t, errors.Is(err, ErrWire), name)
		_, rerr := src.Record(0)
		require.ErrorIs(t, rerr, ErrUnavailable, "%s: nothing unverified is retained", name)
	}
}

func TestAForkedTailIsRefusedAtTheAuthenticatedTip(t *testing.T) {
	c := buildChain(t, 5)
	fork := buildChain(t, 5)
	// a fork that agrees up to index 3 and then continues with other valid records
	s := c.state
	_ = s
	cut, origin := c.cutOf(t, 200, 9_000)
	forked := append([]rootrecords.Record(nil), c.records[:4]...)
	var rid [32]byte
	rid[0] = 0xee
	st := rootrecords.NewState(1, 1)
	st, _ = st.Commit(100, 2, 101, true, id32(9))
	st, _ = st.Block(2, 105)
	st, _, _ = st.Close(1, closureData(100), 105, 1_500)
	for i := 0; i < 3; i++ {
		var r [32]byte
		binary.BigEndian.PutUint64(r[:], uint64(i)+1)
		st, _, _ = st.SessionClosed(r, 106+uint64(i), 1_501+uint64(i))
	}
	_, r4, err := st.SessionClosed(rid, 120, 1_999)
	require.NoError(t, err)
	_, r5, err := func() (rootrecords.State, rootrecords.Record, error) {
		n, _, e := st.SessionClosed(rid, 120, 1_999)
		if e != nil {
			return rootrecords.State{}, rootrecords.Record{}, e
		}
		var r2 [32]byte
		r2[0] = 0xef
		return n.SessionClosed(r2, 121, 2_000)
	}()
	require.NoError(t, err)
	forked = append(forked, r4, r5)
	_ = fork
	remote := &fakeRemote{cut: cut, records: forked}
	src := NewSource(remote)
	_, err = src.Cursor(context.Background(), origin)
	require.ErrorIs(t, err, ErrAuth, "a well-formed log that ends at another tip is not the authenticated log")
	_, rerr := src.Record(0)
	require.ErrorIs(t, rerr, ErrUnavailable)
}

func TestWithholdingIsUnavailabilityNeverAnEmptyFeed(t *testing.T) {
	c := buildChain(t, 5)
	cut, origin := c.cutOf(t, 200, 9_000)
	for name, remote := range map[string]*fakeRemote{
		"no cut":            {cutErr: errors.New("pruned"), records: c.records},
		"a failing fetch":   {cut: cut, recordsErr: errors.New("down")},
		"an empty response": {cut: cut},
	} {
		_, err := NewSource(remote).Cursor(context.Background(), origin)
		require.ErrorIs(t, err, ErrUnavailable, name)
	}
}

func TestACachedLogThatDisagreesWithTheAuthenticatedTipIsRefused(t *testing.T) {
	a := buildChain(t, 5)
	cutA, originA := a.cutOf(t, 200, 9_000)
	src := NewSource(&fakeRemote{cut: cutA, records: a.records})
	_, err := src.Cursor(context.Background(), originA)
	require.NoError(t, err)
	// the same length, another log: the cache is never silently replaced
	b := buildChain(t, 5)
	b.records[3].Predecessor = a.records[3].Predecessor
	st := b.state
	st.Tip[0] ^= 1
	cutB, originB := chain{state: st}.cutOf(t, 201, 9_001)
	src.remotes = []Remote{&fakeRemote{cut: cutB, records: a.records}}
	_, err = src.Cursor(context.Background(), originB)
	require.ErrorIs(t, err, ErrAuth)
}

// The route is what a pair's B1 config consumes.
var _ rootinput.RecordsSource = (*Source)(nil)
