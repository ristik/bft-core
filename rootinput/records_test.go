package rootinput_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/b1fixture"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

type fakeRecords struct {
	log       []rootrecords.Record
	cursor    rootrecords.Cursor
	cursorErr error
	missing   map[uint64]bool
}

func (f fakeRecords) Record(i uint64) (rootrecords.Record, error) {
	if f.missing[i] || i >= uint64(len(f.log)) {
		return rootrecords.Record{}, errors.New("not retained")
	}
	return f.log[i], nil
}

func (f fakeRecords) Cursor(context.Context, uint64) (rootrecords.Cursor, error) {
	return f.cursor, f.cursorErr
}

func backlog(t *testing.T, n int) fakeRecords {
	t.Helper()
	l := &rootrecords.Log{}
	var last rootrecords.Record
	for i := 0; i < n; i++ {
		var id [32]byte
		id[0], id[1] = byte(i+1), 0x51
		r, err := l.Append(rootrecords.KindSessionClosed, id[:], rootrecords.Anchor{Progress: 10 + uint64(i), UCTime: 1_001 + uint64(i)})
		require.NoError(t, err)
		last = r
	}
	return fakeRecords{log: l.Records(), cursor: rootrecords.Cursor{Progress: 100, UCTime: 2_000, TargetCount: uint64(n), TargetTip: last.ID}}
}

func TestTheRootInputCommitsTheNextRequiredPrefixOfTheSourceLog(t *testing.T) {
	f := b1fixture.New(t, 0)
	c := rootinput.ContextV2{Context: context.Background(), Genesis: f.Origin, Parent: f.Parent, Round: 1, ParentHash: f.Parent.ParentHash().Bytes(), B1: f.Pair}

	f.Pair.Records = backlog(t, 40)
	res, err := rootinput.DeriveV2(c, f.Observation)
	require.NoError(t, err)
	imp, err := rootrecords.DecodeImport(res.RecordsImport)
	require.NoError(t, err)
	require.Len(t, imp.Entries, 32, "exactly min(32, target - count)")
	require.EqualValues(t, 40, imp.TargetCount)
	require.EqualValues(t, 0, imp.Entries[0].Record.Index, "the registry holds none yet")
	require.Equal(t, sha256.Sum256(res.RecordsImport), [32]byte(res.Input.RootRecordsHash))
	require.Equal(t, byte(0x8d), res.Encoded[0])

	// an empty source log still imports: the mandatory empty batch
	f.Pair.Records = b1fixture.EmptyRecords{UCTime: f.Pair.Profile.GenesisUCTime}
	res, err = rootinput.DeriveV2(c, f.Observation)
	require.NoError(t, err)
	imp, err = rootrecords.DecodeImport(res.RecordsImport)
	require.NoError(t, err)
	require.Empty(t, imp.Entries)
}

func TestTheRecordsImportRefusesWhatTheRegistryWouldRefuse(t *testing.T) {
	f := b1fixture.New(t, 0)
	c := rootinput.ContextV2{Context: context.Background(), Genesis: f.Origin, Parent: f.Parent, Round: 1, ParentHash: f.Parent.ParentHash().Bytes(), B1: f.Pair}
	cases := map[string]func(r *fakeRecords){
		"the cursor is unavailable":                  func(r *fakeRecords) { r.cursorErr = errors.New("origin block pruned") },
		"a record the source cannot serve":           func(r *fakeRecords) { r.missing = map[uint64]bool{3: true} },
		"a current UC time below the registry's":     func(r *fakeRecords) { r.cursor.UCTime = f.Pair.Profile.GenesisUCTime - 1 },
		"a target tip that is not the log's":         func(r *fakeRecords) { r.cursor.TargetTip[0] ^= 1 },
		"a current progress below a record's anchor": func(r *fakeRecords) { r.cursor.Progress = 12 },
	}
	for name, mutate := range cases {
		src := backlog(t, 5)
		mutate(&src)
		f.Pair.Records = src
		_, err := rootinput.DeriveV2(c, f.Observation)
		require.ErrorIs(t, err, rootinput.ErrRecordsAdmission, name)
	}
	f.Pair.Records = nil
	_, err := rootinput.DeriveV2(c, f.Observation)
	require.ErrorIs(t, err, rootinput.ErrRecordsAdmission, "a fresh profile cannot admit a block without the import")
}

func TestThePairRederivesTheImportForImportReplayAndRecovery(t *testing.T) {
	f := b1fixture.New(t, 0)
	f.Pair.Records = backlog(t, 3)
	c := rootinput.ContextV2{Context: context.Background(), Genesis: f.Origin, Parent: f.Parent, Round: 1, ParentHash: f.Parent.ParentHash().Bytes(), B1: f.Pair}
	res, err := rootinput.DeriveV2(c, f.Observation)
	require.NoError(t, err)
	hash := res.Input.RootRecordsHash
	got, err := f.Pair.CompareRecords(context.Background(), f.Parent, f.Observation, res.RecordsImport, hash)
	require.NoError(t, err)
	require.Equal(t, res.RecordsImport, got.Import)
	other := append([]byte(nil), res.RecordsImport...)
	other[len(other)-1] ^= 1
	_, err = f.Pair.CompareRecords(context.Background(), f.Parent, f.Observation, other, hash)
	require.ErrorIs(t, err, rootinput.ErrRecordsAdmission)
	wrongHash := append([]byte(nil), hash...)
	wrongHash[0] ^= 1
	_, err = f.Pair.CompareRecords(context.Background(), f.Parent, f.Observation, res.RecordsImport, wrongHash)
	require.ErrorIs(t, err, rootinput.ErrRecordsAdmission)
}
