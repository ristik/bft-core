package recordsfeed

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootrecords"
)

func TestAFailedExtensionDoesNotAuthenticateARestoredPrefix(t *testing.T) {
	c := buildChain(t, 5)
	cut, origin := c.cutOf(t, 500, 9000)
	// An internally consistent retained prefix with a different session record.
	prefix := append([]rootrecords.Record(nil), c.records[:2]...)
	prefix[1].Data = append([]byte(nil), prefix[1].Data...)
	prefix[1].Data[0] ^= 1
	r := &prefix[1]
	r.ID = rootrecords.RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data)
	store := KVCutStore{DB: memorydb.New()}
	require.NoError(t, store.AppendRecords(prefix))
	src := NewSource(&fakeRemote{cut: cut, recordsErr: errors.New("unavailable")})
	require.NoError(t, src.SetCutStore(store))
	_, err := src.Record(1)
	require.ErrorIs(t, err, ErrUnavailable)
	_, err = src.Cursor(context.Background(), origin)
	require.ErrorIs(t, err, ErrUnavailable)
	_, err = src.Record(1)
	require.ErrorIs(t, err, ErrUnavailable, "failed extension must not authenticate an unanchored prefix")
}

type failFirstAppend struct {
	CutStore
	calls atomic.Int32
}

func (s *failFirstAppend) AppendRecords(r []rootrecords.Record) error {
	if s.calls.Add(1) == 1 {
		return errors.New("transient disk failure")
	}
	return s.CutStore.AppendRecords(r)
}

func TestAPersistenceFailureKeepsConcurrentExtensionsAtomic(t *testing.T) {
	c := buildChain(t, 5)
	cut, origin := c.cutOf(t, 500, 9000)
	src := NewSource(&fakeRemote{cut: cut, records: c.records})
	require.NoError(t, src.SetCutStore(&failFirstAppend{CutStore: KVCutStore{DB: memorydb.New()}}))
	entered, resume := make(chan struct{}), make(chan struct{})
	src.OnPersistError(func(error) { close(entered); <-resume })
	done := make(chan error, 1)
	go func() { _, err := src.Cursor(context.Background(), origin); done <- err }()
	<-entered
	_, err := src.Cursor(context.Background(), origin)
	require.NoError(t, err)
	close(resume)
	require.NoError(t, <-done)
	records, err := src.Records(0, 100)
	require.NoError(t, err)
	require.NoError(t, rootrecords.VerifyAfter(nil, records), "concurrent extensions must retain a single valid chain")
}

// The same tampered prefix with the genuine suffix available: the suffix does not join it, the cursor fails, and the prefix stays unusable.
func TestATamperedRestoredPrefixStaysUnusableWhenTheSuffixDoesNotJoin(t *testing.T) {
	c := buildChain(t, 5)
	cut, origin := c.cutOf(t, 500, 9000)
	prefix := append([]rootrecords.Record(nil), c.records[:2]...)
	prefix[1].Data = append([]byte(nil), prefix[1].Data...)
	prefix[1].Data[0] ^= 1
	r := &prefix[1]
	r.ID = rootrecords.RecordID(r.Index, r.Predecessor, r.Kind, r.Progress, r.UCTime, r.Data)
	store := KVCutStore{DB: memorydb.New()}
	require.NoError(t, store.AppendRecords(prefix))
	src := NewSource(&fakeRemote{cut: cut, records: c.records})
	require.NoError(t, src.SetCutStore(store))
	_, err := src.Cursor(context.Background(), origin)
	require.ErrorIs(t, err, ErrAuth)
	for i := uint64(0); i < 2; i++ {
		_, err = src.Record(i)
		require.ErrorIs(t, err, ErrUnavailable, "record %d", i)
	}
}
