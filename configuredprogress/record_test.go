package configuredprogress

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestPublishFirstRecordReopenAndRetention(t *testing.T) {
	f := newFixture(t, 3)
	s, path := f.open(2)
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	o1 := f.first(1, 2, 5)
	p, _, err := s.PrepareObservation(context.Background(), f.ctx, o1)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	rp, err := s.PrepareRecord(context.Background(), f.ctx, f.record(1, o1))
	require.NoError(t, err)
	l, err := s.CommitRecord(rp)
	require.NoError(t, err)
	require.Equal(t, uint64(1), l.BlockNumber())
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(2), st.Revision())
	head, ok := st.Head()
	require.True(t, ok)
	require.Equal(t, uint64(1), head.BlockNumber())
	require.NoError(t, s.Close())
	s, err = OpenConfiguredV2(path, Settings{Retain: 2})
	require.NoError(t, err)
	defer s.Close()
	st, _, err = s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	head, ok = st.Head()
	require.True(t, ok)
	require.Equal(t, uint64(1), head.BlockNumber())
	for i := 2; i <= 3; i++ {
		o := f.ordinary(i, uint64(i+1), uint64(4+i))
		op, _, e := s.PrepareObservation(context.Background(), f.ctx, o)
		require.NoError(t, e)
		_, _, e = s.CommitObservation(op)
		require.NoError(t, e)
		rp, e := s.PrepareRecord(context.Background(), f.ctx, f.record(i, o))
		require.NoError(t, e)
		_, e = s.CommitRecord(rp)
		require.NoError(t, e)
	}
	keys, err := bucketKeys(s)
	require.NoError(t, err)
	var records int
	for _, k := range keys {
		if len(k) > 7 && k[:7] == "record/" {
			records++
		}
	}
	require.Equal(t, 2, records)
}

func TestRecordCASAndAtomicFailure(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(3)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	o1 := f.first(1, 2, 5)
	op, _, _ := s.PrepareObservation(context.Background(), f.ctx, o1)
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	rp, err := s.PrepareRecord(context.Background(), f.ctx, f.record(1, o1))
	require.NoError(t, err)
	o2 := f.ordinary(2, 3, 6)
	op, _, err = s.PrepareObservation(context.Background(), f.ctx, o2)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	_, err = s.CommitRecord(rp)
	require.ErrorIs(t, err, ErrStale)
	rp, err = s.PrepareRecord(context.Background(), f.ctx, f.record(1, o1))
	require.NoError(t, err)
	s.checkpoint = func(name string) error {
		if name == "after-record-put" {
			return errors.New("cut")
		}
		return nil
	}
	_, err = s.CommitRecord(rp)
	require.Error(t, err)
	s.checkpoint = nil
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	_, ok := st.Head()
	require.False(t, ok, "transaction rollback leaves observation-only recovery state")
	require.Equal(t, uint64(2), st.Revision())
	rp, err = s.PrepareRecord(context.Background(), f.ctx, f.record(1, o1))
	require.NoError(t, err)
	_, err = s.CommitRecord(rp)
	require.NoError(t, err)
}

func bucketKeys(s *Store) ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		return b.ForEach(func(k, v []byte) error { out = append(out, string(k)); return nil })
	})
	return out, err
}
