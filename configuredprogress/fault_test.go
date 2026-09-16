package configuredprogress

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRetentionDeletionFailureRollsBackWholeTransactionAcrossReopen(t *testing.T) {
	f := newFixture(t, 2)
	s, path := f.open(1)
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	o1 := f.first(1, 2, 5)
	op, _, err := s.PrepareObservation(context.Background(), f.ctx, o1)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	rp, err := s.PrepareRecord(context.Background(), f.ctx, f.record(1, o1))
	require.NoError(t, err)
	_, err = s.CommitRecord(rp)
	require.NoError(t, err)
	o2 := f.ordinary(2, 3, 6)
	op, _, err = s.PrepareObservation(context.Background(), f.ctx, o2)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	rp, err = s.PrepareRecord(context.Background(), f.ctx, f.record(2, o2))
	require.NoError(t, err)
	s.checkpoint = func(name string) error {
		if name == "after-retention-delete" {
			return errors.New("retention cut")
		}
		return nil
	}
	_, err = s.CommitRecord(rp)
	require.ErrorContains(t, err, "retention cut")
	s.checkpoint = nil
	require.NoError(t, s.Close())
	s, err = OpenConfiguredV2(path, Settings{Retain: 1})
	require.NoError(t, err)
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	head, ok := st.Head()
	require.True(t, ok)
	require.Equal(t, uint64(1), head.BlockNumber(), "failed transaction retains the old head")
	keys, err := bucketKeys(s)
	require.NoError(t, err)
	require.Contains(t, keys, string(recordKey(1, f.c.Blocks[1].Hash)))
	require.NotContains(t, keys, string(recordKey(2, f.c.Blocks[2].Hash)))
	rp, err = s.PrepareRecord(context.Background(), f.ctx, f.record(2, o2))
	require.NoError(t, err)
	_, err = s.CommitRecord(rp)
	require.NoError(t, err)
	require.NoError(t, s.Close())
	s, err = OpenConfiguredV2(path, Settings{Retain: 1})
	require.NoError(t, err)
	defer s.Close()
	st, _, err = s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	head, ok = st.Head()
	require.True(t, ok)
	require.Equal(t, uint64(2), head.BlockNumber(), "successful transaction survives reopen")
	keys, err = bucketKeys(s)
	require.NoError(t, err)
	require.NotContains(t, keys, string(recordKey(1, f.c.Blocks[1].Hash)))
	require.Contains(t, keys, string(recordKey(2, f.c.Blocks[2].Hash)))
}
