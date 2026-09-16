package configuredprogress

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootinput"
	bolt "go.etcd.io/bbolt"
)

func TestHashIndexReadRetentionReopenAndOwnedEvidence(t *testing.T) {
	f := newFixture(t, 3)
	s, path := f.open(2)
	for i := 1; i <= 3; i++ {
		publishIndexed(t, s, f, i)
	}
	_, err := s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[1].Hash)
	require.ErrorIs(t, err, ErrUnavailable, "retention deletes locator with record")
	loaded, err := s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[2].Hash)
	require.NoError(t, err)
	ev := loaded.Witness()
	ev.Header[0] ^= 1
	again, err := s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[2].Hash)
	require.NoError(t, err)
	require.NotEqual(t, ev.Header, again.Witness().Header)
	require.NoError(t, s.Close())
	s, err = OpenConfiguredV2(path, Settings{Retain: 2})
	require.NoError(t, err)
	defer s.Close()
	_, err = s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[3].Hash)
	require.NoError(t, err)
}

func TestHashIndexIsLocatorOnlyAndFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *Store, *fixture){
		"forged locator to valid record": func(t *testing.T, s *Store, f *fixture) {
			v, _ := encodeHashIndex(recordKey(f.c.Blocks[2].Round, f.c.Blocks[2].Hash))
			putRaw(t, s, hashIndexKey(f.c.Blocks[1].Hash), v)
		},
		"dangling": func(t *testing.T, s *Store, f *fixture) {
			deleteRaw(t, s, recordKey(f.c.Blocks[1].Round, f.c.Blocks[1].Hash))
		},
		"corrupt locator": func(t *testing.T, s *Store, f *fixture) { putRaw(t, s, hashIndexKey(f.c.Blocks[1].Hash), []byte{0xff}) },
		"corrupt head": func(t *testing.T, s *Store, f *fixture) {
			st, _, err := s.Load(context.Background(), f.ctx)
			require.NoError(t, err)
			putRaw(t, s, st.i.headName, []byte{0xff})
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 2)
			s, _ := f.open(2)
			defer s.Close()
			publishIndexed(t, s, f, 1)
			publishIndexed(t, s, f, 2)
			mutate(t, s, f)
			_, err := s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[1].Hash)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrUnavailable)
		})
	}
}

func TestHashIndexRejectsFutureCandidateAgainstCurrentImage(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(3)
	defer s.Close()
	publishIndexed(t, s, f, 1)
	oldControl := readRawValue(t, s, controlKey)
	publishIndexed(t, s, f, 2)
	putRaw(t, s, controlKey, oldControl)
	_, err := s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[2].Hash)
	require.ErrorIs(t, err, ErrUntrusted)
}

func TestHashIndexRequiresPublishedOrdinaryImage(t *testing.T) {
	for _, observed := range []bool{false, true} {
		t.Run(map[bool]string{false: "revision zero", true: "observed without head"}[observed], func(t *testing.T) {
			f := newFixture(t, 1)
			s, _ := f.open(2)
			defer s.Close()
			_, _, err := s.Initialize(context.Background(), f.ctx)
			require.NoError(t, err)
			o := f.first(1, 2, 5)
			if observed {
				op, _, _ := s.PrepareObservation(context.Background(), f.ctx, o)
				_, _, err = s.CommitObservation(op)
				require.NoError(t, err)
			}
			st, _, err := s.Load(context.Background(), f.ctx)
			require.NoError(t, err)
			key, raw, _, _, err := encodeOuterRecord(context.Background(), f.ctx, st.i.descriptorDigest, f.record(1, o))
			require.NoError(t, err)
			idx, _ := encodeHashIndex(key)
			putRaw(t, s, key, raw)
			putRaw(t, s, hashIndexKey(f.c.Blocks[1].Hash), idx)
			_, err = s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[1].Hash)
			require.ErrorIs(t, err, ErrUntrusted)
		})
	}
}

func TestOldUnindexedRecordsRemainUsableWithoutBackfill(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(1)
	defer s.Close()
	o1 := publishIndexed(t, s, f, 1)
	deleteRaw(t, s, hashIndexKey(f.c.Blocks[1].Hash))
	_, err := s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[1].Hash)
	require.ErrorIs(t, err, ErrUnavailable)
	noOp, err := s.PrepareRecord(context.Background(), f.ctx, f.record(1, o1))
	require.NoError(t, err)
	_, err = s.CommitRecord(noOp)
	require.NoError(t, err)
	require.Nil(t, readRawValueOptional(t, s, hashIndexKey(f.c.Blocks[1].Hash)), "no-op does not backfill")
	publishIndexed(t, s, f, 2)
	_, err = s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[2].Hash)
	require.NoError(t, err)
}

func TestDanglingMatchingIndexRefusesPublicationAtomically(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	o := f.first(1, 2, 5)
	op, _, _ := s.PrepareObservation(context.Background(), f.ctx, o)
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	key := recordKey(f.c.Blocks[1].Round, f.c.Blocks[1].Hash)
	idx, _ := encodeHashIndex(key)
	putRaw(t, s, hashIndexKey(f.c.Blocks[1].Hash), idx)
	p, err := s.PrepareRecord(context.Background(), f.ctx, f.record(1, o))
	require.NoError(t, err)
	_, err = s.CommitRecord(p)
	require.ErrorIs(t, err, ErrUntrusted)
	require.Nil(t, readRawValueOptional(t, s, key))
}

func TestHashIndexAtomicRollback(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	o := f.first(1, 2, 5)
	op, _, _ := s.PrepareObservation(context.Background(), f.ctx, o)
	_, _, _ = s.CommitObservation(op)
	p, err := s.PrepareRecord(context.Background(), f.ctx, f.record(1, o))
	require.NoError(t, err)
	s.checkpoint = func(name string) error {
		if name == "after-record-put" {
			return errors.New("cut")
		}
		return nil
	}
	_, err = s.CommitRecord(p)
	require.Error(t, err)
	s.checkpoint = nil
	require.Nil(t, readRawValueOptional(t, s, hashIndexKey(f.c.Blocks[1].Hash)))
}

func publishIndexed(t *testing.T, s *Store, f *fixture, i int) rootinput.VerifiedObservationV2 {
	t.Helper()
	o := f.first(i, uint64(i+1), uint64(4+i))
	if i > 1 {
		o = f.ordinary(i, uint64(i+1), uint64(4+i))
	}
	if i == 1 {
		_, _, err := s.Initialize(context.Background(), f.ctx)
		require.NoError(t, err)
	}
	op, _, err := s.PrepareObservation(context.Background(), f.ctx, o)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	rp, err := s.PrepareRecord(context.Background(), f.ctx, f.record(i, o))
	require.NoError(t, err)
	_, err = s.CommitRecord(rp)
	require.NoError(t, err)
	return o
}

func putRaw(t *testing.T, s *Store, key, value []byte) {
	t.Helper()
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketName).Put(key, value) }))
}
func deleteRaw(t *testing.T, s *Store, key []byte) {
	t.Helper()
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bucketName).Delete(key) }))
}
func readRawValue(t *testing.T, s *Store, key []byte) []byte {
	t.Helper()
	v := readRawValueOptional(t, s, key)
	require.NotNil(t, v)
	return v
}
func readRawValueOptional(t *testing.T, s *Store, key []byte) []byte {
	t.Helper()
	var out []byte
	require.NoError(t, s.db.View(func(tx *bolt.Tx) error { out = bytes.Clone(tx.Bucket(bucketName).Get(key)); return nil }))
	return out
}
