package configuredprogress

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/parentwitness"
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

func TestHashReaderProviderWireIntegration(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	publishIndexed(t, s, f, 1)
	reader, err := s.BindHashReader(f.ctx)
	require.NoError(t, err)
	pc := f.origin.ProofContext()
	target, err := parentwitness.NewTarget(parentwitness.TargetConfig{NetworkID: 3, PartitionID: 8, ShardID: f.ctx.Observation.ShardID, FullShardConfHash: f.origin.FullShardConfHash(), Registry: pc, BlockHash: f.c.Blocks[1].Hash})
	require.NoError(t, err)
	provider, err := parentwitness.NewProvider(target, reader)
	require.NoError(t, err)
	resp, err := provider.Serve(context.Background(), target.Request())
	require.NoError(t, err)
	require.Equal(t, parentwitness.OutcomeFound, resp.Outcome)
	raw, err := parentwitness.EncodeResponse(resp)
	require.NoError(t, err)
	verified, err := parentwitness.VerifyResponse(target, raw)
	require.NoError(t, err)
	require.True(t, verified.Found())
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

func TestHashIndexRejectsCandidateNewerThanPublishedHead(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(3)
	defer s.Close()
	publishIndexed(t, s, f, 1)
	o2 := f.ordinary(2, 3, 6)
	op, _, err := s.PrepareObservation(context.Background(), f.ctx, o2)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	key, raw, _, _, err := encodeOuterRecord(context.Background(), f.ctx, st.i.descriptorDigest, f.record(2, o2))
	require.NoError(t, err)
	idx, _ := encodeHashIndex(key)
	putRaw(t, s, key, raw)
	putRaw(t, s, hashIndexKey(f.c.Blocks[2].Hash), idx)
	_, err = s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[2].Hash)
	require.ErrorContains(t, err, "newer/conflicting with head")
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

func TestHashIndexRetentionRollbackAndReopen(t *testing.T) {
	f := newFixture(t, 2)
	s, path := f.open(1)
	publishIndexed(t, s, f, 1)
	o2 := f.ordinary(2, 3, 6)
	op, _, _ := s.PrepareObservation(context.Background(), f.ctx, o2)
	_, _, _ = s.CommitObservation(op)
	rp, err := s.PrepareRecord(context.Background(), f.ctx, f.record(2, o2))
	require.NoError(t, err)
	s.checkpoint = func(name string) error {
		if name == "after-retention-delete" {
			return errors.New("cut")
		}
		return nil
	}
	_, err = s.CommitRecord(rp)
	require.Error(t, err)
	s.checkpoint = nil
	require.NotNil(t, readRawValueOptional(t, s, recordKey(f.c.Blocks[1].Round, f.c.Blocks[1].Hash)))
	require.NotNil(t, readRawValueOptional(t, s, hashIndexKey(f.c.Blocks[1].Hash)))
	require.Nil(t, readRawValueOptional(t, s, recordKey(f.c.Blocks[2].Round, f.c.Blocks[2].Hash)))
	require.Nil(t, readRawValueOptional(t, s, hashIndexKey(f.c.Blocks[2].Hash)))
	require.NoError(t, s.Close())
	s, err = OpenConfiguredV2(path, Settings{Retain: 1})
	require.NoError(t, err)
	defer s.Close()
	_, err = s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[1].Hash)
	require.NoError(t, err)
}

func TestLoadedEvidenceSurvivesEviction(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(1)
	defer s.Close()
	publishIndexed(t, s, f, 1)
	loaded, err := s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[1].Hash)
	require.NoError(t, err)
	before := loaded.Witness()
	publishIndexed(t, s, f, 2)
	_, err = s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[1].Hash)
	require.ErrorIs(t, err, ErrUnavailable)
	require.Equal(t, before.Header, loaded.Witness().Header)
}

func TestHashIndexMetadataAndCandidateRefusals(t *testing.T) {
	for name, mutate := range map[string]func(*testing.T, *Store, *fixture){
		"descriptor oversized": func(t *testing.T, s *Store, f *fixture) {
			putRaw(t, s, descriptorKey, make([]byte, MaxDescriptorBytes+1))
		},
		"locator oversized": func(t *testing.T, s *Store, f *fixture) {
			putRaw(t, s, hashIndexKey(f.c.Blocks[1].Hash), make([]byte, MaxHashIndexValueBytes+1))
		},
		"candidate oversized": func(t *testing.T, s *Store, f *fixture) {
			putRaw(t, s, recordKey(f.c.Blocks[1].Round, f.c.Blocks[1].Hash), make([]byte, MaxOuterRecordBytes+1))
		},
		"head missing": func(t *testing.T, s *Store, f *fixture) {
			deleteRaw(t, s, recordKey(f.c.Blocks[1].Round, f.c.Blocks[1].Hash))
		},
		"wrong round key": func(t *testing.T, s *Store, f *fixture) {
			old := recordKey(f.c.Blocks[1].Round, f.c.Blocks[1].Hash)
			forged := recordKey(f.c.Blocks[1].Round+9, f.c.Blocks[1].Hash)
			putRaw(t, s, forged, readRawValue(t, s, old))
			idx, _ := encodeHashIndex(forged)
			putRaw(t, s, hashIndexKey(f.c.Blocks[1].Hash), idx)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1)
			s, _ := f.open(2)
			defer s.Close()
			publishIndexed(t, s, f, 1)
			mutate(t, s, f)
			_, err := s.ReadByHash(context.Background(), f.ctx, f.c.Blocks[1].Hash)
			require.Error(t, err)
		})
	}
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	publishIndexed(t, s, f, 1)
	bad := f.ctx
	bad.Observation.NetworkID++
	_, err := s.ReadByHash(context.Background(), bad, f.c.Blocks[1].Hash)
	require.Error(t, err)
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
