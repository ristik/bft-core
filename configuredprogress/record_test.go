package configuredprogress

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
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

func TestFirstCertifiedRecordRequiresDecodedB0Predecessor(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	wrongParent := f.c.Blocks[0]
	wrongParent.Hash = common.HexToHash("0xdead")
	b := f.c.Executed(wrongParent, 1, 5)
	ir := &types.InputRecord{Version: 1, RoundNumber: 1, Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_001, BlockHash: b.Hash.Bytes()}
	o := f.observation(ir, 2, 5)
	op, _, err := s.PrepareObservation(context.Background(), f.ctx, o)
	require.NoError(t, err, "witnessless observation persists before B1 acquisition")
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	r := certifiedstore.Record{BlockHash: b.Hash, BlockNumber: 1, StateRoot: b.StateRoot, PartitionRound: 1, Certificate: o.Certificate(), Technical: o.TechnicalRecord(), Witness: b.Evidence}
	_, err = s.PrepareRecord(context.Background(), f.ctx, r)
	require.ErrorIs(t, err, ErrConflict)
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

func TestCorruptHeadNeverFallsBackToOlderRecord(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(3)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	for i := 1; i <= 2; i++ {
		var o rootinput.VerifiedObservationV2
		if i == 1 {
			o = f.first(1, 2, 5)
		} else {
			o = f.ordinary(2, 3, 6)
		}
		op, _, e := s.PrepareObservation(context.Background(), f.ctx, o)
		require.NoError(t, e)
		_, _, e = s.CommitObservation(op)
		require.NoError(t, e)
		rp, e := s.PrepareRecord(context.Background(), f.ctx, f.record(i, o))
		require.NoError(t, e)
		_, e = s.CommitRecord(rp)
		require.NoError(t, e)
	}
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		cp, e := decodeEnvelope(b.Get(controlKey), kindControl, MaxControlBytes)
		if e != nil {
			return e
		}
		var c controlWire
		if e = decodePayload(cp, &c); e != nil {
			return e
		}
		return b.Put(c.HeadKey, []byte{0x01})
	}))
	_, _, err = s.Load(context.Background(), f.ctx)
	require.Error(t, err, "older retained record is never selected")
}

func TestEquivalentRepeatDoesNotRewriteHeadRecord(t *testing.T) {
	f := newFixture(t, 1)
	s, _ := f.open(2)
	defer s.Close()
	_, _, err := s.Initialize(context.Background(), f.ctx)
	require.NoError(t, err)
	first := f.first(1, 2, 5)
	op, _, err := s.PrepareObservation(context.Background(), f.ctx, first)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	rp, err := s.PrepareRecord(context.Background(), f.ctx, f.record(1, first))
	require.NoError(t, err)
	_, err = s.CommitRecord(rp)
	require.NoError(t, err)
	var original []byte
	require.NoError(t, s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		original = bytes.Clone(b.Get(recordKey(1, f.c.Blocks[1].Hash)))
		return nil
	}))
	repeat := f.first(1, 3, 6)
	op, out, err := s.PrepareObservation(context.Background(), f.ctx, repeat)
	require.NoError(t, err)
	require.Equal(t, ObservationRepeated, out)
	_, _, err = s.CommitObservation(op)
	require.NoError(t, err)
	rp, err = s.PrepareRecord(context.Background(), f.ctx, f.record(1, repeat))
	require.NoError(t, err)
	_, err = s.CommitRecord(rp)
	require.NoError(t, err)
	var after []byte
	require.NoError(t, s.db.View(func(tx *bolt.Tx) error {
		after = bytes.Clone(tx.Bucket(bucketName).Get(recordKey(1, f.c.Blocks[1].Hash)))
		return nil
	}))
	require.Equal(t, original, after, "equivalent repeat evidence does not rewrite the retained block record")
}

func bucketKeys(s *Store) ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketName)
		return b.ForEach(func(k, v []byte) error { out = append(out, string(k)); return nil })
	})
	return out, err
}
