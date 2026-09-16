package configuredprogress

import (
	"bytes"
	"context"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
	bolt "go.etcd.io/bbolt"
)

func TestReviewControlCanonicalRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, []byte) []byte
	}{
		{"nonminimal revision", func(t *testing.T, p []byte) []byte {
			require.Len(t, p, 40)
			require.Equal(t, byte(0x86), p[0])
			require.Equal(t, byte(0x00), p[36])
			return append(append(append([]byte{}, p[:36]...), 0x18, 0x00), p[37:]...)
		}},
		{"indefinite array", func(t *testing.T, p []byte) []byte {
			require.Equal(t, byte(0x86), p[0])
			return append(append([]byte{0x9f}, p[1:]...), 0xff)
		}},
		{"trailing field", func(t *testing.T, p []byte) []byte {
			require.Equal(t, byte(0x86), p[0])
			return append(append([]byte{0x87}, p[1:]...), 0xf6)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t, 1)
			s, _ := f.open(2)
			defer s.Close()
			_, _, err := s.Initialize(context.Background(), f.ctx)
			require.NoError(t, err)
			raw := readBucketValue(t, s, controlKey)
			payload, err := decodeEnvelope(raw, kindControl, MaxControlBytes)
			require.NoError(t, err)
			writeControlPayload(t, s, tc.mutate(t, payload))

			_, _, err = s.Load(context.Background(), f.ctx)
			require.ErrorIs(t, err, ErrUntrusted)
		})
	}
}

func TestReviewControlSemanticRefusals(t *testing.T) {
	for _, name := range []string{"ordinary observed without first", "bootstrap first", "ordinary first with bootstrap observed", "wrong descriptor digest"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, 1)
			s, _ := f.open(2)
			defer s.Close()
			st, _, err := s.Initialize(context.Background(), f.ctx)
			require.NoError(t, err)
			cw := st.i.control
			cw.Revision = 1
			bootstrap, _, err := pairFromObservation(f.bootstrap(1, 4))
			require.NoError(t, err)
			ordinary, _, err := pairFromObservation(f.first(1, 2, 5))
			require.NoError(t, err)
			switch name {
			case "ordinary observed without first":
				cw.Observed = &ordinary
			case "bootstrap first":
				cw.First, cw.Observed = &bootstrap, &ordinary
			case "ordinary first with bootstrap observed":
				cw.First, cw.Observed = &ordinary, &bootstrap
			case "wrong descriptor digest":
				cw.Revision = 0
				cw.DescriptorDigest = bytes.Repeat([]byte{0xcc}, 32)
			}
			payload, err := marshal(cw)
			require.NoError(t, err)
			writeControlPayload(t, s, payload)

			_, _, err = s.Load(context.Background(), f.ctx)
			if name == "wrong descriptor digest" {
				require.ErrorIs(t, err, ErrContext)
			} else {
				require.ErrorIs(t, err, ErrUntrusted)
			}
		})
	}
}

func TestReviewRevisionOverflow(t *testing.T) {
	f := newFixture(t, 2)
	s, _ := f.open(2)
	defer s.Close()
	installObserved(t, s, f, f.first(1, 2, 5))
	st, _, err := s.Load(context.Background(), f.ctx)
	require.NoError(t, err)
	cw := st.i.control
	cw.Revision = math.MaxUint64
	payload, err := marshal(cw)
	require.NoError(t, err)
	writeControlPayload(t, s, payload)
	_, _, err = s.Load(context.Background(), f.ctx)
	require.NoError(t, err, "maximum revision remains a valid durable image")

	_, _, err = s.PrepareObservation(context.Background(), f.ctx, f.ordinary(2, 3, 6))
	require.ErrorIs(t, err, ErrBounds)
}

func TestReviewTokenAndCASDetectIndependentByteChanges(t *testing.T) {
	t.Run("descriptor only", func(t *testing.T) {
		f := newFixture(t, 1)
		s, _ := f.open(2)
		defer s.Close()
		_, token, err := s.Initialize(context.Background(), f.ctx)
		require.NoError(t, err)
		prepared, _, err := s.PrepareObservation(context.Background(), f.ctx, f.first(1, 2, 5))
		require.NoError(t, err)
		flipBucketValue(t, s, descriptorKey)
		require.False(t, s.Unchanged(token))
		_, _, err = s.CommitObservation(prepared)
		require.ErrorIs(t, err, ErrStale)
	})

	t.Run("head content only", func(t *testing.T) {
		f := newFixture(t, 1)
		s, _ := f.open(2)
		defer s.Close()
		o := f.first(1, 2, 5)
		installObserved(t, s, f, o)
		prepared, err := s.PrepareRecord(context.Background(), f.ctx, f.record(1, o))
		require.NoError(t, err)
		_, err = s.CommitRecord(prepared)
		require.NoError(t, err)
		_, token, err := s.Load(context.Background(), f.ctx)
		require.NoError(t, err)
		noOp, err := s.PrepareRecord(context.Background(), f.ctx, f.record(1, o))
		require.NoError(t, err)
		head := token.t.headName
		require.NotEmpty(t, head)
		flipBucketValue(t, s, head)
		require.False(t, s.Unchanged(token))
		_, err = s.CommitRecord(noOp)
		require.ErrorIs(t, err, ErrStale)
	})
}

func readBucketValue(t *testing.T, s *Store, key []byte) []byte {
	t.Helper()
	var out []byte
	require.NoError(t, s.db.View(func(tx *bolt.Tx) error {
		out = bytes.Clone(tx.Bucket(bucketName).Get(key))
		return nil
	}))
	require.NotEmpty(t, out)
	return out
}

func writeControlPayload(t *testing.T, s *Store, payload []byte) {
	t.Helper()
	raw, err := encodeEnvelope(kindControl, payload, MaxControlBytes)
	require.NoError(t, err)
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put(controlKey, raw)
	}))
}

func flipBucketValue(t *testing.T, s *Store, key []byte) {
	t.Helper()
	raw := readBucketValue(t, s, key)
	raw[len(raw)-1] ^= 0x01
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketName).Put(key, raw)
	}))
}
