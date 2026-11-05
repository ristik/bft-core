package rsmtbatch

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier/rsmt"
)

func verify(t *testing.T, env []byte, old, next [32]byte, tau uint64) error {
	t.Helper()
	decoded, err := rsmt.DecodeEnvelope(env)
	require.NoError(t, err)
	return rsmt.Verify(decoded, rsmt.Root{Hash: old, Set: true}, rsmt.Root{Hash: next, Set: true}, tau)
}

// The verifier accepts what this builds, at any size and in either half of the key space, and only for its own roots and reference time.
func TestEnvelopesVerify(t *testing.T) {
	const tau = 1000
	for _, c := range []struct {
		keyBit, pre, inserted int
	}{{-1, 1, 1}, {-1, 2, 1}, {-1, 1, 2}, {0, 10, 10}, {1, 100, 7}, {-1, 7, 100}, {0, 10_000, 1_000}, {1, 10_000, 1_000}, {-1, 10_000, 1_000}} {
		b := New("seed", c.keyBit, c.pre, c.inserted)
		env, next, s, err := b.Envelope(tau)
		require.NoError(t, err)
		require.NoError(t, verify(t, env, b.PreRoot(), next, tau), "%+v", c)
		require.Equal(t, c.pre, s.PreLeaves)
		require.Equal(t, c.inserted, s.Inserted)
		require.Equal(t, c.inserted, s.EnvelopeLeaves)
		require.Equal(t, c.inserted, s.New)
		require.Equal(t, len(env), s.Bytes)

		require.ErrorIs(t, verify(t, env, b.PreRoot(), next, tau+1), rsmt.ErrRootMismatch, "another reference time")
		other := next
		other[0] ^= 0xff
		require.ErrorIs(t, verify(t, env, b.PreRoot(), other, tau), rsmt.ErrRootMismatch, "another new root")
		require.ErrorIs(t, verify(t, env, other, next, tau), rsmt.ErrRootMismatch, "another old root")
	}
}

func TestKeysAreDistinctAndInTheirHalf(t *testing.T) {
	for bit := range 2 {
		b := New("seed", bit, 1_000, 1_000)
		seen := map[[32]byte]bool{}
		for _, l := range append(b.pre, b.fresh...) {
			require.False(t, seen[l.key])
			seen[l.key] = true
			require.Equal(t, byte(bit), rsmt.KeyBitAt(l.key, 0))
		}
	}
}

// The default-batch row's populated tree makes the proof mostly opaque preserved subtrees, with the leaf and junction count of the batch.
func TestDefaultBatchShape(t *testing.T) {
	_, _, s, err := New("seed", 0, 10_000, 1_000).Envelope(1000)
	require.NoError(t, err)
	require.Equal(t, 1_000, s.New)
	require.Greater(t, s.Opaque, 500)
	t.Logf("%+v", s)
}
