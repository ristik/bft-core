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
		// every junction of the tree is one of these, and every subtree below a split is one of these: a miscount of either breaks the identity
		require.Equal(t, s.Junctions+1, s.Opaque+s.New+s.OpenJunctions+s.OpenLeaves, "%+v", s)

		require.ErrorIs(t, verify(t, env, b.PreRoot(), next, tau+1), rsmt.ErrRootMismatch, "another reference time")
		other := next
		other[0] ^= 0xff
		require.ErrorIs(t, verify(t, env, b.PreRoot(), other, tau), rsmt.ErrRootMismatch, "another new root")
		require.ErrorIs(t, verify(t, env, other, next, tau), rsmt.ErrRootMismatch, "another old root")
	}
}

// The shape of the row posted on #886 (shard 9/0 of the default batch): the identity above does not catch an open leaf counted as opaque.
func TestPublishedRowStats(t *testing.T) {
	_, _, s, err := New("9/0", 0, 10_000, 1_000).Envelope(1000)
	require.NoError(t, err)
	require.Equal(t, Stats{PreLeaves: 10_000, Inserted: 1_000, EnvelopeLeaves: 1_000, Bytes: 212_480, Opaque: 2_091, New: 1_000, Junctions: 4_009, OpenJunctions: 222, OpenLeaves: 697}, s)
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

// A chain of batches: each Next starts from the root the last envelope certified, under the reference time it was certified at, and the next
// envelope verifies from there and not from the old pre-state.
func TestNextChainsFromTheCertifiedRoot(t *testing.T) {
	b := New("chain", 1, 1_000, 100)
	for i, tau := range []uint64{1000, 1007, 2000} {
		env, next, s, err := b.Envelope(tau)
		require.NoError(t, err)
		require.NoError(t, verify(t, env, b.PreRoot(), next, tau), "generation %d", i)
		require.Equal(t, 1_000+100*i, s.PreLeaves)
		n := b.Next(tau)
		require.Equal(t, next, n.PreRoot(), "generation %d: the next pre-state is the certified root", i)
		require.NotEqual(t, b.Next(tau+1).PreRoot(), n.PreRoot(), "the stored values depend on the reference time")
		nextEnv, nextRoot, _, err := n.Envelope(tau + 1)
		require.NoError(t, err)
		require.ErrorIs(t, verify(t, nextEnv, b.PreRoot(), nextRoot, tau+1), rsmt.ErrRootMismatch, "not from the old pre-state")
		b = n
	}
}
