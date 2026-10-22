package archivepolicy

import (
	"errors"
	"math/rand"
	"sort"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

func ids(n int) []peer.ID {
	out := make([]peer.ID, n)
	for i := range out {
		out[i] = peer.ID([]byte{0x12, 0x20, byte(i + 1), byte(0xa0 + i)}) // distinct, ascending, raw bytes
	}
	return out
}

func shuffled(in []peer.ID, seed int64) []peer.ID {
	out := append([]peer.ID(nil), in...)
	rand.New(rand.NewSource(seed)).Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// The replicas are the next three validators after the writer in circular order of the sorted IDs, the writer excluded.
func TestSelectNextThreeAfterTheWriterCircular(t *testing.T) {
	v := ids(5) // v0..v4 ascending
	for writer, want := range map[int][]int{
		0: {1, 2, 3},
		1: {2, 3, 4},
		2: {3, 4, 0},
		3: {4, 0, 1},
		4: {0, 1, 2},
	} {
		p, err := Select(v[writer], v, 7)
		require.NoError(t, err)
		var got []peer.ID
		for _, i := range want {
			got = append(got, v[i])
		}
		sort.Slice(got, func(i, j int) bool { return string(got[i]) < string(got[j]) })
		require.Equal(t, got, p.Replicas, "writer v%d", writer)
		require.Equal(t, K, p.K)
		require.True(t, p.Tolerant())
		require.False(t, p.Eligible(v[writer]), "the writer never counts")
	}
}

// Selection does not depend on the order the membership is listed in, on duplicates, or on whether the writer is listed.
func TestSelectIsDeterministicUnderShuffleDuplicatesAndWriterListing(t *testing.T) {
	v := ids(6)
	want, err := Select(v[2], v, 3)
	require.NoError(t, err)
	for seed := int64(1); seed <= 20; seed++ {
		got, err := Select(v[2], shuffled(append(append([]peer.ID(nil), v...), v[0], v[4], v[2]), seed), 3)
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	// the writer not being a listed validator: selection starts at its place in circular order
	outsider := peer.ID([]byte{0x12, 0x20, 0x03, 0xff})
	p, err := Select(outsider, v, 3)
	require.NoError(t, err)
	require.Equal(t, []peer.ID{v[3], v[4], v[5]}, p.Replicas)
	require.NotEqual(t, want.Membership, MembershipDigest(append(v, outsider)), "the digest covers exactly the listed set")
}

func TestSelectByMembershipSize(t *testing.T) {
	v := ids(6)
	w := v[0]
	for others, tc := range map[int]struct {
		err      bool
		replicas int
		tolerant bool
	}{
		0: {err: true}, 1: {err: true}, 2: {replicas: 2}, 3: {replicas: 3, tolerant: true}, 4: {replicas: 3, tolerant: true}, 5: {replicas: 3, tolerant: true},
	} {
		p, err := Select(w, v[:others+1], 1)
		if tc.err {
			require.ErrorIs(t, err, ErrTooFewValidators, "%d others", others)
			continue
		}
		require.NoError(t, err, "%d others", others)
		require.Len(t, p.Replicas, tc.replicas)
		require.Equal(t, tc.tolerant, p.Tolerant(), "with exactly two others a single outage stops progress and K is never lowered")
		require.Equal(t, K, p.K)
	}
	_, err := Select(w, []peer.ID{w, w, w}, 1)
	require.ErrorIs(t, err, ErrTooFewValidators, "duplicates of the writer are not other validators")
	_, err = Select("", v, 1)
	require.ErrorIs(t, err, ErrInvalid)
}

// A different installed set or epoch is a different policy generation.
func TestPolicyDigestChangesWithEpochMembershipAndReplicas(t *testing.T) {
	v := ids(5)
	base, err := Select(v[0], v, 1)
	require.NoError(t, err)
	d0, err := base.Digest()
	require.NoError(t, err)
	for name, p := range map[string]func() (Policy, error){
		"epoch": func() (Policy, error) { return Select(v[0], v, 2) },
		"membership": func() (Policy, error) {
			return Select(v[0], append(append([]peer.ID(nil), v...), peer.ID([]byte{0x12, 0x20, 0x09, 0x01})), 1)
		},
		"writer": func() (Policy, error) { return Select(v[1], v, 1) },
	} {
		got, err := p()
		require.NoError(t, err, name)
		d, err := got.Digest()
		require.NoError(t, err)
		require.NotEqual(t, d0, d, name)
	}
	again, _ := Select(v[0], shuffled(v, 9), 1)
	d1, _ := again.Digest()
	require.Equal(t, d0, d1)
}

func TestMatchesConfiguredReplicas(t *testing.T) {
	v := ids(5)
	p, err := Select(v[0], v, 1)
	require.NoError(t, err)
	require.True(t, p.Matches([]peer.ID{v[3], v[1], v[2]}), "any order")
	require.False(t, p.Matches([]peer.ID{v[1], v[2]}), "two of three is not the policy")
	require.False(t, p.Matches([]peer.ID{v[1], v[2], v[4]}))
	require.False(t, p.Matches([]peer.ID{v[1], v[2], v[2]}))
	require.False(t, p.Matches([]peer.ID{v[1], v[2], v[3], v[4]}))
}

func TestEncodeDecodeRoundTripAndStrictness(t *testing.T) {
	v := ids(5)
	for _, n := range []int{3, 5} {
		p, err := Select(v[0], v[:n], 11)
		require.NoError(t, err)
		raw, err := p.Encode()
		require.NoError(t, err)
		got, err := Decode(raw)
		require.NoError(t, err)
		require.Equal(t, p, got)
	}
	p, _ := Select(v[0], v, 11)
	raw, _ := p.Encode()

	t.Run("every single-byte corruption is refused", func(t *testing.T) {
		for i := range raw {
			bad := append([]byte(nil), raw...)
			bad[i] ^= 0x01
			_, err := Decode(bad)
			require.Error(t, err, "byte %d", i)
		}
	})
	t.Run("truncation and extension are refused", func(t *testing.T) {
		for i := 0; i < len(raw); i++ {
			_, err := Decode(raw[:i])
			require.Error(t, err, "length %d", i)
		}
		_, err := Decode(append(append([]byte(nil), raw...), 0))
		require.Error(t, err)
	})
	t.Run("a version this code does not know", func(t *testing.T) {
		bad := append([]byte(nil), raw...)
		bad[len(domain)] = 2
		_, err := Decode(bad)
		require.True(t, errors.Is(err, ErrVersion) || errors.Is(err, ErrInvalid))
	})
	t.Run("an invalid policy is not encoded", func(t *testing.T) {
		for name, mutate := range map[string]func(*Policy){
			"k lowered":        func(p *Policy) { p.K = 1 },
			"self as replica":  func(p *Policy) { p.Replicas[0] = p.Writer },
			"one replica":      func(p *Policy) { p.Replicas = p.Replicas[:1] },
			"four replicas":    func(p *Policy) { p.Replicas = append(p.Replicas, peer.ID([]byte{0x12, 0x20, 0xff, 0xff})) },
			"unsorted":         func(p *Policy) { p.Replicas[0], p.Replicas[1] = p.Replicas[1], p.Replicas[0] },
			"duplicate":        func(p *Policy) { p.Replicas[1] = p.Replicas[0] },
			"empty replica id": func(p *Policy) { p.Replicas[2] = "" },
		} {
			q, _ := Select(v[0], v, 1)
			q.Replicas = append([]peer.ID(nil), q.Replicas...)
			mutate(&q)
			_, err := q.Encode()
			require.Error(t, err, name)
		}
	})
}
