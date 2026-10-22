package rootinput

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type recordingMemo struct {
	mu        sync.Mutex
	seen      map[[32]byte]struct{}
	remembers int
	hits      int
}

func (m *recordingMemo) Verified(key [32]byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.seen[key]
	if ok {
		m.hits++
	}
	return ok
}

func (m *recordingMemo) Remember(key [32]byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen == nil {
		m.seen = map[[32]byte]struct{}{}
	}
	m.seen[key] = struct{}{}
	m.remembers++
}

// bft-core#728: the memo skips a certificate signature verification only for the same certificate, the same trust base CONTENT, partition, shard and
// configuration hash; it remembers only successes; and it never replaces the other checks of the authentication.
func TestVerifyMemoKeyedByEverythingTheVerificationReads(t *testing.T) {
	f := newV2Fixture(t)
	_, uc := f.signed(t, &types.InputRecord{Version: 1}, 7, 4)
	tr := certifiedchain.Technical(6)
	tr.Round = 7

	memo := &recordingMemo{}
	ctx := f.obsContext()
	ctx.VerifyMemo = memo
	_, err := AuthenticateHistoricalObservationV2(context.Background(), ctx, uc, tr)
	require.NoError(t, err)
	require.Equal(t, 1, memo.remembers, "the first success is remembered")
	_, err = AuthenticateHistoricalObservationV2(context.Background(), ctx, uc, tr)
	require.NoError(t, err)
	require.Equal(t, 1, memo.remembers)
	require.Equal(t, 1, memo.hits, "and the second is answered from the memo")

	t.Run("a different shard configuration hash misses and fails", func(t *testing.T) {
		beforeHits, beforeRemembers := memo.hits, memo.remembers
		other := ctx
		other.ShardConfHash = append([]byte(nil), ctx.ShardConfHash...)
		other.ShardConfHash[0] ^= 0xff
		_, err := AuthenticateHistoricalObservationV2(context.Background(), other, uc, tr)
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.Equal(t, beforeHits, memo.hits, "no hit")
		require.Equal(t, beforeRemembers, memo.remembers, "and a failure is never remembered")
	})
	t.Run("a configuration installed for the shard epoch is part of the key", func(t *testing.T) {
		before := memo.hits
		other := ctx
		other.ConfForEpoch = func(uint64) ([]byte, bool) { return bytesOf(0x42, 32), true }
		_, err := AuthenticateHistoricalObservationV2(context.Background(), other, uc, tr)
		require.ErrorIs(t, err, ErrUnauthenticated)
		require.Equal(t, before, memo.hits)
	})
	t.Run("a trust base with different content at the same epoch misses and fails", func(t *testing.T) {
		signer, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		otherTB, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
		require.True(t, ok)
		before := memo.hits
		other := ctx
		other.TrustBases = stubTrustBases{tb: otherTB}
		_, err = AuthenticateHistoricalObservationV2(context.Background(), other, uc, tr)
		require.Error(t, err)
		require.Equal(t, before, memo.hits)
	})
	t.Run("an equal trust base held by another pointer hits (content, not identity)", func(t *testing.T) {
		before := memo.hits
		clone := *f.c.TrustBase
		other := ctx
		other.TrustBases = stubTrustBases{tb: &clone}
		_, err := AuthenticateHistoricalObservationV2(context.Background(), other, uc, tr)
		require.NoError(t, err)
		require.Equal(t, before+1, memo.hits)
	})
	t.Run("a different partition misses", func(t *testing.T) {
		before := memo.hits
		other := ctx
		other.PartitionID++
		_, err := AuthenticateHistoricalObservationV2(context.Background(), other, uc, tr)
		require.Error(t, err)
		require.Equal(t, before, memo.hits)
	})
	t.Run("the checks the memo does not cover still run on a hit", func(t *testing.T) {
		other := ctx
		other.NetworkID++ // the signature verification is unchanged and memoized; the network check is not
		_, err := AuthenticateHistoricalObservationV2(context.Background(), other, uc, tr)
		require.ErrorIs(t, err, ErrWrongContext)
		other = ctx
		other.EpochAuthority = &testEpochAuthority{epoch: 0, ready: false}
		_, err = AuthenticateHistoricalObservationV2(context.Background(), other, uc, tr)
		require.Error(t, err, "an epoch authority that is not ready refuses even a memoized certificate")
	})
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func TestVerifyMemoKeyChangesWithEachInput(t *testing.T) {
	f := newV2Fixture(t)
	_, uc := f.signed(t, &types.InputRecord{Version: 1}, 7, 4)
	base, ok := certificateVerificationKey(uc, f.c.TrustBase, 8, types.ShardID{}, bytesOf(1, 32))
	require.True(t, ok)
	same, _ := certificateVerificationKey(uc, f.c.TrustBase, 8, types.ShardID{}, bytesOf(1, 32))
	require.Equal(t, base, same)
	for name, mutate := range map[string]func() ([32]byte, bool){
		"shard": func() ([32]byte, bool) {
			var shard types.ShardID
			require.NoError(t, shard.UnmarshalText([]byte("0xc0")))
			return certificateVerificationKey(uc, f.c.TrustBase, 8, shard, bytesOf(1, 32))
		},
		"conf": func() ([32]byte, bool) {
			return certificateVerificationKey(uc, f.c.TrustBase, 8, types.ShardID{}, bytesOf(2, 32))
		},
		"partition": func() ([32]byte, bool) {
			return certificateVerificationKey(uc, f.c.TrustBase, 9, types.ShardID{}, bytesOf(1, 32))
		},
		"trust base": func() ([32]byte, bool) {
			tb := *f.c.TrustBase
			tb.Epoch++
			return certificateVerificationKey(uc, &tb, 8, types.ShardID{}, bytesOf(1, 32))
		},
		"certificate": func() ([32]byte, bool) {
			u := *uc
			seal := *uc.UnicitySeal
			seal.RootChainRoundNumber++
			u.UnicitySeal = &seal
			return certificateVerificationKey(&u, f.c.TrustBase, 8, types.ShardID{}, bytesOf(1, 32))
		},
	} {
		got, ok := mutate()
		require.True(t, ok, name)
		require.NotEqual(t, base, got, "the key must change with the %s", name)
	}
}
