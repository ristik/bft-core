package rootinput

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

// countingTrustBases counts the trust-base lookups an authentication performs.
type countingTrustBases struct {
	inner TrustBases
	calls *int
}

func (c countingTrustBases) GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	*c.calls++
	return c.inner.GetByEpoch(ctx, epoch)
}

// X1 row X-48 (#12 acceptance): importing a block is bounded by the block's own input and the one validator
// set it names, not by the number of skipped root rounds or by every assignment installed before it. The
// verifier holds `history` installed shard configurations; the certificate arrives after `gap` skipped root
// rounds. Whatever the two are, authenticating and deriving costs one trust-base lookup, one configuration
// lookup and the same number of allocations. The comparison is of operation counts and allocations, never time.
func TestImportWorkDoesNotGrowWithSkippedRoundsOrInstalledHistory(t *testing.T) {
	f := newAssignmentFixture(t)
	p := f.blocks[1]
	snap := f.snapshot(t, p, registryproof.Assignment{})
	ir := f.irAt(p, f.blocks[0], 0)
	tr := technicalAt(0, 11)

	type measure struct {
		trustLookups, confLookups int
		allocs                    float64
	}
	run := func(t *testing.T, history int, gap uint64) measure {
		installed := map[uint64][32]byte{0: f.hash[0]}
		for e := 1; e < history; e++ {
			var h [32]byte
			h[0], h[1], h[2] = byte(e), byte(e>>8), 0xee
			installed[uint64(e)] = h
		}
		var m measure
		obs := f.obsContext(1)
		obs.TrustBases = countingTrustBases{inner: obs.TrustBases, calls: &m.trustLookups}
		obs.ConfForEpoch = func(epoch uint64) ([]byte, bool) {
			m.confLookups++
			h, ok := installed[epoch]
			return bytes.Clone(h[:]), ok
		}
		uc := f.certify(t, f.pdr[0], ir, tr, 12+gap, 1)
		once := func() {
			o, err := AuthenticateObservationV2(context.Background(), obs, uc, tr)
			require.NoError(t, err)
			_, err = f.derive(t, p, snap, 11, o, nil)
			require.NoError(t, err)
		}
		once()
		m.allocs = testing.AllocsPerRun(20, func() { m.trustLookups, m.confLookups = 0, 0; once() })
		return m
	}

	base := run(t, 1, 0)
	require.Equal(t, 1, base.trustLookups, "one trust-base lookup: the certificate's own root epoch")
	require.Equal(t, 1, base.confLookups, "one configuration lookup: the shard epoch its technical record names")
	for _, tc := range []struct {
		name    string
		history int
		gap     uint64
		slack   float64 // a larger round number encodes into a wider integer: a few allocations, constant in the gap
	}{
		{"a long installed history", 4096, 0, 2},
		{"a million skipped root rounds", 1, 1_000_000, 8},
		{"a billion skipped root rounds", 1, 1_000_000_000, 8},
		{"both", 4096, 1_000_000_000, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := run(t, tc.history, tc.gap)
			require.Equal(t, base.trustLookups, got.trustLookups)
			require.Equal(t, base.confLookups, got.confLookups)
			if tc.gap == 1_000_000_000 && tc.history == 1 {
				million := run(t, 1, 1_000_000)
				require.InDelta(t, million.allocs, got.allocs, 4, "a thousand times the gap costs the same")
			}
			require.InDelta(t, base.allocs, got.allocs, tc.slack, "allocations per import must not depend on history or the gap")
		})
	}
}
