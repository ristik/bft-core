package q3format_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3format"
)

// Evidence row 5c, root side: the per-block projection of the authenticated history (B1EntriesFrom) costs the same at 7, 60 and 4000 permanent
// epochs when it asks for the same suffix, and returns exactly what the full projection holds for those epochs.
func TestB1EntriesFromIsConstantInTheLengthOfThePermanentHistory(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	s := q3fixture.New(t, q3fixture.Options{After: f})
	base, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	base, err = base.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	base, err = base.VerifyEnvelope(s.Envelope)
	require.NoError(t, err)

	const suffix = 2 // the imported tip and the one epoch an acknowledgement block installs after it
	allocs := map[int]float64{}
	for _, n := range []int{7, 60, 4000} {
		t.Run(fmt.Sprintf("%d epochs", n), func(t *testing.T) {
			h := q3format.Synthesize(base, n-3)
			origin := uint64(1) << 40
			from := uint64(n - 1) // the epoch numbers start at 1: the last `suffix` epochs are n-1 and n
			got, err := h.B1EntriesFrom(origin, from)
			require.NoError(t, err)
			require.Len(t, got, suffix)
			require.EqualValues(t, from, got[0].Epoch)
			require.EqualValues(t, from+1, got[1].Epoch)
			if n <= 60 { // the full projection (it validates every epoch: kept to the sizes where that is cheap) agrees on the same epochs
				all, err := h.B1Entries(origin)
				require.NoError(t, err)
				require.Len(t, all, n)
				require.Equal(t, all[n-suffix:], got)
			}
			allocs[n] = testing.AllocsPerRun(20, func() {
				if _, err := h.B1EntriesFrom(origin, from); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
	// the cost does not grow with the history: the allocation count is the same at every size
	require.Equal(t, allocs[7], allocs[60])
	require.Equal(t, allocs[7], allocs[4000])

	// refusals
	_, err = base.B1EntriesFrom(1<<40, 0)
	require.ErrorIs(t, err, q3format.ErrHistory, "an epoch below the first")
	_, err = base.B1EntriesFrom(1<<40, 99)
	require.ErrorIs(t, err, q3format.ErrUnknownEpoch, "an epoch beyond the last")
	_, err = base.B1EntriesFrom(0, 2)
	require.ErrorIs(t, err, q3format.ErrUnknownEpoch, "an origin before the requested epoch started")
}
