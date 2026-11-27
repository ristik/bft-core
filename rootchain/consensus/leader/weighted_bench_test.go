package leader

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/weightcap"
)

// §49: the cost of building the weighted selector at the committee sizes the native format now allows. The construction is O(period*n) with
// period <= B = 65,536; the table is at most B bytes. Rows: 128 and 256 members at unit weights (period n, the usual PoA case) and the worst
// total (B, gcd 1, period B). A lookup is O(1) and allocation free (see the Q4 gate).
//
//	go test ./rootchain/consensus/leader -run xxx -bench BenchmarkNewWeightedAtScale -benchmem
func BenchmarkNewWeightedAtScale(b *testing.B) {
	for _, in := range []q4Input{
		{"n=128 unit", q4Equal(128, 1)},
		{"n=256 unit", q4Equal(256, 1)},
		{"n=128 worst total", q4WorstTotal(128)},
		{"n=256 worst total", q4WorstTotal(256)},
	} {
		nodes := q4Members(b, in.weights)
		b.Run(in.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				w, err := NewWeighted(1, nodes)
				if err != nil {
					b.Fatal(err)
				}
				_ = w
			}
		})
	}
}

// The inputs of the benchmark are what they claim: totals, gcd and periods.
func TestTheAtScaleBenchmarkInputsAreTheWorstCases(t *testing.T) {
	for _, tc := range []struct {
		n      int
		worst  bool
		period uint64
	}{{128, false, 128}, {256, false, 256}, {128, true, weightcap.B}, {256, true, weightcap.B}} {
		var ws []uint64
		if tc.worst {
			ws = q4WorstTotal(tc.n)
		} else {
			ws = q4Equal(tc.n, 1)
		}
		w, err := NewWeighted(1, q4Members(t, ws))
		require.NoError(t, err, fmt.Sprintf("%+v", tc))
		require.EqualValues(t, tc.period, w.Period(), fmt.Sprintf("%+v", tc))
	}
	// every one of the 256 indices (0..255, the whole uint8 range) leads exactly once in a period of unit weights
	w, err := NewWeighted(1, q4Members(t, q4Equal(256, 1)))
	require.NoError(t, err)
	seen := map[uint8]int{}
	for _, idx := range w.table {
		seen[idx]++
	}
	require.Len(t, seen, 256)
	for idx, n := range seen {
		require.Equal(t, 1, n, "index %d", idx)
	}
	// 256 is the bound: one more is refused
	_, err = NewWeighted(1, q4Members(t, q4Equal(257, 1)))
	require.ErrorIs(t, err, ErrTooManyMembers)
}
