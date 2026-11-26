package vrschedule

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The expiry readyBitmap (#1311) is presence only: bit i for the i-th successor (ascending staking id) whose verified possession proof
// the root holds for the current intent over the result; zero for another result or with no current intent.
func TestPresenceIsTheHeldProofsOfTheCurrentIntent(t *testing.T) {
	w := newWorld(t)
	s := w.service("x")
	require.Zero(t, s.Presence([32]byte(w.R)), "no current intent")
	s.Update(w.committed(0))
	require.Zero(t, s.Presence([32]byte(w.R)), "no proof held")

	pops := w.PoPs(w.in)
	require.GreaterOrEqual(t, len(pops), 2)
	// every proof but the first successor's
	var want uint16
	for i, m := range w.J {
		for k := range pops {
			if pops[k].EVMNodeID != m.EVMNodeID || i == 0 {
				continue
			}
			o, _, err := s.Offer("peer", Message{PoP: &pops[k]})
			require.NoError(t, err)
			require.Equal(t, Retained, o)
			want |= 1 << i
		}
	}
	require.NotZero(t, want)
	require.Equal(t, want, s.Presence([32]byte(w.R)))
	require.Zero(t, want&1, "the missing successor's bit is clear")
	require.Zero(t, s.Presence([32]byte{0x42}), "another result")
}
