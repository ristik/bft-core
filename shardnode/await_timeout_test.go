package shardnode

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

/*
TestAwaitTimeoutForT2 pins the one property the value exists for: it is always shorter than the
shard's T2.

The failure it prevents is not a lost round, it is a lost validator. A follower waits for the
leader's block synchronously, so the await budget bounds how fast it can consume certificates; the
root chain issues one per T2 while a shard is not reaching quorum. A budget at or above T2 therefore
means the node falls further behind on every round rather than abstaining from one — measured at
T2=3s against the 5s default, where a validator accepted exactly one certificate every 5.00s and
never recovered while its leader stayed silent.
*/
func TestAwaitTimeoutForT2(t *testing.T) {
	for _, tc := range []struct {
		name string
		t2   time.Duration
		want time.Duration
	}{
		{"test-lane T2, halved", 5 * time.Second, 2500 * time.Millisecond},
		{"historical 3s reproduction", 3 * time.Second, 1500 * time.Millisecond},
		{"a long T2 is capped at the default rather than scaling with it", time.Minute, DefaultAwaitTimeout},
		{"a very short T2 is floored so a punctual leader is not abstained from", 100 * time.Millisecond, MinAwaitTimeout},
		{"an unset T2 falls back to the default", 0, DefaultAwaitTimeout},
		{"a negative T2 is treated as unset, not as an instant timeout", -time.Second, DefaultAwaitTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, AwaitTimeoutForT2(tc.t2))
		})
	}

	t.Run("shorter than T2 across the range that matters", func(t *testing.T) {
		// The floor can exceed T2 for a T2 below 400ms — a configuration no shard uses and one
		// where the leader could not publish in time anyway. Everything above it must hold the
		// property, so the property is asserted rather than left to the table above.
		for t2 := 400 * time.Millisecond; t2 <= 30*time.Second; t2 += 100 * time.Millisecond {
			require.Less(t, AwaitTimeoutForT2(t2), t2,
				"await budget must be shorter than T2 at T2=%s", t2)
		}
	})
}
