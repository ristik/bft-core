package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// bft-core#1167: the doctor's block-interval check is the rule `shard-node run` refuses to start on, and its fix names a T2 that passes.
func TestDoctorBlockIntervalCheck(t *testing.T) {
	const rbr = 900 * time.Millisecond
	ok, detail, _ := blockIntervalCheck(0, 5*time.Second, rbr)
	require.True(t, ok, detail)

	ok, detail, _ = blockIntervalCheck(10*time.Second, 20*time.Second, rbr)
	require.True(t, ok, detail)

	ok, detail, fix := blockIntervalCheck(10*time.Second, 5*time.Second, rbr)
	require.False(t, ok)
	require.Contains(t, detail, "needs a shard T2 of at least 15.9s")
	require.Contains(t, fix, "--t2-timeout of at least 15900")
	ok, _, _ = blockIntervalCheck(10*time.Second, 15900*time.Millisecond, rbr)
	require.True(t, ok, "the T2 the fix names passes")
}
