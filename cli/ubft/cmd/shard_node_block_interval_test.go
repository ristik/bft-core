package cmd

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// bft-core#1167: the doctor's block-interval check is the rule `shard-node run` refuses to start on, and its fix names a T2 that passes.
func TestDoctorBlockIntervalCheck(t *testing.T) {
	const rbr = 900 * time.Millisecond
	ok, detail, _ := blockIntervalCheck(0, 5*time.Second, rbr, 30*time.Second)
	require.True(t, ok, detail)

	ok, detail, fix := blockIntervalCheck(10*time.Second, 20*time.Second, rbr, 30*time.Second)
	require.True(t, ok, detail)
	require.Empty(t, fix, "the testnet's 10 s interval leaves 14.1 s below the 30 s inactivity timeout: no warning")

	ok, detail, fix = blockIntervalCheck(10*time.Second, 5*time.Second, rbr, 30*time.Second)
	require.False(t, ok)
	require.Contains(t, detail, "needs a shard T2 of at least 15.9s")
	require.Contains(t, fix, "--t2-timeout of at least 15900")
	ok, _, _ = blockIntervalCheck(10*time.Second, 15900*time.Millisecond, rbr, 30*time.Second)
	require.True(t, ok, "the T2 the fix names passes")

	// a longer interval passes T2 but comes within 10 s of the inactivity re-handshake: a warning (ok, with a fix), not a failure
	ok, detail, fix = blockIntervalCheck(15*time.Second, 30*time.Second, rbr, 30*time.Second)
	require.True(t, ok, detail)
	require.Contains(t, detail, "below the 30s inactivity timeout")
	require.Contains(t, fix, "--inactivity-timeout of at least 30.9s")
	ok, _, fix = blockIntervalCheck(15*time.Second, 30*time.Second, rbr, 31*time.Second)
	require.True(t, ok)
	require.Empty(t, fix, "the timeout the fix names clears the warning")
}
