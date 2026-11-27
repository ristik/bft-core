package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
)

// TestRootNodeRunChecksTheTargetBlockIntervalAtEntry (review #1172, sol 3): the command refuses an explicit 0 and anything under 100 ms
// or at LocalTimeout/2 before anything else runs (the bad operator source below would otherwise be the first refusal), and passes the
// 450 ms default on.
func TestRootNodeRunChecksTheTargetBlockIntervalAtEntry(t *testing.T) {
	run := func(args ...string) error {
		cmd := rootNodeRunCmd(&baseFlags{})
		cmd.SetArgs(append(args, "--operator-allowed-sources=banana"))
		cmd.SilenceUsage, cmd.SilenceErrors = true, true
		return cmd.Execute()
	}
	for _, v := range []string{"0", "0s", "99ms", "5s"} {
		err := run("--target-block-interval=" + v)
		require.ErrorIs(t, err, consensus.ErrTargetBlockInterval, v)
		require.ErrorContains(t, err, "--target-block-interval", v)
	}
	for _, args := range [][]string{nil, {"--target-block-interval=100ms"}, {"--target-block-interval=4999ms"}} {
		err := run(args...)
		require.NotErrorIs(t, err, consensus.ErrTargetBlockInterval, args)
		require.ErrorContains(t, err, "operator-allowed-sources", "the next entry check refuses: the target passed")
	}
	require.Equal(t, "450ms", rootNodeRunCmd(&baseFlags{}).Flags().Lookup("target-block-interval").DefValue)
}
