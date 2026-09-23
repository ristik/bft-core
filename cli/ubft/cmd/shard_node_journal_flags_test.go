package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestShardNodeRun_RefusesEvidenceRecoveryWithJournal(t *testing.T) {
	cmd := shardNodeRunCmd(&baseFlags{})
	cmd.SetArgs([]string{"--executor", "engine-api", "--execution-journal", "journal.db", "--evidence-recover"})
	err := cmd.Execute()
	require.ErrorContains(t, err, "cannot be combined with --execution-journal")
}
