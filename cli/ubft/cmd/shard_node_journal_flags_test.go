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

func TestShardNodeRun_Profile2NeedsJournal(t *testing.T) {
	cmd := shardNodeRunCmd(&baseFlags{})
	cmd.SetArgs([]string{"--trust-history-profile-2"})
	err := cmd.Execute()
	require.ErrorContains(t, err, "requires --execution-journal")
}
