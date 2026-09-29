package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archivewiring"
)

func TestRestoreCommandAcceptsProfile2AndRequiresFreshState(t *testing.T) {
	base := &baseFlags{HomeDir: t.TempDir()}
	run := shardNodeRunCmd(base)
	restore := shardNodeRestoreCmd(base)
	require.Nil(t, run.Flags().Lookup("tip-uc"), "ordinary profile-off run has no restore pin requirement")
	for _, name := range []string{"tip-uc", "tip-tr", "trust-body-id", "execution-journal", "archive-replica"} {
		require.NotNil(t, restore.Flags().Lookup(name), name)
	}
	journal := filepath.Join(base.HomeDir, "journal.db")
	flags := &shardNodeRunFlags{baseFlags: base, Restore: true, Executor: "engine-api", ExecutionJournal: journal,
		ArchiveStore: filepath.Join(base.HomeDir, "archive"), ArchivePrune: true, RestoreTipUC: "tip.uc", RestoreTipTR: "tip.tr",
		RestoreTrustBodyID: strings.Repeat("a", 64), shardNodeSigningFlags: shardNodeSigningFlags{SigningAuthoritySocket: "authority.sock"}}
	require.NoError(t, os.WriteFile(journal, []byte("copied journal"), 0600))
	err := shardNodeRun(context.Background(), flags, nil)
	require.ErrorContains(t, err, "fresh BFT data directory")
	require.ErrorContains(t, err, journal)
	require.NoError(t, os.Remove(journal))
	flags.ArchivePrune = false
	err = shardNodeRun(context.Background(), flags, nil)
	require.ErrorContains(t, err, "--archive-prune")
	flags.ArchivePrune = true
	flags.SigningAuthoritySocket = ""
	err = shardNodeRun(context.Background(), flags, nil)
	require.ErrorContains(t, err, "local-key restore is refused")
	flags.SigningAuthoritySocket = "authority.sock"
	flags.TrustHistoryProfile2 = true
	err = shardNodeRun(context.Background(), flags, nil)
	require.ErrorIs(t, err, archivewiring.ErrConfig, "profile-2 restore reaches ordinary replica configuration validation")
	require.NoError(t, os.Mkdir(journal+".handoffs", 0700))
	err = shardNodeRun(context.Background(), flags, nil)
	require.ErrorContains(t, err, "fresh BFT data directory")
	require.NoError(t, os.Remove(journal+".handoffs"))
	flags.TrustHistoryProfile2 = false
	flags.Executor = "fake"
	err = shardNodeRun(context.Background(), flags, nil)
	require.ErrorContains(t, err, "--executor engine-api")
}
