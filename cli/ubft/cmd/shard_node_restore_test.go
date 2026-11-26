package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archivewiring"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
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
	flags.ArchiveReplicas = []string{"one-replica-is-neither-derived-nor-a-pair"}
	err = shardNodeRun(context.Background(), flags, nil)
	require.ErrorIs(t, err, archivewiring.ErrConfig, "profile-2 restore reaches ordinary replica configuration validation")
	flags.ArchiveReplicas = nil
	require.NoError(t, os.Mkdir(journal+".handoffs", 0700))
	err = shardNodeRun(context.Background(), flags, nil)
	require.ErrorContains(t, err, "fresh BFT data directory")
	require.NoError(t, os.Remove(journal+".handoffs"))
	require.NoError(t, os.Mkdir(flags.ArchiveStore, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(flags.ArchiveStore, "unrelated"), nil, 0600))
	err = shardNodeRun(context.Background(), flags, nil)
	require.ErrorContains(t, err, "is not empty; supply a fresh directory")
	require.NoFileExists(t, journal)
	require.NoError(t, os.Remove(filepath.Join(flags.ArchiveStore, "unrelated")))
	flags.TrustHistoryProfile2 = false
	flags.Executor = "fake"
	err = shardNodeRun(context.Background(), flags, nil)
	require.ErrorContains(t, err, "--executor engine-api")
}

func TestRestoreCommandAllowsOnlyMatchingCheckpointToReopenPaths(t *testing.T) {
	ctx := context.Background()
	base := &baseFlags{HomeDir: t.TempDir()}
	flags := &shardNodeRunFlags{
		baseFlags: base, Restore: true, Executor: "engine-api", ArchivePrune: true,
		ExecutionJournal: filepath.Join(base.HomeDir, "journal.db"), ArchiveStore: filepath.Join(base.HomeDir, "archive"),
		RestoreTipUC: filepath.Join(base.HomeDir, "tip.uc"), RestoreTipTR: filepath.Join(base.HomeDir, "tip.tr"),
		RestoreTrustBodyID: strings.Repeat("a", 64), shardNodeSigningFlags: shardNodeSigningFlags{SigningAuthoritySocket: "authority.sock"},
		ArchiveReplicas: []string{"reject-in-replica-validation"},
	}
	uc := &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1}, UnicitySeal: &types.UnicitySeal{Version: 1}}
	tr := &certification.TechnicalRecord{Round: 1}
	writePin := func() {
		t.Helper()
		u, err := types.Cbor.Marshal(uc)
		require.NoError(t, err)
		r, err := types.Cbor.Marshal(tr)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(flags.RestoreTipUC, u, 0600))
		require.NoError(t, os.WriteFile(flags.RestoreTipTR, r, 0600))
	}
	writePin()
	scope, err := restoreResumeScope(flags)
	require.NoError(t, err)
	pin, err := archivewiring.RestorePinID(uc, tr, scope)
	require.NoError(t, err)

	full, path, _ := preparedGenesisFixture(t, 1337)
	origin, _, err := loadGenesisOrigin(full, path, "", 1)
	require.NoError(t, err)
	trust := staticTrustBases{}
	confHash := origin.FullShardConfHash().Bytes()
	c := configuredprogress.Context{Origin: origin,
		Observation: rootinput.ObservationContextV2{NetworkID: full.NetworkID, PartitionID: full.PartitionID, ShardID: full.ShardID,
			ShardConfHash: confHash, RootEpoch: 1, TrustBases: trust},
		Record: certifiedstore.Context{NetworkID: full.NetworkID, PartitionID: full.PartitionID, ShardID: full.ShardID,
			FullShardConfHash: confHash, Registry: origin.ProofContext(), TrustBases: trust}}
	journal, err := configuredprogress.OpenConfiguredV2(flags.ExecutionJournal, configuredprogress.Settings{Retain: 128})
	require.NoError(t, err)
	_, _, err = journal.Initialize(ctx, c)
	require.NoError(t, err)
	limits := configuredprogress.JournalLimits{Candidates: 3, Observations: 4, Bytes: 16 << 20}
	require.NoError(t, journal.EnableJournal(ctx, c, limits))
	require.NoError(t, journal.BeginArchiveRestore(ctx, c, limits, configuredprogress.RestoreCheckpoint{Pin: pin, Target: [32]byte{1}}))
	require.NoError(t, journal.Close())

	// Fixed-profile startup creates a trust sibling too. Stop at ordinary
	// replica validation so this test needs neither a live EL nor a signer.
	require.NoError(t, os.WriteFile(flags.ExecutionJournal+".trust", nil, 0600))
	require.NoError(t, os.Mkdir(flags.ArchiveStore, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(flags.ArchiveStore, "retained"), nil, 0600))
	require.ErrorIs(t, shardNodeRun(ctx, flags, nil), archivewiring.ErrConfig)
	otherPath := *flags
	otherPath.ArchiveStore = filepath.Join(base.HomeDir, "wrong-archive")
	require.ErrorContains(t, shardNodeRun(ctx, &otherPath, nil), "another pin or restore path")
	otherBody := *flags
	otherBody.RestoreTrustBodyID = strings.Repeat("b", 64)
	require.ErrorContains(t, shardNodeRun(ctx, &otherBody, nil), "another pin or restore path")
	tr.Round++
	writePin()
	require.ErrorContains(t, shardNodeRun(ctx, flags, nil), "another pin or restore path")
}

// bft-core#1309: a supervisor repeats `shard-node restore` with the seed pin on every start (the validator container does, until its node is
// active). Once the restore completed (its replayed tip and recovery anchor are installed), the stores are an ordinary node's: the command
// starts as `shard-node run` instead of replaying the pin again. A checkpoint without the anchor (an interrupted restore) stays a restore
// and keeps every fresh-path check; a completed journal under another pin is still refused.
func TestRestoreCommandStartsACompletedRestoreAsRun(t *testing.T) {
	ctx := context.Background()
	base := &baseFlags{HomeDir: t.TempDir()}
	flags := &shardNodeRunFlags{
		baseFlags: base, Restore: true, Executor: "engine-api", ArchivePrune: true,
		ExecutionJournal: filepath.Join(base.HomeDir, "journal.db"), ArchiveStore: filepath.Join(base.HomeDir, "archive"),
		RestoreTipUC: filepath.Join(base.HomeDir, "tip.uc"), RestoreTipTR: filepath.Join(base.HomeDir, "tip.tr"),
		RestoreTrustBodyID: strings.Repeat("a", 64), shardNodeSigningFlags: shardNodeSigningFlags{SigningAuthoritySocket: "authority.sock"},
		ArchiveReplicas: []string{"reject-in-replica-validation"},
	}
	uc := &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1}, UnicitySeal: &types.UnicitySeal{Version: 1}}
	tr := &certification.TechnicalRecord{Round: 1}
	u, err := types.Cbor.Marshal(uc)
	require.NoError(t, err)
	r, err := types.Cbor.Marshal(tr)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(flags.RestoreTipUC, u, 0600))
	require.NoError(t, os.WriteFile(flags.RestoreTipTR, r, 0600))
	scope, err := restoreResumeScope(flags)
	require.NoError(t, err)
	pin, err := archivewiring.RestorePinID(uc, tr, scope)
	require.NoError(t, err)

	full, path, _ := preparedGenesisFixture(t, 1337)
	origin, _, err := loadGenesisOrigin(full, path, "", 1)
	require.NoError(t, err)
	trust := staticTrustBases{}
	confHash := origin.FullShardConfHash().Bytes()
	c := configuredprogress.Context{Origin: origin,
		Observation: rootinput.ObservationContextV2{NetworkID: full.NetworkID, PartitionID: full.PartitionID, ShardID: full.ShardID,
			ShardConfHash: confHash, RootEpoch: 1, TrustBases: trust},
		Record: certifiedstore.Context{NetworkID: full.NetworkID, PartitionID: full.PartitionID, ShardID: full.ShardID,
			FullShardConfHash: confHash, Registry: origin.ProofContext(), TrustBases: trust}}
	journal, err := configuredprogress.OpenConfiguredV2(flags.ExecutionJournal, configuredprogress.Settings{Retain: 128})
	require.NoError(t, err)
	_, _, err = journal.Initialize(ctx, c)
	require.NoError(t, err)
	limits := configuredprogress.JournalLimits{Candidates: 3, Observations: 4, Bytes: 16 << 20}
	require.NoError(t, journal.EnableJournal(ctx, c, limits))
	require.NoError(t, journal.BeginArchiveRestore(ctx, c, limits, configuredprogress.RestoreCheckpoint{Pin: pin, Target: [32]byte{1}}))
	require.NoError(t, journal.Close())
	// what an ordinary run leaves next to the journal: the retained archive and (fixed profile) the handoff history
	require.NoError(t, os.Mkdir(flags.ArchiveStore, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(flags.ArchiveStore, "retained"), nil, 0600))
	require.NoError(t, os.Mkdir(flags.ExecutionJournal+".handoffs", 0700))

	_, complete, err := checkRestorePaths(flags)
	require.ErrorContains(t, err, "fresh BFT data directory", "an interrupted restore keeps the fresh-path checks")
	require.False(t, complete)
	require.ErrorContains(t, shardNodeRun(ctx, flags, nil), "fresh BFT data directory")

	markRestoreComplete(t, flags.ExecutionJournal)
	checkpoint, complete, err := checkRestorePaths(flags)
	require.NoError(t, err)
	require.True(t, complete)
	require.Equal(t, pin, checkpoint.Pin)
	// started as `run`: past the restore checks, to the ordinary replica validation (this test needs neither an EL nor a signer)
	require.ErrorIs(t, shardNodeRun(ctx, flags, nil), archivewiring.ErrConfig)
	require.True(t, flags.Restore, "the caller's flags are not changed")
	tr.Round++
	r, err = types.Cbor.Marshal(tr)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(flags.RestoreTipTR, r, 0600))
	require.ErrorContains(t, shardNodeRun(ctx, flags, nil), "another pin or restore path")
}

// markRestoreComplete stands for a finished restore's final transaction: only the presence of its recovery anchor matters to the command.
func markRestoreComplete(t *testing.T, path string) {
	t.Helper()
	db, err := bolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("configured-progress/v2")).Put([]byte("journal/restore-anchor"), []byte{1})
	}))
	require.NoError(t, db.Close())
}
