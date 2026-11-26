package cmd

import (
	"context"
	"crypto/sha256"
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

// restoreFixture is a restore invocation over a journal initialized for it; checkpoint, when set, records this invocation's pin as a
// finished replay to height 1 (its finality authorized), as a same-epoch restore leaves it just before it installs its tip.
type restoreFixture struct {
	flags *shardNodeRunFlags
	uc    *types.UnicityCertificate
	tr    *certification.TechnicalRecord
	pin   [32]byte
}

func newRestoreFixture(t *testing.T, epoch uint64, checkpoint bool) *restoreFixture {
	t.Helper()
	ctx := context.Background()
	base := &baseFlags{HomeDir: t.TempDir()}
	f := &restoreFixture{flags: &shardNodeRunFlags{
		baseFlags: base, Restore: true, Executor: "engine-api", ArchivePrune: true,
		ExecutionJournal: filepath.Join(base.HomeDir, "journal.db"), ArchiveStore: filepath.Join(base.HomeDir, "archive"),
		RestoreTipUC: filepath.Join(base.HomeDir, "tip.uc"), RestoreTipTR: filepath.Join(base.HomeDir, "tip.tr"),
		RestoreTrustBodyID: strings.Repeat("a", 64), shardNodeSigningFlags: shardNodeSigningFlags{SigningAuthoritySocket: "authority.sock"},
		ArchiveReplicas: []string{"reject-in-replica-validation"},
	}}
	f.uc = &types.UnicityCertificate{Version: 1, InputRecord: &types.InputRecord{Version: 1}, UnicitySeal: &types.UnicitySeal{Version: 1, Epoch: epoch}}
	f.tr = &certification.TechnicalRecord{Round: 1}
	f.writePin(t)
	scope, err := restoreResumeScope(f.flags)
	require.NoError(t, err)
	f.pin, err = archivewiring.RestorePinID(f.uc, f.tr, scope)
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
	journal, err := configuredprogress.OpenConfiguredV2(f.flags.ExecutionJournal, configuredprogress.Settings{Retain: 128})
	require.NoError(t, err)
	_, _, err = journal.Initialize(ctx, c)
	require.NoError(t, err)
	limits := configuredprogress.JournalLimits{Candidates: 3, Observations: 4, Bytes: 16 << 20}
	require.NoError(t, journal.EnableJournal(ctx, c, limits))
	if checkpoint {
		cp := configuredprogress.RestoreCheckpoint{Pin: f.pin, Target: [32]byte{1}}
		require.NoError(t, journal.BeginArchiveRestore(ctx, c, limits, cp))
		cp, err = journal.AdvanceArchiveRestore(cp, [32]byte{2})
		require.NoError(t, err)
		_, err = journal.AuthorizeRestoreFinality(cp)
		require.NoError(t, err)
	}
	require.NoError(t, journal.Close())
	return f
}

func (f *restoreFixture) writePin(t *testing.T) {
	t.Helper()
	u, err := types.Cbor.Marshal(f.uc)
	require.NoError(t, err)
	r, err := types.Cbor.Marshal(f.tr)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(f.flags.RestoreTipUC, u, 0600))
	require.NoError(t, os.WriteFile(f.flags.RestoreTipTR, r, 0600))
}

// bft-core#1309: a supervisor repeats `shard-node restore` with the seed pin on every start (the validator container does, until its node is
// active). Once the restore under THIS pin completed (its checkpoint names the installed anchor), the command starts the node as `shard-node
// run`: the effective flags are a run's and no pin is replayed. An interrupted restore stays a restore; another pin, another trust BodyID, or
// a checkpoint that does not name the anchor is refused.
func TestRestoreStartRunsOnlyACompletedRestoreOfThisPin(t *testing.T) {
	f := newRestoreFixture(t, 1, true)
	start, err := restoreStart(f.flags)
	require.NoError(t, err)
	require.False(t, start.completed, "an interrupted restore (a checkpoint, no anchor) resumes as a restore")
	require.True(t, start.flags.Restore)
	require.Equal(t, f.pin, start.checkpoint.Pin)
	require.NotNil(t, start.uc, "it replays the pin")

	writeRestoreAnchor(t, f.flags.ExecutionJournal, 1, [32]byte{1})
	start, err = restoreStart(f.flags)
	require.NoError(t, err)
	require.True(t, start.completed)
	require.False(t, start.flags.Restore, "a completed restore of this pin starts as `shard-node run`")
	require.Nil(t, start.uc, "and replays no pin")
	require.Equal(t, configuredprogress.RestoreCheckpoint{}, start.checkpoint)
	require.True(t, f.flags.Restore, "the caller's flags are not changed")
	// through the command: past the restore checks, to the ordinary replica validation (this test needs neither an EL nor a signer)
	require.ErrorIs(t, shardNodeRun(context.Background(), f.flags, nil), archivewiring.ErrConfig)

	body := *f.flags
	body.RestoreTrustBodyID = strings.Repeat("b", 64)
	_, err = restoreStart(&body)
	require.ErrorContains(t, err, "another pin or restore path", "another trust BodyID")
	f.tr.Round++
	f.writePin(t)
	_, err = restoreStart(f.flags)
	require.ErrorContains(t, err, "another pin or restore path", "another pin")
	f.tr.Round--
	f.writePin(t)
	writeRestoreAnchor(t, f.flags.ExecutionJournal, 2, [32]byte{1})
	_, err = restoreStart(f.flags)
	require.ErrorContains(t, err, "does not name its installed restore anchor")
}

// A restore whose pin is later than the genesis epoch records no checkpoint, so its completed journal names no pin: a restore command
// cannot be matched to it and is refused whatever its pin and BodyID (the node starts with `shard-node run`), as before bft-core#1309.
func TestRestoreStartRefusesACompletedRestoreWithoutACheckpoint(t *testing.T) {
	f := newRestoreFixture(t, 7, false)
	writeRestoreAnchor(t, f.flags.ExecutionJournal, 40, [32]byte{9})
	f.flags.RestoreTrustBodyID = strings.Repeat("c", 64)
	start, err := restoreStart(f.flags)
	require.ErrorContains(t, err, "completed without a restore checkpoint")
	require.ErrorContains(t, err, "shard-node run")
	require.False(t, start.completed)
	require.ErrorContains(t, shardNodeRun(context.Background(), f.flags, nil), "completed without a restore checkpoint")
}

// writeRestoreAnchor stands for a finished restore's final transaction: its recovery anchor, in the journal's own encoding (an envelope of
// format version 2, kind 9, over the anchor's array). The command decodes it; its binding to the journal's body is the run startup's.
func writeRestoreAnchor(t *testing.T, path string, height uint64, hash [32]byte) {
	t.Helper()
	payload, err := types.Cbor.Marshal(struct {
		_          struct{} `cbor:",toarray"`
		Version    uint64
		Descriptor []byte
		Height     uint64
		Hash       []byte
		StateRoot  []byte
		RootRound  uint64
	}{Version: 1, Descriptor: make([]byte, 32), Height: height, Hash: hash[:], StateRoot: make([]byte, 32), RootRound: 5})
	require.NoError(t, err)
	digest := sha256.Sum256(payload)
	raw, err := types.Cbor.Marshal(struct {
		_               struct{} `cbor:",toarray"`
		Version, Kind   uint64
		Payload, Digest []byte
	}{Version: configuredprogress.FormatVersion, Kind: 9, Payload: payload, Digest: digest[:]})
	require.NoError(t, err)
	db, err := bolt.Open(path, 0o600, nil)
	require.NoError(t, err)
	require.NoError(t, db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte("configured-progress/v2")).Put([]byte("journal/restore-anchor"), raw)
	}))
	require.NoError(t, db.Close())
}
