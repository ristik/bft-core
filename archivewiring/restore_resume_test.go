package archivewiring

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

var errRestoreInterrupted = errors.New("interrupted restore")

type interruptedRestoreExecutor struct {
	*restoreExecutorFixture
	stage                              string
	verifies, forkchoiceCalls, commits int
}

func (e *interruptedRestoreExecutor) Verify(ctx context.Context, block shardnode.Block, params shardnode.RoundParams) (shardnode.Status, error) {
	e.verifies++
	return e.restoreExecutorFixture.Verify(ctx, block, params)
}

func (e *interruptedRestoreExecutor) RecoveryForkchoice(ctx context.Context, head, finalized shardnode.Hash) (shardnode.Status, error) {
	e.forkchoiceCalls++
	status, err := e.restoreExecutorFixture.RecoveryForkchoice(ctx, head, finalized)
	if e.stage == "replay" && e.head.Number == 2 && err == nil {
		return shardnode.StatusSyncing, errRestoreInterrupted
	}
	return status, err
}

func (e *interruptedRestoreExecutor) Commit(ctx context.Context, head shardnode.Hash) (shardnode.Status, error) {
	e.commits++
	if e.stage == "before finality" {
		return shardnode.StatusSyncing, errRestoreInterrupted
	}
	status, err := e.restoreExecutorFixture.Commit(ctx, head)
	if e.stage == "lost finality response" && err == nil {
		return shardnode.StatusSyncing, errRestoreInterrupted
	}
	return status, err
}

func (e *interruptedRestoreExecutor) Head(ctx context.Context) (shardnode.BlockRef, error) {
	if e.stage == "after finality" && e.finalized.Number != 0 {
		return shardnode.BlockRef{}, errRestoreInterrupted
	}
	return e.restoreExecutorFixture.Head(ctx)
}

func (f *retryRestoreFixture) reopenRestoreStores(t *testing.T) {
	t.Helper()
	checkpoint, err := f.journal.RestoreCheckpoint()
	require.NoError(t, err)
	require.NotEqual(t, configuredprogress.RestoreCheckpoint{}, checkpoint)
	require.NoError(t, f.journal.Close())
	diskCheckpoint, err := configuredprogress.ReadRestoreCheckpoint(f.journalPath)
	require.NoError(t, err)
	require.Equal(t, checkpoint, diskCheckpoint)
	journal, err := configuredprogress.OpenConfiguredV2(f.journalPath, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	t.Cleanup(func() { _ = journal.Close() })
	require.NoError(t, journal.EnableJournal(context.Background(), f.restore.Context, f.limits))
	local, err := archive.Open(f.archivePath)
	require.NoError(t, err)
	f.restore.Journal, f.restore.Archive, f.journal = journal, local, journal
}

func TestSingleEpochArchiveRestoreResumesInterruptedTip(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name, stage          string
		head, finalized      uint64
		rollback             bool
		diskHead, diskFinal  uint64
		forkchoices, commits int
	}{
		{stage: "replay", head: 2, forkchoices: 3, commits: 1},
		{stage: "before finality", head: 5, commits: 1},
		{stage: "lost finality response", head: 5, finalized: 5},
		{stage: "after finality", head: 5, finalized: 5},
		{stage: "before anchor commit", head: 5, finalized: 5},
		{stage: "after anchor commit", head: 5, finalized: 5},
		{name: "replay lost its last head", stage: "replay", head: 2, rollback: true, diskHead: 1, forkchoices: 4, commits: 1},
		{name: "EL lost the finalized tip before anchor", stage: "before anchor commit", head: 5, finalized: 5,
			rollback: true, diskHead: 3, diskFinal: 2, forkchoices: 2, commits: 1},
		{name: "EL lost all progress after anchor", stage: "after anchor commit", head: 5, finalized: 5,
			rollback: true, forkchoices: 5, commits: 1},
		{name: "EL lost the finalized tip after anchor", stage: "after anchor commit", head: 5, finalized: 5,
			rollback: true, diskHead: 3, diskFinal: 3, forkchoices: 2, commits: 1},
	} {
		name := tt.name
		if name == "" {
			name = tt.stage
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			f := newRetryRestoreFixture(t, 0, fastRetry(time.Second))
			e := &interruptedRestoreExecutor{restoreExecutorFixture: f.executor, stage: tt.stage}
			f.restore.Adapter = e
			// Install a quiet tip so resuming also exercises the saved target
			// lookup and both ordinary observations.
			result := f.restore.TipUC
			quiet := *result.InputRecord
			quiet.RoundNumber++
			quiet.PreviousHash = bytes.Clone(quiet.Hash)
			quiet.BlockHash = nil
			f.restore.TipUC, f.restore.TipTR = signWiring(t, f.wf.chain, &quiet, quiet.RoundNumber+1, result.GetRootRoundNumber()+1)
			if tt.stage == "before anchor commit" {
				f.journal.SetFaultHook(func(point string) error {
					if point == "before-replayed-tip-commit" {
						return errRestoreInterrupted
					}
					return nil
				})
			}
			if tt.stage == "after anchor commit" {
				require.NoError(t, f.restore.Restore(ctx))
			} else {
				require.ErrorIs(t, f.restore.Restore(ctx), errRestoreInterrupted)
			}
			require.Equal(t, tt.head, e.head.Number)
			require.Equal(t, tt.finalized, e.finalized.Number)
			f.reopenRestoreStores(t)
			image, err := f.journal.LoadJournal(ctx, f.wf.context, f.limits)
			require.NoError(t, err)
			if tt.stage == "after anchor commit" {
				require.NotNil(t, image.RestoreBase)
				require.NoError(t, f.journal.CheckArchiveRestoreComplete())
			} else {
				require.ErrorIs(t, f.journal.CheckArchiveRestoreComplete(), configuredprogress.ErrUnavailable)
				require.Nil(t, image.RestoreBase)
				require.Empty(t, image.Observations)
				require.Empty(t, image.Candidates)
			}
			if tt.rollback {
				persisted := newRestoreExecutorFixture(e.genesis)
				for key, ref := range e.blocks {
					if ref.Number <= tt.diskHead {
						persisted.blocks[key], persisted.parents[key] = ref, e.parents[key]
					}
					if ref.Number == tt.diskHead {
						persisted.head = ref
					}
					if ref.Number == tt.diskFinal {
						persisted.finalized = ref
					}
				}
				e.restoreExecutorFixture = persisted
			}
			e.stage, e.commits, e.forkchoiceCalls = "", 0, 0
			streams := f.host.calls.Load()
			f.host.failures = -1
			require.NoError(t, f.restore.Restore(ctx))
			require.Equal(t, streams, f.host.calls.Load(), "durable archive records cover the whole retry")
			require.Equal(t, tt.forkchoices, e.forkchoiceCalls)
			require.Equal(t, tt.commits, e.commits)
			require.EqualValues(t, 5, e.finalized.Number)
			image, err = f.journal.LoadJournal(ctx, f.wf.context, f.limits)
			require.NoError(t, err)
			require.NotNil(t, image.RestoreBase)
			require.Equal(t, e.finalized.Hash, shardnode.Hash(image.RestoreBase.Hash[:]))
			require.Len(t, image.Observations, 3)
			require.Len(t, image.Candidates, 1)
			require.True(t, image.Candidates[0].Certified)
		})
	}
}

func TestSingleEpochArchiveRestoreRefusesMismatchedResume(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRetryRestoreFixture(t, 0, fastRetry(time.Second))
	e := &interruptedRestoreExecutor{restoreExecutorFixture: f.executor, stage: "replay"}
	f.restore.Adapter = e
	require.ErrorIs(t, f.restore.Restore(ctx), errRestoreInterrupted)
	f.reopenRestoreStores(t)
	e.stage, e.commits, e.forkchoiceCalls = "", 0, 0

	probe := *f.restore
	for _, entry := range f.wf.entries {
		if entry.Candidate.Number == 1 {
			probe.TipUC, probe.TipTR = entry.ResultingUC, entry.ResultingTR
			break
		}
	}
	require.NotEqual(t, f.restore.TipUC.GetRoundNumber(), probe.TipUC.GetRoundNumber())
	require.ErrorContains(t, probe.Restore(ctx), "another restore pin")
	probe = *f.restore
	probe.ResumeScope[0] = 1
	require.ErrorContains(t, probe.Restore(ctx), "another restore pin")

	originalHead := e.head
	e.head.Hash = bytes.Clone(originalHead.Hash)
	e.head.Hash[0] ^= 1
	require.ErrorContains(t, f.restore.Restore(ctx), "EL head is outside")
	e.head = originalHead

	for _, entry := range f.wf.entries {
		if entry.Candidate.Number == originalHead.Number+1 {
			e.head = shardnode.BlockRef{Number: entry.Candidate.Number, Hash: entry.Candidate.Hash, StateRoot: entry.Candidate.StateRoot}
			break
		}
	}
	require.Greater(t, e.head.Number, originalHead.Number)
	require.ErrorContains(t, f.restore.Restore(ctx), "beyond the verified restore prefix")
	e.head = originalHead

	e.finalized = e.head
	require.ErrorContains(t, f.restore.Restore(ctx), "EL finality is outside")
	e.finalized = e.genesis

	journal, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/unrelated.db", configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	defer journal.Close()
	_, _, err = journal.Initialize(ctx, f.wf.context)
	require.NoError(t, err)
	require.NoError(t, journal.EnableJournal(ctx, f.wf.context, f.limits))
	probe = *f.restore
	probe.Journal = journal
	require.ErrorContains(t, probe.Restore(ctx), "checked genesis for a fresh restore")
	require.Zero(t, e.forkchoiceCalls)
	require.Zero(t, e.commits)
	require.NoError(t, f.restore.Restore(ctx))
	e.finalized.Hash = bytes.Clone(e.finalized.Hash)
	e.finalized.Hash[0] ^= 1
	require.ErrorContains(t, f.restore.Restore(ctx), "EL finality is outside")
}

func TestSingleEpochArchiveRestoreRefusesChangedVerifiedArchive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRetryRestoreFixture(t, 0, fastRetry(time.Second))
	e := &interruptedRestoreExecutor{restoreExecutorFixture: f.executor, stage: "replay"}
	f.restore.Adapter = e
	require.ErrorIs(t, f.restore.Restore(ctx), errRestoreInterrupted)
	f.reopenRestoreStores(t)
	e.stage, e.commits, e.forkchoiceCalls = "", 0, 0

	replacement, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for _, entry := range f.wf.entries {
		q := archive.Request{Context: f.restore.Subject, BlockHash: [32]byte(entry.Candidate.Hash)}
		rec, err := f.restore.Archive.Get(q)
		require.NoError(t, err)
		if entry.Candidate.Number == 1 {
			var companion engineapi.SealCompanion
			require.NoError(t, json.Unmarshal(rec.Companion, &companion))
			companion.Provenance = "different"
			rec.Companion, err = json.Marshal(&companion)
			require.NoError(t, err)
		}
		require.NoError(t, replacement.Put(q, rec))
	}
	f.restore.Archive = replacement
	require.ErrorContains(t, f.restore.Restore(ctx), "retained archive differs from the verified restore prefix")
	require.Zero(t, e.forkchoiceCalls)
	require.Zero(t, e.commits)
}

func TestSingleEpochArchiveRestoreEquivalentBlockTipPin(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRetryRestoreFixture(t, 0, fastRetry(time.Second))
	archived := f.restore.TipUC
	original := f.wf.chain.TrustBase.RootNodes[0]
	extra, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := extra.Verifier()
	require.NoError(t, err)
	publicKey, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(publicKey)
	require.NoError(t, err)
	tb, err := types.NewTrustBase(f.wf.chain.TrustBase.NetworkID, []*types.NodeInfo{
		{NodeID: original.NodeID, SigKey: original.SigKey, Stake: 3},
		{NodeID: id.String(), SigKey: publicKey, Stake: 1},
	})
	require.NoError(t, err)
	f.restore.Context.Observation.TrustBases = fixtureTrust{tb}
	f.restore.Context.Record.TrustBases = fixtureTrust{tb}

	archivedRaw, err := types.Cbor.Marshal(archived)
	require.NoError(t, err)
	var pin types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(archivedRaw, &pin))
	require.NoError(t, pin.UnicitySeal.Sign(id.String(), extra))
	for _, uc := range []*types.UnicityCertificate{archived, &pin} {
		_, err := rootinput.AuthenticateObservationV2(ctx, f.restore.Context.Observation, uc, f.restore.TipTR)
		require.NoError(t, err)
	}
	f.restore.TipUC = &pin
	wantPin, err := RestorePinID(&pin, f.restore.TipTR, f.restore.ResumeScope)
	require.NoError(t, err)
	archivedPin, err := RestorePinID(archived, f.restore.TipTR, f.restore.ResumeScope)
	require.NoError(t, err)
	require.NotEqual(t, archivedPin, wantPin)

	require.NoError(t, f.restore.Restore(ctx))
	require.EqualValues(t, 5, f.executor.finalized.Number)
	f.reopenRestoreStores(t)
	checkpoint, err := f.journal.RestoreCheckpoint()
	require.NoError(t, err)
	require.Equal(t, wantPin, checkpoint.Pin)
	require.NoError(t, f.restore.Restore(ctx))

	image, err := f.journal.LoadJournal(ctx, f.restore.Context, f.limits)
	require.NoError(t, err)
	require.NotNil(t, image.RestoreBase)
	require.Len(t, image.Candidates, 1)
	require.Len(t, image.Observations, 2)
	state, _, err := f.journal.Load(ctx, f.restore.Context)
	require.NoError(t, err)
	observed, ok := state.Observed()
	require.True(t, ok)
	first, ok := state.FirstOrdinary()
	require.True(t, ok)
	for _, uc := range []*types.UnicityCertificate{image.Candidates[0].ResultingUC, image.Observations[1].UC, first.Certificate(), observed.Certificate()} {
		raw, err := types.Cbor.Marshal(uc)
		require.NoError(t, err)
		require.Equal(t, archivedRaw, raw)
	}
	f.restore.TipUC = archived
	require.ErrorContains(t, f.restore.Restore(ctx), "another restore pin")
}

func TestSingleEpochArchiveRestoreReopensCompletedRestoreWithEmptyArchive(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	f := newRetryRestoreFixture(t, 0, fastRetry(time.Second))
	require.NoError(t, f.restore.Restore(ctx))
	f.reopenRestoreStores(t)
	require.NoError(t, os.Rename(f.archivePath, f.archivePath+"-original"))
	empty, err := archive.Open(f.archivePath)
	require.NoError(t, err)
	f.restore.Archive = empty
	e := &interruptedRestoreExecutor{restoreExecutorFixture: f.executor}
	f.restore.Adapter = e

	f.host.failures = -1
	require.ErrorIs(t, f.restore.Restore(ctx), archive.ErrUnavailable)
	f.host.failures = 0
	require.NoError(t, f.restore.Restore(ctx))
	for _, entry := range f.wf.entries {
		q := archive.Request{Context: f.restore.Subject, BlockHash: [32]byte(entry.Candidate.Hash)}
		_, err := empty.Get(q)
		require.NoError(t, err, "successful retry must restore every archived ancestor")
	}
	require.Zero(t, e.verifies)
	require.Zero(t, e.forkchoiceCalls)
	require.Zero(t, e.commits)
}
