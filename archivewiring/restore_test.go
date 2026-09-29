package archivewiring

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredadmission"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

type restoreExecutorFixture struct {
	genesis   shardnode.BlockRef
	head      shardnode.BlockRef
	finalized shardnode.BlockRef
	blocks    map[string]shardnode.BlockRef
	parents   map[string]shardnode.Hash
}

func TestSingleEpochArchiveRestoreResolvesCertifiedQuietTip(t *testing.T) {
	f := newWiringFixture(t, 1)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	first := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	second := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for _, remote := range []*network.Peer{first, second} {
		sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		store, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, f.entries[0])
		require.NoError(t, err)
		require.NoError(t, store.Put(q, rec))
		server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), remote)
	}
	result := f.entries[0].ResultingUC
	quiet := *result.InputRecord
	quiet.RoundNumber++
	quiet.PreviousHash = bytes.Clone(quiet.Hash)
	quiet.BlockHash = nil
	uc, tr := signWiring(t, f.chain, &quiet, 3, result.GetRootRoundNumber()+1)
	journal, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/restore.db", configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	defer journal.Close()
	_, _, err = journal.Initialize(context.Background(), f.context)
	require.NoError(t, err)
	limits := configuredprogress.JournalLimits{Candidates: 3, Observations: 5, Bytes: 16 << 20}
	require.NoError(t, journal.EnableJournal(context.Background(), f.context, limits))
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	genesis := shardnode.BlockRef{Hash: f.context.Origin.BlockHash().Bytes(), StateRoot: f.context.Origin.StateRoot().Bytes()}
	executor := newRestoreExecutorFixture(genesis)
	r := &SingleEpochRestore{Journal: journal, Context: f.context, JournalLimits: limits, Archive: local,
		Subject: f.subject, Replicas: [2]peer.ID{first.ID(), second.ID()}, Host: sender,
		Limits: DefaultLimits(), Adapter: executor, Genesis: genesis, TipUC: uc, TipTR: tr}
	require.NoError(t, r.Restore(context.Background()))
	require.EqualValues(t, 1, executor.head.Number)
	image, err := journal.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	require.Len(t, image.Observations, 3)
	require.Empty(t, image.Observations[2].TargetHash)
}

func TestArchiveRestoreBackfillsAnUnresolvedHistoricalObservation(t *testing.T) {
	f := newWiringFixture(t, 3)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	first := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	second := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for _, remote := range []*network.Peer{first, second} {
		sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		store, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		for _, entry := range f.entries {
			q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, entry)
			require.NoError(t, err)
			if remote.ID() == first.ID() {
				corrupt := *rec
				corrupt.Body = bytes.Clone(rec.Body)
				corrupt.Body[0] ^= 0xff
				rec = &corrupt
			}
			require.NoError(t, store.Put(q, rec))
		}
		server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), remote)
	}
	journal, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/restore.db", configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	defer journal.Close()
	_, _, err = journal.Initialize(context.Background(), f.context)
	require.NoError(t, err)
	limits := configuredprogress.JournalLimits{Candidates: 4, Observations: 8, Bytes: 16 << 20}
	require.NoError(t, journal.EnableJournal(context.Background(), f.context, limits))
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	genesis := shardnode.BlockRef{Hash: f.context.Origin.BlockHash().Bytes(), StateRoot: f.context.Origin.StateRoot().Bytes()}
	executor := newRestoreExecutorFixture(genesis)
	last := f.entries[len(f.entries)-1]
	restore := &ArchiveRestore{Journal: journal, Context: f.context, JournalLimits: limits, Archive: local,
		Subject: f.subject, Replicas: [2]peer.ID{first.ID(), second.ID()}, Host: sender, Limits: DefaultLimits(),
		Adapter: executor, Genesis: genesis, TipUC: last.ResultingUC, TipTR: last.ResultingTR}
	require.NoError(t, restore.Restore(context.Background()))
	// A retry after the replay marker and EL finality are durable resumes the
	// observation repair path without requiring another empty-disk restore.
	require.NoError(t, restore.Restore(context.Background()))

	// This valid historical certificate has no hot journal body after replay;
	// the direct repair path confirms the journal reports the missing proof.
	entry := f.entries[1]
	require.ErrorIs(t, journal.BackfillJournalObservation(context.Background(), f.context, limits, entry.ResultingUC, entry.ResultingTR), configuredprogress.ErrUnavailable)
	observation := configuredprogress.JournalObservation{UC: entry.ResultingUC, TR: entry.ResultingTR,
		TargetHash: bytes.Clone(entry.Candidate.Hash), Unresolved: true}
	image, err := journal.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	probeArchive, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	fallbackRestore := *restore
	fallbackRestore.Archive = probeArchive
	require.NoError(t, fallbackRestore.backfillRestoredObservation(context.Background(), image.CoverageBase.Height, observation),
		"a corrupt first replica is skipped for the good second replica")
	image, err = journal.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	found := false
	for _, o := range image.Observations {
		if o.UC.GetRoundNumber() == entry.ResultingUC.GetRoundNumber() && o.UC.GetRootRoundNumber() == entry.ResultingUC.GetRootRoundNumber() {
			require.False(t, o.Unresolved)
			found = true
		}
	}
	require.True(t, found, "verified archive body backfills the unresolved observation")
	for _, candidate := range image.Candidates {
		if bytes.Equal(candidate.Candidate.Hash, entry.Candidate.Hash) {
			require.True(t, candidate.Certified)
			return
		}
	}
	t.Fatal("backfilled archive body was not retained in the journal")
}

func newRestoreExecutorFixture(genesis shardnode.BlockRef) *restoreExecutorFixture {
	return &restoreExecutorFixture{genesis: genesis, head: genesis, finalized: genesis,
		blocks: map[string]shardnode.BlockRef{string(genesis.Hash): genesis}, parents: make(map[string]shardnode.Hash)}
}
func (e *restoreExecutorFixture) Head(context.Context) (shardnode.BlockRef, error) {
	return e.head, nil
}
func (e *restoreExecutorFixture) GenesisBlock(context.Context) (shardnode.BlockRef, error) {
	return e.genesis, nil
}
func (e *restoreExecutorFixture) Build(context.Context, shardnode.RoundParams) (shardnode.BuildID, error) {
	return "", fmt.Errorf("restore fixture does not build")
}
func (e *restoreExecutorFixture) Seal(context.Context, shardnode.BuildID) (shardnode.Block, error) {
	return shardnode.Block{}, fmt.Errorf("restore fixture does not seal")
}
func (e *restoreExecutorFixture) Finalized(context.Context) (shardnode.BlockRef, error) {
	return e.finalized, nil
}
func (e *restoreExecutorFixture) Header(_ context.Context, hash shardnode.Hash) (shardnode.BlockRef, shardnode.Hash, error) {
	b, ok := e.blocks[string(hash)]
	if !ok {
		return shardnode.BlockRef{}, nil, fmt.Errorf("unknown header %x", hash)
	}
	return b, e.parents[string(hash)], nil
}
func (e *restoreExecutorFixture) Verify(_ context.Context, b shardnode.Block, p shardnode.RoundParams) (shardnode.Status, error) {
	if !sameBlockRef(e.head, p.Parent) || b.Number != p.Parent.Number+1 || !bytes.Equal(b.ParentHash, p.Parent.Hash) || len(b.Raw) == 0 {
		return shardnode.StatusInvalid, nil
	}
	e.blocks[string(b.Hash)] = shardnode.BlockRef{Number: b.Number, Hash: b.Hash, StateRoot: b.StateRoot}
	e.parents[string(b.Hash)] = b.ParentHash
	return shardnode.StatusValid, nil
}
func (e *restoreExecutorFixture) RecoveryForkchoice(_ context.Context, hash, finalized shardnode.Hash) (shardnode.Status, error) {
	if !bytes.Equal(finalized, e.finalized.Hash) {
		return shardnode.StatusInvalid, nil
	}
	b, ok := e.blocks[string(hash)]
	if !ok {
		return shardnode.StatusSyncing, nil
	}
	e.head = b
	return shardnode.StatusValid, nil
}
func (e *restoreExecutorFixture) Commit(_ context.Context, hash shardnode.Hash) (shardnode.Status, error) {
	if !bytes.Equal(e.head.Hash, hash) {
		return shardnode.StatusInvalid, nil
	}
	e.finalized = e.head
	return shardnode.StatusValid, nil
}
func (e *restoreExecutorFixture) CheckParentWitness(_ context.Context, parent shardnode.BlockRef) error {
	if !sameBlockRef(e.head, parent) {
		return fmt.Errorf("parent witness differs from head")
	}
	return nil
}
func (e *restoreExecutorFixture) CheckBlockBinding(context.Context, shardnode.Block, shardnode.RoundParams) error {
	return nil
}

func TestSingleEpochArchiveRestoreReplaysBeyondJournalCapWithReplicaFailover(t *testing.T) {
	f := newWiringFixture(t, 5)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	failed := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	healthy := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	sender.Network().Peerstore().AddAddrs(healthy.ID(), healthy.MultiAddresses(), peerstore.PermanentAddrTTL)
	remote, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for _, entry := range f.entries {
		q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, entry)
		require.NoError(t, err)
		require.NoError(t, remote.Put(q, rec))
	}
	server, err := NewServer(remote, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
	require.NoError(t, err)
	server.Register(context.Background(), healthy)

	path := t.TempDir() + "/restored.db"
	journal, err := configuredprogress.OpenConfiguredV2(path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	_, _, err = journal.Initialize(context.Background(), f.context)
	require.NoError(t, err)
	limits := configuredprogress.JournalLimits{Candidates: 3, Observations: 4, Bytes: 16 << 20}
	require.NoError(t, journal.EnableJournal(context.Background(), f.context, limits))
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	last := f.entries[len(f.entries)-1]
	for _, entry := range f.entries {
		if entry.Candidate.Number > last.Candidate.Number {
			last = entry
		}
	}
	genesis := shardnode.BlockRef{Number: 0, Hash: f.context.Origin.BlockHash().Bytes(), StateRoot: f.context.Origin.StateRoot().Bytes()}
	executor := newRestoreExecutorFixture(genesis)
	restore := &SingleEpochRestore{Journal: journal, Context: f.context, JournalLimits: limits, Archive: local,
		Subject: f.subject, Replicas: [2]peer.ID{failed.ID(), healthy.ID()}, Host: sender,
		Limits: Limits{Deadline: DefaultLimits().Deadline / 10, Pending: 4, PerPeer: 1}, Adapter: executor,
		Genesis: genesis, TipUC: last.ResultingUC, TipTR: last.ResultingTR}
	require.NoError(t, restore.Restore(context.Background()))
	require.EqualValues(t, 5, executor.head.Number)
	require.True(t, sameBlockRef(executor.head, executor.finalized))
	image, err := journal.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 1, "restore retains a certified base rather than overflowing the bounded journal")
	require.NotNil(t, image.Restored)
	require.Equal(t, &configuredprogress.CoverageBase{Height: image.Restored.Height, Hash: image.Restored.Hash}, image.CoverageBase)
	coordinator := &configuredadmission.ExecutionRecovery{Store: journal, Context: f.context, JournalLimits: limits,
		Executor: executor, Gate: shardnode.NewFinalityGate(), Genesis: genesis, Limits: configuredadmission.DefaultRecoveryLimits()}
	ticket, err := coordinator.Prepare(context.Background(), last.ResultingUC)
	require.NoError(t, err)
	require.NoError(t, coordinator.Revalidate(context.Background(), ticket, last.ResultingUC))
	executor.head = genesis
	require.Error(t, coordinator.Revalidate(context.Background(), ticket, last.ResultingUC), "readiness must close if EL head falls behind")
	executor.head = executor.finalized
	// A restored frontier is the base for new two-replica coverage. Bring
	// back the failed replica before the next certified block is pruned.
	sender.Network().Peerstore().AddAddrs(failed.ID(), failed.MultiAddresses(), peerstore.PermanentAddrTTL)
	remote2, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	server2, err := NewServer(remote2, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{sender.ID()}, DefaultLimits())
	require.NoError(t, err)
	server2.Register(context.Background(), failed)
	var nextState [32]byte
	nextState[0], nextState[31] = 6, 23
	var parentHash [32]byte
	copy(parentHash[:], last.Candidate.Hash)
	nextHash, nextRaw, nextSize := wiringBlock(t, parentHash, nextState, 6, last.ResultingUC.GetRootRoundNumber(), last.ResultingUC, last.ResultingTR)
	candidate := configuredprogress.JournalCandidate{Round: 6, Number: 6, ParentNumber: 5,
		Hash: nextHash[:], StateRoot: nextState[:], ParentHash: parentHash[:], ParentState: last.Candidate.StateRoot,
		Raw: nextRaw, BlockSize: nextSize, AuthorizingUC: last.ResultingUC, AuthorizingTR: last.ResultingTR}
	require.NoError(t, journal.PutJournalCandidate(context.Background(), f.context, limits, candidate))
	ir := &types.InputRecord{Version: 1, RoundNumber: 6, PreviousHash: bytes.Clone(last.Candidate.StateRoot),
		Hash: nextState[:], BlockHash: nextHash[:], SummaryValue: []byte{}, Timestamp: 1_700_000_006}
	uc6, tr6 := signWiring(t, f.chain, ir, 7, last.ResultingUC.GetRootRoundNumber()+1)
	observation, err := rootinput.AuthenticateObservationV2(context.Background(), f.context.Observation, uc6, tr6)
	require.NoError(t, err)
	prepared, _, err := journal.PrepareObservation(context.Background(), f.context, observation)
	require.NoError(t, err)
	_, _, err = journal.CommitObservation(prepared)
	require.NoError(t, err)
	var state7 [32]byte
	state7[0], state7[31] = 7, 24
	parentHash7 := nextHash
	nextHash7, nextRaw7, nextSize7 := wiringBlock(t, parentHash7, state7, 7, uc6.GetRootRoundNumber(), uc6, tr6)
	candidate7 := configuredprogress.JournalCandidate{Round: 7, Number: 7, ParentNumber: 6,
		Hash: nextHash7[:], StateRoot: state7[:], ParentHash: parentHash7[:], ParentState: nextState[:],
		Raw: nextRaw7, BlockSize: nextSize7, AuthorizingUC: uc6, AuthorizingTR: tr6}
	require.NoError(t, journal.PutJournalCandidate(context.Background(), f.context, limits, candidate7))
	ir7 := &types.InputRecord{Version: 1, RoundNumber: 7, PreviousHash: bytes.Clone(nextState[:]),
		Hash: state7[:], BlockHash: nextHash7[:], SummaryValue: []byte{}, Timestamp: 1_700_000_007}
	uc7, tr7 := signWiring(t, f.chain, ir7, 8, uc6.GetRootRoundNumber()+1)
	observation7, err := rootinput.AuthenticateObservationV2(context.Background(), f.context.Observation, uc7, tr7)
	require.NoError(t, err)
	prepared, _, err = journal.PrepareObservation(context.Background(), f.context, observation7)
	require.NoError(t, err)
	_, _, err = journal.CommitObservation(prepared)
	require.NoError(t, err)
	image, err = journal.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	for _, entry := range image.Candidates {
		if entry.Candidate.Number < 6 {
			continue
		}
		q, rec, err := FromJournal(context.Background(), f.context, f.subject, nil, entry)
		require.NoError(t, err)
		for _, store := range []*archive.Store{local, remote, remote2} {
			require.NoError(t, store.Put(q, rec))
		}
	}
	policy := frontier.Policy{Context: f.subject,
		Replicas: [2]string{failed.ID().String(), healthy.ID().String()},
		Binding:  CertifiedBinding{Context: f.context, Subject: f.subject},
		Availability: ReplicaAvailability{Context: context.Background(), Host: sender,
			Replicas: [2]peer.ID{failed.ID(), healthy.ID()}, Limits: DefaultLimits()}}
	require.NoError(t, journal.EnableFrontier(context.Background(), f.context, limits, policy))
	worker := &FrontierWorker{Journal: journal, Context: f.context, Limits: limits, Archive: local,
		Subject: f.subject, Replicas: [2]peer.ID{failed.ID(), healthy.ID()}, Host: sender, TransportLimits: DefaultLimits()}
	require.NoError(t, worker.Pass(context.Background()))
	image, err = journal.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	require.NotNil(t, image.Frontier)
	require.EqualValues(t, 7, image.Frontier.Anchor.Height)
	require.EqualValues(t, 7, image.Frontier.Floor, "frontier pruning crosses the restored coverage base")
	require.Len(t, image.Candidates, 1)
	for _, candidate := range image.Candidates {
		require.NotEqualValues(t, 6, candidate.Candidate.Number, "the covered height between the base and tip is pruned")
	}
	// The restored checkpoint is the start of local two-replica coverage;
	// subsequent audits must not demand pre-restore coverage entries.
	require.NoError(t, worker.Pass(context.Background()))
	// The trust decision also survives a journal process restart.
	require.NoError(t, journal.Close())
	reopened, err := configuredprogress.OpenConfiguredV2(path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	defer reopened.Close()
	require.NoError(t, reopened.EnableJournal(context.Background(), f.context, limits))
	require.NoError(t, reopened.EnableFrontier(context.Background(), f.context, limits, policy))
	image, err = reopened.LoadJournal(context.Background(), f.context, limits)
	require.NoError(t, err)
	require.NotNil(t, image.Frontier)
	require.EqualValues(t, 7, image.Frontier.Anchor.Height)
}
