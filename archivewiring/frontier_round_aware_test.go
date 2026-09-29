package archivewiring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredadmission"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestRoundAwareFrontierBreaksUnresolvedObservationDeadlock(t *testing.T) {
	limits := configuredprogress.JournalLimits{Candidates: 2, Observations: 8, Bytes: 16 << 20}
	f := newWiringFixtureWithLimits(t, 1, limits)
	ctx := context.Background()

	firstEntry := f.entries[0]
	parentHash := [32]byte{}
	parentState := [32]byte{}
	copy(parentHash[:], firstEntry.Candidate.Hash)
	copy(parentState[:], firstEntry.Candidate.StateRoot)

	// Fill the bounded candidate journal with a side proposal. The certified
	// next body must be dropped while the root observation remains durable.
	loser := firstEntry.Candidate
	loserHash := sha256.Sum256([]byte("full journal side proposal"))
	loser.Hash, loser.Raw, loser.BlockSize = loserHash[:], []byte("side proposal"), uint64(len("side proposal"))
	require.NoError(t, f.store.PutJournalCandidate(ctx, f.context, limits, loser))

	var nextState [32]byte
	nextState[0], nextState[31] = 2, 19
	nextHash, nextRaw, nextSize := wiringBlock(t, parentHash, nextState, 2,
		firstEntry.ResultingUC.GetRootRoundNumber(), firstEntry.ResultingUC, firstEntry.ResultingTR)
	nextCandidate := configuredprogress.JournalCandidate{Round: 2, Number: 2, ParentNumber: 1,
		Hash: nextHash[:], StateRoot: nextState[:], ParentHash: parentHash[:], ParentState: parentState[:],
		Raw: nextRaw, BlockSize: nextSize, AuthorizingUC: firstEntry.ResultingUC, AuthorizingTR: firstEntry.ResultingTR}
	require.ErrorIs(t, f.store.PutJournalCandidate(ctx, f.context, limits, nextCandidate), configuredprogress.ErrBounds,
		"the journal is at its candidate cap")

	ir := &types.InputRecord{Version: 1, RoundNumber: 2, Hash: nextState[:], PreviousHash: bytes.Clone(parentState[:]),
		BlockHash: nextHash[:], SummaryValue: []byte{}, Timestamp: 1_700_000_002}
	nextUC, nextTR := signWiring(t, f.chain, ir, 3, firstEntry.ResultingUC.GetRootRoundNumber()+1)
	observation, err := rootinput.AuthenticateObservationV2(ctx, f.context.Observation, nextUC, nextTR)
	require.NoError(t, err)
	prepared, _, err := f.store.PrepareObservation(ctx, f.context, observation)
	require.NoError(t, err)
	_, _, err = f.store.CommitObservation(prepared)
	require.NoError(t, err)

	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	firstReplica, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	secondReplica, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	firstRequest, firstRecord := f.record(t, 0)
	for _, copy := range []*archive.Store{local, firstReplica, secondReplica} {
		require.NoError(t, copy.Put(firstRequest, firstRecord))
	}
	nextRecordEntry := configuredprogress.JournalEntry{Candidate: nextCandidate, Certified: true, ResultingUC: nextUC, ResultingTR: nextTR}
	nextRequest, nextRecord, err := FromJournal(ctx, f.context, f.subject, nil, nextRecordEntry)
	require.NoError(t, err)
	require.NoError(t, local.Put(nextRequest, nextRecord))

	peers := [2]peer.ID{"first", "second"}
	policy := frontier.Policy{Context: f.subject, Replicas: [2]string{peers[0].String(), peers[1].String()},
		Binding: CertifiedBinding{Context: f.context, Subject: f.subject},
		Availability: fixtureAvailability{stores: map[string]*archive.Store{
			peers[0].String(): firstReplica, peers[1].String(): secondReplica,
		}}}
	require.NoError(t, f.store.EnableFrontier(ctx, f.context, limits, policy))
	worker := &FrontierWorker{Journal: f.store, Context: f.context, Limits: limits, Archive: local,
		Subject: f.subject, Replicas: peers}
	require.NoError(t, worker.Pass(ctx), "the frontier at root round 5 may prune below unresolved round 6")
	image, err := f.store.LoadJournal(ctx, f.context, limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 1, "pruning frees one candidate slot")
	require.Len(t, image.Observations, 1)
	require.True(t, image.Observations[0].Unresolved, "the later observation remains durable")

	genesis := shardnode.BlockRef{Number: 0, Hash: f.context.Origin.BlockHash().Bytes(), StateRoot: f.context.Origin.StateRoot().Bytes()}
	base := shardnode.BlockRef{Number: 1, Hash: bytes.Clone(firstEntry.Candidate.Hash), StateRoot: bytes.Clone(firstEntry.Candidate.StateRoot)}
	executor := newRestoreExecutorFixture(genesis)
	executor.blocks[string(base.Hash)] = base
	executor.parents[string(base.Hash)] = bytes.Clone(genesis.Hash)
	executor.head, executor.finalized = base, base
	source := &RecoverySource{Context: f.context, Subject: f.subject, Local: local, Limits: DefaultLimits()}
	recovery := &configuredadmission.ExecutionRecovery{Store: f.store, Context: f.context, JournalLimits: limits,
		Executor: executor, Gate: shardnode.NewFinalityGate(), Genesis: genesis,
		Limits:       configuredadmission.RecoveryLimits{Blocks: 4, Bytes: 4 << 20, Deadline: 5 * time.Second},
		FetchArchive: source.FetchSuffix}
	require.NoError(t, recovery.AcquireForCertificate(ctx, nextUC, nextTR),
		"after pruning frees capacity, the missing body is fetched from the verified archive")

	image, err = f.store.LoadJournal(ctx, f.context, limits)
	require.NoError(t, err)
	require.Len(t, image.Candidates, 2)
	var foundBody, foundObservation bool
	for _, candidate := range image.Candidates {
		if bytes.Equal(candidate.Candidate.Hash, nextHash[:]) {
			foundBody = true
			require.True(t, candidate.Certified)
		}
	}
	for _, stored := range image.Observations {
		if bytes.Equal(stored.TargetHash, nextHash[:]) {
			foundObservation = true
			require.False(t, stored.Unresolved)
		}
	}
	require.True(t, foundBody)
	require.True(t, foundObservation)
}
