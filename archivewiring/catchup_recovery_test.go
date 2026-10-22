package archivewiring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredadmission"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// replicaA and replicaB are the replicas' names as the frontier keys them (a peer ID's string form).
var replicaA, replicaB = peer.ID("first").String(), peer.ID("second").String()

// returningLimits is a small journal, so that the gap is several times what it holds (the #751 acceptance ran with 32).
var returningLimits = configuredprogress.JournalLimits{Candidates: 12, Observations: 24, Bytes: 16 << 20}

// returningNode is a validator that comes back at genesis after the network moved on (#769): an empty journal with the bootstrap
// certificate, frontier pruning against two replicas, an executor at genesis, and a recovery coordinator with the archive catch-up.
type returningNode struct {
	store    *configuredprogress.Store
	exec     *restoreExecutorFixture
	worker   *FrontierWorker
	recovery *configuredadmission.ExecutionRecovery
}

func newReturningNode(t *testing.T, p *planFixture, replicas map[string]*archive.Store) *returningNode {
	t.Helper()
	ctx := context.Background()
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 8})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, _, err = store.Initialize(ctx, p.f.context)
	require.NoError(t, err)
	require.NoError(t, store.EnableJournal(ctx, p.f.context, returningLimits))
	boot := p.f.entries[0].Candidate
	o, err := rootinput.AuthenticateObservationV2(ctx, p.f.context.Observation, boot.AuthorizingUC, boot.AuthorizingTR)
	require.NoError(t, err)
	prepared, _, err := store.PrepareObservation(ctx, p.f.context, o)
	require.NoError(t, err)
	_, _, err = store.CommitObservation(prepared)
	require.NoError(t, err)
	names := []peer.ID{"first", "second"}
	policy := frontier.Policy{Context: p.f.subject, Replicas: [2]string{names[0].String(), names[1].String()},
		Binding: CertifiedBinding{Context: p.f.context, Subject: p.f.subject}, Availability: fixtureAvailability{stores: replicas}}
	require.NoError(t, store.EnableFrontier(ctx, p.f.context, returningLimits, policy))
	exec := newRestoreExecutorFixture(p.genesis)
	worker := &FrontierWorker{Journal: store, Context: p.f.context, Limits: returningLimits, Archive: p.local, Subject: p.f.subject, Replicas: names, Finalized: exec.Finalized}
	recovery := &configuredadmission.ExecutionRecovery{Store: store, Context: p.f.context, JournalLimits: returningLimits, Executor: exec, Gate: shardnode.NewFinalityGate(),
		Genesis: p.genesis, Limits: configuredadmission.RecoveryLimits{Blocks: 8, Bytes: 4 << 20, Deadline: 20 * time.Second},
		FetchArchive: p.source.FetchSuffix, ArchiveCatchUp: &CatchUp{Source: p.source, Frontier: worker}}
	return &returningNode{store: store, exec: exec, worker: worker, recovery: recovery}
}

// catchUp submits the gap's target certificate until it is admitted, as the node's admission does with each new certificate, and
// checks the journal stays inside its limits after every call.
func (n *returningNode) catchUp(t *testing.T, p *planFixture, height int, maxCalls int) int {
	t.Helper()
	ctx := context.Background()
	target := p.f.entries[height-1]
	for calls := 1; calls <= maxCalls; calls++ {
		err := n.recovery.AcquireForCertificate(ctx, target.ResultingUC, target.ResultingTR)
		image, loadErr := n.store.LoadJournal(ctx, p.f.context, returningLimits)
		require.NoError(t, loadErr)
		require.LessOrEqual(t, len(image.Candidates), returningLimits.Candidates, "call %d: candidates", calls)
		require.LessOrEqual(t, len(image.Observations), returningLimits.Observations, "call %d: observations", calls)
		if err == nil {
			// the node recovers from the journal once the certificate is admitted: the executor ends finalized at the target
			head, err := n.recovery.Recover(ctx, target.ResultingUC)
			require.NoError(t, err)
			require.EqualValues(t, height, head.Number)
			return calls
		}
		require.ErrorIs(t, err, configuredadmission.ErrRecoveryUnavailable, "call %d", calls)
		require.False(t, n.recovery.Terminal(err), "call %d: a catch-up in progress never stops the node: %v", calls, err)
		require.False(t, errors.Is(err, configuredadmission.ErrRecoveryInvalid) || errors.Is(err, configuredadmission.ErrRecoveryConflict), "call %d: %v", calls, err)
	}
	t.Fatalf("the gap to %d was not closed in %d calls", height, maxCalls)
	return 0
}

func TestArchiveCatchUp_ClosesAGapSeveralJournalsLongPageByPage(t *testing.T) {
	t.Parallel()
	const gap = 29 // 3 pages of the journal's 12 candidates and then some; one recovery is 8 blocks here
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap)
	n := newReturningNode(t, p, map[string]*archive.Store{replicaA: p.replica, replicaB: p.second})
	calls := n.catchUp(t, p, gap, 40)
	require.EqualValues(t, gap, n.exec.finalized.Number, "the executor is finalized at the target")
	require.GreaterOrEqual(t, calls, (gap-8)/3, "pages of a quarter of the journal (3 blocks), until the rest fits one recovery (8) and the journal")
	image, err := n.store.LoadJournal(context.Background(), p.f.context, returningLimits)
	require.NoError(t, err)
	require.NotNil(t, image.Frontier)
	require.Greater(t, image.Frontier.Anchor.Height, uint64(gap-returningLimits.Candidates), "the frontier followed the pages")
}

// TestArchiveCatchUp_TakesTheNewestBlocksFromAPeersJournal: rev2 R1. The newest blocks are only in the peer's hot journal (its frontier
// pruned everything older), and everything older only in the archive.
func TestArchiveCatchUp_TakesTheNewestBlocksFromAPeersJournal(t *testing.T) {
	t.Parallel()
	const gap, fresh = 29, 6
	ctx := context.Background()
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap-fresh) // the archive lacks the newest six
	// the peer: the fixture's own journal holds all 29; its frontier prunes what the archive holds
	peerLocal, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for h := 1; h <= gap; h++ {
		q, rec := p.f.record(t, h-1)
		require.NoError(t, peerLocal.Put(q, rec))
	}
	names := []peer.ID{"first", "second"}
	replicas := map[string]*archive.Store{replicaA: p.replica, replicaB: p.second}
	require.NoError(t, p.f.store.EnableFrontier(ctx, p.f.context, p.f.limits, frontier.Policy{Context: p.f.subject, Replicas: [2]string{replicaA, replicaB},
		Binding: CertifiedBinding{Context: p.f.context, Subject: p.f.subject}, Availability: fixtureAvailability{stores: replicas}}))
	top := p.ref(gap)
	peerWorker := &FrontierWorker{Journal: p.f.store, Context: p.f.context, Limits: p.f.limits, Archive: peerLocal, Subject: p.f.subject, Replicas: names,
		Finalized: func(context.Context) (shardnode.BlockRef, error) { return top, nil }}
	// a legacy two-replica worker reads back no copies itself (the journal does): cover exactly what the archive holds
	require.NoError(t, peerWorker.Advance(ctx, gap-fresh))
	pruned, err := p.f.store.LoadFrontier(ctx, p.f.context, p.f.limits)
	require.NoError(t, err)
	require.EqualValues(t, gap-fresh, pruned.Anchor.Height, "the peer retains only the blocks the archive lacks")

	server, err := shardnode.NewJournalServer(configuredadmission.JournalProvider{Store: p.f.store, Context: p.f.context, Limits: p.f.limits}, shardnode.DefaultJournalTransportLimits())
	require.NoError(t, err)
	peerHost := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	server.Register(peerHost)
	asker := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	asker.Network().Peerstore().AddAddrs(peerHost.ID(), peerHost.MultiAddresses(), peerstore.PermanentAddrTTL)

	n := newReturningNode(t, p, replicas)
	n.recovery.Host, n.recovery.Providers = asker, []peer.ID{peerHost.ID()}
	n.catchUp(t, p, gap, 40)
	require.EqualValues(t, gap, n.exec.finalized.Number)
}

// TestArchiveCatchUp_WaitsForArchiveCopiesWithoutStopping: when the replicas cannot prove two copies, the frontier does not move and the
// journal fills; the catch-up then waits (rev2 R2: a frontier condition is never a recovery error class) and resumes once copies exist.
func TestArchiveCatchUp_WaitsForArchiveCopiesWithoutStopping(t *testing.T) {
	t.Parallel()
	const gap = 20
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap)
	empty, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	copies := map[string]*archive.Store{replicaA: p.replica, replicaB: empty} // one copy only: nothing can be covered
	n := newReturningNode(t, p, copies)
	ctx := context.Background()
	target := p.f.entries[gap-1]
	waited := false
	for range 12 {
		err := n.recovery.AcquireForCertificate(ctx, target.ResultingUC, target.ResultingTR)
		require.ErrorIs(t, err, configuredadmission.ErrRecoveryUnavailable)
		require.False(t, n.recovery.Terminal(err), "%v", err)
		if strings.Contains(err.Error(), "waiting for archive copies") {
			waited = true
		}
	}
	require.True(t, waited, "a full journal is reported as waiting for archive copies")
	image, err := n.store.LoadJournal(ctx, p.f.context, returningLimits)
	require.NoError(t, err)
	require.LessOrEqual(t, len(image.Candidates), returningLimits.Candidates)

	copies[replicaB] = p.second // the second copy appears (the #760 backfill)
	n.catchUp(t, p, gap, 40)
	require.EqualValues(t, gap, n.exec.finalized.Number)
}
