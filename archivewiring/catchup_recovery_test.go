package archivewiring

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"sync/atomic"
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
	limits   configuredprogress.JournalLimits
	store    *configuredprogress.Store
	exec     *restoreExecutorFixture
	worker   *FrontierWorker
	recovery *configuredadmission.ExecutionRecovery
}

func newReturningNode(t *testing.T, p *planFixture, replicas map[string]*archive.Store) *returningNode {
	t.Helper()
	return newReturningNodeWith(t, p, replicas, returningLimits, configuredadmission.RecoveryLimits{Blocks: 8, Bytes: 4 << 20, Deadline: 20 * time.Second})
}

func newReturningNodeWith(t *testing.T, p *planFixture, replicas map[string]*archive.Store, limits configuredprogress.JournalLimits, recoveryLimits configuredadmission.RecoveryLimits) *returningNode {
	t.Helper()
	returningLimits := limits
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
		Genesis: p.genesis, Limits: recoveryLimits,
		FetchArchive: p.source.FetchSuffix, ArchiveCatchUp: &CatchUp{Source: p.source, Frontier: worker}}
	return &returningNode{limits: limits, store: store, exec: exec, worker: worker, recovery: recovery}
}

// catchUp submits the gap's target certificate until it is admitted, as the node's admission does with each new certificate, and
// checks the journal stays inside its limits after every call.
func (n *returningNode) catchUp(t *testing.T, p *planFixture, height int, maxCalls int) int {
	t.Helper()
	ctx := context.Background()
	target := p.f.entries[height-1]
	for calls := 1; calls <= maxCalls; calls++ {
		err := n.recovery.AcquireForCertificate(ctx, target.ResultingUC, target.ResultingTR)
		image, loadErr := n.store.LoadJournal(ctx, p.f.context, n.limits)
		require.NoError(t, loadErr)
		require.LessOrEqual(t, len(image.Candidates), n.limits.Candidates, "call %d: candidates", calls)
		require.LessOrEqual(t, len(image.Observations), n.limits.Observations, "call %d: observations", calls)
		if err == nil {
			// the node recovers from the journal once the certificate is admitted: the executor ends finalized at the target
			head, err := n.recovery.Recover(ctx, target.ResultingUC)
			require.NoError(t, err)
			require.EqualValues(t, height, head.Number)
			return calls
		}
		var certified uint64
		for _, e := range image.Candidates {
			if e.Certified {
				certified = max(certified, e.Candidate.Number)
			}
		}
		require.GreaterOrEqual(t, n.exec.finalized.Number, certified, "call %d: every admitted page is executed and finalized in the same call", calls)
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
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap-fresh) // the archive lacks the newest six
	replicas := map[string]*archive.Store{replicaA: p.replica, replicaB: p.second}
	honest := prunedPeer(t, p, replicas, gap, gap-fresh)
	server, err := shardnode.NewJournalServer(honest, shardnode.DefaultJournalTransportLimits())
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

// TestArchiveCatchUp_CutsPagesAtTheByteBudget: rev2 B1. A page of P blocks can be more than one recovery's byte budget (64 blocks of
// 1 MiB against 64 MiB); admitting it would end in the terminal ErrRecoveryBudget. Here the budget is about two of the fixture's blocks.
func TestArchiveCatchUp_CutsPagesAtTheByteBudget(t *testing.T) {
	t.Parallel()
	const gap = 20
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap)
	raw := int64(len(p.f.entries[0].Candidate.Raw))
	n := newReturningNodeWith(t, p, map[string]*archive.Store{replicaA: p.replica, replicaB: p.second}, returningLimits,
		configuredadmission.RecoveryLimits{Blocks: 8, Bytes: 2*raw + raw/2, Deadline: 20 * time.Second})
	require.Greater(t, 3*raw, 2*raw+raw/2, "a page of three blocks is over the budget")
	n.catchUp(t, p, gap, 60)
	require.EqualValues(t, gap, n.exec.finalized.Number)
}

// TestArchiveCatchUp_TheObservationLimitBinds: a journal whose observation limit is tighter than its candidate limit still never
// overruns either (each admitted block brings its certificate).
func TestArchiveCatchUp_TheObservationLimitBinds(t *testing.T) {
	t.Parallel()
	const gap = 20
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap)
	n := newReturningNodeWith(t, p, map[string]*archive.Store{replicaA: p.replica, replicaB: p.second},
		configuredprogress.JournalLimits{Candidates: 16, Observations: 6, Bytes: 16 << 20}, configuredadmission.RecoveryLimits{Blocks: 8, Bytes: 4 << 20, Deadline: 20 * time.Second})
	n.catchUp(t, p, gap, 60)
	require.EqualValues(t, gap, n.exec.finalized.Number)
}

// TestArchiveCatchUp_TheLastPageAdmitsTheCertificate: with one recovery smaller than any remaining stretch, the catch-up's own last
// page reaches the target, and that call returns nil (the certificate is admitted) instead of asking for another round.
func TestArchiveCatchUp_TheLastPageAdmitsTheCertificate(t *testing.T) {
	t.Parallel()
	const gap = 14
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap)
	n := newReturningNodeWith(t, p, map[string]*archive.Store{replicaA: p.replica, replicaB: p.second}, returningLimits,
		configuredadmission.RecoveryLimits{Blocks: 2, Bytes: 4 << 20, Deadline: 20 * time.Second})
	ctx := context.Background()
	target := p.f.entries[gap-1]
	for calls := 1; ; calls++ {
		require.LessOrEqual(t, calls, 30)
		err := n.recovery.AcquireForCertificate(ctx, target.ResultingUC, target.ResultingTR)
		if err == nil {
			break
		}
		require.ErrorIs(t, err, configuredadmission.ErrRecoveryUnavailable)
	}
	image, err := n.store.LoadJournal(ctx, p.f.context, returningLimits)
	require.NoError(t, err)
	require.Equal(t, target.Candidate.Hash, image.Observations[len(image.Observations)-1].TargetHash, "the target's certificate is the journal's latest")
}

// TestArchiveCatchUp_FallsBackToAnEarlierCertifiedTarget: with no peer to name the top and the current target not archived yet, the walk
// starts from the target an earlier call was asked for, which the archive has by then.
func TestArchiveCatchUp_FallsBackToAnEarlierCertifiedTarget(t *testing.T) {
	t.Parallel()
	const gap, earlier = 29, 25
	ctx := context.Background()
	p := newPlanFixture(t, gap)
	p.serve(t, 1, earlier-1) // the earlier target is not archived yet either
	n := newReturningNode(t, p, map[string]*archive.Store{replicaA: p.replica, replicaB: p.second})
	first := p.f.entries[earlier-1]
	require.ErrorIs(t, n.recovery.AcquireForCertificate(ctx, first.ResultingUC, first.ResultingTR), configuredadmission.ErrRecoveryUnavailable)
	p.serve(t, earlier, earlier) // archived now; the newest four still are not
	target := p.f.entries[gap-1]
	for range 20 {
		err := n.recovery.AcquireForCertificate(ctx, target.ResultingUC, target.ResultingTR)
		require.ErrorIs(t, err, configuredadmission.ErrRecoveryUnavailable)
		if n.exec.finalized.Number >= earlier {
			break
		}
	}
	require.EqualValues(t, earlier, n.exec.finalized.Number, "the walk started from the earlier target and the catch-up reached it")
	p.serve(t, earlier+1, gap)
	n.catchUp(t, p, gap, 20)
}

// liarProvider serves a self-consistent tail whose oldest parent is fabricated, a different one on every request: the archive has none
// of them, and no refusal keyed on the top could stop it (rev2 B2 delta).
type liarProvider struct {
	honest configuredadmission.JournalProvider
	served *atomic.Uint64
}

func (l liarProvider) FetchJournal(ctx context.Context, req shardnode.JournalFetchRequest) ([]shardnode.JournalFetchEntry, error) {
	entries, err := l.honest.FetchJournal(ctx, req)
	if err != nil || len(entries) == 0 {
		return entries, err
	}
	n := l.served.Add(1)
	fake := bytes.Repeat([]byte{0x5a}, 32)
	binary.BigEndian.PutUint64(fake[24:], n)
	entries[0].Block.ParentHash = fake
	return entries, nil
}

// TestArchiveCatchUp_ALyingFirstPeerDoesNotHoldItUp: rev2 B2. The first provider's tail names a top the archive does not have; it is
// skipped after its walk fails, and the honest second provider's tail closes the gap.
func TestArchiveCatchUp_ALyingFirstPeerDoesNotHoldItUp(t *testing.T) {
	t.Parallel()
	const gap, fresh = 29, 6
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap-fresh)
	replicas := map[string]*archive.Store{replicaA: p.replica, replicaB: p.second}
	honest := prunedPeer(t, p, replicas, gap, gap-fresh)
	asker := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var providers []peer.ID
	liar := liarProvider{honest: honest, served: new(atomic.Uint64)}
	for _, provider := range []shardnode.JournalFetchProvider{liar, honest} {
		server, err := shardnode.NewJournalServer(provider, shardnode.DefaultJournalTransportLimits())
		require.NoError(t, err)
		host := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		server.Register(host)
		asker.Network().Peerstore().AddAddrs(host.ID(), host.MultiAddresses(), peerstore.PermanentAddrTTL)
		providers = append(providers, host.ID())
	}
	n := newReturningNode(t, p, replicas)
	n.recovery.Host, n.recovery.Providers = asker, providers
	n.catchUp(t, p, gap, 40)
	require.EqualValues(t, gap, n.exec.finalized.Number)
	require.LessOrEqual(t, liar.served.Load(), uint64(2), "the liar's tail is not asked for again within the refusal minute (the other request it may answer is the ordinary exact suffix at the end)")
}

// prunedPeer is a peer whose journal (the fixture's own, all gap blocks) has pruned through the archived height: it retains only the
// blocks the archive lacks.
func prunedPeer(t *testing.T, p *planFixture, replicas map[string]*archive.Store, gap, archived int) configuredadmission.JournalProvider {
	t.Helper()
	ctx := context.Background()
	peerLocal, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for h := 1; h <= gap; h++ {
		q, rec := p.f.record(t, h-1)
		require.NoError(t, peerLocal.Put(q, rec))
	}
	require.NoError(t, p.f.store.EnableFrontier(ctx, p.f.context, p.f.limits, frontier.Policy{Context: p.f.subject, Replicas: [2]string{replicaA, replicaB},
		Binding: CertifiedBinding{Context: p.f.context, Subject: p.f.subject}, Availability: fixtureAvailability{stores: replicas}}))
	top := p.ref(gap)
	peerWorker := &FrontierWorker{Journal: p.f.store, Context: p.f.context, Limits: p.f.limits, Archive: peerLocal, Subject: p.f.subject, Replicas: []peer.ID{"first", "second"},
		Finalized: func(context.Context) (shardnode.BlockRef, error) { return top, nil }}
	// a legacy two-replica worker reads back no copies itself (the journal does): cover exactly what the archive holds
	require.NoError(t, peerWorker.Advance(ctx, archived))
	pruned, err := p.f.store.LoadFrontier(ctx, p.f.context, p.f.limits)
	require.NoError(t, err)
	require.EqualValues(t, archived, pruned.Anchor.Height, "the peer retains only the blocks the archive lacks")
	return configuredadmission.JournalProvider{Store: p.f.store, Context: p.f.context, Limits: p.f.limits}
}

// TestArchiveCatchUp_AfterTheNodeHoldsTheNewCertificate is the order a restarted validator meets (the #769 acceptance, run 39826811339):
// its admission retains the network's newest certificate first, unresolved, and only then asks for the gap, so the journal no longer
// loads as a chain and the coordinator acquires the missing suffix behind the retained certificate (acquireMissing), not before it.
func TestArchiveCatchUp_AfterTheNodeHoldsTheNewCertificate(t *testing.T) {
	t.Parallel()
	const gap = 29
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap)
	n := newReturningNode(t, p, map[string]*archive.Store{replicaA: p.replica, replicaB: p.second})
	ctx := context.Background()
	target := p.f.entries[gap-1]
	o, err := rootinput.AuthenticateObservationV2(ctx, p.f.context.Observation, target.ResultingUC, target.ResultingTR)
	require.NoError(t, err)
	prepared, _, err := n.store.PrepareObservation(ctx, p.f.context, o)
	require.NoError(t, err)
	_, _, err = n.store.CommitObservation(prepared)
	require.NoError(t, err)
	n.catchUp(t, p, gap, 40)
	require.EqualValues(t, gap, n.exec.finalized.Number, "the executor is finalized at the target")
}

// TestArchiveCatchUp_AForkedFinalizedBlockFoundThroughThePlanIsAConflict: bft-core#843, rev's #862 item. An execution client comes back with a
// finalized block far below the journal's base (a gap longer than one recovery, so the replay goes through the catch-up plan) and that block
// is not on the certified chain: the plan's verified walk proves it, and the coordinator ends in the terminal conflict with nothing moved.
func TestArchiveCatchUp_AForkedFinalizedBlockFoundThroughThePlanIsAConflict(t *testing.T) {
	t.Parallel()
	const gap = 29
	p := newPlanFixture(t, gap)
	p.serve(t, 1, gap)
	n := newReturningNode(t, p, map[string]*archive.Store{replicaA: p.replica, replicaB: p.second})
	n.catchUp(t, p, gap, 40)
	image, err := n.store.LoadJournal(context.Background(), p.f.context, n.limits)
	require.NoError(t, err)
	require.NotNil(t, image.Frontier)
	require.Greater(t, image.Frontier.Anchor.Height, uint64(10), "the journal's base is far above the fork")

	// the production wiring maps a suffix that is too long to the unavailable class, which sends the replay to the plan
	n.recovery.FetchArchive = func(ctx context.Context, after shardnode.BlockRef, target []byte) ([]shardnode.JournalFetchEntry, error) {
		entries, err := p.source.FetchSuffix(ctx, after, target)
		if errors.Is(err, ErrArchiveSuffixTooLong) {
			return nil, errors.Join(configuredadmission.ErrRecoveryUnavailable, err)
		}
		if errors.Is(err, ErrArchiveRecoveryInvalid) {
			return nil, errors.Join(configuredadmission.ErrRecoveryInvalid, err)
		}
		return entries, err
	}
	forked := shardnode.BlockRef{Number: 2, Hash: bytes.Repeat([]byte{9}, 32), StateRoot: p.ref(2).StateRoot}
	n.exec.head, n.exec.finalized = forked, forked
	_, err = n.recovery.Recover(context.Background(), p.f.entries[gap-1].ResultingUC)
	require.ErrorIs(t, err, configuredadmission.ErrRecoveryConflict)
	require.ErrorIs(t, err, shardnode.ErrCertifiedChainForksAnchor)
	require.True(t, n.recovery.Terminal(err))
	require.Equal(t, forked, n.exec.finalized, "finality never retreats or moves on a conflict")
	require.Equal(t, forked, n.exec.head)
}
