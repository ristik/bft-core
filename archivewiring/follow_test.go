package archivewiring

import (
	"context"
	"errors"
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
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

type followRecord struct {
	q   archive.Request
	rec *archive.Record
}

// followSource is an archive replica holding the given records that serves a non-validator follower through its public read budget.
func followSource(t *testing.T, follower *network.Peer, f *wiringFixture, records []followRecord) peer.ID {
	t.Helper()
	remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	follower.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
	store, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	for _, r := range records {
		require.NoError(t, store.Put(r.q, r.rec))
	}
	server, err := NewServer(store, f.subject, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{"validator"}, DefaultLimits())
	require.NoError(t, err)
	require.NoError(t, server.SetPublicReads(Limits{Deadline: 5 * time.Second, Pending: 4, PerPeer: 2}))
	server.Register(context.Background(), remote)
	return remote.ID()
}

// The root-free head follower offers the newest certificate it can verify from any source, ignores a source whose newer head is forged,
// offers nothing twice, and offers nothing while the node is active.
func TestHeadFollowerOffersTheNewestVerifiedHeadOnly(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 4)
	follower := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var all, behind []followRecord
	for i := range f.entries {
		q, rec := f.record(t, i)
		all = append(all, followRecord{q, rec})
		if i < 2 {
			behind = append(behind, followRecord{q, rec})
		}
	}
	// a source whose newest record (block 4) carries a forged resulting certificate: a higher root round with a broken seal
	forged := append([]followRecord(nil), behind...)
	q4, rec4 := f.record(t, 3)
	bad := *rec4
	var result types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(rec4.ResultingUC, &result))
	result.UnicitySeal.RootChainRoundNumber += 100
	raw, err := types.Cbor.Marshal(&result)
	require.NoError(t, err)
	bad.ResultingUC = raw
	forged = append(forged, followRecord{q4, &bad})

	sources := []peer.ID{followSource(t, follower, f, forged), followSource(t, follower, f, behind), followSource(t, follower, f, all)}
	var offered []*types.UnicityCertificate
	active := false
	h := &HeadFollower{Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Host: follower, Limits: DefaultLimits(),
		Sources: func() []peer.ID { return sources }, Active: func() bool { return active },
		Offer: func(uc *types.UnicityCertificate, _ *certification.TechnicalRecord) bool {
			offered = append(offered, uc)
			return true
		}}
	require.True(t, h.Poll(context.Background()))
	require.Len(t, offered, 1)
	var want types.UnicityCertificate
	newest := uint64(0)
	for _, r := range all { // the newest genuine record's resulting certificate
		var uc types.UnicityCertificate
		require.NoError(t, types.Cbor.Unmarshal(r.rec.ResultingUC, &uc))
		if uc.GetRootRoundNumber() > newest {
			newest, want = uc.GetRootRoundNumber(), uc
		}
	}
	require.Equal(t, want.GetRootRoundNumber(), offered[0].GetRootRoundNumber(), "the newest verified head, not the forged one")
	require.Equal(t, want.InputRecord.BlockHash, offered[0].InputRecord.BlockHash)
	require.False(t, h.Poll(context.Background()), "the same head is not offered twice")

	active = true
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	h.offered, h.Interval = nil, 10*time.Millisecond
	require.NoError(t, h.Run(ctx))
	require.Len(t, offered, 1, "an active node takes its certificates from the roots, not the follower")
}

// The continuous root-free follower end to end below the process: a node that starts empty follows the archive head, the journal
// admission's archive catch-up executes the missing suffix, and as the chain grows the node extends from its retained journal and
// execution state. A process restart in the middle keeps the state and continues: nothing is restored or wiped, and the executor's
// finalized head only moves forward.
func TestHeadFollowerFollowsIncrementallyFromRetainedState(t *testing.T) {
	t.Parallel()
	const total = 24
	p := newPlanFixture(t, total)
	p.serve(t, 1, 10)
	n := newReturningNode(t, p, map[string]*archive.Store{replicaA: p.replica, replicaB: p.second})
	recovery := n.recovery
	var finalized []uint64
	offer := func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) bool {
		ctx := context.Background()
		for calls := 0; calls < 60; calls++ {
			err := recovery.AcquireForCertificate(ctx, uc, tr)
			if err == nil {
				head, err := recovery.Recover(ctx, uc)
				require.NoError(t, err)
				finalized = append(finalized, head.Number)
				return true
			}
			require.ErrorIs(t, err, configuredadmission.ErrRecoveryUnavailable)
			require.False(t, recovery.Terminal(err), "%v", err)
		}
		t.Fatal("the followed head was not reached")
		return false
	}
	h := &HeadFollower{Binding: CertifiedBinding{Context: p.f.context, Subject: p.f.subject}, Host: p.source.Host, Limits: DefaultLimits(),
		Sources: func() []peer.ID { return p.source.Replicas }, Offer: offer}

	require.True(t, h.Poll(context.Background()))
	require.EqualValues(t, 10, n.exec.finalized.Number, "followed from empty to the archive head")

	p.serve(t, 11, 17)
	require.True(t, h.Poll(context.Background()))
	require.EqualValues(t, 17, n.exec.finalized.Number, "extended from the retained state")

	// a process restart that keeps its state: a new coordinator over the same journal and execution client
	recovery = &configuredadmission.ExecutionRecovery{Store: n.store, Context: p.f.context, JournalLimits: n.limits, Executor: n.exec, Gate: shardnode.NewFinalityGate(),
		Genesis: p.genesis, Limits: n.recovery.Limits, FetchArchive: p.source.FetchSuffix, ArchiveCatchUp: &CatchUp{Source: p.source, Frontier: n.worker}}
	h.offered = nil
	p.serve(t, 18, total)
	require.True(t, h.Poll(context.Background()))
	require.EqualValues(t, total, n.exec.finalized.Number, "continued after the restart without a restore")
	require.Equal(t, []uint64{10, 17, total}, finalized, "the finalized head only moves forward")
	require.False(t, h.Poll(context.Background()), "nothing newer: nothing offered")
}

// An offered head is suppressed only once the node durably holds it: when its admission fails (a transient missing dependency) and the
// source head stays where it is, the same head is offered again after the retry wait, and not before; once held, never again.
func TestHeadFollowerReoffersAnUnacceptedHead(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 2)
	follower := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var records []followRecord
	for i := range f.entries {
		q, rec := f.record(t, i)
		records = append(records, followRecord{q, rec})
	}
	source := followSource(t, follower, f, records)
	offers, held := 0, false
	now := time.Unix(1000, 0)
	h := &HeadFollower{Binding: CertifiedBinding{Context: f.context, Subject: f.subject}, Host: follower, Limits: DefaultLimits(),
		Sources: func() []peer.ID { return []peer.ID{source} }, Retry: 5 * time.Second, now: func() time.Time { return now },
		Offer:    func(*types.UnicityCertificate, *certification.TechnicalRecord) bool { offers++; return true }, // queued, then admission fails
		Accepted: func(*types.UnicityCertificate) bool { return held }}
	require.True(t, h.Poll(context.Background()))
	require.False(t, h.Poll(context.Background()), "not again before the retry wait")
	now = now.Add(5 * time.Second)
	require.True(t, h.Poll(context.Background()), "the dependency is back: the unchanged head is offered again")
	held = true
	now = now.Add(time.Minute)
	require.False(t, h.Poll(context.Background()), "held: never offered again")
	require.Equal(t, 2, offers)
}

// freshNode is a returning node whose journal is fresh: no bootstrap certificate, as on a joiner that never contacted a root.
func freshNode(t *testing.T, p *planFixture) *returningNode {
	t.Helper()
	ctx := context.Background()
	store, err := configuredprogress.OpenConfiguredV2(t.TempDir()+"/journal.db", configuredprogress.Settings{Retain: 8})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	_, _, err = store.Initialize(ctx, p.f.context)
	require.NoError(t, err)
	require.NoError(t, store.EnableJournal(ctx, p.f.context, returningLimits))
	names := []peer.ID{"first", "second"}
	policy := frontier.Policy{Context: p.f.subject, Replicas: [2]string{names[0].String(), names[1].String()},
		Binding: CertifiedBinding{Context: p.f.context, Subject: p.f.subject}, Availability: fixtureAvailability{stores: map[string]*archive.Store{replicaA: p.replica, replicaB: p.second}}}
	require.NoError(t, store.EnableFrontier(ctx, p.f.context, returningLimits, policy))
	exec := newRestoreExecutorFixture(p.genesis)
	worker := &FrontierWorker{Journal: store, Context: p.f.context, Limits: returningLimits, Archive: p.local, Subject: p.f.subject, Replicas: names, Finalized: exec.Finalized}
	recovery := &configuredadmission.ExecutionRecovery{Store: store, Context: p.f.context, JournalLimits: returningLimits, Executor: exec, Gate: shardnode.NewFinalityGate(),
		Genesis: p.genesis, Limits: configuredadmission.RecoveryLimits{Blocks: 8, Bytes: 4 << 20, Deadline: 20 * time.Second},
		FetchArchive: p.source.FetchSuffix, ArchiveCatchUp: &CatchUp{Source: p.source, Frontier: worker}}
	return &returningNode{limits: returningLimits, store: store, exec: exec, worker: worker, recovery: recovery}
}

// admit is what the node's journal admission does with an offered certificate: authenticate, prepare, catch up the gap, commit.
func (n *returningNode) admit(t *testing.T, p *planFixture, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	ctx := context.Background()
	o, err := rootinput.AuthenticateObservationV2(ctx, p.f.context.Observation, uc, tr)
	if err != nil {
		return err
	}
	prepared, _, err := n.store.PrepareObservation(ctx, p.f.context, o)
	if errors.Is(err, configuredprogress.ErrUnavailable) || errors.Is(err, configuredprogress.ErrConflict) {
		for calls := 0; calls < 60; calls++ {
			if err = n.recovery.AcquireForCertificate(ctx, uc, tr); err == nil {
				break
			}
		}
		if err != nil {
			return err
		}
		prepared, _, err = n.store.PrepareObservation(ctx, p.f.context, o)
	}
	if err != nil {
		return err
	}
	_, _, err = n.store.CommitObservation(prepared)
	return err
}

// #1050, failure 1: a joiner's journal is fresh (its bootstrap certificate normally comes from a root quorum, which a non-active follower
// never asks). Without a root-free bootstrap the archive head is never admitted; with it, the follower takes the bootstrap certificate from
// its sources' first certified record, and the head is then admitted and executed through the archive catch-up.
func TestAFreshFollowerBootstrapsFromItsSourcesWithoutARoot(t *testing.T) {
	t.Parallel()
	const total = 12
	p := newPlanFixture(t, total)
	p.serve(t, 1, total)

	stuck := freshNode(t, p)
	head := p.f.entries[total-1]
	err := stuck.admit(t, p, head.ResultingUC, head.ResultingTR)
	require.Error(t, err, "the failure of the exit gate: a fresh journal must begin with the bootstrap certificate")

	n := freshNode(t, p)
	needs := true
	h := &HeadFollower{Binding: CertifiedBinding{Context: p.f.context, Subject: p.f.subject}, Host: p.source.Host, Limits: DefaultLimits(),
		Sources: func() []peer.ID { return p.source.Replicas }, NeedsBootstrap: func() bool { return needs },
		Offer: func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) bool {
			require.NoError(t, n.admit(t, p, uc, tr))
			return true
		}}
	require.True(t, h.Poll(context.Background()), "the bootstrap certificate is offered")
	st, _, err := n.store.Load(context.Background(), p.f.context)
	require.NoError(t, err)
	_, observed := st.Observed()
	require.True(t, observed, "admitted as the journal's bootstrap certificate")
	needs = false
	require.True(t, h.Poll(context.Background()), "then the head")
	n.catchUp(t, p, total, 40) // the admission's retries page the gap in from the archive
	require.EqualValues(t, total, n.exec.finalized.Number, "executed to the archive head, root-free")
}
