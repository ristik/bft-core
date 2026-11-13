package archivewiring

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The tests of this file are not parallel: each runs several libp2p hosts and independent journals, and in parallel they starve the
// time-bounded catch-up tests of this package. Sequential tests run before the parallel ones.

// rotationNet is a writer with a local archive, a publisher and a frontier worker following a versioned replica policy, and n archive
// replicas (bft-core#1030). Each replica is an independent validator: its own journal of the same certified chain, its own archive, and
// the production verifier chain (its journal and coverage, then the verified historical import over its own archive). A replica accepts
// a publication only while accept[i] is set (a lagging replica refuses), and its journal knows no block at or below floor[i] (a
// replacement restored at that height has no association below it; its restored history is whatever its archive holds). A stopped
// replica neither answers nor accepts.
type rotationNet struct {
	f        *wiringFixture
	sender   *network.Peer
	remotes  []*network.Peer
	peers    []peer.ID
	stores   []*archive.Store
	journals []*wiringFixture
	accept   []*atomic.Bool
	bundles  []*atomic.Bool // the replica accepts activation bundles
	floor    []*atomic.Uint64
	journal  atomic.Pointer[configuredprogress.Store]
	local    *archive.Store
	policy   *ReplicaPolicy
	worker   *FrontierWorker
	stopPub  func()
}

func newRotationNet(t *testing.T, blocks, n int, holds []bool) *rotationNet {
	t.Helper()
	f := newWiringFixture(t, blocks)
	x := &rotationNet{f: f, sender: testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))}
	x.journal.Store(f.store)
	var err error
	x.local, err = archive.Open(t.TempDir())
	require.NoError(t, err)
	for i := 0; i < n; i++ {
		remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		x.remotes, x.peers = append(x.remotes, remote), append(x.peers, remote.ID())
		store, err := archive.Open(t.TempDir())
		require.NoError(t, err)
		own := newWiringFixtureOpts(t, wiringOpts{blocks: blocks, limits: f.limits, chain: f.chain})
		x.stores, x.journals = append(x.stores, store), append(x.journals, own)
		accept, bundles, floor := &atomic.Bool{}, &atomic.Bool{}, &atomic.Uint64{}
		accept.Store(true)
		bundles.Store(true)
		x.accept, x.bundles, x.floor = append(x.accept, accept), append(x.bundles, bundles), append(x.floor, floor)
		journal := JournalVerifier(own.store, own.context, own.limits, own.subject)
		history := HistoryVerifier(store, CertifiedBinding{Context: own.context, Subject: own.subject})
		verify := ChainVerifiers(func(ctx context.Context, q archive.Request, rec *archive.Record) error {
			var header gethtypes.Header
			if rlp.DecodeBytes(rec.Header, &header) != nil || header.Number.Uint64() <= floor.Load() {
				return fmt.Errorf("%w: below this replica's restore base", ErrUncertified)
			}
			return journal(ctx, q, rec)
		}, history)
		lagging := func(ctx context.Context, q archive.Request, rec *archive.Record) error {
			if !accept.Load() {
				return fmt.Errorf("%w: this replica lags", ErrUncertified)
			}
			return verify(ctx, q, rec)
		}
		x.sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		server, err := NewServer(store, f.subject, lagging, []peer.ID{x.sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.SetBundleVerifier(func(context.Context, archive.BundleRequest, []byte) error {
			if !bundles.Load() {
				return errors.New("this replica does not take bundles now")
			}
			return nil
		})
		server.Register(context.Background(), remote)
	}
	for i := range f.entries {
		q, rec := f.record(t, i)
		require.NoError(t, x.local.Put(q, rec))
		for j, s := range x.stores {
			if j < len(holds) && holds[j] {
				require.NoError(t, s.Put(q, rec))
			}
		}
	}
	t.Cleanup(func() {
		if x.stopPub != nil {
			x.stopPub()
		}
	})
	return x
}

func (x *rotationNet) ids(members []int) []peer.ID {
	var out []peer.ID
	for _, i := range members {
		out = append(out, x.peers[i])
	}
	return out
}

// derive stands in for archivepolicy.Select: any replica set, under a digest named by tag.
func derive(tag string) ([32]byte, []byte) { return sha256.Sum256([]byte(tag)), []byte(tag) }

// start creates the policy and the frontier under it, and the worker.
func (x *rotationNet) start(t *testing.T, members []int, tag string) {
	t.Helper()
	digest, encoded := derive(tag)
	var err error
	x.policy, err = NewReplicaPolicy(x.ids(members), digest, encoded, 0)
	require.NoError(t, err)
	_, err = EnableDerivedFrontier(context.Background(), x.journal.Load(), x.f.context, x.f.limits, x.f.subject, x.sender, DefaultLimits(), x.policy, x.policy.Snapshot())
	require.NoError(t, err)
	x.newWorker()
}

func (x *rotationNet) newWorker() {
	snap := x.policy.Snapshot()
	x.worker = &FrontierWorker{Journal: x.journal.Load(), Context: x.f.context, Limits: x.f.limits, Archive: x.local, Subject: x.f.subject,
		Replicas: snap.Replicas, PolicyDigest: snap.Digest, Policy: x.policy, Host: x.sender, TransportLimits: DefaultLimits()}
}

// switchTo is an activation that derives another replica set.
func (x *rotationNet) switchTo(t *testing.T, members []int, tag string, epoch uint64) {
	t.Helper()
	digest, encoded := derive(tag)
	switched, err := x.policy.Switch(x.ids(members), digest, encoded, epoch)
	require.NoError(t, err)
	require.True(t, switched)
}

// publish runs the publisher, following the policy, until the test ends.
func (x *rotationNet) publish(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	p := &Publisher{Journal: x.journal.Load(), Context: x.f.context, JournalLimits: x.f.limits, Archive: x.local, Subject: x.f.subject, Host: x.sender,
		Replicas: x.policy.Snapshot().Replicas, Policy: x.policy, Limits: DefaultLimits()}
	done := make(chan struct{})
	go func() { defer close(done); _ = p.Run(ctx) }()
	x.stopPub = func() { cancel(); <-done }
}

func (x *rotationNet) stop(t *testing.T, i int) {
	t.Helper()
	require.NoError(t, x.remotes[i].Close())
	x.sender.Network().Peerstore().ClearAddrs(x.peers[i])
	_ = x.sender.Network().ClosePeer(x.peers[i])
}

func (x *rotationNet) frontier(t *testing.T) configuredprogress.FrontierSnapshot {
	t.Helper()
	snap, err := x.journal.Load().LoadFrontier(context.Background(), x.f.context, x.f.limits)
	require.NoError(t, err)
	return snap
}

func (x *rotationNet) migration(t *testing.T) configuredprogress.ArchiveMigration {
	t.Helper()
	m, found, err := x.journal.Load().LoadArchiveMigration(context.Background(), x.f.context, x.f.limits)
	require.NoError(t, err)
	require.True(t, found)
	return m
}

// passUntil runs worker passes until cond holds.
func (x *rotationNet) passUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	var last error
	require.Eventually(t, func() bool {
		last = x.worker.Pass(context.Background())
		return cond()
	}, 30*time.Second, 100*time.Millisecond, "%s (last pass: %v)", what, last)
}

func (x *rotationNet) anchoredAt(t *testing.T, height uint64) func() bool {
	return func() bool {
		snap := x.frontier(t)
		return snap.Anchor != nil && snap.Anchor.Height == height && snap.Floor == height && !snap.Anchor.Migrated()
	}
}

func (x *rotationNet) complete(t *testing.T) func() bool {
	return func() bool { return x.migration(t).Complete() && len(x.policy.Snapshot().Retained) == 0 }
}

func names2(r *frontier.Record) []string { return []string{r.Acks[0].Replica, r.Acks[1].Replica} }

// The incident shape of bft-core#1030: of the writer's three replicas one retires (and goes away) while another is unavailable. Under the
// startup policy only one copy is left and the frontier, and with it the bounded journal, stops for good. The activation switches the
// policy to the installed assignment's replicas: the replacement receives the pending blocks and the promised history, the frontier
// moves on with two copies (never one), and the retired replica stops being a holder.
func TestRetirementWithAnotherReplicaUnavailableSwitchesWithoutStall(t *testing.T) {
	x := newRotationNet(t, 7, 4, []bool{true, true, true, false})
	x.start(t, []int{0, 1, 2}, "p0")
	require.NoError(t, x.worker.Pass(context.Background()))
	require.Equal(t, uint64(passCoverage), x.frontier(t).Anchor.Height)

	x.stop(t, 2) // retired and gone
	x.stop(t, 1) // unavailable
	for i := 0; i < 3; i++ {
		err := x.worker.Pass(context.Background())
		require.True(t, errors.Is(err, frontier.ErrAcknowledgment) || errors.Is(err, frontier.ErrUnavailable), "the startup policy is left with one copy: the old behaviour stalls here: %v", err)
	}
	require.Equal(t, uint64(passCoverage), x.frontier(t).Anchor.Height)

	x.switchTo(t, []int{0, 1, 3}, "p1", 2)
	require.Equal(t, []peer.ID{x.peers[2]}, x.policy.Snapshot().Retained, "until the worker adopts the switch every earlier replica is still a holder")
	x.publish(t)
	x.passUntil(t, "the frontier reaches the head on the staying replica and the replacement", x.anchoredAt(t, 7))
	anchor := x.frontier(t).Anchor
	require.Equal(t, sha256.Sum256([]byte("p1")), anchor.PolicyDigest)
	require.ElementsMatch(t, []string{x.peers[0].String(), x.peers[3].String()}, names2(anchor))
	x.passUntil(t, "the history promised under the old policy is verified on the replacement", x.complete(t))
	require.False(t, x.policy.Holder(x.peers[2]))
	require.NoError(t, x.worker.Pass(context.Background()))
	report := PolicyReportOf(x.policy.Snapshot())
	require.True(t, report.MigrationDone)
	require.Zero(t, report.MigrationBacklog)
}

// A retiring replica that is still up stays a holder of the promised history while the replacement lags and another replica is down:
// the promise keeps two copies (the retained holder counts, K is never lowered), new blocks wait for two current copies rather than
// being covered by fewer, and the retired machine is reported as still needed. Once the replacement catches up, the frontier moves to
// the head, the history is migrated to it, and the retired replica is released and may be powered off.
func TestRetainedHolderCoversThePromiseUntilTheReplacementCatchesUp(t *testing.T) {
	x := newRotationNet(t, 7, 4, []bool{true, true, true, false})
	x.start(t, []int{0, 1, 2}, "p0")
	require.NoError(t, x.worker.Pass(context.Background()))
	require.Equal(t, uint64(4), x.frontier(t).Anchor.Height)

	x.accept[3].Store(false) // the replacement lags
	x.stop(t, 2)             // another replica is down
	x.switchTo(t, []int{0, 2, 3}, "p1", 2)
	x.publish(t)
	for i := 0; i < 5; i++ {
		err := x.worker.Pass(context.Background())
		require.ErrorIs(t, err, frontier.ErrAcknowledgment, "pass %d: one current copy of the new blocks is not enough", i)
	}
	snap := x.frontier(t)
	require.Equal(t, uint64(4), snap.Anchor.Height, "nothing is covered by fewer than two copies")
	require.True(t, snap.Anchor.Migrated(), "the anchor is historical evidence of the old policy")
	require.NoError(t, x.worker.audit(context.Background()), "the promised history keeps two copies: the staying replica and the retained one")
	m := x.migration(t)
	require.False(t, m.Complete())
	require.Equal(t, []string{x.peers[1].String()}, m.Retained)
	require.True(t, x.policy.Holder(x.peers[1]), "the retired replica keeps archive-service access while it holds promised copies")
	require.Equal(t, []string{x.peers[1].String()}, PolicyReportOf(x.policy.Snapshot()).Retained)

	x.accept[3].Store(true) // the replacement caught up
	x.passUntil(t, "the frontier reaches the head", x.anchoredAt(t, 7))
	x.passUntil(t, "the migration completes", x.complete(t))
	require.False(t, x.policy.Holder(x.peers[1]))
	x.stop(t, 1) // the retired machine is powered off
	x.worker.auditCursor = 0
	require.NoError(t, x.worker.Pass(context.Background()), "the promise no longer depends on the retired replica")
}

// A replacement whose journal knows nothing at or below height 4 (restored there) and whose archive does not hold those blocks either
// (nothing to import from) cannot take the history, while it takes every new block: the frontier moves on at once, and the history
// stays with the retained holder until another current replica holds it. (A real restore holds them: see the verified import test.)
func TestReplacementWithoutTheHistoryKeepsTheRetainedHolder(t *testing.T) {
	x := newRotationNet(t, 7, 4, []bool{true, true, false, false})
	x.start(t, []int{0, 1}, "p0") // a three-validator shard: a two-of-two policy
	require.NoError(t, x.worker.Pass(context.Background()))
	require.Equal(t, uint64(4), x.frontier(t).Anchor.Height)

	x.floor[3].Store(4)      // the replacement was restored at height 4
	x.accept[2].Store(false) // and the third replica lags
	x.switchTo(t, []int{0, 2, 3}, "p1", 2)
	x.publish(t)
	x.passUntil(t, "new blocks are covered by the staying replica and the replacement", x.anchoredAt(t, 7))
	for i := 0; i < 3; i++ {
		require.NoError(t, x.worker.Pass(context.Background()))
	}
	m := x.migration(t)
	require.False(t, m.Complete(), "heights 1-4 have one current copy")
	require.Equal(t, uint64(4), m.Since)
	require.Zero(t, m.Through)
	require.True(t, x.policy.Holder(x.peers[1]))

	x.accept[2].Store(true)
	x.passUntil(t, "the lagging replica takes the history", x.complete(t))
	require.False(t, x.policy.Holder(x.peers[1]))
}

// A join that adds a replica: a two-of-two policy (any outage stops pruning) becomes two of three. Nothing earlier is retained, so the
// switch is complete at once, the new replica receives everything, and from then on one stopped replica no longer stops the frontier.
func TestJoinAddsAReplica(t *testing.T) {
	x := newRotationNet(t, 7, 3, []bool{true, true, false})
	x.start(t, []int{0, 1}, "p0")
	require.NoError(t, x.worker.Pass(context.Background()))
	require.Equal(t, uint64(4), x.frontier(t).Anchor.Height)

	x.switchTo(t, []int{0, 1, 2}, "p1", 2)
	x.stop(t, 1) // under the two-of-two policy this alone stops the frontier
	x.publish(t)
	x.passUntil(t, "the frontier reaches the head with one replica stopped", x.anchoredAt(t, 7))
	m := x.migration(t)
	require.True(t, m.Complete(), "a superset retains nothing")
	require.Empty(t, x.policy.Snapshot().Retained)
	require.ElementsMatch(t, []string{x.peers[0].String(), x.peers[2].String()}, names2(x.frontier(t).Anchor))
}

// The upgrade path: records written by a node that never persisted its policy (the startup-only derivation), and a restart into an
// assignment where neither acknowledger of the durable anchor is a replica any more (zero overlap; refused with frontier.ErrContext before
// the lineage existed). The lineage is read from the coverage, both old acknowledgers are retained holders, and the migration moves the
// promise to the new replicas before releasing them.
func TestRestartWithOldPolicyRecordsAndZeroOverlap(t *testing.T) {
	ctx := context.Background()
	x := newRotationNet(t, 7, 5, []bool{true, true, false, false, false})
	old := x.ids([]int{0, 1})
	oldDigest, _ := derive("startup")
	require.NoError(t, x.f.store.EnableFrontier(ctx, x.f.context, x.f.limits, frontier.Policy{Context: x.f.subject, Eligible: names(old), PolicyDigest: oldDigest,
		Binding: CertifiedBinding{Context: x.f.context, Subject: x.f.subject}, Availability: ReplicaAvailability{Context: ctx, Host: x.sender, Replicas: old, Limits: DefaultLimits()}}))
	legacy := &FrontierWorker{Journal: x.f.store, Context: x.f.context, Limits: x.f.limits, Archive: x.local, Subject: x.f.subject, Replicas: old, PolicyDigest: oldDigest, Host: x.sender, TransportLimits: DefaultLimits()}
	require.NoError(t, legacy.Pass(ctx))
	require.Equal(t, uint64(4), x.frontier(t).Anchor.Height)

	// restart under the new binary into the installed assignment {2, 3, 4}
	require.NoError(t, x.f.store.Close())
	reopened, err := configuredprogress.OpenConfiguredV2(x.f.path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	require.NoError(t, reopened.EnableJournal(ctx, x.f.context, x.f.limits))
	x.journal.Store(reopened)
	x.start(t, []int{2, 3, 4}, "p1")
	m := x.migration(t)
	require.ElementsMatch(t, names(old), m.Retained)
	require.ElementsMatch(t, names(old), m.Lineage)
	require.Equal(t, uint64(4), m.Since)
	require.True(t, x.frontier(t).Anchor.Migrated())
	x.publish(t)
	x.passUntil(t, "the frontier reaches the head on the new replicas", x.anchoredAt(t, 7))
	x.passUntil(t, "the history moves to the new replicas", x.complete(t))
	x.stop(t, 0)
	x.stop(t, 1)
	x.worker.auditCursor = 0
	require.NoError(t, x.worker.Pass(ctx))
}

// A migration interrupted by crashes (at the adoption commit, at a progress commit, and by a process restart while the replacement lags)
// resumes where its durable record says: the restart keeps the persisted policy and its switch height instead of re-deriving a new digest
// and starting over, retained holders stay retained throughout, and the migration completes once the replacement catches up.
func TestCrashInterruptedMigrationResumes(t *testing.T) {
	ctx := context.Background()
	x := newRotationNet(t, 7, 4, []bool{true, true, false, false})
	x.start(t, []int{0, 1, 2}, "p0")
	require.NoError(t, x.worker.Pass(ctx))

	crash := func(point string, times int) {
		var n atomic.Int32
		x.journal.Load().SetFaultHook(func(p string) error {
			if p == point && n.Add(1) <= int32(times) {
				return errors.New("crash: " + p)
			}
			return nil
		})
	}
	x.accept[2].Store(false)
	x.accept[3].Store(false)
	x.switchTo(t, []int{0, 2, 3}, "p1", 2)
	crash("before-archive-policy-commit", 1)
	require.ErrorContains(t, x.worker.Pass(ctx), "crash")
	require.Equal(t, sha256.Sum256([]byte("p0")), x.migration(t).Digest, "the policy in force is unchanged by a crashed adoption")
	require.ErrorIs(t, x.worker.Pass(ctx), frontier.ErrAcknowledgment, "the next pass adopts it; one current copy is not enough for new blocks")
	m := x.migration(t)
	require.Equal(t, sha256.Sum256([]byte("p1")), m.Digest)
	require.Equal(t, []string{x.peers[1].String()}, m.Retained)
	require.False(t, m.Complete())

	// R2 catches up and takes the history, but every progress commit crashes; then the process restarts.
	x.accept[2].Store(true)
	crash("before-archive-migration-commit", 1000)
	for i := 0; i < 3; i++ {
		_ = x.worker.Pass(ctx)
	}
	require.Zero(t, x.migration(t).Through, "no progress commit survived")
	require.Equal(t, m.Since, x.migration(t).Since)
	require.NoError(t, x.journal.Load().Close())
	reopened, err := configuredprogress.OpenConfiguredV2(x.f.path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	require.NoError(t, reopened.EnableJournal(ctx, x.f.context, x.f.limits))
	x.journal.Store(reopened)
	persisted := x.migration(t)
	require.Equal(t, m, persisted)
	// the CLI seeds the policy from the record, then re-derives from the installed set (the same replicas: no switch)
	x.policy, err = NewReplicaPolicy(x.ids([]int{0, 1, 2}), sha256.Sum256([]byte("p0")), []byte("p0"), 0)
	require.NoError(t, err)
	require.NoError(t, x.policy.Seed(x.ids([]int{0, 2, 3}), persisted.Digest, persisted.Policy, 2))
	_ = m
	switched, err := x.policy.Switch(x.ids([]int{0, 2, 3}), sha256.Sum256([]byte("p1 at a later epoch")), []byte("p1 at a later epoch"), 3)
	require.NoError(t, err)
	require.False(t, switched, "the same replicas keep the persisted policy and its digest")
	_, err = EnableDerivedFrontier(ctx, reopened, x.f.context, x.f.limits, x.f.subject, x.sender, DefaultLimits(), x.policy, x.policy.Snapshot())
	require.NoError(t, err)
	require.Equal(t, persisted, x.migration(t), "a restart does not restart the migration")
	require.True(t, x.policy.Holder(x.peers[1]))
	x.newWorker()

	x.accept[3].Store(true)
	x.publish(t)
	x.passUntil(t, "the migration completes after the restart", x.complete(t))
	x.passUntil(t, "the frontier reaches the head", x.anchoredAt(t, 7))
}

func TestReplicaPolicySwitchAndAdopt(t *testing.T) {
	a, b, c, d := peer.ID("a"), peer.ID("b"), peer.ID("c"), peer.ID("d")
	legacy, err := NewReplicaPolicy([]peer.ID{a, b}, [32]byte{}, nil, 0)
	require.NoError(t, err)
	switched, err := legacy.Switch([]peer.ID{a, c}, [32]byte{1}, []byte{1}, 1)
	require.NoError(t, err)
	require.False(t, switched, "an explicit pair never switches")

	p, err := NewReplicaPolicy([]peer.ID{a, b, c}, [32]byte{1}, []byte{1}, 0)
	require.NoError(t, err)
	changed := p.Changed()
	switched, err = p.Switch([]peer.ID{a, b, c}, [32]byte{2}, []byte{2}, 1)
	require.NoError(t, err)
	require.False(t, switched, "the same replicas keep the policy")
	switched, err = p.Switch([]peer.ID{a, c, d}, [32]byte{3}, []byte{3}, 2)
	require.NoError(t, err)
	require.True(t, switched)
	<-changed
	s := p.Snapshot()
	require.Equal(t, uint64(2), s.Version)
	require.Equal(t, []peer.ID{b}, s.Retained)
	require.Equal(t, []peer.ID{a, c, d, b}, s.Readable())
	require.True(t, p.Holder(b))
	require.False(t, p.Holder(a), "a current replica is not a retained holder")
	p.adopt([32]byte{1}, configuredprogress.ArchiveMigration{Retained: nil, Since: 1, Through: 1})
	require.True(t, p.Holder(b), "the state of a replaced policy is ignored")
	p.adopt([32]byte{3}, configuredprogress.ArchiveMigration{Retained: nil, Since: 1, Through: 1})
	require.False(t, p.Holder(b))
	_, err = p.Switch([]peer.ID{a}, [32]byte{4}, []byte{4}, 3)
	require.ErrorIs(t, err, ErrConfig)
}

// The incident shape with a restored replacement (astra review of #1034): of the old replicas A/B/C, C retires and is gone and B is
// unavailable; the replacement D was restored at height 4, so its journal has no association for heights 1-4, and its archive holds
// them as its restore authenticated them, in another valid representation than the writer promised. The verified historical import
// takes the writer's exact representation next to D's own: the history reaches two current copies (A and D), the frontier reaches the
// head, and C is released, with B still down.
func TestRestoredReplacementTakesTheHistoryByVerifiedImport(t *testing.T) {
	var err error
	x := newRotationNet(t, 7, 4, []bool{true, true, true, false})
	x.start(t, []int{0, 1, 2}, "p0")
	require.NoError(t, x.worker.Pass(context.Background()))
	require.Equal(t, uint64(4), x.frontier(t).Anchor.Height)

	// D's restored history: heights 1-4 as another validator first associated them (a repeat certificate at a later root round)
	for i, e := range x.f.entries {
		if e.Candidate.Number <= 4 {
			q, rec := x.f.record(t, i)
			variant := *rec
			var uc types.UnicityCertificate
			require.NoError(t, types.Cbor.Unmarshal(rec.ResultingUC, &uc))
			repeat, repeatTR := signWiring(t, x.f.chain, uc.InputRecord, e.Candidate.Number+1, uc.GetRootRoundNumber()+50)
			variant.ResultingUC, err = types.Cbor.Marshal(repeat)
			require.NoError(t, err)
			variant.ResultingTR, err = types.Cbor.Marshal(repeatTR)
			require.NoError(t, err)
			require.NoError(t, CertifiedBinding{Context: x.f.context, Subject: x.f.subject}.VerifyCertified(mustCertified(t, q, &variant), &variant), "a valid representation")
			d, _ := archive.ManifestDigest(q, &variant)
			wd, _ := archive.ManifestDigest(q, rec)
			require.NotEqual(t, wd, d, "another representation than the writer's")
			require.NoError(t, x.stores[3].Put(q, &variant))
		}
	}
	x.floor[3].Store(4)
	x.stop(t, 2) // C retired and gone
	x.stop(t, 1) // B unavailable
	x.switchTo(t, []int{0, 1, 3}, "p1", 2)
	x.publish(t)
	x.passUntil(t, "the frontier reaches the head", x.anchoredAt(t, 7))
	x.passUntil(t, "the history is imported by the replacement and C released", x.complete(t))
	for i, e := range x.f.entries {
		if e.Candidate.Number <= 4 {
			q, rec := x.f.record(t, i)
			d, _ := archive.ManifestDigest(q, rec)
			_, err := x.stores[3].GetExact(q, d)
			require.NoError(t, err, "height %d: the writer's exact representation", e.Candidate.Number)
		}
	}
	require.False(t, x.policy.Holder(x.peers[2]))
}

// The import never takes a block the replica does not already hold authenticated, nor a record that differs from the held block, nor
// certificates that do not certify it.
func TestHistoryVerifierRefusesUnknownOrDifferentBlocks(t *testing.T) {
	f := newWiringFixture(t, 3)
	store, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	verify := HistoryVerifier(store, CertifiedBinding{Context: f.context, Subject: f.subject})
	q, rec := f.record(t, 1)
	require.ErrorIs(t, verify(context.Background(), q, rec), ErrUncertified, "an unknown block")
	require.NoError(t, store.Put(q, rec))
	require.NoError(t, verify(context.Background(), q, rec))
	changed := *rec
	changed.Body = append([]byte(nil), rec.Body...)
	changed.Body[len(changed.Body)-1] ^= 1
	require.ErrorIs(t, verify(context.Background(), q, &changed), ErrBinding, "another body")
	_, wrong := f.record(t, 2)
	forged := *rec
	forged.ResultingUC, forged.ResultingTR = wrong.ResultingUC, wrong.ResultingTR
	require.ErrorIs(t, verify(context.Background(), q, &forged), ErrBinding, "certificates of another block")
}

// Activation between the worker's policy snapshot and its adoption (astra review of #1034, finding 1): the worker adopts the snapshot it
// took, whole, and the next pass adopts the newer policy. The newer policy's migration is never completed by a verification on the
// older policy's replicas: its replicas D and E hold nothing, so its earlier replicas stay retained.
func TestActivationBetweenSnapshotAndAdoptionNeverMixesPolicies(t *testing.T) {
	x := newRotationNet(t, 7, 5, []bool{true, true, true, false, false})
	x.start(t, []int{0, 1, 2}, "p0")
	require.NoError(t, x.worker.Pass(context.Background()))
	x.accept[3].Store(false)
	x.accept[4].Store(false)
	x.switchTo(t, []int{0, 1, 3}, "p1", 2)
	var once atomic.Bool
	x.worker.beforeAdopt = func() {
		if once.CompareAndSwap(false, true) {
			x.switchTo(t, []int{0, 3, 4}, "p2", 3)
		}
	}
	for i := 0; i < 6; i++ {
		_ = x.worker.Pass(context.Background())
	}
	m := x.migration(t)
	require.Equal(t, sha256.Sum256([]byte("p2")), m.Digest)
	require.Equal(t, names(x.ids([]int{0, 3, 4})), m.Replicas)
	require.False(t, m.Complete(), "only A of {A, D, E} holds the history")
	require.Contains(t, m.Retained, x.peers[1].String())
	require.Equal(t, x.policy.Snapshot().Digest, x.worker.PolicyDigest)
	require.True(t, x.policy.Holder(x.peers[1]))
}

// A catch-up's Advance can perform the first adoption (or a switch); its context is canceled when the recovery returns (astra review of
// #1034, finding 2). The availability checker installed then must not keep that cancellation: the next passes advance the frontier.
func TestCanceledCatchUpContextDoesNotStallTheFrontier(t *testing.T) {
	x := newRotationNet(t, 7, 3, []bool{true, true, true})
	x.start(t, []int{0, 1, 2}, "p0")
	x.newWorker() // not yet synchronized: the catch-up's Advance adopts
	recovery, cancel := context.WithCancel(context.Background())
	require.NoError(t, x.worker.Advance(recovery, 4))
	require.Equal(t, uint64(4), x.frontier(t).Anchor.Height)
	cancel()
	x.passUntil(t, "the frontier reaches the head after the recovery's context is canceled", x.anchoredAt(t, 7))
	// and once more through a switch adopted inside a canceled-later Advance
	x.switchTo(t, []int{0, 2, 1}, "p1", 2)
	recovery, cancel = context.WithCancel(context.Background())
	_ = x.worker.Advance(recovery, 4)
	cancel()
	require.NoError(t, x.worker.Pass(context.Background()))
}

// A migration is complete only when every retained activation bundle also has two current, read-verified remote copies (astra review of
// #1034, finding 4): the block history alone does not release the earlier replica.
func TestMigrationWaitsForActivationBundles(t *testing.T) {
	x := newRotationNet(t, 7, 4, []bool{true, true, true, true})
	q := archive.BundleRequest{Context: x.f.subject, Epoch: 2}
	raw := []byte("an activation bundle")
	for _, s := range []*archive.Store{x.local, x.stores[0], x.stores[1]} {
		_, err := s.PutBundle(q, raw, nil)
		require.NoError(t, err)
	}
	x.bundles[2].Store(false) // from the start: the first policy's own verification (on A and B) must not copy it to C either
	x.bundles[3].Store(false)
	x.start(t, []int{0, 1, 2}, "p0")
	require.NoError(t, x.worker.Pass(context.Background()))
	require.True(t, x.migration(t).Complete(), "the first policy has the bundle on two of its replicas")
	x.switchTo(t, []int{0, 2, 3}, "p1", 2)
	for i := 0; i < 4; i++ {
		_ = x.worker.Pass(context.Background())
	}
	m := x.migration(t)
	require.Zero(t, m.Backlog(), "every block position is verified on the current replicas")
	require.False(t, m.Complete(), "one current replica holds the bundle")
	require.True(t, x.policy.Holder(x.peers[1]))
	x.bundles[3].Store(true)
	x.passUntil(t, "the bundle reaches a second current replica", x.complete(t))
	got, err := FetchBundle(context.Background(), x.sender, x.peers[3], q, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, raw, got)
}

// Reading is not the durability policy: a restore may read from the policy's replicas and its retained holders (astra review of #1034,
// finding 5), and a node without pruning grants no retained holder archive access (finding 6).
func TestRestoreSourcesAndUntrackedPolicy(t *testing.T) {
	a, b, c, d, e := peer.ID("a"), peer.ID("b"), peer.ID("c"), peer.ID("d"), peer.ID("e")
	require.True(t, validSources([]peer.ID{a, b, c, d}))
	require.False(t, validSources([]peer.ID{a, a}))
	require.False(t, validSources([]peer.ID{a}))
	p, err := NewReplicaPolicy([]peer.ID{a, b, c}, [32]byte{1}, []byte{1}, 0)
	require.NoError(t, err)
	_, err = p.Switch([]peer.ID{a, d, e}, [32]byte{2}, []byte{2}, 1)
	require.NoError(t, err)
	require.Len(t, p.Snapshot().Readable(), 5)
	require.True(t, validSources(p.Snapshot().Readable()))
	require.True(t, validSources(testpeer.GeneratePeerIDs(t, 40)), "no upper bound below what a policy can retain")
	untracked, err := NewReplicaPolicy([]peer.ID{a, b, c}, [32]byte{1}, []byte{1}, 0)
	require.NoError(t, err)
	untracked.Untracked()
	switched, err := untracked.Switch([]peer.ID{a, d, e}, [32]byte{2}, []byte{2}, 1)
	require.NoError(t, err)
	require.True(t, switched)
	require.Empty(t, untracked.Snapshot().Retained)
	require.False(t, untracked.Holder(b))
}

func mustCertified(t *testing.T, q archive.Request, rec *archive.Record) frontier.Record {
	t.Helper()
	r, err := certifiedRecordOf(q, rec)
	require.NoError(t, err)
	return r
}

// A restore reads from every source the persisted policy can produce (astra round 2 of #1034): successive unfinished migrations keep
// every retained holder, so the list may be long. A restore with eighteen sources, sixteen of them gone and the two that serve last,
// completes; nothing is dropped and the configuration is not refused.
func TestArchiveRestoreReadsFromEveryRetainedSource(t *testing.T) {
	t.Parallel()
	fx := newRetryRestoreFixture(t, 0, FetchRetry{Initial: time.Millisecond, Max: 5 * time.Millisecond, Total: 20 * time.Second})
	dead := testpeer.GeneratePeerIDs(t, 16)
	fx.restore.Replicas = append(dead, fx.restore.Replicas...)
	require.True(t, validSources(fx.restore.Replicas))
	require.NoError(t, fx.restore.Restore(context.Background()))
	require.EqualValues(t, 5, fx.executor.head.Number)
}

// The upgrade path of astra round 2 of #1034, inverted: a journal from before policies were persisted, whose durable block coverage names
// A and B, restarts under A/B/D. Both block acknowledgers stay current, so no holder is retained, yet the retained activation bundle is on
// B (and the retiring C) only. The migration is not complete until two current replicas read it back; then A or D holds it as well.
func TestUpgradeVerifiesBundlesWhenBlockAcknowledgersStay(t *testing.T) {
	ctx := context.Background()
	x := newRotationNet(t, 7, 4, []bool{true, true, true, false})
	old := x.ids([]int{0, 1, 2})
	oldDigest, _ := derive("startup")
	require.NoError(t, x.f.store.EnableFrontier(ctx, x.f.context, x.f.limits, frontier.Policy{Context: x.f.subject, Eligible: names(old), PolicyDigest: oldDigest,
		Binding: CertifiedBinding{Context: x.f.context, Subject: x.f.subject}, Availability: ReplicaAvailability{Context: ctx, Host: x.sender, Replicas: old, Limits: DefaultLimits()}}))
	legacy := &FrontierWorker{Journal: x.f.store, Context: x.f.context, Limits: x.f.limits, Archive: x.local, Subject: x.f.subject, Replicas: old, PolicyDigest: oldDigest, Host: x.sender, TransportLimits: DefaultLimits()}
	require.NoError(t, legacy.Pass(ctx))
	require.ElementsMatch(t, names(x.ids([]int{0, 1})), names2(x.frontier(t).Anchor))
	q := archive.BundleRequest{Context: x.f.subject, Epoch: 2}
	raw := []byte("an activation bundle")
	for _, s := range []*archive.Store{x.local, x.stores[1], x.stores[2]} {
		_, err := s.PutBundle(q, raw, nil)
		require.NoError(t, err)
	}

	require.NoError(t, x.f.store.Close())
	reopened, err := configuredprogress.OpenConfiguredV2(x.f.path, configuredprogress.Settings{Retain: 16})
	require.NoError(t, err)
	t.Cleanup(func() { _ = reopened.Close() })
	require.NoError(t, reopened.EnableJournal(ctx, x.f.context, x.f.limits))
	x.journal.Store(reopened)
	x.bundles[0].Store(false)
	x.bundles[3].Store(false)
	x.start(t, []int{0, 1, 3}, "p1")
	m := x.migration(t)
	require.Empty(t, m.Retained, "both block acknowledgers stay current")
	require.False(t, m.Complete(), "the bundles are not verified yet")
	for i := 0; i < 3; i++ {
		_ = x.worker.Pass(ctx)
	}
	require.False(t, x.migration(t).Complete(), "one current replica (B) holds the bundle")
	require.False(t, PolicyReportOf(x.policy.Snapshot()).MigrationDone)
	x.bundles[3].Store(true)
	x.passUntil(t, "a second current replica holds the bundle", x.complete(t))
	got, err := FetchBundle(ctx, x.sender, x.peers[3], q, DefaultLimits())
	require.NoError(t, err)
	require.Equal(t, raw, got)
	require.True(t, PolicyReportOf(x.policy.Snapshot()).MigrationDone)
}
