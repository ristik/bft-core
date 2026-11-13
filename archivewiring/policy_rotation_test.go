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
)

// rotationNet is a writer with a local archive, a publisher and a frontier worker following a versioned replica policy, and n archive
// replicas (bft-core#1030). A replica accepts a publication only while accept[i] is set (a lagging replica, or a replacement that cannot
// yet vouch for the record, refuses) and only above floor[i] (a replacement restored at that height has no association below it). A
// stopped replica neither answers nor accepts.
type rotationNet struct {
	f       *wiringFixture
	sender  *network.Peer
	remotes []*network.Peer
	peers   []peer.ID
	stores  []*archive.Store
	accept  []*atomic.Bool
	floor   []*atomic.Uint64
	journal atomic.Pointer[configuredprogress.Store]
	local   *archive.Store
	policy  *ReplicaPolicy
	worker  *FrontierWorker
	stopPub func()
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
		x.stores = append(x.stores, store)
		accept, floor := &atomic.Bool{}, &atomic.Uint64{}
		accept.Store(true)
		x.accept, x.floor = append(x.accept, accept), append(x.floor, floor)
		verify := func(ctx context.Context, q archive.Request, rec *archive.Record) error {
			var header gethtypes.Header
			if !accept.Load() || rlp.DecodeBytes(rec.Header, &header) != nil || header.Number.Uint64() <= floor.Load() {
				return fmt.Errorf("%w: this replica has no association for the block", ErrUncertified)
			}
			return JournalVerifier(x.journal.Load(), f.context, f.limits, f.subject)(ctx, q, rec)
		}
		x.sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		server, err := NewServer(store, f.subject, verify, []peer.ID{x.sender.ID()}, DefaultLimits())
		require.NoError(t, err)
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
	_, err = EnableDerivedFrontier(context.Background(), x.journal.Load(), x.f.context, x.f.limits, x.f.subject, x.sender, DefaultLimits(), x.policy)
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
	t.Parallel()
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
	t.Parallel()
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

// A replacement restored above some promised heights cannot accept their records (no association below its restore base), while it
// takes every new block: the frontier moves on at once, and the history stays with the retained holder until another current replica
// holds it.
func TestReplacementBelowItsRestoreBaseKeepsTheRetainedHolder(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	_, err = EnableDerivedFrontier(ctx, reopened, x.f.context, x.f.limits, x.f.subject, x.sender, DefaultLimits(), x.policy)
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
