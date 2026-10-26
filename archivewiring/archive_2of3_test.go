package archivewiring

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
)

var testPolicyDigest = [32]byte{5}

// twoOfThree is a writer with a local archive and three archive replicas. holds[i] says whether replica i has every record; a replica
// that is down has no address in the writer's peer store, so every dial fails at once, exactly like a stopped process.
type twoOfThree struct {
	f       *wiringFixture
	worker  *FrontierWorker
	peers   []peer.ID
	stores  []*archive.Store
	local   *archive.Store
	sender  *network.Peer
	remotes []*network.Peer
}

func newTwoOfThree(t *testing.T, blocks int, holds, down [3]bool) *twoOfThree {
	t.Helper()
	f := newWiringFixture(t, blocks)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	x := &twoOfThree{f: f, stores: make([]*archive.Store, 3), sender: sender}
	local, err := archive.Open(t.TempDir())
	require.NoError(t, err)
	x.local = local
	for i := range x.stores {
		remote := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		x.peers = append(x.peers, remote.ID())
		x.remotes = append(x.remotes, remote)
		x.stores[i], err = archive.Open(t.TempDir())
		require.NoError(t, err)
		if down[i] {
			continue
		}
		sender.Network().Peerstore().AddAddrs(remote.ID(), remote.MultiAddresses(), peerstore.PermanentAddrTTL)
		server, err := NewServer(x.stores[i], f.subject, JournalVerifier(f.store, f.context, f.limits, f.subject), []peer.ID{sender.ID()}, DefaultLimits())
		require.NoError(t, err)
		server.Register(context.Background(), remote)
	}
	for i := range f.entries {
		q, rec := f.record(t, i)
		require.NoError(t, local.Put(q, rec))
		for j, s := range x.stores {
			if holds[j] {
				require.NoError(t, s.Put(q, rec))
			}
		}
	}
	x.enable(t, sender, []int{0, 1, 2}, testPolicyDigest)
	return x
}

// enable installs the frontier policy over the given replicas (indexes into peers) and a worker for them.
func (x *twoOfThree) enable(t *testing.T, sender *network.Peer, members []int, digest [32]byte) {
	t.Helper()
	var ids []peer.ID
	var names []string
	for _, i := range members {
		ids = append(ids, x.peers[i])
		names = append(names, x.peers[i].String())
	}
	policy := frontier.Policy{Context: x.f.subject, Eligible: names, PolicyDigest: digest, Binding: CertifiedBinding{Context: x.f.context, Subject: x.f.subject},
		Availability: ReplicaAvailability{Context: context.Background(), Host: sender, Replicas: ids, Limits: DefaultLimits()}}
	require.NoError(t, x.f.store.EnableFrontier(context.Background(), x.f.context, x.f.limits, policy))
	x.worker = &FrontierWorker{Journal: x.f.store, Context: x.f.context, Limits: x.f.limits, Archive: x.local, Subject: x.f.subject, Replicas: ids, PolicyDigest: digest, Host: sender, TransportLimits: DefaultLimits()}
}

// stop shuts replica i down: from now on it neither answers nor accepts a connection.
func (x *twoOfThree) stop(t *testing.T, i int) {
	t.Helper()
	require.NoError(t, x.remotes[i].Close())
	x.sender.Network().Peerstore().ClearAddrs(x.peers[i])
	_ = x.sender.Network().ClosePeer(x.peers[i])
}

func (x *twoOfThree) anchor(t *testing.T) *frontier.Record {
	t.Helper()
	snap, err := x.f.store.LoadFrontier(context.Background(), x.f.context, x.f.limits)
	require.NoError(t, err)
	return snap.Anchor
}

// Any one replica may be gone or empty: the frontier advances on the other two, names exactly those two, and pruning follows.
func TestFrontierWorkerAdvancesWithAnyOneReplicaLost(t *testing.T) {
	t.Parallel()
	for lost := 0; lost < 3; lost++ {
		for _, stopped := range []bool{false, true} {
			holds, down := [3]bool{true, true, true}, [3]bool{}
			holds[lost] = false
			down[lost] = stopped
			x := newTwoOfThree(t, 6, holds, down)
			require.NoError(t, x.worker.Pass(context.Background()), "lost %d stopped %v", lost, stopped)
			require.NoError(t, x.worker.Pass(context.Background()), "lost %d stopped %v", lost, stopped)
			anchor := x.anchor(t)
			require.NotNil(t, anchor)
			require.Greater(t, anchor.Height, uint64(1))
			require.Equal(t, testPolicyDigest, anchor.PolicyDigest)
			var want []string
			for i, id := range x.peers {
				if i != lost {
					want = append(want, id.String())
				}
			}
			require.Equal(t, want, []string{anchor.Acks[0].Replica, anchor.Acks[1].Replica}, "lost %d: the record names the two replicas that hold the copy", lost)
			snap, err := x.f.store.LoadFrontier(context.Background(), x.f.context, x.f.limits)
			require.NoError(t, err)
			require.Equal(t, snap.Anchor.Height, snap.Floor, "lost %d: pruning follows the frontier", lost)
		}
	}
}

// Two replicas lost leave one verified copy: the frontier does not move and the failure says why.
func TestFrontierWorkerFreezesWithTwoReplicasLost(t *testing.T) {
	t.Parallel()
	for _, hold := range [][3]bool{{true, false, false}, {false, true, false}, {false, false, true}} {
		x := newTwoOfThree(t, 6, hold, [3]bool{})
		err := x.worker.Pass(context.Background())
		require.ErrorIs(t, err, frontier.ErrAcknowledgment, "%v", hold)
		require.Nil(t, x.anchor(t), "%v: nothing is acknowledged by fewer than two replicas", hold)
	}
}

// The audit counts verified copies over the whole configured set: a stopped acknowledger is made up from the third replica, and when
// only one copy is left anywhere the audit fails instead of passing on the strength of a replica that cannot be read.
func TestFrontierAuditMakesUpForAStoppedAcknowledger(t *testing.T) {
	t.Parallel()
	x := newTwoOfThree(t, 6, [3]bool{true, true, true}, [3]bool{})
	require.NoError(t, x.worker.Pass(context.Background()))
	first := x.anchor(t)
	require.NotNil(t, first)
	require.Equal(t, x.peers[0].String(), first.Acks[0].Replica)
	require.Equal(t, x.peers[1].String(), first.Acks[1].Replica)

	// Replica 1 stops. The third holds every copy already: the audit passes, and the next records name replicas 0 and 2.
	stopped := newTwoOfThree(t, 6, [3]bool{true, false, true}, [3]bool{false, true, false})
	require.NoError(t, stopped.worker.Pass(context.Background()))
	require.Equal(t, stopped.peers[2].String(), stopped.anchor(t).Acks[1].Replica)

	// Replicas 1 and 2 stop after the position is persisted: one verified copy is left, and the audit of that position fails
	// instead of passing on the strength of replicas that cannot be read.
	one := newTwoOfThree(t, 6, [3]bool{true, true, true}, [3]bool{})
	require.NoError(t, one.worker.Pass(context.Background()))
	require.NotNil(t, one.anchor(t))
	one.stop(t, 1)
	require.NoError(t, one.worker.audit(context.Background()), "one stopped replica: the other two still hold a verified copy")
	one.stop(t, 2)
	one.worker.auditCursor = 0 // the previous audit swept the whole short history
	require.ErrorIs(t, one.worker.audit(context.Background()), frontier.ErrUnavailable)
}

func TestValidReplicas(t *testing.T) {
	a, b, c, d := peer.ID("a"), peer.ID("b"), peer.ID("c"), peer.ID("d")
	for name, tc := range map[string]struct {
		in   []peer.ID
		want bool
	}{
		"none": {nil, false}, "one": {[]peer.ID{a}, false}, "two": {[]peer.ID{a, b}, true}, "three": {[]peer.ID{a, b, c}, true},
		"four": {[]peer.ID{a, b, c, d}, false}, "duplicate": {[]peer.ID{a, a}, false}, "duplicate of three": {[]peer.ID{a, b, a}, false}, "empty": {[]peer.ID{a, ""}, false},
	} {
		require.Equal(t, tc.want, validReplicas(tc.in), name)
	}
}

// The promised copy stays valid while any two configured replicas hold it: stopping either acknowledger of the durable anchor (or the
// third replica) does not freeze the frontier, and the next records name the replicas that are left.
func TestFrontierAdvancesAfterAnAcknowledgerOfTheAnchorStops(t *testing.T) {
	t.Parallel()
	for stopped := 0; stopped < 3; stopped++ {
		x := newTwoOfThree(t, 7, [3]bool{true, true, true}, [3]bool{})
		require.NoError(t, x.worker.Pass(context.Background()))
		before := x.anchor(t)
		require.NotNil(t, before)
		require.Equal(t, x.peers[0].String(), before.Acks[0].Replica)
		require.Equal(t, x.peers[1].String(), before.Acks[1].Replica)
		x.stop(t, stopped)
		require.NoError(t, x.worker.Pass(context.Background()), "replica %d stopped", stopped)
		after := x.anchor(t)
		require.Greater(t, after.Height, before.Height, "replica %d stopped: the frontier moved on", stopped)
		for _, ack := range after.Acks {
			require.NotEqual(t, x.peers[stopped].String(), ack.Replica)
		}
	}
}

// With two replicas stopped only one copy remains: the frontier does not move.
func TestFrontierFreezesWhenTwoReplicasStopAfterTheAnchor(t *testing.T) {
	t.Parallel()
	for _, stopped := range [][2]int{{0, 1}, {0, 2}, {1, 2}} {
		x := newTwoOfThree(t, 7, [3]bool{true, true, true}, [3]bool{})
		require.NoError(t, x.worker.Pass(context.Background()))
		before := x.anchor(t)
		x.stop(t, stopped[0])
		x.stop(t, stopped[1])
		require.ErrorIs(t, x.worker.Pass(context.Background()), frontier.ErrUnavailable, "%v", stopped)
		require.Equal(t, before.Height, x.anchor(t).Height, "%v", stopped)
	}
}

// An anchor acknowledged by a replica that is no longer in the policy (a membership change) is historical: the frontier advances to a
// record of the current policy as soon as two configured replicas hold the promised copy.
func TestFrontierAdvancesFromAnAnchorWithAnOutsideAcknowledger(t *testing.T) {
	t.Parallel()
	x := newTwoOfThree(t, 7, [3]bool{true, true, true}, [3]bool{})
	require.NoError(t, x.worker.Pass(context.Background()))
	before := x.anchor(t)
	require.Equal(t, x.peers[1].String(), before.Acks[1].Replica)
	x.enable(t, x.sender, []int{0, 2}, [32]byte{6}) // replica 1 leaves the set
	snap, err := x.f.store.LoadFrontier(context.Background(), x.f.context, x.f.limits)
	require.NoError(t, err)
	require.True(t, snap.Anchor.Migrated())
	require.NoError(t, x.worker.Pass(context.Background()))
	after := x.anchor(t)
	require.Greater(t, after.Height, before.Height)
	require.Equal(t, [32]byte{6}, after.PolicyDigest)
	require.False(t, after.Migrated())
	require.Equal(t, x.peers[0].String(), after.Acks[0].Replica)
	require.Equal(t, x.peers[2].String(), after.Acks[1].Replica)
}

// A pass every two seconds at four blocks covers two blocks a second, about what a transaction burst produces; a journal that is already behind (after a
// restart every block is pending again) never catches up and fills (bft-core#876). From half full a pass covers a larger batch.
func TestFrontierWorkerCoversMoreWhenTheJournalFills(t *testing.T) {
	t.Parallel()
	all := [3]bool{true, true, true}
	quiet := newTwoOfThree(t, 6, all, [3]bool{}) // 6 of 16: below the busy level
	require.NoError(t, quiet.worker.Pass(context.Background()))
	require.Equal(t, uint64(passCoverage), quiet.anchor(t).Height, "below the busy level a pass covers four")
	busy := newTwoOfThree(t, 12, all, [3]bool{}) // 12 of 16
	require.NoError(t, busy.worker.Pass(context.Background()))
	require.Equal(t, uint64(12), busy.anchor(t).Height, "from half full a pass covers all twelve")
}
