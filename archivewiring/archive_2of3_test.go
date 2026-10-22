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
	names := make([]string, len(x.peers))
	for i, id := range x.peers {
		names[i] = id.String()
	}
	policy := frontier.Policy{Context: f.subject, Eligible: names, PolicyDigest: testPolicyDigest, Binding: CertifiedBinding{Context: f.context, Subject: f.subject},
		Availability: ReplicaAvailability{Context: context.Background(), Host: sender, Replicas: x.peers, Limits: DefaultLimits()}}
	require.NoError(t, f.store.EnableFrontier(context.Background(), f.context, f.limits, policy))
	x.worker = &FrontierWorker{Journal: f.store, Context: f.context, Limits: f.limits, Archive: local, Subject: f.subject, Replicas: x.peers, PolicyDigest: testPolicyDigest, Host: sender, TransportLimits: DefaultLimits()}
	return x
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
