package shardnode

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-go-base/types"
)

func (n *lateRootNet) handshakeCount() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.handshakes
}

// #1074: a root handoff restarts the roots (their subscriptions are gone) and installs a root epoch the held certificate is not of. The shard
// used to wait for its InactivityTimeout (30 s, on a 5 s heartbeat) before it re-handshook, which made every handoff cost ~37 s of blocks on
// staging. With the production timers, the client now asks the installed epoch's roots at once, again every activationHandshakeEvery until it
// holds a certificate of that epoch, and then stops.
func TestARootActivationIsCaughtUpWithAtOnceNotAfterTheInactivityTimeout(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &lateRootNet{received: make(chan any, 64), ready: true, response: f.respond(f.ucMine)}
	held := f.ucMine.GetRootEpoch()
	var installed atomic.Uint64
	installed.Store(held)
	store := epochTrustStore{TrustBaseStore: stubTrustBaseStore{tb: f.tb}, installed: &installed}
	opts := BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: 5 * time.Second, InactivityTimeout: 30 * time.Second,
		StartupHandshakeInterval: 2 * time.Second}
	c, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		store, &firstUCDriver{got: make(chan struct{})}, nil, opts)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	require.Eventually(t, func() bool { e, ok := c.heldRootEpoch(); return ok && e == held }, 5*time.Second, 10*time.Millisecond,
		"premise: the client holds a certificate of root epoch %d", held)
	time.Sleep(600 * time.Millisecond)
	before := net.handshakeCount()

	activated := time.Now()
	installed.Store(held + 1) // the handoff: the next root epoch is installed, no certificate of it is held yet
	require.Eventually(t, func() bool { return net.handshakeCount() > before }, 5*time.Second, 5*time.Millisecond)
	waited := time.Since(activated)
	t.Logf("activation to the first catch-up handshake: %v (inactivity timeout %v, heartbeat %v)", waited.Round(time.Millisecond), opts.InactivityTimeout,
		opts.HeartbeatInterval)
	require.Less(t, waited, time.Second, "asked at once, not after the inactivity timeout")

	time.Sleep(3*activationHandshakeEvery + 300*time.Millisecond) // the catch-up runs on Run's 250 ms tick
	repeated := net.handshakeCount() - before
	require.GreaterOrEqual(t, repeated, 3, "asked again every %v while not caught up", activationHandshakeEvery)

	installed.Store(held) // caught up: the held certificate is of the installed epoch
	time.Sleep(300 * time.Millisecond)
	settled := net.handshakeCount()
	time.Sleep(2*activationHandshakeEvery + 300*time.Millisecond)
	require.Equal(t, settled, net.handshakeCount(), "no catch-up handshakes once the held certificate is of the installed epoch")
}

// A follower (non-active) node asks no root anything after an activation: its certificates come from its follow source.
func TestAFollowerDoesNotHandshakeAfterARootActivation(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &lateRootNet{received: make(chan any, 64), ready: true, response: f.respond(f.ucMine)}
	held := f.ucMine.GetRootEpoch()
	var installed atomic.Uint64
	installed.Store(held)
	store := epochTrustStore{TrustBaseStore: stubTrustBaseStore{tb: f.tb}, installed: &installed}
	c, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		store, &firstUCDriver{got: make(chan struct{})}, nil, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour,
			InactivityTimeout: time.Hour})
	require.NoError(t, err)
	role := &tokenRole{}
	role.active.Store(true)
	c.SetRole(role)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()
	require.Eventually(t, func() bool { _, ok := c.heldRootEpoch(); return ok }, 5*time.Second, 10*time.Millisecond)
	role.active.Store(false)
	time.Sleep(300 * time.Millisecond)
	before := net.handshakeCount()
	installed.Store(held + 1)
	time.Sleep(2*activationHandshakeEvery + 300*time.Millisecond)
	require.Equal(t, before, net.handshakeCount())
}
