package shardnode

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
	"github.com/unicitynetwork/bft-go-base/types"
)

// lapsedFeedNet is a root whose certificate feed to this node has lapsed: it answers every handshake with its last certification
// response, as rootchain/node.go onHandshake does, and sends nothing else. That is what a node sees once its subscription quota at
// every root is spent and nothing refills it, for example because its certification requests do not reach the roots (bft-core#558:
// requests held at every root while repeat certificates kept spending the quota).
type lapsedFeedNet struct {
	mu         sync.Mutex
	handshakes []time.Time
	received   chan any
	response   *certification.CertificationResponse
}

func (n *lapsedFeedNet) Send(_ context.Context, msg any, _ ...peer.ID) error {
	switch msg.(type) {
	case *handshake.Handshake, handshake.Handshake:
	default:
		return nil // a certification request: lost, it refills nothing
	}
	n.mu.Lock()
	n.handshakes = append(n.handshakes, time.Now())
	n.mu.Unlock()
	select {
	case n.received <- n.response:
	default:
	}
	return nil
}

func (n *lapsedFeedNet) ReceivedChannel() <-chan any { return n.received }

func (n *lapsedFeedNet) sent() []time.Time {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]time.Time(nil), n.handshakes...)
}

// A node whose feed has lapsed is not cut off for good: after InactivityTimeout without a certification response it subscribes
// again, and the root's answer to a handshake is its latest certificate. The miss is bounded by InactivityTimeout (plus one
// heartbeat), and the node does not ask sooner than that.
func TestALapsedCertificateFeedIsRenewedAfterTheInactivityTimeout(t *testing.T) {
	const inactivity, heartbeat = 400 * time.Millisecond, 20 * time.Millisecond
	f := newConfBindingFixture(t)
	net := &lapsedFeedNet{received: make(chan any, 4), response: f.respond(f.ucMine)}
	driver := &firstUCDriver{got: make(chan struct{})}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, driver, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: heartbeat, InactivityTimeout: inactivity})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case <-driver.got:
	case <-time.After(5 * time.Second):
		t.Fatal("the initial handshake was not answered")
	}
	// At start the node handshakes, and once more for the certificate that answer carried (it submitted nothing for it, so it renews
	// by itself: renewSubscriptionIfIdle). The second answer is the same certificate, which is no new evidence and renews nothing.
	require.Eventually(t, func() bool { return len(net.sent()) == 2 }, time.Second, heartbeat/2)
	time.Sleep(inactivity / 2)
	settled := net.sent()
	require.Len(t, settled, 2, "no further handshake while the feed is merely quiet")

	// nothing arrives any more; the node asks again by itself
	require.Eventually(t, func() bool { return len(net.sent()) >= 3 }, 10*inactivity, heartbeat/2, "the node never subscribed again")
	sent := net.sent()
	gap := sent[2].Sub(sent[1])
	// (the node keeps the time of its last response in whole milliseconds, so the comparison allows for that truncation)
	const clockGrain = 2 * time.Millisecond
	require.GreaterOrEqual(t, gap+clockGrain, inactivity, "not before the inactivity timeout: %s after the previous handshake", gap)
	require.Less(t, gap, inactivity+2*time.Second, "and soon after it (the margin is for a loaded test machine): the timeout is the bound on a lapsed feed")

	// each answer restarts the clock: the node asks once per timeout while the feed stays lapsed, not once per heartbeat
	require.Eventually(t, func() bool { return len(net.sent()) >= 4 }, 10*inactivity, heartbeat/2)
	sent = net.sent()
	require.GreaterOrEqual(t, sent[3].Sub(sent[2])+clockGrain, inactivity, "%s after the previous handshake", sent[3].Sub(sent[2]))
}
