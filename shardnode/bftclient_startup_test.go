package shardnode

import (
	"context"
	"crypto"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
	"github.com/unicitynetwork/bft-go-base/types"
)

// lateRootNet is a root that drops every handshake until it is ready (it has not loaded the shard yet), then answers
// each one with its last certification response, as rootchain/node.go onHandshake does.
type lateRootNet struct {
	mu         sync.Mutex
	ready      bool
	readyAt    time.Time
	handshakes int
	dropped    int
	received   chan any
	response   *certification.CertificationResponse
}

func (n *lateRootNet) Send(_ context.Context, msg any, _ ...peer.ID) error {
	switch msg.(type) {
	case *handshake.Handshake, handshake.Handshake:
	default:
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.handshakes++
	if !n.ready {
		n.dropped++
		return nil
	}
	select {
	case n.received <- n.response:
	default:
	}
	return nil
}

func (n *lateRootNet) ReceivedChannel() <-chan any { return n.received }

func (n *lateRootNet) becomeReady() {
	n.mu.Lock()
	n.ready, n.readyAt = true, time.Now()
	n.mu.Unlock()
}

type firstUCDriver struct {
	once sync.Once
	at   atomic.Int64
	got  chan struct{}
}

func (d *firstUCDriver) HandleCertificate(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
	d.once.Do(func() { d.at.Store(time.Now().UnixNano()); close(d.got) })
	return nil
}

// The root drops the first handshakes (it has not loaded the shard yet). With the startup retry the client gets its
// first certificate within one retry interval of the root becoming ready, long before the inactivity timeout.
func TestStartupHandshakeIsRetriedUntilTheFirstCertificate(t *testing.T) {
	const interval = 100 * time.Millisecond
	f := newConfBindingFixture(t)
	net := &lateRootNet{received: make(chan any, 4), response: f.respond(f.ucMine)}
	driver := &firstUCDriver{got: make(chan struct{})}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, driver, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: time.Hour, StartupHandshakeInterval: interval})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	// Drop at least the initial handshake and several retries, then let the root become ready.
	require.Eventually(t, func() bool { net.mu.Lock(); defer net.mu.Unlock(); return net.dropped >= 4 }, 5*time.Second, 10*time.Millisecond)
	select {
	case <-driver.got:
		t.Fatal("a certificate arrived while the root was still dropping handshakes")
	default:
	}
	net.becomeReady()
	select {
	case <-driver.got:
	case <-time.After(10 * interval):
		t.Fatal("no certificate within the retry interval of the root becoming ready")
	}
	net.mu.Lock()
	lateness := time.Duration(driver.at.Load() - net.readyAt.UnixNano())
	sentWhenGot := net.handshakes
	net.mu.Unlock()
	require.Less(t, lateness, 3*interval, "first certificate follows readiness by about one retry interval")
	// The early retry stops with the first certificate.
	time.Sleep(4 * interval)
	net.mu.Lock()
	require.LessOrEqual(t, net.handshakes, sentWhenGot+1, "no further startup handshakes after the first certificate")
	net.mu.Unlock()
	_ = crypto.SHA256
	_ = authPartitionID
}

func TestStartupHandshakeDisabledByZeroInterval(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &lateRootNet{received: make(chan any, 4), response: f.respond(f.ucMine)}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, &firstUCDriver{got: make(chan struct{})}, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: time.Hour})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done
	net.mu.Lock()
	defer net.mu.Unlock()
	require.Equal(t, 1, net.handshakes, "without the option only the initial handshake is sent (unchanged behaviour)")
}

func TestStartupHandshakeBackoffIsBoundedByTheInactivityTimeout(t *testing.T) {
	base, ceiling := 2*time.Second, 30*time.Second
	for n := 0; n < startupFixedAttempts; n++ {
		require.Equal(t, base, startupHandshakeDelay(base, ceiling, n), "attempt %d", n)
	}
	require.Equal(t, 4*time.Second, startupHandshakeDelay(base, ceiling, 5))
	require.Equal(t, 8*time.Second, startupHandshakeDelay(base, ceiling, 6))
	prev := time.Duration(0)
	for n := 0; n < 40; n++ {
		d := startupHandshakeDelay(base, ceiling, n)
		require.GreaterOrEqual(t, d, prev, "never shrinks")
		require.LessOrEqual(t, d, ceiling, "capped at the inactivity timeout")
		prev = d
	}
	require.Equal(t, ceiling, prev)
}
