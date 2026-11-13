package shardnode

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A non-active follower's client sends nothing to the roots (no handshake at start, at the startup retry or at the inactivity timeout) and
// still delivers a certificate from its follow source through the same verification to the driver. A forged one is not delivered. After
// promotion the next heartbeat subscribes to the roots at once.
func TestFollowerClientSendsNothingToRootsAndDeliversFollowedCertificates(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &lateRootNet{received: make(chan any, 4), response: f.respond(f.ucMine), ready: true}
	driver := &firstUCDriver{got: make(chan struct{})}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, driver, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: 10 * time.Millisecond, StartupHandshakeInterval: 10 * time.Millisecond})
	require.NoError(t, err)
	follower := make(chan bool, 1)
	follower <- true
	nonActive := true
	client.SetFollowerRole(func() bool {
		select {
		case nonActive = <-follower:
		default:
		}
		return nonActive
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	good := f.respond(f.ucMine)
	raw, err := types.Cbor.Marshal(&good.UC)
	require.NoError(t, err)
	var forged types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(raw, &forged))
	forged.UnicitySeal.RootChainRoundNumber += 7 // the seal no longer verifies
	require.True(t, client.FollowCertificate(&forged, &good.Technical))
	time.Sleep(200 * time.Millisecond) // several heartbeats, startup retries and inactivity timeouts
	select {
	case <-driver.got:
		t.Fatal("a forged followed certificate reached the driver")
	default:
	}
	net.mu.Lock()
	require.Zero(t, net.handshakes, "a follower never handshakes with a root")
	net.mu.Unlock()

	require.True(t, client.FollowCertificate(&good.UC, &good.Technical))
	select {
	case <-driver.got:
	case <-time.After(5 * time.Second):
		t.Fatal("a followed certificate was not delivered")
	}

	follower <- false
	client.RoleChanged()
	require.Eventually(t, func() bool { net.mu.Lock(); defer net.mu.Unlock(); return net.handshakes > 0 }, 5*time.Second, 10*time.Millisecond,
		"promoted, it subscribes to the roots at once, not at the next heartbeat")
}
