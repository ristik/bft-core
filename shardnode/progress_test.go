package shardnode

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

// The common progress clock moves only on an adopted certificate: a duplicate of the held one, a forged one and one of another shard
// leave it where it was; a new certificate moves Delivered and Advanced, a repeat moves Delivered only.
func TestTheProgressClockMovesOnlyOnAnAdoptedCertificate(t *testing.T) {
	ctx := context.Background()
	f := newConfBindingFixture(t)
	c, _ := f.client(f.confMine)
	start := c.Progress().Delivered()
	require.False(t, start.IsZero(), "the clock starts with the client")

	time.Sleep(5 * time.Millisecond)
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	adopted := c.Progress().Delivered()
	require.True(t, adopted.After(start), "an adopted certificate is progress")
	require.Equal(t, adopted, c.Progress().Advanced())

	time.Sleep(5 * time.Millisecond)
	_ = c.handleCertificationResponse(ctx, f.respond(f.ucMine)) // a duplicate of the held certificate
	require.Equal(t, adopted, c.Progress().Delivered(), "a duplicate is not progress")

	good := f.respond(f.ucMine)
	raw, err := types.Cbor.Marshal(&good.UC)
	require.NoError(t, err)
	var forged types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(raw, &forged))
	forged.UnicitySeal.RootChainRoundNumber += 9
	bad := good
	bad.UC = forged
	require.Error(t, c.handleCertificationResponse(ctx, bad))
	require.Equal(t, adopted, c.Progress().Delivered(), "an invalid certificate is not progress")

	other := good
	other.Partition++
	require.Error(t, c.handleCertificationResponse(ctx, other))
	require.Equal(t, adopted, c.Progress().Delivered(), "another shard's response is not progress")

	c.clock().adopted(true) // a repeat certificate
	require.True(t, c.Progress().Delivered().After(adopted), "a repeat is a delivery")
	require.Equal(t, adopted, c.Progress().Advanced(), "but not an advance")
}

// The behaviour the clock fixes: a root that answers every handshake with the certificate the node already holds used to refresh the
// inactivity timer, so a stalled node stopped re-subscribing. Duplicates are not progress, so the re-handshake keeps firing.
func TestDuplicateAnswersDoNotPostponeTheInactivityHandshake(t *testing.T) {
	f := newConfBindingFixture(t)
	net := &lateRootNet{received: make(chan any, 8), ready: true, response: f.respond(f.ucMine)}
	client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, &firstUCDriver{got: make(chan struct{})}, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: 20 * time.Millisecond, InactivityTimeout: 100 * time.Millisecond})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	time.Sleep(150 * time.Millisecond) // the first answer is adopted; every later one is a duplicate
	net.mu.Lock()
	before := net.handshakes
	net.mu.Unlock()
	time.Sleep(600 * time.Millisecond)
	net.mu.Lock()
	after := net.handshakes
	net.mu.Unlock()
	require.GreaterOrEqual(t, after-before, 3, "re-subscribing continues while only duplicates arrive")
}
