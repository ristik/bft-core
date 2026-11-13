package shardnode

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// swallowingNet is a root chain that takes every certification request and never certifies it: what the shard sees across the
// closing epoch of a root handoff, which admits only empty blocks until the next epoch starts (#665).
type swallowingNet struct {
	mu       sync.Mutex
	requests []*certification.BlockCertificationRequest
}

func (n *swallowingNet) Send(_ context.Context, msg any, _ ...peer.ID) error {
	if req, ok := msg.(*certification.BlockCertificationRequest); ok {
		n.mu.Lock()
		n.requests = append(n.requests, req)
		n.mu.Unlock()
	}
	return nil
}

func (n *swallowingNet) ReceivedChannel() <-chan any { return nil }

func (n *swallowingNet) sent() []*certification.BlockCertificationRequest {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]*certification.BlockCertificationRequest(nil), n.requests...)
}

func resubmitClient(t *testing.T, f *confBindingFixture, opts BFTClientOptions) (*BFTClient, *swallowingNet) {
	t.Helper()
	c, _ := f.client(f.confMine)
	net := &swallowingNet{}
	opts.CertNodes = 1
	c.net, c.opts = net, opts
	return c, net
}

func pendingRequest(f *confBindingFixture) *certification.BlockCertificationRequest {
	return &certification.BlockCertificationRequest{
		PartitionID: authPartitionID, NodeID: "conf-binding-node",
		InputRecord: &types.InputRecord{Version: 1, RoundNumber: 5, PreviousHash: make([]byte, 32), Hash: make([]byte, 32), SummaryValue: []byte{}, Timestamp: 2},
		Signature:   []byte("signed once"),
	}
}

// The handoff-blackout case: the request is submitted, the root cannot certify it, and every handshake is answered with the
// certificate already held. Each answer re-sends the request unchanged, up to the bound; nothing is re-signed or rebuilt.
func TestAPendingRequestIsResentUnchangedWhenTheRootAnswersWithTheHeldCertificate(t *testing.T) {
	ctx := context.Background()
	f := newConfBindingFixture(t)
	c, net := resubmitClient(t, f, BFTClientOptions{ResubmitMinInterval: time.Millisecond, MaxResubmits: 3})
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	req := pendingRequest(f)
	require.NoError(t, c.Submit(ctx, req))
	require.Len(t, net.sent(), 1)

	for i := 0; i < 8; i++ { // the handshake answers of the blackout
		time.Sleep(3 * time.Millisecond)
		require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	}
	sent := net.sent()
	require.Len(t, sent, 1+3, "the original send and MaxResubmits re-sends, not one per answer")
	want, err := types.Cbor.Marshal(req)
	require.NoError(t, err)
	for i, s := range sent {
		got, err := types.Cbor.Marshal(s)
		require.NoError(t, err)
		require.Equal(t, want, got, "send %d carries the signed bytes unchanged", i)
	}
}

func TestResendsAreSpacedByTheMinimumInterval(t *testing.T) {
	ctx := context.Background()
	f := newConfBindingFixture(t)
	c, net := resubmitClient(t, f, BFTClientOptions{ResubmitMinInterval: time.Hour})
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	require.NoError(t, c.Submit(ctx, pendingRequest(f)))
	for i := 0; i < 5; i++ {
		require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	}
	require.Len(t, net.sent(), 1, "answers arriving right after the send do not repeat it")
}

func TestNothingIsResentWithoutAPendingRequestOrWhenDisabled(t *testing.T) {
	ctx := context.Background()
	f := newConfBindingFixture(t)

	c, net := resubmitClient(t, f, BFTClientOptions{ResubmitMinInterval: time.Millisecond})
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	time.Sleep(3 * time.Millisecond)
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	require.Empty(t, net.sent(), "a duplicate with nothing submitted sends nothing")

	c, net = resubmitClient(t, f, BFTClientOptions{ResubmitMinInterval: time.Millisecond, MaxResubmits: -1})
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	require.NoError(t, c.Submit(ctx, pendingRequest(f)))
	time.Sleep(3 * time.Millisecond)
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	require.Len(t, net.sent(), 1, "a negative bound disables the re-send")
}

// A certificate that advances the round answers the request: it is no longer pending, so a later duplicate of the NEW held
// certificate re-sends nothing (the request was submitted on the one before it).
func TestAnAnsweredRequestIsNotResent(t *testing.T) {
	ctx := context.Background()
	f := newConfBindingFixture(t)
	c, net := resubmitClient(t, f, BFTClientOptions{ResubmitMinInterval: time.Millisecond})
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(f.ucMine)))
	require.NoError(t, c.Submit(ctx, pendingRequest(f)))

	zero := make([]byte, 32)
	trHash, err := f.technical.Hash()
	require.NoError(t, err)
	next := testcertificates.CreateUnicityCertificate(t, f.signer,
		&types.InputRecord{Version: 1, RoundNumber: 5, PreviousHash: zero, Hash: zero, SummaryValue: []byte{}, Timestamp: 2},
		&types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}, 60, zero, trHash)
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(next)))
	require.Equal(t, uint64(5), c.luc.GetRoundNumber(), "the round advanced")

	time.Sleep(3 * time.Millisecond)
	require.NoError(t, c.handleCertificationResponse(ctx, f.respond(next)))
	require.Len(t, net.sent(), 1, "only the original send: the request was answered")
}

// In configured (admission) mode the authenticated feed callback performs no network I/O: a duplicate of the held certificate only
// asks Run, through the wake channel, to re-send the pending request; anything else asks for nothing.
func TestTheConfiguredFeedAsksForAResendOnlyOnADuplicateOfTheHeldCertificate(t *testing.T) {
	f := newConfBindingFixture(t)
	c, _ := f.client(f.confMine)
	c.admissionWake = make(chan struct{}, 1)
	tr := f.technical

	c.observeConfiguredFeed(f.ucMine, tr) // the first certificate: progress, not a duplicate
	<-c.admissionWake
	require.False(t, c.resubmitWanted)

	c.observeConfiguredFeed(f.ucMine, tr) // the root answers with what is held
	select {
	case <-c.admissionWake:
	default:
		t.Fatal("a duplicate of the held certificate did not wake Run")
	}
	require.True(t, c.resubmitWanted)
}
