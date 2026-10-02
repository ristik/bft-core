package archivewiring

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/archive"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

// Every typed refusal survives the reset frame: the code the server writes decodes back to the sentinel the client matches with errors.Is.
// The semantic bundle conflict (#354) used to be encoded as a generic handler failure, so a publisher could not tell equivocation from an
// outage.
func TestResetFrameRoundTripKeepsEachTypedRefusal(t *testing.T) {
	conflict := fmt.Errorf("%w: %w", ErrHandler, archive.ErrBundleConflict)
	for _, tc := range []struct {
		name string
		in   error
		want []error
		not  []error
	}{
		{"peer not allowed", ErrPeerNotAllowed, []error{ErrPeerNotAllowed}, []error{ErrHandler, archive.ErrBundleConflict}},
		{"per-peer limit", ErrPeerLimit, []error{ErrPeerLimit}, []error{ErrHandler, archive.ErrBundleConflict}},
		{"pending limit", ErrPendingLimit, []error{ErrPendingLimit}, []error{ErrHandler, archive.ErrBundleConflict}},
		{"verifier", fmt.Errorf("%w: %w", ErrVerifier, ErrReplica), []error{ErrVerifier}, []error{ErrHandler, archive.ErrBundleConflict}},
		{"handler", fmt.Errorf("%w: %w", ErrHandler, archive.ErrInvalid), []error{ErrHandler}, []error{archive.ErrBundleConflict}},
		{"bundle conflict", conflict, []error{archive.ErrBundleConflict, ErrHandler}, []error{ErrPeerNotAllowed, ErrVerifier}},
		{"bundle conflict, as the handler wraps it", fmt.Errorf("%w: %w", ErrHandler, conflict), []error{archive.ErrBundleConflict, ErrHandler}, []error{ErrPeerNotAllowed, ErrVerifier}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := decodeResetFrame(resetFrame(tc.in), "peer", []byte{5})
			var reset *StreamResetError
			require.ErrorAs(t, err, &reset)
			for _, want := range tc.want {
				require.ErrorIs(t, err, want)
			}
			for _, not := range tc.not {
				require.NotErrorIs(t, err, not)
			}
		})
	}
	require.Equal(t, "bundle_conflict", resetReasonName(conflict))
	require.ErrorIs(t, decodeResetFrame([]byte{resetFrameMarker, 7}, "peer", nil), ErrReplica, "an unknown code is still refused")
}

// Over a live libp2p stream: a replica that holds a different verified handoff for the epoch refuses the put, and the publisher's
// errors.Is sees the conflict, not a generic handler error.
func TestBundleConflictSurvivesTheLiveTransport(t *testing.T) {
	c := newHandoffCopies(t)
	request, _ := transportFixture()
	q := c.q
	q.Context = request.Context
	remote := openStore(t)
	log, _ := quietLog()
	_, err := RetainBundle(t.Context(), remote, q, c.one, c.verify, log)
	require.NoError(t, err)
	client := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	good := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	client.Network().Peerstore().AddAddrs(good.ID(), good.MultiAddresses(), peerstore.PermanentAddrTTL)
	server, err := NewServer(remote, request.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{client.ID()}, DefaultLimits())
	require.NoError(t, err)
	server.SetBundleVerifier(c.verify)
	server.SetLogger(log)
	server.Register(context.Background(), good)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err = PutBundleAndReadBack(ctx, client, good.ID(), q, c.diff, DefaultLimits(), c.verify)
	require.ErrorIs(t, err, archive.ErrBundleConflict)
	require.ErrorIs(t, err, ErrHandler, "still a handler failure for callers that match the class")
	require.NotErrorIs(t, err, ErrReplica)
	var reset *StreamResetError
	require.ErrorAs(t, err, &reset)
	require.NoError(t, PutBundleAndReadBack(ctx, client, good.ID(), q, c.other, DefaultLimits(), c.verify), "the equivalent copy is still accepted")
}

// The publisher records a conflicting bundle once, at ERROR, and stops offering that bundle to that replica; it keeps serving the other
// replica and the replica's own refusal (counted at the server) is not repeated on later passes.
func TestPublisherLogsABundleConflictOnceAndStopsRetrying(t *testing.T) {
	c := newHandoffCopies(t)
	request, _ := transportFixture()
	q := c.q
	q.Context = request.Context
	local := openStore(t)
	remoteLog, remoteSink := quietLog()
	_, err := RetainBundle(t.Context(), local, q, c.diff, c.verify, remoteLog) // what the publisher holds: the different handoff
	require.NoError(t, err)
	remote := openStore(t)
	_, err = RetainBundle(t.Context(), remote, q, c.one, c.verify, remoteLog) // what the conflicting replica holds
	require.NoError(t, err)
	healthy := openStore(t)

	client := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	conflicting := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	good := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	client.Network().Peerstore().AddAddrs(conflicting.ID(), conflicting.MultiAddresses(), peerstore.PermanentAddrTTL)
	client.Network().Peerstore().AddAddrs(good.ID(), good.MultiAddresses(), peerstore.PermanentAddrTTL)
	serve := func(store *archive.Store, host peer.ID) {
		s, err := NewServer(store, request.Context, func(context.Context, archive.Request, *archive.Record) error { return nil }, []peer.ID{client.ID()}, DefaultLimits())
		require.NoError(t, err)
		s.SetBundleVerifier(c.verify)
		s.SetLogger(remoteLog)
		switch host {
		case conflicting.ID():
			s.Register(context.Background(), conflicting)
		default:
			s.Register(context.Background(), good)
		}
	}
	serve(remote, conflicting.ID())
	serve(healthy, good.ID())

	pubLog, pubSink := quietLog()
	p := &Publisher{Archive: local, Subject: request.Context, Host: client, Replicas: [2]peer.ID{conflicting.ID(), good.ID()}, Limits: DefaultLimits(),
		BundleVerifier: c.verify, Log: pubLog, bundleAck: make(map[uint64]uint8)}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for pass := 0; pass < 3; pass++ {
		require.NoError(t, p.publishBundles(ctx), "a recorded conflict is not a transient failure to wait on (pass %d)", pass)
	}
	conflictLines := 0
	for _, line := range strings.Split(pubSink.String(), "\n") {
		if strings.Contains(line, "level=ERROR") && strings.Contains(line, "CONFLICTING HANDOFF BUNDLE") && strings.Contains(line, conflicting.ID().String()) {
			conflictLines++
		}
	}
	require.Equal(t, 1, conflictLines, "logged once at ERROR, naming the replica:\n%s", pubSink.String())
	require.Equal(t, 1, strings.Count(remoteSink.String(), "CONFLICTING HANDOFF BUNDLE"), "the replica was asked once, not on every pass")
	got, err := healthy.GetBundle(q)
	require.NoError(t, err)
	require.Equal(t, c.diff, got, "the other replica still receives the bundle")
	require.Zero(t, p.bundleAck[q.Epoch]&1, "the conflicting copy is never acknowledged")
	require.NotZero(t, p.bundleAck[q.Epoch]&2)
}
