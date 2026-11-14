package q3delivery

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"

	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/q3active"
)

type fakeProvider struct {
	bundle q3active.Bundle
	err    error
	asked  []uint64
}

func (p *fakeProvider) Q3Bundle(_ context.Context, epoch uint64) (q3active.Bundle, error) {
	p.asked = append(p.asked, epoch)
	return p.bundle, p.err
}

// serveOnce runs one Serve against a client exchange over an in-memory duplex and returns the client's result.
func serveOnce(t *testing.T, s *Server, epoch uint64) (q3active.Bundle, error) {
	t.Helper()
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := s.Serve(context.Background(), struct {
			io.Reader
			io.Writer
		}{sr, sw})
		_ = sw.Close()
		done <- err
	}()
	b, err := exchange(struct {
		io.Reader
		io.Writer
	}{cr, cw}, epoch)
	_ = cw.Close()
	<-done
	return b, err
}

func TestAnActivationBundleIsServedAndFetchedByteForByte(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	bundle := q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot, Candidate: f.Candidate}
	p := &fakeProvider{bundle: bundle}
	s, err := NewServer(p)
	require.NoError(t, err)

	got, err := serveOnce(t, s, f.Claim.Epoch)
	require.NoError(t, err)
	want, err := q3active.EncodeBundle(bundle)
	require.NoError(t, err)
	have, err := q3active.EncodeBundle(got)
	require.NoError(t, err)
	require.Equal(t, want, have)
	require.Equal(t, []uint64{f.Claim.Epoch}, p.asked)
}

func TestTheExchangeRefusesEachWrongThingAndAsksNoProviderForABadEpoch(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	good := q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot}

	p := &fakeProvider{bundle: good}
	s, _ := NewServer(p)
	_, err := serveOnce(t, s, 1)
	require.ErrorIs(t, err, ErrBundle, "epoch 1 is not a successor")
	require.Empty(t, p.asked, "an invalid epoch never reaches the provider")

	_, err = serveOnce(t, s, f.Claim.Epoch+1)
	require.ErrorIs(t, err, ErrBundle, "a provider that serves another epoch's bundle")

	p = &fakeProvider{err: errors.New("not committed here")}
	s, _ = NewServer(p)
	_, err = serveOnce(t, s, f.Claim.Epoch)
	require.ErrorIs(t, err, ErrBundle)
	require.Contains(t, err.Error(), "activation unavailable")

	p = &fakeProvider{bundle: q3active.Bundle{Envelope: []byte("garbage"), Snapshot: f.Snapshot}}
	s, _ = NewServer(p)
	_, err = serveOnce(t, s, f.Claim.Epoch)
	require.ErrorIs(t, err, ErrBundle, "a bundle that does not decode is never served")

	_, err = NewServer(nil)
	require.Error(t, err)
}

func TestServerBoundsOnePeersConcurrentRequests(t *testing.T) {
	s, err := NewServer(&fakeProvider{err: errors.New("none")})
	require.NoError(t, err)
	a, b := peer.ID("a"), peer.ID("b")
	for range maxPerPeer {
		require.True(t, s.reservePeer(a))
	}
	require.False(t, s.reservePeer(a), "one peer cannot hold more than its share")
	require.True(t, s.reservePeer(b), "another peer is still served")
	s.releasePeer(a)
	require.True(t, s.reservePeer(a))
}

type fixedProvider struct{ bundle q3active.Bundle }

func (p fixedProvider) Q3Bundle(context.Context, uint64) (q3active.Bundle, error) {
	return p.bundle, nil
}

// A peer that opens every stream it can and withholds its request frames does not stop a second peer from obtaining a staged bundle,
// and its stalled streams are released at the short header deadline, not the request deadline.
func TestOneStalledPeerCannotBlockAnother(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	s, err := NewServer(fixedProvider{q3active.Bundle{Envelope: f.EnvelopeBytes, Snapshot: f.Snapshot, Candidate: f.Candidate}})
	require.NoError(t, err)
	server := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	s.Register(server)
	stalled := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	honest := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for _, c := range []*network.Peer{stalled, honest} {
		c.Network().Peerstore().AddAddrs(server.ID(), server.MultiAddresses(), peerstore.PermanentAddrTTL)
	}
	ctx := context.Background()
	var held []libp2pnetwork.Stream
	for range maxConcurrent {
		st, err := stalled.CreateStream(ctx, server.ID(), Protocol)
		require.NoError(t, err)
		_, _ = st.Write([]byte{0}) // opens the stream on the server, never completes a frame
		held = append(held, st)
	}
	t.Cleanup(func() {
		for _, st := range held {
			_ = st.Reset()
		}
	})
	time.Sleep(200 * time.Millisecond)
	s.mu.Lock()
	require.LessOrEqual(t, s.perPeer[stalled.ID()], maxPerPeer, "the stalled peer holds at most its share")
	s.mu.Unlock()

	started := time.Now()
	got, err := Request(ctx, honest, server.ID(), f.Claim.Epoch)
	require.NoError(t, err)
	require.Equal(t, f.Candidate, got.Candidate)
	require.Less(t, time.Since(started), headerDeadline, "served at once, not after the stalled peer's streams expire")

	require.Eventually(t, func() bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.perPeer[stalled.ID()] == 0
	}, requestDeadline/2, 50*time.Millisecond, "withheld requests are dropped at the header deadline")
}

// Each peer has a request budget: a burst, then a steady rate, independent of other peers.
func TestEachPeerHasARateBudget(t *testing.T) {
	s, err := NewServer(&fakeProvider{err: errors.New("none")})
	require.NoError(t, err)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	a, b := peer.ID("a"), peer.ID("b")
	for range perPeerBurst {
		require.True(t, s.reservePeer(a))
		s.releasePeer(a)
	}
	require.False(t, s.reservePeer(a), "the burst is spent")
	require.True(t, s.reservePeer(b), "another peer has its own budget")
	now = now.Add(time.Second)
	require.True(t, s.reservePeer(a), "the budget refills at its rate")
}
