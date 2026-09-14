package inputcarrier_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/inputcarrier"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// network.Peer is the production host type. Asserted so the Host interface cannot drift from it.
var _ inputcarrier.Host = (*network.Peer)(nil)

func frame(t *testing.T, e inputcarrier.Envelope) []byte {
	t.Helper()
	body, err := inputcarrier.Encode(e, inputcarrier.DefaultLimits)
	require.NoError(t, err)
	prefix := binary.AppendUvarint(nil, uint64(len(body)))
	return append(prefix, body...)
}

func newReceiver(t *testing.T, l inputcarrier.TransportLimits) *inputcarrier.Receiver {
	t.Helper()
	r, err := inputcarrier.NewReceiver(l, nil)
	require.NoError(t, err)
	t.Cleanup(r.Close)
	return r
}

func TestProtocolIsSeparateFromTheShardPayloadProtocol(t *testing.T) {
	require.Equal(t, "/unicity/shard-payload/1.0.0", shardnode.ProtocolShardPayload, "the production dissemination protocol is unchanged")
	require.NotEqual(t, shardnode.ProtocolShardPayload, inputcarrier.Protocol)
}

func TestTransport_TwoRealPeers(t *testing.T) {
	leader := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	follower := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	leader.Network().Peerstore().AddAddrs(follower.ID(), follower.MultiAddresses(), peerstore.PermanentAddrTTL)
	follower.Network().Peerstore().AddAddrs(leader.ID(), leader.MultiAddresses(), peerstore.PermanentAddrTTL)

	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	r.Register(follower)

	e := sampleEnvelope()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, inputcarrier.Send(ctx, leader, follower.ID(), e, inputcarrier.DefaultTransportLimits))

	got, err := r.Await(ctx, e.ShardRound)
	require.NoError(t, err)
	require.Equal(t, e, got)
}

func TestReceiver_DuplicateDoesNotReplaceTheFirstDelivery(t *testing.T) {
	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	first := sampleEnvelope()
	second := sampleEnvelope()
	second.Certificate = []byte{0x80, 0x09}

	require.NoError(t, r.Serve(bytes.NewReader(frame(t, first)), "peer-a"))
	require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, second)), "peer-b"), inputcarrier.ErrDuplicate)

	for i := 0; i < 2; i++ {
		got, err := r.Await(context.Background(), first.ShardRound)
		require.NoError(t, err)
		require.Equal(t, first, got)
	}
}

// endless yields zero bytes forever. A receiver that read a declared body before checking its length
// would allocate the declared size and never finish reading.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestReceiver_FrameOverTheBoundIsRefusedBeforeItsBodyIsRead(t *testing.T) {
	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	prefix := binary.AppendUvarint(nil, 1<<40)

	done := make(chan error, 1)
	go func() { done <- r.Serve(io.MultiReader(bytes.NewReader(prefix), endless{}), "peer-a") }()
	select {
	case err := <-done:
		require.ErrorIs(t, err, inputcarrier.ErrTransport)
	case <-time.After(5 * time.Second):
		t.Fatal("Serve kept reading a frame whose declared length is over the bound")
	}
	require.Zero(t, r.PendingRounds())
	streams, _ := r.PendingStreams()
	require.Zero(t, streams, "the admission slot is released on the refusal path")
}

func TestReceiver_NonCanonicalFrameIsNotDelivered(t *testing.T) {
	r := newReceiver(t, inputcarrier.DefaultTransportLimits)
	body, err := inputcarrier.Encode(sampleEnvelope(), inputcarrier.DefaultLimits)
	require.NoError(t, err)
	body = append(body, 0x00)
	f := append(binary.AppendUvarint(nil, uint64(len(body))), body...)

	require.ErrorIs(t, r.Serve(bytes.NewReader(f), "peer-a"), inputcarrier.ErrMalformedEnvelope)
	require.Zero(t, r.PendingRounds())
}

func TestReceiver_PendingRoundsAreBoundedAndReleasedByPrune(t *testing.T) {
	l := inputcarrier.DefaultTransportLimits
	l.MaxPendingRounds = 3
	r := newReceiver(t, l)

	at := func(round uint64) []byte {
		e := sampleEnvelope()
		e.ShardRound = round
		return frame(t, e)
	}
	for round := uint64(1); round <= 3; round++ {
		require.NoError(t, r.Serve(bytes.NewReader(at(round)), "peer-a"))
	}
	require.ErrorIs(t, r.Serve(bytes.NewReader(at(4)), "peer-a"), inputcarrier.ErrTooManyRounds)
	_, err := r.Await(context.Background(), 9)
	require.ErrorIs(t, err, inputcarrier.ErrTooManyRounds, "an Await for a new round counts against the same bound")

	r.Prune(2)
	require.Equal(t, 1, r.PendingRounds())
	require.NoError(t, r.Serve(bytes.NewReader(at(4)), "peer-a"))
	require.ErrorIs(t, r.Serve(bytes.NewReader(at(2)), "peer-a"), inputcarrier.ErrPruned)
	_, err = r.Await(context.Background(), 1)
	require.ErrorIs(t, err, inputcarrier.ErrPruned)
}

func TestReceiver_StreamAdmissionIsBoundedPerPeerAndReleased(t *testing.T) {
	l := inputcarrier.DefaultTransportLimits
	l.MaxPendingStreams = 3
	l.MaxPendingStreamsPerPeer = 1
	r := newReceiver(t, l)

	// hold opens a stream from a peer that has sent nothing yet, and returns its writer and result.
	hold := func(from string) (*io.PipeWriter, chan error) {
		rd, w := io.Pipe()
		done := make(chan error, 1)
		go func() { done <- r.Serve(rd, from) }()
		return w, done
	}
	pending := func(n int) {
		require.Eventually(t, func() bool { s, _ := r.PendingStreams(); return s == n }, 5*time.Second, 10*time.Millisecond)
	}

	// Two streams held, from two peers: under the total bound of three.
	aWrite, aDone := hold("peer-a")
	bWrite, bDone := hold("peer-b")
	pending(2)

	// The per-peer bound refuses peer-a's second stream while total capacity remains, so this
	// refusal can only come from the per-peer bound.
	require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, sampleEnvelope())), "peer-a"), inputcarrier.ErrNotAdmitted, "per-peer bound")
	s, _ := r.PendingStreams()
	require.Less(t, s, l.MaxPendingStreams, "premise: the total bound was not reached")

	// A third peer fills the total bound; a fourth is then refused by it.
	cWrite, cDone := hold("peer-c")
	pending(3)
	require.ErrorIs(t, r.Serve(bytes.NewReader(frame(t, sampleEnvelope())), "peer-d"), inputcarrier.ErrNotAdmitted, "total bound")

	// One stream completes, two are abandoned; all release their slots.
	go func() { _, _ = aWrite.Write(frame(t, sampleEnvelope())); _ = aWrite.Close() }()
	require.NoError(t, <-aDone)
	_ = bWrite.CloseWithError(errors.New("peer went away"))
	require.ErrorIs(t, <-bDone, inputcarrier.ErrTransport)
	_ = cWrite.CloseWithError(errors.New("peer went away"))
	require.ErrorIs(t, <-cDone, inputcarrier.ErrTransport)

	streams, peers := r.PendingStreams()
	require.Zero(t, streams)
	require.Zero(t, peers)
}

func TestTransport_StalledStreamCostsOneDeadline(t *testing.T) {
	leader := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	follower := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	leader.Network().Peerstore().AddAddrs(follower.ID(), follower.MultiAddresses(), peerstore.PermanentAddrTTL)

	l := inputcarrier.DefaultTransportLimits
	l.Deadline = 300 * time.Millisecond
	r := newReceiver(t, l)
	r.Register(follower)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := leader.CreateStream(ctx, follower.ID(), inputcarrier.Protocol)
	require.NoError(t, err)
	defer s.Reset()
	// Write one byte so the receiver's handler is certainly running, then stall.
	_, err = s.Write([]byte{0x05})
	require.NoError(t, err)

	require.Eventually(t, func() bool { n, _ := r.PendingStreams(); return n == 1 }, 5*time.Second, 5*time.Millisecond)
	start := time.Now()
	require.Eventually(t, func() bool { n, _ := r.PendingStreams(); return n == 0 }, 5*time.Second, 5*time.Millisecond)
	require.Less(t, time.Since(start), 3*time.Second, "a stalled stream is released after about one deadline")
	require.Zero(t, r.PendingRounds())
}

// countingHost records whether a stream was opened.
type countingHost struct{ opened int }

func (h *countingHost) RegisterProtocolHandler(string, libp2pnetwork.StreamHandler) {}
func (h *countingHost) CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error) {
	h.opened++
	return nil, errors.New("not a real host")
}

func TestSend_RefusesAnOversizedEnvelopeBeforeOpeningAStream(t *testing.T) {
	h := &countingHost{}
	e := sampleEnvelope()
	e.Certificate = make([]byte, inputcarrier.DefaultLimits.MaxCertificateBytes+1)
	err := inputcarrier.Send(context.Background(), h, peer.ID("x"), e, inputcarrier.DefaultTransportLimits)
	require.ErrorIs(t, err, inputcarrier.ErrMalformedEnvelope)
	require.Zero(t, h.opened)
}
