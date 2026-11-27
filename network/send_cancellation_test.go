package network

import (
	"context"
	"io"
	"testing"
	"time"

	libp2pNetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/protocol"
	"github.com/stretchr/testify/require"
)

func openSendTestStream(t *testing.T) (libp2pNetwork.Stream, libp2pNetwork.Stream) {
	t.Helper()
	sender, receiver := createPeer(t), createPeer(t)
	const protocolID = "/test/send-cancellation/1"
	incoming := make(chan libp2pNetwork.Stream, 1)
	receiver.RegisterProtocolHandler(protocolID, func(s libp2pNetwork.Stream) { incoming <- s })
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	require.NoError(t, sender.host.Connect(ctx, peer.AddrInfo{ID: receiver.ID(), Addrs: receiver.MultiAddresses()}))
	// Negotiate eagerly so both ends are open before the payload is written.
	require.NoError(t, sender.host.Peerstore().RemoveProtocols(receiver.ID(), protocol.ID(protocolID)))
	out, err := sender.CreateStream(ctx, receiver.ID(), protocolID)
	require.NoError(t, err)
	t.Cleanup(func() { _ = out.Close() })
	select {
	case in := <-incoming:
		t.Cleanup(func() { _ = in.Close() })
		return out, in
	case <-ctx.Done():
		t.Fatal("receiver did not open the negotiated stream")
		return nil, nil
	}
}

type pauseBeforeWrite struct {
	libp2pNetwork.Stream
	paused, resume chan struct{}
	writes         int
}

func (s *pauseBeforeWrite) SetWriteDeadline(deadline time.Time) error {
	err := s.Stream.SetWriteDeadline(deadline)
	close(s.paused)
	<-s.resume
	return err
}

func (s *pauseBeforeWrite) Write(p []byte) (int, error) {
	s.writes++
	return s.Stream.Write(p)
}

func TestCanceledSendResetsAnOpenStreamBeforeTheFirstWrite(t *testing.T) {
	out, in := openSendTestStream(t)
	s := &pauseBeforeWrite{Stream: out, paused: make(chan struct{}), resume: make(chan struct{})}
	defer close(s.resume)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- writeMsg(ctx, s, []byte{1}) }()
	select {
	case <-s.paused:
	case <-time.After(5 * time.Second):
		t.Fatal("sender did not reach the open stream")
	}
	cancel()
	require.NoError(t, in.SetReadDeadline(time.Now().Add(5*time.Second)))
	n, err := in.Read(make([]byte, 1))
	require.Zero(t, n)
	require.ErrorIs(t, err, libp2pNetwork.ErrReset)
	s.resume <- struct{}{}
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		require.Zero(t, s.writes, "the canceled worker must never begin writing")
	case <-time.After(5 * time.Second):
		t.Fatal("canceled sender did not return")
	}
}

func TestCanceledSendInterruptsABlockedWriteOnAnOpenStream(t *testing.T) {
	out, in := openSendTestStream(t)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	done := make(chan error, 1)
	// A payload bigger than the flow-control window blocks once the
	// receiver stops reading. Read one byte to prove the write started.
	go func() { done <- writeMsg(ctx, out, make([]byte, 16<<20)) }()
	require.NoError(t, in.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err := io.ReadFull(in, make([]byte, 1))
	require.NoError(t, err)
	select {
	case err := <-done:
		t.Fatalf("write finished before cancellation: %v", err)
	default:
	}
	cancel()
	select {
	case err := <-done:
		require.ErrorIs(t, err, context.Canceled)
		require.ErrorIs(t, err, ErrNotDelivered)
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation did not interrupt the blocked write")
	}
}
