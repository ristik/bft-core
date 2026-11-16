package network

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p"
	"github.com/libp2p/go-libp2p/config"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

func TestNewLibP2RootConsensusNetwork(t *testing.T) {
	h, err := libp2p.New([]config.Option{
		libp2p.ListenAddrStrings(defaultAddress),
	}...)
	require.NoError(t, err)
	defer func() {
		err := h.Close()
		if err != nil {
			t.Fatalf("error closing node %v", err)
		}
	}()
	peer := &Peer{host: h}

	capacity := uint(1000)
	sendTimeout := 300 * time.Millisecond
	result, err := NewLibP2RootConsensusNetwork(peer, capacity, sendTimeout, observability.Default(t))

	require.NoError(t, err)
	require.Equal(t, h.ID(), result.self.ID())
	require.GreaterOrEqual(t, result.sendProtocols[reflect.TypeOf(abdrc.HandoffApprovalMsg{})].timeout, 5*time.Second)
}

// #1086 review: a received message's authenticated sender and frame size are kept for the consumer that tracks them, and a vote frame over
// MaxRootVoteFrame is refused before it is decoded.
func TestRootConsensusNetworkOriginsAndVoteFrameLimit(t *testing.T) {
	obs := observability.Default(t)
	sender := createPeer(t)
	t.Cleanup(func() { _ = sender.Close() })
	receiver := createPeer(t)
	t.Cleanup(func() { _ = receiver.Close() })
	out, err := NewLibP2RootConsensusNetwork(sender, 8, time.Second, observability.NOPObservability()) // its sends log after the test
	require.NoError(t, err)
	in, err := NewLibP2RootConsensusNetwork(receiver, 8, time.Second, obs)
	require.NoError(t, err)
	sender.Network().Peerstore().AddAddrs(receiver.ID(), receiver.MultiAddresses(), peerstore.PermanentAddrTTL)
	in.TrackOrigins()
	received := in.ReceivedChannel()

	vote := &abdrc.VoteMsg{Author: "forged-author", VoteInfo: &drctypes.RoundInfo{RoundNumber: 7, Epoch: 2}}
	require.NoError(t, out.Send(context.Background(), vote, receiver.ID()))
	var got any
	select {
	case got = <-received:
	case <-time.After(5 * time.Second):
		t.Fatal("the vote was not delivered")
	}
	from, size, ok := in.TakeOrigin(got)
	require.True(t, ok)
	require.Equal(t, sender.ID(), from, "the transport's peer, whatever the message claims")
	require.NotZero(t, size)
	_, _, ok = in.TakeOrigin(got)
	require.False(t, ok, "taken once")

	big := &abdrc.VoteMsg{Author: "x", VoteInfo: &drctypes.RoundInfo{Epoch: 2}, Signature: make([]byte, MaxRootVoteFrame+1)}
	_ = out.Send(context.Background(), big, receiver.ID())
	select {
	case m := <-received:
		t.Fatalf("an oversized vote frame was delivered: %T", m)
	case <-time.After(500 * time.Millisecond):
	}
	in.originsMu.Lock()
	require.Empty(t, in.origins, "nothing is kept for a refused frame")
	in.originsMu.Unlock()
}
