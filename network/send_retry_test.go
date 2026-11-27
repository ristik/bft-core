package network

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	libp2pNetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
)

type retryMsg struct {
	_     struct{} `cbor:",toarray"`
	Name  string
	Value int
}

// sendRetryPair is a sender and a receiver on loopback; the sender's attempts go through fail, which may refuse one before it reaches the
// wire.
func sendRetryPair(t *testing.T, retries int, fail func(attempt int32) error) (nw1, nw2 *LibP2PNetwork, attempts *atomic.Int32) {
	t.Helper()
	obs := observability.Default(t)
	peer1, peer2 := createPeer(t), createPeer(t)
	t.Cleanup(func() { require.NoError(t, peer1.Close()); require.NoError(t, peer2.Close()) })
	var err error
	nw1, err = NewLibP2PNetwork(peer1, 1, obs)
	require.NoError(t, err)
	nw2, err = NewLibP2PNetwork(peer2, 10, obs)
	require.NoError(t, err)
	peer1.Network().Peerstore().AddAddrs(peer2.ID(), peer2.MultiAddresses(), peerstore.PermanentAddrTTL)
	// connected up front: a repeat never dials (it runs under the no-dial context), as in a cluster whose roots are connected
	require.NoError(t, peer1.host.Connect(context.Background(), peer.AddrInfo{ID: peer2.ID(), Addrs: peer2.MultiAddresses()}))
	require.NoError(t, nw1.registerSendProtocol(SendProtocolDescription{ProtocolID: "test/p", MsgType: retryMsg{}, Timeout: 200 * time.Millisecond, Retries: retries}))
	require.NoError(t, nw2.registerReceiveProtocol(ReceiveProtocolDescription{ProtocolID: "test/p", TypeFn: func() any { return &retryMsg{} }}))
	attempts = &atomic.Int32{}
	nw1.sendData = func(ctx context.Context, host *Peer, protocolID string, data []byte, receiverID peer.ID) error {
		if err := fail(attempts.Add(1)); err != nil {
			return err
		}
		return sendMsg(ctx, host, protocolID, data, receiverID)
	}
	return nw1, nw2, attempts
}

func receivedWithin(t *testing.T, nw *LibP2PNetwork, d time.Duration) []any {
	t.Helper()
	var got []any
	deadline := time.After(d)
	for {
		select {
		case m := <-nw.ReceivedChannel():
			got = append(got, m)
		case <-deadline:
			return got
		}
	}
}

// A message whose first attempts are not delivered (the deadline ran out opening the stream) to a connected receiver is sent again, and the
// receiver gets it once (#982: at exactly a quorum, a lost proposal or vote stalls the round).
func TestUndeliveredMessageIsRetriedToAConnectedReceiver(t *testing.T) {
	timedOut := errors.Join(ErrNotDelivered, context.DeadlineExceeded)
	nw1, nw2, attempts := sendRetryPair(t, 2, func(n int32) error {
		if n <= 2 {
			return timedOut
		}
		return nil
	})
	nw1.connected = func(peer.ID) bool { return true }
	msg := &retryMsg{Name: "vote", Value: 7}
	require.NoError(t, nw1.Send(context.Background(), msg, nw2.self.ID()))
	got := receivedWithin(t, nw2, 3*time.Second)
	require.Equal(t, []any{msg}, got, "delivered once, by the third attempt")
	require.EqualValues(t, 3, attempts.Load())
}

// The retries are bounded: after Retries more attempts the message is given up.
func TestUndeliveredMessageIsGivenUpAfterTheRetries(t *testing.T) {
	nw1, nw2, attempts := sendRetryPair(t, 2, func(int32) error { return ErrNotDelivered })
	nw1.connected = func(peer.ID) bool { return true }
	require.NoError(t, nw1.Send(context.Background(), &retryMsg{Name: "vote"}, nw2.self.ID()))
	require.Empty(t, receivedWithin(t, nw2, 2*time.Second))
	require.EqualValues(t, 3, attempts.Load())
}

// No retry to a receiver the host is not connected to (a root that is down: retrying would only dial it again), none for an error after the
// message was written (it may have been delivered), and none for a protocol without retries.
func TestNoRetryWithoutConnectionAfterAWriteOrWithoutRetries(t *testing.T) {
	t.Run("not connected", func(t *testing.T) {
		nw1, nw2, attempts := sendRetryPair(t, 2, func(int32) error { return ErrNotDelivered })
		nw1.connected = func(peer.ID) bool { return false }
		require.NoError(t, nw1.Send(context.Background(), &retryMsg{Name: "vote"}, nw2.self.ID()))
		require.Empty(t, receivedWithin(t, nw2, time.Second))
		require.EqualValues(t, 1, attempts.Load())
	})
	t.Run("written", func(t *testing.T) {
		nw1, nw2, attempts := sendRetryPair(t, 2, func(int32) error { return errors.New("closing p2p stream: reset") })
		nw1.connected = func(peer.ID) bool { return true }
		require.NoError(t, nw1.Send(context.Background(), &retryMsg{Name: "vote"}, nw2.self.ID()))
		require.Empty(t, receivedWithin(t, nw2, time.Second))
		require.EqualValues(t, 1, attempts.Load())
	})
	t.Run("no retries", func(t *testing.T) {
		nw1, nw2, attempts := sendRetryPair(t, 0, func(int32) error { return ErrNotDelivered })
		nw1.connected = func(peer.ID) bool { return true }
		require.NoError(t, nw1.Send(context.Background(), &retryMsg{Name: "vote"}, nw2.self.ID()))
		require.Empty(t, receivedWithin(t, nw2, time.Second))
		require.EqualValues(t, 1, attempts.Load())
	})
}

// The real connectedness: a message to a peer the sender has connected to is retried, one to a peer it never reached is not.
func TestRetryFollowsTheHostConnection(t *testing.T) {
	nw1, nw2, attempts := sendRetryPair(t, 1, func(n int32) error {
		if n == 1 {
			return ErrNotDelivered
		}
		return nil
	})
	stranger := createPeer(t)
	t.Cleanup(func() { require.NoError(t, stranger.Close()) })
	require.False(t, nw1.connected(stranger.ID()))
	ctx := context.Background()
	require.NoError(t, nw1.self.host.Connect(ctx, peer.AddrInfo{ID: nw2.self.ID(), Addrs: nw2.self.MultiAddresses()}))
	require.True(t, nw1.connected(nw2.self.ID()))
	msg := &retryMsg{Name: "proposal"}
	require.NoError(t, nw1.Send(ctx, msg, nw2.self.ID()))
	require.Equal(t, []any{msg}, receivedWithin(t, nw2, 2*time.Second))
	require.EqualValues(t, 2, attempts.Load())
}

// A receiver that disconnects during the delay before a repeat gets no repeat: connectedness is checked again after the delay (astra, #1068).
func TestNoRetryToAReceiverThatDisconnectedDuringTheDelay(t *testing.T) {
	nw1, nw2, attempts := sendRetryPair(t, 2, func(int32) error { return ErrNotDelivered })
	var checks atomic.Int32
	nw1.connected = func(peer.ID) bool { return checks.Add(1) == 1 } // connected when the first attempt fails, gone after the delay
	require.NoError(t, nw1.Send(context.Background(), &retryMsg{Name: "vote"}, nw2.self.ID()))
	require.Empty(t, receivedWithin(t, nw2, time.Second))
	require.EqualValues(t, 1, attempts.Load(), "no second attempt")
	require.EqualValues(t, 2, checks.Load(), "checked before and after the delay")
}

// A repeat never dials: it runs under libp2p's no-dial context, while the first attempt dials as before.
func TestARepeatRunsWithoutDialing(t *testing.T) {
	nw1, nw2, _ := sendRetryPair(t, 2, func(int32) error { return nil })
	nw1.connected = func(peer.ID) bool { return true }
	var noDial []bool
	var calls atomic.Int32
	nw1.sendData = func(ctx context.Context, host *Peer, protocolID string, data []byte, receiverID peer.ID) error {
		nd, _ := libp2pNetwork.GetNoDial(ctx)
		noDial = append(noDial, nd)
		if calls.Add(1) == 1 {
			return notDelivered{errors.New("open p2p stream: timed out")}
		}
		return sendMsg(ctx, host, protocolID, data, receiverID)
	}
	msg := &retryMsg{Name: "vote"}
	require.NoError(t, nw1.Send(context.Background(), msg, nw2.self.ID()))
	require.Equal(t, []any{msg}, receivedWithin(t, nw2, 2*time.Second))
	require.Equal(t, []bool{false, true}, noDial, "the first attempt may dial, the repeat may not")
}

// A failed write does not prove non-delivery: here the first attempt delivers the message and still reports ErrNotDelivered. The repeat is the
// same bytes, so the receiver gets two identical copies (the consensus side refuses the second as a duplicate:
// TestExactQuorumCommitsOverLinksThatLoseSends, "delivered but reported lost").
func TestADeliveredAttemptReportedAsFailedIsRepeatedAsTheSameBytes(t *testing.T) {
	nw1, nw2, attempts := sendRetryPair(t, 2, func(int32) error { return nil })
	nw1.connected = func(peer.ID) bool { return true }
	inner := nw1.sendData
	var sent [][]byte
	nw1.sendData = func(ctx context.Context, host *Peer, protocolID string, data []byte, receiverID peer.ID) error {
		sent = append(sent, data)
		if err := inner(ctx, host, protocolID, data, receiverID); err != nil {
			return err
		}
		if len(sent) == 1 {
			return notDelivered{errors.New("writing data to p2p stream: i/o deadline reached")}
		}
		return nil
	}
	msg := &retryMsg{Name: "vote", Value: 3}
	require.NoError(t, nw1.Send(context.Background(), msg, nw2.self.ID()))
	require.Equal(t, []any{msg, msg}, receivedWithin(t, nw2, 2*time.Second), "delivered twice")
	require.EqualValues(t, 2, attempts.Load())
	require.Len(t, sent, 2)
	require.Equal(t, sent[0], sent[1], "the repeat is the same serialized message")
}

// SetSendFault with send true makes the attempt and reports the error afterwards: a delivered message the sender counts as lost.
func TestSendFaultCanDeliverAndReportAnError(t *testing.T) {
	nw1, nw2, _ := sendRetryPair(t, 1, func(int32) error { return nil })
	nw1.connected = func(peer.ID) bool { return true }
	nw1.SetSendFault(func(_ string, _ peer.ID, attempt int) (bool, error) {
		if attempt == 1 {
			return true, notDelivered{errors.New("reported lost")}
		}
		return true, nil
	})
	msg := &retryMsg{Name: "timeout"}
	require.NoError(t, nw1.Send(context.Background(), msg, nw2.self.ID()))
	require.Equal(t, []any{msg, msg}, receivedWithin(t, nw2, 2*time.Second))
}
