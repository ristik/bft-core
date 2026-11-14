package shardnode

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// The backup path (phase 2): the roots push nothing (every handshake is dropped), and the node's active peers hold the certificate. One
// peer relays a forged pair, another the genuine one: the forged one is refused by the same admission as a root's response and does not
// move the progress clock; the genuine one is delivered to the driver. A follower does not use the relay.
func TestTheUCRelayBacksUpTheRootPushWithVerifiedPairs(t *testing.T) {
	f := newConfBindingFixture(t)
	good := f.respond(f.ucMine)
	raw, err := types.Cbor.Marshal(&good.UC)
	require.NoError(t, err)
	var forged types.UnicityCertificate
	require.NoError(t, types.Cbor.Unmarshal(raw, &forged))
	forged.UnicitySeal.RootChainRoundNumber += 3

	node := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	serve := func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) peer.ID {
		p := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		p.RegisterProtocolHandler(UCRelayProtocol, NewUCRelayServer(func() (*types.UnicityCertificate, *certification.TechnicalRecord) { return uc, tr },
			func(id peer.ID) bool { return id == node.ID() }).Handler)
		node.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
		return p.ID()
	}
	liar, honest := serve(&forged, &good.Technical), serve(&good.UC, &good.Technical)

	net := &lateRootNet{received: make(chan any, 4)} // a root that never answers
	driver := &firstUCDriver{got: make(chan struct{})}
	client, err := NewBFTClient(node, net, f.signer, authPartitionID, types.ShardID{}, f.confMine, stubTrustBaseStore{tb: f.tb}, driver, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: time.Hour})
	require.NoError(t, err)
	client.SetRelay(node, func() []peer.ID { return []peer.ID{liar, honest} }, 50*time.Millisecond)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case <-driver.got:
	case <-time.After(10 * time.Second):
		t.Fatal("the relayed genuine certificate was not delivered")
	}
	uc, _ := client.Held()
	require.Equal(t, good.UC.GetRootRoundNumber(), uc.GetRootRoundNumber(), "the genuine pair is held, never the forged one")
}

func TestAFollowerDoesNotUseTheUCRelay(t *testing.T) {
	f := newConfBindingFixture(t)
	node := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	client, err := NewBFTClient(node, &lateRootNet{received: make(chan any, 1)}, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, &firstUCDriver{got: make(chan struct{})}, nil, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1})
	require.NoError(t, err)
	client.SetRelay(node, func() []peer.ID { return nil }, time.Millisecond)
	client.SetFollowerRole(func() bool { return true })
	require.False(t, client.relayDue(time.Now().Add(time.Hour)), "a non-active node takes its certificates from its follow sources")
	client.SetFollowerRole(func() bool { return false })
	require.True(t, client.relayDue(time.Now().Add(time.Hour)))
}

// The server answers only the peers it admits, at most two streams of one peer at a time.
func TestTheUCRelayServerAdmitsOnlyItsPeers(t *testing.T) {
	f := newConfBindingFixture(t)
	good := f.respond(f.ucMine)
	server := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	member := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	stranger := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	s := NewUCRelayServer(func() (*types.UnicityCertificate, *certification.TechnicalRecord) { return &good.UC, &good.Technical },
		func(id peer.ID) bool { return id == member.ID() })
	server.RegisterProtocolHandler(UCRelayProtocol, s.Handler)
	member.Network().Peerstore().AddAddrs(server.ID(), server.MultiAddresses(), peerstore.PermanentAddrTTL)
	stranger.Network().Peerstore().AddAddrs(server.ID(), server.MultiAddresses(), peerstore.PermanentAddrTTL)
	uc, tr, err := FetchHeldPair(context.Background(), member, server.ID())
	require.NoError(t, err)
	require.Equal(t, good.UC.GetRootRoundNumber(), uc.GetRootRoundNumber())
	require.Equal(t, good.Technical.Round, tr.Round)
	_, _, err = FetchHeldPair(context.Background(), stranger, server.ID())
	require.Error(t, err, "a peer that is not admitted gets nothing")
	require.True(t, s.reserve("p") && s.reserve("p"))
	require.False(t, s.reserve("p"), "two concurrent requests per peer")
}

// blackholeOpener is a relay peer that never answers: CreateStream blocks until its context ends.
type blackholeOpener struct {
	entered   chan struct{}
	cancelled atomic.Int32
	calls     atomic.Int32
}

func (o *blackholeOpener) CreateStream(ctx context.Context, _ peer.ID, _ string) (libp2pnetwork.Stream, error) {
	o.calls.Add(1)
	select {
	case o.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	o.cancelled.Add(1)
	return nil, ctx.Err()
}

// astra on #1054, finding 1: a relay peer that blackholes its streams no longer holds up the client's loop. A genuine root push queued while
// both relay fetches are blocked is delivered at once, and that adoption cancels the blocked fetches; a retirement cancels them too and
// starts no further batch.
func TestABlackholedRelayDoesNotDelayTheRootPushAndIsCancelled(t *testing.T) {
	for _, tc := range []string{"root push", "retirement"} {
		t.Run(tc, func(t *testing.T) {
			f := newConfBindingFixture(t)
			net := &lateRootNet{received: make(chan any, 4)}
			driver := &firstUCDriver{got: make(chan struct{})}
			client, err := NewBFTClient(testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t)), net, f.signer, authPartitionID, types.ShardID{}, f.confMine,
				stubTrustBaseStore{tb: f.tb}, driver, nil, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: time.Hour})
			require.NoError(t, err)
			opener := &blackholeOpener{entered: make(chan struct{}, 2)}
			client.SetRelay(opener, func() []peer.ID { return []peer.ID{"a", "b"} }, 20*time.Millisecond)
			var follower atomic.Bool
			client.SetFollowerRole(follower.Load)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- client.Run(ctx) }()
			t.Cleanup(func() { cancel(); <-done })

			<-opener.entered
			<-opener.entered // both relay fetches are blocked, in parallel
			switch tc {
			case "root push":
				net.received <- f.respond(f.ucMine)
				select {
				case <-driver.got:
				case <-time.After(500 * time.Millisecond):
					t.Fatal("the root push waited behind the blocked relay")
				}
			case "retirement":
				follower.Store(true)
				client.RoleChanged()
			}
			require.Eventually(t, func() bool { return opener.cancelled.Load() == 2 }, time.Second, 5*time.Millisecond,
				"the blocked fetches are cancelled, not left to their deadline")
			calls := opener.calls.Load()
			if tc == "retirement" {
				time.Sleep(150 * time.Millisecond)
				require.Equal(t, calls, opener.calls.Load(), "a non-active node starts no further batch")
			}
		})
	}
}

// The relay server budgets each peer's requests (a burst, then a steady rate), besides its concurrency limits, and serializes the held
// pair once per held pair.
func TestTheUCRelayServerBudgetsRequestsAndCachesTheFrame(t *testing.T) {
	f := newConfBindingFixture(t)
	good := f.respond(f.ucMine)
	encodes := 0
	s := NewUCRelayServer(func() (*types.UnicityCertificate, *certification.TechnicalRecord) {
		encodes++
		return &good.UC, &good.Technical
	}, nil)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	for range ucRelayBurst {
		require.True(t, s.reserve("p"))
		s.release("p")
	}
	require.False(t, s.reserve("p"), "the burst is spent")
	require.True(t, s.reserve("q"), "another peer has its own budget")
	s.release("q")
	now = now.Add(time.Second)
	require.True(t, s.reserve("p"), "the budget refills at its rate")
	s.release("p")

	a, err := s.frame()
	require.NoError(t, err)
	b, err := s.frame()
	require.NoError(t, err)
	require.Same(t, &a[0], &b[0], "the held pair is serialized once")
}

// relayWithQueuedAnswer is a client (not running) whose relay batch has queued a genuine answer from a real relay server, under role
// token 7. The caller decides what happens before admission.
func relayWithQueuedAnswer(t *testing.T) (*BFTClient, *tokenRole, relayedPair, *confBindingFixture) {
	t.Helper()
	f := newConfBindingFixture(t)
	good := f.respond(f.ucMine)
	node := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	server := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	server.RegisterProtocolHandler(UCRelayProtocol, NewUCRelayServer(func() (*types.UnicityCertificate, *certification.TechnicalRecord) { return &good.UC, &good.Technical }, nil).Handler)
	node.Network().Peerstore().AddAddrs(server.ID(), server.MultiAddresses(), peerstore.PermanentAddrTTL)
	client, err := NewBFTClient(node, &lateRootNet{received: make(chan any, 1)}, f.signer, authPartitionID, types.ShardID{}, f.confMine,
		stubTrustBaseStore{tb: f.tb}, &firstUCDriver{got: make(chan struct{})}, nil, BFTClientOptions{HandshakeNodes: 1, CertNodes: 1})
	require.NoError(t, err)
	role := &tokenRole{}
	role.token.Store(7)
	role.active.Store(true)
	client.SetRole(role)
	client.SetRelay(node, func() []peer.ID { return []peer.ID{server.ID()} }, time.Millisecond)
	client.relayStart(context.Background())
	var p relayedPair
	select {
	case p = <-client.relay.results:
	case <-time.After(5 * time.Second):
		t.Fatal("no relayed answer was queued")
	}
	require.Eventually(t, func() bool { client.relay.mu.Lock(); defer client.relay.mu.Unlock(); return !client.relay.running }, time.Second, 5*time.Millisecond)
	return client, role, p, f
}

// astra on #1054, r2: an answer queued under one role is admitted only while that role and its batch are current.
func TestAQueuedRelayAnswerIsAdmittedOnlyUnderItsRoleAndBatch(t *testing.T) {
	t.Run("completed batch", func(t *testing.T) {
		client, _, p, _ := relayWithQueuedAnswer(t)
		require.True(t, client.relayAdmissible(p), "a batch that simply completed keeps its queued answers usable")
	})
	t.Run("retirement after the answer was queued", func(t *testing.T) {
		client, role, p, f := relayWithQueuedAnswer(t)
		role.active.Store(false)
		client.checkRole(context.Background()) // the loop processes the retirement before it reaches the queue
		require.False(t, client.relayAdmissible(p))
		require.False(t, client.Holds(f.ucMine), "nothing is adopted as a follower")
	})
	t.Run("retirement and re-promotion between loop iterations", func(t *testing.T) {
		client, role, p, _ := relayWithQueuedAnswer(t)
		role.active.Store(false)
		role.token.Store(9)
		role.active.Store(true) // the loop never saw the flip: its remembered role is unchanged
		require.False(t, client.relayAdmissible(p), "the answer belongs to the ended role, whatever the loop remembers")
	})
	t.Run("progress invalidates the batch, racing the enqueue", func(t *testing.T) {
		client, _, p, _ := relayWithQueuedAnswer(t)
		client.relayCancel() // an adoption (or retirement) after the worker's last check, before admission
		require.False(t, client.relayAdmissible(p))
	})
}
