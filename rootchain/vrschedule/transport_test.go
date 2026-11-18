package vrschedule

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	p2p "github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/vrhandoff"
)

// The peer protocol over two real libp2p hosts: a pushed message reaches the receiving root's verification queue and its service, a
// restarted root rebuilds its stage set with GetStage, and a peer the receiver does not admit is reset.
func TestThePeerProtocolOverRealHosts(t *testing.T) {
	w := newWorld(t)
	sender := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	receiver := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	stranger := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	for _, p := range []*p2p.Peer{sender, stranger} {
		p.Network().Peerstore().AddAddrs(receiver.ID(), receiver.MultiAddresses(), peerstore.PermanentAddrTTL)
	}
	svc := w.service("x")
	svc.Update(w.committed(0))
	q := NewQueue(svc, 0)
	server := NewServer(svc, q, func(id peer.ID) bool { return id == sender.ID() })
	receiver.RegisterProtocolHandler(ProtocolID, server.Handler)
	t.Cleanup(func() { receiver.RemoveProtocolHandler(ProtocolID) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	go q.Run(ctx)

	for _, m := range w.messages(0) {
		require.NoError(t, Push(ctx, FromLibp2p(sender), []peer.ID{receiver.ID()}, m))
	}
	require.Eventually(t, func() bool { _, ok := svc.Plan(); return ok }, 20*time.Second, 50*time.Millisecond, "the pushed messages complete the view")

	set, err := GetStage(ctx, FromLibp2p(sender), receiver.ID(), w.d, 0)
	require.NoError(t, err)
	require.Len(t, set.PoPs, len(w.J))
	require.Len(t, set.Assemblies, 1)
	require.Len(t, set.Readiness, len(w.J))
	restarted := w.service("y")
	restarted.Update(w.committed(0))
	offerAll(t, restarted, set.Offers())
	_, ok := restarted.Plan()
	require.True(t, ok, "a restarted root rebuilds from the stage set")

	_, err = GetStage(ctx, FromLibp2p(stranger), receiver.ID(), w.d, 0)
	require.Error(t, err, "a peer outside the members and the committee is reset")
}

// PV (design 8.3): the adequacy condition D + delta + Q_max < 4 T, and the serial completion times of the acceptance trace (two slow valid
// messages at 2 s and 11 s, 100 s each on one verifier: completion at 102 and 202).
func TestThePVPremise(t *testing.T) {
	require.Equal(t, []uint64{102, 202}, SerialCompletions([]uint64{2, 11}, 100))
	require.True(t, PVAdequate(10, 1, 300, 80), "10 + 1 + 300 < 320")
	require.False(t, PVAdequate(10, 1, 300, 20), "at T = 20 the premise fails")
}

// GetStage is answered at most once per StageInterval per peer.
func TestGetStageIsThrottledPerPeer(t *testing.T) {
	w := newWorld(t)
	svc := w.service("x")
	s := NewServer(svc, NewQueue(svc, 0), nil)
	now := time.Unix(1000, 0)
	s.now = func() time.Time { return now }
	require.True(t, s.stageDue("a"))
	require.False(t, s.stageDue("a"), "again within the interval")
	require.True(t, s.stageDue("b"), "another peer")
	now = now.Add(StageInterval)
	require.True(t, s.stageDue("a"))
}

// A root that joined after R's publication asks the peers for R's committed source: it takes an entry only when SourceQuorum of them give the
// identical one (here three of four incumbents agree, one lies), and fewer identical answers than the quorum give nothing.
func TestAJoinerFetchesTheSourceFromAQuorumOfPeers(t *testing.T) {
	w := newWorld(t)
	r := [32]byte{0x52}
	good := SourceEntry{Source: vrhandoff.Source{ResultID: r[:], EVMBlockHash: bytes.Repeat([]byte{7}, 32), EVMBlockNumber: 77, CertRootRound: 400, OutputCommit: bytes.Repeat([]byte{9}, 32)}, CertUCTime: 4000}
	bad := good
	bad.EVMBlockNumber = 78
	joiner := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	var servers []*p2p.Peer
	var ids []peer.ID
	for i, e := range []*SourceEntry{&good, &good, &good, &bad, nil} {
		p := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		joiner.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
		src, err := NewSources("")
		require.NoError(t, err)
		if e != nil {
			_, err = src.Record(*e)
			require.NoError(t, err)
		}
		svc := w.service("x")
		p.RegisterProtocolHandler(ProtocolID, NewServer(svc, NewQueue(svc, 0), func(peer.ID) bool { return true }).WithSources(src).Handler)
		t.Cleanup(func() { p.RemoveProtocolHandler(ProtocolID) })
		servers = append(servers, p)
		if i < 4 {
			ids = append(ids, p.ID())
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	require.EqualValues(t, 2, SourceFaulty(4)+1)
	got, err := FetchSource(ctx, FromLibp2p(joiner), weighted(ids, 1), r, 4)
	require.NoError(t, err)
	require.Equal(t, good, got)

	// one honest, one liar, two that did not observe it: no quorum
	_, err = FetchSource(ctx, FromLibp2p(joiner), weighted([]peer.ID{servers[0].ID(), servers[3].ID(), servers[4].ID(), servers[4].ID()}, 1), r, 4)
	require.ErrorIs(t, err, ErrUnavailable)
}

// The quorum rests on the installed committee's size, not on how many peers were asked: a recovering incumbent that asks the three others of a
// committee of four still needs two identical answers (one honest peer alone is not enough), and one peer asked twice counts once.
func TestTheSourceQuorumRestsOnTheCommitteeNotOnThePeersAsked(t *testing.T) {
	w := newWorld(t)
	r := [32]byte{0x52}
	e := SourceEntry{Source: vrhandoff.Source{ResultID: r[:], EVMBlockHash: bytes.Repeat([]byte{7}, 32), EVMBlockNumber: 77, CertRootRound: 400, OutputCommit: bytes.Repeat([]byte{9}, 32)}, CertUCTime: 4000}
	joiner := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	serve := func(entry *SourceEntry) peer.ID {
		p := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		joiner.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
		src, err := NewSources("")
		require.NoError(t, err)
		if entry != nil {
			_, err = src.Record(*entry)
			require.NoError(t, err)
		}
		svc := w.service("x")
		p.RegisterProtocolHandler(ProtocolID, NewServer(svc, NewQueue(svc, 0), func(peer.ID) bool { return true }).WithSources(src).Handler)
		t.Cleanup(func() { p.RemoveProtocolHandler(ProtocolID) })
		return p.ID()
	}
	honest, none1, none2 := serve(&e), serve(nil), serve(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// three peers asked of a committee of four: the quorum is 2, and a single honest answer is not it
	_, err := FetchSource(ctx, FromLibp2p(joiner), weighted([]peer.ID{honest, none1, none2}, 1), r, 4)
	require.ErrorIs(t, err, ErrUnavailable)
	// the same peer listed three times is one responder
	_, err = FetchSource(ctx, FromLibp2p(joiner), weighted([]peer.ID{honest, honest, honest}, 1), r, 4)
	require.ErrorIs(t, err, ErrUnavailable)
	// two distinct peers with the identical entry make it
	second, third := serve(&e), serve(&e) // fresh servers: a server answers one peer at most once per StageInterval
	got, err := FetchSource(ctx, FromLibp2p(joiner), weighted([]peer.ID{second, third, none1}, 1), r, 4)
	require.NoError(t, err)
	require.Equal(t, e, got)
}

func weighted(ids []peer.ID, w uint64) []WeightedPeer {
	var out []WeightedPeer
	for _, id := range ids {
		out = append(out, WeightedPeer{ID: id, Weight: w})
	}
	return out
}

// The agreement is by voting weight: with incumbents of weight 4, 4, 1, 1 (total 10, faulty weight at most 3) the two light roots' identical
// answer (weight 2) is within what Byzantine roots may hold and is not taken; one heavy root's answer (weight 4) is.
func TestSourceAgreementIsByVotingWeight(t *testing.T) {
	w := newWorld(t)
	r := [32]byte{0x53}
	lie := SourceEntry{Source: vrhandoff.Source{ResultID: r[:], EVMBlockHash: bytes.Repeat([]byte{1}, 32), EVMBlockNumber: 5, CertRootRound: 9, OutputCommit: bytes.Repeat([]byte{2}, 32)}, CertUCTime: 1}
	truth := lie
	truth.EVMBlockNumber = 6
	joiner := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	serve := func(entry SourceEntry) peer.ID {
		p := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
		joiner.Network().Peerstore().AddAddrs(p.ID(), p.MultiAddresses(), peerstore.PermanentAddrTTL)
		src, err := NewSources("")
		require.NoError(t, err)
		_, err = src.Record(entry)
		require.NoError(t, err)
		svc := w.service("x")
		p.RegisterProtocolHandler(ProtocolID, NewServer(svc, NewQueue(svc, 0), func(peer.ID) bool { return true }).WithSources(src).Handler)
		t.Cleanup(func() { p.RemoveProtocolHandler(ProtocolID) })
		return p.ID()
	}
	heavy1, heavy2, light1, light2 := serve(truth), serve(truth), serve(lie), serve(lie)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	peers := []WeightedPeer{{heavy1, 4}, {heavy2, 4}, {light1, 1}, {light2, 1}}
	require.EqualValues(t, 3, SourceFaulty(10))
	got, err := FetchSource(ctx, FromLibp2p(joiner), peers, r, 10)
	require.NoError(t, err)
	require.Equal(t, truth, got, "the entry the heavy roots give, not the two light roots'")
	// only the two light roots answer the same lie: weight 2 is not above 3
	_, err = FetchSource(ctx, FromLibp2p(joiner), []WeightedPeer{{light1, 1}, {light2, 1}}, r, 10)
	require.ErrorIs(t, err, ErrUnavailable)
}
