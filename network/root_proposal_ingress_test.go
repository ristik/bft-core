package network

import (
	"encoding/binary"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/libp2p/go-libp2p/core/peerstore"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
)

// testGate admits the roots in known and prioritizes those in eligible.
type testGate struct {
	mu       sync.Mutex
	known    map[peer.ID]bool
	eligible map[peer.ID]bool
}

func (g *testGate) KnownRoot(id peer.ID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.known[id]
}

func (g *testGate) EligibleProposer(id peer.ID) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.eligible[id]
}

// proposalOfSize is a proposal whose CBOR encoding is exactly size bytes (at least a few hundred), its bulk in the signature.
func proposalOfSize(t *testing.T, size int) *abdrc.ProposalMsg {
	p := &abdrc.ProposalMsg{Block: &drctypes.BlockData{Round: 2, Epoch: 1, Payload: &drctypes.Payload{}}}
	for range 4 { // the signature's byte string header grows with its length
		b, err := types.Cbor.Marshal(p)
		require.NoError(t, err)
		if len(b) == size {
			return p
		}
		p.Signature = make([]byte, len(p.Signature)+size-len(b))
	}
	t.Fatalf("no proposal of %d bytes", size)
	return nil
}

type proposalIngressFixture struct {
	in   *LibP2PNetwork
	recv *Peer
	gate *testGate
}

func newProposalIngressFixture(t *testing.T) *proposalIngressFixture {
	recv := createPeer(t)
	in, err := NewLibP2RootConsensusNetwork(recv, 8, time.Second, observability.Default(t))
	require.NoError(t, err)
	in.streamReadTimeout = 20 * time.Second // a maximal frame over the loopback of a loaded runner; the production deadline is not under test
	t.Cleanup(in.Close)
	return &proposalIngressFixture{in: in, recv: recv, gate: &testGate{known: map[peer.ID]bool{}, eligible: map[peer.ID]bool{}}}
}

// sender is a root connected to the fixture's receiver; known and eligible set its standing at the receiver's gate.
func (f *proposalIngressFixture) sender(t *testing.T, known, eligible bool) (*Peer, *LibP2PNetwork) {
	p := createPeer(t)
	out, err := NewLibP2RootConsensusNetwork(p, 8, 20*time.Second, observability.NOPObservability())
	require.NoError(t, err)
	p.Network().Peerstore().AddAddrs(f.recv.ID(), f.recv.MultiAddresses(), peerstore.PermanentAddrTTL)
	f.gate.mu.Lock()
	f.gate.known[p.ID()], f.gate.eligible[p.ID()] = known, eligible
	f.gate.mu.Unlock()
	return p, out
}

// stall opens a proposal stream from p and declares a frame of length bytes without sending its payload: the stream holds whatever the
// receiver reserved for it until its read deadline.
func stall(t *testing.T, p *Peer, to peer.ID, length uint64) {
	s, err := p.CreateStream(t.Context(), to, ProtocolRootProposal)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Reset() })
	_, err = s.Write(binary.AppendUvarint(nil, length))
	require.NoError(t, err)
}

func expectNone(t *testing.T, ch <-chan any, wait time.Duration, why string) {
	select {
	case m := <-ch:
		t.Fatalf("%s: got %T", why, m)
	case <-time.After(wait):
	}
}

func expectProposal(t *testing.T, ch <-chan any, round uint64) {
	select {
	case m := <-ch:
		require.IsType(t, &abdrc.ProposalMsg{}, m)
		require.Equal(t, round, m.(*abdrc.ProposalMsg).Block.Round)
	case <-time.After(30 * time.Second):
		t.Fatal("the proposal was not delivered")
	}
}

// #1113: a proposal is admitted only from a root the gate knows, and not at all before the gate is set.
func TestRootProposalAdmission(t *testing.T) {
	f := newProposalIngressFixture(t)
	received := f.in.ReceivedChannel()
	_, out := f.sender(t, true, false)
	_, outsiderNet := f.sender(t, false, true)

	require.NoError(t, out.Send(t.Context(), proposalOfSize(t, 4096), f.recv.ID()))
	expectNone(t, received, 500*time.Millisecond, "a proposal was admitted before the gate was set")

	f.in.SetRootConsensusGate(f.gate)
	require.NoError(t, outsiderNet.Send(t.Context(), proposalOfSize(t, 4096), f.recv.ID()))
	expectNone(t, received, 500*time.Millisecond, "a proposal of a root outside the committee was admitted")

	p := proposalOfSize(t, 4096)
	p.Block.Round = 9
	require.NoError(t, out.Send(t.Context(), p, f.recv.ID()))
	expectProposal(t, received, 9)
}

// #1113: a frame that declares more than abdrc.MaxProposalFrame is refused from its declared length, before anything is reserved or
// allocated for it.
func TestRootProposalOversizedFrameRefusedBeforeAllocation(t *testing.T) {
	f := newProposalIngressFixture(t)
	f.in.SetRootConsensusGate(f.gate)
	received := f.in.ReceivedChannel()
	member, _ := f.sender(t, true, true)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	s, err := member.CreateStream(t.Context(), f.recv.ID(), ProtocolRootProposal)
	require.NoError(t, err)
	_, err = s.Write(binary.AppendUvarint(nil, abdrc.MaxProposalFrame+1))
	require.NoError(t, err)
	// the receiver resets the stream on the declared length: a read sees the reset, not the read deadline
	_ = s.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = s.Read(make([]byte, 1))
	require.Error(t, err)
	runtime.ReadMemStats(&after)
	require.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(32<<20), "nothing near the declared 128 MiB was allocated (the rest is the process: libp2p, the race detector)")
	expectNone(t, received, 300*time.Millisecond, "an oversized frame was delivered")
	for _, b := range f.in.ingress {
		require.Zero(t, b.Used(), "nothing is reserved for a refused frame")
	}
}

// #1113: a proposal of exactly abdrc.MaxProposalFrame is accepted.
func TestRootProposalOfTheMaximumSizeIsAccepted(t *testing.T) {
	if testing.Short() {
		t.Skip("moves a 128 MiB frame")
	}
	f := newProposalIngressFixture(t)
	f.in.SetRootConsensusGate(f.gate)
	received := f.in.ReceivedChannel()
	_, out := f.sender(t, true, false)
	p := proposalOfSize(t, abdrc.MaxProposalFrame)
	p.Block.Round = 5
	require.NoError(t, out.Send(t.Context(), p, f.recv.ID()))
	expectProposal(t, received, 5)
}

// #1113: admitted roots that are not the current or next leader can together reserve only the general share of the proposal budget,
// however many maximal frames they declare; the leaders still have their protected share, and nothing is ever reserved beyond the budget.
func TestRootProposalBudgetUnderConcurrentLargeFrames(t *testing.T) {
	f := newProposalIngressFixture(t)
	f.in.SetRootConsensusGate(f.gate)
	received := f.in.ReceivedChannel()
	budget := f.in.ingress[0]

	// four committee roots that are not leaders each declare a maximal frame and send nothing more
	for range 4 {
		p, _ := f.sender(t, true, false)
		stall(t, p, f.recv.ID(), abdrc.MaxProposalFrame)
	}
	require.Eventually(t, func() bool { return budget.Used() == RootProposalIngressBytes-RootProposalIngressProtected }, 5*time.Second, 10*time.Millisecond,
		"the stalled frames hold the general share and no more")
	time.Sleep(200 * time.Millisecond)
	require.EqualValues(t, RootProposalIngressBytes-RootProposalIngressProtected, budget.Used(), "the other declarations were refused")

	// another non-leader's ordinary proposal does not fit the general share
	_, other := f.sender(t, true, false)
	require.NoError(t, other.Send(t.Context(), proposalOfSize(t, 4096), f.recv.ID()))
	expectNone(t, received, 500*time.Millisecond, "a non-leader's frame was taken beyond the general share")

	// the leader of the round is served from the protected share
	_, leader := f.sender(t, true, true)
	p := proposalOfSize(t, 4096)
	p.Block.Round = 11
	require.NoError(t, leader.Send(t.Context(), p, f.recv.ID()))
	expectProposal(t, received, 11)

	// two leaders stalling a maximal frame each fill the protected share: the budget is never exceeded
	for range 3 {
		l, _ := f.sender(t, true, true)
		stall(t, l, f.recv.ID(), abdrc.MaxProposalFrame)
	}
	require.Eventually(t, func() bool { return budget.Used() == RootProposalIngressBytes }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(200 * time.Millisecond)
	require.EqualValues(t, RootProposalIngressBytes, budget.Used())
}

// The protected share under concurrent reservations: the total never exceeds the budget, the peers without priority never exceed the
// general share, and one peer never exceeds its own.
func TestProtectedIngressBudgetConcurrent(t *testing.T) {
	const global, protected, perPeer = 300, 200, 100
	b := NewProtectedIngressBudget(global, protected, perPeer)
	var leaders sync.Map
	b.SetPriority(func(id peer.ID) bool { _, ok := leaders.Load(id); return ok })
	leaders.Store(peer.ID("l1"), true)
	leaders.Store(peer.ID("l2"), true)
	var violations atomic.Int32
	var wg sync.WaitGroup
	for _, id := range []peer.ID{"a", "b", "c", "d", "l1", "l2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 2000 {
				c, ok := b.reserve(id, 40)
				b.mu.Lock()
				if b.used > global || b.usedGeneral > global-protected || b.peers[id] > perPeer {
					violations.Add(1)
				}
				b.mu.Unlock()
				if ok {
					b.release(c)
				}
			}
		}()
	}
	wg.Wait()
	require.Zero(t, violations.Load())
	require.Zero(t, b.Used())

	// the general share full, a leader still gets its share; a peer that is not one does not
	var held []ingressCharge
	for _, id := range []peer.ID{"a", "b"} {
		c, ok := b.reserve(id, 50)
		require.True(t, ok)
		held = append(held, c)
	}
	_, ok := b.reserve("c", 1)
	require.False(t, ok, "the general share is full")
	for _, id := range []peer.ID{"l1", "l2"} {
		c, ok := b.reserve(id, perPeer)
		require.True(t, ok, "a leader is served from the protected share")
		held = append(held, c)
	}
	_, ok = b.reserve("l3", 1)
	require.False(t, ok, "not a leader")
	for _, c := range held {
		b.release(c)
	}
	require.Zero(t, b.Used())
}
