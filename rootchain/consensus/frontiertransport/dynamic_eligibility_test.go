package frontiertransport

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

// membership is an eligible set that changes while the server runs.
type membership struct {
	mu      sync.Mutex
	members map[peer.ID]bool
}

func (m *membership) set(id peer.ID, in bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.members[id] = in
}

func (m *membership) allowed(id peer.ID) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.members[id]
}

// ask sends one frontier request as from and reports whether the server answered it (true) or reset the stream (false).
func ask(t *testing.T, server *Server, from peer.ID) bool {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	done := make(chan struct{})
	go func() { defer close(done); server.ServeFrontier(from, &pipeStream{b}) }()
	require.NoError(t, a.SetDeadline(time.Now().Add(2*time.Second)))
	served := false
	if err := writeFrame(a, testFrontierRequest(t), MaxRequestBytes); err == nil {
		response, err := readFrame(a, MaxResponseBytes)
		served = err == nil && string(response) == "frontier"
	}
	_ = a.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the server did not finish the stream")
	}
	return served
}

func answeringHandlers() Handlers {
	return Handlers{
		Frontier: func(context.Context, FrontierRequest) ([]byte, error) { return []byte("frontier"), nil },
		Cut:      func(context.Context, CutRequest) ([]byte, error) { return []byte("cut"), nil },
	}
}

// The eligible set follows its source while the server runs: a peer admitted after the server started is served, and a member that
// was removed is refused, both without a new server.
func TestServerForFollowsAChangingEligibleSet(t *testing.T) {
	m := &membership{members: map[peer.ID]bool{"member": true}}
	limits := testLimits()
	limits.MaxEligiblePeers = 8
	server, err := NewServerFor(context.Background(), m.allowed, limits, answeringHandlers())
	require.NoError(t, err)
	defer server.Close()

	require.True(t, ask(t, server, "member"), "a member at start is served")
	require.False(t, ask(t, server, "joiner"), "a peer that is not a member yet is refused")

	m.set("joiner", true)
	require.True(t, ask(t, server, "joiner"), "admitted after the server started: served without a restart")

	m.set("member", false)
	require.False(t, ask(t, server, "member"), "removed: refused")
	require.True(t, ask(t, server, "joiner"), "the other member is unaffected")
	server.mu.Lock()
	_, kept := server.peers["member"]
	server.mu.Unlock()
	require.False(t, kept, "a removed member's budget is forgotten")

	// the fixed-set server is unchanged: its set is the one it was built with
	fixed, err := NewServer(context.Background(), []peer.ID{"member"}, limits, answeringHandlers())
	require.NoError(t, err)
	defer fixed.Close()
	require.True(t, ask(t, fixed, "member"))
	require.False(t, ask(t, fixed, "joiner"))
}

// Each eligible peer keeps its own request budget, as with the fixed set: one peer spending its burst does not take another's.
func TestServerForKeepsAPerPeerBudget(t *testing.T) {
	m := &membership{members: map[peer.ID]bool{"a": true, "b": true}}
	limits := testLimits()
	limits.MaxEligiblePeers, limits.Burst, limits.RequestsPerSecond = 8, 2, 0.001
	server, err := NewServerFor(context.Background(), m.allowed, limits, answeringHandlers())
	require.NoError(t, err)
	defer server.Close()
	require.True(t, ask(t, server, "a"))
	require.True(t, ask(t, server, "a"))
	require.False(t, ask(t, server, "a"), "a's burst is spent")
	require.True(t, ask(t, server, "b"), "b has its own")
}

// At most MaxEligiblePeers budgets are kept. A new eligible peer takes the place of an idle one whose budget has refilled; while
// every kept budget is partly spent, a further peer is refused rather than the bound exceeded.
func TestServerForBoundsTheBudgetsItKeeps(t *testing.T) {
	m := &membership{members: map[peer.ID]bool{"a": true, "b": true, "c": true}}
	limits := testLimits()
	limits.MaxEligiblePeers, limits.Burst, limits.RequestsPerSecond = 2, 2, 0.001
	server, err := NewServerFor(context.Background(), m.allowed, limits, answeringHandlers())
	require.NoError(t, err)
	defer server.Close()
	require.True(t, ask(t, server, "a"))
	require.True(t, ask(t, server, "b"))
	require.False(t, ask(t, server, "c"), "both kept budgets are partly spent: the bound holds")
	server.mu.Lock()
	require.Len(t, server.peers, 2)
	server.peers["a"].last = time.Now().Add(-time.Hour) // a's budget has long refilled (0.001/s over an hour is more than one token)
	server.mu.Unlock()
	require.True(t, ask(t, server, "c"), "a refilled idle budget makes room")
	server.mu.Lock()
	_, aKept := server.peers["a"]
	n := len(server.peers)
	server.mu.Unlock()
	require.False(t, aKept)
	require.Equal(t, 2, n)
}

func TestNewServerForRefusesAMissingAuthorizer(t *testing.T) {
	_, err := NewServerFor(context.Background(), nil, testLimits(), answeringHandlers())
	require.ErrorIs(t, err, ErrBounds)
}
