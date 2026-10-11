package q4shim

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
)

type gateFixture struct {
	t     *testing.T
	inner *fakeInner
	gate  *ShardGate
	recv  <-chan any
	mu    sync.Mutex
	trace []ShardEvent
}

func newGateFixture(t *testing.T) *gateFixture {
	g := &gateFixture{t: t, inner: newFakeInner()}
	g.gate = NewShardGate(g.inner, testPeer(t), func(ev ShardEvent) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.trace = append(g.trace, ev)
	})
	g.recv = g.gate.ReceivedChannel()
	t.Cleanup(g.gate.Close)
	return g
}

func (g *gateFixture) apply(c ShardControl) {
	g.t.Helper()
	require.NoError(g.t, g.gate.Apply(context.Background(), c))
}

func request(partition types.PartitionID, node string, round uint64) *certification.BlockCertificationRequest {
	return &certification.BlockCertificationRequest{PartitionID: partition, NodeID: node, InputRecord: &types.InputRecord{RoundNumber: round}}
}

func response(partition types.PartitionID, round uint64) *certification.CertificationResponse {
	return &certification.CertificationResponse{Partition: partition, UC: types.UnicityCertificate{InputRecord: &types.InputRecord{RoundNumber: round}}}
}

// next is the next message the root reads, or nil when none arrives within a short wait.
func (g *gateFixture) next() any {
	select {
	case m := <-g.recv:
		return m
	case <-time.After(200 * time.Millisecond):
		return nil
	}
}

// events is a copy of the trace so far (an inbound release is delivered by its own goroutine).
func (g *gateFixture) events() []ShardEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]ShardEvent(nil), g.trace...)
}

func (g *gateFixture) kinds() (out []string) {
	for _, e := range g.events() {
		out = append(out, e.Kind)
	}
	return out
}

func TestShardGate(t *testing.T) {
	t.Run("without rules every message passes in both directions, in order", func(t *testing.T) {
		g := newGateFixture(t)
		g.inner.in <- request(8, "n1", 4)
		g.inner.in <- &handshake.Handshake{PartitionID: 8, NodeID: "n1"}
		require.Equal(t, request(8, "n1", 4), g.next())
		require.IsType(t, &handshake.Handshake{}, g.next())
		to := testPeer(t)
		require.NoError(t, g.gate.Send(context.Background(), response(8, 4), to))
		require.Len(t, g.inner.got(), 1)
		require.Equal(t, []string{"in", "in", "out"}, g.kinds())
	})
	t.Run("an inbound hold keeps one partition's requests until the release, which delivers them in order and heals", func(t *testing.T) {
		g := newGateFixture(t)
		g.apply(ShardControl{Gen: 1, Rules: []ShardRule{{Name: "delay", Direction: In, Partition: 8, Action: Hold, Require: true}}})
		g.inner.in <- request(8, "n1", 4)
		g.inner.in <- request(9, "agg", 7)
		g.inner.in <- request(8, "n2", 5)
		require.Equal(t, request(9, "agg", 7), g.next(), "another partition passes")
		require.Nil(t, g.next(), "the EVM requests are held")
		st := g.gate.Status()
		require.Equal(t, 2, st.Held["delay"])
		require.Equal(t, 2, st.Rules["delay"])
		g.apply(ShardControl{Gen: 2, Rules: []ShardRule{{Name: "delay", Direction: In, Partition: 8, Action: Hold}}, Releases: []Release{{ID: "r1", Rule: "delay", Order: FIFO}}})
		require.Equal(t, request(8, "n1", 4), g.next())
		require.Equal(t, request(8, "n2", 5), g.next())
		g.inner.in <- request(8, "n1", 6)
		require.Equal(t, request(8, "n1", 6), g.next(), "a released rule is retired: later requests pass")
		require.Zero(t, g.gate.Status().Held["delay"])
		g.apply(ShardControl{Gen: 3, Rules: []ShardRule{{Name: "delay", Direction: In, Partition: 8, Action: Hold}}, Releases: []Release{{ID: "r1", Rule: "delay"}}})
		require.Nil(t, g.next(), "a release id is performed once")
	})
	t.Run("a LIFO release reorders the held messages", func(t *testing.T) {
		g := newGateFixture(t)
		g.apply(ShardControl{Rules: []ShardRule{{Name: "r", Direction: In, Action: Hold}}})
		for round := uint64(1); round <= 3; round++ {
			g.inner.in <- request(8, "n1", round)
		}
		require.Eventually(t, func() bool { return g.gate.Status().Held["r"] == 3 }, time.Second, 10*time.Millisecond)
		g.apply(ShardControl{Rules: []ShardRule{{Name: "r", Direction: In, Action: Hold}}, Releases: []Release{{ID: "x", Rule: "r", Order: LIFO}}})
		for _, round := range []uint64{3, 2, 1} {
			require.Equal(t, request(8, "n1", round), g.next())
		}
	})
	t.Run("a node filter cuts one shard node both ways; the others pass", func(t *testing.T) {
		g := newGateFixture(t)
		cut, other := testPeer(t), testPeer(t)
		g.apply(ShardControl{Rules: []ShardRule{
			{Name: "cut-in", Direction: In, Partition: 8, Nodes: []string{cut.String()}, Action: Hold},
			{Name: "cut-out", Direction: Out, Partition: 8, Nodes: []string{cut.String()}, Action: Hold},
		}})
		g.inner.in <- request(8, cut.String(), 4)
		g.inner.in <- request(8, other.String(), 4)
		require.Equal(t, request(8, other.String(), 4), g.next())
		require.Nil(t, g.next())
		require.NoError(t, g.gate.Send(context.Background(), response(8, 4), cut, other))
		got := g.inner.got()
		require.Len(t, got, 1)
		require.Equal(t, other, got[0].to)
		g.apply(ShardControl{Releases: []Release{{ID: "a", Rule: "cut-in"}, {ID: "b", Rule: "cut-out"}}})
		require.Equal(t, request(8, cut.String(), 4), g.next())
		got = g.inner.got()
		require.Len(t, got, 2)
		require.Equal(t, cut, got[1].to)
		released := func() (out []string) {
			for _, e := range g.events() {
				if e.Kind == "release" || e.Kind == "deliver" {
					out = append(out, e.Kind+"/"+e.Direction+"/"+e.Node)
				}
			}
			return out
		}
		want := []string{"release/in/" + cut.String(), "deliver/in/" + cut.String(), "release/out/" + cut.String(), "deliver/out/" + cut.String()}
		require.Eventually(t, func() bool { return len(released()) == len(want) }, time.Second, 10*time.Millisecond)
		require.ElementsMatch(t, want, released())
	})
	t.Run("a drop loses the message and says so", func(t *testing.T) {
		g := newGateFixture(t)
		g.apply(ShardControl{Rules: []ShardRule{{Name: "d", Direction: Out, Action: Drop}}})
		require.NoError(t, g.gate.Send(context.Background(), response(8, 4), testPeer(t)))
		require.Empty(t, g.inner.got())
		require.Equal(t, []string{"out", "drop"}, g.kinds())
	})
	t.Run("messages the gate does not classify pass untouched and untraced", func(t *testing.T) {
		g := newGateFixture(t)
		g.apply(ShardControl{Rules: []ShardRule{{Name: "all", Direction: Out, Action: Drop}, {Name: "allin", Direction: In, Action: Drop}}})
		require.NoError(t, g.gate.Send(context.Background(), "something else", testPeer(t)))
		require.Len(t, g.inner.got(), 1)
		g.inner.in <- "other"
		require.Equal(t, "other", g.next())
		require.Empty(t, g.events())
	})
	t.Run("an invalid document changes nothing", func(t *testing.T) {
		g := newGateFixture(t)
		g.apply(ShardControl{Gen: 1, Rules: []ShardRule{{Name: "keep", Direction: In, Action: Hold}}})
		for name, c := range map[string]ShardControl{
			"no name":       {Rules: []ShardRule{{Direction: In, Action: Hold}}},
			"duplicate":     {Rules: []ShardRule{{Name: "a", Direction: In, Action: Hold}, {Name: "a", Direction: Out, Action: Hold}}},
			"bad direction": {Rules: []ShardRule{{Name: "a", Direction: "both", Action: Hold}}},
			"duplicate act": {Rules: []ShardRule{{Name: "a", Direction: In, Action: Duplicate}}},
			"release no id": {Releases: []Release{{Rule: "keep"}}},
			"release order": {Releases: []Release{{ID: "x", Rule: "keep", Order: RoundAsc}}},
		} {
			require.ErrorIs(t, g.gate.Apply(context.Background(), c), ErrBadControl, name)
		}
		require.EqualValues(t, 1, g.gate.Status().Gen)
		g.inner.in <- request(8, "n", 1)
		require.Nil(t, g.next(), "the previous hold is still in force")
	})
	t.Run("the lane's control file is read and the status written", func(t *testing.T) {
		g := newGateFixture(t)
		dir := t.TempDir()
		ctl, status := filepath.Join(dir, "shard-control.json"), filepath.Join(dir, "shard-status.json")
		require.NoError(t, os.WriteFile(ctl, []byte(`{"gen":7,"rules":[{"name":"cut","direction":"in","partition":8,"action":"hold","require":true}]}`), 0o600))
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go g.gate.Watch(ctx, ctl, status, 10*time.Millisecond)
		require.Eventually(t, func() bool {
			raw, err := os.ReadFile(status)
			var st ShardStatus
			return err == nil && json.Unmarshal(raw, &st) == nil && st.Gen == 7
		}, 2*time.Second, 10*time.Millisecond)
		require.NoError(t, os.WriteFile(ctl, []byte(`{"gen":8,"rules":[{"name":"cut","direction":"sideways","action":"hold"}]}`), 0o600))
		require.Eventually(t, func() bool { return len(g.gate.Status().Faults) == 1 }, 2*time.Second, 10*time.Millisecond)
		require.EqualValues(t, 7, g.gate.Status().Gen, "an invalid document is a fault and leaves the rules in force")
	})
	t.Run("a closed gate passes nothing on and holds nothing", func(t *testing.T) {
		g := newGateFixture(t)
		g.gate.Close()
		var to peer.ID = testPeer(t)
		require.NoError(t, g.gate.Send(context.Background(), response(8, 1), to))
		require.Len(t, g.inner.got(), 1, "outbound still reaches the network (the node is stopping)")
		require.Empty(t, g.events())
	})
}
