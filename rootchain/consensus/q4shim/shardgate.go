package q4shim

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
)

// ShardGate is the shard-facing counterpart of Net: a wrapper around the root node's partition network (the network a root receives
// block certification requests and handshakes on and sends certification responses with). A rule selects the traffic of one partition,
// optionally of named shard nodes only, in one direction, and passes, drops or holds it; a release delivers what a rule held, in order,
// and retires the rule. It never edits a message: what reaches the root or the shard node is the message that was sent, or nothing.
// A lane uses it to cut an EVM shard node from the roots while the root quorum stays (both directions held), or to delay the shard's
// certification requests (inbound held), and to release the stale traffic afterwards.
type ShardGate struct {
	inner Inner
	self  peer.ID
	trace func(ShardEvent)
	clock func() time.Time

	mu       sync.Mutex
	rules    []*shardRuleState
	held     []*heldShard
	released map[string]struct{}
	gen      uint64
	seq      uint64
	faults   []error
	closed   bool

	recv      chan any
	stopRecv  chan struct{}
	startOnce sync.Once
}

// Direction of shard traffic, seen from the root.
const (
	In  = "in"  // a shard node's request or handshake to this root
	Out = "out" // this root's certification response to a shard node
)

// ShardRule selects shard traffic: Partition 0 is any partition, empty Nodes any shard node (in: the request's node identifier; out:
// the receiving peer). Action is pass, drop or hold.
type ShardRule struct {
	Name      string            `json:"name"`
	Direction string            `json:"direction"`
	Partition types.PartitionID `json:"partition,omitempty"`
	Nodes     []string          `json:"nodes,omitempty"`
	Action    Action            `json:"action"`
	Require   bool              `json:"require,omitempty"`
}

// ShardControl is the document a lane writes to steer the gate (shard-control.json); Gen is reported back in the status.
type ShardControl struct {
	Gen      uint64      `json:"gen"`
	Rules    []ShardRule `json:"rules,omitempty"`
	Releases []Release   `json:"releases,omitempty"`
}

// ShardStatus is what the gate reports (shard-status.json): rule name -> messages matched, rule name -> messages held now.
type ShardStatus struct {
	Gen    uint64         `json:"gen"`
	Self   string         `json:"self"`
	Rules  map[string]int `json:"rules"`
	Held   map[string]int `json:"held"`
	Faults []string       `json:"faults,omitempty"`
}

// ShardEvent is one line of the gate's trace (shard-trace.jsonl). Kind: in, out (seen), drop, hold, release, deliver, fault.
type ShardEvent struct {
	Seq       uint64    `json:"seq"`
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Direction string    `json:"direction,omitempty"`
	Rule      string    `json:"rule,omitempty"`
	Type      string    `json:"type,omitempty"`
	Partition uint32    `json:"partition,omitempty"`
	Node      string    `json:"node,omitempty"`
	Round     uint64    `json:"round,omitempty"` // the request's IR round, or the response's UC IR round
	Error     string    `json:"error,omitempty"`
}

type shardRuleState struct {
	ShardRule
	hits    int
	retired bool
}

type heldShard struct {
	dir  string
	msg  any
	to   peer.ID
	desc shardMsg
	rule string
}

type shardMsg struct {
	typ       string
	partition types.PartitionID
	node      string
	round     uint64
}

// NewShardGate wraps the root's partition network. trace is optional.
func NewShardGate(inner Inner, self peer.ID, trace func(ShardEvent)) *ShardGate {
	return &ShardGate{inner: inner, self: self, trace: trace, clock: time.Now, released: map[string]struct{}{}, recv: make(chan any), stopRecv: make(chan struct{})}
}

func describeShard(msg any) (shardMsg, bool) {
	switch v := msg.(type) {
	case *certification.BlockCertificationRequest:
		d := shardMsg{typ: "request", partition: v.PartitionID, node: v.NodeID}
		if v.InputRecord != nil {
			d.round = v.InputRecord.RoundNumber
		}
		return d, true
	case *handshake.Handshake:
		return shardMsg{typ: "handshake", partition: v.PartitionID, node: v.NodeID}, true
	case *certification.CertificationResponse:
		d := shardMsg{typ: "response", partition: v.Partition}
		if v.UC.InputRecord != nil {
			d.round = v.UC.InputRecord.RoundNumber
		}
		return d, true
	}
	return shardMsg{}, false
}

func (r *shardRuleState) matches(dir string, d shardMsg, node string) bool {
	switch {
	case r.retired, r.Direction != dir:
		return false
	case r.Partition != 0 && r.Partition != d.partition:
		return false
	case len(r.Nodes) > 0 && !slices.Contains(r.Nodes, node):
		return false
	}
	return true
}

// record appends a trace event. The caller holds g.mu.
func (g *ShardGate) record(ev ShardEvent, d shardMsg) {
	g.seq++
	ev.Seq, ev.Time = g.seq, g.clock()
	ev.Type, ev.Partition, ev.Round = d.typ, uint32(d.partition), d.round
	if ev.Node == "" {
		ev.Node = d.node
	}
	if g.trace != nil {
		g.trace(ev)
	}
}

func (g *ShardGate) fault(err error) {
	g.faults = append(g.faults, err)
	g.record(ShardEvent{Kind: "fault", Error: err.Error()}, shardMsg{})
}

// decide returns the action for one message and records it; a hold keeps the message. The caller holds g.mu.
func (g *ShardGate) decide(dir string, msg any, to peer.ID, d shardMsg, node string) Action {
	g.record(ShardEvent{Kind: dir, Direction: dir, Node: node}, d)
	for _, r := range g.rules {
		if !r.matches(dir, d, node) {
			continue
		}
		r.hits++
		switch r.Action {
		case Drop:
			g.record(ShardEvent{Kind: "drop", Direction: dir, Rule: r.Name, Node: node}, d)
		case Hold:
			g.held = append(g.held, &heldShard{dir: dir, msg: msg, to: to, desc: d, rule: r.Name})
			g.record(ShardEvent{Kind: "hold", Direction: dir, Rule: r.Name, Node: node}, d)
		}
		return r.Action
	}
	return Pass
}

// Send routes a certification response (or any other message) to each receiver through the outbound rules.
func (g *ShardGate) Send(ctx context.Context, msg any, receivers ...peer.ID) error {
	d, ok := describeShard(msg)
	if !ok {
		return g.inner.Send(ctx, msg, receivers...)
	}
	var first error
	for _, to := range receivers {
		g.mu.Lock()
		action := Pass
		if !g.closed {
			action = g.decide(Out, msg, to, d, to.String())
		}
		g.mu.Unlock()
		if action != Pass {
			continue
		}
		if err := g.inner.Send(ctx, msg, to); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// ReceivedChannel forwards what the partition network received through the inbound rules: passed messages in their order, held ones on
// release, dropped ones never.
func (g *ShardGate) ReceivedChannel() <-chan any {
	g.startOnce.Do(func() {
		go func() {
			in := g.inner.ReceivedChannel()
			for {
				select {
				case msg, ok := <-in:
					if !ok {
						return
					}
					if d, ok := describeShard(msg); ok {
						g.mu.Lock()
						action := g.decide(In, msg, "", d, d.node)
						g.mu.Unlock()
						if action != Pass {
							continue
						}
					}
					select {
					case g.recv <- msg:
					case <-g.stopRecv:
						return
					}
				case <-g.stopRecv:
					return
				}
			}
		}()
	})
	return g.recv
}

// Close stops the receive forwarder; held messages are discarded (a closed gate is a stopped node).
func (g *ShardGate) Close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return
	}
	g.closed = true
	close(g.stopRecv)
}

func validateShard(c ShardControl) error {
	names := map[string]struct{}{}
	for _, r := range c.Rules {
		if r.Name == "" {
			return fmt.Errorf("%w: a shard rule has no name", ErrBadControl)
		}
		if _, dup := names[r.Name]; dup {
			return fmt.Errorf("%w: duplicate shard rule %q", ErrBadControl, r.Name)
		}
		names[r.Name] = struct{}{}
		if r.Direction != In && r.Direction != Out {
			return fmt.Errorf("%w: shard rule %q has direction %q", ErrBadControl, r.Name, r.Direction)
		}
		switch r.Action {
		case Pass, Drop, Hold:
		default:
			return fmt.Errorf("%w: shard rule %q has action %q", ErrBadControl, r.Name, r.Action)
		}
	}
	for _, rel := range c.Releases {
		if rel.ID == "" || rel.Rule == "" {
			return fmt.Errorf("%w: a release needs an id and a rule", ErrBadControl)
		}
		switch rel.Order {
		case "", FIFO, LIFO:
		default:
			return fmt.Errorf("%w: shard release %q has order %q", ErrBadControl, rel.ID, rel.Order)
		}
	}
	return nil
}

// Apply installs a control document: the full rule set (a rule that keeps its name keeps its counters and its retired flag) and the
// releases not performed before. An invalid document changes nothing.
func (g *ShardGate) Apply(ctx context.Context, c ShardControl) error {
	if err := validateShard(c); err != nil {
		return err
	}
	g.mu.Lock()
	old := g.rules
	g.rules = g.rules[:0:0]
	for _, r := range c.Rules {
		st := &shardRuleState{ShardRule: r}
		if i := slices.IndexFunc(old, func(o *shardRuleState) bool { return o.Name == r.Name }); i >= 0 {
			st.hits, st.retired = old[i].hits, old[i].retired
		}
		g.rules = append(g.rules, st)
	}
	g.gen = c.Gen
	var batches [][]*heldShard
	for _, rel := range c.Releases {
		if _, done := g.released[rel.ID]; done {
			continue
		}
		g.released[rel.ID] = struct{}{}
		batches = append(batches, g.take(rel.Rule, rel.Order))
	}
	g.mu.Unlock()
	// delivery happens without the lock. Outbound messages go to the network at once; inbound ones wait for the node to read its receive
	// channel, so they are handed over by one goroutine per release, in the release order, and Apply (the control watcher) never waits for the node
	for _, batch := range batches {
		var in []*heldShard
		for _, h := range batch {
			if h.dir == Out {
				g.deliver(ctx, []*heldShard{h})
			} else {
				in = append(in, h)
			}
		}
		if len(in) > 0 {
			go g.deliver(context.WithoutCancel(ctx), in)
		}
	}
	return nil
}

// take removes the messages a rule holds, in the release order, records the release and retires the rule. The caller holds g.mu.
func (g *ShardGate) take(rule string, order Order) []*heldShard {
	var batch []*heldShard
	g.held = slices.DeleteFunc(g.held, func(h *heldShard) bool {
		if h.rule == rule {
			batch = append(batch, h)
			return true
		}
		return false
	})
	if order == LIFO {
		slices.Reverse(batch)
	}
	for _, r := range g.rules {
		if r.Name == rule {
			r.retired = true
		}
	}
	for _, h := range batch {
		node := h.desc.node
		if h.dir == Out {
			node = h.to.String()
		}
		g.record(ShardEvent{Kind: "release", Direction: h.dir, Rule: rule, Node: node}, h.desc)
	}
	return batch
}

func (g *ShardGate) deliver(ctx context.Context, batch []*heldShard) {
	for _, h := range batch {
		var err error
		node := h.desc.node
		if h.dir == Out {
			node = h.to.String()
			err = g.inner.Send(ctx, h.msg, h.to)
		} else {
			select {
			case g.recv <- h.msg:
			case <-g.stopRecv:
				return
			}
		}
		g.mu.Lock()
		if err != nil {
			g.record(ShardEvent{Kind: "fault", Direction: h.dir, Rule: h.rule, Node: node, Error: err.Error()}, h.desc)
		} else {
			g.record(ShardEvent{Kind: "deliver", Direction: h.dir, Rule: h.rule, Node: node}, h.desc)
		}
		g.mu.Unlock()
	}
}

// Status is the gate's report.
func (g *ShardGate) Status() ShardStatus {
	g.mu.Lock()
	defer g.mu.Unlock()
	st := ShardStatus{Gen: g.gen, Self: g.self.String(), Rules: map[string]int{}, Held: map[string]int{}}
	for _, r := range g.rules {
		st.Rules[r.Name] = r.hits
	}
	for _, h := range g.held {
		st.Held[h.rule]++
	}
	for _, f := range g.faults {
		st.Faults = append(st.Faults, f.Error())
	}
	return st
}

// Watch polls the control file and applies it whenever its content changes, and writes the status after every poll, until ctx ends. An
// invalid document is a fault and leaves the previous rules in force.
func (g *ShardGate) Watch(ctx context.Context, controlPath, statusPath string, every time.Duration) {
	var last, lastStatus []byte
	tick := time.NewTicker(every)
	defer tick.Stop()
	for {
		if raw, err := os.ReadFile(controlPath); err == nil && !bytes.Equal(raw, last) {
			last = raw
			var c ShardControl
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.DisallowUnknownFields()
			if err := dec.Decode(&c); err != nil {
				g.mu.Lock()
				g.fault(fmt.Errorf("%w: %w", ErrBadControl, err))
				g.mu.Unlock()
			} else if err := g.Apply(ctx, c); err != nil {
				g.mu.Lock()
				g.fault(err)
				g.mu.Unlock()
			}
		}
		if statusPath != "" {
			if b, err := json.MarshalIndent(g.Status(), "", " "); err == nil && !bytes.Equal(b, lastStatus) {
				lastStatus = b
				tmp := statusPath + ".tmp"
				if os.WriteFile(tmp, b, 0o600) == nil {
					_ = os.Rename(tmp, statusPath)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
