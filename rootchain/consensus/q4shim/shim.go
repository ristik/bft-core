// Package q4shim is the Q4 #51 (B) per-peer fault shim of the root consensus network: a wrapper around the RootNet a
// ConsensusManager sends and receives on. Every outgoing message is classified (class, epoch, round, author, canonical signed
// statement), recorded with an immutable serialized copy, and then passed, dropped, held or duplicated by the first rule that
// matches its receiver; held messages are released in an explicit order. The shim never edits an honest message, so production
// authentication is untouched: what reaches a peer is the exact byte string the sender signed, or nothing. The one thing that
// writes a new message is the Byzantine adapter (equivocate.go), which signs a second statement with the node's own key outside
// its SafetyModule, and which is only reachable through a rule a test or a lane sets.
//
// The package is inert library code: nothing in a production binary imports it. cli/ubft/cmd wires it behind the q4shim build
// tag (q4shim_on.go), driven by a control file; an in-process test wraps a skewed network with the same type.
package q4shim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/crypto"
)

var (
	// ErrTriggerNotFired is returned by Finish when a required trigger never fired: the fault it was to arm was never injected.
	ErrTriggerNotFired = errors.New("q4shim: a required trigger never fired")
	// ErrRuleNotHit is returned by Finish when a required rule never matched a message.
	ErrRuleNotHit = errors.New("q4shim: a required rule never matched a message")
	// ErrNoDecision is returned by a replaying shim for a message the recorded decision log does not contain.
	ErrNoDecision = errors.New("q4shim: replay has no recorded decision for this message")
	// ErrBadControl is returned for a control document that is not valid (unknown action or order, a duplicate rule name, a rule that
	// names an unknown trigger). The shim keeps the rules it had.
	ErrBadControl = errors.New("q4shim: invalid control document")
	// ErrNoSigner is returned when an equivocation is requested of a shim that was given no signer.
	ErrNoSigner = errors.New("q4shim: no signer for the Byzantine adapter")
)

// Inner is the network the shim wraps; it is the consensus manager's RootNet.
type Inner interface {
	Send(ctx context.Context, msg any, receivers ...peer.ID) error
	ReceivedChannel() <-chan any
}

// Action is what a matching rule does with one message to one receiver.
type Action string

const (
	Pass      Action = "pass"
	Drop      Action = "drop"
	Hold      Action = "hold"
	Duplicate Action = "duplicate"
)

// Rule selects messages by receiver, class, epoch and round range and gives the action for the first matching rule. Empty To matches
// any receiver, a zero Class or Epoch is unbounded, RoundMax 0 is unbounded. A message the node sends to itself matches only when Self
// is set. After names a trigger: the rule is inert until the trigger has fired. Require makes Finish fail if the rule never matched.
type Rule struct {
	Name     string   `json:"name"`
	To       []string `json:"to,omitempty"`
	Class    Class    `json:"class,omitempty"`
	Epoch    uint64   `json:"epoch,omitempty"`
	RoundMin uint64   `json:"roundMin,omitempty"`
	RoundMax uint64   `json:"roundMax,omitempty"`
	Self     bool     `json:"self,omitempty"`
	Action   Action   `json:"action"`
	After    string   `json:"after,omitempty"`
	Require  bool     `json:"require,omitempty"`
}

// Trigger is an observed outgoing message that arms later rules (After). It fires for the messages that follow the one that
// matched it. Require makes Finish fail if it never fired.
type Trigger struct {
	Name     string `json:"name"`
	Class    Class  `json:"class,omitempty"`
	Epoch    uint64 `json:"epoch,omitempty"`
	RoundMin uint64 `json:"roundMin,omitempty"`
	RoundMax uint64 `json:"roundMax,omitempty"`
	Author   string `json:"author,omitempty"`
	Require  bool   `json:"require,omitempty"`
}

// Order is the order in which a release delivers the held messages of a rule.
type Order string

const (
	FIFO     Order = "fifo"
	LIFO     Order = "lifo"
	RoundAsc Order = "round-asc"
	RoundDsc Order = "round-desc"
)

// Release delivers every message held by Rule, in Order. ID makes it idempotent: a control document that is read again does not
// release twice.
type Release struct {
	ID    string `json:"id"`
	Rule  string `json:"rule"`
	Order Order  `json:"order,omitempty"`
}

// Equivocation makes this node, as a declared Byzantine identity, send a second validly signed vote for the round of each of its own
// votes inside [RoundMin, RoundMax] to the Recipients, after the honest one: Variant "state" differs in the executed state hash (a
// conflicting statement for the same round), "rebroadcast" repeats the honest message. The signature is made by the shim's signer
// directly; the node's SafetyModule never signs it and never records it.
type Equivocation struct {
	Name       string   `json:"name"`
	Recipients []string `json:"recipients"`
	Epoch      uint64   `json:"epoch,omitempty"`
	RoundMin   uint64   `json:"roundMin,omitempty"`
	RoundMax   uint64   `json:"roundMax,omitempty"`
	Variant    string   `json:"variant"`
	Require    bool     `json:"require,omitempty"`
}

// Event is one line of the trace. Attempt and delivery are separate events: Attempt is what the node tried to send, Deliver what the
// shim handed to the wrapped network, Recv what the node's receive channel produced. A drop, a hold and a release are events too, so
// that no message is silently lost.
type Event struct {
	Seq        uint64    `json:"seq"`
	Time       time.Time `json:"time"`
	Kind       string    `json:"kind"` // attempt drop hold deliver release equivocate recv fault
	SendID     uint64    `json:"sendId,omitempty"`
	DeliveryID uint64    `json:"deliveryId,omitempty"`
	From       string    `json:"from,omitempty"`
	To         string    `json:"to,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	Class      Class     `json:"class,omitempty"`
	Type       string    `json:"type,omitempty"`
	Epoch      uint64    `json:"epoch,omitempty"`
	Round      uint64    `json:"round,omitempty"`
	Author     string    `json:"author,omitempty"`
	Scheme     uint64    `json:"scheme,omitempty"`
	Statement  string    `json:"statement,omitempty"` // hex of SHA-256 of the signed statement
	RawSHA256  string    `json:"rawSha256,omitempty"`
	Raw        []byte    `json:"raw,omitempty"` // the serialized message; kept only with Config.KeepRaw
	Error      string    `json:"error,omitempty"`

	msg Msg
}

// Msg is the description the event was made from (with the statement and raw bytes in full).
func (e Event) Msg() Msg { return e.msg }

// Decisions is the recorded decision log of a run: what the rules decided for the nth message of a class between two peers.
// Replaying it into a shim reproduces the same schedule without the rules.
type Decisions struct {
	Actions map[string]Action `json:"actions"`
}

// Config configures a shim.
type Config struct {
	Self    peer.ID
	Signing SigningFor    // the epoch's authenticated signing configuration; needed to describe a scheme 2 message
	Signer  crypto.Signer // the node's key, for the Byzantine adapter only
	Trace   func(Event)   // optional sink called for every event, in order (a JSONL writer)
	KeepRaw bool          // keep the serialized bytes in every event
	Replay  *Decisions    // when set, decisions come from this log and the rules are ignored
	Clock   func() time.Time
}

type ruleState struct {
	Rule
	hits    int
	retired bool
}

type triggerState struct {
	Trigger
	fired int
}

type held struct {
	id   uint64
	to   peer.ID
	m    Msg
	rule string
}

// Net is the shim. It implements the manager's RootNet.
type Net struct {
	inner Inner
	cfg   Config

	mu         sync.Mutex
	rules      []*ruleState
	triggers   []*triggerState
	equivs     []*equivState
	held       []*held
	released   map[string]struct{}
	nth        map[string]int
	actions    map[string]Action
	sends      uint64
	deliveries uint64
	seq        uint64
	gen        uint64
	trace      []Event
	faults     []error
	closed     bool

	recv      chan any
	stopRecv  chan struct{}
	startOnce sync.Once
}

// New wraps inner. Rules are installed with SetRules or Apply.
func New(inner Inner, cfg Config) *Net {
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &Net{inner: inner, cfg: cfg, released: map[string]struct{}{}, nth: map[string]int{}, actions: map[string]Action{},
		recv: make(chan any), stopRecv: make(chan struct{})}
}

// ReceivedChannel is the wrapped network's channel, with every message recorded as a Recv event on its way through. The order and
// the content are untouched.
func (n *Net) ReceivedChannel() <-chan any {
	n.startOnce.Do(func() {
		go func() {
			in := n.inner.ReceivedChannel()
			for {
				select {
				case msg, ok := <-in:
					if !ok {
						return
					}
					n.observeRecv(msg)
					select {
					case n.recv <- msg:
					case <-n.stopRecv:
						return
					}
				case <-n.stopRecv:
					return
				}
			}
		}()
	})
	return n.recv
}

func (n *Net) observeRecv(msg any) {
	m, err := Describe(msg, n.cfg.Signing)
	n.mu.Lock()
	defer n.mu.Unlock()
	if err != nil {
		n.fault(fmt.Errorf("describing a received message: %w", err))
	}
	if m.Class == Other {
		return
	}
	n.record(Event{Kind: "recv", To: n.cfg.Self.String(), msg: m}, m)
}

// Close stops the receive forwarder. Held messages are discarded: a closed shim is a stopped node.
func (n *Net) Close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	n.mu.Unlock()
	close(n.stopRecv)
}

// Send routes the message to every receiver through the rules.
func (n *Net) Send(ctx context.Context, msg any, receivers ...peer.ID) error {
	var first error
	for _, to := range receivers {
		if err := n.route(ctx, msg, to); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (n *Net) fault(err error) {
	n.faults = append(n.faults, err)
	n.record(Event{Kind: "fault", Error: err.Error()}, Msg{})
}

// record appends an event made from m. The caller holds n.mu.
func (n *Net) record(ev Event, m Msg) {
	n.seq++
	ev.Seq, ev.Time = n.seq, n.cfg.Clock()
	ev.Class, ev.Type, ev.Epoch, ev.Round, ev.Author, ev.Scheme = m.Class, m.Type, m.Epoch, m.Round, m.Author, m.Scheme
	if len(m.Statement) > 0 {
		s := sha256.Sum256(m.Statement)
		ev.Statement = hex.EncodeToString(s[:])
	}
	if len(m.Raw) > 0 {
		s := sha256.Sum256(m.Raw)
		ev.RawSHA256 = hex.EncodeToString(s[:])
		if n.cfg.KeepRaw {
			ev.Raw = m.Raw
		}
	}
	ev.msg = m
	n.trace = append(n.trace, ev)
	if n.cfg.Trace != nil {
		n.cfg.Trace(ev)
	}
}

func (r *ruleState) matches(self, to peer.ID, m Msg) bool {
	switch {
	case self == to && !r.Self:
		return false
	case len(r.To) > 0 && !slices.Contains(r.To, to.String()):
		return false
	case r.Class != "" && r.Class != m.Class, r.Epoch != 0 && r.Epoch != m.Epoch:
		return false
	case m.Round < r.RoundMin, r.RoundMax != 0 && m.Round > r.RoundMax:
		return false
	}
	return true
}

func (t *triggerState) matches(m Msg) bool {
	switch {
	case t.Class != "" && t.Class != m.Class, t.Epoch != 0 && t.Epoch != m.Epoch:
		return false
	case t.Author != "" && t.Author != m.Author:
		return false
	case m.Round < t.RoundMin, t.RoundMax != 0 && m.Round > t.RoundMax:
		return false
	}
	return true
}

func (n *Net) triggerFired(name string) bool {
	for _, t := range n.triggers {
		if t.Name == name {
			return t.fired > 0
		}
	}
	return false
}

func decisionPrefix(from, to peer.ID, m Msg) string {
	return fmt.Sprintf("%s>%s/%s/e%d/r%d", from, to, m.Class, m.Epoch, m.Round)
}

func (n *Net) route(ctx context.Context, msg any, to peer.ID) error {
	m, derr := Describe(msg, n.cfg.Signing)
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil
	}
	if derr != nil {
		// a message the shim cannot describe is passed on as it is and the failure is kept: the scenario fails at Finish
		n.fault(fmt.Errorf("describing a sent message: %w", derr))
		return n.inner.Send(ctx, msg, to)
	}
	if m.Class == Other {
		return n.inner.Send(ctx, msg, to)
	}
	n.sends++
	id := n.sends
	n.record(Event{Kind: "attempt", SendID: id, From: n.cfg.Self.String(), To: to.String()}, m)

	prefix := decisionPrefix(n.cfg.Self, to, m)
	key := fmt.Sprintf("%s#%d", prefix, n.nth[prefix])
	n.nth[prefix]++

	action, ruleName := Pass, ""
	if n.cfg.Replay != nil {
		a, ok := n.cfg.Replay.Actions[key]
		if !ok {
			err := fmt.Errorf("%w: %s", ErrNoDecision, key)
			n.fault(err)
			return err
		}
		action = a
	} else {
		for _, r := range n.rules {
			if r.retired || !r.matches(n.cfg.Self, to, m) || (r.After != "" && !n.triggerFired(r.After)) {
				continue
			}
			r.hits++
			action, ruleName = r.Action, r.Name
			break
		}
	}
	n.actions[key] = action
	for _, t := range n.triggers {
		if t.matches(m) {
			t.fired++
		}
	}
	var err error
	switch action {
	case Drop:
		n.record(Event{Kind: "drop", SendID: id, From: n.cfg.Self.String(), To: to.String(), Rule: ruleName}, m)
	case Hold:
		n.held = append(n.held, &held{id: id, to: to, m: m, rule: ruleName})
		n.record(Event{Kind: "hold", SendID: id, From: n.cfg.Self.String(), To: to.String(), Rule: ruleName}, m)
	case Duplicate:
		for i := 0; i < 2 && err == nil; i++ {
			err = n.deliver(ctx, id, to, m, msg, ruleName, true)
		}
	default:
		err = n.deliver(ctx, id, to, m, msg, ruleName, false)
	}
	if err != nil {
		n.fault(err)
		return err
	}
	return n.equivocate(ctx, msg, to, m)
}

// deliver hands the message to the wrapped network. A copy decoded from the recorded bytes is sent when the message is held, released
// or duplicated, so that a sender that mutates its message afterwards changes nothing; a plain pass sends the original. The caller
// holds n.mu.
func (n *Net) deliver(ctx context.Context, id uint64, to peer.ID, m Msg, orig any, rule string, copyIt bool) error {
	out := orig
	if copyIt {
		cp, err := Copy(m)
		if err != nil {
			return err
		}
		if cp != nil {
			out = cp
		}
	}
	if err := n.inner.Send(ctx, out, to); err != nil {
		n.record(Event{Kind: "fault", SendID: id, To: to.String(), Rule: rule, Error: err.Error()}, m)
		return nil // the wrapped network refusing one receiver is not the shim's failure; it is in the trace
	}
	n.deliveries++
	n.record(Event{Kind: "deliver", SendID: id, DeliveryID: n.deliveries, From: n.cfg.Self.String(), To: to.String(), Rule: rule}, m)
	return nil
}

func orderLess(o Order) func(a, b *held) int {
	switch o {
	case LIFO:
		return func(a, b *held) int { return int(b.id) - int(a.id) }
	case RoundAsc:
		return func(a, b *held) int {
			if a.m.Round != b.m.Round {
				return int(a.m.Round) - int(b.m.Round)
			}
			return int(a.id) - int(b.id)
		}
	case RoundDsc:
		return func(a, b *held) int {
			if a.m.Round != b.m.Round {
				return int(b.m.Round) - int(a.m.Round)
			}
			return int(a.id) - int(b.id)
		}
	default:
		return func(a, b *held) int { return int(a.id) - int(b.id) }
	}
}

// ReleaseHeld delivers the messages held by the rule in the given order and returns how many it delivered. The rule stops holding:
// what it matches afterwards is passed, so a release is also a heal.
func (n *Net) ReleaseHeld(ctx context.Context, rule string, order Order) (int, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.release(ctx, rule, order)
}

func (n *Net) release(ctx context.Context, rule string, order Order) (int, error) {
	var batch []*held
	n.held = slices.DeleteFunc(n.held, func(h *held) bool {
		if h.rule == rule {
			batch = append(batch, h)
			return true
		}
		return false
	})
	for _, r := range n.rules {
		if r.Name == rule {
			r.retired = true
		}
	}
	slices.SortStableFunc(batch, orderLess(order))
	for _, h := range batch {
		n.record(Event{Kind: "release", SendID: h.id, To: h.to.String(), Rule: rule}, h.m)
		if err := n.deliver(ctx, h.id, h.to, h.m, nil, rule, true); err != nil {
			n.fault(err)
			return 0, err
		}
	}
	return len(batch), nil
}

// Held is the number of messages the rule currently holds.
func (n *Net) Held(rule string) (c int) {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, h := range n.held {
		if h.rule == rule {
			c++
		}
	}
	return c
}

// Trace is a copy of the events so far.
func (n *Net) Trace() []Event {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.trace)
}

// Decisions is the decision log so far, for an offline replay.
func (n *Net) Decisions() Decisions {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := Decisions{Actions: make(map[string]Action, len(n.actions))}
	for k, v := range n.actions {
		out.Actions[k] = v
	}
	return out
}

// Hits is how many messages the rule matched.
func (n *Net) Hits(rule string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, r := range n.rules {
		if r.Name == rule {
			return r.hits
		}
	}
	return 0
}

// Fired is how many messages the trigger matched.
func (n *Net) Fired(trigger string) int {
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, t := range n.triggers {
		if t.Name == trigger {
			return t.fired
		}
	}
	return 0
}

// Faults are the harness failures so far: a message that did not survive its copy, one that could not be described, a replay without
// a decision. They also end up in the trace.
func (n *Net) Faults() []error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return slices.Clone(n.faults)
}

// Finish reports whether every injection the scenario required happened and nothing in the harness failed. It does not stop the
// shim; messages still held stay held and are listed by Held.
func (n *Net) Finish() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	var errs []error
	errs = append(errs, n.faults...)
	for _, t := range n.triggers {
		if t.Require && t.fired == 0 {
			errs = append(errs, fmt.Errorf("%w: %s", ErrTriggerNotFired, t.Name))
		}
	}
	for _, r := range n.rules {
		if r.Require && r.hits == 0 {
			errs = append(errs, fmt.Errorf("%w: %s", ErrRuleNotHit, r.Name))
		}
	}
	for _, e := range n.equivs {
		if e.Require && e.sent == 0 {
			errs = append(errs, fmt.Errorf("%w: equivocation %s", ErrRuleNotHit, e.Name))
		}
	}
	return errors.Join(errs...)
}
