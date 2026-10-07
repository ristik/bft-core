package consensus

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
)

// Q4 #51 (A) delivery: a deterministic, directional fault adapter over skewedNet. Every send is classified (class, epoch, round,
// phase), recorded with an immutable serialized copy of the message, and then passed, dropped, held or duplicated by the first rule
// that matches; held messages are released in an explicit order. Attempts and actual deliveries are separate trace events. The
// delivered message is a decoded copy of the recorded bytes, so a sender that mutates its message afterwards changes nothing.

var (
	errQ4TriggerNotFired = errors.New("q4 delivery: a required trigger never fired")
	errQ4RuleNotHit      = errors.New("q4 delivery: a required rule never matched a message")
	errQ4NoDecision      = errors.New("q4 delivery: replay has no recorded decision for this message")
	errQ4CopyMismatch    = errors.New("q4 delivery: message does not survive its serialized copy")
)

type q4Class string

const (
	q4Proposal q4Class = "proposal"
	q4Vote     q4Class = "vote"
	q4Timeout  q4Class = "timeout"
	q4Other    q4Class = "other"
)

// q4Msg is the immutable description of one message: its class, epoch, round, author, the canonical signed statement and the
// serialized bytes. Phase is the class: a proposal opens a round, a vote goes to the next collector, a timeout leaves the round.
type q4Msg struct {
	Class     q4Class
	Epoch     uint64
	Round     uint64
	Author    string
	Statement []byte
	Raw       []byte
}

func q4Describe(msg any) (q4Msg, error) {
	var m q4Msg
	var err error
	switch v := msg.(type) {
	case *abdrc.VoteMsg:
		m = q4Msg{Class: q4Vote, Epoch: v.VoteInfo.Epoch, Round: v.VoteInfo.RoundNumber, Author: v.Author}
		m.Statement, err = v.LedgerCommitInfo.SigBytes()
	case *abdrc.TimeoutMsg:
		m = q4Msg{Class: q4Timeout, Epoch: v.Timeout.Epoch, Round: v.Timeout.Round, Author: v.Author, Statement: v.Bytes()}
	case *abdrc.ProposalMsg:
		m = q4Msg{Class: q4Proposal, Epoch: v.Block.Epoch, Round: v.Block.Round, Author: v.Block.Author}
		m.Statement, err = v.Block.Hash(crypto.SHA256)
	default:
		return q4Msg{Class: q4Other}, nil
	}
	if err != nil {
		return m, err
	}
	m.Raw, err = types.Cbor.Marshal(msg)
	return m, err
}

// q4Copy decodes the recorded bytes into a fresh message and checks that it encodes back to the same bytes.
func q4Copy(m q4Msg) (any, error) {
	var out any
	switch m.Class {
	case q4Vote:
		out = new(abdrc.VoteMsg)
	case q4Timeout:
		out = new(abdrc.TimeoutMsg)
	case q4Proposal:
		out = new(abdrc.ProposalMsg)
	default:
		return nil, nil
	}
	if err := types.Cbor.Unmarshal(m.Raw, out); err != nil {
		return nil, err
	}
	again, err := types.Cbor.Marshal(out)
	if err != nil || !bytes.Equal(again, m.Raw) {
		return nil, fmt.Errorf("%w: %s round %d", errQ4CopyMismatch, m.Class, m.Round)
	}
	return out, nil
}

type q4Action string

const (
	q4Pass      q4Action = "pass"
	q4Drop      q4Action = "drop"
	q4Hold      q4Action = "hold"
	q4Duplicate q4Action = "duplicate"
)

// q4Match selects messages. Empty From/To match any peer, a zero Class/Epoch/Round bound is unbounded. A message a node sends to
// itself is matched only when Self is set: self delivery is preserved unless it is targeted.
type q4Match struct {
	From, To           []peer.ID
	Class              q4Class
	Epoch              uint64
	RoundMin, RoundMax uint64
	Self               bool
}

func (m q4Match) matches(from, to peer.ID, msg q4Msg) bool {
	switch {
	case from == to && !m.Self:
		return false
	case len(m.From) > 0 && !slices.Contains(m.From, from), len(m.To) > 0 && !slices.Contains(m.To, to):
		return false
	case m.Class != "" && m.Class != msg.Class, m.Epoch != 0 && m.Epoch != msg.Epoch:
		return false
	case msg.Round < m.RoundMin, m.RoundMax != 0 && msg.Round > m.RoundMax:
		return false
	}
	return true
}

type q4Rule struct {
	Name    string
	Match   q4Match
	Action  q4Action
	After   string // name of the trigger that must have fired before the rule applies; empty: always
	Require bool   // the rule must match at least one message
	hits    int
}

type q4Trigger struct {
	Name  string
	Match q4Match
	fired int
}

// q4Event is one trace entry. Kind is attempt (a send, before any decision), deliver (an actual enqueue at the receiver, with a
// delivery ID), drop (a rule dropped it), hold, release (a held message is let go), offline (the network refused it because a
// party is offline) or discard (still held when the network shut down).
type q4Event struct {
	Seq        uint64
	Kind       string
	SendID     uint64
	DeliveryID uint64
	From, To   peer.ID
	Msg        q4Msg
	Rule       string
}

type q4Trace []q4Event

type q4Held struct {
	sendID   uint64
	from, to peer.ID
	msg      q4Msg
	raw      any
	rule     string
}

// q4Decisions is the recorded decision log: the action for the n-th message of every (from, to, class, epoch, round) key and the
// keys of the released messages in release order. A scheduler built from it takes every decision from the log.
type q4Decisions struct {
	Actions  map[string]q4Action
	Releases []string
}

type q4Sched struct {
	mu         sync.Mutex
	rules      []*q4Rule
	triggers   []*q4Trigger
	seq        uint64
	sends      uint64
	deliveries uint64
	held       []*q4Held
	trace      q4Trace
	nth        map[string]int
	actions    map[string]q4Action
	releases   []string
	replay     *q4Decisions
	heldKey    map[uint64]string
	faults     []error
	closed     bool
}

func newQ4Sched(rules []*q4Rule, triggers []*q4Trigger) *q4Sched {
	return &q4Sched{rules: rules, triggers: triggers, nth: map[string]int{}, actions: map[string]q4Action{}, heldKey: map[uint64]string{}}
}

func newQ4Replay(log q4Decisions) *q4Sched {
	s := newQ4Sched(nil, nil)
	s.replay = &log
	return s
}

func (s *q4Sched) record(ev q4Event) {
	s.seq++
	ev.Seq = s.seq
	s.trace = append(s.trace, ev)
}

func q4Key(from, to peer.ID, m q4Msg, nth int) string {
	return fmt.Sprintf("%s>%s/%s/e%d/r%d#%d", from, to, m.Class, m.Epoch, m.Round, nth)
}

// send is the replacement of the network's send for one receiver. A harness failure (a message that does not survive its copy, a
// replay without a decision) is returned to the sender and also kept, so that Finish reports it even if the sender ignores it.
func (s *q4Sched) send(n *skewedNet, from, to peer.ID, msg any) error {
	_, err := s.sendID(n, from, to, msg)
	return err
}

func (s *q4Sched) sendID(n *skewedNet, from, to peer.ID, msg any) (uint64, error) {
	id, err := s.route(n, from, to, msg)
	if err != nil {
		s.mu.Lock()
		s.faults = append(s.faults, err)
		s.mu.Unlock()
	}
	return id, err
}

func (s *q4Sched) route(n *skewedNet, from, to peer.ID, msg any) (uint64, error) {
	m, err := q4Describe(msg)
	if err != nil {
		return 0, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, nil
	}
	s.sends++
	id := s.sends
	s.record(q4Event{Kind: "attempt", SendID: id, From: from, To: to, Msg: m})
	prefix := q4Key(from, to, m, 0)
	prefix = prefix[:len(prefix)-1]
	nth := s.nth[prefix]
	s.nth[prefix]++
	key := fmt.Sprintf("%s%d", prefix, nth)

	action, ruleName := q4Pass, ""
	if s.replay != nil {
		a, ok := s.replay.Actions[key]
		if !ok {
			return id, fmt.Errorf("%w: %s", errQ4NoDecision, key)
		}
		action = a
	} else {
		for _, r := range s.rules {
			if !r.Match.matches(from, to, m) || !s.active(r) {
				continue
			}
			r.hits++
			action, ruleName = r.Action, r.Name
			break
		}
	}
	s.actions[key] = action
	for _, tr := range s.triggers { // a trigger arms the rules for the messages after the one that fired it
		if tr.Match.matches(from, to, m) {
			tr.fired++
		}
	}
	switch action {
	case q4Drop:
		s.record(q4Event{Kind: "drop", SendID: id, From: from, To: to, Msg: m, Rule: ruleName})
	case q4Hold:
		s.held = append(s.held, &q4Held{id, from, to, m, msg, ruleName})
		s.heldKey[id] = key
		s.record(q4Event{Kind: "hold", SendID: id, From: from, To: to, Msg: m, Rule: ruleName})
	case q4Duplicate:
		for i := 0; i < 2; i++ {
			if err := s.deliver(n, id, from, to, m, msg, ruleName); err != nil {
				return id, err
			}
		}
	default:
		return id, s.deliver(n, id, from, to, m, msg, ruleName)
	}
	return id, nil
}

func (s *q4Sched) active(r *q4Rule) bool {
	if r.After == "" {
		return true
	}
	for _, tr := range s.triggers {
		if tr.Name == r.After {
			return tr.fired > 0
		}
	}
	return false
}

// deliver enqueues a decoded copy of the recorded bytes at the receiver; the caller holds s.mu.
func (s *q4Sched) deliver(n *skewedNet, id uint64, from, to peer.ID, m q4Msg, raw any, rule string) error {
	cp, err := q4Copy(m)
	if err != nil {
		return err
	}
	if cp == nil { // a class the adapter does not describe (state sync, change requests) is passed on as it is
		cp = raw
	}
	enqueued, err := n.deliver(from, to, cp)
	if err != nil {
		return err
	}
	if !enqueued {
		s.record(q4Event{Kind: "offline", SendID: id, From: from, To: to, Msg: m, Rule: rule})
		return nil
	}
	s.deliveries++
	s.record(q4Event{Kind: "deliver", SendID: id, DeliveryID: s.deliveries, From: from, To: to, Msg: m, Rule: rule})
	return nil
}

// q4Order orders the held messages for release.
type q4Order func(a, b *q4Held) int

var (
	q4FIFO    q4Order = func(a, b *q4Held) int { return int(a.sendID) - int(b.sendID) }
	q4LIFO    q4Order = func(a, b *q4Held) int { return int(b.sendID) - int(a.sendID) }
	q4ByRound q4Order = func(a, b *q4Held) int {
		if a.msg.Round != b.msg.Round {
			return int(a.msg.Round) - int(b.msg.Round)
		}
		return int(a.sendID) - int(b.sendID)
	}
)

// release lets go of the held messages that the rule produced (all of them when rule is empty), in the given order.
func (s *q4Sched) release(n *skewedNet, rule string, order q4Order) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out, keep []*q4Held
	for _, h := range s.held {
		if rule == "" || h.rule == rule {
			out = append(out, h)
		} else {
			keep = append(keep, h)
		}
	}
	s.held = keep
	if s.replay != nil {
		return s.replayRelease(n, out)
	}
	slices.SortStableFunc(out, order)
	for _, h := range out {
		s.releases = append(s.releases, s.heldKey[h.sendID])
		s.record(q4Event{Kind: "release", SendID: h.sendID, From: h.from, To: h.to, Msg: h.msg, Rule: h.rule})
		if err := s.deliver(n, h.sendID, h.from, h.to, h.msg, h.raw, h.rule); err != nil {
			return 0, err
		}
	}
	return len(out), nil
}

func (s *q4Sched) replayRelease(n *skewedNet, held []*q4Held) (int, error) {
	byKey := map[string]*q4Held{}
	for _, h := range held {
		byKey[s.heldKey[h.sendID]] = h
	}
	count := 0
	for _, key := range s.replay.Releases {
		h, ok := byKey[key]
		if !ok {
			continue
		}
		s.record(q4Event{Kind: "release", SendID: h.sendID, From: h.from, To: h.to, Msg: h.msg, Rule: h.rule})
		if err := s.deliver(n, h.sendID, h.from, h.to, h.msg, h.raw, h.rule); err != nil {
			return count, err
		}
		delete(byKey, key)
		count++
	}
	for _, h := range byKey { // recorded as never released: still held
		s.held = append(s.held, h)
	}
	return count, nil
}

// Decisions is the log a replay scheduler is built from.
func (s *q4Sched) Decisions() q4Decisions {
	s.mu.Lock()
	defer s.mu.Unlock()
	return q4Decisions{Actions: cloneActions(s.actions), Releases: slices.Clone(s.releases)}
}

func cloneActions(m map[string]q4Action) map[string]q4Action {
	out := make(map[string]q4Action, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (s *q4Sched) Trace() q4Trace {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.trace)
}

// Inject sends a message as the given identity through the adapter and returns its send ID: the way a Byzantine fixture signer
// speaks. The message is recorded and subject to the rules like any other.
func (s *q4Sched) Inject(n *skewedNet, from, to peer.ID, msg any) (uint64, error) {
	return s.sendID(n, from, to, msg)
}

// Fired is the number of attempts that matched the named trigger.
func (s *q4Sched) Fired(name string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tr := range s.triggers {
		if tr.Name == name {
			return tr.fired
		}
	}
	return -1
}

// Held is the number of messages currently held, optionally for one rule.
func (s *q4Sched) Held(rule string) (n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range s.held {
		if rule == "" || h.rule == rule {
			n++
		}
	}
	return n
}

// AddRule installs a rule while the scheduler runs; it is evaluated before the rules that are already installed.
func (s *q4Sched) AddRule(r *q4Rule) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append([]*q4Rule{r}, s.rules...)
}

// RemoveRule stops the named rule matching; messages it already held stay held until released.
func (s *q4Sched) RemoveRule(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = slices.DeleteFunc(s.rules, func(r *q4Rule) bool { return r.Name == name })
}

// Finish closes the scheduler (what is still held is recorded as discarded, so that nothing is lost silently) and reports every
// required trigger and rule that never fired or matched. A required injection that did not happen fails the scenario.
func (s *q4Sched) Finish() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for _, h := range s.held {
		s.record(q4Event{Kind: "discard", SendID: h.sendID, From: h.from, To: h.to, Msg: h.msg, Rule: h.rule})
	}
	s.held = nil
	errs := slices.Clone(s.faults)
	for _, tr := range s.triggers {
		if tr.fired == 0 {
			errs = append(errs, fmt.Errorf("%w: %s", errQ4TriggerNotFired, tr.Name))
		}
	}
	for _, r := range s.rules {
		if r.Require && r.hits == 0 {
			errs = append(errs, fmt.Errorf("%w: %s", errQ4RuleNotHit, r.Name))
		}
	}
	return errors.Join(errs...)
}

// Unaccounted are the attempts that have no outcome yet: neither delivered, dropped, refused nor discarded, and not held.
func (tr q4Trace) Unaccounted() []uint64 {
	out := map[uint64]bool{}
	for _, ev := range tr {
		switch ev.Kind {
		case "attempt":
			out[ev.SendID] = true
		case "deliver", "drop", "offline", "discard", "hold":
			delete(out, ev.SendID)
		}
	}
	var ids []uint64
	for id := range out {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// Deliveries are the actual deliveries in order: receiver, class, round and the exact bytes.
func (tr q4Trace) Deliveries() []string {
	var out []string
	for _, ev := range tr {
		if ev.Kind == "deliver" {
			out = append(out, fmt.Sprintf("%s>%s %s r%d %x", ev.From, ev.To, ev.Msg.Class, ev.Msg.Round, ev.Msg.Raw))
		}
	}
	return out
}

func q4IDs(es ...*q4Entity) []peer.ID {
	out := make([]peer.ID, len(es))
	for i, e := range es {
		out[i] = e.ID
	}
	return out
}

func TestQ4Delivery(t *testing.T) {
	r := q4DefaultRoster(t, q4SetA)
	h, a, b, c := r.Entities[r.Index("H")], r.Entities[r.Index("a")], r.Entities[r.Index("b")], r.Entities[r.Index("c")]

	// a network of the four identities; each receiver's channel is drained by the test
	build := func(t *testing.T, rules []*q4Rule, triggers []*q4Trigger) (*skewedNet, map[peer.ID]*skewedConn, *q4Sched) {
		n := newSkewedNet(t)
		conns := map[peer.ID]*skewedConn{}
		for _, e := range r.Entities {
			conns[e.ID] = n.connect(e.ID)
		}
		n.sched = newQ4Sched(rules, triggers)
		return n, conns, n.sched
	}
	vote := func(e *q4Entity, round uint64, hash byte) *abdrc.VoteMsg {
		v := NewDummyVote(t, e.ID.String(), round, bytes.Repeat([]byte{hash}, 32))
		v.VoteInfo.Epoch = 1
		require.NoError(t, v.Sign(e.Signer))
		return v
	}
	recv := func(conn *skewedConn) *abdrc.VoteMsg {
		select {
		case m := <-conn.ReceivedChannel():
			return m.(*abdrc.VoteMsg)
		case <-time.After(5 * time.Second):
			t.Fatal("nothing delivered")
			return nil
		}
	}
	none := func(conn *skewedConn) {
		select {
		case m := <-conn.ReceivedChannel():
			t.Fatalf("unexpected delivery %T", m)
		case <-time.After(150 * time.Millisecond):
		}
	}
	send := func(conn *skewedConn, msg any, to ...peer.ID) {
		require.NoError(t, conn.Send(context.Background(), msg, to...))
	}

	t.Run("directional isolation drops one direction only, with the attempt recorded", func(t *testing.T) {
		_, conns, s := build(t, []*q4Rule{{Name: "a-to-H", Match: q4Match{From: q4IDs(a), To: q4IDs(h)}, Action: q4Drop, Require: true}}, nil)
		send(conns[a.ID], vote(a, 5, 1), h.ID)
		none(conns[h.ID])
		send(conns[h.ID], vote(h, 5, 1), a.ID)
		require.Equal(t, h.ID.String(), recv(conns[a.ID]).Author, "the reverse direction passes")
		tr := s.Trace()
		require.NoError(t, s.Finish())
		require.Equal(t, []string{"attempt", "drop", "attempt", "deliver"}, q4Kinds(tr), "attempted and actual delivery are separate events")
		require.Empty(t, tr.Unaccounted(), "no silent loss: every attempt has an outcome")
	})

	t.Run("self delivery is preserved unless it is targeted", func(t *testing.T) {
		_, conns, s := build(t, []*q4Rule{{Name: "all-votes", Match: q4Match{Class: q4Vote}, Action: q4Drop}}, nil)
		send(conns[h.ID], vote(h, 5, 1), h.ID, a.ID)
		require.Equal(t, h.ID.String(), recv(conns[h.ID]).Author, "the vote to itself passes the rule")
		none(conns[a.ID])
		s.AddRule(&q4Rule{Name: "self", Match: q4Match{Class: q4Vote, From: q4IDs(h), To: q4IDs(h), Self: true}, Action: q4Drop})
		send(conns[h.ID], vote(h, 6, 1), h.ID)
		none(conns[h.ID])
	})

	t.Run("hold, duplicate and release in an explicit order, with immutable payloads", func(t *testing.T) {
		n, conns, s := build(t, []*q4Rule{
			{Name: "hold-b", Match: q4Match{From: q4IDs(b), Class: q4Vote}, Action: q4Hold, Require: true},
			{Name: "dup-c", Match: q4Match{From: q4IDs(c), Class: q4Vote}, Action: q4Duplicate, Require: true},
		}, nil)
		v1, v2 := vote(b, 5, 1), vote(b, 6, 1)
		send(conns[b.ID], v1, h.ID)
		send(conns[b.ID], v2, h.ID)
		sent := vote(c, 5, 1)
		send(conns[c.ID], sent, h.ID)
		sent.VoteInfo.RoundNumber = 99 // the sender mutates its message after the send: the recorded and delivered payloads do not move
		first, second := recv(conns[h.ID]), recv(conns[h.ID])
		require.EqualValues(t, 5, first.VoteInfo.RoundNumber)
		require.Equal(t, first.Signature, second.Signature, "the duplicate is the same message")
		none(conns[h.ID])
		require.Equal(t, 2, s.Held("hold-b"))

		got, err := s.release(n, "hold-b", q4LIFO)
		require.NoError(t, err)
		require.Equal(t, 2, got)
		require.EqualValues(t, 6, recv(conns[h.ID]).VoteInfo.RoundNumber, "LIFO: the later round is released first")
		require.EqualValues(t, 5, recv(conns[h.ID]).VoteInfo.RoundNumber)
		require.NoError(t, s.Finish())
		tr := s.Trace()
		require.Empty(t, tr.Unaccounted())
		ids := map[uint64]bool{}
		for _, ev := range tr {
			if ev.Kind == "deliver" {
				require.False(t, ids[ev.DeliveryID], "delivery IDs are unique")
				ids[ev.DeliveryID] = true
			}
		}
		require.Len(t, ids, 4, "two copies of c's vote and the two released votes")
		for _, ev := range tr {
			if ev.Kind == "attempt" && ev.Msg.Author == c.ID.String() {
				require.EqualValues(t, 5, ev.Msg.Round, "the trace holds the message as it was sent")
			}
		}
	})

	t.Run("a trigger fires on an observed event and arms later rules only", func(t *testing.T) {
		_, conns, s := build(t,
			[]*q4Rule{{Name: "after-r7", Match: q4Match{From: q4IDs(a), Class: q4Vote}, Action: q4Drop, After: "r7", Require: true}},
			[]*q4Trigger{{Name: "r7", Match: q4Match{From: q4IDs(a), Class: q4Vote, RoundMin: 7}}})
		send(conns[a.ID], vote(a, 6, 1), h.ID)
		require.EqualValues(t, 6, recv(conns[h.ID]).VoteInfo.RoundNumber)
		require.Zero(t, s.Fired("r7"))
		send(conns[a.ID], vote(a, 7, 1), h.ID) // the triggering message itself passes
		require.EqualValues(t, 7, recv(conns[h.ID]).VoteInfo.RoundNumber)
		require.Equal(t, 1, s.Fired("r7"))
		send(conns[a.ID], vote(a, 8, 1), h.ID)
		none(conns[h.ID])
		require.NoError(t, s.Finish())
	})

	t.Run("a required trigger or rule that never fires fails the scenario", func(t *testing.T) {
		_, conns, s := build(t,
			[]*q4Rule{{Name: "never", Match: q4Match{Class: q4Timeout}, Action: q4Drop, Require: true}},
			[]*q4Trigger{{Name: "round-50", Match: q4Match{Class: q4Vote, RoundMin: 50}}})
		send(conns[a.ID], vote(a, 6, 1), h.ID)
		recv(conns[h.ID])
		err := s.Finish()
		require.ErrorIs(t, err, errQ4TriggerNotFired)
		require.ErrorIs(t, err, errQ4RuleNotHit)
	})

	t.Run("held messages that are never released are recorded as discarded", func(t *testing.T) {
		_, conns, s := build(t, []*q4Rule{{Name: "hold", Match: q4Match{Class: q4Vote}, Action: q4Hold}}, nil)
		send(conns[a.ID], vote(a, 6, 1), h.ID)
		require.Empty(t, s.Trace().Unaccounted(), "a held message is accounted for as held")
		require.NoError(t, s.Finish())
		require.Equal(t, []string{"attempt", "hold", "discard"}, q4Kinds(s.Trace()))
		send(conns[a.ID], vote(a, 7, 1), h.ID) // nothing is accepted after the shutdown
		require.Len(t, s.Trace(), 3)
	})

	t.Run("recorded decisions replay to the same deliveries", func(t *testing.T) {
		run := func(s *q4Sched, n *skewedNet, conns map[peer.ID]*skewedConn) []string {
			for round := uint64(1); round <= 6; round++ {
				send(conns[a.ID], vote(a, round, 1), h.ID, b.ID)
				send(conns[c.ID], vote(c, round, 2), h.ID)
			}
			_, err := s.release(n, "", q4LIFO)
			require.NoError(t, err)
			require.NoError(t, s.Finish())
			return s.Trace().Deliveries()
		}
		rules := []*q4Rule{
			{Name: "hold-a-to-H", Match: q4Match{From: q4IDs(a), To: q4IDs(h)}, Action: q4Hold},
			{Name: "dup-c", Match: q4Match{From: q4IDs(c), RoundMin: 3, RoundMax: 4}, Action: q4Duplicate},
			{Name: "drop-a-to-b", Match: q4Match{From: q4IDs(a), To: q4IDs(b), RoundMin: 2, RoundMax: 3}, Action: q4Drop},
		}
		n1, conns1, s1 := build(t, rules, nil)
		want := run(s1, n1, conns1)
		require.NotEmpty(t, want)
		n2 := newSkewedNet(t)
		conns2 := map[peer.ID]*skewedConn{}
		for _, e := range r.Entities {
			conns2[e.ID] = n2.connect(e.ID)
		}
		n2.sched = newQ4Replay(s1.Decisions())
		require.Equal(t, want, run(n2.sched, n2, conns2), "the replay delivers the same messages in the same order")

		// a message the log has no decision for is refused, not passed
		n3 := newSkewedNet(t)
		c3 := n3.connect(a.ID)
		n3.connect(h.ID)
		n3.sched = newQ4Replay(q4Decisions{Actions: map[string]q4Action{}})
		require.ErrorIs(t, c3.Send(context.Background(), vote(a, 1, 1), h.ID), errQ4NoDecision)
	})

	t.Run("a message that does not survive its copy is refused", func(t *testing.T) {
		v := vote(a, 3, 1)
		m, err := q4Describe(v)
		require.NoError(t, err)
		_, err = q4Copy(m)
		require.NoError(t, err, "control: the canonical encoding round-trips")

		// the same message with its signature as an indefinite-length byte string decodes to the identical vote but does not
		// encode back to the recorded bytes: the recorded and the delivered message would differ, so it is refused
		at := bytes.Index(m.Raw, v.Signature)
		require.Positive(t, at)
		header := m.Raw[at-2 : at] // 0x58 <len>: a one-byte length byte string
		require.Equal(t, byte(0x58), header[0])
		chunked := append(append(append(slices.Clone(m.Raw[:at-2]), 0x5f), m.Raw[at-2:at+len(v.Signature)]...), 0xff)
		chunked = append(chunked, m.Raw[at+len(v.Signature):]...)
		m.Raw = chunked
		_, err = q4Copy(m)
		require.ErrorIs(t, err, errQ4CopyMismatch)

		m.Raw = append(slices.Clone(m.Raw), 0xf6) // trailing bytes do not decode at all
		_, err = q4Copy(m)
		require.Error(t, err)
	})
}

func q4Kinds(tr q4Trace) []string {
	out := make([]string, len(tr))
	for i, ev := range tr {
		out[i] = ev.Kind
	}
	return out
}
