package vrschedule

import (
	"context"
	"crypto/sha256"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// The verification service (design section 5.3.4, premise PV in 8.3). Every admitted message is verified off the service's lock by one
// worker, in bounded service rounds: a round serves every sender with a queued message once, a sender whose signed message failed
// verification after the others (seated last for the rest of the intent), so no sender waits behind another's backlog for more than a round
// (astra review of #1188, P2). The queue is bounded to (1 + n_s) x 4 views x 2 intents entries (n_s = MAX_COMMITTEE while no intent is
// derived here). Admission is fair: at the bound a sender holding fewer messages than the longest queue displaces that queue's newest
// message, so a few admitted Byzantine peers cannot starve honest senders (review #1188 B3); a sender holds at most MaxQueuedPerPeer.
//
// PiMax is a cost bound, not a wall-clock verdict (review #1188 B4): every message's verification work is bounded before it is verified
// (the frame size, at most SupportRules commitments in a readiness, one conflict per signer and view, one replacement per sender), and a
// verification's result is always kept; one that takes longer than PiMax on the wall clock is only logged. PiMax covers one service: the
// message's verification and the work its admission triggers (this root's assembly, a complete set's certificate check), each at most once
// per view. That it holds on the host is an operating premise, measured, not enforced.
//
// Q_max, the premise PV's bound, follows from the scheduler (astra review of #1188, r2): a message that arrives as the j-th queued message of
// its sender is served within the current round and j more, each serving at most S senders, so within (j + 1) * S * PiMax of its arrival
// (QMax), whatever the other senders keep sending: another sender's backlog costs it one service per round, never more. S is at most the
// senders a round admits: the incumbents, the successors' roots and K's roots (3 * MAX_COMMITTEE = 48), and the local operator identity, so
// 49. That holds for every round across membership changes: a round is built against one snapshot of the admitted senders and drops the
// queued messages of senders outside it (Admission). The queue coalesces a sender's retransmissions (one copy of a message per sender is queued) and admits at most
// MaxQueuedPerPeer = 64 per sender, so the bound the queue itself enforces is j <= 64: 65 * 49 * 100 ms = 318.5 s, a delay only a sender's
// own backlog can cause its own messages.
//
// The operating envelope PV is premised on: an honest sender keeps j <= 3. A member's root sends its proof and one readiness for the
// committed view (readiness for views ahead waits in the service's buffer, not the queue, until its view commits, and a view commits after
// the previous one), and an incumbent its assembly once per view it assembles; retransmissions coalesce. At j = 3, S = 49 and PiMax = 100 ms,
// Q_max = 19.6 s, and with the design's illustrative D = 10 s and delta = 1 s, D + delta + Q_max = 30.6 s < 4 T = 40 s at T(0, 0) = 10 s.
// PiMax must be measured over a whole service (the verification and the work its admission triggers) and with the stage pulls' verifications,
// which run outside the queue, competing for the host.

// DefaultPiMax is the default verification cost bound per message.
const DefaultPiMax = 100 * time.Millisecond

// QueueBound is (1 + n_s) * 4 views * 2 intents.
func QueueBound(successors int) int { return (1 + successors) * RetainedViews * 2 }

// QMax is the queueing bound of premise PV for a message that arrives as the j-th queued message of its sender, with at most senders
// senders queued: (j + 1) service rounds of at most senders services, PiMax each.
func QMax(senders, j int, piMax time.Duration) time.Duration {
	return time.Duration((j+1)*senders) * piMax
}

type queued struct {
	sender string
	msg    Message
	key    [32]byte // the message's wire digest: one copy of a message per sender is queued
}

func messageKey(m Message) [32]byte {
	b, err := encodeMessage(m)
	if err != nil {
		return [32]byte{}
	}
	return sha256.Sum256(b)
}

// Queue is the bounded, round-robin verification queue in front of a Service.
type Queue struct {
	svc   *Service
	piMax time.Duration
	now   func() time.Time
	bound func() int
	// Delivered receives what each processed message produced (this root's assembly, to send); nil drops it.
	Delivered func(Outcome, []Message, error)
	// Admission is the set of senders admitted under one committed membership version (the transport's admission, and the local operator),
	// taken once per round: a round never serves a sender outside it, and their queued messages are dropped when the round begins, so a
	// round holds at most one version's admitted senders whatever the membership was when they queued, or changes to while the round is
	// built (astra review of #1188, r3, r4). Nil admits every sender.
	Admission func() map[string]bool

	mu    sync.Mutex
	per   map[string][]queued
	keys  map[string]map[[32]byte]bool // the queued messages' keys by sender
	ring  []string                     // the senders with queued messages, in arrival order
	round []string                     // the senders still to serve in the current round
	n     int
	ready chan struct{}
}

// NewQueue is the queue of svc with the cost bound piMax (0: DefaultPiMax); the service hands it the buffered messages that become
// judgeable.
func NewQueue(svc *Service, piMax time.Duration) *Queue {
	if piMax <= 0 {
		piMax = DefaultPiMax
	}
	q := &Queue{svc: svc, piMax: piMax, now: time.Now, per: map[string][]queued{}, keys: map[string]map[[32]byte]bool{}, ready: make(chan struct{}, 1),
		bound: func() int { return QueueBound(svc.successors()) }}
	svc.mu.Lock()
	svc.requeue = q.Submit
	svc.mu.Unlock()
	return q
}

// Submit admits one message for verification; false when the queue is full (the message is dropped).
func (q *Queue) Submit(sender string, m Message) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	key := messageKey(m)
	if q.keys[sender][key] {
		return true // coalesced: the same message of this sender is already queued (a retransmission adds nothing to its backlog)
	}
	if len(q.per[sender]) >= MaxQueuedPerPeer {
		return false
	}
	if q.n >= q.bound() && !q.displaceFor(sender) {
		return false
	}
	if _, ok := q.per[sender]; !ok {
		q.ring = append(q.ring, sender)
	}
	q.per[sender] = append(q.per[sender], queued{sender: sender, msg: m, key: key})
	if q.keys[sender] == nil {
		q.keys[sender] = map[[32]byte]bool{}
	}
	q.keys[sender][key] = true
	q.n++
	select {
	case q.ready <- struct{}{}:
	default:
	}
	return true
}

// displaceFor makes room for sender at the bound by dropping the newest message of the longest queue, when that queue holds at least two
// more than sender's: false when sender already holds a fair share. Among equally long queues a sender the service seated last goes first,
// then the smallest sender id.
func (q *Queue) displaceFor(sender string) bool {
	last := q.svc.lastSeats()
	long := ""
	for s, l := range q.per {
		if long == "" || len(l) > len(q.per[long]) {
			long = s
			continue
		}
		if len(l) == len(q.per[long]) && (last[s] && !last[long] || last[s] == last[long] && s < long) {
			long = s
		}
	}
	if long == "" || len(q.per[long]) < len(q.per[sender])+2 {
		return false
	}
	q.forget(q.per[long][len(q.per[long])-1])
	q.per[long] = q.per[long][:len(q.per[long])-1]
	q.n--
	return true
}

// Len is the number of queued messages.
func (q *Queue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.n
}

// pop takes the next message in bounded service rounds (astra review of #1188, P2): a round serves every sender that had a queued message
// when it began exactly once, the senders the service seated last after the others, and a sender that arrives during a round waits for the
// next one. So a seated-last sender is served within one round of any length the other senders keep their queues at, never starved.
func (q *Queue) pop() (queued, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n == 0 {
		return queued{}, false
	}
	for {
		for len(q.round) > 0 {
			sender := q.round[0]
			q.round = q.round[1:]
			if len(q.per[sender]) == 0 {
				continue // displaced meanwhile
			}
			m := q.per[sender][0]
			q.per[sender] = q.per[sender][1:]
			q.forget(m)
			q.n--
			if len(q.per[sender]) == 0 {
				delete(q.per, sender)
				for i, s := range q.ring {
					if s == sender {
						q.ring = append(q.ring[:i], q.ring[i+1:]...)
						break
					}
				}
			}
			return m, true
		}
		if q.n == 0 {
			return queued{}, false
		}
		q.newRound()
		if len(q.round) == 0 {
			return queued{}, false
		}
	}
}

// forget drops a message that leaves the queue from its sender's coalescing set.
func (q *Queue) forget(m queued) {
	delete(q.keys[m.sender], m.key)
	if len(q.keys[m.sender]) == 0 {
		delete(q.keys, m.sender)
	}
}

// newRound orders the senders with queued messages for one service round: in their arrival order, the senders seated last after the
// others.
func (q *Queue) newRound() {
	if q.Admission != nil {
		admitted := q.Admission() // one snapshot for the whole round
		kept := q.ring[:0]
		for _, s := range q.ring {
			if admitted[s] {
				kept = append(kept, s)
				continue
			}
			for _, m := range q.per[s] {
				q.forget(m)
			}
			q.n -= len(q.per[s])
			delete(q.per, s)
		}
		q.ring = kept
	}
	last := q.svc.lastSeats()
	var first, later []string
	for _, s := range q.ring {
		if last[s] {
			later = append(later, s)
		} else {
			first = append(first, s)
		}
	}
	q.round = append(first, later...)
}

// Step verifies one queued message; false when the queue is empty.
func (q *Queue) Step() bool {
	m, ok := q.pop()
	if !ok {
		return false
	}
	j := q.svc.Prepare(m.sender, m.msg)
	o, out, err := j.Outcome, []Message(nil), j.Err
	if j.Verify != nil {
		start := q.now()
		verr := j.Verify()
		if took := q.now().Sub(start); took > q.piMax {
			q.svc.log().Warn("VR handoff: a verification took longer than its cost bound", "took", took, "piMax", q.piMax, "sender", m.sender)
		}
		o, out, err = q.svc.Apply(j, verr)
	}
	if q.Delivered != nil {
		q.Delivered(o, out, err)
	}
	return true
}

// Run serves the queue until ctx ends.
func (q *Queue) Run(ctx context.Context) {
	for {
		for q.Step() {
		}
		select {
		case <-ctx.Done():
			return
		case <-q.ready:
		}
	}
}

func (s *Service) successors() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cur == nil {
		return vrschema.MaxCommittee // the next intent's successors are not known yet: the largest committee
	}
	return len(s.cur.successors)
}

func (s *Service) lastSeats() map[string]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]bool, len(s.lastSeat))
	for k, v := range s.lastSeat {
		out[k] = v
	}
	return out
}

// SerialCompletions are the completion times of messages arriving at the given times on one serial verifier that takes cost each.
func SerialCompletions(arrivals []uint64, cost uint64) []uint64 {
	out := make([]uint64, len(arrivals))
	var free uint64
	for i, a := range arrivals {
		start := max(a, free)
		free = start + cost
		out[i] = free
	}
	return out
}

// PVAdequate is premise PV's adequacy, D + delta + Q_max < 4 T, in seconds.
func PVAdequate(d, delta, qMax, t uint64) bool { return d+delta+qMax < 4*t }
