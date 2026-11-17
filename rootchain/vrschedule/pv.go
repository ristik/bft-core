package vrschedule

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-core/vrschema"
)

// The verification service (design section 5.3.4, premise PV in 8.3). Every admitted message is verified off the service's lock by one
// worker, served round-robin by sender with a sender whose signed message failed verification seated last for the rest of the intent. The
// queue is bounded to (1 + n_s) x 4 views x 2 intents entries (n_s = MAX_COMMITTEE while no intent is derived here). Admission is fair: at
// the bound a sender holding fewer messages than the longest queue displaces that queue's newest message, so a few admitted Byzantine peers
// cannot starve honest senders (review #1188 B3); a sender holds at most MaxQueuedPerPeer.
//
// PiMax is a cost bound, not a wall-clock verdict (review #1188 B4): every message's verification work is bounded before it is verified
// (the frame size, at most SupportRules commitments in a readiness, one conflict per signer and view, one replacement per sender), and a
// verification's result is always kept; one that takes longer than PiMax on the wall clock is only logged.
//
// Q_max, the premise PV's bound, follows from these admission bounds: with B = (1 + n_s) * 4 * 2 queued messages, PiMax each, and one
// worker, a message admitted behind a full queue is verified within B * PiMax of its arrival (QMax). At n_s = 16 and PiMax = 100 ms that
// is 13.6 s, well inside the 4 T >= 40 s the adequacy condition D + delta + Q_max < 4 T needs at T(0, 0) = 10 s.

// DefaultPiMax is the default verification cost bound per message.
const DefaultPiMax = 100 * time.Millisecond

// QueueBound is (1 + n_s) * 4 views * 2 intents.
func QueueBound(successors int) int { return (1 + successors) * RetainedViews * 2 }

// QMax is the queueing bound of premise PV for the admission bounds: a full queue served by one worker at PiMax each.
func QMax(successors int, piMax time.Duration) time.Duration {
	return time.Duration(QueueBound(successors)) * piMax
}

type queued struct {
	sender string
	msg    Message
}

// Queue is the bounded, round-robin verification queue in front of a Service.
type Queue struct {
	svc   *Service
	piMax time.Duration
	now   func() time.Time
	bound func() int
	// Delivered receives what each processed message produced (this root's assembly, to send); nil drops it.
	Delivered func(Outcome, []Message, error)

	mu    sync.Mutex
	per   map[string][]queued
	ring  []string
	next  int
	n     int
	ready chan struct{}
}

// NewQueue is the queue of svc with the cost bound piMax (0: DefaultPiMax); the service hands it the buffered messages that become
// judgeable.
func NewQueue(svc *Service, piMax time.Duration) *Queue {
	if piMax <= 0 {
		piMax = DefaultPiMax
	}
	q := &Queue{svc: svc, piMax: piMax, now: time.Now, per: map[string][]queued{}, ready: make(chan struct{}, 1),
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
	if len(q.per[sender]) >= MaxQueuedPerPeer {
		return false
	}
	if q.n >= q.bound() && !q.displaceFor(sender) {
		return false
	}
	if _, ok := q.per[sender]; !ok {
		q.ring = append(q.ring, sender)
	}
	q.per[sender] = append(q.per[sender], queued{sender, m})
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

// pop takes the next message round-robin by sender, the senders the service seated last after every other.
func (q *Queue) pop() (queued, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.n == 0 {
		return queued{}, false
	}
	last := q.svc.lastSeats()
	order := make([]int, 0, len(q.ring))
	for i := range q.ring {
		order = append(order, (q.next+i)%len(q.ring))
	}
	sort.SliceStable(order, func(a, b int) bool { return !last[q.ring[order[a]]] && last[q.ring[order[b]]] })
	for _, i := range order {
		sender := q.ring[i]
		if len(q.per[sender]) == 0 {
			continue
		}
		m := q.per[sender][0]
		q.per[sender] = q.per[sender][1:]
		q.n--
		if len(q.per[sender]) == 0 {
			// the sender after it moves into its place: serve it next (review #1188 B11)
			delete(q.per, sender)
			q.ring = append(q.ring[:i], q.ring[i+1:]...)
			q.next = 0
			if len(q.ring) > 0 {
				q.next = i % len(q.ring)
			}
		} else {
			q.next = (i + 1) % len(q.ring)
		}
		return m, true
	}
	return queued{}, false
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
