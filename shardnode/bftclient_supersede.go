package shardnode

import (
	"context"
	"sync"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// maxSupersessionInputs bounds the certified input records the supersession marker remembers.
const maxSupersessionInputs = 16

type supersessionMark struct{ epoch, round uint64 }

type supersessionWaiter struct {
	input        string
	epoch, round uint64
	cancel       func()
}

// supersession tells a follower that is waiting for the round leader's block (Round.produceBlock) that the
// certificate it is handling has been replaced by a repeat UC: the same certified InputRecord under the same
// root epoch with a strictly greater authenticated root round. It only ends that wait. The loop, the
// coalescer and the admission journal keep deciding what is delivered next, in order (bft-core#728).
//
// Marker and waiters share one lock, so a repeat that arrived just before the wait registered still cancels it.
type supersession struct {
	mu      sync.Mutex
	latest  map[string]supersessionMark // newest authenticated (epoch, root round) per certified input record
	order   []string                    // insertion order of latest, for the bound
	waiters map[*supersessionWaiter]struct{}
}

// observe records an authenticated response and cancels every registered wait it supersedes. Invalid
// responses never reach it, and neither a duplicate nor an equal-round conflict is "greater".
func (s *supersession) observe(a *certificationAuthorization) {
	s.mu.Lock()
	cur, seen := s.latest[a.inputRecord]
	if seen && (a.rootEpoch < cur.epoch || a.rootEpoch == cur.epoch && a.rootRound <= cur.round) {
		s.mu.Unlock()
		return
	}
	if s.latest == nil {
		s.latest = make(map[string]supersessionMark)
	}
	if !seen {
		s.order = append(s.order, a.inputRecord)
		if len(s.order) > maxSupersessionInputs {
			delete(s.latest, s.order[0])
			s.order = s.order[1:]
		}
	}
	s.latest[a.inputRecord] = supersessionMark{epoch: a.rootEpoch, round: a.rootRound}
	var cancels []func()
	for w := range s.waiters {
		if w.input == a.inputRecord && w.epoch == a.rootEpoch && a.rootRound > w.round {
			cancels = append(cancels, w.cancel)
			delete(s.waiters, w)
		}
	}
	s.mu.Unlock()
	for _, cancel := range cancels { // outside the lock
		cancel()
	}
}

// register arms cancel for the wait on held. It calls cancel at once, before returning, if a repeat of held
// is already known. The returned function unregisters the wait; call it when the wait ends.
func (s *supersession) register(held *types.UnicityCertificate, cancel func()) func() {
	if held == nil || held.InputRecord == nil {
		return func() {}
	}
	input, err := held.InputRecord.Bytes()
	if err != nil {
		return func() {}
	}
	w := &supersessionWaiter{input: string(input), epoch: held.GetRootEpoch(), round: held.GetRootRoundNumber(), cancel: cancel}
	s.mu.Lock()
	if cur, ok := s.latest[w.input]; ok && cur.epoch == w.epoch && cur.round > w.round {
		s.mu.Unlock()
		cancel()
		return func() {}
	}
	if s.waiters == nil {
		s.waiters = make(map[*supersessionWaiter]struct{})
	}
	s.waiters[w] = struct{}{}
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		delete(s.waiters, w)
		s.mu.Unlock()
	}
}

// WatchSupersession is what a Round is given (Round.SetSupersessionWatch).
func (c *BFTClient) WatchSupersession(held *types.UnicityCertificate, cancel func()) func() {
	return c.superseded.register(held, cancel)
}

// receiveQueue is the delivery loop's input: messages the reader took from the network while a delivery was in progress (carry), then the network channel itself.
type receiveQueue struct {
	carry  []any
	ch     <-chan any
	closed bool // the network channel closed while the reader held it
}

func (q *receiveQueue) len() int { return len(q.carry) + len(q.ch) }

// pop returns the next queued message without blocking. closed reports that the network channel is closed and drained.
func (q *receiveQueue) pop() (msg any, ok, closed bool) {
	if len(q.carry) > 0 {
		msg, q.carry = q.carry[0], q.carry[1:]
		return msg, true, false
	}
	select {
	case m, open := <-q.ch:
		if !open {
			return nil, false, true
		}
		return m, true, false
	default:
		return nil, false, q.closed
	}
}

// receiveDuring keeps reading the network channel while the loop is inside a delivery (a round driver or the admission journal), which is the only time the loop itself
// cannot. It verifies each certification response with the coalescer's own check (verifyCertificationAuthorization) and feeds the authenticated ones to c.superseded, so a
// repeat UC that arrives during a wait is seen then and not after the wait ends. Nothing is dropped, reordered or decided here: the messages are handed back to the loop
// through q.carry, ahead of the channel, and the coalescer judges them as before. It holds at most the channel's capacity (one message for an unbuffered channel); beyond
// that the channel's own backpressure applies. The returned function stops the reader and must be called once the delivery is over.
func (c *BFTClient) receiveDuring(ctx context.Context, q *receiveQueue) (stop func()) {
	limit := cap(q.ch)
	if limit < 1 {
		limit = 1
	}
	quit, done := make(chan struct{}), make(chan struct{})
	var held []any
	closed := false
	go func() {
		defer close(done)
		for len(held) < limit {
			select {
			case <-quit:
				return
			case <-ctx.Done():
				return
			case msg, open := <-q.ch:
				if !open {
					closed = true
					return
				}
				if cr, isCR := msg.(*certification.CertificationResponse); isCR && cr != nil {
					if authorization, err := c.verifyCertificationAuthorization(ctx, cr); err == nil {
						c.superseded.observe(authorization)
					}
				}
				held = append(held, msg)
			}
		}
	}()
	return func() {
		close(quit)
		<-done
		q.carry = append(q.carry, held...)
		q.closed = q.closed || closed
	}
}
