package consensus

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

// Experimental capped exponential spacing of the retransmission of the node's own, already recorded timeout vote (#982; arch's review in
// briefs/dev2-timeout-backoff-design.md). It is OFF unless UBFT_TIMEOUT_BACKOFF_C is set to an integer >= 2: with it unset (or 1) the manager runs
// exactly the code it ran before (the pacemaker ticker re-sends every LocalTimeout), and nothing here is on the path.
//
// With T = LocalTimeout and the first successful store-and-broadcast of the round's vote at t0, and no resets, the attempts are made at
// t0+T, t0+3T, t0+7T, t0+11T, ... : the successive INTERVALS are T, 2T, 4T, ... capped at C·T. The attempts are driven by a timer of this
// scheduler, not by the pacemaker ticker (whose ticks are not aligned to t0 after an early f+1 timeout), so the spacing is the stated one and
// is not quantized by the ticker: the ticker's repeats are suppressed while a round is scheduled. Not changed: the signed bytes (the recorded vote is
// resent unchanged), the first send (local timeout, weighted f+1, #886's immediate unknown-leader send), the round deadline, the store-before-send
// rule and the retry after a failed store (no schedule exists until a first send succeeded in storing, so the ticker keeps trying every T).
//
// A reset is a newly registered signer of the current epoch and round (after the existing verification and context checks; duplicates, invalid and
// old messages never get there): the exponent returns to the start and the next attempt is brought forward to now+T, never postponed. Resets are
// coalesced (they only move the due time; nothing is sent at once). No state is persisted: a restart or a state installation starts again from a first
// send, i.e. at the base interval.
const (
	timeoutBackoffEnv = "UBFT_TIMEOUT_BACKOFF_C"
	maxBackoffCap     = 64 // saturating bound for C
)

type retxTrigger int

const (
	retxTick      retxTrigger = iota // the pacemaker's repeat of the timeout event
	retxScheduled                    // this scheduler's timer
	retxImmediate                    // an entry action that must send at once (#886 unknown leader)
)

type retxCounters struct {
	firstSends       int
	scheduledSends   int
	immediateRepeats int
	suppressedTicks  int
	staleFires       int
	retired          int
	resetsForward    int // a new signer that brought the next attempt forward
	resetsNoEffect   int // a new signer while the next attempt was already due sooner
	sendErrors       int
	byInterval       map[int]int // scheduled attempts by the scheduled interval, in multiples of T
	schedMs, actMs   int64       // sums over scheduled attempts of the scheduled and the actual wait since the previous attempt
	lagMaxMs         int64       // largest (actual - scheduled) wait
	lagMinMs         int64
	lagSet           bool
}

// timeoutRetx is touched by the consensus loop goroutine only.
type timeoutRetx struct {
	T     time.Duration
	C     int64
	now   func() time.Time
	timer *time.Timer

	active       bool
	epoch, round uint64
	next         time.Time // when the next attempt is due
	prev         time.Time // when the previous attempt (or the first send) was made
	sched        time.Duration
	sent         int // scheduled attempts made since the first send or the last reset

	c     retxCounters
	start time.Time
}

func newTimeoutRetx(t time.Duration, c int64, now func() time.Time) *timeoutRetx {
	if c < 1 {
		c = 1
	}
	if c > maxBackoffCap {
		c = maxBackoffCap
	}
	return &timeoutRetx{T: t, C: c, now: now, c: retxCounters{byInterval: map[int]int{}}}
}

func timeoutRetxFromEnv(localTimeout time.Duration) *timeoutRetx {
	v, err := strconv.ParseInt(os.Getenv(timeoutBackoffEnv), 10, 64)
	if err != nil || v < 2 || localTimeout <= 0 {
		return nil
	}
	r := newTimeoutRetx(localTimeout, v, time.Now)
	r.timer = time.NewTimer(time.Hour)
	r.timer.Stop()
	return r
}

// interval is the wait after the j-th scheduled attempt (j=0: after the first send): min(2^j·T, C·T), saturating.
func (r *timeoutRetx) interval(j int) time.Duration {
	limit := time.Duration(r.C) * r.T
	d := r.T
	for i := 0; i < j && d < limit; i++ {
		d *= 2
	}
	if d > limit {
		d = limit
	}
	return d
}

// C is the timer channel; nil (never ready) when the scheduler is off, so the loop's select needs no condition.
func (r *timeoutRetx) Chan() <-chan time.Time {
	if r == nil || r.timer == nil {
		return nil
	}
	return r.timer.C
}

func (r *timeoutRetx) arm() {
	if r.timer == nil {
		return
	}
	if !r.timer.Stop() {
		select {
		case <-r.timer.C:
		default:
		}
	}
	if !r.active {
		return
	}
	d := r.next.Sub(r.now())
	if d < 0 {
		d = 0
	}
	r.timer.Reset(d)
}

func (r *timeoutRetx) clear() {
	r.active = false
	if r.timer != nil && !r.timer.Stop() {
		select {
		case <-r.timer.C:
		default:
		}
	}
}

// allowTick says whether a repeat raised by the pacemaker's ticker may send: never while the round is scheduled (the timer owns the repeats).
func (r *timeoutRetx) allowTick(epoch, round uint64) bool {
	if r == nil {
		return true
	}
	if r.active && r.epoch == epoch && r.round == round {
		r.c.suppressedTicks++
		return false
	}
	return true
}

// firstSent records the first broadcast attempt of the round's recorded vote (made, whether or not the network took it) and schedules the next.
func (r *timeoutRetx) firstSent(epoch, round uint64, sendErr bool) {
	if r == nil {
		return
	}
	now := r.now()
	if r.start.IsZero() {
		r.start = now
	}
	r.c.firstSends++
	if sendErr {
		r.c.sendErrors++
	}
	r.active, r.epoch, r.round, r.sent = true, epoch, round, 0
	r.prev, r.sched = now, r.interval(0)
	r.next = now.Add(r.sched)
	r.arm()
}

// immediateRepeat records a repeat that was sent at once (an entry action); the schedule is not moved.
func (r *timeoutRetx) immediateRepeat(sendErr bool) {
	if r == nil {
		return
	}
	r.c.immediateRepeats++
	if sendErr {
		r.c.sendErrors++
	}
}

// due reports whether the timer's firing is the scheduled attempt of the current round; a firing for a round that has moved on is stale.
func (r *timeoutRetx) due(epoch, round uint64) bool {
	if r == nil {
		return false
	}
	if !r.active || r.epoch != epoch || r.round != round || r.now().Before(r.next) {
		r.c.staleFires++
		return false
	}
	return true
}

// scheduledSent records a scheduled attempt (made, whether or not the network took it) and schedules the following one.
func (r *timeoutRetx) scheduledSent(sendErr bool) {
	now := r.now()
	act := now.Sub(r.prev)
	r.c.scheduledSends++
	if sendErr {
		r.c.sendErrors++
	}
	r.c.byInterval[int(r.sched/r.T)]++
	r.c.schedMs += r.sched.Milliseconds()
	r.c.actMs += act.Milliseconds()
	lag := (act - r.sched).Milliseconds()
	if !r.c.lagSet || lag > r.c.lagMaxMs {
		r.c.lagMaxMs = lag
	}
	if !r.c.lagSet || lag < r.c.lagMinMs {
		r.c.lagMinMs = lag
	}
	r.c.lagSet = true
	r.sent++
	r.prev, r.sched = now, r.interval(r.sent)
	r.next = now.Add(r.sched)
	r.arm()
}

// registered is a newly registered signer of the given epoch and round: it resets the exponent and brings the next attempt forward to now+T when
// that is sooner than what is scheduled, and never postpones one.
func (r *timeoutRetx) registered(epoch, round uint64) {
	if r == nil || !r.active || r.epoch != epoch || r.round != round {
		return
	}
	r.sent = 0
	if due := r.now().Add(r.T); due.Before(r.next) {
		r.next, r.sched = due, r.T
		r.c.resetsForward++
		r.arm()
		return
	}
	r.c.resetsNoEffect++ // the pending attempt is already due sooner and keeps its time; the intervals after it start over (sent=0)
}

// retire drops the schedule unless it is the one of the epoch and round whose vote the pacemaker holds (held=false: it holds none, e.g. the round
// changed or a recovery reset it).
func (r *timeoutRetx) retire(epoch, round uint64, held bool) {
	if r == nil || !r.active || (held && r.epoch == epoch && r.round == round) {
		return
	}
	r.c.retired++
	r.clear()
}

func (r *timeoutRetx) report(log *slog.Logger, now time.Time) {
	if r == nil || r.start.IsZero() || now.Sub(r.start) < certShadowInterval {
		return
	}
	c := r.c
	var by []string
	for k := 1; k <= int(r.C); k++ {
		if n := c.byInterval[k]; n > 0 {
			by = append(by, fmt.Sprintf("%dT:%d", k, n))
		}
	}
	log.Info("consensus timeout backoff", "capFactor", r.C, "firstSends", c.firstSends, "scheduledSends", c.scheduledSends,
		"immediateRepeats", c.immediateRepeats, "suppressedTicks", c.suppressedTicks, "staleFires", c.staleFires, "retired", c.retired,
		"resetsForward", c.resetsForward, "resetsNoEffect", c.resetsNoEffect, "sendErrors", c.sendErrors,
		"scheduledByInterval", strings.Join(by, ","), "scheduledWaitMs", c.schedMs, "actualWaitMs", c.actMs,
		"lagMinMs", c.lagMinMs, "lagMaxMs", c.lagMaxMs, "intervalMs", now.Sub(r.start).Milliseconds())
	r.c, r.start = retxCounters{byInterval: map[int]int{}}, now
}
