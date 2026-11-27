package consensus

import (
	"log/slog"
	"os"
	"strconv"
	"time"
)

// UBFT_SHADOW_BACKOFF=1 turns the shadow model of a capped exponential backoff of timeout-vote rebroadcast on (measurement only; arch's review of
// briefs/dev2-timeout-backoff-design.md, step 1). It changes nothing: the node still rebroadcasts exactly as before. The model only classifies each
// rebroadcast the node actually made as one the backoff schedule would have sent or would have suppressed, and counts the registrations of new
// signers that would have brought a due send forward. UBFT_SHADOW_BACKOFF_C is the cap factor (default 4).
const (
	backoffShadowEnv  = "UBFT_SHADOW_BACKOFF"
	backoffShadowCEnv = "UBFT_SHADOW_BACKOFF_C"
)

// backoffShadow follows arch's schedule: from the first send at t0 the next attempts are due at t0+T, then every interval doubles up to C·T:
// intervals T, 2T, 4T, 4T… (C=4), i.e. t0+T, t0+3T, t0+7T, t0+11T. A newly registered current-round signer resets the exponent and brings the next
// due attempt forward to now+T, never later than it already was. It is touched by the consensus loop goroutine only.
type backoffShadow struct {
	T      time.Duration
	C      int64
	now    func() time.Time
	rounds map[uint64]*backoffRound
	c      backoffCounters
	start  time.Time
}

type backoffRound struct {
	next time.Time
	sent int // attempts the model allowed so far (after the first send)
}

type backoffCounters struct {
	firstSends, rebroadcasts, allowed, suppressed int
	newSigners, resetsApplied                     int
}

func newBackoffShadow(t time.Duration, c int64, now func() time.Time) *backoffShadow {
	if c < 1 {
		c = 1
	}
	return &backoffShadow{T: t, C: c, now: now, rounds: map[uint64]*backoffRound{}}
}

// backoffShadowFromEnv returns a model when the environment asks for one, else nil.
func backoffShadowFromEnv(localTimeout time.Duration) *backoffShadow {
	if os.Getenv(backoffShadowEnv) != "1" || localTimeout <= 0 {
		return nil
	}
	c := int64(4)
	if v, err := strconv.ParseInt(os.Getenv(backoffShadowCEnv), 10, 64); err == nil && v >= 1 {
		c = v
	}
	return newBackoffShadow(localTimeout, c, time.Now)
}

// interval is the wait after the j-th allowed attempt (j=0: after the first send): min(2^j·T, C·T), saturating.
func (b *backoffShadow) interval(j int) time.Duration {
	d := b.T
	for i := 0; i < j && d < time.Duration(b.C)*b.T; i++ {
		d *= 2
	}
	if limit := time.Duration(b.C) * b.T; d > limit {
		d = limit
	}
	return d
}

// attempt records one broadcast attempt of the round's timeout vote (counted when it is made, whether or not the network accepts it).
// rebroadcast is false for the first send of the round's vote.
func (b *backoffShadow) attempt(round uint64, rebroadcast bool) {
	if b == nil {
		return
	}
	now := b.now()
	if b.start.IsZero() {
		b.start = now
	}
	st := b.rounds[round]
	if st == nil || !rebroadcast {
		b.c.firstSends++
		b.rounds[round] = &backoffRound{next: now.Add(b.interval(0))}
		for r := range b.rounds {
			if r+16 < round {
				delete(b.rounds, r)
			}
		}
		return
	}
	b.c.rebroadcasts++
	// the real clock ticks every T, so an attempt a few percent early is the attempt that was due
	if !now.Before(st.next.Add(-b.T / 20)) {
		b.c.allowed++
		st.sent++
		st.next = now.Add(b.interval(st.sent))
		return
	}
	b.c.suppressed++
}

// registered records that a valid timeout vote of a signer not counted before was registered in the given (current) round.
func (b *backoffShadow) registered(round uint64) {
	if b == nil {
		return
	}
	st := b.rounds[round]
	if st == nil {
		return // this node has not timed the round out: nothing is scheduled
	}
	b.c.newSigners++
	st.sent = 0
	if due := b.now().Add(b.interval(0)); due.Before(st.next) {
		st.next = due
		b.c.resetsApplied++
	}
}

func (b *backoffShadow) report(log *slog.Logger, now time.Time) {
	if b == nil || b.start.IsZero() || now.Sub(b.start) < certShadowInterval {
		return
	}
	c := b.c
	log.Info("consensus shadow backoff", "capFactor", b.C, "firstSends", c.firstSends, "rebroadcasts", c.rebroadcasts,
		"wouldSend", c.allowed, "wouldSuppress", c.suppressed, "newSigners", c.newSigners, "resetsBringingForward", c.resetsApplied,
		"intervalMs", now.Sub(b.start).Milliseconds())
	b.c, b.start = backoffCounters{}, now
}
