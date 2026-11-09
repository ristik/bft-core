package consensus

import (
	"log/slog"
	"reflect"
	"sort"
	"time"
)

// loopProfileInterval is how often the consensus loop reports where its time went.
const loopProfileInterval = 30 * time.Second

// loopProfile is a measurement aid for scaling runs (briefs/dev2-128-root-experiment-design.md): per root network message type, how many
// messages the single consensus loop handled and how long it spent in handleRootNetMsg (which includes the signature checks of the
// message), and how much of the interval the loop was busy. It is touched only by the loop goroutine and costs two clock reads per message.
type loopProfile struct {
	start  time.Time
	byType map[reflect.Type]*loopStat
	busy   time.Duration
	// timeout votes: verifications skipped (exact message already verified and counted) and done, and the time spent on digests
	verifyHits, verifyMisses int
	digestTime               time.Duration
}

type loopStat struct {
	count int
	total time.Duration
	max   time.Duration
}

func (p *loopProfile) observe(msg any, d time.Duration) {
	if p.byType == nil {
		p.byType = make(map[reflect.Type]*loopStat)
	}
	t := reflect.TypeOf(msg)
	s := p.byType[t]
	if s == nil {
		s = &loopStat{}
		p.byType[t] = s
	}
	s.count++
	s.total += d
	if d > s.max {
		s.max = d
	}
	p.busy += d
}

// report logs and resets the profile once the interval has passed.
func (p *loopProfile) report(log *slog.Logger, now time.Time) {
	if p.start.IsZero() {
		p.start = now
		return
	}
	if now.Sub(p.start) < loopProfileInterval || len(p.byType) == 0 {
		return
	}
	types := make([]reflect.Type, 0, len(p.byType))
	for t := range p.byType {
		types = append(types, t)
	}
	sort.Slice(types, func(i, j int) bool { return p.byType[types[i]].total > p.byType[types[j]].total })
	wall := now.Sub(p.start)
	for _, t := range types {
		s := p.byType[t]
		log.Info("consensus loop profile", "type", t.String(), "count", s.count, "totalMs", s.total.Milliseconds(),
			"avgUs", s.total.Microseconds()/int64(s.count), "maxMs", s.max.Milliseconds(), "intervalMs", wall.Milliseconds())
	}
	log.Info("consensus loop busy", "busyMs", p.busy.Milliseconds(), "intervalMs", wall.Milliseconds(),
		"timeoutVerifyHits", p.verifyHits, "timeoutVerifyMisses", p.verifyMisses, "timeoutDigestUs", p.digestTime.Microseconds())
	p.start, p.byType, p.busy, p.verifyHits, p.verifyMisses, p.digestTime = now, nil, 0, 0, 0, 0
}
