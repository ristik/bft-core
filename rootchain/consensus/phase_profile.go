package consensus

import (
	"log/slog"
	"sort"
	"time"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// phaseProfile is a measurement aid (scaling runs, ristik/bft-core#982): the time the consensus loop spends in each step of handling a
// proposal, so the ~190 ms mean of a ProposalMsg can be split into signature checks, state execution, disk writes and signing. It is touched
// only by the loop goroutine; the cost is one clock read per step. Nothing in the handling changes.
type phaseProfile struct {
	start  time.Time
	phases map[string]*phaseStat
}

type phaseStat struct {
	count      int
	total, max time.Duration
}

// phaseLap times the consecutive steps of one handler run.
type phaseLap struct {
	p *phaseProfile
	t time.Time
}

func (p *phaseProfile) begin() phaseLap { return phaseLap{p: p, t: time.Now()} }

// lap records the time since the previous lap under name and starts the next step.
func (l *phaseLap) lap(name string) {
	now := time.Now()
	l.p.add(name, now.Sub(l.t))
	l.t = now
}

// rest records whatever is left when the handler returns early (an error path), under "rest".
func (l *phaseLap) rest() { l.lap("rest") }

func (p *phaseProfile) add(name string, d time.Duration) {
	if p.phases == nil {
		p.phases = make(map[string]*phaseStat)
	}
	s := p.phases[name]
	if s == nil {
		s = &phaseStat{}
		p.phases[name] = s
	}
	s.count++
	s.total += d
	if d > s.max {
		s.max = d
	}
}

// report logs the phases of the period, largest total first, and resets them.
func (p *phaseProfile) report(log *slog.Logger, now time.Time) {
	if p.start.IsZero() {
		p.start = now
		return
	}
	if now.Sub(p.start) < loopProfileInterval || len(p.phases) == 0 {
		return
	}
	names := make([]string, 0, len(p.phases))
	for n := range p.phases {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return p.phases[names[i]].total > p.phases[names[j]].total })
	for _, n := range names {
		s := p.phases[n]
		log.Info("consensus proposal phase", "phase", n, "count", s.count, "totalMs", s.total.Milliseconds(),
			"avgUs", s.total.Microseconds()/int64(s.count), "maxMs", s.max.Milliseconds(), "intervalMs", now.Sub(p.start).Milliseconds())
	}
	for _, w := range storage.TakeWriteTimings() {
		log.Info("consensus storage write", "op", w.Name, "count", w.Count, "totalMs", w.Total.Milliseconds(),
			"avgUs", w.Total.Microseconds()/int64(w.Count), "maxMs", w.Max.Milliseconds(), "commitWriteMs", w.CommitWrite.Milliseconds(),
			"intervalMs", now.Sub(p.start).Milliseconds())
	}
	p.start, p.phases = now, nil
}
