package storage

import (
	"sort"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

// Write timing is a MEASUREMENT aid for scaling runs (ristik/bft-core#982, briefs/dev2-128-root-experiment-design.md): how long each durable
// write of the consensus store takes as a whole, and how much of that bbolt itself reports as time spent writing pages to disk (its commit
// writes and syncs them). It changes nothing about the writes. The commit part is read from bbolt's cumulative TxStats around the transaction,
// so it is approximate when another goroutine commits in the same window.
type WriteTiming struct {
	Name        string
	Count       int
	Total, Max  time.Duration
	CommitWrite time.Duration
}

var timers = struct {
	mu sync.Mutex
	m  map[string]*WriteTiming
}{m: map[string]*WriteTiming{}}

func observeWrite(name string, total, commit time.Duration) {
	timers.mu.Lock()
	defer timers.mu.Unlock()
	t := timers.m[name]
	if t == nil {
		t = &WriteTiming{Name: name}
		timers.m[name] = t
	}
	t.Count++
	t.Total += total
	t.CommitWrite += commit
	if total > t.Max {
		t.Max = total
	}
}

// TakeWriteTimings returns the timings since the previous call, largest total first, and resets them.
func TakeWriteTimings() []WriteTiming {
	timers.mu.Lock()
	defer timers.mu.Unlock()
	out := make([]WriteTiming, 0, len(timers.m))
	for _, t := range timers.m {
		out = append(out, *t)
	}
	timers.m = map[string]*WriteTiming{}
	sort.Slice(out, func(i, j int) bool { return out[i].Total > out[j].Total })
	return out
}

// update is db.Update with the write timing around it.
func (db BoltDB) update(name string, fn func(tx *bbolt.Tx) error) error {
	start := time.Now()
	var before time.Duration
	err := db.db.Update(func(tx *bbolt.Tx) error {
		st := db.db.Stats().TxStats
		before = st.GetWriteTime()
		return fn(tx)
	})
	after := db.db.Stats().TxStats
	observeWrite(name, time.Since(start), after.GetWriteTime()-before)
	return err
}

// ObserveStep records the duration of a named non-write step of a storage operation (same table, "step." prefix), so a slow call can be
// split into its parts. Measurement only.
func ObserveStep(name string, d time.Duration) { observeWrite("step."+name, d, 0) }
