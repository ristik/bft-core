package recordsfeed

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Prefetching (bft-core#1071): a catch-up verifies a page of blocks one by one, and each block's derivation needs the root-record cut of
// its origin, one round trip to a mirror. Prefetch fetches a page's cuts ahead, a few at a time. Everything here is speculative:
//
//   - nothing fetched is believed: Cursor verifies a prefetched cut against the authenticated origin it is asked for and uses it once;
//   - the keys are locators read from unauthenticated certificates, so the table is a bounded, evictable cache: a completed entry that is
//     not used is dropped when its batch ends (the suffix was refused or abandoned), when it is older than prefetchTTL, or to make room;
//   - the fetches go through one scheduler for the whole Source, which bounds them in all (prefetchStreams) and per peer
//     (prefetchPerPeer, on every fallback too), leaving each mirror's other stream slots to the foreground Cursor and record reads.

const (
	// maxPrefetched and maxPrefetchedBytes bound the cuts fetched ahead and not yet used: a few catch-up pages.
	maxPrefetched      = 256
	maxPrefetchedBytes = 16 << 20
	// prefetchTTL is how long a completed, unused prefetch is kept.
	prefetchTTL = time.Minute
	// prefetchStreams bounds the prefetches in flight from one Source; prefetchPerPeer those to one peer. A server admits MaxPendingPerPeer
	// streams of a peer: half are left to the requests the verification itself makes.
	prefetchStreams = 6
	prefetchPerPeer = MaxPendingPerPeer / 2
)

// PeerRemote is a Remote that names the peers it would ask (resolved for the node's current role) and can ask one of them alone, so that
// the prefetch scheduler admits each request against the peer it actually goes to.
type PeerRemote interface {
	Remote
	Peers() []peer.ID
	CutFrom(ctx context.Context, id peer.ID, key CutKey) (Cut, error)
}

type prefetchState uint8

const (
	prefetchQueued prefetchState = iota
	prefetchRunning
	prefetchDone
)

// prefetch is one speculative cut. done closes once cut and err are final; both are written only before that.
type prefetch struct {
	key      CutKey
	batch    uint64 // the batch that owns it: the newest that asked for it
	state    prefetchState
	tried    map[string]bool
	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{}
	cut      Cut
	err      error
	finished time.Time
	bytes    int
}

// cutSource is one place a cut can be fetched from: a peer of a PeerRemote, or a Remote that names none.
type cutSource struct {
	id    string
	fetch func(context.Context, CutKey) (Cut, error)
}

// prefetcher is a Source's speculative cut table and its scheduler; the zero value is ready.
type prefetcher struct {
	mu        sync.Mutex
	entries   map[CutKey]*prefetch
	queue     []*prefetch
	running   int
	perSource map[string]int
	bytes     int
	batch     uint64
	now       func() time.Time // tests
}

func (p *prefetcher) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

// sources lists where cuts can be fetched now: every peer the remotes name for the current role (a non-active node's root remotes name
// none), each once, and each remote that names no peers as itself.
func (s *Source) sources() []cutSource {
	var out []cutSource
	seen := map[string]bool{}
	for i, r := range s.remotes {
		if pr, ok := r.(PeerRemote); ok {
			for _, id := range pr.Peers() {
				key := "peer:" + id.String()
				if id == "" || seen[key] {
					continue
				}
				seen[key] = true
				id := id
				out = append(out, cutSource{id: key, fetch: func(ctx context.Context, k CutKey) (Cut, error) { return pr.CutFrom(ctx, id, k) }})
			}
			continue
		}
		key := fmt.Sprintf("remote:%d", i)
		seen[key] = true
		out = append(out, cutSource{id: key, fetch: r.Cut})
	}
	return out
}

// Prefetch fetches the cuts of the given keys ahead of their use and returns the function that ends the batch: it drops what the batch
// fetched and nothing used, and cancels what is still queued or running for it. The batch also ends with ctx. A key this source holds a
// verified cut for is skipped; one already prefetched is taken over by this batch, so ending an older batch leaves it to this one. The call
// returns at once.
func (s *Source) Prefetch(ctx context.Context, keys []CutKey) func() {
	if len(s.remotes) == 0 || len(keys) == 0 {
		return func() {}
	}
	s.mu.Lock()
	store := s.store
	var wanted []CutKey
	for _, key := range keys {
		if _, ok := s.cuts[key]; !ok {
			wanted = append(wanted, key)
		}
	}
	s.mu.Unlock()
	if store != nil {
		missing := wanted[:0:0]
		for _, key := range wanted {
			if _, ok, err := store.GetCut(key); err != nil || !ok {
				missing = append(missing, key)
			}
		}
		wanted = missing
	}
	p := &s.prefetch
	p.mu.Lock()
	if p.entries == nil {
		p.entries, p.perSource = make(map[CutKey]*prefetch), make(map[string]int)
	}
	p.batch++
	batch := p.batch
	p.expireLocked()
	for _, key := range wanted {
		if e, ok := p.entries[key]; ok {
			e.batch = batch
			continue
		}
		if len(p.entries) >= maxPrefetched && !p.evictLocked() {
			break // every entry is queued or running: the rest of the batch is fetched on demand
		}
		jobCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
		e := &prefetch{key: key, batch: batch, tried: map[string]bool{}, ctx: jobCtx, cancel: cancel, done: make(chan struct{})}
		p.entries[key] = e
		p.queue = append(p.queue, e)
	}
	p.mu.Unlock()
	var once sync.Once
	end := func() { once.Do(func() { s.endBatch(batch) }) }
	stop := context.AfterFunc(ctx, end)
	s.pump()
	return func() { stop(); end() }
}

// endBatch drops the entries batch still owns: queued ones are failed, running ones canceled, completed ones that nothing used forgotten.
func (s *Source) endBatch(batch uint64) {
	p := &s.prefetch
	p.mu.Lock()
	for key, e := range p.entries {
		if e.batch != batch {
			continue
		}
		switch e.state {
		case prefetchQueued:
			p.removeQueuedLocked(e)
			p.finishLocked(e, Cut{}, context.Canceled)
		case prefetchRunning:
			e.cancel() // its fetch ends and finishes it as failed
		case prefetchDone:
			p.dropLocked(key, e)
		}
	}
	p.mu.Unlock()
	s.pump()
}

// take waits for a prefetch of key and returns its cut, removing it from the table: it is used once. false when there is none, it failed,
// or ctx ended first.
func (p *prefetcher) take(ctx context.Context, key CutKey) (Cut, bool) {
	p.mu.Lock()
	e := p.entries[key]
	p.mu.Unlock()
	if e == nil {
		return Cut{}, false
	}
	select {
	case <-e.done:
	case <-ctx.Done():
		return Cut{}, false
	}
	p.mu.Lock()
	if p.entries[key] == e {
		p.dropLocked(key, e)
	}
	p.mu.Unlock()
	return e.cut, e.err == nil
}

// pump starts queued fetches while the Source-wide and per-source bounds allow: each on the source with the fewest prefetches in flight
// that it has not tried yet. A queued fetch that every current source has failed is failed.
func (s *Source) pump() {
	sources := s.sources()
	p := &s.prefetch
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := 0; i < len(p.queue) && p.running < prefetchStreams; {
		e := p.queue[i]
		if e.ctx.Err() != nil {
			p.queue = append(p.queue[:i], p.queue[i+1:]...)
			p.finishLocked(e, Cut{}, e.ctx.Err())
			continue
		}
		var pick *cutSource
		untried := false
		for j := range sources {
			src := &sources[j]
			if e.tried[src.id] {
				continue
			}
			untried = true
			if p.perSource[src.id] >= prefetchPerPeer {
				continue
			}
			if pick == nil || p.perSource[src.id] < p.perSource[pick.id] {
				pick = src
			}
		}
		if !untried {
			p.queue = append(p.queue[:i], p.queue[i+1:]...)
			p.finishLocked(e, Cut{}, fmt.Errorf("%w: no source served the cut", ErrUnavailable))
			continue
		}
		if pick == nil {
			i++ // its sources are busy: a later key may have an idle one
			continue
		}
		p.queue = append(p.queue[:i], p.queue[i+1:]...)
		e.state, e.tried[pick.id] = prefetchRunning, true
		p.running++
		p.perSource[pick.id]++
		go s.run(e, *pick)
	}
}

// run fetches one prefetch from src and settles it: a success completes it, a failure queues it again for its next source.
func (s *Source) run(e *prefetch, src cutSource) {
	cut, err := src.fetch(e.ctx, e.key)
	size := 0
	if err == nil {
		raw, merr := types.Cbor.Marshal(cut)
		if merr != nil {
			err = errors.Join(ErrWire, merr)
		}
		size = len(raw)
	}
	p := &s.prefetch
	p.mu.Lock()
	p.running--
	if p.perSource[src.id]--; p.perSource[src.id] <= 0 {
		delete(p.perSource, src.id)
	}
	switch {
	case e.ctx.Err() != nil:
		// its batch ended (or it was taken and dropped) while it ran: whatever it got is not kept
		p.finishLocked(e, Cut{}, e.ctx.Err())
	case err == nil && size <= maxPrefetchedBytes:
		for p.bytes+size > maxPrefetchedBytes && p.evictLocked() {
		}
		if p.bytes+size > maxPrefetchedBytes {
			p.finishLocked(e, Cut{}, fmt.Errorf("%w: prefetch byte budget", ErrUnavailable))
			break
		}
		e.bytes, p.bytes = size, p.bytes+size
		p.finishLocked(e, cut, nil)
	case err == nil:
		p.finishLocked(e, Cut{}, fmt.Errorf("%w: cut of %d bytes", ErrWire, size))
	default:
		e.state = prefetchQueued
		p.queue = append([]*prefetch{e}, p.queue...) // its next source, first
	}
	p.mu.Unlock()
	s.pump()
}

// finishLocked makes e final. A failed prefetch leaves the table at once (Cursor then asks the remotes); a completed one stays until it is
// taken, its batch ends, it expires, or it is evicted.
func (p *prefetcher) finishLocked(e *prefetch, cut Cut, err error) {
	if e.state == prefetchDone {
		return
	}
	e.state, e.cut, e.err, e.finished = prefetchDone, cut, err, p.clock()
	close(e.done)
	if err != nil {
		if p.entries[e.key] == e {
			delete(p.entries, e.key)
		}
		e.cancel()
	}
}

// dropLocked forgets a completed (or failed) entry and returns its bytes.
func (p *prefetcher) dropLocked(key CutKey, e *prefetch) {
	if p.entries[key] == e {
		delete(p.entries, key)
	}
	p.bytes -= e.bytes
	e.bytes = 0
	e.cancel()
}

func (p *prefetcher) removeQueuedLocked(e *prefetch) {
	for i, q := range p.queue {
		if q == e {
			p.queue = append(p.queue[:i], p.queue[i+1:]...)
			return
		}
	}
}

// expireLocked drops the completed entries older than prefetchTTL.
func (p *prefetcher) expireLocked() {
	now := p.clock()
	for key, e := range p.entries {
		if e.state == prefetchDone && now.Sub(e.finished) > prefetchTTL {
			p.dropLocked(key, e)
		}
	}
}

// evictLocked drops the oldest completed, unused entry; false when every entry is still queued or running.
func (p *prefetcher) evictLocked() bool {
	var done []*prefetch
	for _, e := range p.entries {
		if e.state == prefetchDone {
			done = append(done, e)
		}
	}
	if len(done) == 0 {
		return false
	}
	sort.Slice(done, func(i, j int) bool { return done[i].finished.Before(done[j].finished) })
	p.dropLocked(done[0].key, done[0])
	return true
}

// prefetchStats are the table's counters (tests).
type prefetchStats struct {
	entries, queued, running, bytes int
}

func (p *prefetcher) stats() prefetchStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return prefetchStats{entries: len(p.entries), queued: len(p.queue), running: p.running, bytes: p.bytes}
}
