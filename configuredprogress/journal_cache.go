package configuredprogress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"log/slog"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// The journal snapshot cache (bft-core#728). LoadJournal re-reads, re-decodes and cross-checks the whole journal; the recovery stage, both archive replica loops
// and the frontier worker call it about five times a second, and the journal grows to its configured bounds while an archive replica is down. The cache keeps
// the last snapshot a full load built together with the database commit id (bolt Tx.ID) it was built at, and answers a load from it only when, read in one
// transaction, the commit id, the digests of the progress descriptor and control, the verification context and the limits are all unchanged. Any commit by any
// code changes the commit id, so a writer that knows nothing about the cache can only make it miss. Everything a hit returns is a deep copy.
//
// Safety net: every samplerEvery-th hit, and at least every samplerInterval, a full load that uses neither the cache nor the verification memo runs in the
// background and is deep-compared with the cached snapshot; a difference is logged as an error, counted, and drops the cache.

const (
	samplerEvery    = 64
	samplerInterval = 30 * time.Second
)

// ctxIdentity is what a cached snapshot's verification depended on that the Context carries. A Context holding something not comparable cannot be cached.
//
// Invariants the identity relies on: a trust base for an epoch and the shard configuration installed for a shard epoch never change content once they exist,
// so holding TrustBases by identity and ConfForEpoch by presence is enough for the snapshot cache (the verification memo, in contrast, keys on content). The
// root-epoch authority is a live object whose answer changes under the same pointer and whose "not ready" makes a fresh load fail, so its STATE
// (current epoch, ready) is part of the identity and is read at every lookup and before every fill.
type ctxIdentity struct {
	network    types.NetworkID
	partition  types.PartitionID
	shard      string
	conf       string
	rootEpoch  uint64
	execConfig [32]byte
	origin     [32]byte
	trust      any
	hasAuth    bool
	authEpoch  uint64
	authReady  bool
	confFn     bool
}

func identityOf(c Context) (ctxIdentity, bool) {
	id := ctxIdentity{
		network: c.Observation.NetworkID, partition: c.Observation.PartitionID, shard: string(c.Observation.ShardID.Bytes()),
		conf: string(c.Observation.ShardConfHash), rootEpoch: c.Observation.RootEpoch, execConfig: c.ExecutionConfigV2,
		trust: c.Observation.TrustBases, confFn: c.Observation.ConfForEpoch != nil,
	}
	id.origin = c.Origin.BlockHash()
	if c.Observation.EpochAuthority != nil {
		id.hasAuth = true
		id.authEpoch, id.authReady = c.Observation.EpochAuthority.CurrentRootEpoch()
	}
	if id.trust != nil && !reflect.TypeOf(id.trust).Comparable() {
		return ctxIdentity{}, false
	}
	return id, true
}

type journalCacheEntry struct {
	txid       int
	descriptor [32]byte
	control    [32]byte
	ctx        ctxIdentity
	limits     JournalLimits
	snap       JournalSnapshot // private to the cache; never handed out
}

// journalStamp is what a read transaction reports about the database: its commit id and the digests of the progress descriptor and control.
type journalStamp struct {
	txid       int
	descriptor [32]byte
	control    [32]byte
	ok         bool
}

func stampOf(tx *bolt.Tx) journalStamp {
	b := tx.Bucket(bucketName)
	if b == nil {
		return journalStamp{}
	}
	d, c := b.Get(descriptorKey), b.Get(controlKey)
	if d == nil || c == nil {
		return journalStamp{}
	}
	return journalStamp{txid: tx.ID(), descriptor: sha256.Sum256(d), control: sha256.Sum256(c), ok: true}
}

// JournalViewStats counts what the cache and its sampler did; for tests and diagnostics.
type JournalViewStats struct {
	Hits, Misses, Samples, Mismatches uint64
}

type journalCache struct {
	mu      sync.Mutex
	entry   *journalCacheEntry
	hits    atomic.Uint64
	misses  atomic.Uint64
	samples atomic.Uint64
	bad     atomic.Uint64
	lastRun atomic.Int64 // unix nanoseconds of the last sampler start
	running atomic.Bool
	wg      sync.WaitGroup // background samplers, waited for by Close

	// test and tuning hooks; zero means the defaults
	every    uint64
	interval time.Duration
	inline   bool // run the sampler synchronously (tests)
	disabled atomic.Bool
	fresh    func(ctx context.Context, c Context, limits JournalLimits) (JournalSnapshot, journalStamp, bool, error)
}

func (s *Store) ViewStats() JournalViewStats {
	return JournalViewStats{Hits: s.jc.hits.Load(), Misses: s.jc.misses.Load(), Samples: s.jc.samples.Load(), Mismatches: s.jc.bad.Load()}
}

// DropJournalView forgets the cached snapshot.
func (s *Store) DropJournalView() {
	s.jc.mu.Lock()
	s.jc.entry = nil
	s.jc.mu.Unlock()
}

// cachedJournal answers a load from the cache if, in one read transaction, nothing the snapshot depends on has changed.
func (s *Store) cachedJournal(c Context, limits JournalLimits) (JournalSnapshot, bool) {
	if s.jc.disabled.Load() {
		return JournalSnapshot{}, false
	}
	id, ok := identityOf(c)
	if !ok {
		return JournalSnapshot{}, false
	}
	var stamp journalStamp
	if err := s.db.View(func(tx *bolt.Tx) error { stamp = stampOf(tx); return nil }); err != nil || !stamp.ok {
		return JournalSnapshot{}, false
	}
	s.jc.mu.Lock()
	e := s.jc.entry
	hit := e != nil && e.txid == stamp.txid && e.descriptor == stamp.descriptor && e.control == stamp.control && e.limits == limits && e.ctx == id
	var out JournalSnapshot
	if hit {
		out = cloneSnapshot(e.snap)
	}
	s.jc.mu.Unlock()
	if !hit {
		return JournalSnapshot{}, false
	}
	s.jc.hits.Add(1)
	s.maybeSample(c, limits)
	return out, true
}

// storeJournal caches a snapshot a full load built, unless the database moved on after it or the load found the progress image it started from changed.
func (s *Store) storeJournal(id ctxIdentity, limits JournalLimits, stamp journalStamp, consistent bool, snap JournalSnapshot) {
	if s.jc.disabled.Load() || !stamp.ok || !consistent || snap.coverageBaseNeedsPersist {
		return
	}
	entry := &journalCacheEntry{txid: stamp.txid, descriptor: stamp.descriptor, control: stamp.control, ctx: id, limits: limits, snap: cloneSnapshot(snap)}
	s.jc.mu.Lock()
	if s.jc.entry == nil || s.jc.entry.txid <= entry.txid {
		s.jc.entry = entry
	}
	s.jc.mu.Unlock()
}

func (s *Store) maybeSample(c Context, limits JournalLimits) {
	if s.jc.disabled.Load() {
		return
	}
	every := s.jc.every
	if every == 0 {
		every = samplerEvery
	}
	interval := s.jc.interval
	if interval == 0 {
		interval = samplerInterval
	}
	due := s.jc.hits.Load()%every == 0
	if !due && time.Since(time.Unix(0, s.jc.lastRun.Load())) < interval {
		return
	}
	if !s.jc.running.CompareAndSwap(false, true) {
		return
	}
	s.jc.lastRun.Store(time.Now().UnixNano())
	run := func() {
		defer s.jc.running.Store(false)
		s.sampleJournal(c, limits)
	}
	if s.jc.inline {
		run()
		return
	}
	s.jc.wg.Add(1)
	go func() {
		defer s.jc.wg.Done()
		run()
	}()
}

// currentStamp reads the database's commit id and progress digests in one transaction.
func (s *Store) currentStamp() journalStamp {
	var stamp journalStamp
	if err := s.db.View(func(tx *bolt.Tx) error { stamp = stampOf(tx); return nil }); err != nil {
		return journalStamp{}
	}
	return stamp
}

func (e *journalCacheEntry) stampMatches(stamp journalStamp) bool {
	return stamp.ok && e.txid == stamp.txid && e.descriptor == stamp.descriptor && e.control == stamp.control
}

// sampleJournal runs a full load with neither the cache nor the verification memo and compares it with the cached snapshot, provided the database is at the
// cached commit before and after it. At that commit a difference is a mismatch, and so is a fresh load that FAILS where the cache would have served a snapshot:
// that is the divergence that matters most (a context that no longer verifies the journal), so it is logged, counted and drops the view like any other.
func (s *Store) sampleJournal(c Context, limits JournalLimits) {
	s.jc.mu.Lock()
	e := s.jc.entry
	s.jc.mu.Unlock()
	if e == nil || !e.stampMatches(s.currentStamp()) {
		return
	}
	cached := cloneSnapshot(e.snap)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	fresh, _, _, err := s.freshLoad(ctx, c, limits)
	s.jc.samples.Add(1)
	if !e.stampMatches(s.currentStamp()) {
		return // the database moved on while the full load ran: there is no commit at which to compare
	}
	equal := err == nil && reflect.DeepEqual(cached, fresh)
	if s.log != nil {
		st := s.ViewStats()
		s.log.LogAttrs(ctx, slog.LevelDebug, "configuredprogress: journal view sampled", slog.Int("txid", e.txid), slog.Bool("equal", equal), slog.Bool("freshLoadFailed", err != nil),
			slog.Uint64("hits", st.Hits), slog.Uint64("misses", st.Misses), slog.Uint64("samples", st.Samples), slog.Uint64("mismatches", st.Mismatches),
			slog.Int("candidates", len(fresh.Candidates)), slog.Int("observations", len(fresh.Observations)))
	}
	if equal {
		return
	}
	s.jc.bad.Add(1)
	s.DropJournalView()
	if s.log != nil {
		attrs := []any{slog.Int("txid", e.txid), slog.Int("cachedCandidates", len(cached.Candidates)), slog.Int("freshCandidates", len(fresh.Candidates)),
			slog.Int("cachedObservations", len(cached.Observations)), slog.Int("freshObservations", len(fresh.Observations))}
		msg := "configuredprogress: the cached journal snapshot differs from a full load at the same commit; cache dropped"
		if err != nil {
			msg = "configuredprogress: a full load at the cached commit fails where the cache would have served a snapshot; cache dropped"
			attrs = append(attrs, slog.String("err", err.Error()))
		}
		s.log.ErrorContext(ctx, msg, attrs...)
	}
}

// freshLoad is the sampler's full load (neither cache nor memo); tests replace it.
func (s *Store) freshLoad(ctx context.Context, c Context, limits JournalLimits) (JournalSnapshot, journalStamp, bool, error) {
	if s.jc.fresh != nil {
		return s.jc.fresh(ctx, c, limits)
	}
	return s.loadJournalFull(ctx, c, limits, false)
}

var (
	typeUC = reflect.TypeOf((*types.UnicityCertificate)(nil))
	typeTR = reflect.TypeOf((*certification.TechnicalRecord)(nil))
)

// cloneSnapshot deep-copies a snapshot so that a consumer that changes what it was handed cannot change the cache, with one exception: the certificates and
// technical records (decoded, authenticated values nothing in this repository mutates) are shared, as they are by every full load's callers.
func cloneSnapshot(s JournalSnapshot) JournalSnapshot {
	return cloneValue(reflect.ValueOf(s)).Interface().(JournalSnapshot)
}

func cloneValue(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return v
		}
		if v.Type() == typeUC || v.Type() == typeTR {
			return v
		}
		out := reflect.New(v.Type().Elem())
		out.Elem().Set(cloneValue(v.Elem()))
		return out
	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return reflect.ValueOf(bytes.Clone(v.Bytes())).Convert(v.Type())
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(cloneValue(v.Index(i)))
		}
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(cloneValue(v.Index(i)))
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v) // unexported fields (the snapshot's coverageBaseNeedsPersist flag) are copied as they are
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				out.Field(i).Set(cloneValue(v.Field(i)))
			}
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(cloneValue(iter.Key()), cloneValue(iter.Value()))
		}
		return out
	default:
		return v
	}
}
