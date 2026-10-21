package configuredprogress

import (
	"bytes"
	"context"
	"errors"
	"math/rand"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-go-base/types"
	bolt "go.etcd.io/bbolt"
)

// loadBoth returns what the production path (cache, memo) and a plain full load (neither) say about the store now.
func loadBoth(t *testing.T, s *Store, c Context, limits JournalLimits) (got, want JournalSnapshot, gotErr, wantErr error) {
	t.Helper()
	got, gotErr = s.LoadJournal(context.Background(), c, limits)
	want, wantErr = s.loadJournal(context.Background(), c, limits, false)
	return
}

func requireEquivalent(t *testing.T, s *Store, c Context, limits JournalLimits, step string) {
	t.Helper()
	got, want, gotErr, wantErr := loadBoth(t, s, c, limits)
	if wantErr != nil || gotErr != nil {
		require.Equal(t, errString(wantErr), errString(gotErr), "%s: the production path and the full load disagree on the error", step)
		return
	}
	require.True(t, reflect.DeepEqual(want, got), "%s: the cached snapshot differs from a full load\nfull:   %d candidates %d observations\ncached: %d candidates %d observations", step,
		len(want.Candidates), len(want.Observations), len(got.Candidates), len(got.Observations))
	// and asking again, with no write in between, is answered from the cache
	hits := s.ViewStats().Hits
	again, err := s.LoadJournal(context.Background(), c, limits)
	require.NoError(t, err)
	require.Equal(t, hits+1, s.ViewStats().Hits, "%s: the second load of an unchanged database must be a cache hit", step)
	require.True(t, reflect.DeepEqual(want, again), "%s: the cache hit differs from a full load", step)
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// bft-core#728: after every write, accepted or refused, the cached snapshot equals a full load that uses neither the cache nor the verification memo.
func TestJournalCacheEquivalentToFullLoadAfterEveryWrite(t *testing.T) {
	for _, seed := range []int64{1, 2, 3} {
		seed := seed
		t.Run("seed", func(t *testing.T) {
			rng := rand.New(rand.NewSource(seed))
			s, f, c, _, item, limits := frontierTestSetupWithLimits(t, t.TempDir()+"/journal.db", JournalLimits{Candidates: 64, Observations: 128, Bytes: 16 << 20})
			defer s.Close()
			ctx := context.Background()
			requireEquivalent(t, s, c, limits, "initial")

			image, err := s.loadJournal(ctx, c, limits, false)
			require.NoError(t, err)
			last := image.Observations[len(image.Observations)-1]
			repeatIR := *last.UC.InputRecord
			assigned, root := last.TR.Round+1, last.UC.GetRootRoundNumber()+1
			advanced, pruned := false, false
			branch := byte(0x10)

			for step := 0; step < 60; step++ {
				var name string
				switch op := rng.Intn(8); op {
				case 0, 1: // a repeat certificate of the certified round
					name = "admit a repeat UC"
					ir := repeatIR
					o := f.observation(&ir, assigned, root)
					assigned++
					root++
					p, _, e := s.PrepareObservation(ctx, c, o)
					require.NoError(t, e)
					_, _, e = s.CommitObservation(p)
					require.NoError(t, e)
				case 2, 3: // a new candidate body on the certified parent (a branch)
					name = "put a branch candidate"
					branch++
					cand := branchCandidate(image, branch)
					e := s.PutJournalCandidate(ctx, c, limits, cand)
					if e != nil {
						require.True(t, errors.Is(e, ErrConflict) || errors.Is(e, ErrBounds), "%v", e)
					}
				case 4: // the same candidate again (idempotent) or the same hash with other bytes (refused)
					name = "put a candidate twice / conflicting"
					cand := branchCandidate(image, 0x10)
					_ = s.PutJournalCandidate(ctx, c, limits, cand)
					cand.Raw = []byte{0xde, 0xad}
					require.Error(t, s.PutJournalCandidate(ctx, c, limits, cand))
				case 5:
					name = "advance the frontier"
					if !advanced {
						require.NoError(t, s.AdvanceFrontier(ctx, c, limits, []frontier.Coverage{item}))
						advanced = true
					}
				case 6:
					name = "prune"
					if advanced {
						require.NoError(t, s.PruneFrontier(ctx, c, limits))
						pruned = true
					}
				case 7: // a refused write that must leave everything as it was
					name = "refused write"
					bad := branchCandidate(image, 0x77)
					bad.AuthorizingUC = nil
					require.Error(t, s.PutJournalCandidate(ctx, c, limits, bad))
				}
				requireEquivalent(t, s, c, limits, name)
			}
			require.True(t, advanced && pruned || seed != 1, "the run should have exercised the frontier")
			require.Zero(t, s.ViewStats().Mismatches)
		})
	}
}

func branchCandidate(image JournalSnapshot, tag byte) JournalCandidate {
	base := image.Candidates[0].Candidate
	cand := base
	cand.Hash = bytes.Repeat([]byte{tag}, 32)
	cand.Raw = []byte{0x81, 0x42, tag}
	cand.Round, cand.Number, cand.ParentNumber = 2, 2, 1
	cand.ParentHash, cand.ParentState = base.Hash, base.StateRoot
	cand.StateRoot = bytes.Repeat([]byte{tag + 1}, 32)
	cand.LocallyBuilt = false
	return cand
}

// A writer that knows nothing about the cache (a raw transaction, as a bug or an offline tool would) changes the commit id, so the next load misses, and the
// progress token does not have to change for that.
func TestJournalCacheMissesAfterABypassWriterWithAnUnchangedProgressToken(t *testing.T) {
	s, _, c, _, _, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	before, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	_, token, err := s.Load(ctx, c)
	require.NoError(t, err)
	require.False(t, before.Candidates[0].Candidate.LocallyBuilt)

	key := journalCandidateKey(before.Candidates[0].Candidate.Hash)
	require.NoError(t, s.db.Update(func(tx *bolt.Tx) error { // not through any Store writer
		b := tx.Bucket(bucketName)
		w, e := decodeCandidate(b.Get(key))
		if e != nil {
			return e
		}
		w.LocallyBuilt = true
		raw, e := encodeCandidate(w)
		if e != nil {
			return e
		}
		return b.Put(key, raw)
	}))
	require.True(t, s.Unchanged(token), "the progress token is the same: it does not cover journal-only writes")

	misses := s.ViewStats().Misses
	after, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	require.Equal(t, misses+1, s.ViewStats().Misses, "the commit id changed, so the cache missed")
	require.True(t, after.Candidates[0].Candidate.LocallyBuilt, "and the new bytes are what the load returned")
	requireEquivalent(t, s, c, limits, "after the bypass writer")
}

// A refused write (rolled back) leaves the database as it was: the cache stays valid and still equals a full load.
func TestJournalCacheSurvivesARefusedWrite(t *testing.T) {
	s, _, c, _, _, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	image, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	hits := s.ViewStats().Hits
	bad := image.Candidates[0].Candidate
	bad.Raw = []byte{0xba, 0xd0}
	require.ErrorIs(t, s.PutJournalCandidate(ctx, c, limits, bad), ErrConflict)
	requireEquivalent(t, s, c, limits, "after a refused write")
	require.Greater(t, s.ViewStats().Hits, hits)
}

// The cache is keyed by the limits and the context it was built for.
func TestJournalCacheIsKeyedByLimitsAndContext(t *testing.T) {
	s, _, c, _, _, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	_, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	other := limits
	other.Candidates++
	misses := s.ViewStats().Misses
	_, err = s.LoadJournal(ctx, c, other)
	require.Error(t, err, "limits the journal was not created with are refused: a cached view must not answer for them")
	require.Equal(t, misses+1, s.ViewStats().Misses, "other limits are a different view")

	changed := c
	changed.Observation.RootEpoch++
	misses = s.ViewStats().Misses
	_, _ = s.LoadJournal(ctx, changed, limits) // refused or not, it must not be answered from the view built for another context
	require.Equal(t, misses+1, s.ViewStats().Misses, "another verification context is a different view")

	// the progress digests are part of the stamp as well as the commit id
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	for name, poison := range map[string]func(e *journalCacheEntry){
		"descriptor": func(e *journalCacheEntry) { e.descriptor[0] ^= 1 },
		"control":    func(e *journalCacheEntry) { e.control[0] ^= 1 },
	} {
		s.jc.mu.Lock()
		poison(s.jc.entry)
		s.jc.mu.Unlock()
		misses = s.ViewStats().Misses
		_, err = s.LoadJournal(ctx, c, limits)
		require.NoError(t, err)
		require.Equal(t, misses+1, s.ViewStats().Misses, "a changed %s digest is a miss", name)
		_, err = s.LoadJournal(ctx, c, limits) // refilled by the miss
		require.NoError(t, err)
	}
}

// What a hit returns is a deep copy: changing it, anywhere but in the shared certificates, cannot change what the next load returns.
func TestJournalCacheHandsOutCopies(t *testing.T) {
	s, _, c, _, _, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	pristine, err := s.loadJournal(ctx, c, limits, false)
	require.NoError(t, err)
	first, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	scribble(reflect.ValueOf(&first).Elem())
	second, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(pristine, second), "a consumer changed its snapshot and the cache followed")
	third, err := s.LoadJournal(ctx, c, limits) // and a hit's copy, changed, does not reach the next hit either
	require.NoError(t, err)
	scribble(reflect.ValueOf(&second).Elem())
	require.True(t, reflect.DeepEqual(pristine, third))
	again, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(pristine, again))
}

// scribble overwrites every byte slice, number and bool reachable from v except inside the shared certificates.
func scribble(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() || v.Type() == typeUC || v.Type() == typeTR {
			return
		}
		scribble(v.Elem())
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			for i := 0; i < v.Len(); i++ {
				v.Index(i).SetUint(v.Index(i).Uint() ^ 0xff)
			}
			return
		}
		for i := 0; i < v.Len(); i++ {
			scribble(v.Index(i))
		}
	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			scribble(v.Index(i))
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				scribble(v.Field(i))
			}
		}
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uint:
		if v.CanSet() {
			v.SetUint(v.Uint() ^ 0xffff)
		}
	case reflect.Int, reflect.Int64:
		if v.CanSet() {
			v.SetInt(v.Int() + 12345)
		}
	case reflect.Bool:
		if v.CanSet() {
			v.SetBool(!v.Bool())
		}
	}
}

// Readers race a writer and the sampler: every snapshot a reader gets is equal to a full load at some point between its start and its end (the journal only
// grows here, so it is at least as large as the one before and no larger than the one after).
func TestJournalCacheRaceReadersWriterAndSampler(t *testing.T) {
	s, f, c, _, _, limits := frontierTestSetupWithLimits(t, t.TempDir()+"/journal.db", JournalLimits{Candidates: 8, Observations: 512, Bytes: 16 << 20})
	defer s.Close()
	ctx := context.Background()
	s.jc.every = 3 // sample often
	image, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	last := image.Observations[len(image.Observations)-1]
	repeatIR := *last.UC.InputRecord

	var wg sync.WaitGroup
	stop := make(chan struct{})
	var mu sync.Mutex
	var failures []string
	for r := 0; r < 4; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			prev := 0
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap, e := s.LoadJournal(ctx, c, limits)
				mu.Lock()
				if errors.Is(e, ErrStale) {
					// a full load that keeps losing the race with a writer gives up after three attempts: existing behaviour, retried by callers
				} else if e != nil {
					failures = append(failures, e.Error())
				} else if len(snap.Observations) < prev {
					failures = append(failures, "the journal went backwards")
				} else {
					prev = len(snap.Observations)
				}
				mu.Unlock()
				scribble(reflect.ValueOf(&snap).Elem())
			}
		}()
	}
	assigned, root := last.TR.Round+1, last.UC.GetRootRoundNumber()+1
	for i := 0; i < 25; i++ {
		ir := repeatIR
		o := f.observation(&ir, assigned, root)
		assigned++
		root++
		p, _, e := s.PrepareObservation(ctx, c, o)
		require.NoError(t, e)
		_, _, e = s.CommitObservation(p)
		require.NoError(t, e)
	}
	close(stop)
	wg.Wait()
	require.Empty(t, failures)
	requireEquivalent(t, s, c, limits, "after the race")
	require.Zero(t, s.ViewStats().Mismatches, "the sampler found no difference")
}

// The sampler notices a cache that disagrees with the database at the same commit id, reports it, and drops the cache.
func TestJournalCacheSamplerDetectsADivergentView(t *testing.T) {
	s, _, c, _, _, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	rec := &recordedLog{}
	s.SetLogger(slogOf(rec))
	s.jc.inline = true
	s.jc.every = 1
	_, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)

	// a healthy view is sampled and found equal
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	require.Positive(t, s.ViewStats().Samples)
	require.Zero(t, s.ViewStats().Mismatches)

	// corrupt the cached snapshot behind the cache's back
	s.jc.mu.Lock()
	s.jc.entry.snap.Candidates[0].Candidate.Number += 41
	s.jc.mu.Unlock()
	fresh, err := s.LoadJournal(ctx, c, limits) // a hit, which triggers the sampler
	require.NoError(t, err)
	require.NotEqual(t, uint64(1), fresh.Candidates[0].Candidate.Number+0*41, "the poisoned copy was served once")
	require.Equal(t, uint64(1), s.ViewStats().Mismatches)
	require.NotEmpty(t, rec.find("configuredprogress: the cached journal snapshot differs from a full load at the same commit; cache dropped"))

	healed, err := s.LoadJournal(ctx, c, limits) // the cache was dropped: this is a full load again
	require.NoError(t, err)
	want, err := s.loadJournal(ctx, c, limits, false)
	require.NoError(t, err)
	require.True(t, reflect.DeepEqual(want, healed))
}

// A cache that was filled from a snapshot taken at an older commit must not overwrite a newer one.
func TestJournalCacheNeverReplacesNewerWithOlder(t *testing.T) {
	s, f, c, _, _, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	_, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	newer := s.jc.entry.txid
	old := *s.jc.entry
	old.txid = newer - 1
	s.storeJournal(old.ctx, limits, journalStamp{txid: old.txid, descriptor: old.descriptor, control: old.control, ok: true}, true, old.snap)
	require.Equal(t, newer, s.jc.entry.txid)
	_ = f
}

var _ = types.ShardID{}

// Work per delivery is flat: after each write the next load verifies only what the write added (the memo remembers each real verification once), however
// large the journal has grown.
func TestLoadAfterEachWriteVerifiesOnlyWhatChanged(t *testing.T) {
	s, f, c, _, _, limits := frontierTestSetupWithLimits(t, t.TempDir()+"/journal.db", JournalLimits{Candidates: 8, Observations: 128, Bytes: 16 << 20})
	defer s.Close()
	ctx := context.Background()
	image, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	last := image.Observations[len(image.Observations)-1]
	repeatIR := *last.UC.InputRecord
	assigned, root := last.TR.Round+1, last.UC.GetRootRoundNumber()+1

	var perStep []uint64
	for i := 0; i < 80; i++ {
		ir := repeatIR
		o := f.observation(&ir, assigned, root)
		assigned++
		root++
		p, _, e := s.PrepareObservation(ctx, c, o)
		require.NoError(t, e)
		_, _, e = s.CommitObservation(p)
		require.NoError(t, e)
		before := s.vm.remembered.Load()
		got, e := s.LoadJournal(ctx, c, limits)
		require.NoError(t, e)
		perStep = append(perStep, s.vm.remembered.Load()-before)
		require.Len(t, got.Observations, len(image.Observations)+i+1)
	}
	for i, n := range perStep {
		require.LessOrEqual(t, n, uint64(4), "step %d verified %d new certificates after one admitted observation (per step: %v)", i, n, perStep)
	}
	var early, late uint64
	for i := 0; i < 20; i++ {
		early += perStep[i]
		late += perStep[len(perStep)-1-i]
	}
	require.Positive(t, early, "each new observation was verified once, through the memo")
	require.LessOrEqual(t, late, early, "the verification work per delivery must not grow with the journal (first 20 steps: %d, last 20: %d)", early, late)

	// a load with nothing new in between does no verification and no full load
	before, hits := s.vm.remembered.Load(), s.ViewStats().Hits
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	require.Equal(t, before, s.vm.remembered.Load())
	require.Equal(t, hits+1, s.ViewStats().Hits)
}

type liveAuthority struct {
	mu    sync.Mutex
	epoch uint64
	ready bool
}

func (a *liveAuthority) CurrentRootEpoch() (uint64, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.epoch, a.ready
}

func (a *liveAuthority) set(epoch uint64, ready bool) {
	a.mu.Lock()
	a.epoch, a.ready = epoch, ready
	a.mu.Unlock()
}

// The root-epoch authority is a live object: the cache key holds its STATE, so a snapshot cached while it was ready is not served once a full load would refuse.
func TestJournalCacheKeyHoldsTheAuthoritysState(t *testing.T) {
	s, _, c, _, _, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	auth := &liveAuthority{epoch: c.Observation.RootEpoch, ready: true}
	c.Observation.EpochAuthority = auth

	_, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	hits := s.ViewStats().Hits
	require.Positive(t, hits)

	auth.set(c.Observation.RootEpoch, false) // same pointer, same commit, but a fresh load now refuses
	_, wantErr := s.loadJournal(ctx, c, limits, false)
	require.Error(t, wantErr)
	_, gotErr := s.LoadJournal(ctx, c, limits)
	require.Error(t, gotErr, "the cached snapshot must not be served while the authority is not ready")
	require.Equal(t, wantErr.Error(), gotErr.Error())
	require.Equal(t, hits, s.ViewStats().Hits)

	auth.set(c.Observation.RootEpoch, true)
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)

	misses := s.ViewStats().Misses
	auth.set(c.Observation.RootEpoch+1, true) // the epoch advanced: one miss, then hits again
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	require.Equal(t, misses+1, s.ViewStats().Misses)
	_, err = s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	require.Equal(t, misses+1, s.ViewStats().Misses)
}

// The divergence that matters most: the cache holds a snapshot and a full load at the SAME commit fails. The sampler must flag it, say why, and drop the view,
// after which a load fails exactly as an uncached one does.
func TestJournalCacheSamplerFlagsAFullLoadThatFailsAtTheCachedCommit(t *testing.T) {
	s, _, c, _, _, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	rec := &recordedLog{}
	s.SetLogger(slogOf(rec))
	auth := &liveAuthority{epoch: c.Observation.RootEpoch, ready: true}
	c.Observation.EpochAuthority = auth
	_, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)

	auth.set(c.Observation.RootEpoch, false)
	s.sampleJournal(c, limits) // the sampler runs without the lookup, as it does when the authority goes unready during a sample

	require.Equal(t, uint64(1), s.ViewStats().Mismatches)
	logs := rec.find("configuredprogress: a full load at the cached commit fails where the cache would have served a snapshot; cache dropped")
	require.Len(t, logs, 1)
	require.NotEmpty(t, logs[0]["err"])
	s.jc.mu.Lock()
	require.Nil(t, s.jc.entry, "the view was dropped")
	s.jc.mu.Unlock()
	_, gotErr := s.LoadJournal(ctx, c, limits)
	_, wantErr := s.loadJournal(ctx, c, limits, false)
	require.Error(t, gotErr)
	require.Equal(t, wantErr.Error(), gotErr.Error())
}

// A failed full load while the database moves is not evidence against the view: no commit to compare at, so nothing is counted.
func TestJournalCacheSamplerIgnoresAFailureWhenTheCommitMoved(t *testing.T) {
	s, f, c, _, _, limits := frontierTestSetupWithFixture(t, t.TempDir()+"/journal.db")
	defer s.Close()
	ctx := context.Background()
	s.jc.every, s.jc.interval = 1<<62, 1000*time.Hour // no background sampler: this test calls the sampler itself
	s.jc.lastRun.Store(time.Now().UnixNano())
	image, err := s.LoadJournal(ctx, c, limits)
	require.NoError(t, err)
	last := image.Observations[len(image.Observations)-1]
	ir := *last.UC.InputRecord
	s.jc.fresh = func(context.Context, Context, JournalLimits) (JournalSnapshot, journalStamp, bool, error) {
		o := f.observation(&ir, last.TR.Round+1, last.UC.GetRootRoundNumber()+1)
		p, _, e := s.PrepareObservation(ctx, c, o)
		require.NoError(t, e)
		_, _, e = s.CommitObservation(p)
		require.NoError(t, e)
		return JournalSnapshot{}, journalStamp{}, false, errors.New("injected failure after the database moved")
	}
	s.sampleJournal(c, limits)
	require.Zero(t, s.ViewStats().Mismatches)
}
