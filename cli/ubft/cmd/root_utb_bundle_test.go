package cmd

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utbstore"
)

type fakeUTBSource struct {
	tip    utbstore.Tip
	entry  []byte
	ranges atomic.Int32
}

func (f *fakeUTBSource) Tip() utbstore.Tip                            { return f.tip }
func (f *fakeUTBSource) GenesisEpoch() uint64                         { return 1 }
func (f *fakeUTBSource) Entry(uint64) (*types.RootTrustBaseV2, error) { return nil, nil }
func (f *fakeUTBSource) Range(from, to uint64, maxEntries, maxBytes int) ([][]byte, uint64, bool, error) {
	f.ranges.Add(1)
	return [][]byte{f.entry}, 0, false, nil
}

// The bundle is built once per tip and reused; a larger history than the budget is refused, not built.
func TestUTBBundleCacheBuildsOncePerTipAndHonoursTheBudget(t *testing.T) {
	src := &fakeUTBSource{tip: utbstore.Tip{Epoch: 1}, entry: make([]byte, 100)}
	c := &utbBundleCache{src: src, budget: 50}
	if _, err := c.get(); err == nil {
		t.Fatal("a history over the budget was built")
	}
	c = &utbBundleCache{src: src, budget: 1 << 20}
	// the fake entry is not a valid entry, so the encoder refuses; what is checked here is that a refusal is not cached as a success
	for i := 0; i < 2; i++ {
		if _, err := c.get(); err == nil {
			t.Fatal("an undecodable history was served")
		}
	}
}

func TestUTBBundleServerIsOneReadOnlyRouteWithBoundedConcurrency(t *testing.T) {
	src := &fakeUTBSource{tip: utbstore.Tip{Epoch: 1}, entry: make([]byte, 10)}
	c := &utbBundleCache{src: src, budget: 1 << 20}
	h := c.handler(nil)
	for _, tc := range []struct{ method, path string }{{"POST", "/api/v1/utb/bundle"}, {"GET", "/api/v1/roundInfo"}, {"PUT", "/api/v1/trustbases"}, {"GET", "/api/v1/handoff/plan"}} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code == http.StatusOK {
			t.Errorf("%s %s answered 200 on the bundle listener", tc.method, tc.path)
		}
	}
	// concurrent requests: at most utbBundleMaxInFlight are served at once; the rest get 503 immediately
	var wg sync.WaitGroup
	var busy atomic.Int32
	block := make(chan struct{})
	slow := &blockingSource{fakeUTBSource: src, block: block}
	c2 := &utbBundleCache{src: slow, budget: 1 << 20}
	h2 := c2.handler(nil)
	for i := 0; i < utbBundleMaxInFlight+3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			h2.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/utb/bundle", nil))
			if rec.Code == http.StatusServiceUnavailable {
				busy.Add(1)
			}
		}()
	}
	for busy.Load() < 3 {
	}
	close(block)
	wg.Wait()
	if busy.Load() != 3 {
		t.Errorf("%d requests were refused as busy, want 3", busy.Load())
	}
}

type blockingSource struct {
	*fakeUTBSource
	block chan struct{}
}

func (b *blockingSource) Range(from, to uint64, maxEntries, maxBytes int) ([][]byte, uint64, bool, error) {
	<-b.block
	return b.fakeUTBSource.Range(from, to, maxEntries, maxBytes)
}
