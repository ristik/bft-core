package cmd

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/gettrustbase"
	"github.com/unicitynetwork/bft-core/seed"
	"github.com/unicitynetwork/bft-core/utbstore"
)

// The signed trust-base history is public data, but producing it copies and encodes every retained entry, so it never runs on the operator RPC's
// request path. A separate read-only listener (--utb-bundle-address, off by default) serves exactly one route; the encoded bundle is built once per
// trust-base tip (the epoch and the EntryID name it) and reused, one build at a time, with at most utbBundleMaxInFlight requests in service.
const (
	utbBundleMaxInFlight = 4
	utbBundlePage        = 256
)

type utbBundleCache struct {
	src    gettrustbase.Source
	budget int // aggregate bytes of the encoded history (a bigger history is not served here)
	mu     sync.Mutex
	tip    utbstore.Tip
	raw    []byte
}

// get returns the encoded bundle for the store's current tip. Concurrent callers wait on the one build.
func (c *utbBundleCache) get() ([]byte, error) {
	tip := c.src.Tip()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.raw != nil && c.tip == tip {
		return c.raw, nil
	}
	var raw [][]byte
	total := 0
	for from := c.src.GenesisEpoch(); ; {
		page, next, more, err := c.src.Range(from, tip.Epoch, utbBundlePage, c.budget)
		if err != nil {
			return nil, fmt.Errorf("reading from epoch %d: %w", from, err)
		}
		for _, e := range page {
			total += len(e)
		}
		if total > c.budget {
			return nil, fmt.Errorf("the history is larger than the %d byte budget of one response: export it with `ubft trust-base utb-export` from the store", c.budget)
		}
		raw = append(raw, page...)
		if !more {
			break
		}
		from = next
	}
	enc, err := types.EncodeTrustBaseBundle(raw)
	if err != nil {
		return nil, err
	}
	if len(enc) > c.budget {
		return nil, fmt.Errorf("the encoded history is larger than the %d byte budget of one response", c.budget)
	}
	c.tip, c.raw = tip, enc
	return enc, nil
}

func (c *utbBundleCache) handler(obs Observability) http.Handler {
	sem := make(chan struct{}, utbBundleMaxInFlight)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/utb/bundle", func(w http.ResponseWriter, r *http.Request) {
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		raw, err := c.get()
		if err != nil {
			operatorLogger(obs).Warn("utb bundle request", "error", err)
			http.Error(w, "the history cannot be served", http.StatusInsufficientStorage)
			return
		}
		w.Header().Set("Content-Type", "application/cbor")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		_, _ = w.Write(raw)
	})
	return mux
}

func newUTBBundleServer(addr string, src gettrustbase.Source, obs Observability) *http.Server {
	c := &utbBundleCache{src: src, budget: seed.MaxUTBBytes}
	return &http.Server{Addr: addr, Handler: c.handler(obs), ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 30 * time.Second}
}
