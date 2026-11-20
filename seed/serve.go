package seed

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// maxServing bounds the concurrent responses of Handler: a seed is public data, but an exporter's disk and links are not unlimited.
const maxServing = 8

// Handler serves a seed directory read-only: GET and HEAD of "/manifest.json" and of the three payload files, nothing else (no listing, no
// other file of the directory, no redirects). It re-reads the directory per request, so a newer export replaces the seed atomically (the
// manifest is written last); a client holding the old manifest then fails its hash check and starts over.
func Handler(dir string) http.Handler {
	sem := make(chan struct{}, maxServing)
	allowed := map[string]int64{"/" + ManifestName: MaxManifestBytes}
	for n, lim := range fileLimits {
		allowed["/"+n] = lim
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		limit, ok := allowed[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		path := filepath.Join(dir, filepath.Base(r.URL.Path))
		st, err := os.Lstat(path)
		if err != nil || !st.Mode().IsRegular() || st.Size() > limit {
			http.NotFound(w, r)
			return
		}
		f, err := os.Open(path)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		if r.Method == http.MethodGet {
			_, _ = io.CopyN(w, f, st.Size())
		}
	})
}
