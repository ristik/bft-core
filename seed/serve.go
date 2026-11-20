package seed

import (
	"io"
	"net/http"
	"strconv"
	"strings"
)

// maxServing bounds the concurrent responses of Handler: a seed is public data, but an exporter's disk and links are not unlimited.
const maxServing = 8

// Handler serves a seed directory read-only: GET and HEAD of "/manifest.json" and of the three payload files, nothing else (no listing, no
// other file of the directory, no redirects). It re-reads the directory per request, so a newer export replaces the seed atomically (the
// manifest is written last); a client holding the old manifest then fails its hash check and starts over.
func Handler(dir string) http.Handler {
	sem := make(chan struct{}, maxServing)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name != ManifestName {
			if _, listed := fileLimits[name]; !listed {
				http.NotFound(w, r)
				return
			}
		}
		// the serving slot covers everything below, the manifest read included
		select {
		case sem <- struct{}{}:
			defer func() { <-sem }()
		default:
			http.Error(w, "busy", http.StatusServiceUnavailable)
			return
		}
		// one directory version for the whole request: the directory is opened once (no symlink followed) and the manifest and the payload are read
		// relative to it
		d, err := openSeedDir(dir)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer d.Close()
		limit := int64(MaxManifestBytes)
		if name != ManifestName {
			// a payload is served at exactly the size the directory's own manifest declares for it, never more
			_, m, err := d.readManifest()
			if err != nil || m.file(name).Size <= 0 {
				http.NotFound(w, r)
				return
			}
			limit = m.file(name).Size
		}
		f, st, err := d.openRegular(name, limit)
		if err != nil || (name != ManifestName && st.Size() != limit) {
			if f != nil {
				f.Close()
			}
			http.NotFound(w, r)
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Length", strconv.FormatInt(st.Size(), 10))
		if r.Method == http.MethodGet {
			_, _ = io.Copy(w, io.LimitReader(f, st.Size()))
		}
	})
}
