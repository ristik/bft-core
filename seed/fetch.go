package seed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"
)

// FetchOptions bound a fetch.
type FetchOptions struct {
	Pins Pins
	// MinSources is how many sources must answer with the same manifest (default 1). Sources that answer differently always refuse the fetch.
	MinSources int
	// Client is the HTTP client (default: 30 s timeout, redirects refused).
	Client *http.Client
}

// Sourced is a verified seed with the sources that served the manifest.
type Sourced struct {
	*Verified
	// Sources are the sources whose manifest bytes were identical.
	Sources []string
	// Unreachable lists the sources that did not answer, with the reason.
	Unreachable []string
}

func defaultClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// normalize is the canonical form of a source: lower-case scheme and host, the default port dropped, the path cleaned and without a trailing slash.
// Equivalent spellings of one endpoint ("HTTP://Host:80/seed/", "http://host/seed") become one source. It cannot tell two names of one machine
// apart (localhost, 127.0.0.1, a DNS alias): independence of the mirrors is the operator's choice.
func normalize(src string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(src))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", refuse("source %q is not an http(s) URL without credentials", src)
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" || (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	p := path.Clean("/" + u.EscapedPath())
	if p == "/" {
		p = ""
	}
	return scheme + "://" + host + p, nil
}

func get(ctx context.Context, c *http.Client, base, name string, max int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+name, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", name, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: more than %d bytes", name, max)
	}
	return b, nil
}

// Fetch takes the manifest from every source, refuses when any two differ, downloads the payload (each file bounded by the manifest's size and
// checked against its hash, from the first source that serves it intact) and verifies the whole seed against the pins.
func Fetch(ctx context.Context, sources []string, opt FetchOptions) (*Sourced, error) {
	if len(sources) == 0 {
		return nil, refuse("no source given")
	}
	c := opt.Client
	if c == nil {
		c = defaultClient()
	}
	if opt.MinSources < 1 {
		opt.MinSources = 1
	}
	var bases []string
	seen := map[string]bool{}
	for _, s := range sources {
		b, err := normalize(s)
		if err != nil {
			return nil, err
		}
		if !seen[b] {
			seen[b] = true
			bases = append(bases, b)
		}
	}

	byDigest := map[string][]string{}
	raws := map[string][]byte{}
	var down []string
	for _, b := range bases {
		raw, err := get(ctx, c, b, ManifestName, MaxManifestBytes)
		if err != nil {
			down = append(down, fmt.Sprintf("%s: %v", b, err))
			continue
		}
		d := ManifestDigest(raw)
		byDigest[d] = append(byDigest[d], b)
		raws[d] = raw
	}
	switch {
	case len(byDigest) == 0:
		return nil, refuse("no source answered: %s", strings.Join(down, "; "))
	case len(byDigest) > 1:
		var parts []string
		for d, srcs := range byDigest {
			parts = append(parts, fmt.Sprintf("%s from %s", d, strings.Join(srcs, ", ")))
		}
		sort.Strings(parts)
		return nil, refuse("the sources disagree about the seed (%d different manifests): %s", len(byDigest), strings.Join(parts, "; "))
	}
	var digest string
	for d := range byDigest {
		digest = d
	}
	agree := byDigest[digest]
	if len(agree) < opt.MinSources {
		return nil, refuse("%d source(s) answered, %d required: %s", len(agree), opt.MinSources, strings.Join(down, "; "))
	}
	m, err := DecodeManifest(raws[digest])
	if err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	for _, f := range m.Files {
		var last error
		for _, b := range agree {
			data, err := get(ctx, c, b, f.Name, f.Size)
			switch {
			case err != nil:
				last = fmt.Errorf("%s: %w", b, err)
			case int64(len(data)) != f.Size || sum(data) != strings.ToLower(f.SHA256):
				last = fmt.Errorf("%s: %s does not match the manifest", b, f.Name)
			default:
				files[f.Name], last = data, nil
			}
			if last == nil {
				break
			}
		}
		if last != nil {
			return nil, refuse("fetching %s: %w", f.Name, errors.Join(last))
		}
	}
	v, err := Verify(raws[digest], files, opt.Pins)
	if err != nil {
		return nil, err
	}
	return &Sourced{Verified: v, Sources: agree, Unreachable: down}, nil
}
