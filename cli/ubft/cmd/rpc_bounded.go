package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
)

// maxRPCBody bounds one JSON-RPC response read by the status and exporter paths: a misbehaving or hostile endpoint cannot make a poll allocate more.
const maxRPCBody = 4 << 20

var errRPCBodyTooLarge = errors.New("rpc: response exceeds the size bound")

type boundedTransport struct{ next http.RoundTripper }

func (t boundedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.next.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	resp.Body = &boundedBody{rc: resp.Body, left: maxRPCBody}
	return resp, nil
}

type boundedBody struct {
	rc   io.ReadCloser
	left int64
}

func (b *boundedBody) Read(p []byte) (int, error) {
	if b.left <= 0 {
		return 0, errRPCBodyTooLarge
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.rc.Read(p)
	b.left -= int64(n)
	if err == nil && b.left <= 0 {
		// the bound is reached: one more byte would exceed it
		var one [1]byte
		if m, _ := b.rc.Read(one[:]); m > 0 {
			return n, errRPCBodyTooLarge
		}
	}
	return n, err
}

func (b *boundedBody) Close() error { return b.rc.Close() }

// dialBounded dials an RPC endpoint; an http(s) endpoint gets a response-size bound and a request timeout (other schemes are dialled as they are).
func dialBounded(ctx context.Context, url string) (*rpc.Client, error) {
	if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
		return rpc.DialOptions(ctx, url, rpc.WithHTTPClient(&http.Client{Timeout: 15 * time.Second, Transport: boundedTransport{next: http.DefaultTransport}}))
	}
	return rpc.DialContext(ctx, url)
}
