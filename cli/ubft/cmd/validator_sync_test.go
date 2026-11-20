package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/rpc"
)

func TestETA(t *testing.T) {
	for _, c := range []struct {
		behind     int64
		rate, head float64
		want       string
	}{{0, 0, 0, "caught up"}, {2, 0, 0, "caught up"}, {100, 0, 0.1, "not closing"}, {100, 5.1, 0.1, "20s"}, {600, 11, 1, "1m0s"}} {
		if got := etaOf(c.behind, c.rate, c.head); got != c.want {
			t.Errorf("etaOf(%d, %v, %v) = %q, want %q", c.behind, c.rate, c.head, got, c.want)
		}
	}
}

func staticRPC(t *testing.T, result string) *rpc.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%s}`, result)
	}))
	t.Cleanup(srv.Close)
	c, err := rpc.Dial(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// An unavailable head is an error (unknown), never height 0 and so never "caught up"; a genuine block 0 is still a head.
func TestBlockInfoRefusesAnUnavailableHead(t *testing.T) {
	for _, bad := range []string{`null`, `{}`, `{"number":"0x1"}`} {
		if _, _, err := blockInfo(context.Background(), staticRPC(t, bad), "latest"); err == nil {
			t.Errorf("blockInfo accepted %s", bad)
		}
	}
	n, ts, err := blockInfo(context.Background(), staticRPC(t, `{"number":"0x0","timestamp":"0x5"}`), "latest")
	if err != nil || n != 0 || ts != 5 {
		t.Errorf("genesis block: %d %d %v", n, ts, err)
	}
}

// An unavailable public head serializes as null, never 0, at the top level and in the nested sync view.
func TestUnknownPublicHeadSerializesAsNull(t *testing.T) {
	r := &validatorStatusReport{PublicHeadUnknown: true, Sync: &syncView{PublicHeadUnknown: true, Sources: []string{}}}
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), `"publicHead":null`) != 2 || strings.Contains(string(raw), `"publicHead":0`) {
		t.Fatalf("publicHead must be null in both places: %s", raw)
	}
	var sb strings.Builder
	r.text(&sb)
	if !strings.Contains(sb.String(), "public head UNKNOWN") || !strings.Contains(sb.String(), "public head unknown") {
		t.Fatalf("the text report must say the head is unknown: %q", sb.String())
	}
	n := uint64(0) // a genuine block 0 is a head and is serialized as 0
	r2 := &validatorStatusReport{PublicHead: &n}
	raw, _ = json.Marshal(r2)
	if !strings.Contains(string(raw), `"publicHead":0`) {
		t.Fatalf("a genuine head 0 must stay 0: %s", raw)
	}
}
