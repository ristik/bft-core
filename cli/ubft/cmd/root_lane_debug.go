package cmd

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime/pprof"
	"strconv"
)

// registerRootLaneDebug exposes diagnostics only on a literal loopback RPC bind and
// only when the rehearsal harness opts in. Neither handler reads the block store.
func registerRootLaneDebug(mux *http.ServeMux, addr string, round func() uint64) {
	host, _, err := net.SplitHostPort(addr)
	if os.Getenv("UBFT_LANE_ROOT_DEBUG") != "1" || err != nil || !net.ParseIP(host).IsLoopback() {
		return
	}
	pid := strconv.Itoa(os.Getpid())
	mux.HandleFunc("GET /debug/consensus/round", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Root-Pid", pid)
		_, _ = fmt.Fprintln(w, round())
	})
	mux.HandleFunc("GET /debug/pprof/goroutine", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Root-Pid") != pid {
			http.Error(w, "expected root PID does not match", http.StatusConflict)
			return
		}
		w.Header().Set("X-Root-Pid", pid)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_ = pprof.Lookup("goroutine").WriteTo(w, 2)
	})
}
