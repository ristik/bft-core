package cmd

import (
	"fmt"
	"net/http"
	"os"
	"runtime/pprof"
	"strconv"
)

// registerRootLaneDebug exposes diagnostics only on a loopback-bound root RPC and
// only when the rehearsal harness opts in. Neither handler reads the block store.
func registerRootLaneDebug(mux *http.ServeMux, addr string, round func() uint64) {
	if os.Getenv("UBFT_LANE_ROOT_DEBUG") != "1" || !rpcBindIsLoopback(addr) {
		return
	}
	pid := strconv.Itoa(os.Getpid())
	mux.HandleFunc("GET /debug/consensus/round", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Root-Pid", pid)
		_, _ = fmt.Fprintln(w, round())
	})
	mux.HandleFunc("GET /debug/pprof/goroutine", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Root-Pid", pid)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_ = pprof.Lookup("goroutine").WriteTo(w, 2)
	})
}
