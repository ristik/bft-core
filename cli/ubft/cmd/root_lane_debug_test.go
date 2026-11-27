package cmd

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRootLaneDebugRequiresOptInAndLoopbackBind(t *testing.T) {
	for _, tc := range []struct {
		name, env, addr string
		enabled         bool
	}{
		{"default", "", "127.0.0.1:25866", false},
		{"wildcard", "1", "0.0.0.0:25866", false},
		{"hostname", "1", "localhost:25866", false},
		{"non-loopback", "1", "192.0.2.1:25866", false},
		{"loopback", "1", "127.0.0.1:25866", true},
		{"IPv6 loopback", "1", "[::1]:25866", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("UBFT_LANE_ROOT_DEBUG", tc.env)
			mux := http.NewServeMux()
			registerRootLaneDebug(mux, tc.addr, func() uint64 { return 52 })
			for path, expected := range map[string]string{
				"/debug/consensus/round":         "52\n",
				"/debug/pprof/goroutine?debug=2": "goroutine ",
			} {
				res := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, path, nil)
				req.Header.Set("X-Root-Pid", strconv.Itoa(os.Getpid()))
				mux.ServeHTTP(res, req)
				if !tc.enabled {
					require.Equal(t, http.StatusNotFound, res.Code)
					continue
				}
				require.Equal(t, http.StatusOK, res.Code)
				require.Equal(t, strconv.Itoa(os.Getpid()), res.Header().Get("X-Root-Pid"))
				require.Contains(t, res.Body.String(), expected)
			}
		})
	}
}

func TestRootLaneDebugStackCaptureRequiresMatchingPID(t *testing.T) {
	t.Setenv("UBFT_LANE_ROOT_DEBUG", "1")
	mux := http.NewServeMux()
	registerRootLaneDebug(mux, "127.0.0.1:25866", func() uint64 { return 52 })
	for _, pid := range []string{"", strconv.Itoa(os.Getpid() + 1)} {
		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/debug/pprof/goroutine?debug=2", nil)
		if pid != "" {
			req.Header.Set("X-Root-Pid", pid)
		}
		mux.ServeHTTP(res, req)
		require.Equal(t, http.StatusConflict, res.Code)
		require.NotContains(t, res.Body.String(), "goroutine ")
	}
}
