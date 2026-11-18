package cmd

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/vrhandofffix"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
)

// astra's review of #1185 (P3): the operator guards of the VR routes, and the Host boundary against DNS rebinding.

func review1185Mux(t *testing.T) *http.ServeMux {
	f := vrhandofffix.New(t)
	in, d := f.Intent()
	keys, _ := f.Incumbents()
	op := &fixtureOperator{f: f, d: vrschedule.Derived{VRIntent: storage.VRIntent{Digest: d, AnchorRound: in.AnchorRound},
		Intent: in, RootEpoch: f.RC.RootEpoch, Body: f.BC}, keys: keys}
	mux := http.NewServeMux()
	registerVRHandoffRoutes(mux, op)
	return mux
}

func TestReview1185OperatorGuards(t *testing.T) {
	mux := review1185Mux(t)
	for _, tc := range []struct {
		name, method, path, remote, content, origin string
		want                                        int
	}{
		{"operator GET", "GET", "intent", "127.0.0.1:1234", "application/json", "", 200},
		{"remote peer", "GET", "intent", "192.0.2.10:1234", "application/json", "", 403},
		{"cross-origin GET", "GET", "intent", "127.0.0.1:1234", "application/json", "http://attacker.example", 415},
		{"browser POST", "POST", "certificate", "127.0.0.1:1234", "application/json", "http://attacker.example", 415},
		{"opaque-origin POST", "POST", "certificate", "127.0.0.1:1234", "application/json", "null", 415},
		{"simple content type", "POST", "certificate", "127.0.0.1:1234", "text/plain", "", 415},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, "http://localhost/api/v1/vr/"+tc.path, nil)
			r.RemoteAddr = tc.remote
			r.Header.Set("Content-Type", tc.content)
			r.Header.Set("Origin", tc.origin)
			r.Header.Set("X-Forwarded-For", "127.0.0.1")
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			require.Equal(t, tc.want, w.Code)
		})
	}
}

func TestReview1185IntentRejectsReboundHost(t *testing.T) {
	mux := review1185Mux(t)
	r := httptest.NewRequest("GET", "http://attacker.example/api/v1/vr/intent", nil)
	r.RemoteAddr = "127.0.0.1:1234"
	r.Header.Set("Content-Type", "application/json")
	// A same-origin GET after DNS rebinding need not carry Origin.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	require.Equal(t, http.StatusForbidden, w.Code, "an untrusted Host should not be accepted as an operator request")
}

// Every operator endpoint shares the guard: a loopback peer naming a host other than an IP literal, localhost or a configured operator name is
// refused; IP literals (a re-bound name never is one), localhost and configured names are served.
func TestOperatorHostBoundary(t *testing.T) {
	t.Cleanup(func() { require.NoError(t, configureOperatorHosts("")) })
	require.NoError(t, configureOperatorHosts(""))
	for host, want := range map[string]bool{
		"127.0.0.1:8002": true, "127.0.0.1": true, "[::1]:8002": true, "10.1.2.3:80": true, "localhost:8002": true, "LOCALHOST.": true,
		"attacker.example": false, "attacker.example:8002": false, "root1:8002": false, "": false, "localhost.attacker.example": false,
	} {
		require.Equal(t, want, operatorHostAllowed(host), host)
	}
	require.NoError(t, configureOperatorHosts("root1, Operator.Example."))
	require.True(t, operatorHostAllowed("root1:8002"))
	require.True(t, operatorHostAllowed("operator.example"))
	require.False(t, operatorHostAllowed("attacker.example"))
	for _, bad := range []string{"root1:8002", "a/b", "root1,,root2", " "} {
		_, err := parseOperatorHosts(bad)
		if bad == " " {
			require.NoError(t, err, "blank is none")
			continue
		}
		require.Error(t, err, bad)
	}

	ok := func(w http.ResponseWriter, r *http.Request) {
		if localOperatorRequest(w, r) {
			w.WriteHeader(http.StatusOK)
		}
	}
	for _, path := range []string{"/api/v1/handoff/plan", "/api/v1/handoff/abort", "/api/v1/q3/status", "/api/v1/pos/control", "/api/v1/vr/certificate"} {
		r := httptest.NewRequest(http.MethodPost, "http://attacker.example"+path, nil)
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		ok(w, r)
		require.Equal(t, http.StatusForbidden, w.Code, path)
		r.Host = "127.0.0.1:8002"
		w = httptest.NewRecorder()
		ok(w, r)
		require.Equal(t, http.StatusOK, w.Code, path)
	}
}

func init() {
	// httptest.NewRequest with a bare path names the host example.com: the endpoint tests address the operator endpoints under it
	testOperatorHost = "example.com"
}
