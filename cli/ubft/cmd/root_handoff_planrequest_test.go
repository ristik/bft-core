package cmd

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// `handoff plan-request` writes exactly the request `propose` sends to the first root, so a wrapper that performs the plan, intent and endorse phases
// itself (each inside one validator's namespace) plans the same attempt.
func TestPlanRequestIsExactlyWhatProposeSends(t *testing.T) {
	var sent []byte
	stub := &handoffOperatorStub{}
	mux := http.NewServeMux()
	plan := rootHandoffPlanHandler(stub)
	mux.HandleFunc("POST /api/v1/handoff/plan", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		sent = body
		r.Body = io.NopCloser(bytes.NewReader(body))
		plan(w, r)
	})
	mux.HandleFunc("POST /api/v1/handoff/intent", rootHandoffIntentHandler(stub))
	mux.HandleFunc("POST /api/v1/handoff/endorse", rootHandoffEndorseHandler(stub))
	server := httptest.NewServer(mux)
	defer server.Close()
	dir := t.TempDir()
	nextFile := filepath.Join(dir, "next-trust-base.json")
	require.NoError(t, os.WriteFile(nextFile, []byte(`{"epoch":2}`), 0o600))
	for name, extra := range map[string][]string{"plain": nil, "v3 without receipts": {"--q3"}} {
		t.Run(name, func(t *testing.T) {
			sent = nil
			root := newRootCmd()
			root.SetOut(&bytes.Buffer{})
			root.SetErr(&bytes.Buffer{})
			root.SetArgs(append([]string{"handoff", "propose", "--next-trust-base", nextFile, "--root-rpc", server.URL}, extra...))
			_ = root.Execute() // the stub root refuses a V3 plan: the request it was sent is what is compared
			require.NotEmpty(t, sent)
			out := filepath.Join(dir, "request.json")
			builder := newRootCmd()
			builder.SetOut(&bytes.Buffer{})
			builder.SetErr(&bytes.Buffer{})
			builder.SetArgs(append([]string{"handoff", "plan-request", "--next-trust-base", nextFile, "--out", out}, extra...))
			require.NoError(t, builder.Execute())
			written, err := os.ReadFile(out)
			require.NoError(t, err)
			require.Equal(t, string(sent)+"\n", string(written))
			info, err := os.Stat(out)
			require.NoError(t, err)
			require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
		})
	}
	t.Run("it refuses what propose refuses and contacts nobody", func(t *testing.T) {
		builder := newRootCmd()
		builder.SetOut(&bytes.Buffer{})
		builder.SetErr(&bytes.Buffer{})
		builder.SetArgs([]string{"handoff", "plan-request", "--next-trust-base", filepath.Join(dir, "missing.json"), "--out", filepath.Join(dir, "x.json")})
		require.Error(t, builder.Execute())
		_, err := os.Stat(filepath.Join(dir, "x.json"))
		require.True(t, os.IsNotExist(err))
	})
}
