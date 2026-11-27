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
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
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

type vrRecoveryStub struct {
	handoffOperatorStub
	planned int
}

func (s *vrRecoveryStub) PlanVRRecovery() (abdrc.HandoffApprovalMsg, error) {
	s.planned++
	return abdrc.HandoffApprovalMsg{Attempt: 3}, nil
}

// A VR exact recovery request names nothing: the plan endpoint hands it to the root's own derivation (#1221), and a root without one refuses it.
func TestVRRecoveryPlanRequest(t *testing.T) {
	request, epoch, err := planRequestFor(true, "", "", "", false)
	require.NoError(t, err)
	require.Zero(t, epoch)
	require.JSONEq(t, `{"nextTrustBase":null,"vrRecovery":true}`, string(request))
	_, _, err = planRequestFor(true, "next.json", "", "", false)
	require.Error(t, err, "no trust base is read for a recovery")
	_, _, err = planRequestFor(false, "", "", "", false)
	require.Error(t, err)

	stub := &vrRecoveryStub{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rootHandoffPlanHandler(stub)(w, r) }))
	defer server.Close()
	var plan abdrc.HandoffApprovalMsg
	require.NoError(t, handoffPost(t.Context(), server.Client(), server.URL+"/api/v1/handoff/plan", request, &plan))
	require.EqualValues(t, 3, plan.Attempt)
	require.Equal(t, 1, stub.planned)

	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rootHandoffPlanHandler(&handoffOperatorStub{})(w, r) }))
	defer plain.Close()
	require.Error(t, handoffPost(t.Context(), plain.Client(), plain.URL+"/api/v1/handoff/plan", request, &plan), "not a VR-mode root")
}
