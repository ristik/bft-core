package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-go-base/types"
)

type handoffOperatorStub struct {
	mu                               sync.Mutex
	planCalls, intents, endorsements int
	// notPrepared is how many endorsement attempts per validator are refused before the Prepare is "committed".
	notPrepared int
	attempts    int
	proposal    *evmassign.Proposal
	evmCalls    int
	endorseErr  error
}

func (s *handoffOperatorStub) PlanHandoff(_ *types.RootTrustBaseV1, p *evmassign.Proposal) (abdrc.HandoffApprovalMsg, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.planCalls++
	if p != nil {
		s.evmCalls++
		s.proposal = p
	}
	return abdrc.HandoffApprovalMsg{Body: []byte{1}}, nil
}

func (s *handoffOperatorStub) AcceptHandoffIntent(_ abdrc.HandoffApprovalMsg) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.intents++
	return nil
}

func (s *handoffOperatorStub) EndorseHandoff(_ context.Context, _ abdrc.HandoffApprovalMsg) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.endorseErr != nil {
		return s.endorseErr
	}
	s.attempts++
	if s.attempts <= s.notPrepared {
		return consensus.ErrEndorseBeforePrepare
	}
	s.endorsements++
	return nil
}

func TestRootHandoffAbortCLIWaitsForCommittedStatus(t *testing.T) {
	var submits, statuses int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		var target abdrc.HandoffAbortTarget
		require.NoError(t, json.NewDecoder(r.Body).Decode(&target))
		require.EqualValues(t, 5, target.Network)
		switch r.URL.Path {
		case "/api/v1/handoff/abort":
			submits++
			w.WriteHeader(http.StatusAccepted)
			_ = json.NewEncoder(w).Encode(abdrc.HandoffAbortStatus{State: "pending", Target: target})
		case "/api/v1/handoff/abort/status":
			statuses++
			_ = json.NewEncoder(w).Encode(abdrc.HandoffAbortStatus{State: "committed", Target: target,
				RecordID: "0xabort", OrderedRound: 12, CommittedRootID: "0xblock", CommittedRootRound: 14})
		default:
			http.Error(w, fmt.Sprintf("unexpected path %s", r.URL.Path), http.StatusNotFound)
		}
	}))
	defer server.Close()
	var stdout bytes.Buffer
	root := newRootCmd()
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"handoff", "abort", "--network", "5", "--old-epoch", "1",
		"--predecessor-body-id", "0x" + strings.Repeat("00", 32), "--attempt", "0",
		"--next-body-id", "0x" + strings.Repeat("11", 32), "--root-rpc", server.URL, "--timeout", "5s"})
	require.NoError(t, root.Execute())
	require.Equal(t, 1, submits)
	require.GreaterOrEqual(t, statuses, 1)
	require.Contains(t, stdout.String(), "committed Abort record 0xabort ordered at round 12")
	require.Contains(t, stdout.String(), "committed root block 0xblock at round 14")
}

type handoffAbortOperatorStub struct {
	target abdrc.HandoffAbortTarget
	calls  int
	state  string
}

func (s *handoffAbortOperatorStub) SubmitHandoffAbort(_ context.Context, target abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error) {
	s.target = target
	s.calls++
	return abdrc.HandoffAbortStatus{State: "pending", Target: target}, nil
}

func (s *handoffAbortOperatorStub) HandoffAbortStatus(target abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error) {
	s.target = target
	return abdrc.HandoffAbortStatus{State: s.state, Target: target}, nil
}

func TestRootHandoffAbortOperatorHTTPIsLocalAndBounded(t *testing.T) {
	stub := &handoffAbortOperatorStub{state: "pending"}
	abort := rootHandoffAbortHandler(stub)
	status := rootHandoffAbortStatusHandler(stub)
	body := `{"network":5,"oldEpoch":1,"predecessorBodyId":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","attempt":0,"nextBodyId":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="}`
	request := func(body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/handoff/abort", bytes.NewBufferString(body))
		r.RemoteAddr = "127.0.0.1:1234"
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	remote := request(body)
	remote.RemoteAddr = "192.0.2.1:1234"
	remoteResponse := httptest.NewRecorder()
	abort(remoteResponse, remote)
	require.Equal(t, http.StatusForbidden, remoteResponse.Code)
	require.Zero(t, stub.calls)
	wrongType := request(body)
	wrongType.Header.Set("Content-Type", "text/plain")
	wrongTypeResponse := httptest.NewRecorder()
	abort(wrongTypeResponse, wrongType)
	require.Equal(t, http.StatusUnsupportedMediaType, wrongTypeResponse.Code)
	trailing := request(body + ` {}`)
	trailingResponse := httptest.NewRecorder()
	abort(trailingResponse, trailing)
	require.Equal(t, http.StatusBadRequest, trailingResponse.Code)
	oversized := request(strings.Repeat("x", (16<<10)+1))
	oversizedResponse := httptest.NewRecorder()
	abort(oversizedResponse, oversized)
	require.Equal(t, http.StatusBadRequest, oversizedResponse.Code)

	local := request(body)
	response := httptest.NewRecorder()
	abort(response, local)
	require.Equal(t, http.StatusAccepted, response.Code)
	require.Equal(t, 1, stub.calls)
	var submitted abdrc.HandoffAbortStatus
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &submitted))
	require.Equal(t, "pending", submitted.State, "submission is not cancellation finality")
	require.EqualValues(t, 5, stub.target.Network)

	statusRequest := request(body)
	statusResponse := httptest.NewRecorder()
	status(statusResponse, statusRequest)
	require.Equal(t, http.StatusOK, statusResponse.Code)
	stub.state = "committed"
	statusRequest = request(body)
	statusResponse = httptest.NewRecorder()
	status(statusResponse, statusRequest)
	var final abdrc.HandoffAbortStatus
	require.NoError(t, json.Unmarshal(statusResponse.Body.Bytes(), &final))
	require.Equal(t, "committed", final.State)
	require.Equal(t, 1, stub.calls, "status must remain read-only")
}

func TestRootHandoffOperatorHTTPIsLocalAndBounded(t *testing.T) {
	stub := &handoffOperatorStub{}
	plan := rootHandoffPlanHandler(stub)
	request := func(addr, body string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/handoff/plan", bytes.NewBufferString(body))
		r.RemoteAddr = addr
		r.Header.Set("Content-Type", "application/json")
		return r
	}
	remote := httptest.NewRecorder()
	plan(remote, request("192.0.2.1:1234", `{}`))
	require.Equal(t, http.StatusForbidden, remote.Code)
	require.Zero(t, stub.planCalls)
	wrongType := httptest.NewRecorder()
	wrongTypeRequest := request("127.0.0.1:1234", `{}`)
	wrongTypeRequest.Header.Set("Content-Type", "text/plain")
	plan(wrongType, wrongTypeRequest)
	require.Equal(t, http.StatusUnsupportedMediaType, wrongType.Code)
	fromBrowser := httptest.NewRecorder()
	fromBrowserRequest := request("127.0.0.1:1234", `{}`)
	fromBrowserRequest.Header.Set("Origin", "https://example.com")
	plan(fromBrowser, fromBrowserRequest)
	require.Equal(t, http.StatusUnsupportedMediaType, fromBrowser.Code)
	oversized := httptest.NewRecorder()
	plan(oversized, request("127.0.0.1:1234", string(bytes.Repeat([]byte{'x'}, 1<<20+1))))
	require.Equal(t, http.StatusBadRequest, oversized.Code)
	local := httptest.NewRecorder()
	plan(local, request("127.0.0.1:1234", `{}`))
	require.Equal(t, http.StatusOK, local.Code)
	var approved abdrc.HandoffApprovalMsg
	require.NoError(t, json.Unmarshal(local.Body.Bytes(), &approved))
	require.Equal(t, []byte{1}, approved.Body)
	require.Equal(t, 1, stub.planCalls)
	endorse := rootHandoffEndorseHandler(stub)
	wrongEndorse := httptest.NewRequest(http.MethodPost, "/api/v1/handoff/endorse", bytes.NewReader(local.Body.Bytes()))
	wrongEndorse.RemoteAddr = "127.0.0.1:1234"
	wrongEndorseResponse := httptest.NewRecorder()
	endorse(wrongEndorseResponse, wrongEndorse)
	require.Equal(t, http.StatusUnsupportedMediaType, wrongEndorseResponse.Code)
	require.Zero(t, stub.endorsements)
	post := httptest.NewRequest(http.MethodPost, "/api/v1/handoff/endorse", bytes.NewReader(local.Body.Bytes()))
	post.RemoteAddr = "127.0.0.1:1234"
	post.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	endorse(response, post)
	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, 1, stub.endorsements)
}

// The CLI plans once, hands every validator the intent, and then endorses: each validator refuses until the Prepare is committed, so
// the CLI waits for it. The plan names no EVM parent and there is no flag to supply one.
func TestRootHandoffProposePlansThenEndorsesAfterPrepare(t *testing.T) {
	newServer := func(operator *handoffOperatorStub) *httptest.Server {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /api/v1/handoff/plan", rootHandoffPlanHandler(operator))
		mux.HandleFunc("POST /api/v1/handoff/intent", rootHandoffIntentHandler(operator))
		mux.HandleFunc("POST /api/v1/handoff/endorse", rootHandoffEndorseHandler(operator))
		return httptest.NewServer(mux)
	}
	nextFile := filepath.Join(t.TempDir(), "next-trust-base.json")
	require.NoError(t, os.WriteFile(nextFile, []byte(`{"epoch":2}`), 0o600))
	run := func(t *testing.T, args ...string) (string, error) {
		var stdout bytes.Buffer
		root := newRootCmd()
		root.SetOut(&stdout)
		root.SetErr(&bytes.Buffer{})
		root.SetArgs(append([]string{"handoff", "propose", "--next-trust-base", nextFile}, args...))
		err := root.Execute()
		return stdout.String(), err
	}

	t.Run("waits for the Prepare, then endorses at every validator", func(t *testing.T) {
		first, second, third := &handoffOperatorStub{notPrepared: 2}, &handoffOperatorStub{notPrepared: 1}, &handoffOperatorStub{}
		servers := []*httptest.Server{newServer(first), newServer(second), newServer(third)}
		for _, server := range servers {
			defer server.Close()
		}
		out, err := run(t, "--root-rpc", servers[0].URL+","+servers[1].URL+","+servers[2].URL, "--prepare-timeout", "30s")
		require.NoError(t, err)
		require.Contains(t, out, "submitted 3 root endorsements for epoch 2")
		require.Equal(t, 1, first.planCalls, "the first validator builds the plan")
		require.Zero(t, second.planCalls+third.planCalls)
		require.Equal(t, 2, second.intents+third.intents, "every other validator holds the plan as its intent")
		require.Zero(t, first.intents)
		require.Equal(t, 1, first.endorsements)
		require.Equal(t, 1, second.endorsements)
		require.Equal(t, 1, third.endorsements)
		require.Equal(t, 3, first.attempts, "refused twice before the Prepare was committed")
	})
	t.Run("no EVM parent flag exists", func(t *testing.T) {
		_, err := run(t, "--frozen-parent", "0x"+strings.Repeat("11", 32), "--root-rpc", "http://127.0.0.1:1")
		require.ErrorContains(t, err, "unknown flag: --frozen-parent")
	})
	t.Run("a Prepare that never commits times out", func(t *testing.T) {
		stub := &handoffOperatorStub{notPrepared: 1 << 20}
		server := newServer(stub)
		defer server.Close()
		_, err := run(t, "--root-rpc", server.URL, "--prepare-timeout", "1500ms")
		require.ErrorContains(t, err, "only 0/1 validators endorsed")
		require.ErrorContains(t, err, consensus.ErrEndorseBeforePrepare.Error())
	})
	t.Run("any other refusal is final", func(t *testing.T) {
		stub := &handoffOperatorStub{endorseErr: consensus.ErrEndorsedParentMismatch}
		server := newServer(stub)
		defer server.Close()
		_, err := run(t, "--root-rpc", server.URL, "--prepare-timeout", "30s")
		require.ErrorContains(t, err, consensus.ErrEndorsedParentMismatch.Error())
		require.Zero(t, stub.attempts, "no retry")
	})
}
