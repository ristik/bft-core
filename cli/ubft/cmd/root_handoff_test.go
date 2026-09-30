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
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archivewiring"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

type handoffOperatorStub struct {
	planCalls, endorsements int
	parent                  []byte
}

func (s *handoffOperatorStub) BuildHandoffPlan(_ *types.RootTrustBaseV1, parent []byte) (abdrc.HandoffApprovalMsg, error) {
	s.planCalls++
	s.parent = append([]byte(nil), parent...)
	return abdrc.HandoffApprovalMsg{Body: []byte{1}}, nil
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
func (s *handoffOperatorStub) BuildAndEndorseHandoff(_ context.Context, next *types.RootTrustBaseV1, parent []byte) (abdrc.HandoffApprovalMsg, error) {
	return s.BuildHandoffPlan(next, parent)
}
func (s *handoffOperatorStub) EndorseHandoff(_ context.Context, _ abdrc.HandoffApprovalMsg) error {
	s.endorsements++
	return nil
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
	plan(remote, request("192.0.2.1:1234", `{"frozenParent":"0x00"}`))
	require.Equal(t, http.StatusForbidden, remote.Code)
	require.Zero(t, stub.planCalls)
	wrongType := httptest.NewRecorder()
	wrongTypeRequest := request("127.0.0.1:1234", `{"frozenParent":"0x0102"}`)
	wrongTypeRequest.Header.Set("Content-Type", "text/plain")
	plan(wrongType, wrongTypeRequest)
	require.Equal(t, http.StatusUnsupportedMediaType, wrongType.Code)
	fromBrowser := httptest.NewRecorder()
	fromBrowserRequest := request("127.0.0.1:1234", `{"frozenParent":"0x0102"}`)
	fromBrowserRequest.Header.Set("Origin", "https://example.com")
	plan(fromBrowser, fromBrowserRequest)
	require.Equal(t, http.StatusUnsupportedMediaType, fromBrowser.Code)
	oversized := httptest.NewRecorder()
	plan(oversized, request("127.0.0.1:1234", string(bytes.Repeat([]byte{'x'}, 1<<20+1))))
	require.Equal(t, http.StatusBadRequest, oversized.Code)
	local := httptest.NewRecorder()
	plan(local, request("127.0.0.1:1234", `{"frozenParent":"0x0102"}`))
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

func TestRootHandoffProposeUsesLatestCertifiedParentAndRejectsStalePin(t *testing.T) {
	latestHash := bytes.Repeat([]byte{0x42}, 32)
	status := archivewiring.OperatorStatus{CertifiedTip: &archivewiring.BlockPin{
		Height: 19, Hash: fmt.Sprintf("0x%x", latestHash), RootEpoch: 3, RootRound: 117,
	}}
	var statusRequests, planRequests int
	statusServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		statusRequests++
		require.Equal(t, http.MethodGet, r.Method)
		require.Equal(t, "/api/v1/operator/status", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(status)
	}))
	defer statusServer.Close()
	operator := &handoffOperatorStub{}
	rootServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		planRequests++
		rootHandoffPlanHandler(operator)(w, r)
	}))
	defer rootServer.Close()

	nextFile := filepath.Join(t.TempDir(), "next-trust-base.json")
	require.NoError(t, os.WriteFile(nextFile, []byte(`{}`), 0o600))
	var stdout, stderr bytes.Buffer
	root := newRootCmd()
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"handoff", "propose", "--next-trust-base", nextFile,
		"--certified-parent-status-url", statusServer.URL, "--root-rpc", rootServer.URL})
	require.NoError(t, root.Execute())
	require.Equal(t, 1, statusRequests)
	require.Equal(t, 1, planRequests)
	require.Equal(t, latestHash, operator.parent)
	require.Contains(t, stderr.String(), "using latest certified EVM parent")
	require.Contains(t, stderr.String(), fmt.Sprintf("height=19 hash=0x%x", latestHash))

	stale := strings.Repeat("11", 32)
	root = newRootCmd()
	root.SetArgs([]string{"handoff", "propose", "--next-trust-base", nextFile,
		"--frozen-parent", stale, "--certified-parent-status-url", statusServer.URL, "--root-rpc", rootServer.URL})
	err := root.Execute()
	require.ErrorIs(t, err, ErrStaleCertifiedParent)
	require.Equal(t, 2, statusRequests, "the explicit pin is compared with a fresh read-only status query")
	require.Equal(t, 1, planRequests, "a stale explicit pin must not be submitted")
}
