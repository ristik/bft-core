package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-go-base/types"
)

type handoffOperatorStub struct{ planCalls, endorsements int }

func (s *handoffOperatorStub) BuildHandoffPlan(_ *types.RootTrustBaseV1, _ []byte) (abdrc.HandoffApprovalMsg, error) {
	s.planCalls++
	return abdrc.HandoffApprovalMsg{Body: []byte{1}}, nil
}
func (s *handoffOperatorStub) BuildAndEndorseHandoff(_ context.Context, next *types.RootTrustBaseV1, parent []byte) (abdrc.HandoffApprovalMsg, error) {
	return s.BuildHandoffPlan(next, parent)
}
func (s *handoffOperatorStub) EndorseHandoff(_ context.Context, _ abdrc.HandoffApprovalMsg) error {
	s.endorsements++
	return nil
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
