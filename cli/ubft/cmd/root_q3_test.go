package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-go-base/types"
)

// q3OperatorStub is the V2 stub plus the V3 planner and candidate derivation.
type q3OperatorStub struct {
	handoffOperatorStub
	v3Plans   int
	v3Receipt []byte
	candidate consensus.V3Candidate
}

func (s *q3OperatorStub) PlanHandoffV3(_ *types.RootTrustBaseV1, _ *evmassign.Proposal, receipts []byte) (abdrc.HandoffApprovalMsg, error) {
	s.v3Plans++
	s.v3Receipt = receipts
	return abdrc.HandoffApprovalMsg{Body: []byte{3}, Receipts: receipts}, nil
}

func (s *q3OperatorStub) PlanV3Candidate(_ *types.RootTrustBaseV1, _ *evmassign.Proposal) (consensus.V3Candidate, error) {
	return s.candidate, nil
}

func postJSON(h http.HandlerFunc, remote string, body any) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(raw))
	req.RemoteAddr = remote
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestAPlanWithReceiptsIsAV3PlanAndOnlyALaneRootAcceptsIt(t *testing.T) {
	stub := &q3OperatorStub{}
	h := rootHandoffPlanHandler(stub)

	rec := postJSON(h, "127.0.0.1:1", rootHandoffPlanRequest{NextTrustBase: &types.RootTrustBaseV1{}})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, stub.planCalls, "no receipts: the V2 plan")
	require.Zero(t, stub.v3Plans)

	rec = postJSON(h, "127.0.0.1:1", rootHandoffPlanRequest{NextTrustBase: &types.RootTrustBaseV1{}, Q3Receipts: []byte("receipts")})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 1, stub.v3Plans, "receipts: the V3 plan")
	require.Equal(t, []byte("receipts"), stub.v3Receipt)
	require.Equal(t, 1, stub.planCalls, "the V2 planner is not asked")
	var plan abdrc.HandoffApprovalMsg
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &plan))
	require.Equal(t, []byte("receipts"), plan.Receipts, "the plan carries the receipts to the intent and endorse endpoints")

	// a root that is not running the lane has no V3 planner
	plain := &handoffOperatorStub{}
	rec = postJSON(rootHandoffPlanHandler(plain), "127.0.0.1:1", rootHandoffPlanRequest{NextTrustBase: &types.RootTrustBaseV1{}, Q3Receipts: []byte("receipts")})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	require.Contains(t, rec.Body.String(), "not running the Q3 lane")
	require.Zero(t, plain.planCalls, "a V3 request is never downgraded to a V2 plan")

	rec = postJSON(h, "10.0.0.5:1", rootHandoffPlanRequest{NextTrustBase: &types.RootTrustBaseV1{}, Q3Receipts: []byte("receipts")})
	require.Equal(t, http.StatusForbidden, rec.Code, "the operator endpoint is local only")
}

func TestTheCandidateEndpointReturnsWhatTheMembersMustSign(t *testing.T) {
	var c consensus.V3Candidate
	c.Attempt, c.ActivationRound = 2, 40
	c.Candidate[0] = 7
	c.CandidatePreimage = []byte("preimage")
	c.Body = q3format.BodyV3{Network: 5, Epoch: 2}
	stub := &q3OperatorStub{candidate: c}

	rec := postJSON(rootQ3CandidateHandler(stub), "127.0.0.1:1", rootHandoffPlanRequest{NextTrustBase: &types.RootTrustBaseV1{}})
	require.Equal(t, http.StatusOK, rec.Code)
	var got rootQ3CandidateResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	require.EqualValues(t, 2, got.Attempt)
	require.EqualValues(t, 40, got.ActivationRound)
	require.Equal(t, c.Candidate[:], []byte(got.Candidate))
	require.Equal(t, []byte("preimage"), []byte(got.CandidatePreimage))
	require.Equal(t, c.Body.Encode(), []byte(got.Body))

	require.Equal(t, http.StatusForbidden, postJSON(rootQ3CandidateHandler(stub), "10.0.0.5:1", rootHandoffPlanRequest{}).Code)
}
