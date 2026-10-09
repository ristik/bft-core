package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
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

	// a V3 plan without receipts is asked for explicitly (the exact recovery K carries none); the V2 planner is still not asked
	rec = postJSON(h, "127.0.0.1:1", rootHandoffPlanRequest{NextTrustBase: &types.RootTrustBaseV1{}, Q3: true})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, 2, stub.v3Plans, "q3 without receipts: the V3 plan")
	require.Empty(t, stub.v3Receipt)
	require.Equal(t, 1, stub.planCalls)

	// a root that is not running the lane has no V3 planner
	plain := &handoffOperatorStub{}
	rec = postJSON(rootHandoffPlanHandler(plain), "127.0.0.1:1", rootHandoffPlanRequest{NextTrustBase: &types.RootTrustBaseV1{}, Q3Receipts: []byte("receipts")})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	require.Contains(t, rec.Body.String(), "not running the Q3 lane")
	require.Zero(t, plain.planCalls, "a V3 request is never downgraded to a V2 plan")
	rec = postJSON(rootHandoffPlanHandler(plain), "127.0.0.1:1", rootHandoffPlanRequest{NextTrustBase: &types.RootTrustBaseV1{}, Q3: true})
	require.Equal(t, http.StatusUnprocessableEntity, rec.Code)
	require.Zero(t, plain.planCalls, "nor is a receipt-less one")

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

// A Q3 root selects the view-aware request branch right after the runtime is attached and before it serves: without it a weighted EVM
// assignment has no request context and every certification request of the shard is refused. A helper test cannot see the call dropped.
func TestRootNodeRunSelectsTheRequestHistoryAfterInstallingTheActivations(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "root_node.go", nil, 0)
	require.NoError(t, err)
	first := map[string]token.Pos{}
	ast.Inspect(file, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok {
				if _, seen := first[id.Name]; !seen {
					first[id.Name] = call.Pos()
				}
			}
		}
		return true
	})
	for _, name := range []string{"attachRootQ3", "installQ3Epochs", "selectRootQ3RequestHistory"} {
		require.Contains(t, first, name)
	}
	require.Less(t, first["attachRootQ3"], first["installQ3Epochs"])
	require.Less(t, first["installQ3Epochs"], first["selectRootQ3RequestHistory"], "an activation installed at this very start counts")
}

// The request history is selected only once the history holds an activation: a genesis root keeps the legacy dispatch, which is the only
// one that can judge a shard that has not certified yet.
func TestOnlyAnActivatedHistorySelectsTheRequestHistory(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	require.False(t, rootQ3HasActivation(rt), "a genesis history")
	require.NoError(t, rt.Recover(context.Background()))
	require.NoError(t, rt.Activate(context.Background(), p.Bundle()))
	require.True(t, rootQ3HasActivation(rt), "after the activation")
}
