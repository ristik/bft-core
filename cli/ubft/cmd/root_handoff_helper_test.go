package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-go-base/types"
)

// helperRoot is one root's operator API as the real handlers serve it: the V3 planner, the intent and endorsement routes, the assignment context and the
// abort status, behind the same loopback and JSON checks. scripts/h6/prepare-handoff.py is the client under test.
type helperRoot struct {
	mu       sync.Mutex
	receipts []q3format.Receipt
	body     []byte
	statuses []abdrc.HandoffAbortTarget
	v2Plans  int
	intents  int
	endorsed int
}

func (r *helperRoot) PlanHandoff(*types.RootTrustBaseV1, *evmassign.Proposal) (abdrc.HandoffApprovalMsg, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.v2Plans++
	return abdrc.HandoffApprovalMsg{}, consensus.ErrHandoffNeedsV3Plan
}

func (r *helperRoot) PlanHandoffV3(next *types.RootTrustBaseV1, _ *evmassign.Proposal, receipts []byte) (abdrc.HandoffApprovalMsg, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	decoded, err := q3format.DecodeReceipts(receipts) // the canonical set or nothing, as the root takes it
	if err != nil {
		return abdrc.HandoffApprovalMsg{}, err
	}
	r.receipts = decoded
	return abdrc.HandoffApprovalMsg{Body: r.body, Attempt: 4, Receipts: receipts}, nil
}

func (r *helperRoot) AcceptHandoffIntent(abdrc.HandoffApprovalMsg) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.intents++
	return nil
}

func (r *helperRoot) EndorseHandoff(context.Context, abdrc.HandoffApprovalMsg) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.endorsed++
	return nil
}

func (r *helperRoot) EVMAssignmentContext() (consensus.EVMAssignmentContext, error) {
	return consensus.EVMAssignmentContext{Network: 3, Predecessor: make([]byte, 32), Attempt: 4}, nil
}

func (r *helperRoot) SubmitHandoffAbort(context.Context, abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error) {
	return abdrc.HandoffAbortStatus{}, nil
}

func (r *helperRoot) HandoffAbortStatus(target abdrc.HandoffAbortTarget) (abdrc.HandoffAbortStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statuses = append(r.statuses, target)
	return abdrc.HandoffAbortStatus{State: "pending", Target: target}, nil
}

func TestPrepareHandoffHelperDrivesTheRealOperatorRoutesOfAV3Plan(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	body := []byte("canonical-v3-body")
	roots := []*helperRoot{{body: body}, {body: body}, {body: body}, {body: body}}
	var urls []string
	for _, root := range roots {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /api/v1/handoff/plan", rootHandoffPlanHandler(root))
		mux.HandleFunc("POST /api/v1/handoff/intent", rootHandoffIntentHandler(root))
		mux.HandleFunc("POST /api/v1/handoff/endorse", rootHandoffEndorseHandler(root))
		mux.HandleFunc("POST /api/v1/handoff/evm-assignment/context", rootHandoffEVMContextHandler(root))
		mux.HandleFunc("POST /api/v1/handoff/abort/status", rootHandoffAbortStatusHandler(root))
		server := httptest.NewServer(mux)
		defer server.Close()
		urls = append(urls, server.URL)
	}
	dir := t.TempDir()
	names := []string{"root-a", "root-b", "root-c", "root-d"}
	trust := func(epoch uint64) []byte {
		var nodes []map[string]any
		for _, name := range names {
			nodes = append(nodes, map[string]any{"nodeId": name, "stake": 1})
		}
		raw, err := json.Marshal(map[string]any{"networkId": 3, "epoch": epoch, "rootNodes": nodes})
		require.NoError(t, err)
		return raw
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "old.json"), trust(1), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "next.json"), trust(2), 0o600))
	bodyID := sha256.Sum256(body)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "v3-body-id.txt"), []byte(hex.EncodeToString(bodyID[:])+"\n"), 0o600))
	var receipts string
	for _, name := range names {
		path := filepath.Join(dir, "receipt-"+name+".json")
		require.NoError(t, os.WriteFile(path, []byte(`{"nodeId":"`+name+`","signature":"0x`+hex.EncodeToString([]byte(name+"-sig"))+`"}`), 0o600))
		if receipts != "" {
			receipts += ","
		}
		receipts += path
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "..", "scripts", "h6", "prepare-handoff.py"))
	require.NoError(t, err)
	out, err := exec.Command(python, script, "--next-trust-base", filepath.Join(dir, "next.json"), "--old-trust-base", filepath.Join(dir, "old.json"),
		"--receipts", receipts, "--v3-body-id", filepath.Join(dir, "v3-body-id.txt"), "--root-rpc", urls[0]+","+urls[1]+","+urls[2]+","+urls[3],
		"--out", filepath.Join(dir, "evidence")).CombinedOutput() // #nosec G204 -- fixed test arguments
	require.NoError(t, err, string(out))
	require.Contains(t, string(out), "PASS: authenticated target is pending")

	require.Zero(t, roots[0].v2Plans, "a V3 epoch refuses a V2 plan by name: the helper must never ask for one")
	require.Len(t, roots[0].receipts, 4)
	for i, name := range names {
		require.Equal(t, name, roots[0].receipts[i].NodeID)
		require.Equal(t, []byte(name+"-sig"), []byte(roots[0].receipts[i].Signature))
	}
	require.Equal(t, 1, roots[0].endorsed, "one root endorses alone")
	for _, other := range roots[1:] {
		require.Equal(t, 1, other.intents)
		require.Zero(t, other.endorsed)
	}
	// the target the status endpoint decoded (DisallowUnknownFields) is the one the documented Abort takes
	require.NotEmpty(t, roots[0].statuses)
	target := roots[0].statuses[len(roots[0].statuses)-1]
	require.Equal(t, abdrc.HandoffAbortTarget{Network: 3, OldEpoch: 1, PredecessorBodyID: make([]byte, 32), Attempt: 4, NextBodyID: bodyID[:]}, target)
}
