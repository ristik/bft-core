package cmd

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient"
)

// pos-publish resumes at the first unfinished step: after each step committed, only the later steps are planned.
func TestPlanPosPublishResumesAfterEachStep(t *testing.T) {
	const members = 4
	for name, c := range map[string]struct {
		pops      uint32
		finalized bool
		vrState   uint8
		want      [3]bool
	}{
		"nothing done":               {0, false, 1, [3]bool{true, true, true}},
		"some proofs stored":         {2, false, 1, [3]bool{true, true, true}},
		"all proofs stored":          {members, false, 1, [3]bool{false, true, true}},
		"the candidate is finalized": {members, true, 1, [3]bool{false, false, true}},
		"published in VR":            {members, true, 2, [3]bool{false, false, false}},
		"a later VR state":           {members, true, 6, [3]bool{false, false, false}},
		"acknowledged":               {members, true, 5, [3]bool{false, false, false}},
	} {
		got, err := planPosPublish(members, c.pops, c.finalized, vrclient.OutputView{State: c.vrState, OutputCommit: [32]byte{9}})
		require.NoError(t, err, name)
		require.Equal(t, c.want, got, name)
	}
	// Invalidated and Rejected are refusals with a clear message, whatever the election holds
	// a Closed output without a publication commitment is a reservation that expired: never published, whatever the election holds
	for _, st := range []uint8{5, 6, 7} {
		_, err := planPosPublish(members, members, true, vrclient.OutputView{State: st})
		require.ErrorIs(t, err, ErrValidator)
		require.ErrorContains(t, err, vrOutputState(st))
		require.ErrorContains(t, err, "without a publication commitment")
	}
	for _, st := range []uint8{3, 4} {
		for _, finalized := range []bool{false, true} {
			_, err := planPosPublish(members, members, finalized, vrclient.OutputView{State: st, OutputCommit: [32]byte{9}})
			require.ErrorIs(t, err, ErrValidator)
			require.ErrorContains(t, err, vrOutputState(st))
		}
	}
}

func TestSameDelegation(t *testing.T) {
	a := vrclient.Delegation{RootNodeID: [32]byte{1}, RootKey: []byte{2}, EvmNodeID: [32]byte{3}, EvmKey: []byte{4}, OperatorPayee: [20]byte{5}}
	require.True(t, sameDelegation(a, a))
	b := a
	b.OperatorPayee = [20]byte{6}
	require.False(t, sameDelegation(a, b))
	b = a
	b.EvmKey = []byte{9}
	require.False(t, sameDelegation(a, b))
	require.False(t, sameDelegation(a, vrclient.Delegation{}))
}

func TestRequireVRPublishedNamesTheState(t *testing.T) {
	require.NoError(t, requireVRPublished(vrclient.OutputView{State: 2}))
	require.NoError(t, requireVRPublished(vrclient.OutputView{State: 7, OutputCommit: [32]byte{1}}), "Closed after a publication")
	for st, name := range map[uint8]string{0: "None", 1: "Reserved", 3: "Invalidated", 4: "Rejected", 7: "Closed"} {
		err := requireVRPublished(vrclient.OutputView{State: st})
		require.ErrorIs(t, err, ErrValidator)
		require.ErrorContains(t, err, name)
	}
}

// ---- the command's run against a fake RPC: planning, sending, and the effect check after each mined transaction ----

type fakePosChain struct {
	mu        sync.Mutex
	pops      uint32
	finalized bool
	vrState   uint8
	commit    [32]byte // VR's publication commitment for the result
	// what each transaction does to the state; publishState is the VR output state after VR.publish (Published unless the result was invalidated)
	publishState  uint8
	publishCommit [32]byte
	noProofs      bool // submitAssignmentPoPs mines without storing the proofs
	sent          []string
}

func (f *fakePosChain) Publication(_ context.Context, _ [32]byte) (vrclient.PublicationRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return vrclient.PublicationRecord{PopCount: f.pops, Published: f.finalized}, nil
}

func (f *fakePosChain) Output(_ context.Context, _ [32]byte) (vrclient.OutputView, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return vrclient.OutputView{State: f.vrState, OutputCommit: f.commit}, nil
}

// serve is a JSON-RPC endpoint for the sender: it prices and simulates everything successfully, and applies a mined transaction to the fake state.
func (f *fakePosChain) serve(t *testing.T, members uint32) *rpc.Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		var res any
		switch req.Method {
		case "eth_getBlockByNumber":
			res = map[string]any{"baseFeePerGas": "0x7"}
		case "eth_estimateGas":
			res = "0x5208"
		case "eth_getTransactionCount":
			res = "0x0"
		case "eth_sendRawTransaction":
			var raw hexutil.Bytes
			require.NoError(t, json.Unmarshal(req.Params[0], &raw))
			var tx types.Transaction
			require.NoError(t, tx.UnmarshalBinary(raw))
			f.mu.Lock()
			switch hex.EncodeToString(tx.Data()[:4]) {
			case hex.EncodeToString(vrclient.PosPublishABI.Methods["submitAssignmentPoPs"].ID):
				f.sent = append(f.sent, "submit")
				if !f.noProofs {
					f.pops = members
				}
			case hex.EncodeToString(vrclient.PosPublishABI.Methods["finalizeCandidate"].ID):
				f.sent = append(f.sent, "finalize")
				f.finalized = true
			case hex.EncodeToString(vrclient.PosPublishABI.Methods["publish"].ID):
				f.sent = append(f.sent, "publish")
				f.vrState = f.publishState
				f.commit = f.publishCommit
			}
			f.mu.Unlock()
			res = tx.Hash()
		case "eth_getTransactionReceipt":
			res = map[string]any{"status": "0x1", "blockNumber": "0x1", "gasUsed": "0x1", "logs": []any{}}
		default:
			t.Errorf("unexpected RPC %s", req.Method)
		}
		out, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": res})
		require.NoError(t, err)
		_, _ = w.Write(out)
	}))
	t.Cleanup(srv.Close)
	c, err := rpc.DialHTTP(srv.URL)
	require.NoError(t, err)
	t.Cleanup(c.Close)
	return c
}

func runFakePosPublish(t *testing.T, f *fakePosChain, members int, pops func() ([]vrclient.PoPInput, error)) (string, error) {
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	var out strings.Builder
	err = runPosPublish(context.Background(), &out, posPublishRun{
		Election: common.Address{0xE1}, Registry: common.Address{0x03}, Rid: [32]byte{1},
		Members: make([]vrclient.FrozenMember, members), Chain: f,
		Pops:   func(context.Context) ([]vrclient.PoPInput, error) { return pops() },
		Sender: vrclient.Sender{RPC: f.serve(t, uint32(members)), Key: key, ChainID: big.NewInt(1), Poll: time.Millisecond}})
	return out.String(), err
}

func TestPosPublishCommandRequiresEachEffect(t *testing.T) {
	noPops := func() ([]vrclient.PoPInput, error) { return []vrclient.PoPInput{{Id: 1}}, nil }
	t.Run("all steps, every effect present", func(t *testing.T) {
		f := &fakePosChain{vrState: 1, publishState: 2}
		_, err := runFakePosPublish(t, f, 4, noPops)
		require.NoError(t, err)
		require.Equal(t, []string{"submit", "finalize", "publish"}, f.sent, "the remaining steps survive each check")
	})
	t.Run("the result is invalidated before VR.publish executes", func(t *testing.T) {
		// planning sees Reserved and a finalized candidate; the successful receipt leaves the output Invalidated
		f := &fakePosChain{pops: 4, finalized: true, vrState: 1, publishState: 3}
		_, err := runFakePosPublish(t, f, 4, noPops)
		require.ErrorIs(t, err, ErrValidator)
		require.ErrorContains(t, err, "Invalidated")
		require.Equal(t, []string{"publish"}, f.sent)
	})
	t.Run("the reservation expired before publication and the output ends Closed", func(t *testing.T) {
		// Closed without a publication commitment is not a publication
		f := &fakePosChain{pops: 4, finalized: true, vrState: 1, publishState: 7}
		_, err := runFakePosPublish(t, f, 4, noPops)
		require.ErrorIs(t, err, ErrValidator)
		require.ErrorContains(t, err, "Closed")
		require.ErrorContains(t, err, "without a publication commitment")
	})
	t.Run("Closed after a real publication is accepted", func(t *testing.T) {
		f := &fakePosChain{pops: 4, finalized: true, vrState: 1, publishState: 7, publishCommit: [32]byte{5}}
		_, err := runFakePosPublish(t, f, 4, noPops)
		require.NoError(t, err)
	})
	t.Run("the proofs are not stored after the receipt", func(t *testing.T) {
		f := &fakePosChain{vrState: 1, publishState: 2, noProofs: true}
		_, err := runFakePosPublish(t, f, 4, noPops)
		require.ErrorContains(t, err, "stores 0 of 4")
		require.Equal(t, []string{"submit"}, f.sent, "nothing is sent after a failed effect")
	})
	t.Run("a resumed run needs no holders", func(t *testing.T) {
		f := &fakePosChain{pops: 4, finalized: true, vrState: 1, publishState: 2}
		_, err := runFakePosPublish(t, f, 4, func() ([]vrclient.PoPInput, error) { t.Fatal("holders read"); return nil, nil })
		require.NoError(t, err)
		require.Equal(t, []string{"publish"}, f.sent)
	})
	t.Run("an already invalidated result is refused at planning", func(t *testing.T) {
		f := &fakePosChain{pops: 4, finalized: true, vrState: 3}
		_, err := runFakePosPublish(t, f, 4, noPops)
		require.ErrorContains(t, err, "Invalidated")
		require.Empty(t, f.sent)
	})
}

func TestPublishReadyResultNeedsEveryMemberProofAndCanBeRetried(t *testing.T) {
	f := &fakePosChain{pops: 4, vrState: 1, publishState: 2}
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	r := posPublishRun{
		Election: common.Address{0xe1}, Registry: common.Address{3}, Rid: [32]byte{1},
		Members: make([]vrclient.FrozenMember, 5), Chain: f,
		Sender: vrclient.Sender{RPC: f.serve(t, 5), Key: key, ChainID: big.NewInt(1), Poll: time.Millisecond},
	}
	var out strings.Builder
	require.NoError(t, publishReadyResult(context.Background(), &out, r))
	require.Empty(t, f.sent, "a partial proof set never leads to a send")
	f.pops = 5
	require.NoError(t, publishReadyResult(context.Background(), &out, r))
	require.Equal(t, []string{"finalize", "publish"}, f.sent)
	require.NoError(t, publishReadyResult(context.Background(), &out, r))
	require.Equal(t, []string{"finalize", "publish"}, f.sent, "retry sends nothing after agreed publication")
}
