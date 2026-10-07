package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	testobserve "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/q3ready"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/util"
)

type laneEntity struct {
	home string
	info *types.NodeInfo
}

// laneCommittee generates four real root identities (keys.json and node-info.json) and the V3 body of their weighted committee.
func laneCommittee(t *testing.T) ([]laneEntity, q3format.BodyV3, q3CandidateFile) {
	t.Helper()
	ctx := context.Background()
	logF := testobserve.NewFactory(t)
	var ents []laneEntity
	var members evmroot.WeightSet
	for i, w := range []uint64{6, 1, 1, 1} {
		home := t.TempDir()
		cmd := New(logF)
		cmd.baseCmd.SetArgs([]string{"root-node", "init", "--home", home, "--generate"})
		require.NoError(t, cmd.Execute(ctx))
		info, err := util.ReadJsonFile(filepath.Join(home, nodeInfoFileName), &types.NodeInfo{})
		require.NoError(t, err)
		ents = append(ents, laneEntity{home: home, info: info})
		members = append(members, evmroot.Member{StakingID: info.NodeID, NodeID: info.NodeID, ConsensusKey: info.SigKey, Weight: w})
		_ = i
	}
	genesis := sha256.Sum256([]byte("lane genesis"))
	body := q3format.BodyV3{Network: 5, Epoch: 2, EarliestActivation: 20, Members: members, RootThreshold: 7,
		StateSummary: bytes.Repeat([]byte{1}, 32), ChangeRecordHash: bytes.Repeat([]byte{2}, 32), PredecessorHash: bytes.Repeat([]byte{3}, 32),
		Config: q3format.Q3Config(5, genesis)}
	require.NoError(t, body.Validate())
	cand := q3CandidateFile{Body: body.Encode(), Attempt: 1, ActivationRound: 40}
	cand.Candidate = sha256.Sum256([]byte("candidate"))
	return ents, body, cand
}

func TestTheCandidateFileIsCanonicalAndRefusesEachMalformation(t *testing.T) {
	_, body, cand := laneCommittee(t)
	raw, err := cand.encode()
	require.NoError(t, err)
	back, err := decodeQ3Candidate(raw)
	require.NoError(t, err)
	require.Equal(t, cand, back)
	_, ctx, err := back.context()
	require.NoError(t, err)
	require.Equal(t, q3format.ContextFor(body, cand.Attempt, cand.Candidate), ctx)

	with := cand
	with.Preimage = []byte("preimage")
	raw2, err := with.encode()
	require.NoError(t, err)
	back, err = decodeQ3Candidate(raw2)
	require.NoError(t, err)
	require.Equal(t, []byte("preimage"), back.Preimage)

	for name, bad := range map[string][]byte{
		"empty":         nil,
		"trailing byte": append(append([]byte(nil), raw...), 0),
		"truncated":     raw[:len(raw)-1],
		"another type":  mustCBOR(t, []any{"OTHER", uint64(1), cand.Body, cand.Candidate[:], nil, uint64(1), uint64(1)}),
		"short digest":  mustCBOR(t, []any{q3CandidateDomain, uint64(1), cand.Body, []byte{1}, nil, uint64(1), uint64(1)}),
		"version 2":     mustCBOR(t, []any{q3CandidateDomain, uint64(2), cand.Body, cand.Candidate[:], nil, uint64(1), uint64(1)}),
	} {
		_, err := decodeQ3Candidate(bad)
		require.Error(t, err, name)
	}
}

func mustCBOR(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := types.Cbor.Marshal(v)
	require.NoError(t, err)
	return raw
}

func TestACandidateDirectoryHoldsTheFilesTheLaneReads(t *testing.T) {
	_, body, cand := laneCommittee(t)
	dir := filepath.Join(t.TempDir(), "candidate.d")
	require.NoError(t, writeQ3CandidateDir(dir, rootQ3CandidateResponse{Body: cand.Body, Candidate: cand.Candidate[:], Attempt: 1, ActivationRound: 40}))

	raw, err := os.ReadFile(filepath.Join(dir, "candidate.cbor"))
	require.NoError(t, err)
	back, err := decodeQ3Candidate(raw)
	require.NoError(t, err)
	require.Equal(t, cand, back)

	var cfg map[string]any
	data, err := os.ReadFile(filepath.Join(dir, "config.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &cfg))
	require.EqualValues(t, 2, cfg["signingScheme"])
	require.EqualValues(t, 5, cfg["network"])

	id, err := os.ReadFile(filepath.Join(dir, "v3-body-id.txt"))
	require.NoError(t, err)
	want := body.Identity()
	require.Equal(t, hex.EncodeToString(want[:])+"\n", string(id))

	var weights []struct {
		NodeID string `json:"nodeId"`
		Weight uint64 `json:"weight"`
	}
	data, err = os.ReadFile(filepath.Join(dir, "root-weights.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &weights))
	var total uint64
	for _, w := range weights {
		total += w.Weight
	}
	require.EqualValues(t, 9, total, "W=9")
	data, err = os.ReadFile(filepath.Join(dir, "evm-weights.json"))
	require.NoError(t, err)
	require.JSONEq(t, "null", string(data), "a root-only candidate has no EVM weights")

	require.Error(t, writeQ3CandidateDir(filepath.Join(t.TempDir(), "x"), rootQ3CandidateResponse{Body: []byte("not a body"), Candidate: cand.Candidate[:]}))
	require.Error(t, writeQ3CandidateDir(filepath.Join(t.TempDir(), "y"), rootQ3CandidateResponse{Body: cand.Body, Candidate: []byte{1}}))
}

// laneServices stands up one entity's three services as local servers.
type laneServices struct {
	root, shard, eth *httptest.Server
	rootStaged       *[32]byte
	genesis          string
	code             string
}

func newLaneServices(t *testing.T, body q3format.BodyV3, staged [32]byte) *laneServices {
	t.Helper()
	s := &laneServices{rootStaged: &staged, genesis: "0x" + hex.EncodeToString(bytes.Repeat([]byte{0x52}, 32)), code: "0x6001600155"}
	rootMux := http.NewServeMux()
	rootMux.HandleFunc("POST /api/v1/q3/status", q3Endpoint(func(context.Context, json.RawMessage) (any, error) {
		out := q3StatusResponse{Network: body.Network, Genesis: hex.EncodeToString(body.Config.Genesis[:])}
		if *s.rootStaged != ([32]byte{}) {
			out.Staged = &q3StagedResponse{CandidateDigest: hex.EncodeToString(s.rootStaged[:])}
		}
		return out, nil
	}))
	s.root = httptest.NewServer(rootMux)
	shardMux := http.NewServeMux()
	(&shardQ3Staging{cfg: func() (q3format.ProtocolConfig, error) { return body.Config, nil }}).register(shardMux)
	s.shard = httptest.NewServer(shardMux)
	s.eth = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct{ Method string }
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "eth_getBlockByNumber":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"hash":"` + s.genesis + `"}}`))
		case "eth_getCode":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":"` + s.code + `"}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"message":"unsupported"}}`))
		}
	}))
	t.Cleanup(func() { s.root.Close(); s.shard.Close(); s.eth.Close() })
	return s
}

func runReadiness(t *testing.T, ent laneEntity, candidate string, s *laneServices, genesisPin, codePin, out string) error {
	t.Helper()
	cmd := New(testobserve.NewFactory(t))
	cmd.baseCmd.SetArgs([]string{"root", "handoff", "q3-readiness", "--candidate", candidate, "--key-conf", filepath.Join(ent.home, "keys.json"),
		"--root-rpc", s.root.URL, "--shard-rpc", s.shard.URL, "--eth-url", s.eth.URL,
		"--execution-genesis-hash", genesisPin, "--execution-code-hash", codePin, "--out", out})
	return cmd.Execute(context.Background())
}

func TestEveryMembersReadinessReceiptVerifiesAndEachRefusalWritesNoReceipt(t *testing.T) {
	ents, body, cand := laneCommittee(t)
	dir := t.TempDir()
	candidate := filepath.Join(dir, "candidate.cbor")
	raw, err := cand.encode()
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(candidate, raw, 0o600))
	codeRaw, _ := hex.DecodeString("6001600155")
	codeSum := sha256.Sum256(codeRaw)
	genesisPin := "0x" + hex.EncodeToString(bytes.Repeat([]byte{0x52}, 32))
	codePin := "0x" + hex.EncodeToString(codeSum[:])

	// the control: all four entities attest, and the receipts are exactly the set the V3 plan requires
	var receipts []q3format.Receipt
	var files []string
	for i, ent := range ents {
		s := newLaneServices(t, body, cand.Candidate)
		out := filepath.Join(dir, "receipt-"+string(rune('1'+i))+".json")
		require.NoError(t, runReadiness(t, ent, candidate, s, genesisPin, codePin, out), "entity %d", i+1)
		files = append(files, out)
	}
	set, err := readQ3Receipts(files)
	require.NoError(t, err)
	receipts, err = q3format.DecodeReceipts(set)
	require.NoError(t, err)
	require.NoError(t, q3format.VerifyReceipts(body, q3format.ContextFor(body, cand.Attempt, cand.Candidate), receipts))

	// each refusal differs from the control in one thing, and writes no receipt
	refused := func(name string, cause error, mutate func(*laneServices), genesis, code string) {
		t.Helper()
		s := newLaneServices(t, body, cand.Candidate)
		mutate(s)
		out := filepath.Join(dir, "refused-"+name+".json")
		err := runReadiness(t, ents[1], candidate, s, genesis, code, out)
		if cause != nil {
			require.ErrorIs(t, err, cause, name)
		} else {
			require.ErrorContains(t, err, "another network, genesis or protocol tuple", name)
		}
		_, statErr := os.Stat(out)
		require.True(t, os.IsNotExist(statErr), "%s: no receipt is written", name)
	}
	refused("root has nothing staged", q3ready.ErrNotReady, func(s *laneServices) { *s.rootStaged = [32]byte{} }, genesisPin, codePin)
	refused("root staged another candidate", q3ready.ErrComponent, func(s *laneServices) { s.rootStaged[0] ^= 1 }, genesisPin, codePin)
	refused("execution genesis is not the pinned one", q3ready.ErrExecutionIdentity, func(s *laneServices) {
		s.genesis = "0x" + hex.EncodeToString(bytes.Repeat([]byte{0x53}, 32))
	}, genesisPin, codePin)
	refused("registry code is not the pinned one", q3ready.ErrExecutionIdentity, func(s *laneServices) { s.code = "0x6002" }, genesisPin, codePin)
	refused("the pin is the wrong value", q3ready.ErrExecutionIdentity, func(*laneServices) {}, "0x"+hex.EncodeToString(bytes.Repeat([]byte{0x54}, 32)), codePin)
	refused("the shard node refuses another chain's candidate", nil, func(s *laneServices) {
		other := body
		other.Config.Genesis[0] ^= 1
		s.shard.Close()
		mux := http.NewServeMux()
		(&shardQ3Staging{cfg: func() (q3format.ProtocolConfig, error) { return other.Config, nil }}).register(mux)
		s.shard = httptest.NewServer(mux)
	}, genesisPin, codePin)
}

func TestAPlanSubmittedWithReceiptsCarriesThemAsOneCanonicalSet(t *testing.T) {
	ents, body, cand := laneCommittee(t)
	ctx := q3format.ContextFor(body, cand.Attempt, cand.Candidate)
	dir := t.TempDir()
	var files []string
	for i, m := range body.Members {
		var keyed KeyConf
		raw, err := os.ReadFile(filepath.Join(ents[i].home, "keys.json"))
		require.NoError(t, err)
		require.NoError(t, json.Unmarshal(raw, &keyed))
		signer, err := keyed.Signer()
		require.NoError(t, err)
		r, err := q3format.SignReceipt(ctx, m.NodeID, signer)
		require.NoError(t, err)
		f := filepath.Join(dir, "r"+string(rune('0'+i))+".json")
		require.NoError(t, writeJSONFile(f, q3Receipt{NodeID: r.NodeID, Signature: r.Signature}))
		files = append(files, f)
	}
	set, err := readQ3Receipts(files)
	require.NoError(t, err)
	rs, err := q3format.DecodeReceipts(set)
	require.NoError(t, err)
	require.NoError(t, q3format.VerifyReceipts(body, ctx, rs))

	_, err = readQ3Receipts(append(files, files[0]))
	require.ErrorIs(t, err, q3format.ErrReceiptDuplicate, "one receipt twice")
	_, err = readQ3Receipts([]string{filepath.Join(dir, "missing.json")})
	require.Error(t, err)
	bad := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(bad, []byte("{"), 0o600))
	_, err = readQ3Receipts([]string{bad})
	require.Error(t, err)
}
