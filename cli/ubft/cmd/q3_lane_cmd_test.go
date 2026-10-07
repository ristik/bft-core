package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	testobserve "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/q3ready"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-go-base/types"
	basehex "github.com/unicitynetwork/bft-go-base/types/hex"
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
	rootStatus       func(*q3StagedResponse) // edits what the root reports as staged
	genesis          string
	code             string
	rootRefuses      bool
	rootBody         [32]byte
	rootAttempt      uint64
	rootConfig       [32]byte
}

type stageFunc func(body []byte, candidate [32]byte, attempt uint64) error

func (f stageFunc) StageV3Candidate(body []byte, candidate [32]byte, attempt uint64) error {
	return f(body, candidate, attempt)
}

// newShardStagingServer is a shard node's staging endpoints for the given chain; reportAs edits the staged record the node reports.
func newShardStagingServer(cfg q3format.ProtocolConfig, reportAs func(*q3StagedResponse)) *httptest.Server {
	st := &shardQ3Staging{cfg: func() (q3format.ProtocolConfig, error) { return cfg, nil }}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/q3/status", q3Endpoint(func(context.Context, json.RawMessage) (any, error) {
		out, err := st.status()
		if err == nil && out.Staged != nil && reportAs != nil {
			reportAs(out.Staged)
		}
		return out, err
	}))
	mux.HandleFunc("POST /api/v1/q3/stage", q3Endpoint(func(_ context.Context, raw json.RawMessage) (any, error) {
		var req shardQ3StageRequest
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		return struct{}{}, st.Stage(req)
	}))
	return httptest.NewServer(mux)
}

func newLaneServices(t *testing.T, body q3format.BodyV3, staged [32]byte) *laneServices {
	t.Helper()
	s := &laneServices{rootStaged: &staged, genesis: "0x" + hex.EncodeToString(bytes.Repeat([]byte{0x52}, 32)), code: "0x6001600155"}
	rootMux := http.NewServeMux()
	rootMux.HandleFunc("POST /api/v1/handoff/q3-stage", rootQ3StageHandler(stageFunc(func(b []byte, digest [32]byte, attempt uint64) error {
		if s.rootRefuses {
			return errors.New("the candidate is not the next epoch of this chain")
		}
		decoded, err := q3format.DecodeBody(b)
		if err != nil {
			return err
		}
		*s.rootStaged = digest
		s.rootBody, s.rootAttempt, s.rootConfig = decoded.Identity(), attempt, decoded.Config.Identity()
		return nil
	})))
	rootMux.HandleFunc("POST /api/v1/q3/status", q3Endpoint(func(context.Context, json.RawMessage) (any, error) {
		out := q3StatusResponse{Network: body.Network, Genesis: hex.EncodeToString(body.Config.Genesis[:])}
		if *s.rootStaged != ([32]byte{}) {
			attempt := s.rootAttempt
			out.Staged = &q3StagedResponse{CandidateDigest: hex.EncodeToString(s.rootStaged[:]), BodyID: hex.EncodeToString(s.rootBody[:]),
				Attempt: &attempt, Config: hex.EncodeToString(s.rootConfig[:])}
			if s.rootStatus != nil {
				s.rootStatus(out.Staged)
			}
		}
		return out, nil
	}))
	s.root = httptest.NewServer(rootMux)
	s.shard = newShardStagingServer(body.Config, nil)
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
	current := candidate
	refused := func(name string, cause error, mutate func(*laneServices), genesis, code string) {
		t.Helper()
		s := newLaneServices(t, body, cand.Candidate)
		mutate(s)
		out := filepath.Join(dir, "refused-"+name+".json")
		err := runReadiness(t, ents[1], current, s, genesis, code, out)
		require.ErrorIs(t, err, cause, name)
		_, statErr := os.Stat(out)
		require.True(t, os.IsNotExist(statErr), "%s: no receipt is written", name)
	}
	refused("the root refuses the candidate", ErrQ3StageRefused, func(s *laneServices) { s.rootRefuses = true }, genesisPin, codePin)
	refused("execution genesis is not the pinned one", q3ready.ErrExecutionIdentity, func(s *laneServices) {
		s.genesis = "0x" + hex.EncodeToString(bytes.Repeat([]byte{0x53}, 32))
	}, genesisPin, codePin)
	refused("registry code is not the pinned one", q3ready.ErrExecutionIdentity, func(s *laneServices) { s.code = "0x6002" }, genesisPin, codePin)
	refused("the pin is the wrong value", q3ready.ErrExecutionIdentity, func(*laneServices) {}, "0x"+hex.EncodeToString(bytes.Repeat([]byte{0x54}, 32)), codePin)
	refused("the shard node refuses another chain's candidate", ErrQ3StageRefused, func(s *laneServices) {
		other := body
		other.Config.Genesis[0] ^= 1
		s.shard.Close()
		s.shard = newShardStagingServer(other.Config, nil)
	}, genesisPin, codePin)
	// the staged context beyond the digest: each service's report differs from the control in exactly one of body, attempt and configuration
	// a field the service did not report at all is not a value. Attempt zero is a valid attempt, so the absence of the field is tested on a
	// candidate whose attempt IS zero (a decoded absence would otherwise equal it), with a positive control first.
	zero := cand
	zero.Attempt = 0
	rawZero, err := zero.encode()
	require.NoError(t, err)
	current = filepath.Join(dir, "candidate-zero.cbor")
	require.NoError(t, os.WriteFile(current, rawZero, 0o600))
	require.NoError(t, runReadiness(t, ents[1], current, newLaneServices(t, body, cand.Candidate), genesisPin, codePin, filepath.Join(dir, "zero-control.json")), "attempt zero is a valid attempt")
	for name, drop := range map[string]func(*q3StagedResponse){
		"attempt": func(r *q3StagedResponse) { r.Attempt = nil },
		"body":    func(r *q3StagedResponse) { r.BodyID = "" },
		"config":  func(r *q3StagedResponse) { r.Config = "" },
	} {
		drop := drop
		refused("the root omits the staged "+name, q3ready.ErrComponent, func(s *laneServices) { s.rootStatus = drop }, genesisPin, codePin)
		refused("the shard node omits the staged "+name, q3ready.ErrComponent, func(s *laneServices) {
			s.shard.Close()
			s.shard = newShardStagingServer(body.Config, drop)
		}, genesisPin, codePin)
	}
	current = candidate
	for name, edit := range map[string]func(*q3StagedResponse){
		"body": func(r *q3StagedResponse) {
			raw, _ := hex.DecodeString(r.BodyID)
			raw[0] ^= 1
			r.BodyID = hex.EncodeToString(raw)
		},
		"attempt": func(r *q3StagedResponse) { *r.Attempt++ },
		"config": func(r *q3StagedResponse) {
			raw, _ := hex.DecodeString(r.Config)
			raw[0] ^= 1
			r.Config = hex.EncodeToString(raw)
		},
	} {
		edit := edit
		refused("the root reports another staged "+name, q3ready.ErrComponent, func(s *laneServices) { s.rootStatus = edit }, genesisPin, codePin)
		refused("the shard node reports another staged "+name, q3ready.ErrComponent, func(s *laneServices) {
			s.shard.Close()
			s.shard = newShardStagingServer(body.Config, edit)
		}, genesisPin, codePin)
	}
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

func TestTheEvidenceCommandsWriteWhatTheRootServes(t *testing.T) {
	ctx := context.Background()
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	require.NoError(t, rt.Recover(ctx))
	require.NoError(t, rt.Activate(ctx, p.Bundle()))

	signed := uint64(7)
	api := rootQ3API{Rt: rt, Bundle: func(context.Context, uint64) (q3active.Bundle, error) { return p.Bundle(), nil },
		State: func() (*abdrc.StateMsg, error) {
			return &abdrc.StateMsg{CommittedHead: &abdrc.CommittedBlock{CommitQc: &rctypes.QuorumCert{Scheme: 2,
				VoteInfo: &rctypes.RoundInfo{Epoch: 2, RoundNumber: 3}, Signatures: map[string]basehex.Bytes{"heavy": {1}}}}}, nil
		},
		Trust: func(uint64) (*types.RootTrustBaseV1, error) {
			return &types.RootTrustBaseV1{Epoch: 2, QuorumThreshold: signed, RootNodes: []*types.NodeInfo{{NodeID: "heavy", Stake: 6}}}, nil
		}}
	mux := http.NewServeMux()
	api.register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	dir := t.TempDir()

	_, err := runCLI(t, "root", "handoff", "q3-activation", "--root-rpc", srv.URL, "--epoch", "2", "--out", filepath.Join(dir, "activation.json"))
	require.NoError(t, err)
	var rec q3active.ActivationRecord
	raw, err := os.ReadFile(filepath.Join(dir, "activation.json"))
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &rec))
	require.EqualValues(t, 2, rec.SigningScheme)

	_, err = runCLI(t, "q3", "history", "--root-rpc", srv.URL, "--out", filepath.Join(dir, "history.txt"))
	require.NoError(t, err)
	raw, err = os.ReadFile(filepath.Join(dir, "history.txt"))
	require.NoError(t, err)
	require.Len(t, strings.Split(strings.TrimSpace(string(raw)), "\n"), 2, "one line per epoch")

	_, err = runCLI(t, "q3", "proof-envelope", "--root-rpc", srv.URL, "--epoch", "2", "--out", filepath.Join(dir, "envelope.cbor"))
	require.NoError(t, err)
	raw, err = os.ReadFile(filepath.Join(dir, "envelope.cbor"))
	require.NoError(t, err)
	_, _, err = q3active.DecodeBundle(raw)
	require.NoError(t, err)

	// the committed certificate's signed weight 6 is below the threshold 7: no evidence file is written
	signed = 7
	_, err = runCLI(t, "q3", "signers", "--root-rpc", srv.URL, "--out", filepath.Join(dir, "signers.json"))
	require.ErrorIs(t, err, ErrQ3SignerQuorum)
	_, statErr := os.Stat(filepath.Join(dir, "signers.json"))
	require.True(t, os.IsNotExist(statErr))
	signed = 6
	_, err = runCLI(t, "q3", "signers", "--root-rpc", srv.URL, "--out", filepath.Join(dir, "signers.json"))
	require.NoError(t, err)
	raw, err = os.ReadFile(filepath.Join(dir, "signers.json"))
	require.NoError(t, err)
	require.Contains(t, string(raw), `"weight": 6`)
}

// The shard node's own refusals to stage, each with its sentinel and nothing staged.
func TestTheShardNodeRefusesToStageWhatIsNotACandidateOfItsChain(t *testing.T) {
	_, body, cand := laneCommittee(t)
	st := &shardQ3Staging{cfg: func() (q3format.ProtocolConfig, error) { return body.Config, nil }}
	good := shardQ3StageRequest{Body: cand.Body, Candidate: cand.Candidate[:], Attempt: 3}

	short := good
	short.Candidate = []byte{1}
	require.ErrorIs(t, st.Stage(short), ErrQ3StageDigest)
	garbled := good
	garbled.Body = []byte("not a body")
	require.ErrorIs(t, st.Stage(garbled), ErrQ3StageBody)
	other := body
	other.Config.Genesis[0] ^= 1
	foreign := good
	foreign.Body = other.Encode()
	require.ErrorIs(t, st.Stage(foreign), ErrQ3StageChain)
	status, err := st.status()
	require.NoError(t, err)
	require.Nil(t, status.Staged, "a refused candidate is not staged")

	require.NoError(t, st.Stage(good))
	status, err = st.status()
	require.NoError(t, err)
	require.EqualValues(t, 3, status.Staged.Attempt)
	require.Equal(t, hex.EncodeToString(cand.Candidate[:]), status.Staged.CandidateDigest)
}
