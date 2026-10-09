package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/q3ready"
	"github.com/unicitynetwork/bft-go-base/types"
	basehex "github.com/unicitynetwork/bft-go-base/types/hex"
)

// The operator commands of the Q3 acceptance lane. They talk to the validator's own processes over their local operator endpoints and
// to nothing else: a candidate is derived by the root that will plan it, readiness is attested by the entity's own components, and the
// evidence is read back from the processes that hold it.

const q3CandidateDomain = "UNICITY_Q3_CANDIDATE"

// q3CandidateFile is the candidate every successor member declares itself ready for: the V3 body, the candidate digest it binds, the
// coupled assignment's preimage (empty for a root-only change), and the attempt and activation round the plan is for.
type q3CandidateFile struct {
	Body            []byte
	Candidate       [32]byte
	Preimage        []byte
	Attempt         uint64
	ActivationRound uint64
}

func (c q3CandidateFile) encode() ([]byte, error) {
	var preimage any
	if len(c.Preimage) != 0 {
		preimage = c.Preimage
	}
	return types.Cbor.Marshal([]any{q3CandidateDomain, uint64(1), c.Body, c.Candidate[:], preimage, c.Attempt, c.ActivationRound})
}

func decodeQ3Candidate(raw []byte) (q3CandidateFile, error) {
	var out q3CandidateFile
	var v []any
	if err := types.Cbor.Unmarshal(raw, &v); err != nil || len(v) != 7 {
		return out, errors.New("not a Q3 candidate file")
	}
	if domain, _ := v[0].(string); domain != q3CandidateDomain {
		return out, errors.New("not a Q3 candidate file: domain")
	}
	if version, _ := v[1].(uint64); version != 1 {
		return out, errors.New("not a Q3 candidate file: version")
	}
	body, bodyOK := v[2].([]byte)
	digest, digestOK := v[3].([]byte)
	attempt, attemptOK := v[5].(uint64)
	activation, activationOK := v[6].(uint64)
	if !bodyOK || !digestOK || len(digest) != 32 || !attemptOK || !activationOK {
		return out, errors.New("not a Q3 candidate file: fields")
	}
	out.Body, out.Attempt, out.ActivationRound = body, attempt, activation
	copy(out.Candidate[:], digest)
	switch p := v[4].(type) {
	case nil:
	case []byte:
		out.Preimage = p
	default:
		return out, errors.New("not a Q3 candidate file: preimage")
	}
	if again, err := out.encode(); err != nil || !bytes.Equal(again, raw) {
		return q3CandidateFile{}, errors.New("not a Q3 candidate file: not canonical")
	}
	return out, nil
}

// context is the readiness context of this candidate: the body it binds, the attempt and the candidate digest.
func (c q3CandidateFile) context() (q3format.BodyV3, q3format.ReceiptContext, error) {
	body, err := q3format.DecodeBody(c.Body)
	if err != nil {
		return q3format.BodyV3{}, q3format.ReceiptContext{}, err
	}
	return body, q3format.ContextFor(body, c.Attempt, c.Candidate), nil
}

// q3Receipt is a readiness receipt as a file.
type q3Receipt struct {
	NodeID    string        `json:"nodeId"`
	Signature basehex.Bytes `json:"signature"`
}

func readQ3Receipts(paths []string) ([]byte, error) {
	var rs []q3format.Receipt
	for _, p := range paths {
		raw, err := os.ReadFile(p) // #nosec G304 -- operator supplied local file
		if err != nil {
			return nil, err
		}
		var r q3Receipt
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("receipt %q: %w", p, err)
		}
		rs = append(rs, q3format.Receipt{NodeID: r.NodeID, Signature: r.Signature})
	}
	return q3format.EncodeReceipts(rs)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// firstPost sends the request to each endpoint in order and returns the first answer.
func firstPost(ctx context.Context, endpoints []string, path string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 15 * time.Second}
	var errs []error
	for _, e := range endpoints {
		err := handoffPost(ctx, client, strings.TrimRight(e, "/")+path, body, out)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func writeJSONFile(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// ---- q3-candidate ------------------------------------------------------------------------------------------------------------------------

var (
	// ErrQ3StageRefused is returned when the entity's root or shard service refuses the candidate it is asked to stage.
	ErrQ3StageRefused = errors.New("a service refused to stage the candidate")
	// ErrQ3SignerQuorum is returned when the committed certificate the root serves does not carry the threshold weight.
	ErrQ3SignerQuorum = errors.New("the committed certificate does not reach the threshold weight")
)

func newQ3CandidateCmd() *cobra.Command {
	var nextFile, nextEVM, rootRPCs, outDir string
	cmd := &cobra.Command{Use: "q3-candidate", Short: "Derive the V3 candidate of a coupled handoff for the members to declare readiness for",
		Long: "Asks one root for the V3 body (the next committee with its exact weights) and candidate of the handoff it would plan, and writes\n" +
			"candidate.cbor (what every successor member attests readiness for), config.json (the protocol tuple), v3-body-id.txt and the\n" +
			"root and EVM weights. The root also stages the candidate: it is what its readiness report will name. Nothing is planned or ordered.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := os.ReadFile(nextFile) // #nosec G304 -- operator supplied local file
			if err != nil {
				return err
			}
			var next types.RootTrustBaseV1
			if err := json.Unmarshal(raw, &next); err != nil {
				return err
			}
			request := rootHandoffPlanRequest{NextTrustBase: &next}
			if nextEVM != "" {
				if request.EVMAssignment, err = readEVMAssignment(nextEVM); err != nil {
					return err
				}
				if err := checkCoupledProposal(&next, request.EVMAssignment); err != nil {
					return err
				}
			}
			endpoints := splitList(rootRPCs)
			if len(endpoints) == 0 {
				return errors.New("root RPC endpoints required")
			}
			var resp rootQ3CandidateResponse
			if err := firstPost(cmd.Context(), endpoints, "/api/v1/handoff/q3-candidate", request, &resp); err != nil {
				return err
			}
			return writeQ3CandidateDir(outDir, resp)
		}}
	cmd.Flags().StringVar(&nextFile, "next-trust-base", "", "next epoch trust base JSON (its stakes are the exact weights)")
	cmd.Flags().StringVar(&nextEVM, "next-evm-assignment", "", "the coupled EVM assignment (see `handoff evm-assemble`)")
	cmd.Flags().StringVar(&rootRPCs, "root-rpc", "", "comma-separated local root RPC URLs; the first that answers derives the candidate")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "directory to write the candidate files to")
	_ = cmd.MarkFlagRequired("next-trust-base")
	_ = cmd.MarkFlagRequired("root-rpc")
	_ = cmd.MarkFlagRequired("out-dir")
	return cmd
}

func writeQ3CandidateDir(dir string, resp rootQ3CandidateResponse) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	body, err := q3format.DecodeBody(resp.Body)
	if err != nil {
		return fmt.Errorf("the root returned a body that is not a valid V3 body: %w", err)
	}
	if len(resp.Candidate) != 32 {
		return errors.New("the root returned a candidate digest that is not 32 bytes")
	}
	file := q3CandidateFile{Body: resp.Body, Preimage: resp.CandidatePreimage, Attempt: resp.Attempt, ActivationRound: resp.ActivationRound}
	copy(file.Candidate[:], resp.Candidate)
	raw, err := file.encode()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "candidate.cbor"), raw, 0o600); err != nil {
		return err
	}
	cfg := body.Config
	if err := writeJSONFile(filepath.Join(dir, "config.json"), map[string]any{
		"revision": cfg.Revision, "network": cfg.Network, "genesis": "0x" + hex.EncodeToString(cfg.Genesis[:]), "signingScheme": cfg.SigningScheme,
		"voteCodec": cfg.VoteCodec, "quorumProfile": cfg.QuorumProfile, "leaderPolicy": cfg.LeaderPolicy, "evmRequestPolicy": cfg.EVMRequestPolicy, "aggregatorPolicy": cfg.AggregatorPolicy,
		"attempt": resp.Attempt, "activationRound": resp.ActivationRound}); err != nil {
		return err
	}
	id := body.Identity()
	if err := os.WriteFile(filepath.Join(dir, "v3-body-id.txt"), []byte(hex.EncodeToString(id[:])+"\n"), 0o600); err != nil {
		return err
	}
	var rootWeights, evmWeights []q3active.Signer
	for _, m := range body.Members {
		rootWeights = append(rootWeights, q3active.Signer{NodeID: m.NodeID, Weight: m.Weight})
	}
	if err := writeJSONFile(filepath.Join(dir, "root-weights.json"), rootWeights); err != nil {
		return err
	}
	if len(resp.CandidatePreimage) != 0 {
		c, err := evmassign.DecodeCandidate(resp.CandidatePreimage)
		if err != nil {
			return fmt.Errorf("the root returned a candidate preimage that does not decode: %w", err)
		}
		succ, err := c.Successor()
		if err != nil {
			return err
		}
		for _, v := range succ.Validators {
			evmWeights = append(evmWeights, q3active.Signer{NodeID: v.NodeID, Weight: v.Stake})
		}
	}
	return writeJSONFile(filepath.Join(dir, "evm-weights.json"), evmWeights)
}

// ---- q3-readiness ------------------------------------------------------------------------------------------------------------------------

// httpQ3Service is one of the entity's own services, asked for its report over its local operator endpoint.
type httpQ3Service struct {
	url    string
	client *http.Client
}

func (s httpQ3Service) Report(ctx context.Context) (q3ready.ServiceReport, error) {
	body, _ := json.Marshal(struct{}{})
	var st q3StatusResponse
	if err := handoffPost(ctx, s.client, strings.TrimRight(s.url, "/")+"/api/v1/q3/status", body, &st); err != nil {
		return q3ready.ServiceReport{}, err
	}
	out := q3ready.ServiceReport{Network: st.Network}
	genesis, err := hex.DecodeString(st.Genesis)
	if err != nil || len(genesis) != 32 {
		return q3ready.ServiceReport{}, errors.New("the service reported a genesis that is not 32 bytes")
	}
	copy(out.Genesis[:], genesis)
	if st.Staged != nil { // nothing staged leaves the zero digest, body and configuration, which no candidate has
		for _, f := range []struct {
			name string
			text string
			into *[32]byte
		}{{"digest", st.Staged.CandidateDigest, &out.Staged}, {"body identity", st.Staged.BodyID, &out.StagedBody}, {"protocol configuration", st.Staged.Config, &out.StagedConfig}} {
			raw, err := hex.DecodeString(f.text)
			if err != nil || len(raw) != 32 {
				return q3ready.ServiceReport{}, fmt.Errorf("%w: the service reported a staged %s that is not 32 bytes", q3ready.ErrComponent, f.name)
			}
			copy(f.into[:], raw)
		}
		if st.Staged.Attempt == nil {
			return q3ready.ServiceReport{}, fmt.Errorf("%w: the service reported a staged candidate without its attempt", q3ready.ErrComponent)
		}
		out.StagedAttempt = *st.Staged.Attempt
	}
	return out, nil
}

// ethExecution reports the paired execution client's loaded identity over its plain endpoint: the hash of its block 0 and the SHA-256 of the
// seal registry contract's code it serves, the two values the operator pinned.
type ethExecution struct {
	url      string
	registry string
	client   *http.Client
	// engineURL and secret are the pair's JWT-authenticated Engine endpoint: the network and root genesis its pair binding is bound to are
	// read there, never from a plain eth_* answer alone.
	engineURL string
	secret    engineapi.Secret
}

func (e ethExecution) call(ctx context.Context, method string, params []any, out any) error {
	body, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct{ Message string }
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&envelope); err != nil {
		return err
	}
	if envelope.Error != nil {
		return fmt.Errorf("%s: %s", method, envelope.Error.Message)
	}
	return json.Unmarshal(envelope.Result, out)
}

func (e ethExecution) Report(ctx context.Context) (q3ready.ExecutionReport, error) {
	var block struct {
		Hash string `json:"hash"`
	}
	if err := e.call(ctx, "eth_getBlockByNumber", []any{"0x0", false}, &block); err != nil {
		return q3ready.ExecutionReport{}, err
	}
	genesis, err := hex.DecodeString(strings.TrimPrefix(block.Hash, "0x"))
	if err != nil || len(genesis) != 32 {
		return q3ready.ExecutionReport{}, errors.New("the execution client reported a genesis hash that is not 32 bytes")
	}
	var code string
	if err := e.call(ctx, "eth_getCode", []any{e.registry, "latest"}, &code); err != nil {
		return q3ready.ExecutionReport{}, err
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(code, "0x"))
	if err != nil || len(raw) == 0 {
		return q3ready.ExecutionReport{}, errors.New("the execution client serves no registry code")
	}
	sum := sha256.Sum256(raw)
	pins, err := engineapi.ReadPairPins(ctx, e.engineURL, e.secret)
	if err != nil {
		return q3ready.ExecutionReport{}, fmt.Errorf("the authenticated pair connection: %w", err)
	}
	return q3ready.ExecutionReport{GenesisHash: genesis, CodeHash: sum[:], Authenticated: true, PairNetwork: pins.NetworkID, PairGenesis: pins.RootGenesisID}, nil
}

func parsePin32(name, s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("--%s must be a 32-byte hex value", name)
	}
	return raw, nil
}

func newQ3ReadinessCmd() *cobra.Command {
	var candidateFile, keyFile, rootRPC, shardRPC, ethURL, engineURL, jwtFile, registry, genesisPin, codePin, out string
	cmd := &cobra.Command{Use: "q3-readiness", Short: "Sign this validator entity's readiness receipt for a V3 candidate",
		Long: "Run by a successor member's operator. The entity's BFT node and its shard service must each report the chain and have the\n" +
			"candidate staged, and the paired execution client must be the genesis and registry code the operator pinned (the pins are\n" +
			"never read from the client under test). Only then is the receipt signed with the entity's root key; any one refusal writes no\n" +
			"receipt. The receipt is an accountable declaration, not an attestation.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := os.ReadFile(candidateFile) // #nosec G304 -- operator supplied local file
			if err != nil {
				return err
			}
			cand, err := decodeQ3Candidate(raw)
			if err != nil {
				return err
			}
			body, rc, err := cand.context()
			if err != nil {
				return err
			}
			rawKey, err := os.ReadFile(keyFile) // #nosec G304 -- operator supplied local key file
			if err != nil {
				return err
			}
			var conf KeyConf
			if err := json.Unmarshal(rawKey, &conf); err != nil {
				return fmt.Errorf("decoding key configuration %q: %w", keyFile, err)
			}
			signer, err := conf.Signer()
			if err != nil {
				return err
			}
			id, err := conf.NodeID()
			if err != nil {
				return err
			}
			genesis, err := parsePin32("execution-genesis-hash", genesisPin)
			if err != nil {
				return err
			}
			code, err := parsePin32("execution-code-hash", codePin)
			if err != nil {
				return err
			}
			secret, err := readJWTSecret(jwtFile)
			if err != nil {
				return err
			}
			client := &http.Client{Timeout: 10 * time.Second}
			if err := stageOnRoot(cmd.Context(), client, rootRPC, cand); err != nil {
				return fmt.Errorf("bft node: %w", err)
			}
			if err := stageOnShard(cmd.Context(), client, shardRPC, cand); err != nil {
				return fmt.Errorf("shard service: %w", err)
			}
			entity := q3ready.Entity{NodeID: id.String(), BFT: httpQ3Service{url: rootRPC, client: client}, Authority: httpQ3Service{url: shardRPC, client: client},
				Execution: ethExecution{url: ethURL, registry: registry, client: client, engineURL: engineURL, secret: secret}}
			receipt, err := entity.Attest(cmd.Context(), rc, body.Config, q3ready.ExecutionPin{GenesisHash: genesis, CodeHash: code}, signer)
			if err != nil {
				return err
			}
			return writeJSONFile(out, q3Receipt{NodeID: receipt.NodeID, Signature: receipt.Signature})
		}}
	cmd.Flags().StringVar(&candidateFile, "candidate", "", "candidate.cbor from `handoff q3-candidate`")
	cmd.Flags().StringVar(&keyFile, "key-conf", "", "this entity's root key configuration (keys.json)")
	cmd.Flags().StringVar(&rootRPC, "root-rpc", "", "this entity's root node RPC URL")
	cmd.Flags().StringVar(&shardRPC, "shard-rpc", "", "this entity's shard node RPC URL")
	cmd.Flags().StringVar(&ethURL, "eth-url", "", "this entity's execution client plain endpoint")
	cmd.Flags().StringVar(&engineURL, "engine-url", "", "this entity's execution client JWT-authenticated Engine endpoint (the pair pins are read here)")
	cmd.Flags().StringVar(&jwtFile, "jwt-secret", "", "the Engine endpoint's JWT secret file")
	cmd.Flags().StringVar(&registry, "registry-address", "0xff00000000000000000000000000000000000002", "the seal registry contract whose code the execution pin names")
	cmd.Flags().StringVar(&genesisPin, "execution-genesis-hash", "", "the pinned execution genesis block hash")
	cmd.Flags().StringVar(&codePin, "execution-code-hash", "", "the pinned SHA-256 of the registry contract code")
	cmd.Flags().StringVar(&out, "out", "", "receipt file to write")
	for _, f := range []string{"candidate", "key-conf", "root-rpc", "shard-rpc", "eth-url", "engine-url", "jwt-secret", "execution-genesis-hash", "execution-code-hash", "out"} {
		_ = cmd.MarkFlagRequired(f)
	}
	return cmd
}

// stageOnRoot hands the entity's root node the candidate another validator derived. The root refuses a body that is not the next epoch of
// its own chain.
func stageOnRoot(ctx context.Context, client *http.Client, rootRPC string, cand q3CandidateFile) error {
	body, err := json.Marshal(rootQ3StageRequest{Body: cand.Body, Candidate: cand.Candidate[:], Attempt: cand.Attempt, Preimage: cand.Preimage})
	if err != nil {
		return err
	}
	if err := handoffPost(ctx, client, strings.TrimRight(rootRPC, "/")+"/api/v1/handoff/q3-stage", body, nil); err != nil {
		return fmt.Errorf("%w: %w", ErrQ3StageRefused, err)
	}
	return nil
}

// stageOnShard hands the shard service the candidate it will report as staged. The shard node refuses a body of another chain.
func stageOnShard(ctx context.Context, client *http.Client, shardRPC string, cand q3CandidateFile) error {
	body, err := json.Marshal(shardQ3StageRequest{Body: cand.Body, Candidate: cand.Candidate[:], Attempt: cand.Attempt, Preimage: cand.Preimage})
	if err != nil {
		return err
	}
	if err := handoffPost(ctx, client, strings.TrimRight(shardRPC, "/")+"/api/v1/q3/stage", body, nil); err != nil {
		return fmt.Errorf("%w: %w", ErrQ3StageRefused, err)
	}
	return nil
}

// ---- q3-activation and the q3 evidence group -----------------------------------------------------------------------------------------------

func newQ3ActivationCmd() *cobra.Command {
	var rootRPCs, out string
	var epoch uint64
	cmd := &cobra.Command{Use: "q3-activation", Short: "Write the committed activation record of a root epoch",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var rec q3active.ActivationRecord
			if err := firstPost(cmd.Context(), splitList(rootRPCs), "/api/v1/q3/activation", q3EpochRequest{Epoch: epoch}, &rec); err != nil {
				return err
			}
			return writeJSONFile(out, rec)
		}}
	cmd.Flags().StringVar(&rootRPCs, "root-rpc", "", "comma-separated local root RPC URLs")
	cmd.Flags().Uint64Var(&epoch, "epoch", 0, "the activated root epoch")
	cmd.Flags().StringVar(&out, "out", "", "file to write")
	_ = cmd.MarkFlagRequired("root-rpc")
	_ = cmd.MarkFlagRequired("epoch")
	_ = cmd.MarkFlagRequired("out")
	return cmd
}

func newQ3Cmd() *cobra.Command {
	q3 := &cobra.Command{Use: "q3", Short: "Evidence of the Q3 acceptance lane, read from the processes that hold it"}
	var rootRPCs, out string
	var epoch uint64
	common := func(c *cobra.Command) {
		c.Flags().StringVar(&rootRPCs, "root-rpc", "", "comma-separated local root RPC URLs")
		c.Flags().StringVar(&out, "out", "", "file to write")
		_ = c.MarkFlagRequired("root-rpc")
		_ = c.MarkFlagRequired("out")
	}
	history := &cobra.Command{Use: "history", Short: "The verified history identities a root holds: one line per epoch, bodyId and commitId",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var resp q3HistoryResponse
			if err := firstPost(cmd.Context(), splitList(rootRPCs), "/api/v1/q3/history", struct{}{}, &resp); err != nil {
				return err
			}
			var b strings.Builder
			for _, e := range resp.Entries {
				fmt.Fprintf(&b, "%d %s %s\n", e.Epoch, e.BodyID, e.CommitID)
			}
			return os.WriteFile(out, []byte(b.String()), 0o600)
		}}
	envelope := &cobra.Command{Use: "proof-envelope", Short: "The canonical activation bundle (proof envelope, checkpoint, candidate) of an epoch",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var resp q3BundleResponse
			if err := firstPost(cmd.Context(), splitList(rootRPCs), "/api/v1/q3/bundle", q3EpochRequest{Epoch: epoch}, &resp); err != nil {
				return err
			}
			raw, err := hex.DecodeString(resp.Bundle)
			if err != nil {
				return err
			}
			if _, _, err := q3active.DecodeBundle(raw); err != nil {
				return fmt.Errorf("the root returned a bundle that does not decode: %w", err)
			}
			return os.WriteFile(out, raw, 0o600)
		}}
	envelope.Flags().Uint64Var(&epoch, "epoch", 0, "the activated root epoch")
	_ = envelope.MarkFlagRequired("epoch")
	signers := &cobra.Command{Use: "signers", Short: "The signers and weights of the committed root quorum certificate",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var resp q3SignersResponse
			if err := firstPost(cmd.Context(), splitList(rootRPCs), "/api/v1/q3/signers", struct{}{}, &resp); err != nil {
				return err
			}
			if !resp.Quorum {
				return fmt.Errorf("%w: signed weight %d, threshold %d", ErrQ3SignerQuorum, resp.SignedTotal, resp.Threshold)
			}
			return writeJSONFile(out, resp.Signers)
		}}
	for _, c := range []*cobra.Command{history, envelope, signers} {
		common(c)
		q3.AddCommand(c)
	}
	q3.AddCommand(newQ3PairCmds()...)
	return q3
}
