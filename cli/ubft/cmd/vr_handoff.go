package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrhandoff"
	"github.com/unicitynetwork/bft-core/vrschema"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// The VR handoff's root side, first stage (VT-05b PR A, ristik/bft-core#1159): the root observes VR through its execution client and
// derives the intent; a complete view certificate reaches it through the loopback operator endpoints below, and its leader orders the
// Prepare, the Freeze v5 and H. `ubft vr-handoff drive` is the development harness that makes that certificate on a generation whose
// keys it holds (every successor's PoP and readiness, the assembler's assembly); the staged protocol among the roots and the successor
// nodes replaces it (VT-05b PR B, VT-09).

// ErrVRHandoffCmd reports a refused VR handoff command.
var ErrVRHandoffCmd = errors.New("vr-handoff")

// vrSourcesFileName is the root's persisted VR sources (stage 0) in its home.
const vrSourcesFileName = "vr-sources.json"

// enableVRHandoff wires the VR handoff root side of a VR-mode manager: the observer over the execution client at rpcURL (eth_getProof
// and eth_call at the certified block hashes), the persisted sources, the intent provider and the Freeze witness builder.
func enableVRHandoff(ctx context.Context, cm *consensus.ConsensusManager, dep vradmit.Deployment, pins vrstate.Pins, shardConfs []*types.PartitionDescriptionRecord,
	rpcURL, home string) error {
	if rpcURL == "" {
		return fmt.Errorf("%w: a VR generation's roots read VR through --pos-evm-rpc", ErrVRHandoffCmd)
	}
	var evm *types.PartitionDescriptionRecord
	for _, c := range shardConfs {
		if _, ok := c.PartitionParams["validator_registry"]; ok {
			evm = c
		}
	}
	if evm == nil {
		return fmt.Errorf("%w: no genesis shard configuration pins VR", ErrVRHandoffCmd)
	}
	client, err := rpc.DialContext(ctx, rpcURL)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrVRHandoffCmd, err)
	}
	sources, err := vrschedule.NewSources(filepath.Join(home, vrSourcesFileName))
	if err != nil {
		return err
	}
	reader := vrschedule.RPC{Client: client, Pins: pins}
	return cm.EnableVRHandoff(ctx, consensus.VRHandoffConfig{
		Intents: &vrschedule.Intents{Deployment: dep, Pins: pins, Sources: sources, Outputs: vrschedule.NewOutputs()},
		Reader:  reader,
		EVM:     types.PartitionShardID{PartitionID: evm.PartitionID, ShardID: evm.ShardID.Key()},
		Witness: func(ctx context.Context, blockHash, stateRoot [32]byte, result vrschema.Word) ([]byte, error) {
			return reader.OutputState(ctx, blockHash, stateRoot, result)
		},
	})
}

type vrHandoffOperator interface {
	VRIntent() (consensus.VRIntentView, error)
	VRBody(candidate []byte) (q3format.BodyV3, []byte, error)
	SubmitVRCertificate(c vrschema.ViewCertificate) error
}

type vrIntentResponse struct {
	Intent     hex.Bytes `json:"intent"`
	Digest     hex.Bytes `json:"digest"`
	RootEpoch  uint64    `json:"rootEpoch"`
	Incumbents []string  `json:"incumbents"`
	Assembler  string    `json:"assembler"`
}

type vrBodyRequest struct {
	Candidate hex.Bytes `json:"candidate"`
}

type vrBodyResponse struct {
	Body      hex.Bytes `json:"body"`
	TrustBase hex.Bytes `json:"trustBase"`
}

type vrCertificateRequest struct {
	Certificate hex.Bytes `json:"certificate"`
}

const maxVRHandoffRequest = 4 << 20

func vrHandoffError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if errors.Is(err, consensus.ErrVRHandoff) {
		status = http.StatusUnprocessableEntity
	}
	http.Error(w, err.Error(), status)
}

// registerVRHandoffRoutes serves the operator endpoints on the root's loopback RPC.
func registerVRHandoffRoutes(mux *http.ServeMux, op vrHandoffOperator) {
	mux.HandleFunc("GET /api/v1/vr/intent", func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		v, err := op.VRIntent()
		if err != nil {
			vrHandoffError(w, err)
			return
		}
		raw, err := v.Intent.Encode()
		if err != nil {
			vrHandoffError(w, err)
			return
		}
		writeVRJSON(w, vrIntentResponse{Intent: raw, Digest: v.Digest[:], RootEpoch: v.RootEpoch, Incumbents: v.Incumbents, Assembler: v.Assembler})
	})
	mux.HandleFunc("POST /api/v1/vr/body", func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var req vrBodyRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, maxVRHandoffRequest)).Decode(&req) != nil || len(req.Candidate) == 0 {
			http.Error(w, "invalid body request", http.StatusBadRequest)
			return
		}
		body, tb, err := op.VRBody(req.Candidate)
		if err != nil {
			vrHandoffError(w, err)
			return
		}
		writeVRJSON(w, vrBodyResponse{Body: body.Encode(), TrustBase: tb})
	})
	mux.HandleFunc("POST /api/v1/vr/certificate", func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var req vrCertificateRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, maxVRHandoffRequest)).Decode(&req) != nil {
			http.Error(w, "invalid certificate submission", http.StatusBadRequest)
			return
		}
		c, err := vrschema.DecodeViewCertificate(req.Certificate)
		if err != nil {
			http.Error(w, "invalid certificate: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := op.SubmitVRCertificate(c); err != nil {
			vrHandoffError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

func writeVRJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func newVRHandoffCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "vr-handoff", Short: "Validator-registry handoff tools (development)"}
	cmd.AddCommand(newVRHandoffDriveCmd())
	return cmd
}

// homeKeys reads the signing key and node id of every home's keys.json.
func homeKeys(homes []string) (map[string]abcrypto.Signer, error) {
	out := map[string]abcrypto.Signer{}
	for _, h := range homes {
		raw, err := os.ReadFile(filepath.Join(h, keyConfFileName)) // #nosec G304 -- operator supplied home
		if err != nil {
			return nil, err
		}
		var kc KeyConf
		if err := json.Unmarshal(raw, &kc); err != nil {
			return nil, fmt.Errorf("%s: %w", h, err)
		}
		id, err := kc.NodeID()
		if err != nil {
			return nil, err
		}
		s, err := kc.Signer()
		if err != nil {
			return nil, err
		}
		out[id.String()] = s
	}
	return out, nil
}

// vrClient is the harness's view of the roots' operator endpoints.
type vrClient struct {
	http *http.Client
}

func (c vrClient) do(method, url string, in, out any) error {
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxVRHandoffRequest))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%w: %s %s: %s: %s", ErrVRHandoffCmd, method, url, resp.Status, bytes.TrimSpace(raw))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// vrDrive makes the complete view certificate of the current intent with keys the harness holds and delivers it to every root.
func vrDrive(c vrClient, roots []string, rootKeys, evmKeys map[string]abcrypto.Signer, view uint64, out io.Writer) error {
	if len(roots) == 0 {
		return fmt.Errorf("%w: no root", ErrVRHandoffCmd)
	}
	var ir vrIntentResponse
	if err := c.do(http.MethodGet, roots[0]+"/api/v1/vr/intent", nil, &ir); err != nil {
		return err
	}
	in, err := vrschema.DecodeIntent(ir.Intent)
	if err != nil {
		return err
	}
	d, err := in.Digest()
	if err != nil || !bytes.Equal(d[:], ir.Digest) {
		return fmt.Errorf("%w: the served intent does not hash to its digest", ErrVRHandoffCmd)
	}
	cand, err := vrhandoff.CandidateOf(in)
	if err != nil {
		return err
	}
	// stage 2: every successor's sticky possession proof
	var pops []vrhandoff.PoPOffer
	for _, m := range cand.Identities {
		s, ok := evmKeys[m.EVMNodeID]
		if !ok {
			return fmt.Errorf("%w: no EVM key of successor %s", ErrVRHandoffCmd, m.EVMNodeID)
		}
		p, err := vrhandoff.SignPoP(in, m, s)
		if err != nil {
			return err
		}
		pops = append(pops, p)
	}
	// stage 3: the assembly by the view's assembler
	_, raw, _, err := vrhandoff.Assemble(in, pops)
	if err != nil {
		return err
	}
	who := vrhandoff.Assembler(d, ir.Incumbents, view)
	as, ok := rootKeys[who]
	if !ok {
		return fmt.Errorf("%w: no root key of view %d's assembler %s", ErrVRHandoffCmd, view, who)
	}
	a, err := vrhandoff.SignAssembly(in, view, raw, as)
	if err != nil {
		return err
	}
	// stage 4: the body and trust base the root derives for this candidate, and every successor's readiness over them
	var br vrBodyResponse
	if err := c.do(http.MethodPost, roots[0]+"/api/v1/vr/body", vrBodyRequest{Candidate: raw}, &br); err != nil {
		return err
	}
	body, err := q3format.DecodeBody(br.Body)
	if err != nil {
		return err
	}
	rs := map[string]vrhandoff.Readiness{}
	for _, m := range cand.Identities {
		s, ok := rootKeys[m.RootNodeID]
		if !ok {
			return fmt.Errorf("%w: no root key of successor %s", ErrVRHandoffCmd, m.RootNodeID)
		}
		r, err := vrhandoff.SignReadiness(in, a, body, m.RootNodeID, br.TrustBase, nil, s)
		if err != nil {
			return err
		}
		rs[m.RootNodeID] = r
	}
	cert, err := vrhandoff.Certificate(a, cand.Identities, rs, body.Identity())
	if err != nil {
		return err
	}
	certRaw, err := cert.Encode()
	if err != nil {
		return err
	}
	for _, root := range roots {
		if err := c.do(http.MethodPost, root+"/api/v1/vr/certificate", vrCertificateRequest{Certificate: certRaw}, nil); err != nil {
			return err
		}
	}
	bodyID := body.Identity()
	summary := map[string]any{"intent": fmt.Sprintf("%x", d), "result": fmt.Sprintf("%x", cand.SourceRef), "rootEpoch": ir.RootEpoch,
		"attempt": in.Attempt, "anchorRound": in.AnchorRound, "view": view, "assembler": who, "body": fmt.Sprintf("%x", bodyID),
		"successors": successorNames(cand.Identities), "earliestActivation": body.EarliestActivation, "roots": len(roots)}
	enc := json.NewEncoder(out)
	enc.SetIndent("", " ")
	return enc.Encode(summary)
}

func successorNames(ids []evmassign.Identity) []string {
	out := make([]string, len(ids))
	for i, m := range ids {
		out[i] = m.RootNodeID + "/" + m.EVMNodeID
	}
	return out
}

func newVRHandoffDriveCmd() *cobra.Command {
	var roots, rootHomes, evmHomes []string
	var view uint64
	cmd := &cobra.Command{Use: "drive",
		Short: "Make the current intent's complete view certificate with the generation's keys and hand it to every root (development harness)",
		Long: "Reads the intent a root derives over its committed state (GET /api/v1/vr/intent), signs every successor's possession proof with its EVM key, " +
			"the assembly with the view's assembler's root key, every successor's readiness over the body and trust base the root derives (POST /api/v1/vr/body), " +
			"and delivers the certificate to every root (POST /api/v1/vr/certificate); their leaders then order the Prepare, the Freeze v5 and H. " +
			"Development generations only: it reads keys.json from every home it is given.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			rk, err := homeKeys(rootHomes)
			if err != nil {
				return err
			}
			ek, err := homeKeys(evmHomes)
			if err != nil {
				return err
			}
			return vrDrive(vrClient{http: &http.Client{Timeout: 30 * time.Second}}, roots, rk, ek, view, cmd.OutOrStdout())
		}}
	cmd.Flags().StringSliceVar(&roots, "root-rpc", nil, "the roots' RPC base URLs (loopback), the first one serves the intent and the body")
	cmd.Flags().StringSliceVar(&rootHomes, "root-home", nil, "root node homes (keys.json): the assembler and every successor")
	cmd.Flags().StringSliceVar(&evmHomes, "evm-home", nil, "EVM shard node homes (keys.json): every successor")
	cmd.Flags().Uint64Var(&view, "view", 0, "the committed view the certificate is for")
	_ = cmd.MarkFlagRequired("root-rpc")
	return cmd
}
