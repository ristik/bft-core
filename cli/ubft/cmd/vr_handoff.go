package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/rpc"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/spf13/cobra"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/vrschedule"
	"github.com/unicitynetwork/bft-core/rootchain/vrstate"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
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
	rpcURL, home, evmKeys, shardRPC string, signer abcrypto.Signer, host *network.Peer, authority ...vrEVMAuthority) error {
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
	member, err := vrMemberConfig(home, evmKeys, authority...)
	if err != nil {
		return err
	}
	shard, err := vrShardSink(shardRPC)
	if err != nil {
		return err
	}
	reader := vrschedule.RPC{Client: client, Pins: pins}
	var opener vrschedule.Opener
	if host != nil {
		opener = vrschedule.FromLibp2p(host)
	}
	if err := cm.EnableVRHandoff(ctx, consensus.VRHandoffConfig{
		Intents: &vrschedule.Intents{Deployment: dep, Pins: pins, Sources: sources, Outputs: vrschedule.NewOutputs()},
		Reader:  reader,
		EVM:     types.PartitionShardID{PartitionID: evm.PartitionID, ShardID: evm.ShardID.Key()},
		Witness: func(ctx context.Context, blockHash, stateRoot [32]byte, result vrschema.Word) ([]byte, error) {
			return reader.OutputState(ctx, blockHash, stateRoot, result)
		},
		Signer:      signer,
		Opener:      opener,
		Member:      member,
		ShardStaged: shard,
	}); err != nil {
		return err
	}
	if host != nil {
		// the peer protocol: the installed root committee always, besides the current intent's members the service names
		svc, queue := cm.VRService()
		server := vrschedule.NewServer(svc, queue, func(id peer.ID) bool { return slices.Contains(cm.Validators(), id) }).WithSources(sources)
		host.RegisterProtocolHandler(vrschedule.ProtocolID, server.Handler)
		go func() { <-ctx.Done(); host.RemoveProtocolHandler(vrschedule.ProtocolID) }()
	}
	return nil
}

// enableVRHandoffInVRMode wires the VR handoff root side on a VR-mode root, one whose VR services (the generation's deployment and the
// state authority over the pinned VR) are installed: it is the root side of every VR generation's handoff, replacing the P85 operator
// script (handoff_drive.py) there. A root outside VR mode is unchanged. It must run after the VR services are installed (enableVRServices);
// checkVRHandoffWired, before the root starts, refuses a VR-mode root whose root side is off. It reports whether the root side is on.
func enableVRHandoffInVRMode(ctx context.Context, cm *consensus.ConsensusManager, shardConfs []*types.PartitionDescriptionRecord, rpcURL, home, evmKeys, shardRPC string,
	signer abcrypto.Signer, host *network.Peer, authority ...vrEVMAuthority) (bool, error) {
	dep, pins, on, err := vrHandoffWiring(cm.VRServices(), rpcURL)
	if err != nil || !on {
		return false, err
	}
	if err := enableVRHandoff(ctx, cm, dep, pins, shardConfs, rpcURL, home, evmKeys, shardRPC, signer, host, authority...); err != nil {
		return false, err
	}
	return true, nil
}

// vrEVMAuthority is the node's signing authority as the member reaches it: its possession-proof socket and the member's credential.
type vrEVMAuthority struct{ Socket, Credential string }

func (a vrEVMAuthority) empty() bool { return a.Socket == "" && a.Credential == "" }

// vrMemberFileName is the node's persisted member state (sticky proofs, signed views) in its home.
const vrMemberFileName = "vr-member.json"

// vrMemberConfig is the node's member participation (VT-09): every VR-mode node does the successor-member steps itself when an intent names
// it. The possession proof is signed by its EVM key, read from the EVM shard node's keys.json (--vr-evm-keys, the key the validator
// configuration names as evmKeys); without one the node signs readiness but cannot send its proof. The root process then holds that EVM
// validator key (and the file's auth key): a compromised root process compromises the EVM validator too, so give the flag only on a host that
// already holds both. The member refuses to sign when the key is not the EVM node the intent names for this node.
func vrMemberConfig(home, evmKeys string, authority ...vrEVMAuthority) (*consensus.VRMemberConfig, error) {
	m := &consensus.VRMemberConfig{Path: filepath.Join(home, vrMemberFileName)}
	m.Hold = devMemberHold(home)
	if len(authority) > 0 && !authority[0].empty() {
		// the EVM key stays in the node's signing authority: the member reaches its possession-proof endpoint (VT-09, #1201)
		a := authority[0]
		if evmKeys != "" {
			return nil, fmt.Errorf("%w: --vr-evm-keys and --vr-evm-authority-socket are two holders of the EVM key: give one", ErrVRHandoffCmd)
		}
		if a.Socket == "" || a.Credential == "" {
			return nil, fmt.Errorf("%w: --vr-evm-authority-socket needs --vr-evm-authority-credential", ErrVRHandoffCmd)
		}
		credential, err := readCredentialFile(a.Credential)
		if err != nil {
			return nil, fmt.Errorf("%w: loading the possession-proof credential: %v", ErrVRHandoffCmd, err)
		}
		c, err := service.NewPoPClient(service.ClientConfig{Dial: service.UnixDialer(a.Socket), Credential: credential, Timeout: vrschedule.AuthorityPoPTimeout})
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrVRHandoffCmd, err)
		}
		m.EVMPoP = vrschedule.AuthorityPoP{Client: c}
		return m, nil
	}
	if evmKeys == "" {
		return m, nil
	}
	dir := filepath.Dir(evmKeys)
	if filepath.Base(evmKeys) != keyConfFileName {
		return nil, fmt.Errorf("%w: --vr-evm-keys must name a %s", ErrVRHandoffCmd, keyConfFileName)
	}
	ks, err := homeKeys([]string{dir})
	if err != nil || len(ks) != 1 {
		return nil, fmt.Errorf("%w: --vr-evm-keys: %v (%d keys)", ErrVRHandoffCmd, err, len(ks))
	}
	for id, s := range ks { // exactly one entry: the file's own key
		m.EVMNodeID, m.EVMSigner = id, s
	}
	return m, nil
}

// vrHandoffWiring is what the installed VR services and --pos-evm-rpc decide: off outside VR mode; in VR mode the generation's deployment
// and pins, and an execution client is required. A VR-mode root cannot execute a HandoffView or a Freeze v5 without the intent it derives
// through that client (review #1188 r2 N1), so it is refused at startup rather than stall at the first handoff.
func vrHandoffWiring(reg *storage.VRServices, rpcURL string) (vradmit.Deployment, vrstate.Pins, bool, error) {
	if reg == nil {
		return vradmit.Deployment{}, vrstate.Pins{}, false, nil
	}
	if rpcURL == "" {
		return vradmit.Deployment{}, vrstate.Pins{}, false, fmt.Errorf("%w: a VR-mode root derives the handoff intent through its execution client: --pos-evm-rpc is required", ErrVRHandoffCmd)
	}
	a, ok := reg.State.(vrstate.Authority)
	if !ok {
		return vradmit.Deployment{}, vrstate.Pins{}, false, fmt.Errorf("%w: the VR state authority carries no pins", ErrVRHandoffCmd)
	}
	return reg.Deployment, a.Pins, true, nil
}

// checkVRHandoffWired refuses a VR-mode root whose handoff root side is off: its VR services were installed after the root side was wired
// (root-node run installs them first; review #1188 r2 N2).
func checkVRHandoffWired(reg *storage.VRServices, on bool) error {
	if reg != nil && !on {
		return fmt.Errorf("%w: the VR services were installed after the VR handoff root side was wired", ErrVRHandoffCmd)
	}
	return nil
}

type vrHandoffOperator interface {
	VRIntent() (consensus.VRIntentView, error)
	VRBody(candidate []byte) (q3format.BodyV3, []byte, error)
	SubmitVRCertificate(c vrschema.ViewCertificate) error
	OfferVRMessage(m vrschedule.Message) error
	VRStage(fromView uint64) (vrschedule.StageSet, [32]byte, error)
	VRMemberStatus() consensus.VRMemberStatus
}

type vrMessageRequest struct {
	PoP       hex.Bytes `json:"pop,omitempty"`
	Assembly  hex.Bytes `json:"assembly,omitempty"`
	Readiness hex.Bytes `json:"readiness,omitempty"`
}

type vrStageResponse struct {
	Intent     hex.Bytes   `json:"intent"`
	PoPs       []hex.Bytes `json:"pops"`
	Assemblies []hex.Bytes `json:"assemblies"`
	Readiness  []hex.Bytes `json:"readiness"`
}

type vrIntentResponse struct {
	Intent     hex.Bytes `json:"intent"`
	Digest     hex.Bytes `json:"digest"`
	RootEpoch  uint64    `json:"rootEpoch"`
	View       uint64    `json:"view"`
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
		writeVRJSON(w, vrIntentResponse{Intent: raw, Digest: v.Digest[:], RootEpoch: v.RootEpoch, View: v.View, Incumbents: v.Incumbents, Assembler: v.Assembler})
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
	mux.HandleFunc("POST /api/v1/vr/message", func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var req vrMessageRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, maxVRHandoffRequest)).Decode(&req) != nil {
			http.Error(w, "invalid message", http.StatusBadRequest)
			return
		}
		m, err := decodeVRMessage(req)
		if err != nil {
			http.Error(w, "invalid message: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := op.OfferVRMessage(m); err != nil {
			vrHandoffError(w, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("GET /api/v1/vr/member", func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		writeVRJSON(w, op.VRMemberStatus())
	})
	mux.HandleFunc("GET /api/v1/vr/stage", func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var from uint64
		if f := r.URL.Query().Get("from"); f != "" {
			if _, err := fmt.Sscan(f, &from); err != nil {
				http.Error(w, "invalid from", http.StatusBadRequest)
				return
			}
		}
		set, intent, err := op.VRStage(from)
		if err != nil {
			vrHandoffError(w, err)
			return
		}
		resp := vrStageResponse{Intent: intent[:]}
		for _, p := range set.PoPs {
			b, _ := types.Cbor.Marshal(p)
			resp.PoPs = append(resp.PoPs, b)
		}
		for _, a := range set.Assemblies {
			b, _ := types.Cbor.Marshal(a)
			resp.Assemblies = append(resp.Assemblies, b)
		}
		for _, rd := range set.Readiness {
			b, _ := rd.Encode()
			resp.Readiness = append(resp.Readiness, b)
		}
		writeVRJSON(w, resp)
	})
}

func decodeVRMessage(req vrMessageRequest) (vrschedule.Message, error) {
	var m vrschedule.Message
	n := 0
	if len(req.PoP) != 0 {
		var p vrhandoff.PoPOffer
		if err := types.Cbor.Unmarshal(req.PoP, &p); err != nil {
			return m, err
		}
		m.PoP, n = &p, n+1
	}
	if len(req.Assembly) != 0 {
		var a vrhandoff.Assembly
		if err := types.Cbor.Unmarshal(req.Assembly, &a); err != nil {
			return m, err
		}
		m.Assembly, n = &a, n+1
	}
	if len(req.Readiness) != 0 {
		r, err := vrschema.DecodeReadiness(req.Readiness)
		if err != nil {
			return m, err
		}
		m.Readiness, n = &r, n+1
	}
	if n != 1 {
		return m, fmt.Errorf("%w: exactly one of pop, assembly, readiness", ErrVRHandoffCmd)
	}
	return m, nil
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

// vrDriveProtocol plays the successor members on a development generation whose keys it holds, through the staged protocol: every
// member's possession proof to every root; the committed view's assembler root assembles; then every member's readiness over that assembly
// to every root, whose leaders order the Prepare, the Freeze v5 and H once a complete verified certificate is held.
func vrDriveProtocol(c vrClient, roots []string, rootKeys, evmKeys map[string]abcrypto.Signer, wait time.Duration, out io.Writer) error {
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
	for _, m := range cand.Identities {
		s, ok := evmKeys[m.EVMNodeID]
		if !ok {
			return fmt.Errorf("%w: no EVM key of successor %s", ErrVRHandoffCmd, m.EVMNodeID)
		}
		p, err := vrhandoff.SignPoP(in, m, s)
		if err != nil {
			return err
		}
		raw, err := types.Cbor.Marshal(p)
		if err != nil {
			return err
		}
		for _, root := range roots {
			if err := c.do(http.MethodPost, root+"/api/v1/vr/message", vrMessageRequest{PoP: raw}, nil); err != nil {
				return err
			}
		}
	}
	// the committed view's assembler assembles from the proofs it holds
	var a *vrhandoff.Assembly
	deadline := time.Now().Add(wait)
	for a == nil {
		var sr vrStageResponse
		if err := c.do(http.MethodGet, fmt.Sprintf("%s/api/v1/vr/stage?from=%d", roots[0], ir.View), nil, &sr); err == nil && bytes.Equal(sr.Intent, d[:]) {
			for _, raw := range sr.Assemblies {
				var x vrhandoff.Assembly
				if types.Cbor.Unmarshal(raw, &x) == nil && x.Slot >= ir.View {
					a = &x
				}
			}
		}
		if a == nil {
			if time.Now().After(deadline) {
				return fmt.Errorf("%w: no assembly of view %d from its assembler %s within %s", ErrVRHandoffCmd, ir.View, ir.Assembler, wait)
			}
			time.Sleep(time.Second)
		}
	}
	var br vrBodyResponse
	if err := c.do(http.MethodPost, roots[0]+"/api/v1/vr/body", vrBodyRequest{Candidate: a.Candidate}, &br); err != nil {
		return err
	}
	body, err := q3format.DecodeBody(br.Body)
	if err != nil {
		return err
	}
	for _, m := range cand.Identities {
		s, ok := rootKeys[m.RootNodeID]
		if !ok {
			return fmt.Errorf("%w: no root key of successor %s", ErrVRHandoffCmd, m.RootNodeID)
		}
		r, err := vrhandoff.SignReadiness(in, *a, body, m.RootNodeID, br.TrustBase, nil, s)
		if err != nil {
			return err
		}
		raw, err := r.Encode()
		if err != nil {
			return err
		}
		for _, root := range roots {
			if err := c.do(http.MethodPost, root+"/api/v1/vr/message", vrMessageRequest{Readiness: raw}, nil); err != nil {
				return err
			}
		}
	}
	bodyID := body.Identity()
	enc := json.NewEncoder(out)
	enc.SetIndent("", " ")
	return enc.Encode(map[string]any{"intent": fmt.Sprintf("%x", d), "result": fmt.Sprintf("%x", cand.SourceRef), "rootEpoch": ir.RootEpoch,
		"attempt": in.Attempt, "anchorRound": in.AnchorRound, "view": a.Slot, "assembler": ir.Assembler, "body": fmt.Sprintf("%x", bodyID),
		"successors": successorNames(cand.Identities), "earliestActivation": body.EarliestActivation, "roots": len(roots), "mode": "protocol"})
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
	var certificate bool
	var wait time.Duration
	cmd := &cobra.Command{Use: "drive",
		Short: "Play the successor members of the current intent with the generation's keys (development harness)",
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
			c := vrClient{http: &http.Client{Timeout: 30 * time.Second}}
			if certificate {
				return vrDrive(c, roots, rk, ek, view, cmd.OutOrStdout())
			}
			return vrDriveProtocol(c, roots, rk, ek, wait, cmd.OutOrStdout())
		}}
	cmd.Flags().StringSliceVar(&roots, "root-rpc", nil, "the roots' RPC base URLs (loopback), the first one serves the intent and the body")
	cmd.Flags().StringSliceVar(&rootHomes, "root-home", nil, "root node homes (keys.json): the assembler and every successor")
	cmd.Flags().StringSliceVar(&evmHomes, "evm-home", nil, "EVM shard node homes (keys.json): every successor")
	cmd.Flags().Uint64Var(&view, "view", 0, "with --certificate: the committed view the certificate is for")
	cmd.Flags().BoolVar(&certificate, "certificate", false, "make the whole certificate here (the assembler's key from --root-home) and submit it, instead of playing the members through the protocol")
	cmd.Flags().DurationVar(&wait, "assembly-wait", 2*time.Minute, "how long to wait for the committed view's assembler root to assemble")
	_ = cmd.MarkFlagRequired("root-rpc")
	return cmd
}

// vrShardSink is the paired shard node's staged-successor endpoint (--vr-shard-rpc): the root posts the EVM node ids of the derived intent's
// successor to it. The endpoint is the shard node's local operator RPC, so only a loopback address is accepted; an empty URL gives none.
func vrShardSink(rawURL string) (func(ctx context.Context, ids []string) error, error) {
	if rawURL == "" {
		return nil, nil
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" || u.Host == "" {
		return nil, fmt.Errorf("%w: --vr-shard-rpc must be an http URL of the paired shard node's local RPC", ErrVRHandoffCmd)
	}
	if h := u.Hostname(); h != "127.0.0.1" && h != "localhost" && h != "::1" {
		return nil, fmt.Errorf("%w: --vr-shard-rpc must be a loopback address (the shard node's operator RPC is local-only), got %s", ErrVRHandoffCmd, h)
	}
	target := strings.TrimRight(rawURL, "/") + "/api/v1/vr/staged"
	client := &http.Client{Timeout: 3 * time.Second}
	return func(ctx context.Context, ids []string) error {
		body, err := json.Marshal(vrStagedRequest{IDs: ids})
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			raw, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			return fmt.Errorf("%w: the shard node refused the staged successor: %s: %s", ErrVRHandoffCmd, resp.Status, bytes.TrimSpace(raw))
		}
		return nil
	}, nil
}
