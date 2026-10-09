package cmd

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/spf13/cobra"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-go-base/types"
)

const publicationFixture = "../../../rootchain/evmstate/testdata/publication.json"

func letter(id uint64) string { return string(rune('a' + id - 1)) }

// electionRPC serves eth_call from what the real modules answered (the contracts' publication fixture). The contracts hold only
// keccak256(peer id) for a node id and the fixture's own words were never derived from peer ids, so the delegations' two node-id words are
// replaced by the words of the test's peer ids ("r-a", "ev-a", ...); nothing else in an answer is touched.
func electionRPC(t *testing.T) (*httptest.Server, map[string]int) {
	raw, err := os.ReadFile(publicationFixture)
	require.NoError(t, err)
	var fx struct {
		RelayerReads []struct{ To, Data, Ret string }
	}
	require.NoError(t, json.Unmarshal(raw, &fx))
	reads := map[string][]byte{}
	for _, c := range fx.RelayerReads {
		ret, err := hex.DecodeString(strings.TrimPrefix(c.Ret, "0x"))
		require.NoError(t, err)
		data, err := hex.DecodeString(strings.TrimPrefix(c.Data, "0x"))
		require.NoError(t, err)
		if len(data) == 4+64 && len(ret) > 160 && bytes.Equal(data[4:4+24], make([]byte, 24)) { // delegation(id, generation)
			id := binary.BigEndian.Uint64(data[4+24 : 4+32])
			off := int(binary.BigEndian.Uint64(ret[24:32]))
			rootWord, evmWord := ret[off:off+32], ret[off+64:off+96]
			newRoot, err := evmassign.NodeIDWord("r-" + letter(id))
			require.NoError(t, err)
			newEVM, err := evmassign.NodeIDWord("ev-" + letter(id))
			require.NoError(t, err)
			copy(rootWord, newRoot[:])
			copy(evmWord, newEVM[:])
		}
		reads[strings.ToLower(c.To)+strings.ToLower(c.Data)] = ret
	}
	asked := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		require.Equal(t, "eth_call", req.Method)
		var call struct{ To, Data string }
		require.NoError(t, json.Unmarshal(req.Params[0], &call))
		key := strings.ToLower(call.To) + strings.ToLower(call.Data)
		asked[key]++
		ret, ok := reads[key]
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32000, "message": "execution reverted"}})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": "0x" + hex.EncodeToString(ret)})
	}))
	t.Cleanup(srv.Close)
	return srv, asked
}

// The relayer's builder end to end through the real commands: `pos-relayer proposal` reads the published result from an execution client,
// `root handoff evm-pop` signs the H3 possession proofs over the identities it wrote, `evm-assemble --evm-pops` assembles the proposal, and
// the proposal's identity records and recovery authorization are accepted by the real VerifyPrimary against the facts proven from state.
func TestPosRelayerProposalFeedsTheHandoffPipelineAndVerifyPrimaryAcceptsIt(t *testing.T) {
	p := evmstatetest.Load(t, publicationFixture)
	dir := t.TempDir()
	srv, asked := electionRPC(t)

	// the root's view: K is the committee of the acknowledged configuration
	k := p.Candidate.Authorization.K
	var infos []*types.NodeInfo
	for i, x := range k {
		infos = append(infos, &types.NodeInfo{NodeID: "ev-" + letter(uint64(i+1)), SigKey: x.EVMKey, Stake: x.Weight})
	}
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 5 * time.Second, Epoch: 0, EpochStart: 1, Validators: infos}
	ctx := consensus.EVMAssignmentContext{Network: 5, Predecessor: bytes.Repeat([]byte{1}, 32), Attempt: 2, Installed: pdr, Acknowledged: pdr}
	contextFile := writeJSON(t, dir, "context.json", ctx)
	deployment := writeJSON(t, dir, "pos-deployment.json", map[string]string{
		"networkWord": "0x" + hex.EncodeToString(p.Pins.NetworkWord[:]), "chainId": "31337",
		"custody": "0x" + hex.EncodeToString(p.Pins.Custody[:]), "custodyCodeHash": "0x" + strings.Repeat("aa", 32),
		"registry": "0xff00000000000000000000000000000000000002", "registryCodeHash": "0x" + strings.Repeat("bb", 32),
		"election": "0x" + hex.EncodeToString(p.Pins.Election[:]), "electionCodeHash": "0x" + strings.Repeat("cc", 32)})
	var ids []string
	for i := range k {
		ids = append(ids, "r-"+letter(uint64(i+1)), "ev-"+letter(uint64(i+1)))
	}
	popsFile := writeJSON(t, dir, "assembled-pops.json", map[string]any{"evmPops": func() []popJSON {
		var out []popJSON
		for _, x := range p.PoPs {
			out = append(out, toPoPJSON(x))
		}
		return out
	}()})

	out := filepath.Join(dir, "proposal")
	run := func(args ...string) (string, error) {
		var buf bytes.Buffer
		var cmd *cobra.Command
		if args[0] == "pos-relayer" {
			cmd, args = newPosRelayerCmd(), args[1:]
		} else {
			cmd, args = newRootCmd(), args[1:]
		}
		cmd.SetOut(&buf)
		cmd.SetErr(&buf)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return buf.String(), err
	}
	log, err := run("pos-relayer", "proposal", "--eth-rpc", srv.URL, "--pos-deployment", deployment, "--context", contextFile,
		"--node-ids", strings.Join(ids, ","), "--evm-pops", popsFile, "--out-dir", out)
	require.NoError(t, err, log)
	require.Contains(t, log, "4 members")
	for _, f := range []string{"identities.json", "authorization.json", "validators.json", "bindings.json", "evm-pops.json"} {
		require.FileExists(t, filepath.Join(out, f))
	}
	require.NotEmpty(t, asked, "the command read from the execution client")

	// H3 possession proofs over exactly these records, by the validators' keys (the fixture's EVM keys are 0x3000+i)
	validators := filepath.Join(out, "validators.json")
	var proofFiles []string
	for i := range k {
		conf, err := generateKeys()
		require.NoError(t, err)
		scalar := make([]byte, 32)
		binary.BigEndian.PutUint64(scalar[24:], uint64(0x3000+i))
		conf.SigKey.PrivateKey = scalar
		keyFile := writeJSON(t, dir, "k"+letter(uint64(i+1))+".json", conf)
		popFile := filepath.Join(dir, "pop-"+letter(uint64(i+1))+".json")
		res, err := run("root", "handoff", "evm-pop", "--context", contextFile, "--validators", validators, "--node-id", "ev-"+letter(uint64(i+1)),
			"--key-conf", keyFile, "--identities", filepath.Join(out, "identities.json"))
		require.NoError(t, err, res)
		require.NoError(t, os.WriteFile(popFile, []byte(res), 0o600))
		proofFiles = append(proofFiles, popFile)
	}
	assignment := filepath.Join(dir, "assignment.json")
	res, err := run("root", "handoff", "evm-assemble", "--context", contextFile, "--validators", validators, "--pops", strings.Join(proofFiles, ","),
		"--bindings", filepath.Join(out, "bindings.json"), "--identities", filepath.Join(out, "identities.json"),
		"--authorization", filepath.Join(out, "authorization.json"), "--evm-pops", filepath.Join(out, "evm-pops.json"), "--out", assignment)
	require.NoError(t, err, res)

	proposal, err := readEVMAssignment(assignment)
	require.NoError(t, err)
	require.EqualValues(t, evmassign.KindPrimary, proposal.Kind)
	require.Equal(t, p.PoPs, proposal.EVMPoPs, "the members' EVM possession proofs travel in the proposal, ordered by member")
	cand := evmassign.Candidate{Kind: evmassign.KindPrimary, Identities: proposal.Identities, Authorization: proposal.Authorization}
	require.NoError(t, evmassign.VerifyPrimary(cand, p.Deployment, p.Facts, proposal.EVMPoPs), "the assembled proposal is what the root's primary check accepts")

	t.Run("an EVM possession proof the election did not store is refused before anything is written", func(t *testing.T) {
		bad := make([]popJSON, 0, len(p.PoPs))
		for _, x := range p.PoPs {
			bad = append(bad, toPoPJSON(x))
		}
		bad[0].Signature = bad[1].Signature
		badFile := writeJSON(t, dir, "bad-pops.json", map[string]any{"evmPops": bad})
		outBad := filepath.Join(dir, "bad")
		_, err := run("pos-relayer", "proposal", "--eth-rpc", srv.URL, "--pos-deployment", deployment, "--context", contextFile,
			"--node-ids", strings.Join(ids, ","), "--evm-pops", badFile, "--out-dir", outBad)
		require.Error(t, err)
		require.NoDirExists(t, outBad)
	})
	t.Run("without the peer ids the node-id words cannot be resolved", func(t *testing.T) {
		_, err := run("pos-relayer", "proposal", "--eth-rpc", srv.URL, "--pos-deployment", deployment, "--context", contextFile, "--out-dir", filepath.Join(dir, "none"))
		require.Error(t, err)
		require.Contains(t, err.Error(), "node id")
	})
	t.Run("a deployment without the election cannot be read", func(t *testing.T) {
		plain := writeDeployment(t, deploymentJSON(goodWord, "1", goodCustody))
		_, err := run("pos-relayer", "proposal", "--eth-rpc", srv.URL, "--pos-deployment", plain, "--context", contextFile, "--out-dir", filepath.Join(dir, "none2"))
		require.ErrorIs(t, err, ErrPosRelayer)
	})
}
