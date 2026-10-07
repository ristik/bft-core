package cmd

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/identityfix"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

type successorKey struct {
	id   string
	conf KeyConf
	info *types.NodeInfo
}

func newSuccessorKey(t *testing.T, id string) successorKey {
	t.Helper()
	conf, err := generateKeys()
	require.NoError(t, err)
	signer, err := conf.Signer()
	require.NoError(t, err)
	v, err := signer.Verifier()
	require.NoError(t, err)
	pub, err := v.MarshalPublicKey()
	require.NoError(t, err)
	return successorKey{id: id, conf: *conf, info: &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1}}
}

func writeJSON(t *testing.T, dir, name string, v any) string {
	t.Helper()
	raw, err := json.MarshalIndent(v, "", "  ")
	require.NoError(t, err)
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func installedPDR(t *testing.T) *types.PartitionDescriptionRecord {
	t.Helper()
	old := newSuccessorKey(t, "ev-old")
	return &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 5 * time.Second, Epoch: 0, EpochStart: 1, PartitionParams: map[string]string{"seal_registry_genesis": "g"},
		Validators: []*types.NodeInfo{old.info}}
}

// identityFixture writes the identity records and the recovery authorization of a successor whose validators "ev-x" are the delegated
// EVM validators of root entities "r-x", and returns the files, the records and their digest. K is a fabricated incumbent.
func identityFixture(t *testing.T, dir string, installed *types.PartitionDescriptionRecord, succ *types.PartitionDescriptionRecord, predecessor []byte) (idsFile, authFile string, ids []evmassign.Identity, digest [32]byte) {
	t.Helper()
	var root []evmassign.RootMember
	var bindings []evmassign.Binding
	for i, v := range succ.Validators {
		id := "r-" + strings.TrimPrefix(v.NodeID, "ev-")
		root = append(root, evmassign.RootMember{NodeID: id, Key: bytes.Repeat([]byte{byte(0x30 + i)}, 33), Weight: v.Stake})
		bindings = append(bindings, evmassign.Binding{RootNodeID: id, EVMNodeID: v.NodeID})
	}
	ids = identityfix.Identities(root, succ, bindings)
	var err error
	digest, err = evmassign.IdentitiesDigest(ids)
	require.NoError(t, err)
	incumbent := identityfix.Identities([]evmassign.RootMember{{NodeID: "r-old", Key: bytes.Repeat([]byte{0x20}, 33), Weight: 1}}, installed,
		[]evmassign.Binding{{RootNodeID: "r-old", EVMNodeID: installed.Validators[0].NodeID}})
	incDigest, err := evmassign.IdentitiesDigest(incumbent)
	require.NoError(t, err)
	base, err := evmassign.AssignmentHash(installed, incDigest)
	require.NoError(t, err)
	auth := identityfix.Authorization(5, predecessor, base, incumbent)
	return writeJSON(t, dir, "identities.json", ids), writeJSON(t, dir, "authorization.json", auth), ids, digest
}

func TestEVMAssignmentCLIFlow(t *testing.T) {
	dir := t.TempDir()
	keys := []successorKey{newSuccessorKey(t, "ev-a"), newSuccessorKey(t, "ev-b"), newSuccessorKey(t, "ev-c")}
	infos := []*types.NodeInfo{keys[0].info, keys[1].info, keys[2].info}
	ctx := consensus.EVMAssignmentContext{Network: 5, Predecessor: bytes.Repeat([]byte{1}, 32), Attempt: 2, Installed: installedPDR(t)}
	contextFile := writeJSON(t, dir, "context.json", ctx)
	validatorsFile := writeJSON(t, dir, "validators.json", infos)
	// Validator-set changes are coupled: each successor root entity has one delegated EVM validator.
	bindingsFile := writeJSON(t, dir, "bindings.json", []evmassign.Binding{{RootNodeID: "r-a", EVMNodeID: "ev-a"}, {RootNodeID: "r-b", EVMNodeID: "ev-b"}, {RootNodeID: "r-c", EVMNodeID: "ev-c"}})
	flowSucc, err := evmassign.NewSuccessor(ctx.Installed, infos)
	require.NoError(t, err)
	identitiesFile, authorizationFile, _, identitiesDigest := identityFixture(t, dir, ctx.Installed, flowSucc, ctx.Predecessor)

	proofFiles := make([]string, 0, len(keys))
	for _, k := range keys {
		keyFile := writeJSON(t, dir, k.id+"-keys.json", k.conf)
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetArgs([]string{"handoff", "evm-pop", "--context", contextFile, "--validators", validatorsFile, "--node-id", k.id, "--key-conf", keyFile, "--identities", identitiesFile})
		require.NoError(t, cmd.Execute())
		path := filepath.Join(dir, k.id+"-pop.json")
		require.NoError(t, os.WriteFile(path, out.Bytes(), 0o600))
		proofFiles = append(proofFiles, path)
	}

	assignment := filepath.Join(dir, "assignment.json")
	var assembled bytes.Buffer
	cmd := newRootCmd()
	cmd.SetOut(&assembled)
	cmd.SetArgs([]string{"handoff", "evm-assemble", "--context", contextFile, "--validators", validatorsFile,
		"--pops", proofFiles[0] + "," + proofFiles[1] + "," + proofFiles[2], "--bindings", bindingsFile, "--out", assignment,
		"--identities", identitiesFile, "--authorization", authorizationFile})
	require.NoError(t, cmd.Execute())
	require.Contains(t, assembled.String(), "assignment epoch 1 for 3 validators")

	proposal, err := readEVMAssignment(assignment)
	require.NoError(t, err)
	succ, err := evmassign.NewSuccessor(ctx.Installed, proposal.Validators)
	require.NoError(t, err)
	_, pop, err := readContextFile(contextFile)
	require.NoError(t, err)
	pop.Identities = identitiesDigest
	require.NoError(t, evmassign.VerifyPoPs(pop, succ, proposal.PoPs), "the assembled proofs verify under the context they were signed for")

	t.Run("a key that is not the successor key cannot sign for the node", func(t *testing.T) {
		impostor := newSuccessorKey(t, "ev-a")
		keyFile := writeJSON(t, dir, "impostor-keys.json", impostor.conf)
		cmd := newRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"handoff", "evm-pop", "--context", contextFile, "--validators", validatorsFile, "--node-id", "ev-a", "--key-conf", keyFile, "--identities", identitiesFile})
		err := cmd.Execute()
		require.ErrorContains(t, err, "not the successor key")
	})
	t.Run("assembling refuses a missing proof", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"handoff", "evm-assemble", "--context", contextFile, "--validators", validatorsFile, "--pops", proofFiles[0] + "," + proofFiles[1], "--bindings", bindingsFile,
			"--identities", identitiesFile, "--authorization", authorizationFile})
		require.ErrorContains(t, cmd.Execute(), `no proof of possession for successor validator "ev-c"`)
	})
	t.Run("assembling refuses a proof signed for another context", func(t *testing.T) {
		other := ctx
		other.Attempt = 7
		otherContext := writeJSON(t, dir, "other-context.json", other)
		cmd := newRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"handoff", "evm-assemble", "--context", otherContext, "--validators", validatorsFile,
			"--pops", proofFiles[0] + "," + proofFiles[1] + "," + proofFiles[2], "--bindings", bindingsFile,
			"--identities", identitiesFile, "--authorization", authorizationFile})
		require.ErrorIs(t, cmd.Execute(), evmassign.ErrPoP)
	})
	t.Run("supersede needs a pending acknowledgement", func(t *testing.T) {
		cmd := newRootCmd()
		cmd.SetOut(&bytes.Buffer{})
		cmd.SetArgs([]string{"handoff", "evm-assemble", "--context", contextFile, "--validators", validatorsFile, "--supersede",
			"--pops", proofFiles[0] + "," + proofFiles[1] + "," + proofFiles[2], "--bindings", bindingsFile,
			"--identities", identitiesFile, "--authorization", authorizationFile})
		require.ErrorContains(t, cmd.Execute(), "pending")
	})
	t.Run("an assignment file must prove every successor key", func(t *testing.T) {
		short := writeJSON(t, dir, "short.json", evmassign.Proposal{Validators: infos, PoPs: proposal.PoPs[:2], Bindings: proposal.Bindings})
		_, err := readEVMAssignment(short)
		require.ErrorContains(t, err, "every successor key, retained ones included")
		unbound := writeJSON(t, dir, "unbound.json", evmassign.Proposal{Validators: infos, PoPs: proposal.PoPs})
		_, err = readEVMAssignment(unbound)
		require.ErrorContains(t, err, "root-entity bindings", "validator-set changes are always coupled")
		empty := writeJSON(t, dir, "empty.json", evmassign.Proposal{})
		_, err = readEVMAssignment(empty)
		require.ErrorContains(t, err, "no successor validators")
	})
}

func TestProposeCarriesTheEVMAssignmentToTheOperator(t *testing.T) {
	dir := t.TempDir()
	keys := []successorKey{newSuccessorKey(t, "ev-a"), newSuccessorKey(t, "ev-b")}
	succInfos := []*types.NodeInfo{keys[0].info, keys[1].info}
	installed := installedPDR(t)
	succ, err := evmassign.NewSuccessor(installed, succInfos)
	require.NoError(t, err)
	pop := evmassign.PoPContext{Network: 5, Attempt: 0, Predecessor: [32]byte{1}}
	_, _, propIDs, propDigest := identityFixture(t, dir, installed, succ, pop.Predecessor[:])
	pop.Identities = propDigest
	var proofs []evmassign.PoP
	for _, k := range keys {
		signer, err := k.conf.Signer()
		require.NoError(t, err)
		p, err := evmassign.SignPoP(signer, pop, succ, k.id)
		require.NoError(t, err)
		proofs = append(proofs, p)
	}
	bindings := []evmassign.Binding{{RootNodeID: "r-a", EVMNodeID: "ev-a"}, {RootNodeID: "r-b", EVMNodeID: "ev-b"}}
	_, propAuth, _, _ := identityFixture(t, dir, installed, succ, pop.Predecessor[:])
	var authorization evmassign.Authorization
	rawAuth, err := os.ReadFile(propAuth)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawAuth, &authorization))
	assignment := writeJSON(t, dir, "assignment.json", evmassign.Proposal{Validators: succ.Validators, PoPs: proofs, Bindings: bindings,
		Kind: evmassign.KindPrimary, Identities: propIDs, Authorization: &authorization})
	rootA, rootB := newSuccessorKey(t, "r-a"), newSuccessorKey(t, "r-b")
	nextFile := writeJSON(t, dir, "next.json", types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{rootA.info, rootB.info}})

	operator := &handoffOperatorStub{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rootHandoffPlanHandler(operator)(w, r) }))
	defer server.Close()

	cmd := newRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"handoff", "propose", "--next-trust-base", nextFile,
		"--root-rpc", server.URL, "--next-evm-assignment", assignment})
	require.NoError(t, cmd.Execute())
	require.Equal(t, 1, operator.evmCalls, "an assignment request reaches the EVM-capable operator entry point")
	require.NotNil(t, operator.proposal)
	require.Len(t, operator.proposal.PoPs, 2)
	require.Equal(t, hex.Bytes(proofs[0].Signature), operator.proposal.PoPs[0].Signature)

	// Without the flag the root-only entry point is used and no proposal is sent.
	operator = &handoffOperatorStub{}
	cmd = newRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetArgs([]string{"handoff", "propose", "--next-trust-base", nextFile, "--root-rpc", server.URL})
	require.NoError(t, cmd.Execute())
	require.Zero(t, operator.evmCalls)
}

type evmContextStub struct{ calls int }

func (s *evmContextStub) EVMAssignmentContext() (consensus.EVMAssignmentContext, error) {
	s.calls++
	return consensus.EVMAssignmentContext{Network: 5, Predecessor: bytes.Repeat([]byte{1}, 32)}, nil
}

func TestEVMContextEndpointIsLocalAndBounded(t *testing.T) {
	stub := &evmContextStub{}
	handler := rootHandoffEVMContextHandler(stub)
	post := func(addr, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/handoff/evm-assignment/context", bytes.NewBufferString(body))
		r.RemoteAddr = addr
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler(w, r)
		return w
	}
	require.Equal(t, http.StatusForbidden, post("192.0.2.1:1", `{}`).Code)
	require.Zero(t, stub.calls)
	require.Equal(t, http.StatusOK, post("127.0.0.1:1", `{}`).Code)
	require.Equal(t, 1, stub.calls, "the context names no EVM parent, so there is nothing to supply")
	_ = abcrypto.NewInMemorySecp256K1Signer
}

// The CLI refuses, before any endorsement, a proposal whose EVM participants are not the coupled image of the next committee.
func TestProposeRefusesAnUncoupledAssignment(t *testing.T) {
	dir := t.TempDir()
	keys := []successorKey{newSuccessorKey(t, "ev-a"), newSuccessorKey(t, "ev-b")}
	succ, err := evmassign.NewSuccessor(installedPDR(t), []*types.NodeInfo{keys[0].info, keys[1].info})
	require.NoError(t, err)
	rootA, rootB, rootC := newSuccessorKey(t, "r-a"), newSuccessorKey(t, "r-b"), newSuccessorKey(t, "r-c")
	good := []evmassign.Binding{{RootNodeID: "r-a", EVMNodeID: "ev-a"}, {RootNodeID: "r-b", EVMNodeID: "ev-b"}}
	next := writeJSON(t, dir, "next.json", types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{rootA.info, rootB.info}})
	grown := writeJSON(t, dir, "grown.json", types.RootTrustBaseV1{RootNodes: []*types.NodeInfo{rootA.info, rootB.info, rootC.info}})
	pops := make([]evmassign.PoP, 2)        // the CLI checks the coupling before it looks at the proofs
	shaped := make([]evmassign.Identity, 2) // and before it looks at the identity records
	for name, tc := range map[string]struct {
		next     string
		bindings []evmassign.Binding
	}{
		"a root entity without a binding": {grown, good},
		"a binding to an unknown EVM key": {next, []evmassign.Binding{{RootNodeID: "r-a", EVMNodeID: "ev-a"}, {RootNodeID: "r-b", EVMNodeID: "zz"}}},
	} {
		t.Run(name, func(t *testing.T) {
			assignment := writeJSON(t, dir, "a-"+strings.ReplaceAll(name, " ", "-")+".json", evmassign.Proposal{Validators: succ.Validators, PoPs: pops, Bindings: tc.bindings,
				Kind: evmassign.KindPrimary, Identities: shaped, Authorization: &evmassign.Authorization{}})
			operator := &handoffOperatorStub{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { rootHandoffPlanHandler(operator)(w, r) }))
			defer server.Close()
			cmd := newRootCmd()
			cmd.SetOut(&bytes.Buffer{})
			cmd.SetArgs([]string{"handoff", "propose", "--next-trust-base", tc.next,
				"--root-rpc", server.URL, "--next-evm-assignment", assignment})
			require.ErrorIs(t, cmd.Execute(), evmassign.ErrCoupling)
			require.Zero(t, operator.evmCalls, "nothing reaches the operator")
		})
	}
}

// An aggregator node-key replacement from the operator's side: each new key proves possession against the aggregator shard's
// installed configuration, shard-assemble builds the change (validators only), and evm-assemble carries it in the proposal.
func TestShardKeyReplacementCLIFlow(t *testing.T) {
	dir := t.TempDir()
	evmKeys := []successorKey{newSuccessorKey(t, "ev-a"), newSuccessorKey(t, "ev-b")}
	evmInfos := []*types.NodeInfo{evmKeys[0].info, evmKeys[1].info}
	ctx := consensus.EVMAssignmentContext{Network: 5, Predecessor: bytes.Repeat([]byte{1}, 32), Attempt: 2, Installed: installedPDR(t)}
	contextFile := writeJSON(t, dir, "context.json", ctx)
	_, pop, err := readContextFile(contextFile)
	require.NoError(t, err)

	oldAgg := newSuccessorKey(t, "agg-old")
	aggregator := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: 0, EpochStart: 1, PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"},
		Validators: []*types.NodeInfo{oldAgg.info}}
	installedFile := writeJSON(t, dir, "aggregator-installed.json", aggregator)
	newAgg := newSuccessorKey(t, "agg-new")
	aggValidators := writeJSON(t, dir, "agg-validators.json", []*types.NodeInfo{newAgg.info})

	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		cmd := newRootCmd()
		cmd.SetOut(&out)
		cmd.SetArgs(append([]string{"handoff"}, args...))
		err := cmd.Execute()
		return out.String(), err
	}
	keyFile := writeJSON(t, dir, "agg-new-keys.json", newAgg.conf)
	popOut, err := run("evm-pop", "--context", contextFile, "--validators", aggValidators, "--node-id", "agg-new", "--key-conf", keyFile, "--installed", installedFile)
	require.NoError(t, err)
	aggPop := filepath.Join(dir, "agg-new-pop.json")
	require.NoError(t, os.WriteFile(aggPop, []byte(popOut), 0o600))

	changeFile := filepath.Join(dir, "change.json")
	out, err := run("shard-assemble", "--context", contextFile, "--installed", installedFile, "--validators", aggValidators, "--pops", aggPop, "--out", changeFile)
	require.NoError(t, err)
	require.Contains(t, out, "partition 9 shard epoch 1 for 1 validators")

	t.Run("a proof for another key is refused", func(t *testing.T) {
		other := newSuccessorKey(t, "agg-new")
		_, err := run("evm-pop", "--context", contextFile, "--validators", aggValidators, "--node-id", "agg-new",
			"--key-conf", writeJSON(t, dir, "impostor.json", other.conf), "--installed", installedFile)
		require.ErrorContains(t, err, "not the successor key")
	})
	t.Run("a missing proof is refused", func(t *testing.T) {
		two := writeJSON(t, dir, "two.json", []*types.NodeInfo{newAgg.info, oldAgg.info})
		_, err := run("shard-assemble", "--context", contextFile, "--installed", installedFile, "--validators", two, "--pops", aggPop)
		require.ErrorContains(t, err, "no proof of possession")
	})

	// The change rides in the EVM assignment's proposal.
	evmValidators := writeJSON(t, dir, "validators.json", evmInfos)
	evmSucc, err := evmassign.NewSuccessor(ctx.Installed, evmInfos)
	require.NoError(t, err)
	evmIdentities, evmAuthorization, _, _ := identityFixture(t, dir, ctx.Installed, evmSucc, ctx.Predecessor)
	evmPops := make([]string, 0, 2)
	for _, k := range evmKeys {
		o, err := run("evm-pop", "--context", contextFile, "--validators", evmValidators, "--node-id", k.id, "--key-conf", writeJSON(t, dir, k.id+"-k.json", k.conf),
			"--identities", evmIdentities)
		require.NoError(t, err)
		path := filepath.Join(dir, k.id+"-pop.json")
		require.NoError(t, os.WriteFile(path, []byte(o), 0o600))
		evmPops = append(evmPops, path)
	}
	bindings := writeJSON(t, dir, "bindings.json", []evmassign.Binding{{RootNodeID: "r-a", EVMNodeID: "ev-a"}, {RootNodeID: "r-b", EVMNodeID: "ev-b"}})
	assignment := filepath.Join(dir, "assignment.json")
	_, err = run("evm-assemble", "--context", contextFile, "--validators", evmValidators, "--pops", strings.Join(evmPops, ","),
		"--bindings", bindings, "--changes", changeFile, "--out", assignment, "--identities", evmIdentities, "--authorization", evmAuthorization)
	require.NoError(t, err)
	proposal, err := readEVMAssignment(assignment)
	require.NoError(t, err)
	require.Len(t, proposal.Changes, 1)
	decoded, err := evmassign.ValidateChanges(proposal.Changes, nil, pop, 0x7fff)
	require.NoError(t, err)
	require.NoError(t, evmassign.VerifyChangeInstalled(decoded[0], aggregator))

	t.Run("a supersession carries no changes", func(t *testing.T) {
		pending := ctx
		pending.Pending = true
		pendingFile := writeJSON(t, dir, "pending-context.json", pending)
		_, err := run("evm-assemble", "--context", pendingFile, "--validators", evmValidators, "--pops", strings.Join(evmPops, ","),
			"--bindings", bindings, "--changes", changeFile, "--supersede", "--out", filepath.Join(dir, "x.json"),
			"--identities", evmIdentities, "--authorization", evmAuthorization)
		require.ErrorContains(t, err, "no aggregator changes")
	})
}
