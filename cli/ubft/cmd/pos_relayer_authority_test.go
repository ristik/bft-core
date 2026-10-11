package cmd

import (
	"bytes"
	"context"
	"crypto"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/posrelayer"
	"github.com/unicitynetwork/bft-core/rootchain/evmstate/evmstatetest"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/signingauthority/service"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

// authorityHarness is a running signing authority for the validator "node-1" of the P85 lane's EVM shard, with both sockets served.
type authorityHarness struct {
	dir, operatorSock, credentialPath, nodeID string
	key                                       []byte
	op                                        *service.OperatorClient
	pdr                                       *bfttypes.PartitionDescriptionRecord
}

func newAuthorityHarness(t *testing.T) authorityHarness {
	dir := authoritySocketDir(t)
	rootSigner, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, rootSigner).(*bfttypes.RootTrustBaseV1)
	require.True(t, ok)
	installed := installedPDR(t)
	enrollHash, err := installed.Hash(crypto.SHA256)
	require.NoError(t, err)
	authority, err := signingauthority.New(signingauthority.Enrollment{AuthorityID: "a1", NodeID: "node-1", NetworkID: installed.NetworkID,
		PartitionID: installed.PartitionID, ShardID: installed.ShardID, ShardEpoch: installed.Epoch, RootEpoch: signingauthority.PinRootEpoch(1),
		ShardConfHash: enrollHash, Profile: signingauthority.ProfileLegacyBCRv1}, authorityTrust{tb: tb})
	require.NoError(t, err)
	t.Cleanup(authority.Close)
	operatorCredential, err := service.NewCredential()
	require.NoError(t, err)
	server, err := service.NewServer(authority, service.Config{OperatorCredential: operatorCredential})
	require.NoError(t, err)
	t.Cleanup(server.Close)
	operatorListener, err := service.ListenUnix(filepath.Join(dir, "operator.sock"))
	require.NoError(t, err)
	clientListener, err := service.ListenUnix(filepath.Join(dir, "client.sock"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = operatorListener.Close(); _ = clientListener.Close() })
	go func() { _ = server.Serve(operatorListener, service.OperatorEndpoint) }()
	go func() { _ = server.Serve(clientListener, service.ClientEndpoint) }()
	credentialPath := filepath.Join(dir, "operator.cred")
	require.NoError(t, writeCredentialFile(credentialPath, operatorCredential, false))
	key, err := authority.SigningPublicKey()
	require.NoError(t, err)
	op, err := openOperator(filepath.Join(dir, "operator.sock"), credentialPath)
	require.NoError(t, err)
	t.Cleanup(func() { _ = op.Close() })
	return authorityHarness{dir: dir, operatorSock: filepath.Join(dir, "operator.sock"), credentialPath: credentialPath, nodeID: "node-1", key: key, op: op, pdr: installed}
}

// An authority-backed validator's election possession proof comes from its signing authority (its key never leaves it) and is the proof the
// root's VerifyPrimary and `pos-relayer assemble` accept.
func TestPosRelayerSignPoPFromASigningAuthority(t *testing.T) {
	h := newAuthorityHarness(t)
	p := evmstatetest.Load(t, publicationFixture)
	c := p.Candidate
	pdr := &bfttypes.PartitionDescriptionRecord{Version: 1, NetworkID: h.pdr.NetworkID, PartitionID: h.pdr.PartitionID, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: h.pdr.T2Timeout, Epoch: h.pdr.Epoch + 1, Validators: []*bfttypes.NodeInfo{{NodeID: h.nodeID, SigKey: h.key, Stake: 1}}}
	var err error
	c.Assignment, err = bfttypes.Cbor.Marshal(pdr)
	require.NoError(t, err)
	c.Network, c.Predecessor = uint64(h.pdr.NetworkID), bytes.Repeat([]byte{1}, 32)
	c.Identities = append([]evmassign.Identity(nil), c.Identities...)
	c.Identities[0].EVMKey, c.Identities[0].EVMNodeID = h.key, h.nodeID
	ctx, err := c.PoPContext()
	require.NoError(t, err)
	pop, err := h.op.SignHandoffPoP(context.Background(), signingauthority.HandoffPoPRequest{Domain: evmassign.PoPDomain, NodeID: h.nodeID, Successor: pdr, Context: ctx})
	require.NoError(t, err)
	c.PoPs = []evmassign.PoP{pop}
	enc, err := c.Encode()
	require.NoError(t, err)
	candidateFile := filepath.Join(h.dir, "candidate.hex")
	require.NoError(t, os.WriteFile(candidateFile, []byte(hex.EncodeToString(enc)), 0o600))
	deployment := writeJSON(t, h.dir, "pos-deployment.json", map[string]string{
		"networkWord": hexutil.Encode(p.Deployment.NetworkWord[:]), "chainId": "31337", "custody": hexutil.Encode(p.Deployment.Custody[:]),
		"custodyCodeHash": "0x" + hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32)), "registry": "0xff00000000000000000000000000000000000002",
		"registryCodeHash": "0x" + hex.EncodeToString(bytes.Repeat([]byte{0xbb}, 32)), "election": hexutil.Encode(p.Deployment.Election[:]),
		"electionCodeHash": "0x" + hex.EncodeToString(bytes.Repeat([]byte{0xcc}, 32))})

	run := func(args ...string) (string, error) {
		var out bytes.Buffer
		cmd := newPosRelayerCmd()
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetArgs(args)
		err := cmd.Execute()
		return out.String(), err
	}
	out := filepath.Join(h.dir, "pop.json")
	_, err = run("sign-pop", "--candidate", candidateFile, "--pos-deployment", deployment, "--attempt", "3", "--out", out,
		"--authority-socket", h.operatorSock, "--authority-credential", h.credentialPath)
	require.NoError(t, err)
	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	var j popJSON
	require.NoError(t, json.Unmarshal(raw, &j))
	got, err := j.pop()
	require.NoError(t, err)
	digest, id, err := evmassign.ElectionPoPDigest(c, evmassign.ElectionDeployment{Deployment: evmassign.Deployment{NetworkWord: p.Deployment.NetworkWord,
		ChainID: [32]byte{30: 0x7a, 31: 0x69}, Custody: p.Deployment.Custody}, Election: p.Deployment.Election}, 3, h.key, h.nodeID)
	require.NoError(t, err)
	require.Equal(t, id, got.ID)
	rec := append([]byte(nil), got.Signature...)
	rec[64] -= 27
	pub, err := ethcrypto.SigToPub(digest[:], rec)
	require.NoError(t, err)
	require.Equal(t, h.key, ethcrypto.CompressPubkey(pub), "the proof is the authority's key over the election's possession digest")

	t.Run("a key file and the authority flags together are refused", func(t *testing.T) {
		keyFile := filepath.Join(h.dir, "k")
		require.NoError(t, os.WriteFile(keyFile, []byte("00"), 0o600))
		_, err := run("sign-pop", "--candidate", candidateFile, "--pos-deployment", deployment, "--evm-key-file", keyFile,
			"--authority-socket", h.operatorSock, "--authority-credential", h.credentialPath)
		require.ErrorIs(t, err, errBothKeyHolders)
	})
	t.Run("the client socket is not the operator channel", func(t *testing.T) {
		_, err := run("sign-pop", "--candidate", candidateFile, "--pos-deployment", deployment, "--attempt", "3",
			"--authority-socket", filepath.Join(h.dir, "client.sock"), "--authority-credential", h.credentialPath)
		require.ErrorIs(t, err, service.ErrWrongEndpoint)
	})
	t.Run("a candidate that does not name this validator's key is refused by the authority", func(t *testing.T) {
		other := c
		other.Identities = append([]evmassign.Identity(nil), c.Identities...)
		other.Identities[0].EVMNodeID = "someone-else"
		enc, err := other.Encode()
		require.NoError(t, err)
		f := filepath.Join(h.dir, "other.hex")
		require.NoError(t, os.WriteFile(f, []byte(hex.EncodeToString(enc)), 0o600))
		_, err = run("sign-pop", "--candidate", f, "--pos-deployment", deployment, "--attempt", "3",
			"--authority-socket", h.operatorSock, "--authority-credential", h.credentialPath)
		require.ErrorIs(t, err, signingauthority.ErrContextMismatch)
	})
}

// A joiner whose EVM key lives in a signing authority is admitted with the authority's delegation possession: the transaction carries the
// authority's signature over the delegation digest, and the owner's.
func TestPosRelayerJoinAdmitsWithAnAuthorityHeldEVMKey(t *testing.T) {
	h := newAuthorityHarness(t)
	ownerKey, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	rootKey, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	joinerPath := writeJSON(t, h.dir, "joiner.json", map[string]any{"ownerKey": hexutil.Encode(ethcrypto.FromECDSA(ownerKey)),
		"rootKey": hexutil.Encode(ethcrypto.FromECDSA(rootKey)), "withdrawal": "0x00000000000000000000000000000000000000a1", "payee": "0x00000000000000000000000000000000000000a2",
		"rootNodeId": "root-joiner", "evmNodeId": h.nodeID, "expiry": 1_000_000_000})
	p := evmstatetest.Load(t, publicationFixture)
	deployment := writeJSON(t, h.dir, "pos-deployment.json", map[string]string{
		"networkWord": hexutil.Encode(p.Deployment.NetworkWord[:]), "chainId": "31337", "custody": hexutil.Encode(p.Deployment.Custody[:]),
		"custodyCodeHash": "0x" + hex.EncodeToString(bytes.Repeat([]byte{0xaa}, 32)), "registry": "0xff00000000000000000000000000000000000002",
		"registryCodeHash": "0x" + hex.EncodeToString(bytes.Repeat([]byte{0xbb}, 32)), "election": hexutil.Encode(p.Deployment.Election[:]),
		"electionCodeHash": "0x" + hex.EncodeToString(bytes.Repeat([]byte{0xcc}, 32))})
	network := p.Deployment.NetworkWord

	// the execution client: it answers the onboarding's reads and mines what it is sent
	var sent []*types.Transaction
	var wantDigest [32]byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage   `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&req))
		var res any
		switch req.Method {
		case "eth_blockNumber":
			res = "0x2a"
		case "eth_call":
			var call struct{ Data string }
			require.NoError(t, json.Unmarshal(req.Params[0], &call))
			data, err := hexutil.Decode(call.Data)
			require.NoError(t, err)
			sel := hex.EncodeToString(data[:4])
			switch sel {
			case hex.EncodeToString(ethcrypto.Keccak256([]byte("network()"))[:4]):
				res = hexutil.Encode(network[:])
			case hex.EncodeToString(ethcrypto.Keccak256([]byte("registerNonce(address)"))[:4]), hex.EncodeToString(ethcrypto.Keccak256([]byte("nextStakingID()"))[:4]):
				res = hexutil.Encode(make([]byte, 32))
			default: // delegationDigest(request): the shim cannot compute the contract's; the test compares what was signed with evmassign's
				res = hexutil.Encode(wantDigest[:])
			}
		case "eth_getTransactionCount":
			res = "0x0"
		case "eth_getBlockByNumber":
			res = map[string]any{"baseFeePerGas": "0x3b9aca00"}
		case "eth_estimateGas":
			res = "0x30d40"
		case "eth_sendRawTransaction":
			var raw hexutil.Bytes
			require.NoError(t, json.Unmarshal(req.Params[0], &raw))
			tx := new(types.Transaction)
			require.NoError(t, tx.UnmarshalBinary(raw))
			sent = append(sent, tx)
			res = tx.Hash().Hex()
		case "eth_getTransactionReceipt":
			res = map[string]any{"status": "0x1"}
		default:
			t.Errorf("unexpected method %s", req.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": res})
	}))
	t.Cleanup(srv.Close)

	rootWord, err := evmassign.NodeIDWord("root-joiner")
	require.NoError(t, err)
	evmWord, err := evmassign.NodeIDWord(h.nodeID)
	require.NoError(t, err)
	req := evmassign.DelegationRequest{Id: 1, Generation: 1, Expiry: 1_000_000_000, Binding: evmassign.DelegationBinding{RootNodeID: rootWord,
		RootKey: ethcrypto.CompressPubkey(&rootKey.PublicKey), EvmNodeID: evmWord, EvmKey: h.key}}
	copy(req.Binding.OperatorPayee[:], hexutil.MustDecode("0x00000000000000000000000000000000000000a2"))
	wantDigest = evmassign.DelegationDigest(network, [32]byte{30: 0x7a, 31: 0x69}, p.Deployment.Election, req)

	var out bytes.Buffer
	cmd := newPosRelayerCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{"tx", "join", "admit", "--eth-rpc", srv.URL, "--pos-deployment", deployment, "--joiner", joinerPath, "--id", "1",
		"--evm-authority-socket", h.operatorSock, "--evm-authority-credential", h.credentialPath})
	require.NoError(t, cmd.Execute(), out.String())
	require.Len(t, sent, 1)
	require.Equal(t, p.Deployment.Election, [20]byte(*sent[0].To()))
	// the transaction carries the request, the owner's signature and the authority's: both recover over the delegation digest
	got, ownerSig, evmSig, err := posrelayer.DecodeAdmit(sent[0].Data())
	require.NoError(t, err)
	require.Equal(t, req, got)
	recoverKey := func(sig []byte) []byte {
		rec := append([]byte(nil), sig...)
		rec[64] -= 27
		pub, err := ethcrypto.SigToPub(wantDigest[:], rec)
		require.NoError(t, err)
		return ethcrypto.CompressPubkey(pub)
	}
	require.Equal(t, h.key, recoverKey(evmSig), "the EVM possession is the authority's")
	require.Equal(t, ethcrypto.CompressPubkey(&ownerKey.PublicKey), recoverKey(ownerSig), "the authorization is the owner's")
}
