package cmd

// The end-to-end check of `ubft validator` against the real ValidatorRegistry, PoaElection and FoundationMultisig bytecode: the VR
// genesis alloc of VT-14's plan (unicity-pos-contracts script/vr-genesis.sh over testdata/validator-e2e/input.json, whose genesis owner
// of identity 1 and whose five multisig signers are the deterministic test keys below), loaded into anvil, with the test's MockSeal
// (unicity-pos-contracts test/vr/VRMocks.sol) as the SealRegistry clock at 0xff..02.
//
//	UBFT_VALIDATOR_E2E_ANVIL=$(which anvil) go test ./cli/ubft/cmd -run TestValidatorE2E -v
//
// It covers apply -> (Foundation multisig Admit, by the test helper) -> status Admitted, an exit of an Active genesis member, the
// owner's refusal to exit while Admitted, and a key rotation verified by VR's own KeyLib. To regenerate the fixture:
//
//	UBFT_VALIDATOR_E2E_INPUT=<dir> go test ./cli/ubft/cmd -run TestValidatorE2EInput   # writes <dir>/input.json
//	unicity-pos-contracts$ script/vr-genesis.sh <dir>/input.json <dir>                     # writes alloc.json, deployment.json

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient"
)

func e2eKey(t *testing.T, name string) *ecdsa.PrivateKey {
	k, err := ethcrypto.ToECDSA(ethcrypto.Keccak256([]byte("unicity.vt10.e2e/" + name)))
	require.NoError(t, err)
	return k
}

func e2eAddr(t *testing.T, name string) string {
	return strings.ToLower(ethcrypto.PubkeyToAddress(e2eKey(t, name).PublicKey).Hex())
}

// TestValidatorE2EInput writes the genesis plan input of the fixture (the format `ubft vr-genesis plan` writes; VT-14).
func TestValidatorE2EInput(t *testing.T) {
	dir := os.Getenv("UBFT_VALIDATOR_E2E_INPUT")
	if dir == "" {
		t.Skip("set UBFT_VALIDATOR_E2E_INPUT to regenerate the fixture input")
	}
	var signers []string
	for i := 1; i <= 5; i++ {
		signers = append(signers, e2eAddr(t, fmt.Sprintf("signer-%d", i)))
	}
	sort.Strings(signers)
	var ids []map[string]any
	for i := 1; i <= 4; i++ {
		rk, ek := e2eKey(t, fmt.Sprintf("root-%d", i)), e2eKey(t, fmt.Sprintf("evm-%d", i))
		ids = append(ids, map[string]any{"id": i, "owner": e2eAddr(t, fmt.Sprintf("owner-%d", i)), "rootNodeID": fmt.Sprintf("e2e-root-%d", i),
			"rootKey": hexutil.Encode(ethcrypto.CompressPubkey(&rk.PublicKey)), "evmNodeID": fmt.Sprintf("e2e-evm-%d", i),
			"evmKey": hexutil.Encode(ethcrypto.CompressPubkey(&ek.PublicKey)), "payee": e2eAddr(t, fmt.Sprintf("payee-%d", i)), "rawWeight": 1})
	}
	in := map[string]any{"format": "unicity.vr.genesis-input.v1", "chainId": 3,
		"network": hexutil.Encode(ethcrypto.Keccak256([]byte("unicity.vt10.e2e/network"))), "governorSigners": signers,
		"limits":         map[string]any{"nMin": 4, "nTarget": 4, "nMax": 16, "vMax": 16, "lMax": 1, "rMax": 4, "maxBatch": 32},
		"knownRootEpoch": 1, "epochStartProgress": 0,
		"fees":   map[string]any{"baseFeeFloor": 1000000, "changeDenominator": 8, "feeCollector": "0x00000000000000000000000000000000000000fe"},
		"maxGas": 184729388, "systemGas": 124729388, "continuity": map[string]any{"maxM": 4, "distNum": 1, "distDen": 2},
		"identityCount": 4, "identities": ids}
	b, err := json.MarshalIndent(in, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "input.json"), append(b, '\n'), 0o600))
}

var multisigABI = func() abi.ABI {
	a, err := abi.JSON(strings.NewReader(`[
 {"type":"function","name":"execute","stateMutability":"nonpayable","inputs":[{"name":"target","type":"address"},{"name":"data","type":"bytes"},{"name":"sigs","type":"bytes[]"}],"outputs":[]},
 {"type":"function","name":"callDigest","stateMutability":"view","inputs":[{"name":"target","type":"address"},{"name":"data","type":"bytes"},{"name":"nonce_","type":"uint64"}],"outputs":[{"name":"","type":"bytes32"}]},
 {"type":"function","name":"nonce","stateMutability":"view","inputs":[],"outputs":[{"name":"","type":"uint64"}]},
 {"type":"function","name":"setClock","stateMutability":"nonpayable","inputs":[{"name":"p","type":"uint64"},{"name":"t","type":"uint64"}],"outputs":[]}]`))
	if err != nil {
		panic(err)
	}
	return a
}()

type anvilChain struct {
	t   *testing.T
	url string
	rpc *rpc.Client
	vr  *vrclient.Client
	// payer sends the helper's transactions (the Foundation's submitter, the clock)
	payer vrclient.Sender
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func startAnvil(t *testing.T, bin string) *anvilChain {
	port := freePort(t)
	cmd := exec.Command(bin, "--port", fmt.Sprint(port), "--chain-id", "3", "--hardfork", "cancun", "--silent") // #nosec G204 -- test tool
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	var c *rpc.Client
	require.Eventually(t, func() bool {
		var err error
		if c, err = rpc.Dial(url); err != nil {
			return false
		}
		var n hexutil.Uint64
		return c.Call(&n, "eth_blockNumber") == nil
	}, 20*time.Second, 100*time.Millisecond)
	a := &anvilChain{t: t, url: url, rpc: c, vr: vrclient.New(c, vrclient.DefaultRegistry)}
	a.payer = vrclient.Sender{RPC: c, Key: e2eKey(t, "payer"), ChainID: big.NewInt(3), Poll: 50 * time.Millisecond}
	a.fund(a.payer.From())
	return a
}

func (a *anvilChain) fund(addr ethcommon.Address) {
	require.NoError(a.t, a.rpc.Call(nil, "anvil_setBalance", addr, hexutil.EncodeBig(big.NewInt(1e18))))
}

// load writes the fixture's alloc and the MockSeal clock into the chain.
func (a *anvilChain) load(dir string) {
	raw, err := os.ReadFile(filepath.Join(dir, "alloc.json"))
	require.NoError(a.t, err)
	var alloc map[string]struct {
		Code    string            `json:"code"`
		Nonce   string            `json:"nonce"`
		Storage map[string]string `json:"storage"`
	}
	require.NoError(a.t, json.Unmarshal(raw, &alloc))
	require.Len(a.t, alloc, 7)
	for addr, acct := range alloc {
		require.NoError(a.t, a.rpc.Call(nil, "anvil_setCode", addr, acct.Code))
		if acct.Nonce != "" && acct.Nonce != "0x0" {
			require.NoError(a.t, a.rpc.Call(nil, "anvil_setNonce", addr, acct.Nonce))
		}
		for k, v := range acct.Storage {
			require.NoError(a.t, a.rpc.Call(nil, "anvil_setStorageAt", addr, k, ethcommon.HexToHash(v)))
		}
	}
	seal, err := os.ReadFile(filepath.Join(dir, "mockseal.hex"))
	require.NoError(a.t, err)
	require.NoError(a.t, a.rpc.Call(nil, "anvil_setCode", vrclient.DefaultSealRegistry, strings.TrimSpace(string(seal))))
	a.setClock(5000, uint64(time.Now().Unix()))
}

// sendRaw sends a helper transaction that the CLI's decoder does not know (multisig, MockSeal), with its own estimate.
func (a *anvilChain) sendRaw(to ethcommon.Address, data []byte) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var gas hexutil.Uint64
	err := a.rpc.CallContext(ctx, &gas, "eth_estimateGas", map[string]any{"from": a.payer.From(), "to": to, "data": hexutil.Bytes(data)})
	require.NoError(a.t, vrclient.WrapRevert(err))
	p := vrclient.Plan{From: a.payer.From(), Tx: vrclient.Tx{To: to, Data: data}, Gas: uint64(gas), Tip: big.NewInt(1e9), FeeCap: big.NewInt(100e9)}
	_, _, err = a.payer.Send(ctx, p)
	require.NoError(a.t, err)
}

func (a *anvilChain) setClock(progress, ucTime uint64) {
	data, err := multisigABI.Pack("setClock", progress, ucTime)
	require.NoError(a.t, err)
	a.sendRaw(vrclient.DefaultSealRegistry, data)
}

// admit is the Foundation's side, as a test helper: three of the five signers approve VR.queue(ModuleAction(Admit, id)) through the
// FoundationMultisig, the clock passes both governance delays, and anyone executes the change.
func (a *anvilChain) admit(id uint64) {
	ctx := context.Background()
	cfg, err := a.vr.Config(ctx)
	require.NoError(a.t, err)
	mod, err := a.vr.ActiveModule(ctx)
	require.NoError(a.t, err)
	payload, err := vrclient.EncodeModuleAction(mod.Module, vrclient.ActionAdmit, id)
	require.NoError(a.t, err)
	queue, err := vrclient.VRABI.Pack("queue", vrclient.KindModuleAction, payload)
	require.NoError(a.t, err)
	gov := cfg.Governor
	var nonceRet hexutil.Bytes
	nd, _ := multisigABI.Pack("nonce")
	require.NoError(a.t, a.rpc.Call(&nonceRet, "eth_call", map[string]any{"to": gov, "data": hexutil.Bytes(nd)}, "latest"))
	nonce := new(big.Int).SetBytes(nonceRet).Uint64()
	dd, _ := multisigABI.Pack("callDigest", a.vr.Registry, queue, nonce)
	var digestRet hexutil.Bytes
	require.NoError(a.t, a.rpc.Call(&digestRet, "eth_call", map[string]any{"to": gov, "data": hexutil.Bytes(dd)}, "latest"))
	var digest [32]byte
	copy(digest[:], digestRet)
	type sig struct {
		addr ethcommon.Address
		sig  []byte
	}
	var sigs []sig
	for _, n := range []int{2, 4, 5} {
		k := e2eKey(a.t, fmt.Sprintf("signer-%d", n))
		s, err := vrclient.SignDigest(k, digest)
		require.NoError(a.t, err)
		sigs = append(sigs, sig{ethcrypto.PubkeyToAddress(k.PublicKey), s})
	}
	sort.Slice(sigs, func(i, j int) bool { return strings.ToLower(sigs[i].addr.Hex()) < strings.ToLower(sigs[j].addr.Hex()) })
	var raw [][]byte
	for _, s := range sigs {
		raw = append(raw, s.sig)
	}
	exec, err := multisigABI.Pack("execute", a.vr.Registry, queue, raw)
	require.NoError(a.t, err)
	a.sendRaw(gov, exec)
	pending, err := a.vr.PendingChanges(ctx)
	require.NoError(a.t, err)
	require.NotEmpty(a.t, pending)
	changeID := pending[len(pending)-1]
	ch, err := a.vr.Change(ctx, changeID)
	require.NoError(a.t, err)
	require.Equal(a.t, vrclient.KindModuleAction, ch.Kind)
	a.setClock(ch.NotBeforeProgress, ch.NotBeforeTime)
	ex, err := vrclient.VRABI.Pack("execute", changeID)
	require.NoError(a.t, err)
	a.sendRaw(a.vr.Registry, ex)
	ch, err = a.vr.Change(ctx, changeID)
	require.NoError(a.t, err)
	require.Equal(a.t, "Active", vrclient.ChangeState(ch.State), "the ModuleAction executed into the module")
}

func TestValidatorE2E(t *testing.T) {
	bin := os.Getenv("UBFT_VALIDATOR_E2E_ANVIL")
	if bin == "" {
		t.Skip("set UBFT_VALIDATOR_E2E_ANVIL to the anvil binary to run the end-to-end check")
	}
	fixture := filepath.Join("testdata", "validator-e2e")
	a := startAnvil(t, bin)
	a.load(fixture)

	// the genesis as VT-14 planned it: four Active members, PoaElection active
	ctx := context.Background()
	committee, err := a.vr.Committee(ctx)
	require.NoError(t, err)
	require.Len(t, committee, 4)

	home := initHome(t, a.url)
	_, keys := loadHome(t, home)
	a.fund(ethcrypto.PubkeyToAddress(keys.Operator.PublicKey))

	out, err := runValidator(t, home, "status")
	require.NoError(t, err, out)
	t.Logf("status before apply:\n%s", out)
	require.Contains(t, out, "committee: root epoch 1, 4 members [1 2 3 4]")

	out, err = runValidator(t, home, "apply", "--dry-run")
	require.NoError(t, err, out)
	t.Logf("apply --dry-run:\n%s", out)
	require.Contains(t, out, "apply identity 5 (predicted)")

	out, err = runValidator(t, home, "apply")
	require.NoError(t, err, out)
	t.Logf("apply:\n%s", out)
	require.Equal(t, uint64(5), readConfig(t, home).ID)

	out, err = runValidator(t, home, "status")
	require.NoError(t, err, out)
	require.Contains(t, out, "PoA state   Applied")

	a.admit(5)
	out, err = runValidator(t, home, "status")
	require.NoError(t, err, out)
	t.Logf("status after Admit:\n%s", out)
	require.Contains(t, out, "PoA state   Admitted")
	require.Contains(t, out, "local keys  match the current binding")

	_, err = runValidator(t, home, "exit", "--dry-run")
	require.ErrorContains(t, err, "ask the Foundation for ModuleAction Remove")

	// rotation: VR's KeyLib verifies both binding PoPs
	newEVM := filepath.Join(t.TempDir(), "keys.json")
	_, _, err = ensureKeyConf(newEVM)
	require.NoError(t, err)
	out, err = runValidator(t, home, "rotate", "--new-evm-keys", newEVM)
	require.NoError(t, err, out)
	t.Logf("rotate:\n%s", out)
	idn, err := a.vr.Identity(ctx, 5)
	require.NoError(t, err)
	require.NotEqual(t, [32]byte{}, idn.StagedRef)

	// the exit of an Active member: the genesis owner of identity 1, with its own operator key
	ownerKey := filepath.Join(t.TempDir(), "owner-1.key")
	require.NoError(t, os.WriteFile(ownerKey, []byte(hexutil.Encode(ethcrypto.FromECDSA(e2eKey(t, "owner-1")))), 0o600))
	home1 := initHome(t, a.url, "--operator-key", ownerKey, "--id", "1")
	a.fund(ethcrypto.PubkeyToAddress(e2eKey(t, "owner-1").PublicKey))
	out, err = runValidator(t, home1, "exit", "--dry-run")
	require.NoError(t, err, out)
	require.Contains(t, out, "PoaElection.requestExit(")
	out, err = runValidator(t, home1, "exit")
	require.NoError(t, err, out)
	t.Logf("exit of identity 1:\n%s", out)
	out, err = runValidator(t, home1, "status")
	require.NoError(t, err, out)
	t.Logf("status of identity 1 after exit:\n%s", out)
	require.Contains(t, out, "PoA state   ExitRequested")
	require.Contains(t, out, "member      true")
}
