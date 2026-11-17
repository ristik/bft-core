package vrclient

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
)

// schemaKey is vrschema's fixture key i (vrschema/gen.go genKey).
func schemaKey(t *testing.T, i int) NodeKeys {
	n := ethcrypto.S256().Params().N
	d := new(big.Int).SetBytes(ethcrypto.Keccak256([]byte(fmt.Sprintf("unicity.vr.schema.test-key/%d", i))))
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	k, err := ethcrypto.ToECDSA(d.FillBytes(make([]byte, 32)))
	require.NoError(t, err)
	return NodeKeys{Key: k}
}

type vector struct {
	Name   string         `json:"name"`
	Op     string         `json:"op"`
	Input  map[string]any `json:"input"`
	Expect map[string]any `json:"expect"`
}

func frozenVectors(t *testing.T) []vector {
	_, file, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "testvectors", "validator-registry", "encoding.json"))
	require.NoError(t, err)
	var f struct {
		Vectors []vector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	return f.Vectors
}

func hexIn(t *testing.T, v any) []byte {
	b, err := hexutil.Decode(v.(string))
	require.NoError(t, err)
	return b
}

func regOf(t *testing.T, in map[string]any) Registration {
	r := Registration{RootNodeID: in["rootNodeId"].(string), RootKey: hexIn(t, in["rootKey"]), EvmNodeID: in["evmNodeId"].(string),
		EvmKey: hexIn(t, in["evmKey"]), Payee: ethcommon.HexToAddress(in["payee"].(string))}
	if n, ok := in["nonce"].(float64); ok {
		r.Nonce = uint64(n)
	}
	return r
}

// TestFrozenRegistrationVectors runs the CLI's registration signer over the frozen schema vectors (bft-core testvectors/
// validator-registry/encoding.json): digest.register and digest.binding reproduce the digest and both PoPs byte for byte (the signer is
// deterministic), and every digest.registrationShape vector is refused by NewRegistration's shape check.
func TestFrozenRegistrationVectors(t *testing.T) {
	keyIndex := map[string][2]int{"digest.register": {2, 3}, "digest.binding": {14, 15}}
	pass := 0
	for _, v := range frozenVectors(t) {
		switch v.Op {
		case "digest.register", "digest.binding":
			r := regOf(t, v.Input)
			ki := keyIndex[v.Op]
			root, evm := schemaKey(t, ki[0]), schemaKey(t, ki[1])
			root.NodeID, evm.NodeID = r.RootNodeID, r.EvmNodeID
			require.Equal(t, r.RootKey, root.Public(), v.Name)
			require.Equal(t, r.EvmKey, evm.Public(), v.Name)
			chain := new(big.Int).SetBytes(hexIn(t, v.Input["chainId"]))
			var network [32]byte
			copy(network[:], hexIn(t, v.Input["network"]))
			d := Domain{Network: network, ChainID: chain, Registry: ethcommon.HexToAddress(v.Input["registry"].(string))}
			s, err := Sign(d, ethcommon.HexToAddress(v.Input["sender"].(string)), v.Op == "digest.binding", uint64(v.Input["id"].(float64)), r, root, evm)
			require.NoError(t, err, v.Name)
			require.Equal(t, v.Expect["digest"], hexutil.Encode(s.Digest[:]), v.Name)
			require.Equal(t, v.Expect["rootPoP"], hexutil.Encode(s.RootPoP), v.Name)
			require.Equal(t, v.Expect["evmPoP"], hexutil.Encode(s.EvmPoP), v.Name)
			pass++
		case "digest.registrationShape":
			r := regOf(t, v.Input)
			err := toSchema(r).ValidShape()
			require.Error(t, err, v.Name)
			require.Contains(t, err.Error(), v.Expect["error"].(string), v.Name)
			pass++
		}
	}
	require.Equal(t, 7, pass, "2 digest vectors and 5 shape vectors")
}

func TestDecodeCallAndRevert(t *testing.T) {
	root, evm := schemaKey(t, 2), schemaKey(t, 3)
	root.NodeID, evm.NodeID = "root-node", "evm-node"
	r, err := NewRegistration(root, evm, ethcommon.HexToAddress("0x9a00000000000000000000000000000000000001"), 0)
	require.NoError(t, err)
	s, err := Sign(Domain{ChainID: big.NewInt(3), Registry: DefaultRegistry}, ethcommon.HexToAddress("0xc000000000000000000000000000000000000003"), false, 0, r, root, evm)
	require.NoError(t, err)
	data, err := RegisterCalldata(s)
	require.NoError(t, err)
	c, err := DecodeCall(data)
	require.NoError(t, err)
	require.Equal(t, "ValidatorRegistry", c.Contract)
	require.Equal(t, "register", c.Method)
	out := c.String()
	require.Contains(t, out, `RootNodeID: "root-node"`)
	require.Contains(t, out, "rootPoP: 0x")
	require.Contains(t, out, "(65 bytes)")

	for _, m := range []string{MethodSubmitApplication, MethodWithdrawApplication, MethodRequestExit, MethodRejoin} {
		data, err := PoaCalldata(m, 5)
		require.NoError(t, err)
		c, err := DecodeCall(data)
		require.NoError(t, err)
		require.Equal(t, "PoaElection", c.Contract)
		require.Equal(t, m, c.Method)
		require.Equal(t, uint64(5), c.Args[0].Value)
	}
	_, err = PoaCalldata("elect", 1)
	require.Error(t, err)

	e := VRABI.Errors["RegistrationRefused"]
	arg, err := e.Inputs.Pack(uint8(6))
	require.NoError(t, err)
	rv := DecodeRevert(append(e.ID[:4:4], arg...))
	require.NotNil(t, rv)
	require.Equal(t, "RegistrationRefused(6): a key is already registered (keys are tombstoned for good across identities and roles)", rv.Error())
	be := PoaABI.Errors["BadState"]
	arg, err = be.Inputs.Pack(uint8(PoaAdmitted))
	require.NoError(t, err)
	require.True(t, strings.HasSuffix(DecodeRevert(append(be.ID[:4:4], arg...)).Error(), "not allowed in PoA state Admitted"))
	require.Nil(t, DecodeRevert([]byte{1, 2, 3, 4}))
}

// TestModuleActionPayload checks the payload codec against the frozen "ModuleAction Admit" and "ForceRemove" change.payload vectors.
func TestModuleActionPayload(t *testing.T) {
	var admit, force vector
	for _, v := range frozenVectors(t) {
		switch v.Name {
		case "ModuleAction Admit":
			admit = v
		case "ForceRemove":
			force = v
		}
	}
	require.Equal(t, "change.payload", admit.Op)
	vals := admit.Input["values"].([]any)
	inner := hexIn(t, vals[1])
	m := ethcommon.HexToAddress(vals[0].(string))
	id := new(big.Int).SetBytes(inner[32:64]).Uint64()
	p, err := EncodeModuleAction(m, ActionAdmit, id)
	require.NoError(t, err)
	require.Equal(t, admit.Expect["payload"], hexutil.Encode(p))
	a, ok := DecodeModuleAction(p)
	require.True(t, ok)
	require.Equal(t, ModuleAction{Module: m, Action: ActionAdmit, ID: id}, a)
	_, ok = DecodeModuleAction(p[:64])
	require.False(t, ok)
	_, ok = DecodeModuleAction(hexIn(t, force.Expect["payload"]))
	require.False(t, ok, "a ForceRemove payload is not a ModuleAction")
}

func TestNames(t *testing.T) {
	require.Equal(t, "Parked", PoaState(PoaParked))
	require.Equal(t, "state 10", PoaState(10))
	require.Equal(t, "ModuleAction", ChangeKind(KindModuleAction))
	require.Equal(t, "Inconsistent", Health(3))
	require.Equal(t, "Published", OutputState(2))
	require.Equal(t, keccakHex("unicity.vr.poa.v1"), hexutil.Encode(ModuleTagPoA[:]))
}

func keccakHex(s string) string { return hexutil.Encode(ethcrypto.Keccak256([]byte(s))) }
