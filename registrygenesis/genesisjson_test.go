package registrygenesis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

const (
	funded1   = "0x1000000000000000000000000000000000000001"
	funded2   = "0x1000000000000000000000000000000000000002"
	contract1 = "0x2000000000000000000000000000000000000001"
)

func operatorGenesis(t testing.TB) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(generate(t).GenesisJSON(), &doc))
	doc["nonce"] = "0x0102030405060708"
	doc["timestamp"] = 17
	doc["difficulty"] = "123456789"
	doc["mixHash"] = "0x1111111111111111111111111111111111111111111111111111111111111111"
	doc["coinbase"] = "0x3000000000000000000000000000000000000001"
	doc["extraData"] = "0xaabbcc"
	doc["gasLimit"] = "0x1c9c381"
	doc["baseFeePerGas"] = "1234567"
	doc["number"] = 0
	doc["parentHash"] = common.Hash{}.Hex()
	doc["gasUsed"] = "0x0"
	doc["blobGasUsed"] = 0
	doc["excessBlobGas"] = "0"
	doc["alloc"] = map[string]any{
		funded1:                           map[string]any{"balance": "0x123456789abcdef"},
		strings.TrimPrefix(funded2, "0x"): map[string]any{"balance": 42, "nonce": "7"},
		contract1:                         map[string]any{"balance": "5", "nonce": 3, "code": "0x6001600055", "storage": map[string]any{"0x1": "0x02", "0x3": "0x0"}},
	}
	raw, err := json.Marshal(doc)
	require.NoError(t, err)
	return raw
}

func prepareFunded(t testing.TB) *PreparedGenesis {
	t.Helper()
	a := pinnedArtifact(t)
	p, err := PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, operatorGenesis(t), GenesisJSONLimits{})
	require.NoError(t, err)
	return p
}

func TestPrepareAndValidateFundedGenesis(t *testing.T) {
	p := prepareFunded(t)
	require.Equal(t, common.HexToHash("0xf63207575830a59dece6e1b59ecbc46faa865492715252d5a846a6996bde98ba"), p.Origin().ExecutionConfigIdentity())
	require.Equal(t, common.HexToHash("0x030c8f48abdcfba2a393b0422726d1e492272edaa5e7044af846281055b5b33e"), p.Origin().Identity())
	require.Equal(t, common.HexToHash("0x9d672f7822f0747687bcf1c4273cecac83f987871d215d5554d71fb1d1f6f1b9"), p.Origin().BlockHash())
	require.Equal(t, common.HexToHash("0x8936f379e65d90577242c6333f644cd0716325117e5bb064a2a32c08ba8afdf0"), p.Origin().StateRoot())
	// Independently spell the two documented canonical tuples rather than obtaining either digest from
	// the implementation helper under test.
	cfgTuple := []any{executionProfile, uint64(1337),
		uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0), uint64(0),
		uint64(0), uint64(0), uint64(0), true}
	cfgCBOR, err := bfttypes.Cbor.Marshal(cfgTuple)
	require.NoError(t, err)
	cfgID := common.Hash(sha256.Sum256(cfgCBOR))
	require.Equal(t, p.Origin().ExecutionConfigIdentity(), cfgID)
	r := p.Origin().Record()
	originCBOR, err := bfttypes.Cbor.Marshal([]any{"UNICITY_GENESIS_ORIGIN", executionProfile,
		r.NetworkID, r.PartitionID, r.ShardID, p.Origin().FullShardConfHash().Bytes(),
		SystemAddress.Bytes(), registryproof.RegistryAddress.Bytes(), aCodeHash(t).Bytes(), cfgID.Bytes(),
		p.Origin().BlockHash().Bytes(), p.Origin().StateRoot().Bytes()})
	require.NoError(t, err)
	require.Equal(t, p.Origin().Identity(), common.Hash(sha256.Sum256(originCBOR)))
	require.True(t, p.Origin().Valid())
	full, err := p.FullConfig()
	require.NoError(t, err)
	a := pinnedArtifact(t)
	finalized := p.GenesisJSON()
	copyBefore := bytes.Clone(finalized)
	o, err := ValidateFinalizedGenesisJSON(full, vectorPins(a), a, finalized, nil, GenesisJSONLimits{})
	require.NoError(t, err)
	require.Equal(t, copyBefore, finalized, "validation is pure")
	require.Equal(t, p.Origin().Identity(), o.Identity())
	require.Equal(t, p.Origin().ExecutionConfigIdentity(), o.ExecutionConfigIdentity())
	require.Equal(t, p.Origin().BlockHash(), o.BlockHash())
	require.Equal(t, p.Origin().StateRoot(), o.StateRoot())
	_, err = ValidateFinalizedGenesisJSON(nil, vectorPins(a), a, finalized, nil, GenesisJSONLimits{})
	require.ErrorIs(t, err, ErrGenesisJSON)

	var header types.Header
	require.NoError(t, rlp.DecodeBytes(p.genesis.Header(), &header))
	require.Equal(t, o.BlockHash(), header.Hash())
	require.Equal(t, o.StateRoot(), header.Root)
	require.Equal(t, uint64(0x0102030405060708), header.Nonce.Uint64())
	require.Equal(t, uint64(17), header.Time)
	require.Equal(t, uint64(0x1c9c381), header.GasLimit)
	require.Equal(t, uint64(1_234_567), header.BaseFee.Uint64())
	require.Equal(t, []byte{0xaa, 0xbb, 0xcc}, header.Extra)
	require.Equal(t, common.HexToHash("0x11"+strings.Repeat("11", 31)), header.MixDigest)

	s, err := registryproof.Verify(o.ProofContext(), o.BlockHash(), o.Evidence())
	require.NoError(t, err)
	require.True(t, s.Genesis())
	require.Equal(t, o.StateRoot(), s.StateRoot())

	expected := o.Identity()
	_, err = ValidateFinalizedGenesisJSON(full, vectorPins(a), a, finalized, &expected, GenesisJSONLimits{})
	require.NoError(t, err)
	expected[0] ^= 1
	_, err = ValidateFinalizedGenesisJSON(full, vectorPins(a), a, finalized, &expected, GenesisJSONLimits{})
	require.ErrorIs(t, err, ErrOriginIdentity)

	e := o.Evidence()
	e.Header[0] ^= 1
	require.NotEqual(t, e.Header, o.Evidence().Header, "origin owns its proof bytes")
	r = o.Record()
	r.ShardID[0] ^= 1
	require.NotEqual(t, r.ShardID, o.Record().ShardID, "origin owns its record bytes")
	j := p.GenesisJSON()
	j[0] ^= 1
	require.NotEqual(t, j, p.GenesisJSON(), "prepared result owns its JSON bytes")
	c1, err := p.FullConfig()
	require.NoError(t, err)
	c1.PartitionParams["changed"] = "yes"
	c2, err := p.FullConfig()
	require.NoError(t, err)
	require.NotContains(t, c2.PartitionParams, "changed")
}

func aCodeHash(t testing.TB) common.Hash { t.Helper(); return pinnedArtifact(t).CodeHash }

func TestEquivalentGenesisSpellingsHaveOneIdentity(t *testing.T) {
	a := pinnedArtifact(t)
	one, err := PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, operatorGenesis(t), GenesisJSONLimits{})
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(operatorGenesis(t), &doc))
	doc["nonce"] = uint64(0x0102030405060708)
	doc["timestamp"] = "0x00011"
	doc["difficulty"] = "0x075bcd15"
	doc["gasLimit"] = 30_000_001
	doc["baseFeePerGas"] = "0X00012D687"
	alloc := doc["alloc"].(map[string]any)
	alloc[strings.ToUpper(strings.TrimPrefix(funded1, "0x"))] = alloc[funded1]
	delete(alloc, funded1)
	contract := alloc[contract1].(map[string]any)
	contract["storage"] = map[string]any{common.HexToHash("0x1").Hex(): "0x0002", "0x03": "0x00"}
	raw, err := json.MarshalIndent(doc, "", "    ")
	require.NoError(t, err)
	two, err := PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, raw, GenesisJSONLimits{})
	require.NoError(t, err)
	require.Equal(t, one.Origin().Identity(), two.Origin().Identity())
	require.Equal(t, one.GenesisJSON(), two.GenesisJSON())

	doc = map[string]any{}
	require.NoError(t, json.Unmarshal(operatorGenesis(t), &doc))
	doc["alloc"].(map[string]any)[funded1].(map[string]any)["balance"] = "0x123456789abcdee"
	changed, err := json.Marshal(doc)
	require.NoError(t, err)
	three, err := PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, changed, GenesisJSONLimits{})
	require.NoError(t, err)
	require.NotEqual(t, one.Origin().BlockHash(), three.Origin().BlockHash())
}

func TestGenesisJSONRefusals(t *testing.T) {
	a := pinnedArtifact(t)
	pins := vectorPins(a)
	mutate := func(t *testing.T, f func(map[string]any)) []byte {
		var d map[string]any
		require.NoError(t, json.Unmarshal(operatorGenesis(t), &d))
		f(d)
		b, e := json.Marshal(d)
		require.NoError(t, e)
		return b
	}
	cases := map[string]struct {
		raw    func(*testing.T) []byte
		target error
	}{
		"a sys": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) {
				d["alloc"].(map[string]any)[SystemAddress.Hex()] = map[string]any{"balance": "0x0"}
			})
		}, ErrReservedAccount},
		"a sr": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) {
				d["alloc"].(map[string]any)[registryproof.RegistryAddress.Hex()] = map[string]any{"balance": "0x0"}
			})
		}, ErrReservedAccount},
		"null alloc": {func(t *testing.T) []byte { return mutate(t, func(d map[string]any) { d["alloc"] = nil }) }, ErrGenesisJSON},
		"null storage": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) { d["alloc"].(map[string]any)[contract1].(map[string]any)["storage"] = nil })
		}, ErrGenesisJSON},
		"unknown": {func(t *testing.T) []byte { return mutate(t, func(d map[string]any) { d["surprise"] = 1 }) }, ErrGenesisJSON},
		"secret key": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) {
				d["alloc"].(map[string]any)[funded1].(map[string]any)["secretKey"] = common.Hash{}.Hex()
			})
		}, ErrGenesisJSON},
		"base fee overflow": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) { d["baseFeePerGas"] = "18446744073709551616" })
		}, ErrGenesisJSON},
		"balance overflow": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) {
				d["alloc"].(map[string]any)[funded1].(map[string]any)["balance"] = "0x1" + strings.Repeat("0", 64)
			})
		}, ErrGenesisJSON},
		"nonzero number": {func(t *testing.T) []byte { return mutate(t, func(d map[string]any) { d["number"] = 1 }) }, ErrGenesisJSON},
		"fork mismatch": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) { d["config"].(map[string]any)["cancunTime"] = 1 })
		}, ErrGenesisJSON},
		"chain mismatch": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) { d["config"].(map[string]any)["chainId"] = 1338 })
		}, ErrChainIDMismatch},
		"missing fork": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) { delete(d["config"].(map[string]any), "londonBlock") })
		}, ErrGenesisJSON},
		"fraction": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) { d["timestamp"] = 1.5 })
		}, ErrGenesisJSON},
		"odd code": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) { d["alloc"].(map[string]any)[contract1].(map[string]any)["code"] = "0x1" })
		}, ErrGenesisJSON},
		"long storage word": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) {
				d["alloc"].(map[string]any)[contract1].(map[string]any)["storage"] = map[string]any{"0x" + strings.Repeat("1", 65): "0x1"}
			})
		}, ErrGenesisJSON},
		"address alias": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) {
				a := d["alloc"].(map[string]any)
				a[strings.TrimPrefix(funded1, "0x")] = a[funded1]
			})
		}, ErrGenesisJSON},
		"storage zero alias": {func(t *testing.T) []byte {
			return mutate(t, func(d map[string]any) {
				d["alloc"].(map[string]any)[contract1].(map[string]any)["storage"] = map[string]any{"0x1": "0x0", "0x01": "0x2"}
			})
		}, ErrGenesisJSON},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := PrepareGenesisJSON(vectorConfig(), pins, a, tc.raw(t), GenesisJSONLimits{})
			require.ErrorIs(t, err, tc.target)
		})
	}
	for name, raw := range map[string][]byte{"duplicate": []byte(`{"config":{},"config":{}}`), "trailing": append(operatorGenesis(t), []byte(` {}`)...)} {
		t.Run(name, func(t *testing.T) {
			_, err := PrepareGenesisJSON(vectorConfig(), pins, a, raw, GenesisJSONLimits{})
			require.ErrorIs(t, err, ErrGenesisJSON)
		})
	}
}

func TestFinalizedRegistryMustBeExact(t *testing.T) {
	p := prepareFunded(t)
	full, err := p.FullConfig()
	require.NoError(t, err)
	a := pinnedArtifact(t)
	pins := vectorPins(a)
	for name, change := range map[string]func(map[string]any){
		"missing": func(d map[string]any) {
			delete(d["alloc"].(map[string]any), strings.ToLower(registryproof.RegistryAddress.Hex()))
		},
		"balance": func(d map[string]any) {
			d["alloc"].(map[string]any)[strings.ToLower(registryproof.RegistryAddress.Hex())].(map[string]any)["balance"] = "0x1"
		},
		"extra storage": func(d map[string]any) {
			d["alloc"].(map[string]any)[strings.ToLower(registryproof.RegistryAddress.Hex())].(map[string]any)["storage"].(map[string]any)[common.HexToHash("0xffff").Hex()] = common.HexToHash("0x1").Hex()
		},
	} {
		t.Run(name, func(t *testing.T) {
			var d map[string]any
			require.NoError(t, json.Unmarshal(p.GenesisJSON(), &d))
			change(d)
			raw, e := json.Marshal(d)
			require.NoError(t, e)
			_, e = ValidateFinalizedGenesisJSON(full, pins, a, raw, nil, GenesisJSONLimits{})
			require.ErrorIs(t, e, ErrReservedAccount)
		})
	}
}

func TestGenesisJSONLimits(t *testing.T) {
	a := pinnedArtifact(t)
	raw := operatorGenesis(t)
	limits := DefaultGenesisJSONLimits()
	limits.Accounts = 3
	_, err := PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, raw, limits)
	require.ErrorIs(t, err, ErrGenesisLimit, "inserted registry counts")
	limits = DefaultGenesisJSONLimits()
	limits.CodeTotal = len(a.RuntimeCode) - 1
	_, err = PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, raw, limits)
	require.ErrorIs(t, err, ErrGenesisLimit, "inserted registry code counts")
	limits = DefaultGenesisJSONLimits()
	limits.StorageTotal = 4
	_, err = PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, raw, limits)
	require.ErrorIs(t, err, ErrGenesisLimit, "inserted registry slots count")
	limits = DefaultGenesisJSONLimits()
	limits.SourceBytes = len(raw) - 1
	_, err = PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, raw, limits)
	require.ErrorIs(t, err, ErrGenesisLimit)
	limits = DefaultGenesisJSONLimits()
	limits.CodePerAccount = 4
	_, err = PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, raw, limits)
	require.ErrorIs(t, err, ErrGenesisLimit)
	limits = DefaultGenesisJSONLimits()
	limits.StoragePerAccount = 1
	_, err = PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, raw, limits)
	require.ErrorIs(t, err, ErrGenesisLimit)
	limits = DefaultGenesisJSONLimits()
	limits.Depth = 1
	_, err = PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, raw, limits)
	require.ErrorIs(t, err, ErrGenesisLimit)
	_, err = PrepareGenesisJSON(vectorConfig(), vectorPins(a), a, raw, GenesisJSONLimits{SourceBytes: math.MaxInt})
	require.ErrorIs(t, err, ErrGenesisLimit)
}

func TestFundedGenesisFixture(t *testing.T) {
	want := prepareFunded(t).GenesisJSON()
	path := "testdata/funded-genesis-vector.json"
	if os.Getenv("REGISTRYGENESIS_UPDATE_FUNDED") == "1" {
		require.NoError(t, os.WriteFile(path, want, 0o600))
	}
	got, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got))
}

func TestPinnedRethAgreesWithFundedGenesis(t *testing.T) {
	raw, err := os.ReadFile("testdata/reth-funded-genesis-vector.json")
	require.NoError(t, err)
	var v struct {
		Generator, ClientVersion                  string
		InitGenesisHash, RPCBlock0Hash, StateRoot common.Hash
		Header                                    string
		Proof                                     json.RawMessage
		Accounts                                  map[string]struct {
			Balance, Nonce, Code string
			Storage              map[string]string
		}
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	require.Contains(t, v.Generator, "Commit SHA: 189c0df32617afc488e0f091dbface1bd72cceb4")
	require.Contains(t, v.ClientVersion, "189c0df")
	p := prepareFunded(t)
	o := p.Origin()
	require.Equal(t, o.BlockHash(), v.InitGenesisHash, "reth init")
	require.Equal(t, o.BlockHash(), v.RPCBlock0Hash, "eth_getBlockByNumber(0)")
	require.Equal(t, o.StateRoot(), v.StateRoot)
	header, err := hex.DecodeString(strings.TrimPrefix(v.Header, "0x"))
	require.NoError(t, err)
	require.Equal(t, p.genesis.Header(), header, "debug_getRawHeader")
	var proof registryproof.GetProofResult
	require.NoError(t, json.Unmarshal(v.Proof, &proof))
	evidence, err := registryproof.EvidenceFromGetProof(header, proof)
	require.NoError(t, err)
	_, err = registryproof.Verify(o.ProofContext(), o.BlockHash(), evidence)
	require.NoError(t, err)
	require.Equal(t, "0x123456789abcdef", v.Accounts[funded1].Balance)
	require.Equal(t, "0x0", v.Accounts[funded1].Nonce)
	require.Equal(t, "0x2a", v.Accounts[funded2].Balance)
	require.Equal(t, "0x7", v.Accounts[funded2].Nonce)
	require.Equal(t, "0x5", v.Accounts[contract1].Balance)
	require.Equal(t, "0x3", v.Accounts[contract1].Nonce)
	require.Equal(t, "0x6001600055", v.Accounts[contract1].Code)
	require.Equal(t, common.HexToHash("0x2").Hex(), v.Accounts[contract1].Storage[common.HexToHash("0x1").Hex()])
}
