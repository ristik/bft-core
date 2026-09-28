package registrygenesis

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

// vectorConfig is the illustrative configuration of #153 §5.4, without the parameter.
func vectorConfig() *bfttypes.PartitionDescriptionRecord {
	return &bfttypes.PartitionDescriptionRecord{
		Version: 1, NetworkID: 3, PartitionID: 8, T2Timeout: 5 * time.Second,
		PartitionParams: map[string]string{ChainIDParam: "1337"}, Epoch: 0,
		Validators: []*bfttypes.NodeInfo{{NodeID: "validator-1", SigKey: append([]byte{0x02}, make([]byte, 32)...), Stake: 1}},
	}
}

func pinnedArtifact(t testing.TB) Artifact {
	a, err := PinnedArtifact()
	require.NoError(t, err)
	return a
}

func vectorPins(a Artifact) Pins {
	return Pins{RootEpoch: 1, RegistryCodeHash: a.CodeHash, SystemAddress: SystemAddress, RegistryAddress: registryproof.RegistryAddress}
}

func generate(t testing.TB) *Genesis {
	a := pinnedArtifact(t)
	g, err := Generate(vectorConfig(), vectorPins(a), a, DefaultEVMParams)
	require.NoError(t, err)
	return g
}

func TestPinnedArtifact(t *testing.T) {
	a := pinnedArtifact(t)
	require.Equal(t, common.HexToHash("0x18b4c874e37d8563c1f672b6da073f009cd6a03bc9bfde886cc4743db6c14d3c"), a.CodeHash)
	require.Len(t, a.RuntimeCode, 2408)
	require.Equal(t, a.CodeHash, crypto.Keccak256Hash(a.RuntimeCode))
}

func TestTamperedArtifactIsRefused(t *testing.T) {
	var base map[string]any
	require.NoError(t, json.Unmarshal(pinnedArtifactJSON, &base))
	_, err := parseArtifact(pinnedArtifactJSON)
	require.NoError(t, err, "premise: the embedded artifact parses")

	for name, change := range map[string]func(m map[string]any){
		"profile":              func(m map[string]any) { m["profile"] = "sealRegistry/v2" },
		"legacy pipeline":      func(m map[string]any) { m["compiler"].(map[string]any)["via_ir"] = false },
		"another solc":         func(m map[string]any) { m["compiler"].(map[string]any)["solc"] = "0.8.28" },
		"metadata hash":        func(m map[string]any) { m["compiler"].(map[string]any)["bytecode_hash"] = "ipfs" },
		"system caller":        func(m map[string]any) { m["systemCaller"] = "0xfffffffffffffffffffffffffffffffffffffffe" },
		"slot key name":        func(m map[string]any) { m["slotKeys"].([]any)[5].(map[string]any)["name"] = "clock.round" },
		"slot key value":       func(m map[string]any) { m["slotKeys"].([]any)[5].(map[string]any)["key"] = common.Hash{1}.Hex() },
		"slot key missing":     func(m map[string]any) { m["slotKeys"] = m["slotKeys"].([]any)[1:] },
		"runtime code changed": func(m map[string]any) { m["runtimeBytecode"] = flipLastHexDigit(m["runtimeBytecode"].(string)) },
		"code hash changed":    func(m map[string]any) { m["codeHash"] = crypto.Keccak256Hash([]byte("other")).Hex() },
		"runtime code empty":   func(m map[string]any) { m["runtimeBytecode"] = "0x" },
	} {
		t.Run(name, func(t *testing.T) {
			m := deepCopyJSON(t, base)
			change(m)
			raw, err := json.Marshal(m)
			require.NoError(t, err)
			_, err = parseArtifact(raw)
			require.ErrorIs(t, err, ErrArtifact)
		})
	}
}

func flipLastHexDigit(s string) string {
	last := s[len(s)-1]
	repl := byte('0')
	if last == '0' {
		repl = '1'
	}
	return s[:len(s)-1] + string(repl)
}

func deepCopyJSON(t *testing.T, m map[string]any) map[string]any {
	raw, err := json.Marshal(m)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// The values for the §5.4 configuration with the merged registry. A change to any of them is a change to
// the genesis a deployment of this configuration would run, not a test update.
const (
	wantBaseConfigHash    = "0x3582bd0f44572e45c1e46f9b5c9797991dff8a59cdf85cd12e2879d7d67c5653"
	wantRecordCBOR        = "8c781d554e49434954595f5345414c5f52454749535452595f47454e45534953010308418019053954ff0000000000000000000000000000000000000154ff00000000000000000000000000000000000002582018b4c874e37d8563c1f672b6da073f009cd6a03bc9bfde886cc4743db6c14d3c58203582bd0f44572e45c1e46f9b5c9797991dff8a59cdf85cd12e2879d7d67c56530001"
	wantGenesisCommitment = "0x78c8ae71b930dd4a379a5d2bc82ce30deb54de0ef4387c33c30a27f06fb8ef26"
	wantFullShardConfHash = "0x002a719ed27ff7b185660ac29fe1f32269b0e3ab3f126716a52c47ec2b8a92dd"
	wantStorageRoot       = "0xe6d1f3ea67ba8f07734105ea8959374173a1c68660166cbd3699441890f9b229"
	wantStateRoot         = "0x7920b60c4fef92ed6b001d3ae492eacfa626ba8333e963f951784b636dd4d514"
	wantEVMGenesisHash    = "0x0ba86302dddb0f67e17e5a12b91fbc519ff3d513edca6a332b0cbf07ce239ea0"
)

func TestGenesisVector(t *testing.T) {
	g := generate(t)
	got := map[string]string{
		"baseConfigHash": g.BaseConfigHash().Hex(), "CBOR(G)": hex.EncodeToString(g.RecordCBOR()),
		"genesisCommitment": g.GenesisCommitment().Hex(), "fullShardConfHash": g.FullShardConfHash().Hex(),
		"storageRoot": g.StorageRoot().Hex(), "stateRoot": g.StateRoot().Hex(), "evmGenesisHash": g.EVMGenesisHash().Hex(),
	}
	want := map[string]string{
		"baseConfigHash": wantBaseConfigHash, "CBOR(G)": wantRecordCBOR, "genesisCommitment": wantGenesisCommitment,
		"fullShardConfHash": wantFullShardConfHash, "storageRoot": wantStorageRoot, "stateRoot": wantStateRoot,
		"evmGenesisHash": wantEVMGenesisHash,
	}
	for _, k := range []string{"baseConfigHash", "CBOR(G)", "genesisCommitment", "fullShardConfHash", "storageRoot", "stateRoot", "evmGenesisHash"} {
		t.Logf("%-18s %s", k, got[k])
		require.Equal(t, want[k], got[k], k)
	}

	require.Equal(t, map[string]common.Hash{
		"layoutVersion": wordUint(1), "genesisCommitment": common.HexToHash(wantGenesisCommitment),
		"config.shardConfHash": common.HexToHash(wantFullShardConfHash), "assignment.epoch": {},
		"assignment.rootEpoch": wordUint(1), "phase": wordUint(2),
	}, g.Storage(), "§5.4: exactly six words; assignment.epoch is 0, so it is absent from the trie")

	full, err := g.FullConfig()
	require.NoError(t, err)
	require.Equal(t, strings.TrimPrefix(wantGenesisCommitment, "0x"), full.PartitionParams[GenesisParam])
	fullHash, err := configHash(full)
	require.NoError(t, err)
	require.Equal(t, g.FullShardConfHash(), fullHash, "the decoded full configuration hashes to fullShardConfHash")

	// The committed genesis file is exactly what Generate writes. REGISTRYGENESIS_UPDATE=1 rewrites it,
	// after which testdata/reth-genesis-vector.sh must be rerun.
	path := "testdata/genesis-vector.json"
	if os.Getenv("REGISTRYGENESIS_UPDATE") == "1" {
		require.NoError(t, os.WriteFile(path, g.GenesisJSON(), 0o600))
	}
	committed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(committed), string(g.GenesisJSON()))
}

func TestGenerationIsDeterministic(t *testing.T) {
	a, b := generate(t), generate(t)
	require.Equal(t, a.RecordCBOR(), b.RecordCBOR())
	require.Equal(t, a.GenesisJSON(), b.GenesisJSON())
	require.Equal(t, a.Header(), b.Header())
	require.Equal(t, a.Evidence(), b.Evidence())
	require.Equal(t, a.ProofContext(), b.ProofContext())
}

// With the one-byte placeholder code the #153 model uses, generation reproduces the design document's §5.4
// vector, which the model computes independently of this package.
func TestDesignDocumentVectorIsReproduced(t *testing.T) {
	placeholder := Artifact{RuntimeCode: []byte{0x00}, CodeHash: crypto.Keccak256Hash([]byte{0x00})}
	g, err := Generate(vectorConfig(), vectorPins(placeholder), placeholder, DefaultEVMParams)
	require.NoError(t, err)
	require.Equal(t, "0x071a4f34498689e1f26353434c92f763ddaaba8de9cc634aa68af6e1bf65eab8", g.GenesisCommitment().Hex())
	require.Equal(t, "0x3a2c73649214e56d5e98d1c2d06cff56e7a5d67037a25bcf0e43fcaff8987a6b", g.FullShardConfHash().Hex())
	require.Equal(t, wantBaseConfigHash, g.BaseConfigHash().Hex(), "the base configuration does not depend on the code")
}

// The header template, over an empty allocation, is the genesis the pinned reth (189c0df3) writes for the
// default `ubft engine-api genesis` file with chain id 1337: `reth init` reported this hash.
func TestEmptyAllocationHeaderMatchesPinnedReth(t *testing.T) {
	h := genesisHeader(DefaultEVMParams, types.EmptyRootHash)
	require.Equal(t, "0x0598047b8adde700d2e815fe0c7436002f7c50ef32447aa4f4bf4c09e1a97789", h.Hash().Hex())
}

type rethVector struct {
	Generator       string          `json:"generator"`
	ClientVersion   string          `json:"clientVersion"`
	InitGenesisHash common.Hash     `json:"initGenesisHash"`
	RPCBlock0Hash   common.Hash     `json:"rpcBlock0Hash"`
	StateRoot       common.Hash     `json:"stateRoot"`
	Header          string          `json:"header"`
	Proof           json.RawMessage `json:"proof"`
}

// testdata/reth-genesis-vector.json is what the pinned reth computed and served for
// testdata/genesis-vector.json (testdata/reth-genesis-vector.sh).
func TestPinnedRethAgreesWithTheGeneratedGenesis(t *testing.T) {
	raw, err := os.ReadFile("testdata/reth-genesis-vector.json")
	require.NoError(t, err)
	var v rethVector
	require.NoError(t, json.Unmarshal(raw, &v))
	t.Logf("generator: %s", v.Generator)

	g := generate(t)
	require.Equal(t, g.EVMGenesisHash(), v.InitGenesisHash, "reth init")
	require.Equal(t, g.EVMGenesisHash(), v.RPCBlock0Hash, "eth_getBlockByNumber(0)")
	require.Equal(t, g.StateRoot(), v.StateRoot)
	header, err := hex.DecodeString(strings.TrimPrefix(v.Header, "0x"))
	require.NoError(t, err)
	require.Equal(t, g.Header(), header, "debug_getRawHeader")

	var r registryproof.GetProofResult
	require.NoError(t, json.Unmarshal(v.Proof, &r))
	ev, err := registryproof.EvidenceFromGetProof(header, r)
	require.NoError(t, err)
	s, err := registryproof.Verify(g.ProofContext(), v.RPCBlock0Hash, ev)
	require.NoError(t, err, "reth's genesis proof verifies under the generated context")
	require.True(t, s.Genesis())
	require.Equal(t, uint64(0), s.LastAppliedRootRound())
	require.Equal(t, g.GenesisCommitment(), s.Fields().GenesisCommitment)
	require.Equal(t, g.FullShardConfHash(), s.Fields().ShardConfHash)
}

func TestGeneratedGenesisProofAndParentRule(t *testing.T) {
	g := generate(t)
	ctx := g.ProofContext()
	s, err := registryproof.Verify(ctx, g.EVMGenesisHash(), g.Evidence())
	require.NoError(t, err)
	require.True(t, s.Genesis())
	require.Equal(t, uint64(0), s.Number())
	require.Equal(t, uint64(0), s.LastAppliedRootRound())

	// On this branch the shard node certifies the EVM state root as IR.h (#153 §4.2), so the genesis input
	// record names the generated state root.
	genesisState := g.StateRoot().Bytes()
	installed := &bfttypes.InputRecord{RoundNumber: 0, PreviousHash: genesisState, Hash: genesisState}
	for name, n := range map[string]uint64{"first payload, round 1": 1, "§9.2a one initial timeout, round 2": 2, "three initial timeouts, round 4": 4} {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, registryproof.GenesisParentEligible(n, installed, genesisState, s))
		})
	}
	t.Run("round 0 is installation", func(t *testing.T) {
		require.ErrorIs(t, registryproof.GenesisParentEligible(0, installed, genesisState, s), registryproof.ErrGenesisInstallation)
	})

	for name, tc := range map[string]struct {
		change func(*registryproof.Context)
		want   error
	}{
		"another code hash":          {func(c *registryproof.Context) { c.RegistryCodeHash = crypto.Keccak256Hash([]byte{0x00}) }, registryproof.ErrCodeHash},
		"another genesis commitment": {func(c *registryproof.Context) { c.GenesisCommitment = common.Hash{1} }, registryproof.ErrConfiguration},
		"another configuration hash": {func(c *registryproof.Context) { c.FullShardConfHash = common.Hash{1} }, registryproof.ErrConfiguration},
		"another root epoch":         {func(c *registryproof.Context) { c.RootEpoch = 2 }, registryproof.ErrConfiguration},
		"another EVM genesis hash":   {func(c *registryproof.Context) { c.EVMGenesisHash = common.Hash{1} }, registryproof.ErrConfiguration},
	} {
		t.Run("context: "+name, func(t *testing.T) {
			c := ctx
			tc.change(&c)
			_, err := registryproof.Verify(c, g.EVMGenesisHash(), g.Evidence())
			require.ErrorIs(t, err, tc.want)
		})
	}
}

func TestVerifyContext(t *testing.T) {
	g := generate(t)
	pins := vectorPins(pinnedArtifact(t))
	full, err := g.FullConfig()
	require.NoError(t, err)
	got, err := VerifyContext(full, pins, g.Record())
	require.NoError(t, err, "premise: the generated configuration and G verify")
	require.Equal(t, g.FullShardConfHash(), got)

	withParam := func(value string) *bfttypes.PartitionDescriptionRecord {
		c, err := g.FullConfig()
		require.NoError(t, err)
		c.PartitionParams[GenesisParam] = value
		return c
	}
	commitment := strings.TrimPrefix(g.GenesisCommitment().Hex(), "0x")
	for name, tc := range map[string]struct {
		full *bfttypes.PartitionDescriptionRecord
		want error
	}{
		"parameter with 0x":   {withParam("0x" + commitment), ErrGenesisEncoding},
		"parameter uppercase": {withParam(strings.ToUpper(commitment)), ErrGenesisEncoding},
		"parameter truncated": {withParam(commitment[:63]), ErrGenesisEncoding},
		"parameter absent": {func() *bfttypes.PartitionDescriptionRecord {
			c, _ := g.FullConfig()
			delete(c.PartitionParams, GenesisParam)
			return c
		}(), ErrGenesisEncoding},
		"no chain_id": {func() *bfttypes.PartitionDescriptionRecord {
			c, _ := g.FullConfig()
			delete(c.PartitionParams, ChainIDParam)
			return c
		}(), ErrNoChainID},
		"chain_id with a leading zero": {func() *bfttypes.PartitionDescriptionRecord {
			c, _ := g.FullConfig()
			c.PartitionParams[ChainIDParam] = "01337"
			return c
		}(), ErrNoChainID},
		"another configuration field changed after G": {func() *bfttypes.PartitionDescriptionRecord {
			c, _ := g.FullConfig()
			c.T2Timeout = 6 * time.Second
			return c
		}(), ErrBaseConfig},
		"a commitment for another G": {withParam(strings.Repeat("ab", 32)), ErrGenesisMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := VerifyContext(tc.full, pins, g.Record())
			require.ErrorIs(t, err, tc.want)
		})
	}

	t.Run("G built over the full hash instead of the base hash", func(t *testing.T) {
		circular := g.Record()
		circular.BaseConfigHash = g.FullShardConfHash()
		_, err := VerifyContext(selfConsistent(t, g, circular), pins, circular)
		require.ErrorIs(t, err, ErrBaseConfig)
	})
}

// selfConsistent returns the generated full configuration with the parameter set to wrong's own
// commitment, so a refusal cannot come from a hash mismatch between the two.
func selfConsistent(t *testing.T, g *Genesis, wrong Record) *bfttypes.PartitionDescriptionRecord {
	c, err := wrong.Commitment()
	require.NoError(t, err)
	full, err := g.FullConfig()
	require.NoError(t, err)
	full.PartitionParams[GenesisParam] = hex.EncodeToString(c[:])
	return full
}

// Review 5195786713 P2, over the generator's output: every G field with an independent expected value.
func TestSelfConsistentWrongContextIsRefused(t *testing.T) {
	g := generate(t)
	pins := vectorPins(pinnedArtifact(t))
	for name, tc := range map[string]struct {
		mutate func(*Record)
		want   error
	}{
		"network":            {func(r *Record) { r.NetworkID++ }, ErrContextMismatch},
		"partition":          {func(r *Record) { r.PartitionID++ }, ErrContextMismatch},
		"shard":              {func(r *Record) { r.ShardID = []byte{0xc0} }, ErrContextMismatch},
		"shard epoch":        {func(r *Record) { r.ShardEpoch++ }, ErrContextMismatch},
		"root epoch":         {func(r *Record) { r.RootEpoch++ }, ErrContextMismatch},
		"registry code hash": {func(r *Record) { r.RegistryCodeHash = crypto.Keccak256Hash([]byte{0x00}) }, ErrContextMismatch},
		"a_sys":              {func(r *Record) { r.SystemAddress[19] ^= 0xff }, ErrContextMismatch},
		"a_sr":               {func(r *Record) { r.RegistryAddress[19] ^= 0xff }, ErrContextMismatch},
		"chain id":           {func(r *Record) { r.ChainID++ }, ErrChainIDMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			wrong := g.Record()
			tc.mutate(&wrong)
			full := selfConsistent(t, g, wrong)
			c, err := wrong.Commitment()
			require.NoError(t, err)
			require.Equal(t, hex.EncodeToString(c[:]), full.PartitionParams[GenesisParam], "premise: self-consistent")
			_, err = VerifyContext(full, pins, wrong)
			require.ErrorIs(t, err, tc.want)
		})
	}
	t.Run("pins for another deployment", func(t *testing.T) {
		full, err := g.FullConfig()
		require.NoError(t, err)
		other := pins
		other.RootEpoch = 2
		_, err = VerifyContext(full, other, g.Record())
		require.ErrorIs(t, err, ErrContextMismatch)
	})
}

func TestGenerateRefusals(t *testing.T) {
	a := pinnedArtifact(t)
	pins := vectorPins(a)
	withParams := func(kv ...string) *bfttypes.PartitionDescriptionRecord {
		c := vectorConfig()
		c.PartitionParams = map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			c.PartitionParams[kv[i]] = kv[i+1]
		}
		return c
	}
	placeholder := Artifact{RuntimeCode: []byte{0x00}, CodeHash: crypto.Keccak256Hash([]byte{0x00})}
	for name, tc := range map[string]struct {
		config *bfttypes.PartitionDescriptionRecord
		pins   Pins
		art    Artifact
		evm    EVMParams
		want   error
	}{
		"nil configuration":                            {nil, pins, a, DefaultEVMParams, ErrNoChainID},
		"parameter already set":                        {withParams(ChainIDParam, "1337", GenesisParam, strings.Repeat("00", 32)), pins, a, DefaultEVMParams, ErrAlreadyBound},
		"no chain_id":                                  {withParams("other", "1"), pins, a, DefaultEVMParams, ErrNoChainID},
		"hexadecimal chain_id":                         {withParams(ChainIDParam, "0x539"), pins, a, DefaultEVMParams, ErrNoChainID},
		"chain_id with whitespace":                     {withParams(ChainIDParam, " 1337"), pins, a, DefaultEVMParams, ErrNoChainID},
		"chain_id too large":                           {withParams(ChainIDParam, "18446744073709551616"), pins, a, DefaultEVMParams, ErrNoChainID},
		"artifact code does not hash to its code hash": {vectorConfig(), pins, Artifact{RuntimeCode: []byte{0x01}, CodeHash: a.CodeHash}, DefaultEVMParams, ErrArtifact},
		"artifact is not the pinned code":              {vectorConfig(), pins, placeholder, DefaultEVMParams, ErrPins},
		"another a_sr":                                 {vectorConfig(), Pins{RootEpoch: 1, RegistryCodeHash: a.CodeHash, SystemAddress: SystemAddress, RegistryAddress: common.Address{1}}, a, DefaultEVMParams, ErrPins},
		"stock system caller":                          {vectorConfig(), Pins{RootEpoch: 1, RegistryCodeHash: a.CodeHash, SystemAddress: common.HexToAddress("0xfffffffffffffffffffffffffffffffffffffffe"), RegistryAddress: registryproof.RegistryAddress}, a, DefaultEVMParams, ErrPins},
		"zero pinned code hash":                        {vectorConfig(), Pins{RootEpoch: 1, SystemAddress: SystemAddress, RegistryAddress: registryproof.RegistryAddress}, a, DefaultEVMParams, ErrPins},
		"zero gas limit":                               {vectorConfig(), pins, a, EVMParams{BaseFee: 1}, ErrEVMParams},
		"extraData over 32 bytes":                      {vectorConfig(), pins, a, EVMParams{GasLimit: 1, ExtraData: make([]byte, 33)}, ErrEVMParams},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Generate(tc.config, tc.pins, tc.art, tc.evm)
			require.ErrorIs(t, err, tc.want)
		})
	}
}

// Every configuration and pin input changes G's commitment and therefore the whole genesis. The EVM header
// parameters change only the EVM genesis: G, the commitment and fullShardConfHash do not depend on
// anything derived from the EVM genesis block (§5.3).
func TestEveryInputReachesTheGenesis(t *testing.T) {
	base := generate(t)
	a := pinnedArtifact(t)
	otherCode := append(append([]byte(nil), a.RuntimeCode...), 0x00)
	otherArtifact := Artifact{RuntimeCode: otherCode, CodeHash: crypto.Keccak256Hash(otherCode)}

	type input struct {
		config *bfttypes.PartitionDescriptionRecord
		pins   Pins
		art    Artifact
		evm    EVMParams
	}
	withConfig := func(change func(*bfttypes.PartitionDescriptionRecord)) input {
		c := vectorConfig()
		change(c)
		return input{c, vectorPins(a), a, DefaultEVMParams}
	}
	withEVM := func(change func(*EVMParams)) input {
		e := DefaultEVMParams
		change(&e)
		return input{vectorConfig(), vectorPins(a), a, e}
	}
	for name, tc := range map[string]struct {
		in         input
		commitsInG bool
	}{
		"network":       {withConfig(func(c *bfttypes.PartitionDescriptionRecord) { c.NetworkID = 4 }), true},
		"partition":     {withConfig(func(c *bfttypes.PartitionDescriptionRecord) { c.PartitionID = 9 }), true},
		"chain id":      {withConfig(func(c *bfttypes.PartitionDescriptionRecord) { c.PartitionParams[ChainIDParam] = "1338" }), true},
		"shard epoch":   {withConfig(func(c *bfttypes.PartitionDescriptionRecord) { c.Epoch = 1 }), true},
		"T2 timeout":    {withConfig(func(c *bfttypes.PartitionDescriptionRecord) { c.T2Timeout = 6 * time.Second }), true},
		"validator set": {withConfig(func(c *bfttypes.PartitionDescriptionRecord) { c.Validators[0].Stake = 2 }), true},
		"root epoch":    {input{vectorConfig(), Pins{RootEpoch: 2, RegistryCodeHash: a.CodeHash, SystemAddress: SystemAddress, RegistryAddress: registryproof.RegistryAddress}, a, DefaultEVMParams}, true},
		"registry code": {input{vectorConfig(), vectorPins(otherArtifact), otherArtifact, DefaultEVMParams}, true},
		"gas limit":     {withEVM(func(e *EVMParams) { e.GasLimit++ }), false},
		"coinbase":      {withEVM(func(e *EVMParams) { e.Coinbase = common.Address{1} }), false},
		"extraData":     {withEVM(func(e *EVMParams) { e.ExtraData = []byte{1} }), false},
		"base fee":      {withEVM(func(e *EVMParams) { e.BaseFee++ }), false},
	} {
		t.Run(name, func(t *testing.T) {
			g, err := Generate(tc.in.config, tc.in.pins, tc.in.art, tc.in.evm)
			require.NoError(t, err)
			require.NotEqual(t, base.EVMGenesisHash(), g.EVMGenesisHash())
			require.NotEqual(t, base.GenesisJSON(), g.GenesisJSON())
			if tc.commitsInG {
				require.NotEqual(t, base.GenesisCommitment(), g.GenesisCommitment())
				require.NotEqual(t, base.FullShardConfHash(), g.FullShardConfHash())
				require.NotEqual(t, base.StateRoot(), g.StateRoot())
			} else {
				require.Equal(t, base.RecordCBOR(), g.RecordCBOR())
				require.Equal(t, base.GenesisCommitment(), g.GenesisCommitment())
				require.Equal(t, base.FullShardConfHash(), g.FullShardConfHash())
				require.Equal(t, base.StateRoot(), g.StateRoot())
			}
		})
	}
}

// Generate keeps no reference to its inputs, and every accessor returns a copy.
func TestInputsAndOutputsAreNotShared(t *testing.T) {
	a := pinnedArtifact(t)
	config := vectorConfig()
	evm := EVMParams{GasLimit: 30_000_000, BaseFee: 1, ExtraData: []byte{0xaa}}
	g, err := Generate(config, vectorPins(a), a, evm)
	require.NoError(t, err)
	want := fmt.Sprint(g.EVMGenesisHash(), g.GenesisCommitment(), g.FullShardConfHash())
	// The expected values are independent copies: an accessor that shared memory would otherwise change
	// them together with the value under test.
	wantJSON, wantHeader, wantCBOR := slices.Clone(g.GenesisJSON()), slices.Clone(g.Header()), slices.Clone(g.RecordCBOR())
	wantRecord := g.Record()
	wantRecord.ShardID = slices.Clone(wantRecord.ShardID)
	wantStorage := maps.Clone(g.Storage())

	require.NotContains(t, config.PartitionParams, GenesisParam, "Generate does not modify the caller's configuration")
	config.PartitionParams[ChainIDParam] = "1"
	config.NetworkID = 99
	a.RuntimeCode[0] ^= 0xff
	evm.ExtraData[0] ^= 0xff

	g.GenesisJSON()[0] = 'x'
	g.Header()[0] ^= 0xff
	g.RecordCBOR()[0] ^= 0xff
	g.Record().ShardID[0] ^= 0xff
	g.Storage()["phase"] = common.Hash{}
	ev := g.Evidence()
	ev.Header[0] ^= 0xff
	ev.AccountProof[0][0] ^= 0xff
	full, err := g.FullConfig()
	require.NoError(t, err)
	full.PartitionParams[GenesisParam] = "changed"

	require.Equal(t, want, fmt.Sprint(g.EVMGenesisHash(), g.GenesisCommitment(), g.FullShardConfHash()))
	require.Equal(t, wantJSON, g.GenesisJSON())
	require.Equal(t, wantHeader, g.Header())
	require.Equal(t, wantCBOR, g.RecordCBOR())
	require.Equal(t, wantRecord, g.Record())
	require.True(t, maps.Equal(wantStorage, g.Storage()))
	again, err := g.FullConfig()
	require.NoError(t, err)
	require.Equal(t, strings.TrimPrefix(g.GenesisCommitment().Hex(), "0x"), again.PartitionParams[GenesisParam])
	_, err = registryproof.Verify(g.ProofContext(), g.EVMGenesisHash(), g.Evidence())
	require.NoError(t, err)

	gt := reflect.TypeOf(Genesis{})
	for i := 0; i < gt.NumField(); i++ {
		require.False(t, gt.Field(i).IsExported(), "Genesis field %s is exported", gt.Field(i).Name)
	}
}
