package registrygenesis

import (
	"encoding/json"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
)

func pinnedArtifactV2(t testing.TB) Artifact {
	a, err := PinnedArtifactV2()
	require.NoError(t, err)
	return a
}

func generateV2(t testing.TB) *Genesis {
	a := pinnedArtifactV2(t)
	g, err := Generate(vectorConfig(), vectorPins(a), a, DefaultEVMParams)
	require.NoError(t, err)
	return g
}

func TestPinnedArtifactV2(t *testing.T) {
	a := pinnedArtifactV2(t)
	require.Equal(t, PinnedCodeHashV2, a.CodeHash)
	require.Len(t, a.RuntimeCode, 4301)
	require.Equal(t, a.CodeHash, crypto.Keccak256Hash(a.RuntimeCode))
	require.EqualValues(t, 2, a.Layout)
	v1 := pinnedArtifact(t)
	require.NotEqual(t, v1.CodeHash, a.CodeHash, "the historical v1 artifact stays available and distinct")
}

func TestTamperedArtifactV2IsRefused(t *testing.T) {
	var base map[string]any
	require.NoError(t, json.Unmarshal(pinnedArtifactV2JSON, &base))
	for name, change := range map[string]func(m map[string]any){
		"profile":          func(m map[string]any) { m["profile"] = "sealRegistry/v1" },
		"legacy pipeline":  func(m map[string]any) { m["compiler"].(map[string]any)["via_ir"] = false },
		"system caller":    func(m map[string]any) { m["systemCaller"] = "0xfffffffffffffffffffffffffffffffffffffffe" },
		"active hash slot": func(m map[string]any) { m["slotKeys"].([]any)[5].(map[string]any)["key"] = common.Hash{1}.Hex() },
		"span commit slot": func(m map[string]any) { m["slotKeys"].([]any)[6].(map[string]any)["name"] = "assignment.span" },
		"slot key missing": func(m map[string]any) { m["slotKeys"] = m["slotKeys"].([]any)[1:] },
		"v1 slot list": func(m map[string]any) {
			m["slotKeys"] = append(m["slotKeys"].([]any)[:5], m["slotKeys"].([]any)[7:]...)
		},
		"runtime code change": func(m map[string]any) { m["runtimeBytecode"] = flipLastHexDigit(m["runtimeBytecode"].(string)) },
		"code hash change":    func(m map[string]any) { m["codeHash"] = crypto.Keccak256Hash([]byte("other")).Hex() },
	} {
		t.Run(name, func(t *testing.T) {
			m := deepCopyJSON(t, base)
			change(m)
			raw, err := json.Marshal(m)
			require.NoError(t, err)
			_, err = parseArtifact(raw, 2)
			require.ErrorIs(t, err, ErrArtifact)
		})
	}
	t.Run("the independent code-hash pin rejects a self-consistent replacement", func(t *testing.T) {
		m := deepCopyJSON(t, base)
		code := m["runtimeBytecode"].(string)
		m["runtimeBytecode"] = flipLastHexDigit(code)
		raw, err := hexutil.Decode(m["runtimeBytecode"].(string))
		require.NoError(t, err)
		m["codeHash"] = crypto.Keccak256Hash(raw).Hex()
		out, err := json.Marshal(m)
		require.NoError(t, err)
		_, err = parseArtifact(out, 2)
		require.NoError(t, err, "premise: the replacement is internally consistent")
		saved := pinnedArtifactV2JSON
		pinnedArtifactV2JSON = out
		defer func() { pinnedArtifactV2JSON = saved }()
		_, err = PinnedArtifactV2()
		require.ErrorIs(t, err, ErrArtifact)
		require.ErrorContains(t, err, "is not the pinned")
	})
}

func TestGenerateV2KeepsGenesisHashImmutableAndInitializesTheActiveHash(t *testing.T) {
	g := generateV2(t)
	words := g.Storage()
	require.Len(t, words, 7, "layout, commitment, genesis hash, epochs, active hash and phase")
	require.Equal(t, g.FullShardConfHash(), words["config.shardConfHash"])
	require.Equal(t, g.FullShardConfHash(), words["assignment.activeConfHash"], "the active hash starts at the immutable hash")
	require.Equal(t, wordUint(2), words["layoutVersion"])
	require.EqualValues(t, 2, g.Record().Layout)

	ctx := g.ProofContext()
	require.EqualValues(t, 2, ctx.Layout)
	snap, err := registryproof.Verify(ctx, g.EVMGenesisHash(), g.Evidence())
	require.NoError(t, err)
	require.Equal(t, g.FullShardConfHash(), snap.Fields().ActiveConfHash)

	v1 := generate(t)
	require.NotEqual(t, v1.GenesisCommitment(), g.GenesisCommitment(), "G commits to the layout, so a v1 and a v2 deployment cannot be confused")
	require.NotEqual(t, v1.FullShardConfHash(), g.FullShardConfHash())
	require.NotEqual(t, v1.EVMGenesisHash(), g.EVMGenesisHash())
}

func TestGenerateV2IsDeterministic(t *testing.T) {
	a, b := generateV2(t), generateV2(t)
	require.Equal(t, a.EVMGenesisHash(), b.EVMGenesisHash())
	require.Equal(t, a.GenesisJSON(), b.GenesisJSON())
}

func TestV2GenesisJSONAllocatesTheV2RuntimeAndSevenWords(t *testing.T) {
	g := generateV2(t)
	var parsed struct {
		Alloc map[string]struct {
			Code    string            `json:"code"`
			Storage map[string]string `json:"storage"`
		} `json:"alloc"`
	}
	require.NoError(t, json.Unmarshal(g.GenesisJSON(), &parsed))
	acct, ok := parsed.Alloc[registryproof.RegistryAddress.Hex()[2:]]
	if !ok {
		acct, ok = parsed.Alloc[registryproof.RegistryAddress.Hex()]
	}
	require.True(t, ok, "the registry account is allocated")
	require.Len(t, acct.Storage, 6, "seven genesis words, one of which (shard epoch 0) is the zero word and is not stored")
	a := pinnedArtifactV2(t)
	require.Equal(t, crypto.Keccak256Hash(a.RuntimeCode), crypto.Keccak256Hash(common.FromHex(acct.Code)))
}
