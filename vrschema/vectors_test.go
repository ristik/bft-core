package vrschema

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/stretchr/testify/require"
)

const vectorDir = "../testvectors/validator-registry"

var (
	genOnce  sync.Once
	genFiles map[string][]byte
	genErr   error
)

func generated(t *testing.T) map[string][]byte {
	t.Helper()
	genOnce.Do(func() { genFiles, genErr = Generate() })
	require.NoError(t, genErr)
	return genFiles
}

func committed(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vectorDir, name))
	require.NoError(t, err, "regenerate with go generate ./vrschema")
	return b
}

// The checked-in vectors are exactly a fresh generation, and the manifest covers every file in the directory.
func TestVectorsAreCommitted(t *testing.T) {
	files := generated(t)
	for name, b := range files {
		require.True(t, bytes.Equal(b, committed(t, name)), "%s is stale: regenerate with go generate ./vrschema", name)
	}
	all := map[string][]byte{}
	for k, v := range files {
		all[k] = v
	}
	all[ForgeFixture] = committed(t, ForgeFixture)
	require.Equal(t, string(Manifest(all)), string(committed(t, "MANIFEST.sha256")))
	entries, err := os.ReadDir(vectorDir)
	require.NoError(t, err)
	for _, e := range entries {
		if e.Name() == "MANIFEST.sha256" || e.Name() == "README.md" {
			continue
		}
		require.Contains(t, string(committed(t, "MANIFEST.sha256")), "  "+e.Name()+"\n", "file %s is not in the manifest", e.Name())
	}
}

// The Solidity fixture (forge) wrote exactly the nonzero slots and words the Go layout derives.
func TestForgeStorageIsTheGoLayout(t *testing.T) {
	var f struct {
		Scenarios map[string]struct {
			Account string   `json:"account"`
			Slots   []string `json:"slots"`
			Words   []string `json:"words"`
		} `json:"scenarios"`
	}
	require.NoError(t, json.Unmarshal(committed(t, ForgeFixture), &f))
	scs := StorageScenarios()
	require.Len(t, f.Scenarios, len(scs))
	for _, sc := range scs {
		got, ok := f.Scenarios[sc.Name]
		require.True(t, ok, sc.Name)
		require.Equal(t, strings.ToLower(hexa(sc.Account)), strings.ToLower(got.Account))
		forge := map[string]string{}
		for i, s := range got.Slots {
			if common.HexToHash(got.Words[i]) != (common.Hash{}) {
				forge[s] = got.Words[i]
			}
		}
		want := map[string]string{}
		for s, w := range sc.Slots {
			if w != (Word{}) {
				want[Hexw(s)] = Hexw(w)
			}
		}
		require.Equal(t, want, forge, sc.Name)
	}
}

type vecFile struct {
	Vectors []struct {
		Name   string          `json:"name"`
		Op     string          `json:"op"`
		Input  json.RawMessage `json:"input"`
		Expect json.RawMessage `json:"expect"`
	} `json:"vectors"`
}

func loadVec(t *testing.T, name string) vecFile {
	var f vecFile
	require.NoError(t, json.Unmarshal(committed(t, name), &f))
	require.NotEmpty(t, f.Vectors)
	return f
}

func hexArg(t *testing.T, s string) []byte {
	b, err := common.ParseHexOrString(s)
	require.NoError(t, err)
	return b
}

// Every storage slot proof verifies against the scenario's storage root and proves the expected word.
func TestStorageProofs(t *testing.T) {
	n := 0
	for _, v := range loadVec(t, "storage.json").Vectors {
		if v.Op != "storage.account" {
			continue
		}
		var exp struct {
			Root  string `json:"storageRoot"`
			Slots []struct {
				Slot  string   `json:"slot"`
				Word  string   `json:"word"`
				Proof []string `json:"proof"`
			} `json:"slots"`
		}
		require.NoError(t, json.Unmarshal(v.Expect, &exp))
		for _, s := range exp.Slots {
			db := memorydb.New()
			for _, node := range s.Proof {
				b := hexArg(t, node)
				k := keccak(b)
				require.NoError(t, db.Put(k[:], b))
			}
			slot := common.HexToHash(s.Slot)
			key := keccak(slot[:])
			val, err := trie.VerifyProof(common.HexToHash(exp.Root), key[:], db)
			require.NoError(t, err, s.Slot)
			word := common.HexToHash(s.Word)
			if word == (common.Hash{}) {
				require.Nil(t, val)
				continue
			}
			require.NotNil(t, val, s.Slot)
			var got []byte
			require.NoError(t, rlp.DecodeBytes(val, &got))
			require.Equal(t, trimWord(word), got, s.Slot)
			n++
		}
	}
	require.Greater(t, n, 60)
}

// The module-return vectors are replayed from the file alone, as a consumer sees them.
func TestCodecVectorsReplay(t *testing.T) {
	decoders := map[string]func([]byte) error{
		"codec.elect":    func(r []byte) error { _, e := DecodeElect(r); return e },
		"codec.output":   func(r []byte) error { _, e := DecodeOutputReturn(r); return e },
		"codec.adoption": func(r []byte) error { _, e := DecodeAdoption(r); return e },
		"codec.void":     func(r []byte) error { return DecodeVoid(r) },
	}
	n := 0
	for _, v := range loadVec(t, "encoding.json").Vectors {
		dec, ok := decoders[v.Op]
		if !ok {
			continue
		}
		var in struct {
			Ret string `json:"returndata"`
		}
		var exp struct {
			Result string `json:"result"`
		}
		require.NoError(t, json.Unmarshal(v.Input, &in))
		require.NoError(t, json.Unmarshal(v.Expect, &exp))
		require.Equal(t, exp.Result, string(Classify(dec(hexArg(t, in.Ret)))), v.Name)
		n++
	}
	require.Greater(t, n, 40)
}

// Generation is deterministic: two runs give identical bytes.
func TestGenerationIsDeterministic(t *testing.T) {
	a := generated(t)
	b, err := Generate()
	require.NoError(t, err)
	require.Equal(t, len(a), len(b))
	for k := range a {
		require.True(t, bytes.Equal(a[k], b[k]), k)
	}
}
