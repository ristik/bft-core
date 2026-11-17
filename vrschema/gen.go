package vrschema

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// Vector is one shared vector. Input and Expect are JSON objects whose keys the category documents; byte strings are 0x-prefixed
// lowercase hex, integers above 2^53 are decimal strings.
type Vector struct {
	Name   string         `json:"name"`
	Op     string         `json:"op"`
	Input  map[string]any `json:"input"`
	Expect map[string]any `json:"expect"`
}

// VectorFile is one vector file.
type VectorFile struct {
	Schema  string   `json:"schema"`
	Version int      `json:"version"`
	File    string   `json:"file"`
	Spec    string   `json:"specification"`
	Notes   []string `json:"notes,omitempty"`
	Vectors []Vector `json:"vectors"`
}

// ForgeFixture is the storage dump the Solidity fixture writes (unicity-pos-contracts test/vr/fixtures/storage-forge.json).
const ForgeFixture = "storage-forge.json"

// SpecPath is the normative text.
const SpecPath = "docs/design/validator-registry/schema-v1.md"

// Hexb is 0x-hex of bytes.
func Hexb(b []byte) string { return "0x" + hex.EncodeToString(b) }

// Hexw is 0x-hex of a word.
func Hexw(w Word) string { return Hexb(w[:]) }

func hexa(a [20]byte) string { return Hexb(a[:]) }

// Dec is an integer as a decimal string (exact in every JSON reader).
func Dec(v uint64) string { return fmt.Sprintf("%d", v) }

func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", " ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// genKey is the i-th deterministic test key: keccak256("unicity.vr.schema.test-key/" + i) reduced into [1, n-1].
func genKey(i int) *ecdsa.PrivateKey {
	n := ethcrypto.S256().Params().N
	d := new(big.Int).SetBytes(ethcrypto.Keccak256([]byte(fmt.Sprintf("unicity.vr.schema.test-key/%d", i))))
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	k, err := ethcrypto.ToECDSA(math32(d))
	if err != nil {
		panic(err)
	}
	return k
}

func math32(d *big.Int) []byte {
	b := make([]byte, 32)
	d.FillBytes(b)
	return b
}

func pubOf(k *ecdsa.PrivateKey) []byte { return ethcrypto.CompressPubkey(&k.PublicKey) }

func signerOf(k *ecdsa.PrivateKey) abcrypto.Signer {
	s, err := abcrypto.NewInMemorySecp256K1SignerFromKey(ethcrypto.FromECDSA(k))
	if err != nil {
		panic(err)
	}
	return s
}

// signDigest is the EVM-side 65-byte r||s||v (v in {27, 28}) low-s signature over a 32-byte digest.
func signDigest(k *ecdsa.PrivateKey, d Word) []byte {
	sig, err := ethcrypto.Sign(d[:], k)
	if err != nil {
		panic(err)
	}
	sig[64] += 27
	return sig
}

func w(s string) Word { return keccak([]byte(s)) }

// Generate builds every vector file; the map is file name -> bytes. A vector whose expectation does not hold against this reference
// is a generator error.
func Generate() (map[string][]byte, error) {
	files := map[string][]byte{}
	add := func(name string, v any) error {
		b, err := encodeJSON(v)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		files[name] = b
		return nil
	}
	if err := add("vr-layout.json", VRLayout()); err != nil {
		return nil, err
	}
	if err := add("constants.json", map[string]any{"schema": SchemaID, "version": SchemaVersion, "constants": ConstantsTable()}); err != nil {
		return nil, err
	}
	gens := []struct {
		name  string
		notes []string
		f     func() ([]Vector, error)
	}{
		{"encoding.json", []string{"encodings: exact bytes, round trips and one rejection per malformed case"}, genEncoding},
		{"statemachine.json", []string{"state machines: VR output and change model, S2a, fold, backoff, view protocol judgments, record replay"}, genStateMachines},
		{"arithmetic.json", []string{"checked arithmetic: levels, timeouts, deadlines, F_r, fee bounds"}, genArithmetic},
		{"storage.json", []string{"storage: slots under the VR and liability namespaces, the expected words, the Go reader's output, and a storage-trie proof per slot; storage-forge.json is the same scenarios written by the Solidity fixture"}, genStorage},
	}
	for _, g := range gens {
		vs, err := g.f()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", g.name, err)
		}
		sort.SliceStable(vs, func(i, j int) bool {
			if vs[i].Op != vs[j].Op {
				return vs[i].Op < vs[j].Op
			}
			return vs[i].Name < vs[j].Name
		})
		for i := 1; i < len(vs); i++ {
			if vs[i].Op == vs[i-1].Op && vs[i].Name == vs[i-1].Name {
				return nil, fmt.Errorf("%s: duplicate vector %s/%s", g.name, vs[i].Op, vs[i].Name)
			}
		}
		if err := add(g.name, VectorFile{Schema: SchemaID, Version: SchemaVersion, File: g.name, Spec: SpecPath, Notes: g.notes, Vectors: vs}); err != nil {
			return nil, err
		}
	}
	flat := map[string]any{}
	for _, sc := range StorageScenarios() {
		keys := make([]Word, 0, len(sc.Slots))
		for k := range sc.Slots {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return Hexw(keys[i]) < Hexw(keys[j]) })
		var ss, ws []string
		for _, k := range keys {
			ss, ws = append(ss, Hexw(k)), append(ws, Hexw(sc.Slots[k]))
		}
		flat[sc.Name] = map[string]any{"account": hexa(sc.Account), "slots": ss, "words": ws}
	}
	if err := add("storage-flat.json", map[string]any{"schema": SchemaID, "version": SchemaVersion, "scenarios": flat}); err != nil {
		return nil, err
	}
	return files, nil
}

// Manifest is the sha256sum-format manifest over the given files (sorted by name).
func Manifest(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for n := range files {
		if n != "MANIFEST.sha256" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var sb strings.Builder
	for _, n := range names {
		d := sha256.Sum256(files[n])
		fmt.Fprintf(&sb, "%x  %s\n", d, n)
	}
	return []byte(sb.String())
}

// Counts is the number of vectors per category (op prefix) of a vector file.
func Counts(b []byte) (map[string]int, error) {
	var f VectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, v := range f.Vectors {
		out[strings.SplitN(v.Op, ".", 2)[0]]++
	}
	return out, nil
}

func errName(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func wb(s string) []byte { x := w(s); return x[:] }
