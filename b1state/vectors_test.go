package b1state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestIndependentStorageAndUpdateVector(t *testing.T) {
	var v struct {
		ProfileHash, UpdateBytes, UpdateHash string
		ScanGas, MemberGas                   uint64
		GenesisWords, ChangedWords           map[string]string
		RootKey, DistinctDelegatedEVMKey     string
	}
	raw, err := os.ReadFile("testdata/projection.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	p := fixtureProfile(1)
	h, err := p.Hash()
	if err != nil || hex.EncodeToString(h[:]) != v.ProfileHash {
		t.Fatal("profile hash", h, err)
	}
	updateBytes, err := hex.DecodeString(v.UpdateBytes)
	if err != nil {
		t.Fatal(err)
	}
	u, gas, err := Admit(updateBytes, p, p.SystemGas)
	if err != nil || gas != v.ScanGas+v.MemberGas {
		t.Fatal(gas, err)
	}
	digest := sha256.Sum256(updateBytes)
	if hex.EncodeToString(digest[:]) != v.UpdateHash || u.Hash() != digest {
		t.Fatal("update commitment")
	}
	g := fixtureEntry(0, 7)
	g.Members[0].NodeID = strings.Repeat("a", 128)
	words, err := GenesisWords(p, g)
	if err != nil {
		t.Fatal(err)
	}
	asJSON := func(words map[[32]byte][32]byte) map[string]string {
		m := map[string]string{}
		for slot, word := range words {
			m[hex.EncodeToString(slot[:])] = hex.EncodeToString(word[:])
		}
		return m
	}
	if !reflect.DeepEqual(asJSON(words), v.GenesisWords) {
		t.Fatal("genesis words")
	}
	out, changed, err := (Ring{Head: 1, GenesisStart: 7, OriginRound: 7, Entries: []Entry{g}}).Apply(u, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Entries) != 1 || out.Entries[0].Epoch != 2 || !reflect.DeepEqual(asJSON(changed.Final), v.ChangedWords) {
		t.Fatal("changed words")
	}
	if v.RootKey == v.DistinctDelegatedEVMKey || hex.EncodeToString(g.Members[0].Key[:]) != v.RootKey {
		t.Fatal("root/EVM key separation")
	}
}
