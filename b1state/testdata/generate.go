//go:build ignore

// Independently constructs A′ bytes/slots from the written spec. It imports
// neither b1state nor the caller oracle. Run from the module root:
// go run ./b1state/testdata/generate.go > b1state/testdata/projection.json
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/fxamacker/cbor/v2"
	"os"
	"strings"
)

func hx(b []byte) string     { return hex.EncodeToString(b) }
func hashByte(b byte) []byte { v := make([]byte, 32); v[0] = b; return v }
func word(n uint64) []byte   { b := make([]byte, 32); binary.BigEndian.PutUint64(b[24:], n); return b }
func fixed(s string) []byte  { return crypto.Keccak256([]byte("unicity.seal-registry/" + s)) }
func slot(s string, ns ...uint64) string {
	b := fixed(s)
	for _, n := range ns {
		b = append(b, word(n)...)
	}
	return hx(crypto.Keccak256(b))
}
func key(n byte) []byte {
	b := make([]byte, 32)
	b[31] = n
	k, _ := crypto.ToECDSA(b)
	return crypto.CompressPubkey(&k.PublicKey)
}
func entry(words map[string]string, epoch, start, weight uint64, id string, pub []byte) {
	kind := uint64(2)
	commit := hashByte(byte(epoch + 10))
	if epoch == 0 {
		kind = 1
		commit = make([]byte, 32)
	}
	metadata := [][]byte{word(1), word(kind), hashByte(byte(epoch + 1)), commit, word(start), word(0), word(0), word(1), hashByte(9), word(1), word(weight)}
	for f, w := range metadata {
		words[slot("b1.entry", epoch, uint64(f))] = hx(w)
	}
	ms := make([][]byte, 8)
	for i := range ms {
		ms[i] = make([]byte, 32)
	}
	ms[0] = word(uint64(len(id)))
	for i, b := range []byte(id) {
		ms[1+i/32][i%32] = b
	}
	copy(ms[5], pub[:32])
	ms[6][0] = pub[32]
	ms[7] = word(weight)
	for f, w := range ms {
		words[slot("b1.member", epoch, 0, uint64(f))] = hx(w)
	}
}
func main() {
	enc, _ := cbor.CoreDetEncOptions().EncMode()
	encode := func(v any) []byte {
		b, err := enc.Marshal(v)
		if err != nil {
			panic(err)
		}
		return b
	}
	// Synthetic fixture pins: these do not name a real compiler/runtime/G_rest.
	profile := []any{"UNICITY_B1_PROFILE", uint64(3), uint64(1), uint64(2), uint64(3), uint64(49706068), uint64(0), uint64(56706068), uint64(7000000), uint64(100), uint64(1000000), uint64(1024), uint64(2), uint64(36864), uint64(564), uint64(1000), hashByte(1), uint64(2), hashByte(3), hashByte(4), uint64(64), uint64(128), uint64(16384), uint64(16), uint64(262144), uint64(24576), uint64(32768), "scan=2000+16C;members=1000T;UC=60000+16B+64000+6000S+2000N+250P+1117700;RSMT=2000+16B+250(1+popcount);I=22100;D=7100", "P85-import=scan 2000+16C_R;entries 1000N;C_R<=16384;N<=32;outcome=[system,G_pre,1,'',SHA256(rootInput)];G_pre=admit+open+import", "native-body=1,2,3;signing=1,2;quorum=total-(total-1)/3;claims=8;signatures=64/512;shard=33/256;path=32;summary=256;RSMT=4096/256/12392"}
	pb := encode(profile)
	ph := sha256.Sum256(pb)
	id := strings.Repeat("a", 128)
	pub := key(1)
	member := []any{id, pub, uint64(7)}
	e := []any{uint64(2), uint64(2), hashByte(3), hashByte(12), uint64(9), nil, uint64(1), hashByte(9), []any{member}}
	u := []any{"UNICITY_B1_UPDATE", uint64(3), hashByte(1), uint64(2), ph[:], hashByte(5), uint64(1), uint64(2), uint64(10), hashByte(6), uint64(0), uint64(8), []any{e}}
	ub := encode(u)
	uh := sha256.Sum256(ub)
	genesis := map[string]string{}
	for name, w := range map[string][]byte{"b1.network": word(3), "b1.wCert": word(1), "b1.profileHash": ph[:], "b1.initialized": word(1), "b1.head": word(0), "b1.count": word(1), "clock.rootRound": word(0), "origin.rootEpoch": word(0), "assignment.rootEpoch": word(0), "records.ucTime": word(1000), "phase": word(2)} {
		genesis[hx(fixed(name))] = hx(w)
	}
	entry(genesis, 0, 7, 1, id, pub)
	genesis[slot("b1.queue", 0)] = hx(word(0))
	// Parent ring head 1, epoch zero. Full eviction resets head; expired epoch 1
	// was authenticated upstream but has no storage words in this delta.
	changed := map[string]string{}
	for f := uint64(0); f < 11; f++ {
		changed[slot("b1.entry", 0, f)] = hx(word(0))
	}
	for f := uint64(0); f < 8; f++ {
		changed[slot("b1.member", 0, 0, f)] = hx(word(0))
	}
	changed[slot("b1.queue", 1)] = hx(word(0))
	entry(changed, 2, 9, 7, id, pub)
	changed[slot("b1.queue", 0)] = hx(word(2))
	changed[hx(fixed("b1.head"))] = hx(word(0))
	changed[hx(fixed("b1.count"))] = hx(word(1))
	out := map[string]any{"note": "Synthetic independent Go fixture; no PR3 runtime or authenticated admission. Genesis operational origin is zero before the first prefix.", "profileBytes": hx(pb), "profileHash": hx(ph[:]), "updateBytes": hx(ub), "updateHash": hx(uh[:]), "scanGas": 2000 + 16*len(ub), "memberGas": 1000, "genesisWords": genesis, "changedWords": changed, "rootKey": hx(pub), "distinctDelegatedEVMKey": hx(key(9)), "parentOrigin": 7, "origin": 10, "wCert": 1, "oldTipEnd": 8, "retainedEpochs": []int{2}}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", " ")
	if err := encoder.Encode(out); err != nil {
		panic(err)
	}
}
