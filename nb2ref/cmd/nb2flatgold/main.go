// Command nb2flatgold writes the independently encoded protocol 10 golden files.
// It intentionally does not import nb2ref.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/sha3"
)

func join(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
func u16(n uint16) []byte     { return binary.BigEndian.AppendUint16(nil, n) }
func u64(n uint64) []byte     { return binary.BigEndian.AppendUint64(nil, n) }
func address(n uint16) []byte { return join(make([]byte, 18), u16(n)) }
func word(n uint64) []byte    { return join(make([]byte, 24), u64(n)) }
func sha(in []byte) []byte    { h := sha256.Sum256(in); return h[:] }
func keccak(in []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(in)
	return h.Sum(nil)
}
func hash(label string, parts ...[]byte) []byte {
	return keccak(join(keccak([]byte("UNICITY/NB2/CONT/1.1/"+label)), join(parts...)))
}
func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n <= 255:
		return []byte{major<<5 | 24, byte(n)}
	case n <= 65535:
		return join([]byte{major<<5 | 25}, u16(uint16(n)))
	default:
		panic("golden CBOR field exceeds its supported width")
	}
}
func str(b []byte) []byte           { return join(head(2, uint64(len(b))), b) }
func arr(fields ...[]byte) []byte   { return join(head(4, uint64(len(fields))), join(fields...)) }
func tag(n uint64, v []byte) []byte { return join(head(6, n), v) }
func repeat(b byte, n int) []byte   { return []byte(strings.Repeat(string([]byte{b}), n)) }
func assert(v []byte, want string) {
	if fmt.Sprintf("%x", v) != want {
		panic(fmt.Sprintf("golden mismatch: %x != %s", v, want))
	}
}

func vectors() map[string][]byte {
	const root = "2d0ef1e19cded2205f2701f7d92dff64a133324c482e40506ca4a153cae2e43b"
	execution := sha([]byte("fixture-execution-genesis"))
	stem := fmt.Sprintf("3:%s:%x:31337", root, execution)
	ty := sha([]byte("unicity-bridge:unicity-native-nb2-11:" + stem))
	aid := sha([]byte("unicity-bridge-coin:unicity-native-nb2-11:" + stem))
	asset := sha([]byte("unicity-nb2-asset:native-uct"))
	registry := hx("ff00000000000000000000000000000000000002")
	ordinary := keccak(hx("600000"))
	receipt := keccak(hx("600100"))
	recovery := keccak(hx("600300"))
	vault := address(0xf200)
	vectors := map[string][]byte{}
	descriptors := []string{"cert-batch-v2", "rsmt-member-v1", "seal-registry-layout", "cancun-b1", "build-index", "primitive-vectors"}
	var digests [][]byte
	for _, name := range descriptors {
		data := []byte("fixture/11/" + name)
		vectors["descriptor-"+name+".bin"] = data
		digests = append(digests, sha(data))
	}
	profile := []byte("fixture/11/profile")
	vectors["semantic-profile.bin"] = profile
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(30), nil)
	gamma := arr(str([]byte("UNICITY_NB2_CFG")), hx("02"), hx("03"), str(hx(root)), str(execution), head(0, 31337),
		head(0, 7), str(hx("80")), head(0, 11), str(vault), str(asset), str(ty), str(aid), str(sha(profile)),
		str(address(0xf203)), str(ordinary), head(0, 64), head(0, 16), str(max.Bytes()))
	d := sha(gamma)
	release := hash("RELEASE", digests...)
	rec := func(role uint16, addr, digest []byte) []byte { return join(u16(role), addr, digest) }
	records := join(rec(1, address(0xf203), ordinary), rec(2, address(0xf201), receipt),
		rec(3, address(0x0100), digests[0]), rec(4, address(0x0102), digests[1]),
		rec(5, registry, hash("REGISTRY", keccak(hx("600200")), digests[2])))
	p := hash("PINS", release, u16(5), records)
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}
	g := hash("GEN", salt, d)
	prelude := join([]byte("NB2L"), u16(0x0101), u64(1))
	page := hash("PAGE", u64(uint64(len(prelude))), u64(0), u16(uint16(len(prelude))), prelude)
	session := hash("SESSION", u16(0x0101), g, d, vault, address(0xf202), recovery, p, u64(uint64(len(prelude))), page)
	link := sha(join([]byte("UNICITY/NB2/1.1/PARENT"), d, repeat(0x11, 32), repeat(0x22, 32), repeat(0x33, 32), repeat(0x44, 32), word(7)))
	predicate := tag(39032, arr(hx("01"), str(hx("01")), str(hx("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"))))
	reason := tag(39044, arr(hx("02"), str(link)))
	value := tag(39050, arr(hx("01"), arr(arr(str(aid), str(hx("01")))), hx("f6")))
	mint := tag(39041, arr(hx("02"), hx("03"), predicate, str(make([]byte, 32)), str(ty), str(reason), str(value), hx("f6")))
	assert(d, "0878e7b9e52631f9e2a88eb66b68f42e84af0ddef6ad45b95636b3d98bb56b03")
	assert(release, "bfe8e92ddedc6c902d1d47ad4836011512670f98cfec6da08b1f8efac10cf772")
	assert(p, "b791b5781de4389d6c952c3e6c41626ea9b4584df1d6ec264a38515dce633175")
	assert(g, "7d78535d4ba465388ac887cb8b2e69709bf9eb4e37decd29cd1637c90e9fafa8")
	assert(page, "41a4539a25ea82d7af3a230f9bf19e1c6ef9b84e1a5cc8cd9ade9eba9c6fca8d")
	assert(session, "a51d142480f382058fa6475cafa7f8030b64f020781605e792284fd1bca604b7")
	assert(link, "d392d1f3decfc4046f504921fe94c0b8f89c7cff8759fc26a3e6e86e4a6506d9")
	assert(sha(mint), "40f57865e96167738811b0d053a20bedbdad686c4488a77d0d39fff9ac219230")
	for name, data := range map[string][]byte{"gamma": gamma, "domain": d, "release": release, "pin-records": records,
		"pins": p, "generation-salt": salt, "generation": g, "prelude": prelude, "page-root": page, "session": session,
		"parent-link": link, "child-mint": mint, "child-mint-hash": sha(mint)} {
		vectors[name+".bin"] = data
	}
	defaults := func(label string) []byte {
		v := make([]byte, 32)
		for range 256 {
			v = hash(label, v, v)
		}
		return v
	}
	state := join(hx("01"), u64(0), u64(14), u64(1), u64(0), defaults("SID_NODE"), defaults("CLAIM_NODE"), make([]byte, 193))
	vectors["initial-state.bin"] = state
	vectors["initial-state-digest.bin"] = hash("STATE", session, state)
	for name, signature := range map[string]string{
		"run": "run(bytes)", "advance-gaps": "advanceGaps(bytes)", "redeem-recovered": "redeemRecovered(bytes)",
		"progress": "NB2Progress11(bytes32,uint64,bytes32)",
		"complete": "NB2Complete11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256)",
		"gap":      "NB2Gap11(bytes32,uint64,bytes32,bytes32,uint64,bytes32,address,uint256,uint64,bytes32)",
	} {
		digest := keccak([]byte(signature))
		if strings.HasSuffix(signature, "(bytes)") {
			digest = digest[:4]
		}
		vectors[name+"-signature.bin"] = digest
	}
	return vectors
}

func main() {
	if len(os.Args) != 2 {
		panic("usage: nb2flatgold OUTPUT_DIRECTORY")
	}
	dir := os.Args[1]
	if err := os.MkdirAll(dir, 0755); err != nil {
		panic(err)
	}
	all := vectors()
	var names []string
	for name := range all {
		names = append(names, name)
	}
	sort.Strings(names)
	var manifest strings.Builder
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0644); err != nil {
			panic(err)
		}
	}
	for _, name := range names {
		write(name, all[name])
		fmt.Fprintf(&manifest, "%x  %s\n", sha(all[name]), name)
	}
	write("MANIFEST", []byte(manifest.String()))
}
