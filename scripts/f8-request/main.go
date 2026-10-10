// f8-request prints a signed rugregator certification request (hex CBOR, the form `certification_request` takes) for a given seed, so that
// the F8 and Q4 lanes can make an aggregator shard certify a NEW state root (every seed is a distinct StateID). `-check` verifies the layout
// against the lane's canonical fixture (the StateID, the signature and the public key it recovers), so a drift in the wire format fails loudly.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/crypto"
)

func head(major byte, n int) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	default:
		b := []byte{major<<5 | 25, 0, 0}
		binary.BigEndian.PutUint16(b[1:], uint16(n))
		return b
	}
}
func bstr(b []byte) []byte { return append(head(2, len(b)), b...) }
func tag(t uint16) []byte  { return []byte{0xd9, byte(t >> 8), byte(t)} }
func cat(parts ...[]byte) []byte {
	return bytes.Join(parts, nil)
}

const (
	tagCertData  = 39030
	tagTxn       = 39031
	tagPredicate = 39032
)

func predicate(pub []byte) []byte {
	return cat(tag(tagPredicate), head(4, 3), []byte{0x01}, bstr([]byte{0x01}), bstr(pub))
}
func stateID(pub, source []byte) [32]byte {
	return sha256.Sum256(cat([]byte{0x82}, predicate(pub), bstr(source)))
}
func sigHash(source, txh []byte) [32]byte {
	return sha256.Sum256(cat([]byte{0x82}, bstr(source), bstr(txh)))
}

// build is the request of key for (source, txh): [1, stateID, tag[2, predicate, source, txh, null, signature], 0] (arrays of 4 and 6)
func build(key []byte, source, txh []byte) ([]byte, error) {
	priv, err := crypto.ToECDSA(key)
	if err != nil {
		return nil, err
	}
	pub := crypto.CompressPubkey(&priv.PublicKey)
	h := sigHash(source, txh)
	sig, err := crypto.Sign(h[:], priv)
	if err != nil {
		return nil, err
	}
	id := stateID(pub, source)
	return cat(tag(tagCertData), head(4, 4), []byte{0x01}, bstr(id[:]),
		tag(tagTxn), head(4, 6), []byte{0x02}, predicate(pub), bstr(source), bstr(txh), []byte{0xf6}, bstr(sig),
		[]byte{0x00}), nil
}

// the lane's canonical fixture (scripts/f8-mixed-lane.sh F8_LOAD_REQUEST), as its parts
const fixtureHex = "d9987684015820ffb36b55de9bfaf48b766d1f4e041a6c5d35ba23b402ea2a56a6c7692cb8f81ad998778602d9987883014101582103a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f963507582" + "0e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e615241" + "5820c034e096d7bdf71ba759558663b5cafb7279ecb7e284443e5e6cbce0461aceee" + "f6" + "584154ca6b19a7dbcae7a6adc38af5c8672f81943ecaf51345436684299b4b7ac81a57db2653f32048981e37913db4749ca08d998d1fac4a52ab5579988bc2c50de900" + "00"

func check() error {
	raw, err := hex.DecodeString(fixtureHex)
	if err != nil {
		return err
	}
	pub, _ := hex.DecodeString("03a19eef04b8856f50bf2d688b0d8804575115e53d2a7780da363628343f963507")
	source, _ := hex.DecodeString("e4b183ff6b7a399983cee26e4feea85d517dede0142def5c838e593a9e615241")
	txh, _ := hex.DecodeString("c034e096d7bdf71ba759558663b5cafb7279ecb7e284443e5e6cbce0461aceee")
	sig, _ := hex.DecodeString("54ca6b19a7dbcae7a6adc38af5c8672f81943ecaf51345436684299b4b7ac81a57db2653f32048981e37913db4749ca08d998d1fac4a52ab5579988bc2c50de900")
	id := stateID(pub, source)
	if !bytes.Contains(raw, bstr(id[:])) {
		return fmt.Errorf("the StateID formula does not reproduce the fixture's")
	}
	h := sigHash(source, txh)
	rec, err := crypto.SigToPub(h[:], sig)
	if err != nil {
		return fmt.Errorf("the fixture's signature does not recover: %w", err)
	}
	if !bytes.Equal(crypto.CompressPubkey(rec), pub) {
		return fmt.Errorf("the signature hash formula does not recover the fixture's public key")
	}
	// the layout: rebuilding the fixture's own fields yields its bytes except for the (non-deterministic-by-key) signature, which we reuse
	rebuilt := cat(tag(tagCertData), head(4, 4), []byte{0x01}, bstr(id[:]), tag(tagTxn), head(4, 6), []byte{0x02}, predicate(pub), bstr(source), bstr(txh), []byte{0xf6}, bstr(sig), []byte{0x00})
	if !bytes.Equal(rebuilt, raw) {
		return fmt.Errorf("the layout does not reproduce the fixture's bytes")
	}
	return nil
}

func main() {
	seed := flag.Uint("seed", 1, "distinct per request: the source state hash and the transaction hash derive from it")
	doCheck := flag.Bool("check", false, "verify the layout against the canonical fixture and exit")
	flag.Parse()
	if *doCheck {
		if err := check(); err != nil {
			fmt.Fprintln(os.Stderr, "f8-request:", err)
			os.Exit(1)
		}
		fmt.Println("f8-request: layout matches the canonical fixture")
		return
	}
	var s [8]byte
	binary.BigEndian.PutUint64(s[:], uint64(*seed))
	key := sha256.Sum256(append([]byte("f8-request key "), s[:]...))
	source := sha256.Sum256(append([]byte("f8-request source "), s[:]...))
	txh := sha256.Sum256(append([]byte("f8-request tx "), s[:]...))
	raw, err := build(key[:], source[:], txh[:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "f8-request:", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(raw))
}
