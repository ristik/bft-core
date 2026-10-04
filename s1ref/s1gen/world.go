package s1gen

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// Native CBOR tags (unicity-ids cbor-tags.json).
const (
	tagSeal      = 39005
	tagRoundInfo = 39007

	voteTag    = "UNICITY_POS_VOTE"
	timeoutTag = "UNICITY_POS_TIMEOUT"
)

func sum(parts ...[]byte) [32]byte { return sha256.Sum256(cat(parts...)) }

func hx32(b [32]byte) string { return fmt.Sprintf("%x", b[:]) }

// ---- deterministic randomness -------------------------------------------

// drbg is a counter-mode SHA-256 stream keyed by the seed and a label.
type drbg struct {
	key []byte
	n   uint64
}

func newDRBG(seed string, label string) *drbg {
	h := sha256.Sum256([]byte("s1gen/v1|" + seed + "|" + label))
	return &drbg{key: h[:]}
}

func (d *drbg) hash() [32]byte {
	var c [8]byte
	binary.BigEndian.PutUint64(c[:], d.n)
	d.n++
	return sum(d.key, c[:])
}

// ---- validators and signing ----------------------------------------------

type validator struct {
	id  string
	key *secp256k1.PrivateKey
	pub []byte // compressed, 33 bytes
}

func makeValidator(seed string, id string) validator {
	h := sha256.Sum256([]byte("s1gen/v1|" + seed + "|key|" + id))
	k := secp256k1.PrivKeyFromBytes(h[:])
	return validator{id: id, key: k, pub: k.PubKey().SerializeCompressed()}
}

var curveN = secp256k1.S256().N

// sign is the 64-byte low-s RFC 6979 signature r||s over the SHA-256 digest of
// msg (the signers hash the preimage themselves).
func (v validator) sign(msg []byte) []byte {
	digest := sha256.Sum256(msg)
	compact := ecdsa.SignCompact(v.key, digest[:], true) // header | r | s
	return append([]byte{}, compact[1:65]...)
}

// signV is r||s||v with the true recovery id.
func (v validator) signV(msg []byte) []byte {
	digest := sha256.Sum256(msg)
	compact := ecdsa.SignCompact(v.key, digest[:], true)
	return append(append([]byte{}, compact[1:65]...), compact[0]-27-4)
}

// signNonce is a different valid low-s signature of the same message, made with
// an explicit nonce derived from label. It is what an independently generated
// signature of the same statement looks like.
func (v validator) signNonce(msg []byte, label string) []byte {
	digest := sha256.Sum256(msg)
	for i := 0; ; i++ {
		kb := sha256.Sum256([]byte(fmt.Sprintf("s1gen/v1|nonce|%s|%x|%d", label, v.pub, i)))
		var k secp256k1.ModNScalar
		if k.SetBytes(&kb) != 0 || k.IsZero() {
			continue
		}
		var R secp256k1.JacobianPoint
		secp256k1.ScalarBaseMultNonConst(&k, &R)
		R.ToAffine()
		xb := R.X.Bytes()
		var r secp256k1.ModNScalar
		r.SetBytes(xb)
		if r.IsZero() {
			continue
		}
		var z secp256k1.ModNScalar
		z.SetBytes(&digest)
		var s, kinv secp256k1.ModNScalar
		s.Set(&r).Mul(&v.key.Key).Add(&z)
		kinv.Set(&k).InverseNonConst()
		s.Mul(&kinv)
		if s.IsZero() {
			continue
		}
		if s.IsOverHalfOrder() {
			s.Negate()
		}
		rb, sb := r.Bytes(), s.Bytes()
		return append(rb[:], sb[:]...)
	}
}

// highS returns r || (n-s) [|| rest of sig] for the signature sig.
func highS(sig []byte) []byte {
	s := new(big.Int).SetBytes(sig[32:64])
	s.Sub(curveN, s)
	out := append([]byte{}, sig...)
	copy(out[32:64], pad32(s))
	return out
}

func pad32(n *big.Int) []byte {
	b := n.Bytes()
	return append(make([]byte, 32-len(b)), b...)
}

// withV returns the 64-byte signature with a recovery byte appended.
func withV(sig []byte, v byte) []byte { return append(append([]byte{}, sig[:64]...), v) }

// setRS replaces r and s of a signature.
func setRS(sig []byte, r, s *big.Int) []byte {
	out := append([]byte{}, sig...)
	copy(out[:32], pad32(r))
	copy(out[32:64], pad32(s))
	return out
}

func flip(b []byte, i int) []byte { c := append([]byte{}, b...); c[i] ^= 0x01; return c }
