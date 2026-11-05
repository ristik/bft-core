package b1gen

import (
	"crypto/sha256"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

// keylessMember builds a signature with recovery ID 2 or 3 that recovers, over SHA-256(msg), to a public key, and returns that key: a member
// whose key is DEFINED as the recovery result and whose private key nobody holds. Ordinary signing never yields these IDs (they need the
// R point's x coordinate to be r + n, probability about 2^-127), so a genuine v=2/v=3 case is constructed instead: pick r so that r + n is the
// x coordinate of a curve point R (the parity of its y gives the low bit of v), pick any low s, and solve ECDSA recovery for the key,
// Q = r^-1 (s*R - z*G) with z = SHA-256(msg) mod n.
func keylessMember(msg []byte, id int) (sig, pub []byte) {
	if id != 2 && id != 3 {
		panic("keylessMember: recovery ID must be 2 or 3")
	}
	z := sha256.Sum256(msg)
	var zs secp256k1.ModNScalar
	zs.SetByteSlice(z[:]) // reduced mod n, as in ECDSA
	prefix := byte(2 + id&1)

	p := secp256k1.S256().P
	for r := int64(1); ; r++ {
		x := new(big.Int).Add(curveN, big.NewInt(r))
		if x.Cmp(p) >= 0 {
			panic("keylessMember: no r found below the field size")
		}
		R, err := secp256k1.ParsePubKey(append([]byte{prefix}, pad32(x)...))
		if err != nil {
			continue // r + n is not the x coordinate of a curve point
		}
		var rs, s, rInv secp256k1.ModNScalar
		rs.SetByteSlice(pad32(big.NewInt(r)))
		s.SetByteSlice(pad32(new(big.Int).Rsh(curveN, 2))) // a fixed low s: n/4
		rInv.Set(&rs).InverseNonConst()
		var k1, k2 secp256k1.ModNScalar
		k1.Set(&s).Mul(&rInv)
		k2.Set(&zs).Mul(&rInv).Negate()

		var rj, a, b, sum secp256k1.JacobianPoint
		R.AsJacobian(&rj)
		secp256k1.ScalarMultNonConst(&k1, &rj, &a)
		secp256k1.ScalarBaseMultNonConst(&k2, &b)
		secp256k1.AddNonConst(&a, &b, &sum)
		if (sum.X.IsZero() && sum.Y.IsZero()) || sum.Z.IsZero() {
			continue
		}
		sum.ToAffine()
		pub = secp256k1.NewPublicKey(&sum.X, &sum.Y).SerializeCompressed()

		sig = append(append(append([]byte{}, pad32(big.NewInt(r))...), pad32(new(big.Int).Rsh(curveN, 2))...), byte(id))
		return sig, pub
	}
}

// checkSealSignatureFor is the generator's own check, with the base library, that sig is a canonical recoverable signature of msg by the key pub.
func checkSealSignatureFor(pub, sig, msg []byte) error {
	v, err := abcrypto.NewVerifierSecp256k1(pub)
	if err != nil {
		return err
	}
	return v.VerifyBytes(sig, msg)
}
