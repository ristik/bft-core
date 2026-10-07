package bridgeprofile

import (
	"crypto/sha256"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// H is raw SHA-256.
func H(b []byte) [32]byte { return sha256.Sum256(b) }

// Imprint is I(h) = 0x0000 || h, the 34-byte SHA-256 data hash imprint.
func Imprint(h [32]byte) []byte { return append([]byte{0, 0}, h[:]...) }

var secpN = secp256k1.S256().Params().N
var secpHalfN = new(big.Int).Rsh(secpN, 1)

// UnlockMessage is H(C(b(sourceHash32), b(txHash32))) with no extra prehash.
func UnlockMessage(sourceHash, txHash [32]byte) [32]byte {
	return H(CArr(CBytes(sourceHash[:]), CBytes(txHash[:])))
}

// VerifyUnlock is the one token-unlock acceptance rule: exactly 65 bytes,
// 1<=r<n, 1<=s<=n/2, recovery ID 0..3, recover the signer from the digest and
// (r,s,id), require it to equal the reconstructed source key, then verify
// (r,s) against that key. The supplied recovery ID and a high-s signature are
// never normalised. A range check on the ID alone is not sufficient.
func VerifyUnlock(key *secp256k1.PublicKey, sourceHash, txHash [32]byte, unlock []byte) error {
	if len(unlock) != 65 {
		return ErrUnlockLength
	}
	r := new(big.Int).SetBytes(unlock[:32])
	s := new(big.Int).SetBytes(unlock[32:64])
	if r.Sign() == 0 || r.Cmp(secpN) >= 0 || s.Sign() == 0 || s.Cmp(secpHalfN) > 0 {
		return ErrUnlockScalars
	}
	id := unlock[64]
	if id > 3 {
		return ErrUnlockRecovery
	}
	digest := UnlockMessage(sourceHash, txHash)
	// RecoverCompact takes 27+4(compressed)+id || r || s.
	compact := make([]byte, 65)
	compact[0] = 27 + 4 + id
	copy(compact[1:], unlock[:64])
	rec, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return ErrUnlockKey
	}
	if !rec.IsEqual(key) {
		return ErrUnlockKey
	}
	var rs, ss secp256k1.ModNScalar
	rs.SetByteSlice(unlock[:32])
	ss.SetByteSlice(unlock[32:64])
	if !ecdsa.NewSignature(&rs, &ss).Verify(digest[:], key) {
		return ErrUnlock
	}
	return nil
}

// SignUnlock produces r||s||id over the unlock message, recovery ID as
// produced by the signer, low-s. Used by the oracle's builders.
func SignUnlock(priv *secp256k1.PrivateKey, sourceHash, txHash [32]byte) []byte {
	d := UnlockMessage(sourceHash, txHash)
	compact := ecdsa.SignCompact(priv, d[:], true)
	out := make([]byte, 65)
	copy(out, compact[1:])
	out[64] = compact[0] - 27 - 4
	return out
}

// MinterKey derives the universal minter scalar H(C(b("I_AM_UNIVERSAL_MINTER_FOR_"), b(id))),
// which must be a valid secp256k1 scalar (1<=k<n).
func MinterKey(id [32]byte) (*secp256k1.PrivateKey, error) {
	k := H(CArr(CBytes([]byte("I_AM_UNIVERSAL_MINTER_FOR_")), CBytes(id[:])))
	var sc secp256k1.ModNScalar
	if overflow := sc.SetByteSlice(k[:]); overflow || sc.IsZero() {
		return nil, ErrMinterKey
	}
	return secp256k1.PrivKeyFromBytes(k[:]), nil
}

// ParseKey parses a compressed secp256k1 key.
func ParseKey(b []byte) (*secp256k1.PublicKey, error) {
	if len(b) != 33 || (b[0] != 2 && b[0] != 3) {
		return nil, ErrPredicate
	}
	k, err := secp256k1.ParsePubKey(b)
	if err != nil {
		return nil, ErrPredicate
	}
	return k, nil
}
