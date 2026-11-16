package nb2ref

import (
	"crypto/sha256"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// HU is H_U, raw SHA-256 (the Unicity hash).
func HU(parts ...[]byte) [32]byte {
	h := sha256.New()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// HE is H_E, EVM keccak256.
func HE(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

// Imprint is I(h) = 0x0000 || h, the SHA-256 data hash imprint.
func Imprint(h [32]byte) []byte { return append([]byte{0, 0}, h[:]...) }

var (
	secpN     = secp256k1.S256().Params().N
	secpHalfN = new(big.Int).Rsh(secpN, 1)
)

// UnlockMessage is H(C(b(sourceHash32), b(txHash32))).
func UnlockMessage(sourceHash, txHash [32]byte) [32]byte {
	return HU(CArr(CBytes(sourceHash[:]), CBytes(txHash[:])))
}

// VerifyUnlock is the token-unlock rule over the unlock message H(C(b(sourceHash32), b(txHash32))); see VerifyUnlockDigest.
func VerifyUnlock(key *secp256k1.PublicKey, sourceHash, txHash [32]byte, unlock []byte) error {
	return VerifyUnlockDigest(key, UnlockMessage(sourceHash, txHash), unlock)
}

// VerifyUnlockDigest is the SDK token-unlock rule of protocol 7 under the NB2 unlock restriction (section 14.4, profile
// artifact 5 unlockRestriction): exactly 65 bytes r||s||id (UnlockLength), 1 <= r < n and 1 <= s <= n/2 (UnlockScalars), id in
// 0..1 (UnlockRecovery), the key recovered with the supplied id equal to the source key (UnlockKey), then the compact
// verification. Nothing is normalised. The pinned SDK admits ids 0..3; NB2 refuses 2 and 3 as UnlockRecovery even when the
// signature is valid and recovers the source key, so wallets, plug-in admission, this reference and the Solidity verifier
// accept the same unlocks. Under this order the compact verification cannot fail once the recovered key equals the source key,
// so it has no rule of its own (the Unlock name was dropped, coordinator ruling 2026-11-15); it stays as defense in depth and
// reports UnlockKey.
func VerifyUnlockDigest(key *secp256k1.PublicKey, digest [32]byte, unlock []byte) error {
	if len(unlock) != 65 {
		return fail(ErrUnlockLength)
	}
	r := new(big.Int).SetBytes(unlock[:32])
	s := new(big.Int).SetBytes(unlock[32:64])
	if r.Sign() == 0 || r.Cmp(secpN) >= 0 || s.Sign() == 0 || s.Cmp(secpHalfN) > 0 {
		if err := fail(ErrUnlockScalars); err != nil {
			return err
		}
	}
	id := unlock[64]
	if id > 1 {
		if err := fail(ErrUnlockRecovery); err != nil {
			return err
		}
		id &= 3 // disabled: the SDK relation, ids 0..3
	}
	return sdkRecover(key, digest, unlock[:64], id)
}

// sdkRecover is the pinned SDK's recovery step for a recovery id in 0..3: recover with exactly that id (2 and 3 take x = r + n),
// require the recovered key equal to the source key, then compact verify (UnlockKey).
func sdkRecover(key *secp256k1.PublicKey, digest [32]byte, rs []byte, id byte) error {
	compact := make([]byte, 65)
	compact[0] = 27 + 4 + id
	copy(compact[1:], rs)
	rec, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil || !rec.IsEqual(key) {
		if err := fail(ErrUnlockKey); err != nil {
			return err
		}
		return nil
	}
	var r, s secp256k1.ModNScalar
	r.SetByteSlice(rs[:32])
	s.SetByteSlice(rs[32:])
	if !ecdsa.NewSignature(&r, &s).Verify(digest[:], key) {
		return ErrUnlockKey
	}
	return nil
}

// SignUnlock produces r||s||id over the unlock message, low-s, with the signer's recovery ID.
func SignUnlock(priv *secp256k1.PrivateKey, sourceHash, txHash [32]byte) []byte {
	d := UnlockMessage(sourceHash, txHash)
	compact := ecdsa.SignCompact(priv, d[:], true)
	out := make([]byte, 65)
	copy(out, compact[1:])
	out[64] = compact[0] - 27 - 4
	return out
}

// MinterScalar is H(C(b("I_AM_UNIVERSAL_MINTER_FOR_"), b(id))), the universal minter's secret for a token ID.
func MinterScalar(id [32]byte) [32]byte {
	return HU(CArr(CBytes([]byte("I_AM_UNIVERSAL_MINTER_FOR_")), CBytes(id[:])))
}

// MinterKeyFromScalar admits a minter scalar only when it is a valid secp256k1 secret, 1 <= k < n, never reduced modulo n
// (ErrInvalidMinterScalar, not a rule: no token ID with an invalid scalar is known; the scalar form is what the vectors test).
func MinterKeyFromScalar(k [32]byte) (*secp256k1.PrivateKey, error) {
	var sc secp256k1.ModNScalar
	if overflow := sc.SetByteSlice(k[:]); overflow || sc.IsZero() {
		return nil, ErrInvalidMinterScalar
	}
	return secp256k1.PrivKeyFromBytes(k[:]), nil
}

// MinterKey is the universal minter key of a token ID.
func MinterKey(id [32]byte) (*secp256k1.PrivateKey, error) {
	return MinterKeyFromScalar(MinterScalar(id))
}

// ParseKey parses a compressed secp256k1 key (Predicate on failure).
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

// KeyFromSeed derives a deterministic signing key for fixtures.
func KeyFromSeed(seed string) *secp256k1.PrivateKey {
	for i := 0; ; i++ {
		k := HU([]byte(seed), []byte{byte(i)})
		var sc secp256k1.ModNScalar
		if !sc.SetByteSlice(k[:]) && !sc.IsZero() {
			return secp256k1.PrivKeyFromBytes(k[:])
		}
	}
}
