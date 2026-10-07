package bridgeprofile

import (
	"encoding/binary"
	"math/big"

	"golang.org/x/crypto/sha3"
)

// Slot numbers of the BridgeVault storage layout (design "Vault state").
const (
	SlotLastNonce      = 0
	SlotLocked         = 1
	SlotCredited       = 2
	SlotPaid           = 3
	SlotEntered        = 4
	SlotLockDigest     = 5
	SlotSpentNullifier = 6
	SlotClaimable      = 7
)

// DeriveSalt is salt = H(C("UNICITY_BR_SALT", b(cfg), n)).
func DeriveSalt(cfg [32]byte, n uint64) [32]byte {
	return H(CArr(CBytes([]byte("UNICITY_BR_SALT")), CBytes(cfg[:]), CUint(n)))
}

// DeriveTokenID is id = H(C(b(salt), network)).
func DeriveTokenID(salt [32]byte, network uint16) [32]byte {
	return H(CArr(CBytes(salt[:]), CUint(uint64(network))))
}

// mintSuffix is H("TOKENID").
var mintSuffix = H([]byte("TOKENID"))

// MintSourceHash is h0 = H(C(b(id), b(H("TOKENID")))).
func MintSourceHash(id [32]byte) [32]byte {
	return H(CArr(CBytes(id[:]), CBytes(mintSuffix[:])))
}

// LockRecord is K = [b(zeroAddress), b(ty), b(aid), b(amount), b(id), b(rcpt)].
func LockRecord(zero [20]byte, ty, aid [32]byte, amount *big.Int, id, rcpt [32]byte) []byte {
	return CArr(CBytes(zero[:]), CBytes(ty[:]), CBytes(aid[:]), CAmount(amount), CBytes(id[:]), CBytes(rcpt[:]))
}

// LockDigest is d = H(C("UNICITY_BR_LOCK", b(cfg), n, K)). It binds cfg, which
// is an intentional tightening of the generic digest.
func LockDigest(cfg [32]byte, n uint64, k []byte) [32]byte {
	return H(cat(head(4, 4), CBytes([]byte("UNICITY_BR_LOCK")), CBytes(cfg[:]), CUint(n), k))
}

// MintJustification is tag(39049,[1,chainId,b(vault),b(zeroAddress),n]).
func MintJustification(chainID uint64, vault, zero [20]byte, n uint64) []byte {
	return CTag(TagMintLock, CArr(CUint(WireVersion), CUint(chainID), CBytes(vault[:]), CBytes(zero[:]), CUint(n)))
}

// ReturnReason is R, the exact terminal transfer data:
// tag(39048,[1,chainId,b(vault),b(zeroAddress),b(ty),b(aid),b(recipient),b(amount),b(zeroAddress),b(empty),0]).
// The last three slots are fixed (no fee token, no fee, no deadline).
func ReturnReason(chainID uint64, vault, zero [20]byte, ty, aid [32]byte, recipient [20]byte, amount *big.Int) []byte {
	return CTag(TagReturnReason, CArr(CUint(WireVersion), CUint(chainID), CBytes(vault[:]), CBytes(zero[:]),
		CBytes(ty[:]), CBytes(aid[:]), CBytes(recipient[:]), CAmount(amount), CBytes(zero[:]), CBytes([]byte{}), CUint(0)))
}

// BurnID is btid = H(C("unicity-burn-transition:v1", b(sidBurn), b(txHashBurn))).
func BurnID(sid, txHash [32]byte) [32]byte {
	return H(CArr(CBytes([]byte("unicity-burn-transition:v1")), CBytes(sid[:]), CBytes(txHash[:])))
}

// Nullifier is eta = H(C("UNICITY_BR_NUL", b(cfg), b(btid))). It excludes
// witness bytes, anchor round, signature representation and submitter.
func Nullifier(cfg, btid [32]byte) [32]byte {
	return H(CArr(CBytes([]byte("UNICITY_BR_NUL")), CBytes(cfg[:]), CBytes(btid[:])))
}

func keccak(parts ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func word(n uint64) []byte {
	var w [32]byte
	binary.BigEndian.PutUint64(w[24:], n)
	return w[:]
}

// MappingSlot is the logical Solidity slot keccak256(abi.encode(key, base)).
func MappingSlot(key []byte, base uint64) [32]byte {
	var k [32]byte
	copy(k[32-len(key):], key)
	return keccak(k[:], word(base))
}

// LockDigestSlot is the logical slot of lockDigest[n] (base 5).
func LockDigestSlot(n uint64) [32]byte { return MappingSlot(word(n), SlotLockDigest) }

// SpentSlot is the logical slot of spentNullifier[n] (base 6).
func SpentSlot(n uint64) [32]byte { return MappingSlot(word(n), SlotSpentNullifier) }

// ClaimableSlot is the logical slot of claimable[a] (base 7).
func ClaimableSlot(a [20]byte) [32]byte { return MappingSlot(a[:], SlotClaimable) }

// StorageTrieKey is the Ethereum storage trie key keccak256(logicalSlot).
func StorageTrieKey(slot [32]byte) [32]byte { return keccak(slot[:]) }

// AccountTrieKey is the account trie key keccak256(address).
func AccountTrieKey(a [20]byte) [32]byte { return keccak(a[:]) }

// StorageValueRLP is the canonical RLP of a stored word: leading zero bytes
// stripped, then the RLP string of that integer (a zero word is the empty
// string, 0x80).
func StorageValueRLP(v [32]byte) []byte {
	i := 0
	for i < 32 && v[i] == 0 {
		i++
	}
	s := v[i:]
	switch {
	case len(s) == 1 && s[0] < 0x80:
		return s
	case len(s) <= 55:
		return append([]byte{0x80 + byte(len(s))}, s...)
	}
	return append([]byte{0xb7 + 1, byte(len(s))}, s...)
}

// StorageValueFromRLP recovers the bytes32 word from an RLP storage value by
// left-padding; it rejects non-minimal RLP and values over 32 bytes.
func StorageValueFromRLP(b []byte) ([32]byte, error) {
	var out [32]byte
	if len(b) == 0 {
		return out, ErrShape
	}
	var s []byte
	switch {
	case b[0] < 0x80:
		if len(b) != 1 {
			return out, ErrShape
		}
		s = b
	case b[0] <= 0xb7:
		n := int(b[0] - 0x80)
		if len(b) != 1+n {
			return out, ErrShape
		}
		s = b[1:]
		if n == 1 && s[0] < 0x80 {
			return out, ErrNonCanonical
		}
	case b[0] == 0xb8:
		if len(b) < 2 || int(b[1]) != len(b)-2 || b[1] <= 55 {
			return out, ErrNonCanonical
		}
		s = b[2:]
	default:
		return out, ErrShape
	}
	if len(s) > 32 || (len(s) > 0 && s[0] == 0) {
		return out, ErrNonCanonical
	}
	copy(out[32-len(s):], s)
	return out, nil
}
