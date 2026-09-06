package evmroot

import (
	"crypto/sha256"
	"encoding/binary"
)

// DerivePrevRandao returns prevRandao = H(DOM_rho, r, n):
//
//	SHA-256( CBOR([ "UNICITY_EVM_RANDAO", rootRound, shardRound ]) )
//
// r is the authorizing certificate's root round (UnicitySeal.RootChainRoundNumber),
// n is the authorized shard round. The CBOR array is the deterministic
// encoding from cbor.go, elements in the stated order.
//
// This value is a deterministic, potentially biasable function of certified
// data — it is NOT a secure randomness beacon (evm-partition.tex
// §"Round Parameters"). Contracts needing unpredictability need a separate
// mechanism.
func DerivePrevRandao(rootRound, shardRound uint64) Hash32 {
	return domainHash(DomainPrevRandao, rootRound, shardRound)
}

// DeriveBeaconRoot returns parentBeaconBlockRoot = H(DOM_beta, r, n), same
// construction as DerivePrevRandao with domain "UNICITY_EVM_BEACON". Unlike
// real Ethereum the value never has to be disseminated: every validator
// recomputes it from the same certificate.
func DeriveBeaconRoot(rootRound, shardRound uint64) Hash32 {
	return domainHash(DomainBeaconRoot, rootRound, shardRound)
}

func domainHash(domain string, rootRound, shardRound uint64) Hash32 {
	enc := marshalCBOR(cArray{cText(domain), cUint(rootRound), cUint(shardRound)})
	return sha256.Sum256(enc)
}

// DeriveTimestamp returns max(referenceTime, parentTimestamp+1) — the
// monotone EVM header counter. referenceTime is the authorizing seal's
// timestamp; parentTimestamp is the previous EVM block's header timestamp.
// At sub-second shard cadence the seal timestamp alone can repeat, so the
// +1 path keeps EVM headers strictly increasing.
func DeriveTimestamp(referenceTime, parentTimestamp uint64) uint64 {
	if parentTimestamp+1 > referenceTime {
		return parentTimestamp + 1
	}
	return referenceTime
}

// --- v0 prototype forms, for compatibility vectors only ----------------------

// prototypeDomainHash reproduces engineapi/params.go's pre-D1 derivation:
//
//	SHA-256( domainByte || unicityTreeRoot || bigEndian64(shardRound) )
//
// with domainByte 0x01 for prevRandao and 0x02 for parentBeaconBlockRoot.
// It keys off the Unicity Tree root and a single counter, uses raw
// concatenation instead of CBOR, and has no ASCII domain string. Kept here
// solely so the vector set can show, byte for byte, how v1 differs. Not for
// production use.
func prototypeDomainHash(domainByte byte, unicityTreeRoot []byte, shardRound uint64) Hash32 {
	h := sha256.New()
	h.Write([]byte{domainByte})
	h.Write(unicityTreeRoot)
	var rb [8]byte
	binary.BigEndian.PutUint64(rb[:], shardRound)
	h.Write(rb[:])
	var out Hash32
	copy(out[:], h.Sum(nil))
	return out
}

const (
	prototypeDomainPrevRandao = 0x01
	prototypeDomainBeaconRoot = 0x02
)
