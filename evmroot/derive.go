package evmroot

import (
	"crypto/sha256"
	"errors"
	"math"
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

// ErrTimestampOverflow reports a parent timestamp at the top of the 64-bit range, whose successor cannot be represented: the derived
// EVM header time would not be strictly greater than the parent's. The Rust derivation refuses the same input.
var ErrTimestampOverflow = errors.New("evmroot: parent timestamp + 1 overflows")

// DeriveTimestampChecked returns max(referenceTime, parentTimestamp+1) — the
// monotone EVM header counter — or ErrTimestampOverflow when parentTimestamp+1
// does not fit. referenceTime is the authorizing seal's timestamp (whole
// seconds, non-decreasing, equal seconds valid); parentTimestamp is the
// previous EVM block's header timestamp. At sub-second shard cadence the seal
// timestamp alone repeats, so the +1 path keeps EVM headers strictly
// increasing; that derived clock can run ahead of the root clock and does not
// inherit its future bound.
func DeriveTimestampChecked(referenceTime, parentTimestamp uint64) (uint64, error) {
	if parentTimestamp == math.MaxUint64 {
		return 0, ErrTimestampOverflow
	}
	if parentTimestamp+1 > referenceTime {
		return parentTimestamp + 1, nil
	}
	return referenceTime, nil
}

// DeriveTimestamp is DeriveTimestampChecked for callers that have established the parent timestamp is below the top of the range (tests
// and fixtures). It panics on overflow rather than return a timestamp that is not above the parent's; production paths use the checked form.
func DeriveTimestamp(referenceTime, parentTimestamp uint64) uint64 {
	ts, err := DeriveTimestampChecked(referenceTime, parentTimestamp)
	if err != nil {
		panic(err)
	}
	return ts
}
