package nb2ref

import (
	"errors"
	"math/bits"
)

// Wallet rules that affect safety (section 12) and the wallet refusals of section 14.6.

// SealReceipt is a verified SegmentSealed(j) receipt.
type SealReceipt struct {
	Segment *Segment
}

// VerifySealReceipt verifies a seal receipt proof (a DepositProof container whose log is SegmentSealed) exactly as section 6.2
// steps 2 to 5 for that event: the same EVM UC rule, header, receipt path, type, status, log index and emitter, topics
// [topic0(SegmentSealed), u256(j)] with j < 2^48, and data of exactly 128 + 32K bytes whose identifiers are strictly sorted
// and whose heads link (H_{j+1} = NextHead(D, j, headBefore, M_j)). Every failure is SealReceipt wrapping the inner rule
// (section 14.6): the retryable NoEntryForEpoch when the trust input lacks the seal epoch after the earlier per-UC checks pass
// (extend the authenticated history and retry; the receipt is not invalid for that alone), DepositUC for every other
// EVM-certificate failure.
func VerifySealReceipt(c *Config, t *TrustInput, receipt []byte) (*SealReceipt, error) {
	if err := t.bind(c); err != nil {
		return nil, err
	}
	p, err := DecodeDepositProof(receipt)
	if err != nil {
		return nil, wrap(ErrSealReceipt, err)
	}
	log, err := VerifyReceiptLog(c, t, p)
	if err != nil {
		return nil, wrap(ErrSealReceipt, err)
	}
	if len(log.Topics) != 2 || log.Topics[0] != TopicSegmentSealed {
		return nil, wrap(ErrSealReceipt, ErrLogTopics)
	}
	jw := log.Topics[1]
	for _, x := range jw[:26] {
		if x != 0 {
			return nil, wrap(ErrSealReceipt, ErrLogTopics)
		}
	}
	j := uint64(jw[26])<<40 | uint64(jw[27])<<32 | uint64(jw[28])<<24 | uint64(jw[29])<<16 | uint64(jw[30])<<8 | uint64(jw[31])
	if uint64(len(log.Data)) != 128+32*c.K {
		return nil, wrap(ErrSealReceipt, ErrLogData)
	}
	seg, err := CheckSegmentLog(c.Domain(), c.K, j, [32]byte(log.Data[:32]), log.Data)
	if err != nil {
		return nil, wrap(ErrSealReceipt, err)
	}
	return &SealReceipt{Segment: seg}, nil
}

// BurnIndex is section 12.2: with the newest verified seal receipt of segment j, sign a = j + 1 and keep headAfter = H_{j+1}
// as the start head; with none, a = 0 and H_0.
func BurnIndex(c *Config, newest *SealReceipt) (a uint64, startHead [32]byte) {
	if newest == nil {
		return 0, GenesisHead(c.Domain(), c.K)
	}
	return newest.Segment.Index + 1, newest.Segment.After
}

// MaxProofs is P_max = floor((L_max - L_T - L_O) / (65 + 32h)) with checked arithmetic. baseFits is false when the return
// without history does not fit (L_T > L_max or L_O > L_max - L_T); then no proof count fits, not even zero.
func MaxProofs(lMax, lT, lO, k uint64) (pMax uint64, baseFits bool) {
	if lT > lMax || lO > lMax-lT {
		return 0, false
	}
	return (lMax - lT - lO) / uint64(65+32*bits.TrailingZeros64(k)), true
}

// fitsProofs reports whether the return with p proofs fits L_max.
func fitsProofs(lMax, lT, lO, k, p uint64) bool {
	pMax, ok := MaxProofs(lMax, lT, lO, k)
	return ok && p <= pMax
}

// Preflight is the before-burn capacity input (section 12.5): the index a chosen by section 12.2, a current endpoint estimate
// cObs >= a, the encoded size of the complete prospective return transaction without its history (lT evidence including the
// burn and its certification, lO all other framing, both covering the complete encoding, padding and every component bound;
// this arithmetic cannot establish those) and the gas the return would need with P proofs (expected cost plus gasReserve).
type Preflight struct {
	LMax, LT, LO, K  uint64
	A, CObs, Reserve uint64
	GasAt            func(p uint64) uint64
	UserGasLimit     uint64
}

// CapacityPreflight refuses the burn unless the complete return fits L_max and userGasLimit with the history already owed from
// a (P_now = cObs - a) plus returnReserveSegments proofs, zero history included. An old seal receipt consumes capacity before
// the burn.
func CapacityPreflight(p Preflight) error {
	if p.CObs < p.A {
		return ErrCapacityPreflight
	}
	owed := p.CObs - p.A
	if owed > ^uint64(0)-p.Reserve {
		return ErrCapacityPreflight
	}
	need := owed + p.Reserve
	if !fitsProofs(p.LMax, p.LT, p.LO, p.K, need) {
		return ErrCapacityPreflight
	}
	if p.GasAt == nil || p.GasAt(need) > p.UserGasLimit {
		return ErrCapacityPreflight
	}
	return nil
}

// CapacityExceeded is the at-redemption refusal: the complete return with P proofs does not fit L_max (zero proofs included),
// or the gas limit (expected cost plus gasReserve) is above userGasLimit.
func CapacityExceeded(lMax, lT, lO, k, p, gasLimit, userGasLimit uint64) error {
	if !fitsProofs(lMax, lT, lO, k, p) || gasLimit > userGasLimit {
		return ErrCapacityExceeded
	}
	return nil
}

// ErrStateReadNotAdmitted is not a rule: a plain state() read is admitted only on a stateReadOnly deployment.
var ErrStateReadNotAdmitted = errors.New("nb2: state() read without stateReadOnly")

// CheckStateRead is the stateReadOnly substitute for a seal receipt (section 12.2, test deployments): the read segment index
// must lie in [verified, verified + maxJump], where verified is the wallet's highest index proved by a verified receipt (0
// without one) and maxJump the wallet's plausibility bound; anything else is ImplausibleIndex. The section 14.6 text names
// "the wallet's verified bound" without fixing it; this reference fixes it as that interval (default maxJump 64, the
// manifest's returnReserveSegments default).
func CheckStateRead(stateReadOnly bool, read, verified, maxJump uint64) error {
	if !stateReadOnly {
		return ErrStateReadNotAdmitted
	}
	if read < verified || read-verified > maxJump {
		return ErrImplausibleIndex
	}
	return nil
}

// Companion answers of unicity_getSealCompanionV1 (section 12.7) that are not evidence.
var (
	ErrCompanionUnknown  = errors.New("nb2: companion unknown at this node (re-resolve and retry)")
	ErrCompanionProvider = errors.New("nb2: companion witnesses are not exactly [certificate, technical record] (provider fault)")
)

// CheckCompanion classifies a seal companion answer (ureth SealCompanionLookup, serde tag "status"): "found" with exactly two
// witnesses is usable; "unavailable" (pruned below the
// node's horizon) is EvidencePruned; "unknown" is retryable; anything else is a provider fault.
func CheckCompanion(status string, witnesses int) error {
	switch {
	case status == "found" && witnesses == 2:
		return nil
	case status == "unavailable":
		return ErrEvidencePruned
	case status == "unknown":
		return ErrCompanionUnknown
	}
	return ErrCompanionProvider
}
