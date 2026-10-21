package b1ref

import "math"

// Hard limits of CERT_BATCH_V2 (briefs/b1-any-age-contract.md section 4) and of RSMT_MEMBER_V1.
const (
	MaxCallBytes      = 262144
	MaxUCBytes        = 24576
	MaxClaims         = 16 // K, claim occurrences per call; E, S and A are at most K
	MaxMembers        = 16 // N_admit = N_verify
	MaxSigsPerSeal    = 16
	MaxBatchSigs      = 256 // Q, signatures over the distinct seals
	MaxNodeIDBytes    = 128
	MaxShardDepth     = 256
	MaxShardBytes     = 33
	MaxShardSiblings  = 256
	MaxUnicitySteps   = 32
	MaxCertSteps      = 4608 // shard siblings plus Unicity steps, summed over every occurrence
	MaxCBORDepth      = 16
	MaxCBORTokens     = 32768 // summed over every UC occurrence
	MaxSummaryBytes   = 256
	MaxRSMTValueBytes = 4096
	MaxRSMTSiblings   = 256
	MaxRSMTInputBytes = 4 + 32 + 32 + 4 + MaxRSMTValueBytes + 32 + MaxRSMTSiblings*32 // 12392

	certVersion   = 2 // CERT_BATCH_V2 input and output
	memberVersion = 1 // RSMT_MEMBER_V1 input and output
)

// Limits are the aggregate bounds of one CERT_BATCH_V2 scan. A standalone call (0x0100) uses Standard. The native composition
// (BRIDGE_COMPOSE_V1) groups its anchor table under Composed: the claim count is bounded by the u16 wire count, the request by
// the envelope, and the CBOR item budget applies to each UC occurrence on its own; its gas pays for all of it
// (briefs/dev4-b7-native-compose-spec.md section 7). The per-object bounds (UC bytes, shard, signatures per seal, steps per
// occurrence) are the same in both.
type Limits struct {
	CallBytes  int
	Claims     int
	BatchSigs  uint64
	CertSteps  uint64
	PerUCItems bool // the CBOR item budget is per UC occurrence instead of summed over the call
}

var (
	Standard = Limits{CallBytes: MaxCallBytes, Claims: MaxClaims, BatchSigs: MaxBatchSigs, CertSteps: MaxCertSteps}
	Composed = Limits{CallBytes: math.MaxInt, Claims: math.MaxUint16, BatchSigs: math.MaxUint64, CertSteps: math.MaxUint64, PerUCItems: true}
)

// CERT_BATCH_V2 schedule (contract section 5). Every term depends on the request only, never on registry contents or warmth.
const (
	scanBaseGas    = 60000
	gasPerByte     = 16
	gasPerPair     = 500 // 500*K*(K-1): bounded identity comparisons
	commonReads    = 11
	gasPerRead     = 100 // subsidised registry read
	gasPerMember   = 1000
	epochWords     = 11 + 8*MaxMembers
	EpochGas       = gasPerMember*MaxMembers + gasPerRead*epochWords // 29,900 per distinct declared epoch, at the member ceiling
	gasPerSig      = 6000
	gasPerClaim    = 2000
	gasPerPathStep = 250
	rsmtBaseGas    = 2000
)

// ScanGas is G_scan = 60,000 + 16*C + 500*K*(K-1), reserved before the full structural scan.
func ScanGas(c, k uint64) uint64 { return scanBaseGas + gasPerByte*c + gasPerPair*k*(k-1) }

// BatchGas is G_batch = G_scan + 1,100 + 29,900*E + 6,000*Q + 2,000*A + 250*P over the grouped request. Operands are bounded by
// the limits above, so it cannot overflow.
func BatchGas(c, k, e, q, a, p uint64) uint64 {
	return ScanGas(c, k) + gasPerRead*commonReads + EpochGas*e + gasPerSig*q + gasPerClaim*a + gasPerPathStep*p
}

// RSMTGas is the charge of RSMT_MEMBER_V1: 2000 + 16*B + 250*(1+popcount(bitmap)).
func RSMTGas(b, popcount uint64) uint64 {
	return rsmtBaseGas + gasPerByte*b + gasPerPathStep*(1+popcount)
}
