package b1ref

// Hard admission limits of profile 1 (design section 4).
const (
	MaxCallBytes      = 262144
	MaxUCBytes        = 24576
	MaxViewBytes      = 16384
	MaxClaims         = 8
	MaxMembers        = 64
	MaxSigsPerSeal    = 64
	MaxSigEntries     = 512 // parsed signature entries per shared call
	MaxNodeIDBytes    = 128
	MaxShardDepth     = 256
	MaxShardBytes     = 33
	MaxShardSiblings  = 256
	MaxUnicitySteps   = 32
	MaxCBORDepth      = 16
	MaxCBORTokens     = 32768
	MaxSummaryBytes   = 256
	MaxRSMTValueBytes = 4096
	MaxRSMTSiblings   = 256
	MaxRSMTInputBytes = 4 + 32 + 32 + 4 + MaxRSMTValueBytes + 32 + MaxRSMTSiblings*32 // 12392

	outputVersion = 1
)

// Candidate gas schedule (design section 4).
const (
	ucBaseGas      = 60000
	rsmtBaseGas    = 2000
	gasPerByte     = 16
	gasPerMember   = 1000
	gasPerSig      = 6000
	gasPerClaim    = 2000
	gasPerPathStep = 250
)

// UCGas is the charge of UC_V1/SHARED_SEAL_V1: 60000 + 16*B + 1000*M + 6000*S + 2000*N + 250*P.
// All operands are bounded, so the sum cannot overflow uint64.
func UCGas(b, m, s, n, p uint64) uint64 {
	return ucBaseGas + gasPerByte*b + gasPerMember*m + gasPerSig*s + gasPerClaim*n + gasPerPathStep*p
}

// RSMTGas is the charge of RSMT_MEMBER_V1: 2000 + 16*B + 250*(1+popcount(bitmap)).
func RSMTGas(b, popcount uint64) uint64 {
	return rsmtBaseGas + gasPerByte*b + gasPerPathStep*(1+popcount)
}
