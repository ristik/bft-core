package b1ref

// Hard limits from the A′ design.
const (
	MaxCallBytes      = 262144
	MaxUCBytes        = 24576
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

// UCGas is the charge of UC_V1/SHARED_SEAL_V1: 60000 + 16*B + 64000 + 6000*S + 2000*N + 250*P + 1117700.
// Operands are pre-scanned and bounded by the caller profile.
func UCGas(b, s, n, p uint64) uint64 {
	return ucBaseGas + gasPerByte*b + gasPerMember*MaxMembers + gasPerSig*s + gasPerClaim*n + gasPerPathStep*p + 1117700
}

// RSMTGas is the charge of RSMT_MEMBER_V1: 2000 + 16*B + 250*(1+popcount(bitmap)).
func RSMTGas(b, popcount uint64) uint64 {
	return rsmtBaseGas + gasPerByte*b + gasPerPathStep*(1+popcount)
}
