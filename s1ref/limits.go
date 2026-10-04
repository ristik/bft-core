package s1ref

// Hard admission limits of profile 1 (design, "Errors, bounds and candidate gas").
const (
	MaxInputBytes    = 18448 // 4 + 4 + MaxViewBytes + MaxCount*(4+MaxEvidenceBytes)
	MaxViewBytes     = 16384
	MaxEvidenceBytes = 1024
	MaxCount         = 2
	MaxMembers       = 64
	MaxNodeIDBytes   = 128
	MaxCBORDepth     = 16
	MaxCBORTokens    = 32768

	outputVersion = 1
)

// Candidate gas schedule (design, "Candidate gas"). This is the pure-relation
// charge only; the authenticated-source charge is separate and frozen later.
const (
	baseGas      = 2000
	gasPerByte   = 16
	gasPerMember = 1000
	gasPerSig    = 6000
	gasPerVote   = 2000
)

// Gas is the charge 2000 + 16*B + 1000*M + 6000*S + 2000*N, where B is the
// complete input length, M the carried members, N the evidence count and S is N
// plus the number of non-null sealSignature fields. All operands are bounded,
// so the sum cannot overflow uint64.
func Gas(b, m, s, n uint64) uint64 {
	return baseGas + gasPerByte*b + gasPerMember*m + gasPerSig*s + gasPerVote*n
}

// MaxGas is the conservative maximum: B=18448, M=64, N=2, S=4.
const MaxGas = baseGas + gasPerByte*MaxInputBytes + gasPerMember*MaxMembers + gasPerSig*4 + gasPerVote*2
