package bridgeprofile

// DEV-DEFAULT safety ceilings of design section "Gas and finite development
// limits". They are test ceilings, not a claim that the maximum fits a block.
const (
	MaxTransfers     = 64 // transfers including the final burn
	MaxLeaves        = MaxTransfers + 1
	MaxSemanticBytes = 64 << 10
	MaxEnvelopeBytes = 256 << 10
	MaxCBORDepth     = 16
	MaxCBORItems     = 32768
	MaxPathSteps     = 2048
	MaxPolicyBytes   = 128
	MaxAmountBytes   = 32
	MaxAnchors       = 8 // B1 ceiling; the enabled policy admits exactly one
)

// Fixed protocol bytes adopted from the pinned SDKs (design table "Exact token
// bytes"). They are literals, not layout versions.
const (
	TagPredicate     = 39032
	TagMint          = 39041
	TagTransfer      = 39045
	TagCertification = 39031
	TagToken         = 39040
	TagInclusion     = 39033
	TagMintLock      = 39049 // lock-backed mint justification
	TagReturnReason  = 39048 // terminal burn reason R
	TagExternalMint  = 39047 // rejected by this profile

	EngineBuiltIn = 1
	PredSignature = 1
	PredBurn      = 2
	WireVersion   = 1
)

// Kernel operations (ABI input byte 0).
const (
	OpPrepareLock = 0
	OpMint        = 1
	OpReturn      = 2
)
