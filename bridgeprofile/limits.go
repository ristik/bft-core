package bridgeprofile

// The profile-v3 bounds are named parameters, defined only here and mirrored by
// profile-v3.json limits. They bound the parsers; the 7,000,000 ordinary-capacity gate (gas.go)
// admits or refuses each bundle (two anchors at the maximum sizes pass, five can never pass); a later
// profile version raises them together with the budget.
//
// DEV-DEFAULT safety ceilings of design section "Plug-in verification" and
// "B2 projection". They are test ceilings, not a claim that the maximum fits a
// block. Limits are intersected, never additive entitlements.
const (
	MaxTransfers     = 15       // transfers including the final burn
	MaxLeaves        = 16       // profile parameter: B2 leaves (raise in a later profile version)
	MaxSemanticBytes = 16 << 10 // history projection and Cfg input
	MaxEnvelopeBytes = 64 << 10
	MaxCBORDepth     = 16
	MaxCBORItems     = 32768
	MaxPathSteps     = 2048
	MaxPolicyBytes   = 512
	MaxAmountBytes   = 32
	MaxAnchors       = 4 // profile parameter: distinct UC anchors, a parser ceiling; the gas gate (gas.go) decides each bundle

	// Embedded lock evidence (J). Cumulative and checked before allocation or crypto.
	MaxJustificationBytes = 64 << 10
	MaxLockUCBytes        = 16 << 10
	MaxLockPDRBytes       = 16 << 10
	MaxLockHeaderBytes    = 2 << 10
	MaxMPTNodes           = 65
	MaxMPTNodeBytes       = 1 << 10
	MaxMPTBytes           = 24 << 10 // both node lists combined
	MaxRLPDepth           = 16

	// MaxInputRecordBytes bounds the canonical native InputRecord opening of an
	// anchor: tag(39002,[1,round,epoch,prev,hash,summary<=256,time,block,fees,eth]).
	MaxInputRecordBytes = 512
	MaxAnchorUCBytes    = 8 << 10 // bridge cap on an anchor UC, tighter than B1's 24 KiB
	MaxRSMTSiblings     = 32
	MaxUnicitySteps     = 32
	MaxSummaryBytes     = 256

	// SDK token (oracle-side strict decode only; the kernel never sees a token).
	MaxProofUCBytes = 24 << 10
	MaxTokenBytes   = 4 << 20
)

// NativeBridgeProtoVersion is the byte-contract version of this profile. It is
// distinct from the SDK Token.VERSION and from the external bridge's own
// protocol version. Any byte or derivation change bumps it together with the
// semantic profile; there is no version dispatch in the parsers.
const NativeBridgeProtoVersion = 3

// Fixed protocol bytes adopted from the pinned SDKs v3.0.1. Tags are unchanged
// from the pre-3.0 profile; versions and arities are not.
const (
	TagPredicate     = 39032
	TagMint          = 39041
	TagTransfer      = 39045
	TagCertification = 39031
	TagToken         = 39040
	TagInclusion     = 39033
	TagMintLock      = 39049 // lock-backed mint justification (native lock reason, body version 2)
	TagReturnReason  = 39048 // terminal burn reason R
	TagValue         = 39050 // common wallet value envelope
	TagExternalMint  = 39047 // rejected by this profile
	TagInputRecord   = 39002 // native InputRecord opening

	EngineBuiltIn = 1
	PredSignature = 1
	PredBurn      = 2

	// Literal version fields. SDK 3.0.1 moved M, T, CD and the token to 2;
	// the inclusion proof stays 1; the native lock reason body is 2 and embeds
	// a version 1 LockProof; R keeps version 1.
	PredVersion        = 1
	TxVersion          = 2
	CertVersion        = 2
	TokenVersion       = 2
	InclusionVersion   = 1
	LockReasonVersion  = 2
	LockProofVersion   = 1
	ReturnVersion      = 1
	ValueVersion       = 1
	InputRecordVersion = 1
)

// Kernel operations (ABI input byte 0).
const (
	OpPrepareLock = 0
	OpMint        = 1
	OpReturn      = 2
)
