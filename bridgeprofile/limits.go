package bridgeprofile

import "math"

// BridgeResources: the one resource policy of the direct path (owner section 36, briefs/b7-direct-uncapped-design.md section 1),
// defined only here and mirrored by the semantic profile's limits, the contract (BridgeBounds) and the plug-ins. There is no gas
// ceiling and no history cap. The composition (Compose, BRIDGE_COMPOSE_V1) is bounded by the envelope (MaxEnvelopeBytes, the
// ingress bound the pool and RPC are configured to carry), the wire widths and its gas; it streams the history and the anchor table
// under ComposedHistory and b1ref.Composed (briefs/dev4-b7-native-compose-spec.md section 7). MaxTransfers and MaxSemanticBytes
// are the standalone B2 kernel's own bounds (0x0104: ureth b2 MAX_TRANSFERS, MAX_HISTORY), which prepareLock still calls. The
// remaining constants are per-object shape bounds (schemas, widths, depth), not history caps.
const (
	MaxTransfers     = 64               // standalone B2 MAX_TRANSFERS: transfers including the final burn
	MaxLeaves        = MaxTransfers + 1 // standalone B2 leaf output: the mint and every transfer (the kernel's result bound)
	MaxSemanticBytes = 128 << 10        // standalone B2 MAX_HISTORY: history projection and Cfg input
	MaxEnvelopeBytes = 2 << 20          // ingress: the composition's only aggregate byte bound; the largest measured redemption is 1.45 MB (B7 PR 3); txpool and RPC carry it
	MaxCBORDepth     = 16
	MaxCBORItems     = 32768 // per object: the native scan of one CBOR object
	MaxPolicyBytes   = 512
	MaxAmountBytes   = 32
	MaxAnchors       = math.MaxUint16 // wire width: the CERT_BATCH_V2 claim count and the leaf anchorIndex are u16
	MaxCfgBytes      = 1024

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

// HistoryBounds are the aggregate bounds of one history decode: its bytes, its transfers (the final burn included) and the CBOR
// items of the whole history. The standalone kernel uses KernelHistory; the composition uses ComposedHistory, where the history is
// bounded by the envelope that carries it and every item and leaf is paid before the kernel runs.
type HistoryBounds struct{ Bytes, Transfers, Items int }

var (
	KernelHistory   = HistoryBounds{Bytes: MaxSemanticBytes, Transfers: MaxTransfers, Items: MaxCBORItems}
	ComposedHistory = HistoryBounds{Bytes: MaxEnvelopeBytes, Transfers: math.MaxInt, Items: math.MaxInt}
)

// NativeBridgeProtoVersion is the byte-contract version of this profile. It is
// distinct from the SDK Token.VERSION and from the external bridge's own
// protocol version. Any byte or derivation change bumps it together with the
// semantic profile; there is no version dispatch in the parsers.
const NativeBridgeProtoVersion = 6

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
