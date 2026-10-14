package b1ref

import "errors"

// sentinel is a named error that unwraps to its parent family, so tests can
// match either the exact reason or the family with errors.Is.
type sentinel struct {
	msg    string
	parent error
}

func (e *sentinel) Error() string { return e.msg }
func (e *sentinel) Unwrap() error { return e.parent }

func newSentinel(parent error, msg string) *sentinel { return &sentinel{msg: msg, parent: parent} }

// Error families.
var (
	// ErrMalformed is the family of precompile errors: noncanonical or
	// out-of-bound encodings, wrong counts, unsupported versions. The EVM
	// treats these as an exceptional halt, never as (1,false).
	ErrMalformed = errors.New("b1ref: malformed input")
	// ErrBound is the subfamily of ErrMalformed raised by a hard limit.
	ErrBound = newSentinel(ErrMalformed, "b1ref: bound exceeded")
	// ErrInvalid is the family of well-formed but wrong inputs: output (1,false).
	ErrInvalid = errors.New("b1ref: relation does not hold")
	// ErrOutOfGas is an EVM failure with all forwarded gas consumed.
	ErrOutOfGas = errors.New("b1ref: out of gas")
)

// Malformed (precompile error) reasons.
var (
	ErrTruncated       = newSentinel(ErrMalformed, "b1ref: truncated input")
	ErrTrailingBytes   = newSentinel(ErrMalformed, "b1ref: trailing bytes")
	ErrVersion         = newSentinel(ErrMalformed, "b1ref: unsupported version")
	ErrFlags           = newSentinel(ErrMalformed, "b1ref: unsupported flags")
	ErrCount           = newSentinel(ErrMalformed, "b1ref: wrong claim count")
	ErrNonCanonical    = newSentinel(ErrMalformed, "b1ref: noncanonical encoding")
	ErrDuplicateMapKey = newSentinel(ErrMalformed, "b1ref: duplicate map key")
	ErrForbiddenCBOR   = newSentinel(ErrMalformed, "b1ref: forbidden CBOR item")
	ErrInvalidUTF8     = newSentinel(ErrMalformed, "b1ref: invalid UTF-8")
	ErrShape           = newSentinel(ErrMalformed, "b1ref: unexpected structure")
	ErrNativeDecode    = newSentinel(ErrMalformed, "b1ref: native decode failed")
	ErrReencode        = newSentinel(ErrMalformed, "b1ref: decode/re-encode mismatch")
	ErrShardSiblings   = newSentinel(ErrMalformed, "b1ref: shard sibling count differs from the shard depth")

	ErrShardEncoding = newSentinel(ErrMalformed, "b1ref: invalid shard bit string")
	ErrRSMTLength    = newSentinel(ErrMalformed, "b1ref: RSMT input length does not match its bitmap")
)

// Bound reasons (all wrap ErrBound).
var (
	ErrInputTooLarge = newSentinel(ErrBound, "b1ref: input too large")
	ErrUCTooLarge    = newSentinel(ErrBound, "b1ref: UC too large")

	ErrTooManySigs     = newSentinel(ErrBound, "b1ref: too many signatures")
	ErrNodeIDTooLong   = newSentinel(ErrBound, "b1ref: node ID too long")
	ErrShardTooDeep    = newSentinel(ErrBound, "b1ref: shard too deep")
	ErrTooManySiblings = newSentinel(ErrBound, "b1ref: too many siblings")
	ErrTooManySteps    = newSentinel(ErrBound, "b1ref: too many unicity path steps")
	ErrCertSteps       = newSentinel(ErrBound, "b1ref: too many certificate path steps in the call")
	ErrDepth           = newSentinel(ErrBound, "b1ref: CBOR nesting too deep")
	ErrTokens          = newSentinel(ErrBound, "b1ref: too many CBOR tokens")
	ErrSummaryTooLong  = newSentinel(ErrBound, "b1ref: summary value too long")
	ErrValueTooLarge   = newSentinel(ErrBound, "b1ref: RSMT value too large")
)

// False reasons (all wrap ErrInvalid).
var (
	ErrNetwork            = newSentinel(ErrInvalid, "network mismatch")
	ErrEpochBeforeGenesis = newSentinel(ErrInvalid, "seal epoch is before the registry's genesis epoch")
	ErrEpochNotUsable     = newSentinel(ErrInvalid, "seal epoch is after the usable origin epoch")
	ErrOriginNotReady     = newSentinel(ErrInvalid, "the registry has no usable root origin yet")
	ErrBeforeStart        = newSentinel(ErrInvalid, "root round before the interval start")
	ErrAfterEnd           = newSentinel(ErrInvalid, "root round at or after the interval end")
	ErrFuture             = newSentinel(ErrInvalid, "certificate root round is in the future")

	ErrPartition     = newSentinel(ErrInvalid, "partition mismatch")
	ErrShard         = newSentinel(ErrInvalid, "shard mismatch")
	ErrShardConf     = newSentinel(ErrInvalid, "shard configuration hash mismatch")
	ErrNativeInvalid = newSentinel(ErrInvalid, "native certificate validation failed")
	ErrFold          = newSentinel(ErrInvalid, "certificate path fold failed")
	ErrTreeRoot      = newSentinel(ErrInvalid, "unicity tree root does not match the seal")
	ErrStateRoot     = newSentinel(ErrInvalid, "state root mismatch")
	ErrIRHash        = newSentinel(ErrInvalid, "input record digest mismatch")
	ErrClaimConflict = newSentinel(ErrInvalid, "two different claims for one shard under one seal")

	ErrUnknownSigner = newSentinel(ErrInvalid, "unknown signer")
	ErrSigFormat     = newSentinel(ErrMalformed, "signature is not a canonical compact signature")
	ErrSigRange      = newSentinel(ErrInvalid, "signature scalar out of range or high-s")
	ErrSigInvalid    = newSentinel(ErrInvalid, "signature does not verify")
	ErrQuorum        = newSentinel(ErrInvalid, "quorum not reached")
	ErrRSMTZeroRoot  = newSentinel(ErrInvalid, "zero root")
	ErrRSMTFold      = newSentinel(ErrInvalid, "membership fold does not reach the root")
)

// ErrInfrastructure is the family of execution failures that are neither a verdict nor a halt: impossible admitted registry
// state (Registry) and unavailable state (Host). No EVM result; the Go harness reports used=0.
var ErrInfrastructure = errors.New("b1ref: unavailable or inconsistent registry")

var (
	ErrRegistryCommon       = newSentinel(ErrInfrastructure, "b1ref: impossible common registry state")
	ErrRegistryMissingEpoch = newSentinel(ErrInfrastructure, "b1ref: no installed entry for an admitted epoch")
	ErrRegistryInvalidEpoch = newSentinel(ErrInfrastructure, "b1ref: impossible installed entry")
	ErrHost                 = newSentinel(ErrInfrastructure, "b1ref: execution state unavailable")
)

var ErrPhase = newSentinel(ErrInvalid, "registry prefix has not finalized")
