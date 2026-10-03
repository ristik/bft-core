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
	ErrClaimOrder      = newSentinel(ErrMalformed, "b1ref: claims not in strictly sorted order")
	ErrViewOrder       = newSentinel(ErrMalformed, "b1ref: trust view members not sorted")
	ErrViewKey         = newSentinel(ErrMalformed, "b1ref: trust view key is not a secp256k1 point")
	ErrViewKind        = newSentinel(ErrMalformed, "b1ref: unknown trust view source kind")
	ErrViewEmpty       = newSentinel(ErrMalformed, "b1ref: trust view has no members")
	ErrShardEncoding   = newSentinel(ErrMalformed, "b1ref: invalid shard bit string")
	ErrRSMTLength      = newSentinel(ErrMalformed, "b1ref: RSMT input length does not match its bitmap")
)

// Bound reasons (all wrap ErrBound).
var (
	ErrInputTooLarge   = newSentinel(ErrBound, "b1ref: input too large")
	ErrUCTooLarge      = newSentinel(ErrBound, "b1ref: UC too large")
	ErrViewTooLarge    = newSentinel(ErrBound, "b1ref: trust view too large")
	ErrTooManyMembers  = newSentinel(ErrBound, "b1ref: too many members")
	ErrTooManySigs     = newSentinel(ErrBound, "b1ref: too many signatures")
	ErrNodeIDTooLong   = newSentinel(ErrBound, "b1ref: node ID too long")
	ErrShardTooDeep    = newSentinel(ErrBound, "b1ref: shard too deep")
	ErrTooManySiblings = newSentinel(ErrBound, "b1ref: too many siblings")
	ErrTooManySteps    = newSentinel(ErrBound, "b1ref: too many unicity path steps")
	ErrDepth           = newSentinel(ErrBound, "b1ref: CBOR nesting too deep")
	ErrTokens          = newSentinel(ErrBound, "b1ref: too many CBOR tokens")
	ErrSummaryTooLong  = newSentinel(ErrBound, "b1ref: summary value too long")
	ErrValueTooLarge   = newSentinel(ErrBound, "b1ref: RSMT value too large")
)

// False reasons (all wrap ErrInvalid).
var (
	ErrUnknownEpoch   = newSentinel(ErrInvalid, "unknown epoch")
	ErrViewHash       = newSentinel(ErrInvalid, "trust view hash does not match the registry")
	ErrBodyID         = newSentinel(ErrInvalid, "trust view body ID does not match the registry")
	ErrNetwork        = newSentinel(ErrInvalid, "network mismatch")
	ErrSealEpoch      = newSentinel(ErrInvalid, "seal epoch does not match the trust view epoch")
	ErrOpenInterval   = newSentinel(ErrInvalid, "open interval does not name the origin epoch")
	ErrBeforeStart    = newSentinel(ErrInvalid, "root round before the interval start")
	ErrAfterEnd       = newSentinel(ErrInvalid, "root round at or after the interval end")
	ErrFuture         = newSentinel(ErrInvalid, "certificate root round is in the future")
	ErrStale          = newSentinel(ErrInvalid, "certificate older than W_cert")
	ErrWeightProfile  = newSentinel(ErrInvalid, "member weight is not 1")
	ErrViewDuplicate  = newSentinel(ErrInvalid, "duplicate trust view identity or key")
	ErrPartition      = newSentinel(ErrInvalid, "partition mismatch")
	ErrShard          = newSentinel(ErrInvalid, "shard mismatch")
	ErrShardConf      = newSentinel(ErrInvalid, "shard configuration hash mismatch")
	ErrNativeInvalid  = newSentinel(ErrInvalid, "native certificate validation failed")
	ErrFold           = newSentinel(ErrInvalid, "certificate path fold failed")
	ErrTreeRoot       = newSentinel(ErrInvalid, "unicity tree root does not match the seal")
	ErrStateRoot      = newSentinel(ErrInvalid, "state root mismatch")
	ErrIRHash         = newSentinel(ErrInvalid, "input record digest mismatch")
	ErrSealMismatch   = newSentinel(ErrInvalid, "seals differ across certificates")
	ErrDuplicateClaim = newSentinel(ErrInvalid, "duplicate claim identity")
	ErrUnknownSigner  = newSentinel(ErrInvalid, "unknown signer")
	ErrSigFormat      = newSentinel(ErrInvalid, "signature is not a canonical compact signature")
	ErrSigRange       = newSentinel(ErrInvalid, "signature scalar out of range or high-s")
	ErrSigInvalid     = newSentinel(ErrInvalid, "signature does not verify")
	ErrQuorum         = newSentinel(ErrInvalid, "quorum not reached")
	ErrRSMTZeroRoot   = newSentinel(ErrInvalid, "zero root")
	ErrRSMTFold       = newSentinel(ErrInvalid, "membership fold does not reach the root")
)
