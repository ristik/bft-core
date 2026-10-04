package s1ref

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
	ErrMalformed = errors.New("s1ref: malformed input")
	// ErrBound is the subfamily of ErrMalformed raised by a hard limit.
	ErrBound = newSentinel(ErrMalformed, "s1ref: bound exceeded")
	// ErrInvalid is the family of well-formed but wrong inputs: output (1,false).
	ErrInvalid = errors.New("s1ref: relation does not hold")
	// ErrOutOfGas is an EVM failure with all forwarded gas consumed.
	ErrOutOfGas = errors.New("s1ref: out of gas")
)

// Malformed (precompile error) reasons.
var (
	ErrTruncated       = newSentinel(ErrMalformed, "s1ref: truncated input")
	ErrTrailingBytes   = newSentinel(ErrMalformed, "s1ref: trailing bytes")
	ErrVersion         = newSentinel(ErrMalformed, "s1ref: unsupported version")
	ErrFlags           = newSentinel(ErrMalformed, "s1ref: unsupported flags")
	ErrCount           = newSentinel(ErrMalformed, "s1ref: wrong evidence count")
	ErrNonCanonical    = newSentinel(ErrMalformed, "s1ref: noncanonical encoding")
	ErrDuplicateMapKey = newSentinel(ErrMalformed, "s1ref: duplicate map key")
	ErrForbiddenCBOR   = newSentinel(ErrMalformed, "s1ref: forbidden CBOR item")
	ErrInvalidUTF8     = newSentinel(ErrMalformed, "s1ref: invalid UTF-8")
	ErrShape           = newSentinel(ErrMalformed, "s1ref: unexpected structure")
	ErrReencode        = newSentinel(ErrMalformed, "s1ref: decode/re-encode mismatch")
	ErrViewKind        = newSentinel(ErrMalformed, "s1ref: unknown trust view source kind")
	ErrScheme          = newSentinel(ErrMalformed, "s1ref: unknown signing scheme")
	ErrSigShape        = newSentinel(ErrMalformed, "s1ref: signature is not 64 bytes or 65 bytes with v in {0,1}")
)

// Bound reasons (all wrap ErrBound).
var (
	ErrInputTooLarge    = newSentinel(ErrBound, "s1ref: input too large")
	ErrViewTooLarge     = newSentinel(ErrBound, "s1ref: trust view too large")
	ErrEvidenceTooLarge = newSentinel(ErrBound, "s1ref: evidence too large")
	ErrTooManyMembers   = newSentinel(ErrBound, "s1ref: too many members")
	ErrNodeIDTooLong    = newSentinel(ErrBound, "s1ref: node ID too long")
	ErrDepth            = newSentinel(ErrBound, "s1ref: CBOR nesting too deep")
	ErrTokens           = newSentinel(ErrBound, "s1ref: too many CBOR tokens")
)

// False reasons (all wrap ErrInvalid). They name the first check that failed;
// the output is the same (1,false) and the charge the same for all of them.
var (
	// Injected context.
	ErrUnknownEpoch  = newSentinel(ErrInvalid, "unknown epoch")
	ErrViewHash      = newSentinel(ErrInvalid, "trust view hash does not match the context")
	ErrBodyID        = newSentinel(ErrInvalid, "trust view body ID does not match the context")
	ErrSourceKind    = newSentinel(ErrInvalid, "trust view source kind does not match the context")
	ErrNetwork       = newSentinel(ErrInvalid, "network mismatch")
	ErrEpochMismatch = newSentinel(ErrInvalid, "voting epoch is not the trust view epoch")
	ErrOpenInterval  = newSentinel(ErrInvalid, "open interval does not name the current open epoch")
	ErrBeforeStart   = newSentinel(ErrInvalid, "voting round before the interval start")
	ErrAfterEnd      = newSentinel(ErrInvalid, "voting round at or after the interval end")
	ErrSigningConfig = newSentinel(ErrInvalid, "signing configuration is invalid")
	ErrSchemeEpoch   = newSentinel(ErrInvalid, "evidence scheme is not the signing scheme of its epoch")

	// Trust view semantics.
	ErrViewEmpty     = newSentinel(ErrInvalid, "trust view has no members")
	ErrViewOrder     = newSentinel(ErrInvalid, "trust view members not strictly sorted")
	ErrViewDuplicate = newSentinel(ErrInvalid, "duplicate trust view identity or key")
	ErrWeightProfile = newSentinel(ErrInvalid, "member weight is not 1")
	ErrViewKey       = newSentinel(ErrInvalid, "trust view key is not a secp256k1 point")

	// One vote.
	ErrUnknownAuthor    = newSentinel(ErrInvalid, "author is not a member of the voting epoch view")
	ErrVoteInfo         = newSentinel(ErrInvalid, "vote info is not valid")
	ErrBinding          = newSentinel(ErrInvalid, "vote info hash does not match the commit info previous hash")
	ErrStatement        = newSentinel(ErrInvalid, "vote statement violates the signing rules")
	ErrSealSigMissing   = newSentinel(ErrInvalid, "committing vote has no seal signature")
	ErrSealSigForbidden = newSentinel(ErrInvalid, "seal signature present where forbidden")
	ErrSigRange         = newSentinel(ErrInvalid, "signature scalar out of range or high-s")
	ErrSigInvalid       = newSentinel(ErrInvalid, "signature does not verify")

	// Pair.
	ErrPairScheme        = newSentinel(ErrInvalid, "equivocation needs two scheme 2 votes")
	ErrPairSigner        = newSentinel(ErrInvalid, "pair signers differ")
	ErrPairContext       = newSentinel(ErrInvalid, "pair network, domain, epoch, round or kind differ")
	ErrPairSameStatement = newSentinel(ErrInvalid, "pair carries the same signed statement")
)
