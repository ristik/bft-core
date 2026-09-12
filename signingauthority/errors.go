package signingauthority

import "errors"

// The refusal names the contract uses (§6 of the design note). Step 1 raises the first four; the
// rest are named here so step 2 does not invent a second vocabulary for the same outcomes.
var (
	// ErrContextMismatch is enrollment substitution: another node, partition, shard, network,
	// configuration, shard epoch or signing profile than the one this authority was enrolled for.
	// Enrollment is a guard, never a namespace a caller may move to escape an earlier decision.
	ErrContextMismatch = errors.New("signing-context-mismatch")

	// ErrUnauthenticated is a request whose certificate, seal quorum, inclusion paths or bound
	// TechnicalRecord do not verify against the authority's own trust.
	ErrUnauthenticated = errors.New("signing-unauthenticated-input")

	// ErrProposalMismatch is an authentic authorization with a proposal that does not belong to it:
	// the wrong assigned round or epoch, a previous state hash that is not the certified one, or a
	// timestamp that is not the seal's.
	ErrProposalMismatch = errors.New("signing-proposal-mismatch")

	// ErrRequestTooLarge bounds the complete signature-free request (§5). The bound is measured on
	// the encoding the authority has taken, which is the same byte string it would return, and it is
	// measured before that encoding is decoded into an owned structure. Encoding the caller's
	// request is what makes its size knowable at all, so this is not a promise that nothing is
	// allocated for an oversize message; it is a promise that nothing larger than the bound is
	// decoded, validated or retained beyond that one encoding.
	ErrRequestTooLarge = errors.New("signing-request-too-large")

	// ErrUnsupportedVersion is a structure whose version this profile does not implement. Nothing is
	// truncated or coerced to fit.
	ErrUnsupportedVersion = errors.New("signing-unsupported-version")

	// ErrKeyLost is the authority having no key for this identity. Step 1 can only reach it through
	// a closed authority; there is no import path that could recover one.
	ErrKeyLost = errors.New("signing-key-lost")
)
