package signingauthority

import "errors"

// The refusal names the contract uses (§6 of the design note). Step 1 raises the first four; the
// rest are named here so step 2 does not invent a second vocabulary for the same outcomes.
var (
	// ErrContextMismatch is enrollment substitution: another node, partition, shard, network,
	// configuration, shard epoch or signing profile than the one this authority was enrolled for.
	// Enrollment is a guard, never a namespace a caller may move to escape an earlier decision.
	ErrContextMismatch = errors.New("signing-context-mismatch")

	// ErrPoPDomain is a handoff possession-proof request that does not name the possession-proof domain: the authority signs exactly
	// that one message for its own key, never anything a caller labels differently.
	ErrPoPDomain = errors.New("signing-pop-domain-mismatch")

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

// Step 2 adds the signing record's own refusals (§4, §5 and §6).
var (
	// ErrFenced is an operation from a client generation that is no longer current. Only the
	// operator control plane advances the generation, and a client cannot mint one.
	ErrFenced = errors.New("signing-session-fenced")

	// ErrStale is work below the highest reserved round, even when the bytes are identical. Keeping
	// only the highest reservation is what makes the record bounded; the cost is that old delivery
	// retries stop once newer signing work has superseded them.
	ErrStale = errors.New("signing-stale")

	// ErrConflict is different complete bytes for the round that is already reserved. It is never a
	// reason to rebuild or retry with something else: one assigned partition round admits exactly
	// one unsigned request, whatever authorization is presented for it.
	ErrConflict = errors.New("signing-conflict")

	// ErrNoReservation is signing or releasing when nothing is reserved.
	ErrNoReservation = errors.New("signing-no-reservation")

	// ErrResponseNotRetained is a release before the signed response has been retained. Retention
	// happens before any response can leave, so that a lost caller replays identical bytes.
	ErrResponseNotRetained = errors.New("response-not-retained")

	// ErrStateUntrusted is latched when an invariant of the record fails, and when the generation
	// space is exhausted. It is deliberately terminal for this authority lifetime: the record is
	// never cleared and reused while the same key is held, and there is no reset.
	ErrStateUntrusted = errors.New("signing-state-untrusted")
)

// The authority process boundary adds the outcome that only exists once the authority is somewhere
// else (§3, §6).
var (
	// ErrUnavailable is the authority not answering: no process listening, a connection that died
	// mid-operation, a refused or timed-out call. It is deliberately distinct from every refusal
	// above, because those are decisions the authority made and this one is the absence of a
	// decision. Both make the node non-voting; only one of them says something about the work.
	//
	// There is no fallback local signer, so unavailability is a liveness cost taken on purpose
	// (§3): a node that cannot reach its authority keeps observing and reconciling, and does not
	// vote.
	ErrUnavailable = errors.New("signing-authority-unavailable")
)

// Deployment adds the outcome of an authority that exists but cannot admit anything yet.
var (
	// ErrEnrollmentIncomplete is an authority whose shard configuration has not been stated. The
	// configuration a certificate commits to names every validator's signing key, including the key
	// this authority generates, so it can only be written down after that key exists. Until the
	// operator completes the enrollment (CompleteEnrollment), no session is issued and no request is
	// authenticated or reserved.
	ErrEnrollmentIncomplete = errors.New("signing-enrollment-incomplete")
)

// ErrNoHashSigner is an authority whose key cannot sign a 32-byte digest: the EVM possession proofs need the key's raw ECDSA over a keccak digest.
var ErrNoHashSigner = errors.New("signing-key-cannot-sign-a-digest")
