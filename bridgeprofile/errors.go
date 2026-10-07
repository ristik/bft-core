package bridgeprofile

import "errors"

// sentinel is a named error that unwraps to its parent family so tests can
// match the exact reason or the family with errors.Is.
type sentinel struct {
	msg    string
	parent error
}

func (e *sentinel) Error() string { return e.msg }
func (e *sentinel) Unwrap() error { return e.parent }

func newSentinel(parent error, msg string) *sentinel { return &sentinel{msg: msg, parent: parent} }

// Families. A malformed input is a framing/encoding failure, an invalid one is
// well formed but outside the launch profile or wrong, a budget failure is a
// direct-verification cap.
var (
	ErrMalformed = errors.New("bridgeprofile: malformed encoding")
	ErrInvalid   = errors.New("bridgeprofile: relation does not hold")
	ErrBudget    = errors.New("bridgeprofile: direct budget exceeded")
)

// Malformed reasons.
var (
	ErrTruncated     = newSentinel(ErrMalformed, "truncated input")
	ErrTrailing      = newSentinel(ErrMalformed, "trailing bytes")
	ErrNonCanonical  = newSentinel(ErrMalformed, "non-shortest or reserved CBOR head")
	ErrForbiddenCBOR = newSentinel(ErrMalformed, "forbidden CBOR item (indefinite, float, simple, text, map)")
	ErrShape         = newSentinel(ErrMalformed, "unexpected structure")
	ErrTag           = newSentinel(ErrMalformed, "unexpected tag")
	ErrVersion       = newSentinel(ErrMalformed, "unsupported literal version field")
	ErrLength        = newSentinel(ErrMalformed, "wrong byte length")
	ErrIntRange      = newSentinel(ErrMalformed, "integer out of range")
	ErrABIFraming    = newSentinel(ErrMalformed, "noncanonical ABI framing")
	ErrBadOperation  = newSentinel(ErrMalformed, "unknown kernel operation")
)

// Budget reasons.
var (
	ErrInputTooLarge = newSentinel(ErrBudget, "input too large")
	ErrTooManyTx     = newSentinel(ErrBudget, "too many transfers")
	ErrTooManyItems  = newSentinel(ErrBudget, "too many CBOR items")
	ErrTooDeep       = newSentinel(ErrBudget, "CBOR nesting too deep")
	ErrTooManyPaths  = newSentinel(ErrBudget, "too many path steps")
)

// Configuration and policy reasons.
var (
	ErrCfgMismatch     = newSentinel(ErrInvalid, "configuration does not match")
	ErrPolicyHash      = newSentinel(ErrInvalid, "policy body hash does not match Cfg.aggregatorPolicyHash")
	ErrPolicyTuple     = newSentinel(ErrInvalid, "anchor tuple does not equal the authenticated policy tuple")
	ErrPolicyAnchors   = newSentinel(ErrInvalid, "policy admits exactly one anchor")
	ErrPolicyLeafIndex = newSentinel(ErrInvalid, "leaf proof anchor index is not zero")
	ErrPolicyLeafCount = newSentinel(ErrInvalid, "leaf proof count does not equal the exported leaf count")
	ErrPolicyPartition = newSentinel(ErrInvalid, "aggregator partition equals the EVM partition")
)

// Token profile reasons.
var (
	ErrPredicate      = newSentinel(ErrInvalid, "predicate is not an admitted signature or burn predicate")
	ErrMintShape      = newSentinel(ErrInvalid, "mint is outside the launch profile")
	ErrMintJustif     = newSentinel(ErrInvalid, "mint justification is not the exact lock justification")
	ErrMintSalt       = newSentinel(ErrInvalid, "mint salt is not the derived salt")
	ErrMintType       = newSentinel(ErrInvalid, "mint type is not the bridge type")
	ErrMintData       = newSentinel(ErrInvalid, "mint data is not the bridge payload")
	ErrTransferData   = newSentinel(ErrInvalid, "intermediate transfer carries data")
	ErrCDMismatch     = newSentinel(ErrInvalid, "certification data does not equal the reconstructed transition")
	ErrUnlock         = newSentinel(ErrInvalid, "unlock signature does not verify")
	ErrUnlockLength   = newSentinel(ErrInvalid, "unlock is not 65 bytes")
	ErrUnlockScalars  = newSentinel(ErrInvalid, "unlock scalar out of range or high-s")
	ErrUnlockRecovery = newSentinel(ErrInvalid, "unlock recovery id out of range")
	ErrUnlockKey      = newSentinel(ErrInvalid, "recovered key differs from the source key")
	ErrMinterKey      = newSentinel(ErrInvalid, "derived minter secret is not a valid scalar")
	ErrRepeatedSID    = newSentinel(ErrInvalid, "repeated state ID in history")
	ErrNoTransfers    = newSentinel(ErrInvalid, "return requires at least the final burn")
	ErrHasTransfers   = newSentinel(ErrInvalid, "mint operation requires zero transfers")
	ErrBurnNotFinal   = newSentinel(ErrInvalid, "burn predicate before the final transfer")
	ErrNotBurn        = newSentinel(ErrInvalid, "final transfer does not lock a burn predicate")
	ErrBurnReason     = newSentinel(ErrInvalid, "burn reason is not the hash of the return data")
	ErrReturnData     = newSentinel(ErrInvalid, "return data is not the exact return reason")
	ErrReturnAmount   = newSentinel(ErrInvalid, "return amount is not the whole genesis amount")
	ErrReturnRecip    = newSentinel(ErrInvalid, "return recipient is zero or the vault")
	ErrLockInput      = newSentinel(ErrInvalid, "lock input outside the profile")
	ErrZeroDigest     = newSentinel(ErrInvalid, "lock digest or nullifier is zero")
)
