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
	ErrDeadline      = newSentinel(ErrMalformed, "deadline is neither null nor an integer in [1,2^64-1]")
	ErrRLP           = newSentinel(ErrMalformed, "noncanonical or malformed RLP")
	// A certificate outside the intersection of the native bounded scan and the SDK 3.0.1 codec.
	ErrCertScan      = newSentinel(ErrMalformed, "certificate outside the native/SDK codec intersection")
	ErrCertSigLength = newSentinel(ErrMalformed, "certificate seal signature is not 65 bytes")
)

// Budget reasons.
var (
	ErrInputTooLarge = newSentinel(ErrBudget, "input too large")
	ErrTooManyTx     = newSentinel(ErrBudget, "too many transfers")
	ErrTooManyItems  = newSentinel(ErrBudget, "too many CBOR items")
	ErrTooDeep       = newSentinel(ErrBudget, "CBOR nesting too deep")
	ErrTooManyPaths  = newSentinel(ErrBudget, "too many path steps")
	ErrGasBudget     = newSentinel(ErrBudget, "direct-call gas gate exceeded")
	// Embedded lock evidence over a bound: rejected, never fetched online.
	ErrJustificationTooLarge = newSentinel(ErrBudget, "mint justification over the evidence bound")
	ErrLockProofTooLarge     = newSentinel(ErrBudget, "lock proof component over its bound")
)

// Configuration and policy reasons.
var (
	ErrCfgMismatch     = newSentinel(ErrInvalid, "configuration does not match")
	ErrPolicyHash      = newSentinel(ErrInvalid, "policy body hash does not match Cfg.aggregatorPolicyHash")
	ErrPolicyTuple     = newSentinel(ErrInvalid, "anchor tuple does not equal the authenticated policy tuple")
	ErrPolicyAnchors   = newSentinel(ErrInvalid, "anchor table is not the distinct-UC first-use table of the leaves")
	ErrPolicyLeafIndex = newSentinel(ErrInvalid, "leaf proof anchor index is out of range, not first-use ordered, or not an anchor of the leaf's shard")
	ErrPolicyLeafCount = newSentinel(ErrInvalid, "leaf proof count does not equal the exported leaf count")
	ErrPolicyPartition = newSentinel(ErrInvalid, "aggregator partition equals the EVM partition")
)

// Token profile reasons.
var (
	ErrPredicate      = newSentinel(ErrInvalid, "predicate is not an admitted signature or burn predicate")
	ErrMintShape      = newSentinel(ErrInvalid, "mint is outside the launch profile")
	ErrMintJustif     = newSentinel(ErrInvalid, "mint justification is not the exact lock justification")
	ErrLockProofShape = newSentinel(ErrMintJustif, "embedded lock proof is not the exact canonical shape")
	ErrLockProofCfg   = newSentinel(ErrMintJustif, "embedded lock proof names another configuration")
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

	ErrDeadlineMismatch = newSentinel(ErrInvalid, "certification deadline differs from the transaction deadline")
	ErrDeadlineExpired  = newSentinel(ErrInvalid, "reference time is not before the explicit deadline")
)

// Composition reasons: the anchor opening, the reference-time bound and the
// B1 calls the composing verifier makes.
var (
	ErrIROpening   = newSentinel(ErrInvalid, "input record opening does not hash to the anchor's expected IR hash")
	ErrIRShape     = newSentinel(ErrInvalid, "input record opening is not the exact native encoding")
	ErrIRState     = newSentinel(ErrInvalid, "opened input record state hash differs from the anchor's expected state root")
	ErrIRTime      = newSentinel(ErrInvalid, "leaf reference time is after the authenticated input record timestamp")
	ErrAnchorAuth  = newSentinel(ErrInvalid, "B1 did not authenticate the anchor")
	ErrLeafProof   = newSentinel(ErrInvalid, "B1 did not prove the leaf under the authenticated root")
	ErrPathBitmap  = newSentinel(ErrInvalid, "leaf path bitmap popcount differs from the sibling count")
	ErrLeafValue   = newSentinel(ErrInvalid, "kernel leaf value differs from the recomputed value")
	ErrResultFrame = newSentinel(ErrMalformed, "kernel output is not the canonical result")
)

// Embedded lock proof verification reasons (offline: token plus pinned
// trust base). Unknown epochs and every binding failure are distinct.
var (
	ErrTrustBaseDigest = newSentinel(ErrInvalid, "the proof's trustBaseId is not the digest of the installed trust-base document")
	ErrEpochMismatch   = newSentinel(ErrInvalid, "certificate network, root epoch or root round is outside the one pinned base")
	ErrTrustConfig     = newSentinel(ErrInvalid, "trust base is outside the supported fixed profile (unit weights, quorum N-(N-1)/3)")
	ErrLockUC          = newSentinel(ErrInvalid, "embedded unicity certificate does not verify")
	ErrLockPDR         = newSentinel(ErrInvalid, "embedded partition description is not the pinned deployment's")
	ErrLockHeader      = newSentinel(ErrInvalid, "header is not bound to the certified input record")
	ErrLockAccount     = newSentinel(ErrInvalid, "vault account proof does not verify under the header state root")
	ErrLockCodeHash    = newSentinel(ErrInvalid, "vault account code hash is not the pinned runtime hash")
	ErrLockStorage     = newSentinel(ErrInvalid, "lock storage proof does not verify under the account storage root")
	ErrLockDigest      = newSentinel(ErrInvalid, "stored lock digest differs from the digest reconstructed from the mint")
	ErrMPTNode         = newSentinel(ErrInvalid, "MPT node is noncanonical, mis-hashed or out of order")
	ErrMPTPath         = newSentinel(ErrInvalid, "MPT path is not fully consumed by exactly the supplied nodes")
	ErrMPTAbsent       = newSentinel(ErrInvalid, "MPT key is absent")
	ErrMPTExtraneous   = newSentinel(ErrInvalid, "MPT proof carries a duplicate or extraneous node")
)
