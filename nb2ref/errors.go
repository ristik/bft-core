package nb2ref

import (
	"errors"
	"fmt"
)

// Rule is one named rejection rule of docs/design/native-bridge-v2.md section 14. Every rule has exactly one sentinel, ErrName,
// and the sentinels do not wrap each other: errors.Is(err, ErrX) holds for exactly the rules the error names. A wallet rule
// that reports an inner failure (SealReceipt, SegmentLog) wraps that failure, so errors.Is matches both and RuleOf names the
// outer one.
type Rule struct {
	Name    string // the section 14 name; the on-chain error is Name+"()"
	Section string // "14.1" .. "14.6"
	Retry   bool   // retryable once the verifier holds more data (NoEntryForEpoch)
}

func (r *Rule) Error() string { return "nb2: " + r.Name }

// rules is the registry in section 14 order.
var rules []*Rule

func rule(section, name string) *Rule {
	r := &Rule{Name: name, Section: section}
	rules = append(rules, r)
	return r
}

// Rules returns every rule in section 14 order.
func Rules() []*Rule { return append([]*Rule(nil), rules...) }

// RuleByName returns the rule named name, or nil.
func RuleByName(name string) *Rule {
	for _, r := range rules {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// RuleOf is the outermost rule an error carries, or nil for nil and for an error that names no rule.
func RuleOf(err error) *Rule {
	for err != nil {
		if r, ok := err.(*Rule); ok {
			return r
		}
		switch u := err.(type) {
		case interface{ Unwrap() []error }:
			for _, e := range u.Unwrap() {
				if r := RuleOf(e); r != nil {
					return r
				}
			}
			return nil
		case interface{ Unwrap() error }:
			err = u.Unwrap()
		default:
			return nil
		}
	}
	return nil
}

// RuleName is RuleOf(err).Name, "" for nil.
func RuleName(err error) string {
	if r := RuleOf(err); r != nil {
		return r.Name
	}
	return ""
}

// wrap reports outer with inner as its cause: errors.Is matches both, RuleOf names outer.
func wrap(outer *Rule, inner error) error {
	if inner == nil {
		return outer
	}
	return fmt.Errorf("%w: %w", outer, inner)
}

// detail attaches a diagnostic to a rule without adding another rule.
func detail(r *Rule, format string, args ...any) error {
	return fmt.Errorf("%w: %s", r, fmt.Sprintf(format, args...))
}

// 14.1 Encoding (all structures).
var (
	ErrTruncated     = rule("14.1", "Truncated")
	ErrTrailing      = rule("14.1", "Trailing")
	ErrNonCanonical  = rule("14.1", "NonCanonical")
	ErrShape         = rule("14.1", "Shape")
	ErrTag           = rule("14.1", "Tag")
	ErrVersion       = rule("14.1", "Version")
	ErrLength        = rule("14.1", "Length")
	ErrIntRange      = rule("14.1", "IntRange")
	ErrInputTooLarge = rule("14.1", "InputTooLarge")
	ErrConfigShape   = rule("14.1", "ConfigShape")
	ErrEvidenceShape = rule("14.1", "EvidenceShape")
)

// 14.2 Deposit evidence (section 6.2).
var (
	ErrMintDomain    = rule("14.2", "MintDomain")
	ErrDepositUC     = rule("14.2", "DepositUC")
	ErrDepositHeader = rule("14.2", "DepositHeader")
	ErrReceiptPath   = rule("14.2", "ReceiptPath")
	ErrReceiptType   = rule("14.2", "ReceiptType")
	ErrReceiptStatus = rule("14.2", "ReceiptStatus")
	ErrLogIndex      = rule("14.2", "LogIndex")
	ErrLogEmitter    = rule("14.2", "LogEmitter")
	ErrLogTopics     = rule("14.2", "LogTopics")
	ErrLogData       = rule("14.2", "LogData")
	ErrSecretOpening = rule("14.2", "SecretOpening")
	ErrMintSalt      = rule("14.2", "MintSalt")
	ErrMintType      = rule("14.2", "MintType")
	ErrMintOwner     = rule("14.2", "MintOwner")
	ErrMintData      = rule("14.2", "MintData")
	ErrMintReason    = rule("14.2", "MintReason")
)

// 14.3 Return (sections 8 and 11.2).
var (
	ErrNotBurn         = rule("14.3", "NotBurn")
	ErrBurnNotFinal    = rule("14.3", "BurnNotFinal")
	ErrBurnReason      = rule("14.3", "BurnReason")
	ErrReturnData      = rule("14.3", "ReturnData")
	ErrReturnDomain    = rule("14.3", "ReturnDomain")
	ErrReturnAsset     = rule("14.3", "ReturnAsset")
	ErrReturnAmount    = rule("14.3", "ReturnAmount")
	ErrReturnRecipient = rule("14.3", "ReturnRecipient")
	ErrReturnIndex     = rule("14.3", "ReturnIndex")
)

// 14.4 Token and lineage (unchanged from protocol 7).
var (
	ErrPredicate                      = rule("14.4", "Predicate")
	ErrMintShape                      = rule("14.4", "MintShape")
	ErrTransferData                   = rule("14.4", "TransferData")
	ErrCDMismatch                     = rule("14.4", "CDMismatch")
	ErrUnlockLength                   = rule("14.4", "UnlockLength")
	ErrUnlockScalars                  = rule("14.4", "UnlockScalars")
	ErrUnlockRecovery                 = rule("14.4", "UnlockRecovery")
	ErrUnlockKey                      = rule("14.4", "UnlockKey")
	ErrRepeatedSID                    = rule("14.4", "RepeatedSID")
	ErrNoTransfers                    = rule("14.4", "NoTransfers")
	ErrDeadlineMismatch               = rule("14.4", "DeadlineMismatch")
	ErrDeadlineExpired                = rule("14.4", "DeadlineExpired")
	ErrInclusionProof                 = rule("14.4", "InclusionProof")
	ErrReferenceTime                  = rule("14.4", "ReferenceTime")
	ErrSealNetwork                    = rule("14.4", "SealNetwork")
	ErrSealEpoch                      = rule("14.4", "SealEpoch")
	ErrNoEntryForEpoch                = rule("14.4", "NoEntryForEpoch")
	ErrCertStructure                  = rule("14.4", "CertStructure")
	ErrSealRoot                       = rule("14.4", "SealRoot")
	ErrQuorumNotMet                   = rule("14.4", "QuorumNotMet")
	ErrUnsupportedCertificateEncoding = rule("14.4", "UnsupportedCertificateEncoding")
	ErrSplitJustif                    = rule("14.4", "SplitJustif")
	ErrSplitProofCount                = rule("14.4", "SplitProofCount")
	ErrSplitProofShape                = rule("14.4", "SplitProofShape")
	ErrSplitManifest                  = rule("14.4", "SplitManifest")
	ErrSplitBurn                      = rule("14.4", "SplitBurn")
	ErrSplitProof                     = rule("14.4", "SplitProof")
	ErrSplitSum                       = rule("14.4", "SplitSum")
)

// 14.5 Redemption, deposit and construction (vault).
var (
	ErrBadHistoryLength        = rule("14.5", "BadHistoryLength")
	ErrFutureIndex             = rule("14.5", "FutureIndex")
	ErrStaleEndpoint           = rule("14.5", "StaleEndpoint")
	ErrBadGapProof             = rule("14.5", "BadGapProof")
	ErrChainMismatch           = rule("14.5", "ChainMismatch")
	ErrAlreadyPaid             = rule("14.5", "AlreadyPaid")
	ErrVerifierRefused         = rule("14.5", "VerifierRefused")
	ErrVerifierBadReturn       = rule("14.5", "VerifierBadReturn")
	ErrDomainMismatch          = rule("14.5", "DomainMismatch")
	ErrAssetMismatch           = rule("14.5", "AssetMismatch")
	ErrClaimMismatch           = rule("14.5", "ClaimMismatch")
	ErrBadRecipient            = rule("14.5", "BadRecipient")
	ErrZeroAmount              = rule("14.5", "ZeroAmount")
	ErrLiabilityUnderflow      = rule("14.5", "LiabilityUnderflow")
	ErrSegmentCounterExhausted = rule("14.5", "SegmentCounterExhausted")
	ErrPayoutFailed            = rule("14.5", "PayoutFailed")
	ErrReentrancy              = rule("14.5", "Reentrancy")
	ErrZeroValue               = rule("14.5", "ZeroValue")
	ErrBadFirstOwner           = rule("14.5", "BadFirstOwner")
	ErrLiabilityCap            = rule("14.5", "LiabilityCap")
	ErrDepositCounterExhausted = rule("14.5", "DepositCounterExhausted")
	ErrBadConfig               = rule("14.5", "BadConfig")
)

// 14.6 Wallet refusals (no on-chain counterpart).
var (
	ErrSealReceipt       = rule("14.6", "SealReceipt")
	ErrSegmentLog        = rule("14.6", "SegmentLog")
	ErrCapacityPreflight = rule("14.6", "CapacityPreflight")
	ErrCapacityExceeded  = rule("14.6", "CapacityExceeded")
	ErrImplausibleIndex  = rule("14.6", "ImplausibleIndex")
	ErrEvidencePruned    = rule("14.6", "EvidencePruned")
)

func init() { ErrNoEntryForEpoch.Retry = true }

// ErrInvalidMinterScalar is not a rule: the universal minter scalar of a token ID is outside [1, n). No such ID is known (about
// 2^-128 per ID), so no input can raise it; the coordinator ruling of 2026-11-15 dropped the MinterKey rule name. The scalar
// rule itself is vectored (primitives.minterScalars).
var ErrInvalidMinterScalar = errors.New("nb2: minter scalar outside [1, n)")

// ErrTrustInput is not a rule: the caller supplied a trust-base history that is not the one Γ names (its genesis EntryID is not
// rootGenesis32, or its network is not Γ's). On chain the history is the chain's own seal registry, so this cannot arise there.
var ErrTrustInput = errors.New("nb2: trust-base history does not match the configuration")

// disabled is the disable-each-check seam: a test may switch a semantic check off to prove that some negative vector depends on
// it. Production code never writes it; check reads it.
var disabled map[*Rule]bool

// fail reports r unless the check is disabled, in which case the check is skipped (nil).
func fail(r *Rule) error {
	if disabled[r] {
		return nil
	}
	return r
}

// failf is fail with a diagnostic.
func failf(r *Rule, format string, args ...any) error {
	if disabled[r] {
		return nil
	}
	return detail(r, format, args...)
}
