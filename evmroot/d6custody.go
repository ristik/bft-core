package evmroot

import "bytes"

// D6 part 3: native supply accounting, bridge liability accounting, and the
// refreshable lock witness.
//
// Normative source: docs/design/d6-historical-trust-proof-custody.md §4,
// docs/pos/specification/appendix-bridging.tex §"Accounting",
// evm-partition.tex §"Native Currency".

// GlobalSupplyObservable is false: there is no globally observable
// Execution-layer supply. Public monitoring reports known liabilities and
// coverage of observations, not an exhaustive circulating-supply
// measurement.
const GlobalSupplyObservable = false

// SupplyLedger tracks native UCT. Supply(n) = S0 - Burn(n); protocol
// execution creates no additional UCT.
type SupplyLedger struct {
	S0   uint64
	Burn uint64
}

func (s SupplyLedger) NativeSupply() uint64 { return s.S0 - s.Burn }

// ClaimKind distinguishes the three balances that must never be
// double-counted against the same backing.
type ClaimKind uint8

const (
	ClaimNativeUCT ClaimKind = iota // a native account balance
	ClaimWUCT                       // the wrapped-native ERC-20 contract balance
	ClaimBridged                    // an Execution-layer token claim backed by vault native UCT
)

func (k ClaimKind) String() string {
	return [...]string{"native_uct", "wuct", "bridged"}[k]
}

// VaultBacking is the check that WUCT and bridged claims do not double-count
// the vault's native UCT.
type VaultBacking struct {
	VaultNativeBalance uint64 // native UCT held by the bridge vault (a_A = zero address)
	WUCTSupply         uint64 // outstanding wrapped-native
	BridgedOutstanding uint64 // outstanding bridged claims (O = L - D)
}

// Consistent reports whether the vault's native balance covers both the
// WUCT wrapper and outstanding bridged claims without either being counted
// as the other's backing. WUCT is a separate composability wrapper; a WUCT
// custody path cannot call an ERC-20 balance as native custody.
func (v VaultBacking) Consistent() bool {
	// Each wrapped unit is 1:1 native in the WUCT contract; each bridged
	// outstanding unit is 1:1 native in the vault. The vault's native
	// balance must be at least the bridged outstanding; WUCT is backed by
	// its own contract's native deposits, distinct from the vault.
	return v.BridgedOutstanding <= v.VaultNativeBalance
}

// BridgeLedger is the liability accounting of appendix-bridging.tex
// §"Accounting": L cumulative locked native value, D cumulative redemption
// value credited after verified burns, P cumulative value actually paid to
// claimants (including relayer shares).
type BridgeLedger struct {
	L uint64
	D uint64
	P uint64
}

// Outstanding backing O = L - D.
func (b BridgeLedger) Outstanding() uint64 { return b.L - b.D }

// UnpaidCredits C = D - P.
func (b BridgeLedger) UnpaidCredits() uint64 { return b.D - b.P }

// Invariants: L ≥ D ≥ P, so O ≥ 0 and C ≥ 0. Rewards, treasury and bridge
// liabilities cannot spend one another's backing.
func (b BridgeLedger) Invariants() bool {
	return b.L >= b.D && b.D >= b.P
}

// CustodyState is one intermediate state of a bridged unit.
type CustodyState uint8

const (
	CustodyLocked CustodyState = iota
	CustodyBurned
	CustodyRedemptionCredited
	CustodyPaid
)

func (c CustodyState) String() string {
	return [...]string{"locked", "burned", "redemption_credited", "paid"}[c]
}

// CustodyStep records the ledger after one transition of a unit-value flow.
type CustodyStep struct {
	State        string       `json:"state"`
	Ledger       BridgeLedger `json:"ledger"`
	Outstanding  uint64       `json:"outstanding"`
	UnpaidCredit uint64       `json:"unpaid_credit"`
	InvariantsOK bool         `json:"invariants_ok"`
}

// WalkCustody applies amount through Locked → Burned → RedemptionCredited →
// Paid, recording the ledger and invariants at each step. Burn does not
// change L/D/P (the lock still backs it until redemption is credited);
// crediting moves D; payment moves P.
func WalkCustody(start BridgeLedger, amount uint64) []CustodyStep {
	l := start
	steps := []CustodyStep{}
	record := func(st CustodyState) {
		steps = append(steps, CustodyStep{
			State: st.String(), Ledger: l,
			Outstanding: l.Outstanding(), UnpaidCredit: l.UnpaidCredits(), InvariantsOK: l.Invariants(),
		})
	}
	l.L += amount
	record(CustodyLocked)
	record(CustodyBurned) // burn on the Execution layer; vault ledger unchanged until credit
	l.D += amount
	record(CustodyRedemptionCredited)
	l.P += amount
	record(CustodyPaid)
	return steps
}

// RefreshLockWitness models refreshing historical backing: a recent proof
// of the SAME permanent lock digest refreshes the witness without changing
// token identity. Token identity does not include the refreshed witness.
// Lock digests remain provable after redemption and cannot be deleted.
func RefreshLockWitness(tokenIdentity, permanentLockDigest, oldWitnessRootHistory, freshWitnessRootHistory []byte) (identityUnchanged bool, backingRefreshed bool) {
	// The fresh witness authenticates the same permanentLockDigest under a
	// newer certified root history. Identity is a function of
	// tokenIdentity + permanentLockDigest only.
	identityBefore := lockIdentity(tokenIdentity, permanentLockDigest)
	identityAfter := lockIdentity(tokenIdentity, permanentLockDigest)
	identityUnchanged = bytes.Equal(identityBefore, identityAfter)
	backingRefreshed = !bytes.Equal(oldWitnessRootHistory, freshWitnessRootHistory)
	return
}

func lockIdentity(tokenIdentity, permanentLockDigest []byte) []byte {
	return marshalCBOR(cArray{cBytes(tokenIdentity), cBytes(permanentLockDigest)})
}

// TokenProfile fixes the initial enshrined token type restriction: whole
// transfers and burns only, no split, no merge, no arbitrary mint-reason
// extension. Enforced by the type verifier, all SDKs and both redemption
// relations.
type TokenProfile struct {
	AllowSplit         bool
	AllowMerge         bool
	AllowMintReasonExt bool
}

// InitialEnshrinedProfile is the frozen restriction.
func InitialEnshrinedProfile() TokenProfile { return TokenProfile{} }

// Permits reports whether an operation is allowed under a profile.
func (p TokenProfile) Permits(op string) bool {
	switch op {
	case "transfer", "burn":
		return true
	case "split":
		return p.AllowSplit
	case "merge":
		return p.AllowMerge
	case "mint_reason_extension":
		return p.AllowMintReasonExt
	default:
		return false
	}
}

// RedemptionRelation names the two paths that implement the SAME semantic
// redemption relation on the common admitted token profile.
type RedemptionRelation struct {
	Path               string // "direct" or "succinct"
	BindsNetwork       bool
	BindsConfig        bool
	BindsTrustBase     bool
	BindsNullifier     bool
	BindsLockRefs      bool
	BindsReleaseLeaves bool
}

// SameSemanticRelation reports whether two paths bind the same set of
// facts — the requirement for direct and succinct to be interchangeable on
// their common profile despite different witness formats and budgets.
func SameSemanticRelation(a, b RedemptionRelation) bool {
	return a.BindsNetwork == b.BindsNetwork && a.BindsConfig == b.BindsConfig &&
		a.BindsTrustBase == b.BindsTrustBase && a.BindsNullifier == b.BindsNullifier &&
		a.BindsLockRefs == b.BindsLockRefs && a.BindsReleaseLeaves == b.BindsReleaseLeaves &&
		a.BindsNetwork && a.BindsConfig && a.BindsTrustBase && a.BindsNullifier && a.BindsLockRefs && a.BindsReleaseLeaves
}
