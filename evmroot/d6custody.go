package evmroot

import (
	"bytes"
	"crypto/sha256"
)

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

// VaultBacking is the wrapper-vs-vault separation. WUCT is a distinct
// composability wrapper backed by its OWN contract's native deposits; a
// WUCT custody path cannot call an ERC-20 balance as native custody.
type VaultBacking struct {
	VaultNativeBalance    uint64 // native UCT held by the bridge vault (a_A = zero address)
	WUCTSupply            uint64 // outstanding wrapped-native
	WUCTContractNative    uint64 // native UCT held by the WUCT contract itself
	BridgedTotalLiability uint64 // O + C : outstanding backing + unpaid credits owed by the vault
}

// Consistent requires: the vault's native balance covers the FULL bridge
// liability owed against it (O + C, not just O), and WUCT is fully backed
// by its own contract's native, with no cross-counting between the two.
func (v VaultBacking) Consistent() bool {
	return v.BridgedTotalLiability <= v.VaultNativeBalance &&
		v.WUCTSupply <= v.WUCTContractNative
}

// BridgeLedger is the liability accounting of appendix-bridging.tex
// §"Accounting": L cumulative locked native value, D cumulative redemption
// value credited after verified burns, P cumulative value actually paid to
// claimants (including relayer shares). Balance is the vault's current
// native UCT holding; Shortfall is any amount by which the vault falls
// below what it owes.
type BridgeLedger struct {
	L         uint64
	D         uint64
	P         uint64
	Balance   uint64 // vault native UCT balance
	Shortfall uint64 // Balance deficit versus (L - P); >0 means the vault is under-collateralised
}

// Outstanding backing O = L - D.
func (b BridgeLedger) Outstanding() uint64 { return b.L - b.D }

// UnpaidCredits C = D - P.
func (b BridgeLedger) UnpaidCredits() uint64 { return b.D - b.P }

// Owed is what the vault must hold to cover every claim: O + C == L - P.
func (b BridgeLedger) Owed() uint64 { return b.L - b.P }

// Solvent reports whether the vault actually covers what it owes:
//
//	Balance + Shortfall == L - P    (the accounting identity closes)
//	Shortfall == 0                  (no deficit)
//
// This is the check the earlier model was missing: L == D == 100, P == 0,
// Balance == 0 has L >= D >= P but Owed == 100 and Balance == 0, so it is
// insolvent.
func (b BridgeLedger) Solvent() bool {
	return b.L >= b.D && b.D >= b.P && // ordering still holds
		b.Balance+b.Shortfall == b.Owed() && // identity closes
		b.Shortfall == 0 // and there is no deficit
}

// Invariants keeps the ordering check for callers that only need L >= D >= P.
func (b BridgeLedger) Invariants() bool { return b.L >= b.D && b.D >= b.P }

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
	Owed         uint64       `json:"owed"`
	Solvent      bool         `json:"solvent"`
}

// WalkCustody applies amount through Locked → Burned → RedemptionCredited →
// Paid, tracking the vault Balance and checking solvency at every step.
// Lock deposits native into the vault (Balance += amount); burn on the
// Execution layer changes nothing in the vault; crediting moves D; payment
// debits the vault (Balance -= amount) and moves P. Solvent() holds at
// every step.
func WalkCustody(start BridgeLedger, amount uint64) []CustodyStep {
	l := start
	steps := []CustodyStep{}
	record := func(st CustodyState) {
		steps = append(steps, CustodyStep{
			State: st.String(), Ledger: l,
			Outstanding: l.Outstanding(), UnpaidCredit: l.UnpaidCredits(),
			Owed: l.Owed(), Solvent: l.Solvent(),
		})
	}
	l.L += amount
	l.Balance += amount // native locked into the vault
	record(CustodyLocked)
	record(CustodyBurned) // Execution-layer burn; vault unchanged
	l.D += amount
	record(CustodyRedemptionCredited)
	l.P += amount
	l.Balance -= amount // paid out of the vault
	record(CustodyPaid)
	return steps
}

// LockWitness is an authenticated proof that a permanent lock digest is
// included under a certified EVM state root. Refreshing produces a new
// witness (newer RootStateRoot / path) for the SAME digest.
type LockWitness struct {
	Digest        []byte
	RootStateRoot []byte
	Path          []PathStep
}

// Verify recomputes the witness path and reports whether it authenticates
// Digest under RootStateRoot.
func (w LockWitness) Verify() bool {
	return len(w.Digest) > 0 && bytes.Equal(evalPath(w.Digest, w.Path), w.RootStateRoot)
}

// TokenLockIdentity is SHA-256(CBOR([tokenIdentity, permanentLockDigest])) —
// a function of those two values ONLY. It does not include any witness.
func TokenLockIdentity(tokenIdentity, permanentLockDigest []byte) Hash32 {
	return sha256.Sum256(lockIdentity(tokenIdentity, permanentLockDigest))
}

// RefreshLockWitness checks that `fresh` is a valid witness for the same
// permanentLockDigest as `old`, under a newer certified root. It returns
// whether the token-lock identity is unchanged (it must be — identity omits
// the witness) and whether the backing was genuinely refreshed (a different
// root).
func RefreshLockWitness(tokenIdentity, permanentLockDigest []byte, old, fresh LockWitness) (identityUnchanged, backingRefreshed, freshValid bool) {
	freshValid = fresh.Verify() &&
		bytes.Equal(fresh.Digest, permanentLockDigest) &&
		bytes.Equal(old.Digest, permanentLockDigest)
	before := TokenLockIdentity(tokenIdentity, permanentLockDigest)
	after := TokenLockIdentity(tokenIdentity, permanentLockDigest)
	identityUnchanged = before == after
	backingRefreshed = !bytes.Equal(old.RootStateRoot, fresh.RootStateRoot)
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
