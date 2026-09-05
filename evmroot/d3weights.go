package evmroot

import (
	"crypto/sha256"
	"math/bits"
	"sort"
)

// D3 weighted-consensus model. Reference for versioned weighted quorum,
// timeout and impossibility arithmetic and for the versioned trust-base
// body identity that excludes endorsement witnesses.
//
// It replaces the pre-D3 count-based paths inventoried in
// docs/design/d3-weighted-consensus-trust-base.md §2. Every threshold here
// is over *authenticated voting power*, never over a signature count.
//
// Normative source: docs/design/d3-weighted-consensus-trust-base.md,
// docs/adr/0005-weighted-consensus-trust-base-identity.md. Issue:
// https://github.com/ristik/bft-core/issues/5

// Weight bounds. A member weight is an unsigned 64-bit count of the
// configured atomic UCT denomination u (appendix-evm.tex §"Candidate
// Record"). The per-member and total caps keep every sum and threshold
// computation inside a checked 128-bit intermediate with room to spare.
const (
	MaxMemberWeight uint64 = 1 << 40 // ~1.1e12 u per member
	MaxTotalWeight  uint64 = 1 << 48 // ~2.8e14 u total; below this, 2*W cannot overflow uint64
)

// Member binds an identity to its effective weight. In the trust base this
// is (staking identity, node identity, consensus key, weight); only the id
// and weight matter to the arithmetic.
type Member struct {
	ID     string
	Weight uint64
}

// WeightSet is the active assignment: the members whose weights form the
// quorum denominator W. Order is not significant to the arithmetic;
// canonical bodies sort by ID (see TrustBaseBodyV2).
type WeightSet []Member

// TotalWeight returns W = Σ bᵥ with a checked wide intermediate. ok is
// false if any member exceeds MaxMemberWeight, the running sum overflows
// uint64, or the total exceeds MaxTotalWeight. No caller substitutes a
// silently rescaled value.
func (ws WeightSet) TotalWeight() (w uint64, ok bool) {
	seen := make(map[string]struct{}, len(ws))
	var carry uint64
	for _, m := range ws {
		if m.ID == "" {
			return 0, false
		}
		if _, dup := seen[m.ID]; dup {
			return 0, false // membership must be unique
		}
		seen[m.ID] = struct{}{}
		if m.Weight == 0 || m.Weight > MaxMemberWeight {
			return 0, false // zero weight is not a member; over-cap is rejected
		}
		var c uint64
		w, c = bits.Add64(w, m.Weight, 0)
		carry |= c
	}
	if carry != 0 || w > MaxTotalWeight {
		return 0, false
	}
	return w, true
}

func (ws WeightSet) weightOf(id string) (uint64, bool) {
	for _, m := range ws {
		if m.ID == id {
			return m.Weight, true
		}
	}
	return 0, false
}

// RootQuorumThreshold is ⌊2W/3⌋ + 1 — the BFT Core consensus threshold
// (evm-partition.tex §"Validity"). 2*W cannot overflow because
// W ≤ MaxTotalWeight.
func RootQuorumThreshold(w uint64) uint64 { return (2*w)/3 + 1 }

// ShardAttestationThreshold is ⌊W/2⌋ + 1 — the EVM attestation threshold.
// The EVM uses exactly the same effective weights as the root assignment
// that authorised its shard round; no assumed seat bound substitutes.
func ShardAttestationThreshold(w uint64) uint64 { return w/2 + 1 }

// FaultyWeightBound is the largest voting power that may be Byzantine while
// a root quorum is still safe: W − RootQuorumThreshold(W). Timeout
// amplification (the "f+1" jump) triggers when the timeout-voting weight
// strictly exceeds this bound, since then at least one honest member's
// weight is among the timeout voters.
func FaultyWeightBound(w uint64) uint64 { return w - RootQuorumThreshold(w) }

// SignerWeight sums the unique, authorised signers' weights with a checked
// wide intermediate. ok is false on an unknown signer, a duplicate signer,
// or overflow — a duplicate is never double-counted, and a signature count
// is never substituted for weight.
func (ws WeightSet) SignerWeight(signers []string) (weight uint64, ok bool) {
	seen := make(map[string]struct{}, len(signers))
	for _, id := range signers {
		if _, dup := seen[id]; dup {
			return 0, false
		}
		seen[id] = struct{}{}
		bw, known := ws.weightOf(id)
		if !known {
			return 0, false
		}
		var c uint64
		weight, c = bits.Add64(weight, bw, 0)
		if c != 0 {
			return 0, false
		}
	}
	return weight, true
}

// QuorumReached reports whether the signers' authenticated weight meets the
// threshold. Returns (false,false) when the signer set is malformed.
func (ws WeightSet) QuorumReached(signers []string, threshold uint64) (reached, valid bool) {
	w, ok := ws.SignerWeight(signers)
	if !ok {
		return false, false
	}
	return w >= threshold, true
}

// TimeoutAmplifies reports whether the timeout-voting weight is enough to
// jump straight to the round-timeout state (a quorum for progress is no
// longer possible). True iff signerWeight > FaultyWeightBound(W).
func (ws WeightSet) TimeoutAmplifies(signers []string) (bool, bool) {
	total, ok := ws.TotalWeight()
	if !ok {
		return false, false
	}
	w, ok := ws.SignerWeight(signers)
	if !ok {
		return false, false
	}
	return w > FaultyWeightBound(total), true
}

// QuorumImpossible reports whether a threshold can no longer be reached:
// the weight already committed to a value plus all not-yet-voted weight is
// still below the threshold. remainingWeight is Σ weights of members who
// have not voted for this value.
func QuorumImpossible(currentWeight, remainingWeight, threshold uint64) bool {
	sum, c := bits.Add64(currentWeight, remainingWeight, 0)
	if c != 0 {
		return false // cannot conclude impossibility on overflow
	}
	return sum < threshold
}

// --- versioned trust-base body identity -----------------------------------

// TrustBaseBodyV2 is the canonical, witness-free identity of a trust-base
// entry in the new version. It excludes BOTH the current-epoch signatures
// AND the old-epoch endorsement witness: endorsement composes only after
// consensus has already selected the same handoff body, and its
// serialisation is separate from body identity (appendix-evm.tex
// §"Trust Base Record Derivation"). PredecessorHash is the canonical body
// identity of the current trust base — never a hash that folded in its
// signatures.
type TrustBaseBodyV2 struct {
	Version          uint64
	NetworkID        uint64
	Epoch            uint64
	EpochStart       uint64
	Members          WeightSet
	RootThreshold    uint64 // ⌊2·ΣWeight/3⌋+1, recorded explicitly
	StateSummary     []byte // agreed frozen transition state
	ChangeRecordHash []byte // candidate body hash + committed handoff binding
	PredecessorHash  []byte // canonical body identity of the current trust base
}

func (b TrustBaseBodyV2) canonicalBody() cArray {
	members := append(WeightSet(nil), b.Members...)
	sort.Slice(members, func(i, j int) bool { return members[i].ID < members[j].ID })
	mem := make(cArray, len(members))
	for i, m := range members {
		mem[i] = cArray{cText(m.ID), cUint(m.Weight)}
	}
	return cArray{
		cUint(b.Version),
		cUint(b.NetworkID),
		cUint(b.Epoch),
		cUint(b.EpochStart),
		mem,
		cUint(b.RootThreshold),
		optBytes(b.StateSummary),
		optBytes(b.ChangeRecordHash),
		optBytes(b.PredecessorHash),
	}
}

// Encode returns the canonical deterministic-CBOR body (no signatures, no
// endorsement).
func (b TrustBaseBodyV2) Encode() []byte { return marshalCBOR(b.canonicalBody()) }

// Identity returns SHA-256(CBOR(body)) — stable across any set of valid
// current-epoch signatures and any endorsement witness.
func (b TrustBaseBodyV2) Identity() Hash32 { return sha256.Sum256(b.Encode()) }
