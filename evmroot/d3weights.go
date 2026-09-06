package evmroot

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math/bits"
	"sort"
)

// D3 weighted-consensus model. Reference for versioned weighted quorum,
// timeout and impossibility arithmetic and for the versioned trust-base
// body identity that binds the complete member records and excludes
// endorsement witnesses.
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

	// ConsensusKeyLen is the fixed width of a compressed secp256k1 public
	// key — the consensus signing key bound in each member record.
	ConsensusKeyLen = 33
)

// Member is the complete candidate/trust-base member record
// (appendix-evm.tex §"Candidate Record"): staking identity, node identity,
// consensus public key and effective weight. All four are bound into the
// canonical body identity, so a key or role substitution changes the hash,
// and two records sharing a consensus key are rejected.
type Member struct {
	StakingID    string // on-chain staking account identity
	NodeID       string // consensus node identity — the canonical sort key
	ConsensusKey []byte // compressed secp256k1 public key (ConsensusKeyLen bytes)
	Weight       uint64 // effective bonded voting weight in units of u
}

// WeightSet is the active assignment: the members whose weights form the
// quorum denominator W.
type WeightSet []Member

// errEmptyAssignment etc. surface validation failures with a stable reason.
var (
	errEmptyAssignment = errors.New("evmroot: empty validator assignment")
)

// Validate checks structural well-formedness: non-empty; unique NodeID,
// StakingID and ConsensusKey; fixed-width keys; every weight in
// [1, MaxMemberWeight]; total in [1, MaxTotalWeight] with no overflow.
func (ws WeightSet) Validate() error {
	if len(ws) == 0 {
		return errEmptyAssignment
	}
	nodeIDs := make(map[string]struct{}, len(ws))
	stakingIDs := make(map[string]struct{}, len(ws))
	keys := make(map[string]struct{}, len(ws))
	var total, carry uint64
	for i, m := range ws {
		if m.NodeID == "" || m.StakingID == "" {
			return fmt.Errorf("evmroot: member %d has an empty NodeID or StakingID", i)
		}
		if len(m.ConsensusKey) != ConsensusKeyLen {
			return fmt.Errorf("evmroot: member %q consensus key must be %d bytes, got %d", m.NodeID, ConsensusKeyLen, len(m.ConsensusKey))
		}
		if _, dup := nodeIDs[m.NodeID]; dup {
			return fmt.Errorf("evmroot: duplicate NodeID %q", m.NodeID)
		}
		if _, dup := stakingIDs[m.StakingID]; dup {
			return fmt.Errorf("evmroot: duplicate StakingID %q", m.StakingID)
		}
		if _, dup := keys[string(m.ConsensusKey)]; dup {
			return fmt.Errorf("evmroot: consensus key of %q is shared with another member", m.NodeID)
		}
		nodeIDs[m.NodeID] = struct{}{}
		stakingIDs[m.StakingID] = struct{}{}
		keys[string(m.ConsensusKey)] = struct{}{}
		if m.Weight == 0 || m.Weight > MaxMemberWeight {
			return fmt.Errorf("evmroot: member %q weight %d out of [1, %d]", m.NodeID, m.Weight, MaxMemberWeight)
		}
		var c uint64
		total, c = bits.Add64(total, m.Weight, 0)
		carry |= c
	}
	if carry != 0 || total > MaxTotalWeight {
		return fmt.Errorf("evmroot: total weight overflows MaxTotalWeight")
	}
	return nil
}

// NewWeightSet returns a validated assignment or an error.
func NewWeightSet(members ...Member) (WeightSet, error) {
	ws := WeightSet(members)
	if err := ws.Validate(); err != nil {
		return nil, err
	}
	return ws, nil
}

// TotalWeight returns W = Σ bᵥ. ok is false for an assignment that fails
// Validate (including the empty set — an empty assignment has no quorum
// denominator, so this never returns (0, true)).
func (ws WeightSet) TotalWeight() (w uint64, ok bool) {
	if ws.Validate() != nil {
		return 0, false
	}
	for _, m := range ws {
		w += m.Weight // Validate has already ruled out overflow
	}
	return w, true
}

func (ws WeightSet) weightOf(nodeID string) (uint64, bool) {
	for _, m := range ws {
		if m.NodeID == nodeID {
			return m.Weight, true
		}
	}
	return 0, false
}

// RootQuorumThreshold is ⌊2W/3⌋ + 1 — the BFT Core consensus threshold
// (evm-partition.tex §"Validity"). Callers pass a W from TotalWeight, so
// W ≥ 1 and 2*W cannot overflow.
func RootQuorumThreshold(w uint64) uint64 { return (2*w)/3 + 1 }

// ShardAttestationThreshold is ⌊W/2⌋ + 1 — the EVM attestation threshold.
// The EVM uses exactly the same effective weights as the root assignment
// that authorised its shard round; no assumed seat bound substitutes.
func ShardAttestationThreshold(w uint64) uint64 { return w/2 + 1 }

// FaultyWeightBound is the largest voting power that may be Byzantine while
// a root quorum is still safe: W − RootQuorumThreshold(W). It is 0 for
// W == 0 rather than wrapping. Timeout amplification triggers when the
// timeout-voting weight strictly exceeds this bound.
func FaultyWeightBound(w uint64) uint64 {
	t := RootQuorumThreshold(w)
	if t > w {
		return 0
	}
	return w - t
}

// SignerWeight sums the unique, authorised signers' weights with a checked
// wide intermediate. signers are NodeIDs. ok is false on a malformed
// assignment, an unknown signer, a duplicate signer, or overflow.
func (ws WeightSet) SignerWeight(signers []string) (weight uint64, ok bool) {
	if ws.Validate() != nil {
		return 0, false
	}
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
// threshold. Returns (false,false) when the assignment or signer set is
// malformed, or threshold is 0 (a real threshold is always ≥ 1).
func (ws WeightSet) QuorumReached(signers []string, threshold uint64) (reached, valid bool) {
	if threshold == 0 {
		return false, false
	}
	w, ok := ws.SignerWeight(signers)
	if !ok {
		return false, false
	}
	return w >= threshold, true
}

// TimeoutAmplifies reports whether the timeout-voting weight is enough to
// jump straight to the round-timeout state. True iff signerWeight >
// FaultyWeightBound(W).
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
// still below the threshold. This is the weighted replacement for the
// count-based "not enough votes to prove no quorum" path
// (rootchain/consensus/types/ir_change_request.go:138).
func QuorumImpossible(currentWeight, remainingWeight, threshold uint64) bool {
	sum, c := bits.Add64(currentWeight, remainingWeight, 0)
	if c != 0 {
		return false // cannot conclude impossibility on overflow
	}
	return sum < threshold
}

// --- versioned trust-base body identity -----------------------------------

// TrustBaseVersion is the trust-base body version this model implements.
const TrustBaseVersion = 2

// V1ToV2TransitionDomain opens the tagged preimage that derives the first
// v2 body's predecessor hash from the actual v1 anchor — so no legacy bytes
// are reinterpreted as a v2 body.
const V1ToV2TransitionDomain = "UNICITY_TRUSTBASE_V1_TO_V2"

// V1Anchor is the current (legacy) trust base at the moment of the first v2
// handoff. Its hash is the RootTrustBaseV1.Hash() value — which, by v1
// rules, folds in the signature map. It is never re-encoded as a v2 body.
type V1Anchor struct {
	Version           uint64 // == 1
	NetworkID         uint64
	Epoch             uint64
	HashIncludingSigs []byte // RootTrustBaseV1.Hash(SHA256)
}

// FirstV2PredecessorHash derives the predecessor hash the first v2 body
// carries: SHA-256(CBOR([ "UNICITY_TRUSTBASE_V1_TO_V2", network, epoch,
// v1HashIncludingSigs ])). This binds the first v2 body to the exact v1
// anchor through an explicit versioned transition, without the v2 encoder
// ever touching legacy bytes.
func FirstV2PredecessorHash(a V1Anchor) ([]byte, error) {
	if a.Version != 1 || len(a.HashIncludingSigs) != 32 {
		return nil, fmt.Errorf("evmroot: v1 anchor must be version 1 with a 32-byte hash")
	}
	enc := marshalCBOR(cArray{
		cText(V1ToV2TransitionDomain),
		cUint(a.NetworkID),
		cUint(a.Epoch),
		cBytes(a.HashIncludingSigs),
	})
	h := sha256.Sum256(enc)
	return h[:], nil
}

// TrustBaseBodyV2 is the canonical, witness-free identity of a trust-base
// entry in the new version. It binds the COMPLETE member records (staking
// identity, node identity, consensus key, weight) and the recorded root
// threshold, and excludes BOTH the current-epoch signatures AND the
// old-epoch endorsement witness. PredecessorHash is the v2 body identity of
// the current trust base (or, for the first v2 body, FirstV2PredecessorHash).
type TrustBaseBodyV2 struct {
	Version          uint64
	NetworkID        uint64
	Epoch            uint64
	EpochStart       uint64 // the actual boundary fixed by the committed handoff (D4)
	Members          WeightSet
	RootThreshold    uint64 // must equal RootQuorumThreshold(ΣWeight)
	StateSummary     []byte
	ChangeRecordHash []byte
	PredecessorHash  []byte
}

// Validate checks version, member well-formedness and that RootThreshold is
// exactly the weighted threshold of the members (not an agent-chosen
// value).
func (b TrustBaseBodyV2) Validate() error {
	if b.Version != TrustBaseVersion {
		return fmt.Errorf("evmroot: trust-base body version %d != %d", b.Version, TrustBaseVersion)
	}
	if err := b.Members.Validate(); err != nil {
		return err
	}
	w, _ := b.Members.TotalWeight()
	if want := RootQuorumThreshold(w); b.RootThreshold != want {
		return fmt.Errorf("evmroot: recorded root threshold %d != weighted threshold %d", b.RootThreshold, want)
	}
	if len(b.PredecessorHash) != 32 {
		return fmt.Errorf("evmroot: predecessor hash must be 32 bytes")
	}
	return nil
}

func (b TrustBaseBodyV2) canonicalBody() cArray {
	members := append(WeightSet(nil), b.Members...)
	sort.Slice(members, func(i, j int) bool { return members[i].NodeID < members[j].NodeID })
	mem := make(cArray, len(members))
	for i, m := range members {
		mem[i] = cArray{cText(m.StakingID), cText(m.NodeID), cBytes(m.ConsensusKey), cUint(m.Weight)}
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
// current-epoch signatures and any endorsement witness, and sensitive to
// every bound member field.
func (b TrustBaseBodyV2) Identity() Hash32 { return sha256.Sum256(b.Encode()) }
