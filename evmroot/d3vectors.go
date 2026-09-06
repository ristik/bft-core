package evmroot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func sha256Bytes(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// D3 vector set: weighted quorum / timeout / impossibility arithmetic and
// versioned trust-base body identity, made checkable independently of the
// consensus code. Same builder feeds the golden test and cmd/d3vectors.

type D3VectorSet struct {
	Assignment       D3Assignment      `json:"assignment"`
	RootQuorum       []D3ThresholdCase `json:"root_quorum"`
	ShardQuorum      []D3ThresholdCase `json:"shard_quorum"`
	TimeoutAmpl      []D3TimeoutCase   `json:"timeout_amplification"`
	Impossibility    []D3ImpossCase    `json:"quorum_impossibility"`
	DuplicateSigners D3DuplicateCase   `json:"duplicate_signers"`
	MinorityStake    D3MinorityCase    `json:"minority_stake_majority_identities"`
	Overflow         []D3OverflowCase  `json:"overflow_bounds"`
	BodyValidation   []D3BodyValidCase `json:"body_validation"`
	TrustBaseID      D3TrustBaseIDCase `json:"trust_base_identity"`
	KeyBinding       D3KeyBindingCase  `json:"key_binding"`
	V1ToV2           D3V1ToV2Case      `json:"v1_to_v2_transition"`
}

type D3BodyValidCase struct {
	Name     string `json:"name"`
	Accepted bool   `json:"accepted"` // TrustBaseBodyV2.Validate() == nil
	Reason   string `json:"reason,omitempty"`
}

type D3KeyBindingCase struct {
	Note                    string `json:"note"`
	BaselineIdentity        string `json:"baseline_identity"`
	KeySubstitutionIdentity string `json:"consensus_key_substituted_identity"`
	KeySubstitutionDiffers  bool   `json:"consensus_key_substitution_changes_identity"`
	RoleSwapIdentity        string `json:"staking_id_swapped_identity"`
	RoleSwapDiffers         bool   `json:"staking_id_swap_changes_identity"`
	DuplicateKeyRejected    bool   `json:"duplicate_consensus_key_across_ids_rejected"`
}

type D3V1ToV2Case struct {
	Note               string `json:"note"`
	V1AnchorHash       string `json:"v1_anchor_hash_including_sigs"`
	FirstV2Predecessor string `json:"first_v2_predecessor_hash"`
	IsTagged           bool   `json:"predecessor_is_a_tagged_transition_not_raw_v1_bytes"`
}

type D3Assignment struct {
	Members           []Member `json:"members"`
	TotalWeight       uint64   `json:"total_weight"`
	MemberCount       int      `json:"member_count"`
	RootThreshold     uint64   `json:"root_threshold"`      // floor(2W/3)+1
	ShardThreshold    uint64   `json:"shard_threshold"`     // floor(W/2)+1
	FaultyWeightBound uint64   `json:"faulty_weight_bound"` // W - root_threshold
}

type D3ThresholdCase struct {
	Signers      []string `json:"signers"`
	SignerCount  int      `json:"signer_count"`
	SignerWeight uint64   `json:"signer_weight"`
	Threshold    uint64   `json:"threshold"`
	Reached      bool     `json:"reached"`
	Note         string   `json:"note,omitempty"`
}

type D3TimeoutCase struct {
	Signers      []string `json:"signers"`
	SignerWeight uint64   `json:"signer_weight"`
	Bound        uint64   `json:"faulty_weight_bound"`
	Amplifies    bool     `json:"amplifies"`
	Note         string   `json:"note"`
}

type D3ImpossCase struct {
	CurrentWeight   uint64 `json:"current_weight"`
	RemainingWeight uint64 `json:"remaining_weight"`
	Threshold       uint64 `json:"threshold"`
	Impossible      bool   `json:"impossible"`
	Note            string `json:"note"`
}

type D3DuplicateCase struct {
	Signers []string `json:"signers"`
	Valid   bool     `json:"valid"`
	Note    string   `json:"note"`
}

type D3MinorityCase struct {
	Note                  string   `json:"note"`
	IdentityMajority      []string `json:"identity_majority_signers"` // > half the members
	MajorityCount         int      `json:"identity_majority_count"`
	TotalMembers          int      `json:"total_members"`
	MajorityWeight        uint64   `json:"identity_majority_weight"`
	RootThreshold         uint64   `json:"root_threshold"`
	MajorityReachesQuorum bool     `json:"identity_majority_reaches_quorum"`
	SingleWhaleSigner     string   `json:"single_whale_signer"`
	WhaleWeight           uint64   `json:"whale_weight"`
	WhaleReachesQuorum    bool     `json:"whale_reaches_quorum"`
}

type D3OverflowCase struct {
	Name string `json:"name"`
	OK   bool   `json:"ok"` // TotalWeight ok
	Note string `json:"note"`
}

type D3TrustBaseIDCase struct {
	Note               string `json:"note"`
	BodyCBOR           string `json:"body_cbor"`
	Identity           string `json:"identity"`
	SameFieldsIdentity string `json:"same_fields_identity"` // rebuilt body, same fields -> equal
	IdentitiesEqual    bool   `json:"identities_equal"`
	MutatedIdentity    string `json:"mutated_identity"` // one member weight changed
	MutatedDiffers     bool   `json:"mutated_differs"`
}

// d3Key returns a deterministic, distinct 33-byte compressed-key stand-in
// for a node id.
func d3Key(nodeID string) []byte {
	h := sha256Bytes([]byte("d3key:" + nodeID))
	return append([]byte{0x02}, h...)
}

func d3Member(nodeID string, weight uint64) Member {
	return Member{StakingID: "stake-" + nodeID, NodeID: nodeID, ConsensusKey: d3Key(nodeID), Weight: weight}
}

// d3Assignment is the baseline unequal-weight assignment used across the
// D3 vectors: 5 members, weights 10/6/5/2/1, W = 24.
func d3Assignment() WeightSet {
	return WeightSet{
		d3Member("root-a", 10),
		d3Member("root-b", 6),
		d3Member("root-c", 5),
		d3Member("root-d", 2),
		d3Member("root-e", 1),
	}
}

func BuildD3Vectors() D3VectorSet {
	ws := d3Assignment()
	w, _ := ws.TotalWeight()
	rt := RootQuorumThreshold(w)
	st := ShardAttestationThreshold(w)
	fb := FaultyWeightBound(w)

	var vs D3VectorSet
	vs.Assignment = D3Assignment{
		Members: ws, TotalWeight: w, MemberCount: len(ws),
		RootThreshold: rt, ShardThreshold: st, FaultyWeightBound: fb,
	}

	mkThreshold := func(signers []string, threshold uint64, note string) D3ThresholdCase {
		sw, _ := ws.SignerWeight(signers)
		reached, _ := ws.QuorumReached(signers, threshold)
		return D3ThresholdCase{
			Signers: signers, SignerCount: len(signers), SignerWeight: sw,
			Threshold: threshold, Reached: reached, Note: note,
		}
	}
	// Root quorum: floor(2*24/3)+1 = 17.
	vs.RootQuorum = []D3ThresholdCase{
		mkThreshold([]string{"root-a", "root-b", "root-c"}, rt, "10+6+5 = 21 >= 17: quorum"),
		mkThreshold([]string{"root-a", "root-b"}, rt, "10+6 = 16 < 17: no quorum, though a numeric majority of a 3-of-5 subset"),
		mkThreshold([]string{"root-b", "root-c", "root-d", "root-e"}, rt, "6+5+2+1 = 14 < 17: four of five signers, still short"),
		mkThreshold([]string{"root-a", "root-c", "root-d"}, rt, "10+5+2 = 17 == 17: exactly the threshold"),
	}
	// Shard attestation: floor(24/2)+1 = 13.
	vs.ShardQuorum = []D3ThresholdCase{
		mkThreshold([]string{"root-a", "root-d"}, st, "10+2 = 12 < 13: no attestation quorum"),
		mkThreshold([]string{"root-a", "root-c"}, st, "10+5 = 15 >= 13: attestation quorum"),
		mkThreshold([]string{"root-b", "root-c", "root-e"}, st, "6+5+1 = 12 < 13"),
	}

	// Timeout amplification: bound = 24 - 17 = 7.
	mkTO := func(signers []string, note string) D3TimeoutCase {
		sw, _ := ws.SignerWeight(signers)
		amp, _ := ws.TimeoutAmplifies(signers)
		return D3TimeoutCase{Signers: signers, SignerWeight: sw, Bound: fb, Amplifies: amp, Note: note}
	}
	vs.TimeoutAmpl = []D3TimeoutCase{
		mkTO([]string{"root-d", "root-e"}, "2+1 = 3 <= 7: no amplification"),
		mkTO([]string{"root-b", "root-d"}, "6+2 = 8 > 7: at least one honest weight is timing out -> jump to timeout"),
		mkTO([]string{"root-c", "root-d"}, "5+2 = 7 == bound: not strictly greater -> no amplification"),
	}

	// Quorum impossibility against the root threshold 17.
	vs.Impossibility = []D3ImpossCase{
		{CurrentWeight: 6, RemainingWeight: 8, Threshold: rt, Impossible: QuorumImpossible(6, 8, rt),
			Note: "6 committed + 8 still unvoted = 14 < 17: this value can never reach quorum"},
		{CurrentWeight: 10, RemainingWeight: 8, Threshold: rt, Impossible: QuorumImpossible(10, 8, rt),
			Note: "10 + 8 = 18 >= 17: still possible"},
	}

	// Duplicate signers are rejected, not double-counted.
	dupSigners := []string{"root-a", "root-a", "root-b"}
	_, dupOK := ws.SignerWeight(dupSigners)
	vs.DuplicateSigners = D3DuplicateCase{
		Signers: dupSigners, Valid: dupOK,
		Note: "root-a listed twice: SignerWeight rejects the set rather than counting weight 10 twice",
	}

	// Minority stake, majority identities: root-b..root-e are 4 of 5
	// members but hold 6+5+2+1 = 14 < 17; root-a alone holds 10 but that
	// is also < 17 — the point is that identity count and voting power
	// diverge, and only weight decides.
	idMajority := []string{"root-b", "root-c", "root-d", "root-e"}
	majW, _ := ws.SignerWeight(idMajority)
	majReached, _ := ws.QuorumReached(idMajority, rt)
	whaleW, _ := ws.SignerWeight([]string{"root-a"})
	whaleReached, _ := ws.QuorumReached([]string{"root-a"}, rt)
	vs.MinorityStake = D3MinorityCase{
		Note:             "A numeric majority of signer identities carries a minority of voting power; quorum tracks weight, not headcount.",
		IdentityMajority: idMajority, MajorityCount: len(idMajority), TotalMembers: len(ws),
		MajorityWeight: majW, RootThreshold: rt, MajorityReachesQuorum: majReached,
		SingleWhaleSigner: "root-a", WhaleWeight: whaleW, WhaleReachesQuorum: whaleReached,
	}

	// Overflow / validation bounds.
	overCap := WeightSet{d3Member("x", MaxMemberWeight+1)}
	_, overCapOK := overCap.TotalWeight()
	huge := make(WeightSet, 300)
	for i := range huge {
		huge[i] = d3Member(fmt.Sprintf("n%03d", i), MaxMemberWeight)
	}
	_, hugeOK := huge.TotalWeight()
	_, okSetOK := d3Assignment().TotalWeight()
	_, emptyOK := WeightSet(nil).TotalWeight()
	vs.Overflow = []D3OverflowCase{
		{Name: "within_bounds", OK: okSetOK, Note: "baseline assignment sums cleanly"},
		{Name: "empty_assignment", OK: emptyOK, Note: "an empty assignment has no quorum denominator — TotalWeight returns (0, false), never (0, true)"},
		{Name: "member_over_cap", OK: overCapOK, Note: "a single member weight above MaxMemberWeight is rejected"},
		{Name: "total_over_cap", OK: hugeOK, Note: "300 near-cap members exceed MaxTotalWeight; rejected before 2W can overflow"},
	}

	// Body validation: version, complete members, recorded threshold.
	goodBody := d3Body(rt)
	badVersion := goodBody
	badVersion.Version = 1
	badThreshold := goodBody
	badThreshold.RootThreshold = rt + 3
	emptyBody := goodBody
	emptyBody.Members = nil
	shortKey := goodBody
	sk := append(WeightSet(nil), goodBody.Members...)
	sk[0].ConsensusKey = sk[0].ConsensusKey[:16]
	shortKey.Members = sk
	for _, bv := range []struct {
		name string
		body TrustBaseBodyV2
	}{
		{"well_formed", goodBody},
		{"wrong_version", badVersion},
		{"recorded_threshold_not_weighted_threshold", badThreshold},
		{"empty_members", emptyBody},
		{"short_consensus_key", shortKey},
	} {
		err := bv.body.Validate()
		reason := ""
		if err != nil {
			reason = err.Error()
		}
		vs.BodyValidation = append(vs.BodyValidation, D3BodyValidCase{Name: bv.name, Accepted: err == nil, Reason: reason})
	}

	// Trust-base body identity: witness-free, endorsement-free, and
	// sensitive to every bound member field.
	body := goodBody
	same := body // same fields, rebuilt
	mutated := body
	mm := append(WeightSet(nil), body.Members...)
	mm[0].Weight++
	mutated.Members = mm
	mutated.RootThreshold = RootQuorumThreshold(func() uint64 { w, _ := mutated.Members.TotalWeight(); return w }())
	vs.TrustBaseID = D3TrustBaseIDCase{
		Note: "Identity is SHA-256(CBOR(body)) over the complete member records (staking id, node id, consensus key, weight; sorted by node id) " +
			"plus thresholds/summary/change/predecessor hashes. It has no field for current-epoch signatures or the old-epoch endorsement witness.",
		BodyCBOR: hex.EncodeToString(body.Encode()), Identity: hex.EncodeToString(idBytes(body)),
		SameFieldsIdentity: hex.EncodeToString(idBytes(same)),
		IdentitiesEqual:    body.Identity() == same.Identity(),
		MutatedIdentity:    hex.EncodeToString(idBytes(mutated)),
		MutatedDiffers:     body.Identity() != mutated.Identity(),
	}

	// Key binding: a consensus-key substitution and a staking-id swap each
	// change the identity; two members sharing a consensus key are rejected.
	keySub := body
	ks := append(WeightSet(nil), body.Members...)
	ks[0].ConsensusKey = d3Key("attacker")
	keySub.Members = ks
	roleSwap := body
	rsw := append(WeightSet(nil), body.Members...)
	rsw[0].StakingID, rsw[1].StakingID = rsw[1].StakingID, rsw[0].StakingID
	roleSwap.Members = rsw
	dupKey := append(WeightSet(nil), d3Assignment()...)
	dupKey[1].ConsensusKey = dupKey[0].ConsensusKey // two node ids, one key
	vs.KeyBinding = D3KeyBindingCase{
		Note:                    "The v2 body binds the complete member record; a key or role substitution changes the identity, and a shared consensus key across node ids is rejected by Validate.",
		BaselineIdentity:        hex.EncodeToString(idBytes(body)),
		KeySubstitutionIdentity: hex.EncodeToString(idBytes(keySub)),
		KeySubstitutionDiffers:  body.Identity() != keySub.Identity(),
		RoleSwapIdentity:        hex.EncodeToString(idBytes(roleSwap)),
		RoleSwapDiffers:         body.Identity() != roleSwap.Identity(),
		DuplicateKeyRejected:    dupKey.Validate() != nil,
	}

	// v1 -> v2 first predecessor: a tagged transition, never raw v1 bytes.
	v1Hash := sha256Bytes([]byte("legacy-v1-trust-base-including-signatures"))
	pred, _ := FirstV2PredecessorHash(V1Anchor{Version: 1, NetworkID: 3, Epoch: 6, HashIncludingSigs: v1Hash})
	vs.V1ToV2 = D3V1ToV2Case{
		Note:               "The first v2 body's predecessor is SHA-256(CBOR([\"UNICITY_TRUSTBASE_V1_TO_V2\", network, epoch, v1Hash])). The v1 anchor hash (which by v1 rules folds in signatures) is bound through this explicit transition; the v2 encoder never re-encodes legacy bytes.",
		V1AnchorHash:       hex.EncodeToString(v1Hash),
		FirstV2Predecessor: hex.EncodeToString(pred),
		IsTagged:           hex.EncodeToString(pred) != hex.EncodeToString(v1Hash),
	}

	return vs
}

// d3Body is the baseline well-formed v2 body.
func d3Body(rootThreshold uint64) TrustBaseBodyV2 {
	return TrustBaseBodyV2{
		Version: TrustBaseVersion, NetworkID: 3, Epoch: 7, EarliestActivation: 100_000,
		Members: d3Assignment(), RootThreshold: rootThreshold,
		StateSummary: rep(0x5A, 32), ChangeRecordHash: rep(0xC3, 32), PredecessorHash: rep(0xD0, 32),
	}
}

func idBytes(b TrustBaseBodyV2) []byte {
	h := b.Identity()
	return h[:]
}

func MarshalD3Vectors(vs D3VectorSet) ([]byte, error) {
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
