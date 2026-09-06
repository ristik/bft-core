package evmroot

import (
	"bytes"
	"os"
	"testing"
)

func TestD3_ThresholdsOverWeightNotCount(t *testing.T) {
	ws := d3Assignment() // weights 10/6/5/2/1, W=24
	w, ok := ws.TotalWeight()
	if !ok || w != 24 {
		t.Fatalf("TotalWeight = %d, %v; want 24, true", w, ok)
	}
	if RootQuorumThreshold(w) != 17 {
		t.Fatalf("root threshold = %d, want 17", RootQuorumThreshold(w))
	}
	if ShardAttestationThreshold(w) != 13 {
		t.Fatalf("shard threshold = %d, want 13", ShardAttestationThreshold(w))
	}
	// 4 of 5 identities, minority of weight -> no quorum.
	reached, valid := ws.QuorumReached([]string{"root-b", "root-c", "root-d", "root-e"}, 17)
	if !valid || reached {
		t.Fatalf("identity-majority reached root quorum: reached=%v valid=%v", reached, valid)
	}
	// 1 of 5 identities, plurality of weight -> ... still short here (10<17),
	// but 3 heavy signers clear it.
	reached, _ = ws.QuorumReached([]string{"root-a", "root-b", "root-c"}, 17)
	if !reached {
		t.Fatal("21 weight did not reach threshold 17")
	}
}

func TestD3_DuplicateSignerNotDoubleCounted(t *testing.T) {
	ws := d3Assignment()
	if _, ok := ws.SignerWeight([]string{"root-a", "root-a"}); ok {
		t.Fatal("duplicate signer accepted — weight would be double-counted")
	}
	if _, ok := ws.SignerWeight([]string{"root-a", "ghost"}); ok {
		t.Fatal("unknown signer accepted")
	}
}

func TestD3_TimeoutAmplificationOnFaultyWeightBound(t *testing.T) {
	ws := d3Assignment()                                                  // bound = 24 - 17 = 7
	if amp, _ := ws.TimeoutAmplifies([]string{"root-c", "root-d"}); amp { // 7, not > 7
		t.Fatal("amplified at exactly the faulty-weight bound")
	}
	if amp, _ := ws.TimeoutAmplifies([]string{"root-b", "root-d"}); !amp { // 8 > 7
		t.Fatal("did not amplify above the faulty-weight bound")
	}
}

func TestD3_QuorumImpossibility(t *testing.T) {
	if !QuorumImpossible(6, 8, 17) {
		t.Fatal("6+8 < 17 should be impossible")
	}
	if QuorumImpossible(10, 8, 17) {
		t.Fatal("10+8 >= 17 is still possible")
	}
}

func TestD3_OverflowAndValidationBounds(t *testing.T) {
	if _, ok := (WeightSet{d3Member("x", MaxMemberWeight+1)}).TotalWeight(); ok {
		t.Fatal("member weight above MaxMemberWeight accepted")
	}
	dup := WeightSet{d3Member("a", 1), d3Member("a", 1)}
	if dup.Validate() == nil {
		t.Fatal("duplicate node id accepted")
	}
	if _, ok := (WeightSet{d3Member("z", 0)}).TotalWeight(); ok {
		t.Fatal("zero-weight member accepted")
	}
	if _, ok := WeightSet(nil).TotalWeight(); ok {
		t.Fatal("empty assignment returned (0, true) — it has no quorum denominator")
	}
	if FaultyWeightBound(0) != 0 {
		t.Fatalf("FaultyWeightBound(0) = %d, want 0 (no wrap)", FaultyWeightBound(0))
	}
	// Duplicate consensus key across two distinct node ids is rejected.
	shared := WeightSet{d3Member("a", 1), d3Member("b", 1)}
	shared[1].ConsensusKey = shared[0].ConsensusKey
	if shared.Validate() == nil {
		t.Fatal("two node ids sharing a consensus key were accepted")
	}
	// QuorumReached with a zero threshold is invalid.
	if _, valid := d3Assignment().QuorumReached([]string{"root-a"}, 0); valid {
		t.Fatal("QuorumReached accepted a zero threshold")
	}
}

func TestD3_BodyValidationRequiresWeightedThreshold(t *testing.T) {
	rt := RootQuorumThreshold(24)
	good := d3Body(rt)
	if err := good.Validate(); err != nil {
		t.Fatalf("well-formed body rejected: %v", err)
	}
	bad := good
	bad.RootThreshold = rt + 1 // agent-chosen, not the weighted threshold
	if bad.Validate() == nil {
		t.Fatal("a body recording a non-weighted root threshold was accepted")
	}
	badV := good
	badV.Version = 1
	if badV.Validate() == nil {
		t.Fatal("a version-1 body validated as v2")
	}
}

func TestD3_KeyBindingChangesIdentity(t *testing.T) {
	base := d3Body(RootQuorumThreshold(24))
	sub := base
	m := append(WeightSet(nil), base.Members...)
	m[0].ConsensusKey = d3Key("attacker")
	sub.Members = m
	if base.Identity() == sub.Identity() {
		t.Fatal("substituting a consensus key did not change the body identity")
	}
	swap := base
	sm := append(WeightSet(nil), base.Members...)
	sm[0].StakingID, sm[1].StakingID = sm[1].StakingID, sm[0].StakingID
	swap.Members = sm
	if base.Identity() == swap.Identity() {
		t.Fatal("swapping staking identities did not change the body identity")
	}
}

func TestD3_ActiveEpochFromActivationRecordNotBodyEpochStart(t *testing.T) {
	rt := RootQuorumThreshold(24)
	current := d3Body(rt)
	current.Epoch = 7
	activated := d3Body(rt)
	activated.Epoch = 8
	activated.EarliestActivation = 100_000 // A_min lower bound only
	id := activated.Identity()
	rec := ActivatedTrustBase{BodyIdentity: id[:], EpochStart: 100_050, ActivationCommitID: rep(0xC0, 32)}

	// Before A* (100_050): epoch 7. At/after: epoch 8. A_min (100_000) is
	// NOT the boundary — a consumer that used it would switch 50 rounds early.
	if e, ok := DerivedActiveEpoch(current, activated, rec, 100_049); !ok || e != 7 {
		t.Fatalf("before A*: epoch %d ok %v, want 7", e, ok)
	}
	if e, ok := DerivedActiveEpoch(current, activated, rec, 100_050); !ok || e != 8 {
		t.Fatalf("at A*: epoch %d ok %v, want 8", e, ok)
	}
	// A record naming a different body, or with EpochStart below A_min, is rejected.
	if _, ok := DerivedActiveEpoch(current, activated, ActivatedTrustBase{BodyIdentity: rep(0x11, 32), EpochStart: 100_050}, 200_000); ok {
		t.Fatal("accepted an activation record for a different body")
	}
	if _, ok := DerivedActiveEpoch(current, activated, ActivatedTrustBase{BodyIdentity: id[:], EpochStart: 99_999}, 200_000); ok {
		t.Fatal("accepted an activation record with EpochStart below EarliestActivation")
	}
}

func TestD3_FirstV2PredecessorIsTaggedTransition(t *testing.T) {
	v1 := sha256Bytes([]byte("v1-anchor-hash"))
	pred, err := FirstV2PredecessorHash(V1Anchor{Version: 1, NetworkID: 3, Epoch: 6, HashIncludingSigs: v1})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(pred, v1) {
		t.Fatal("first v2 predecessor is the raw v1 hash — legacy bytes reinterpreted")
	}
	if len(pred) != 32 {
		t.Fatalf("predecessor length %d", len(pred))
	}
	if _, err := FirstV2PredecessorHash(V1Anchor{Version: 2, HashIncludingSigs: v1}); err == nil {
		t.Fatal("accepted a non-v1 anchor")
	}
}

func TestD3_TrustBaseIdentityIgnoresSignaturesAndEndorsement(t *testing.T) {
	// The type has no signature or endorsement field, so identity is a
	// function of the body alone. Rebuilding with identical fields gives an
	// identical identity; changing one member weight changes it.
	base := d3Body(RootQuorumThreshold(24))
	same := base
	if base.Identity() != same.Identity() {
		t.Fatal("identity not stable across rebuild")
	}
	mut := base
	mm := append(WeightSet(nil), base.Members...)
	mm[0].Weight++
	mut.Members = mm
	if base.Identity() == mut.Identity() {
		t.Fatal("changing a member weight did not change the identity")
	}
	// Member order must not matter.
	rev := base
	rm := append(WeightSet(nil), base.Members...)
	for i, j := 0, len(rm)-1; i < j; i, j = i+1, j-1 {
		rm[i], rm[j] = rm[j], rm[i]
	}
	rev.Members = rm
	if base.Identity() != rev.Identity() {
		t.Fatal("identity depends on member order")
	}
}

func TestD3_VectorsMatchGolden(t *testing.T) {
	const path = "testdata/d3-vectors.json"
	got, err := MarshalD3Vectors(BuildD3Vectors())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (run: go run ./evmroot/cmd/d3vectors -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale — regenerate with: go run ./evmroot/cmd/d3vectors -update", path)
	}
}
