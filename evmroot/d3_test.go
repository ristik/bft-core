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

func TestD3_OverflowBounds(t *testing.T) {
	if _, ok := (WeightSet{{ID: "x", Weight: MaxMemberWeight + 1}}).TotalWeight(); ok {
		t.Fatal("member weight above MaxMemberWeight accepted")
	}
	if _, ok := (WeightSet{{ID: "a", Weight: 1}, {ID: "a", Weight: 1}}).TotalWeight(); ok {
		t.Fatal("duplicate member id accepted")
	}
	if _, ok := (WeightSet{{ID: "z", Weight: 0}}).TotalWeight(); ok {
		t.Fatal("zero-weight member accepted")
	}
}

func TestD3_TrustBaseIdentityIgnoresSignaturesAndEndorsement(t *testing.T) {
	// The type has no signature or endorsement field, so identity is a
	// function of the body alone. Rebuilding with identical fields gives an
	// identical identity; changing one member weight changes it.
	base := TrustBaseBodyV2{
		Version: 2, NetworkID: 3, Epoch: 7, EpochStart: 100_000,
		Members: d3Assignment(), RootThreshold: 17,
		StateSummary: rep(0x5A, 32), ChangeRecordHash: rep(0xC3, 32), PredecessorHash: rep(0xD0, 32),
	}
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
