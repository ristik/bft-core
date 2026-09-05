package evmroot

import (
	"bytes"
	"os"
	"testing"
)

func TestD6_NoGlobalSupplyClaim(t *testing.T) {
	if GlobalSupplyObservable {
		t.Fatal("the model claims a globally observable Execution-layer supply")
	}
}

func TestD6_CheckpointFreshnessSeparateFromWCertAndKeyCache(t *testing.T) {
	// Freshness limit is Δ_hold rounds × min round period, in seconds — a
	// different quantity from W_cert (rounds) and from any key count.
	if got := CheckpointFreshnessLimitSeconds(200, 6); got != 1200 {
		t.Fatalf("freshness limit = %d, want 1200", got)
	}
	if !NestingValid(50, 100, 200) {
		t.Fatal("W_cert <= Δ_ev < Δ_hold rejected")
	}
	if NestingValid(120, 100, 200) {
		t.Fatal("W_cert > Δ_ev accepted")
	}
	if NestingValid(50, 200, 200) {
		t.Fatal("Δ_ev == Δ_hold accepted (must be strictly less)")
	}
}

func TestD6_KeyRetentionOutlivesAdmissionCache(t *testing.T) {
	if !KeyRetentionRequired(true, false) {
		t.Fatal("key not retained for an outstanding evidence obligation")
	}
	if !KeyRetentionRequired(false, true) {
		t.Fatal("key not retained for an outstanding retirement obligation")
	}
	if KeyRetentionRequired(false, false) {
		t.Fatal("key retained with no obligation")
	}
}

func TestD6_OldBlockAuthenticatedWithoutRetiredSignatures(t *testing.T) {
	near := AuthenticateOldBlock(AuthPath{Mode: AuthCheckpointAncestry, FromHeadNumber: 900_000, ToBlockNumber: 899_000, HeaderChainOK: true})
	deep := AuthenticateOldBlock(AuthPath{Mode: AuthCheckpointAncestry, FromHeadNumber: 900_000, ToBlockNumber: 400_000, HeaderChainOK: true})
	if !near.Authenticated || !deep.Authenticated {
		t.Fatal("valid header-chain authentication failed")
	}
	if near.ConstantSize || deep.ConstantSize {
		t.Fatal("header-chain path claimed to be constant-size")
	}
	if deep.HeaderCount <= near.HeaderCount {
		t.Fatal("header count did not grow with distance")
	}
	bad := AuthenticateOldBlock(AuthPath{Mode: AuthCheckpointAncestry, FromHeadNumber: 900_000, ToBlockNumber: 899_000, HeaderChainOK: false})
	if bad.Authenticated {
		t.Fatal("broken header chain authenticated")
	}
}

func TestD6_MultiShardAnchorOneSealManyPaths(t *testing.T) {
	anchor := AnchorBundle{
		SealSignaturesVerified: true, RootStateRoot: rep(1, 32),
		ShardPaths: []ShardPath{
			{PartitionID: 7, ShardID: "0", PathToRootOK: true},
			{PartitionID: 7, ShardID: "1", PathToRootOK: true},
		},
	}
	leaves := []AnchoredLeaf{
		{PartitionID: 7, ShardID: "0", LeafOK: true},
		{PartitionID: 7, ShardID: "1", LeafOK: true},
	}
	r := VerifyAnchoredHistory(anchor, leaves)
	if !r.Verified || !r.SealVerifiedOnce || r.ShardPathCount != 2 {
		t.Fatalf("multi-shard anchor verification: %+v", r)
	}
	// A leaf on a third shard with no path fails.
	leaves = append(leaves, AnchoredLeaf{PartitionID: 7, ShardID: "2", LeafOK: true})
	if VerifyAnchoredHistory(anchor, leaves).Verified {
		t.Fatal("verified a leaf with no anchor path")
	}
	// Seal not verified -> fail before any path work.
	anchor.SealSignaturesVerified = false
	if VerifyAnchoredHistory(anchor, leaves[:2]).Verified {
		t.Fatal("verified with an unverified shared seal")
	}
}

func TestD6_LockRefreshLeavesIdentityUnchanged(t *testing.T) {
	idUnchanged, refreshed := RefreshLockWitness(rep(0x7C, 32), rep(0x1C, 32), rep(1, 32), rep(2, 32))
	if !idUnchanged {
		t.Fatal("refreshing the lock witness changed token identity")
	}
	if !refreshed {
		t.Fatal("a different root history was not recognised as a refreshed backing")
	}
}

func TestD6_SupplyAndBackingNotDoubleCounted(t *testing.T) {
	if (SupplyLedger{S0: 1000, Burn: 40}).NativeSupply() != 960 {
		t.Fatal("native supply != S0 - Burn")
	}
	ok := VaultBacking{VaultNativeBalance: 50_000, WUCTSupply: 8_000, BridgedOutstanding: 40_000}
	if !ok.Consistent() {
		t.Fatal("consistent backing rejected")
	}
	bad := VaultBacking{VaultNativeBalance: 30_000, WUCTSupply: 8_000, BridgedOutstanding: 40_000}
	if bad.Consistent() {
		t.Fatal("bridged outstanding exceeding vault native accepted")
	}
}

func TestD6_CustodyWalkthroughInvariants(t *testing.T) {
	steps := WalkCustody(BridgeLedger{L: 100_000, D: 60_000, P: 55_000}, 10_000)
	if len(steps) != 4 {
		t.Fatalf("got %d custody steps, want 4", len(steps))
	}
	for _, s := range steps {
		if !s.InvariantsOK {
			t.Fatalf("invariant broken at %s: %+v", s.State, s.Ledger)
		}
	}
	final := steps[len(steps)-1]
	if final.State != "paid" || final.Ledger.L != 110_000 || final.Ledger.D != 70_000 || final.Ledger.P != 65_000 {
		t.Fatalf("final ledger wrong: %+v", final)
	}
	// Outstanding backing O = L - D held non-negative throughout.
	if steps[1].Outstanding != 50_000 { // after burn, before credit: L=110k D=60k
		t.Fatalf("post-burn outstanding = %d, want 50000", steps[1].Outstanding)
	}
}

func TestD6_TokenProfileForbidsSplitMergeMintExt(t *testing.T) {
	p := InitialEnshrinedProfile()
	if !p.Permits("transfer") || !p.Permits("burn") {
		t.Fatal("whole transfer/burn not permitted")
	}
	for _, op := range []string{"split", "merge", "mint_reason_extension"} {
		if p.Permits(op) {
			t.Fatalf("%s permitted in the initial enshrined profile", op)
		}
	}
}

func TestD6_DirectAndSuccinctSameSemanticRelation(t *testing.T) {
	full := RedemptionRelation{BindsNetwork: true, BindsConfig: true, BindsTrustBase: true, BindsNullifier: true, BindsLockRefs: true, BindsReleaseLeaves: true}
	if !SameSemanticRelation(full, full) {
		t.Fatal("identical full relations not recognised as the same")
	}
	weaker := full
	weaker.BindsNullifier = false
	if SameSemanticRelation(full, weaker) {
		t.Fatal("a path that omits the nullifier binding treated as the same relation")
	}
}

func TestD6_VectorsMatchGolden(t *testing.T) {
	const path = "testdata/d6-vectors.json"
	got, err := MarshalD6Vectors(BuildD6Vectors())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (run: go run ./evmroot/cmd/d6vectors -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale — regenerate with: go run ./evmroot/cmd/d6vectors -update", path)
	}
}
