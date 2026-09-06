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

func TestD6_LiveCertMeasuredFromImportedOrigin(t *testing.T) {
	// The review's case: cert round 100, imported origin 1000, W_cert 10 ->
	// 900 rounds old -> NOT live.
	if AdmitLiveCertificate(100, 1000, 10, true).Admitted {
		t.Fatal("a certificate 900 rounds behind the origin was admitted as live")
	}
	// At the boundary (exactly W_cert old): admitted.
	if !AdmitLiveCertificate(990, 1000, 10, true).Admitted {
		t.Fatal("a certificate exactly W_cert old was not admitted")
	}
	// One past the boundary: not admitted.
	if AdmitLiveCertificate(989, 1000, 10, true).Admitted {
		t.Fatal("a certificate W_cert+1 old was admitted")
	}
	// Ahead of the origin: not admitted (retry after progress).
	if AdmitLiveCertificate(1001, 1000, 10, true).Admitted {
		t.Fatal("a future certificate was admitted")
	}
	// Signer epoch inactive: not admitted.
	if AdmitLiveCertificate(995, 1000, 10, false).Admitted {
		t.Fatal("a certificate from an inactive signer epoch was admitted")
	}
}

func TestD6_CheckpointFreshnessDerivedAndStrict(t *testing.T) {
	fp := FreshnessPolicy{DeltaHoldRounds: 20_000, DeltaEvRounds: 8_000, MinRoundPeriodSeconds: 6, ChurnMarginSeconds: 3_600, AcquireLatencySeconds: 1_800}
	prot := fp.MinRealTimeProtectionSeconds()
	stale := fp.MaxCheckpointStalenessSeconds()
	if prot == 0 || stale == 0 {
		t.Fatalf("degenerate policy: prot=%d stale=%d", prot, stale)
	}
	if stale >= prot {
		t.Fatalf("staleness limit %d is not strictly less than protection %d", stale, prot)
	}
	if !fp.Valid() {
		t.Fatal("a well-formed policy was rejected")
	}
	// A too-short protection window (Δ_hold barely exceeds Δ_ev): no safe policy.
	bad := FreshnessPolicy{DeltaHoldRounds: 8_100, DeltaEvRounds: 8_000, MinRoundPeriodSeconds: 6, ChurnMarginSeconds: 3_600, AcquireLatencySeconds: 1_800}
	if bad.Valid() {
		t.Fatal("an unsafe pacing/protection combination produced a valid policy")
	}
}

func TestD6_WindowNestingAndKeyRetention(t *testing.T) {
	if !NestingValid(50, 100, 200) || NestingValid(120, 100, 200) || NestingValid(50, 200, 200) {
		t.Fatal("window nesting check wrong")
	}
	if !KeyRetentionRequired(true, false) || !KeyRetentionRequired(false, true) || KeyRetentionRequired(false, false) {
		t.Fatal("key retention check wrong")
	}
}

func TestD6_HistoricalAuthWalksARealChain(t *testing.T) {
	chain := LinkHeaders(400_000, rep(0, 32), 300)
	head := chain[len(chain)-1].Hash()
	subject := chain[0].Hash()

	ok := AuthenticateOldBlock(subject, chain, head)
	if !ok.Authenticated || ok.ConstantSize || ok.HeaderCount != 300 {
		t.Fatalf("valid chain not authenticated: %+v", ok)
	}
	// A shorter distance authenticates with fewer headers — linear, not constant.
	short := LinkHeaders(400_000, rep(0, 32), 30)
	if r := AuthenticateOldBlock(short[0].Hash(), short, short[len(short)-1].Hash()); r.HeaderCount >= ok.HeaderCount {
		t.Fatal("header count did not shrink with distance")
	}
	// Broken linkage: not authenticated.
	broken := append([]Header(nil), chain...)
	broken[150].ParentHash = rep(0xFF, 32)
	if AuthenticateOldBlock(subject, broken, head).Authenticated {
		t.Fatal("a broken hash link authenticated")
	}
	// Wrong trusted head: not authenticated. Retired-key signatures are not
	// part of this path at all.
	if AuthenticateOldBlock(subject, chain, rep(0xAB, 32)).Authenticated {
		t.Fatal("authenticated against the wrong trusted head")
	}
}

func TestD6_MultiShardAnchorRecomputesPaths(t *testing.T) {
	ws := d3Assignment()
	w, _ := ws.TotalWeight()
	s0leaf := sha256Bytes([]byte("s0"))
	s1leaf := sha256Bytes([]byte("s1"))
	z := rep(0, 32)
	s0root := hashNode(s0leaf, z)
	s1root := hashNode(s1leaf, z)
	rStar := hashNode(s0root, s1root)
	bundle := AnchorBundle{
		Seal: AnchorSeal{RootStateRoot: rStar, Signers: []string{"root-a", "root-b", "root-c"}, Weights: ws, Threshold: RootQuorumThreshold(w)},
		ShardPaths: []ShardAnchorPath{
			{PartitionID: 7, ShardID: "0", ShardStateRoot: s0root, Path: []PathStep{{Sibling: s1root, Left: false}}},
			{PartitionID: 7, ShardID: "1", ShardStateRoot: s1root, Path: []PathStep{{Sibling: s0root, Left: true}}},
		},
	}
	leaves := []AnchoredLeaf{
		{PartitionID: 7, ShardID: "0", LeafHash: s0leaf, Path: []PathStep{{Sibling: z, Left: false}}},
		{PartitionID: 7, ShardID: "1", LeafHash: s1leaf, Path: []PathStep{{Sibling: z, Left: false}}},
	}
	r := VerifyAnchoredHistory(bundle, leaves)
	if !r.Verified || !r.SealVerifiedOnce || r.ShardPathCount != 2 {
		t.Fatalf("valid multi-shard anchor rejected: %+v", r)
	}
	// A tampered r* -> shard paths no longer recompute.
	bad := bundle
	bad.Seal.RootStateRoot = rep(0x11, 32)
	if VerifyAnchoredHistory(bad, leaves).Verified {
		t.Fatal("a wrong r* verified")
	}
	// A leaf whose path does not recompute to its shard root.
	badLeaves := append([]AnchoredLeaf(nil), leaves...)
	badLeaves[0].LeafHash = rep(0x22, 32)
	if VerifyAnchoredHistory(bundle, badLeaves).Verified {
		t.Fatal("a bad leaf verified")
	}
	// Seal below threshold.
	low := bundle
	low.Seal.Signers = []string{"root-e"}
	if VerifyAnchoredHistory(low, leaves).Verified {
		t.Fatal("a below-threshold seal verified")
	}
}

func TestD6_LockRefreshRealProofs(t *testing.T) {
	tokenID := sha256Bytes([]byte("tok"))
	digest := sha256Bytes([]byte("lock-digest"))
	oldSib := sha256Bytes([]byte("old"))
	freshSib := sha256Bytes([]byte("fresh"))
	oldW := LockWitness{Digest: digest, RootStateRoot: hashNode(digest, oldSib), Path: []PathStep{{Sibling: oldSib}}}
	freshW := LockWitness{Digest: digest, RootStateRoot: hashNode(digest, freshSib), Path: []PathStep{{Sibling: freshSib}}}
	if !oldW.Verify() || !freshW.Verify() {
		t.Fatal("a valid lock witness did not verify")
	}
	idUn, refreshed, valid := RefreshLockWitness(tokenID, digest, oldW, freshW)
	if !valid || !idUn || !refreshed {
		t.Fatalf("refresh with a valid fresh proof failed: valid=%v idUnchanged=%v refreshed=%v", valid, idUn, refreshed)
	}
	// A fresh witness whose path does not recompute.
	brokenFresh := freshW
	brokenFresh.RootStateRoot = rep(0x77, 32)
	if _, _, v := RefreshLockWitness(tokenID, digest, oldW, brokenFresh); v {
		t.Fatal("an invalid fresh witness was accepted")
	}
	// A fresh witness for a different digest.
	other := sha256Bytes([]byte("other"))
	bad := LockWitness{Digest: other, RootStateRoot: hashNode(other, oldSib), Path: []PathStep{{Sibling: oldSib}}}
	if _, _, v := RefreshLockWitness(tokenID, digest, oldW, bad); v {
		t.Fatal("a fresh witness for the wrong digest was accepted")
	}
	// Identity is a pure function of (tokenID, digest).
	if TokenLockIdentity(tokenID, digest) != TokenLockIdentity(tokenID, digest) {
		t.Fatal("token lock identity is not deterministic")
	}
	if TokenLockIdentity(tokenID, digest) == TokenLockIdentity(tokenID, other) {
		t.Fatal("token lock identity does not depend on the digest")
	}
}

func TestD6_CustodySolvencyEquation(t *testing.T) {
	// The case the earlier model missed: L=D=100, P=0, Balance=0. L>=D>=P
	// holds, but Owed()=100 and Balance=0 -> insolvent.
	insolvent := BridgeLedger{L: 100, D: 100, P: 0, Balance: 0}
	if insolvent.Invariants() != true {
		t.Fatal("ordering invariant should still hold")
	}
	if insolvent.Solvent() {
		t.Fatal("a vault owing 100 with a 0 balance was reported solvent")
	}
	solvent := BridgeLedger{L: 100, D: 100, P: 0, Balance: 100}
	if !solvent.Solvent() {
		t.Fatal("a fully-backed vault was reported insolvent")
	}
	// Identity must close: Balance + Shortfall == L - P.
	deficit := BridgeLedger{L: 100, D: 100, P: 0, Balance: 60, Shortfall: 40}
	if deficit.Solvent() {
		t.Fatal("a recorded deficit was reported solvent")
	}
	mismatch := BridgeLedger{L: 100, D: 40, P: 40, Balance: 50, Shortfall: 0}
	if mismatch.Solvent() {
		t.Fatal("an unbalanced identity was reported solvent")
	}
}

func TestD6_CustodyWalkthroughSolventThroughout(t *testing.T) {
	steps := WalkCustody(BridgeLedger{L: 100_000, D: 60_000, P: 55_000, Balance: 45_000}, 10_000)
	if len(steps) != 4 {
		t.Fatalf("got %d steps, want 4", len(steps))
	}
	for _, s := range steps {
		if !s.Solvent {
			t.Fatalf("insolvent at %s: %+v (owed %d)", s.State, s.Ledger, s.Owed)
		}
	}
	final := steps[3]
	if final.State != "paid" || final.Ledger.L != 110_000 || final.Ledger.P != 65_000 || final.Ledger.Balance != 45_000 {
		t.Fatalf("final ledger wrong: %+v", final.Ledger)
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
