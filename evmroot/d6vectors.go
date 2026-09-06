package evmroot

import (
	"encoding/hex"
	"encoding/json"
)

// D6 vector set: historical trust, proof export (real hash-linked
// fixtures), and custody solvency accounting.

type D6VectorSet struct {
	GlobalSupplyObservable bool                `json:"global_execution_layer_supply_observable"`
	LiveCert               []D6LiveCertCase    `json:"live_certificate_admission"`
	Freshness              D6FreshnessCase     `json:"checkpoint_freshness_policy"`
	Windows                D6WindowsCase       `json:"window_nesting_and_key_retention"`
	HistoricalAuth         []D6HistAuthCase    `json:"historical_block_authentication"`
	MultiShardAnchor       []D6AnchorCase      `json:"multi_shard_anchor"`
	ProofBundles           []D6ProofBundleCase `json:"proof_bundle_offline_verification"`
	LockRefresh            []D6LockRefreshCase `json:"lock_witness_refresh"`
	Supply                 D6SupplyCase        `json:"supply_and_backing"`
	Custody                []CustodyStep       `json:"custody_walkthrough"`
	CustodySolvency        []D6SolvencyCase    `json:"custody_solvency"`
	TokenProfile           D6ProfileCase       `json:"token_profile"`
	Redemption             D6RedemptionCase    `json:"redemption_relation"`
}

type D6LiveCertCase struct {
	Name                string `json:"name"`
	CertRound           uint64 `json:"cert_round"`
	ImportedOriginRound uint64 `json:"imported_origin_round"`
	WCert               uint64 `json:"w_cert"`
	SignerEpochActive   bool   `json:"signer_epoch_active_at_claimed_round"`
	Admitted            bool   `json:"admitted"`
	Reason              string `json:"reason,omitempty"`
}

type D6FreshnessCase struct {
	Note                         string `json:"note"`
	DeltaHoldRounds              uint64 `json:"delta_hold_rounds"`
	DeltaEvRounds                uint64 `json:"delta_ev_rounds"`
	MinRoundPeriodSeconds        uint64 `json:"min_round_period_seconds"`
	ChurnMarginSeconds           uint64 `json:"churn_margin_seconds"`
	AcquireLatencySeconds        uint64 `json:"acquire_latency_seconds"`
	EnforcedRealTimeFloorSeconds uint64 `json:"enforced_real_time_floor_seconds"`
	RoundBasedAdvisorySeconds    uint64 `json:"round_based_advisory_seconds"`
	MinRealTimeProtection        uint64 `json:"min_real_time_protection_seconds"`
	MaxCheckpointStaleness       uint64 `json:"max_checkpoint_staleness_seconds"`
	StrictlyLessThanProtection   bool   `json:"staleness_strictly_less_than_protection"`
	PolicySupported              bool   `json:"policy_supported_by_enforced_floor"`
	PolicyValid                  bool   `json:"policy_valid"`
	RoundsOnlyPolicyUnsupported  bool   `json:"rounds_only_policy_reported_unsupported"`
	SubMinRoundEstimateRejected  bool   `json:"sub_physical_minimum_round_estimate_rejected"`
	OverMaxRoundEstimateRejected bool   `json:"arbitrarily_large_round_estimate_rejected"`
	PhysicalMinRoundSeconds      uint64 `json:"physical_min_round_seconds"`
	MaxObservedRoundSeconds      uint64 `json:"max_observed_round_seconds"`
}

type D6WindowsCase struct {
	WCert                    uint64 `json:"w_cert"`
	DeltaEv                  uint64 `json:"delta_ev"`
	DeltaHold                uint64 `json:"delta_hold"`
	NestingValid             bool   `json:"nesting_valid"`
	KeyRetainedForEvidence   bool   `json:"key_retained_for_outstanding_evidence"`
	KeyRetainedForRetirement bool   `json:"key_retained_for_outstanding_retirement"`
	KeyNotRetainedIfClear    bool   `json:"key_not_retained_with_no_obligation"`
}

type D6HistAuthCase struct {
	Name          string `json:"name"`
	ChainLen      int    `json:"chain_len"`
	Authenticated bool   `json:"authenticated"`
	HeaderCount   int    `json:"header_count"`
	ConstantSize  bool   `json:"constant_size"`
	Reason        string `json:"reason,omitempty"`
}

type D6AnchorCase struct {
	Name             string `json:"name"`
	Verified         bool   `json:"verified"`
	SealVerifiedOnce bool   `json:"seal_verified_once"`
	SealWeight       uint64 `json:"seal_weight"`
	SealThreshold    uint64 `json:"seal_threshold"`
	ShardPathCount   int    `json:"shard_path_count"`
	TouchedShards    int    `json:"touched_shards"`
	Reason           string `json:"reason,omitempty"`
}

type D6ProofBundleCase struct {
	Name            string `json:"name"`
	Mode            string `json:"mode"`
	CarriesEvidence bool   `json:"carries_evidence_structurally"`
	OfflineVerifies bool   `json:"verifies_offline"`
	Note            string `json:"note,omitempty"`
}

type D6LockRefreshCase struct {
	Name              string `json:"name"`
	FreshWitnessValid bool   `json:"fresh_witness_valid"`
	IdentityUnchanged bool   `json:"token_identity_unchanged"`
	BackingRefreshed  bool   `json:"historical_backing_refreshed"`
	IdentityHex       string `json:"token_lock_identity,omitempty"`
}

type D6SupplyCase struct {
	S0                    uint64 `json:"s0"`
	Burn                  uint64 `json:"burn"`
	NativeSupply          uint64 `json:"native_supply"`
	VaultNative           uint64 `json:"vault_native_balance"`
	WUCTSupply            uint64 `json:"wuct_supply"`
	WUCTContractNative    uint64 `json:"wuct_contract_native"`
	BridgedTotalLiability uint64 `json:"bridged_total_liability_o_plus_c"`
	BackingConsistent     bool   `json:"backing_consistent"`
	Note                  string `json:"note"`
}

type D6SolvencyCase struct {
	Name      string `json:"name"`
	L         uint64 `json:"l"`
	D         uint64 `json:"d"`
	P         uint64 `json:"p"`
	Balance   uint64 `json:"vault_balance"`
	Shortfall uint64 `json:"shortfall"`
	Owed      uint64 `json:"owed_l_minus_p"`
	Solvent   bool   `json:"solvent"`
}

type D6ProfileCase struct {
	Transfer bool `json:"transfer_allowed"`
	Burn     bool `json:"burn_allowed"`
	Split    bool `json:"split_allowed"`
	Merge    bool `json:"merge_allowed"`
	MintExt  bool `json:"mint_reason_extension_allowed"`
}

type D6RedemptionCase struct {
	Note         string `json:"note"`
	SameRelation bool   `json:"direct_and_succinct_same_semantic_relation"`
}

func BuildD6Vectors() D6VectorSet {
	var vs D6VectorSet
	vs.GlobalSupplyObservable = GlobalSupplyObservable

	// --- live certificate admission (measured vs the imported origin) ----
	for _, lc := range []struct {
		name            string
		cert, origin, w uint64
		signerActive    bool
	}{
		{"fresh_at_origin", 1000, 1000, 10, true},
		{"within_window", 995, 1000, 10, true},
		{"at_window_boundary", 990, 1000, 10, true},
		{"stale_past_window", 100, 1000, 10, true}, // the review's case: 900 rounds old, W_cert 10
		{"future_ahead_of_origin", 1001, 1000, 10, true},
		{"signer_epoch_inactive", 998, 1000, 10, false},
	} {
		r := AdmitLiveCertificate(lc.cert, lc.origin, lc.w, lc.signerActive)
		vs.LiveCert = append(vs.LiveCert, D6LiveCertCase{
			Name: lc.name, CertRound: lc.cert, ImportedOriginRound: lc.origin, WCert: lc.w,
			SignerEpochActive: lc.signerActive, Admitted: r.Admitted, Reason: r.Reason,
		})
	}

	// --- checkpoint freshness policy --------------------------------
	// A round-count-only policy is UNSUPPORTED: consensus does not
	// guarantee a minimum successful-round duration, so no safety limit
	// follows from Δ_hold rounds × a period.
	roundsOnly := FreshnessPolicy{
		DeltaHoldRounds: 20_000, DeltaEvRounds: 8_000,
		MinRoundPeriodSeconds: 6, ChurnMarginSeconds: 3_600, AcquireLatencySeconds: 1_800,
	}
	// The safety limit comes only from an enforced wall-clock floor.
	fp := roundsOnly
	fp.EnforcedRealTimeFloorSeconds = 100_000
	tooFast := fp
	tooFast.MinRoundPeriodSeconds = ConsensusMinRoundPeriodSeconds - 1
	tooSlow := fp
	tooSlow.MinRoundPeriodSeconds = MaxObservedRoundPeriodSeconds + 1
	vs.Freshness = D6FreshnessCase{
		Note:                         "The round-count arithmetic (Δ_hold rounds × a per-round estimate) is ADVISORY ONLY — Pacemaker.AdvanceRoundQC advances immediately on a QC, so consensus guarantees no minimum successful-round duration. A policy with no EnforcedRealTimeFloorSeconds is Unsupported. The staleness limit is derived from that enforced wall-clock floor, minus acquisition latency, strictly less than the floor. The advisory per-round estimate must be a conservative lower bound: in [ConsensusMinRoundPeriodSeconds, MaxObservedRoundPeriodSeconds] — a sub-minimum value or an arbitrarily large one is rejected.",
		DeltaHoldRounds:              fp.DeltaHoldRounds,
		DeltaEvRounds:                fp.DeltaEvRounds,
		MinRoundPeriodSeconds:        fp.MinRoundPeriodSeconds,
		ChurnMarginSeconds:           fp.ChurnMarginSeconds,
		AcquireLatencySeconds:        fp.AcquireLatencySeconds,
		EnforcedRealTimeFloorSeconds: fp.EnforcedRealTimeFloorSeconds,
		RoundBasedAdvisorySeconds:    fp.RoundBasedAdvisorySeconds(),
		MinRealTimeProtection:        fp.MinRealTimeProtectionSeconds(),
		MaxCheckpointStaleness:       fp.MaxCheckpointStalenessSeconds(),
		StrictlyLessThanProtection:   fp.MaxCheckpointStalenessSeconds() < fp.MinRealTimeProtectionSeconds(),
		PolicySupported:              fp.Supported(),
		PolicyValid:                  fp.Valid(),
		RoundsOnlyPolicyUnsupported:  !roundsOnly.Supported() && !roundsOnly.Valid(),
		SubMinRoundEstimateRejected:  !tooFast.Valid(),
		OverMaxRoundEstimateRejected: !tooSlow.Valid(),
		PhysicalMinRoundSeconds:      ConsensusMinRoundPeriodSeconds,
		MaxObservedRoundSeconds:      MaxObservedRoundPeriodSeconds,
	}

	// --- window nesting + key retention ----------------------------
	vs.Windows = D6WindowsCase{
		WCert: 50, DeltaEv: 100, DeltaHold: 200,
		NestingValid:             NestingValid(50, 100, 200),
		KeyRetainedForEvidence:   KeyRetentionRequired(true, false),
		KeyRetainedForRetirement: KeyRetentionRequired(false, true),
		KeyNotRetainedIfClear:    !KeyRetentionRequired(false, false),
	}

	// --- historical header authentication (real hash-linked chain) -----
	chain := LinkHeaders(400_000, rep(0x00, 32), 500)
	head := chain[len(chain)-1].Hash()
	subject := chain[0].Hash()
	shortChain := LinkHeaders(400_000, rep(0x00, 32), 20)
	shortHead := shortChain[len(shortChain)-1].Hash()
	broken := append([]Header(nil), chain...)
	broken[250].ParentHash = rep(0xFF, 32)
	for _, hc := range []struct {
		name  string
		subj  []byte
		ch    []Header
		trust []byte
	}{
		{"valid_deep_chain", subject, chain, head},
		{"valid_short_chain", shortChain[0].Hash(), shortChain, shortHead},
		{"broken_linkage", subject, broken, head},
		{"wrong_trusted_head", subject, chain, rep(0xAB, 32)},
	} {
		r := AuthenticateOldBlock(hc.subj, hc.ch, hc.trust)
		vs.HistoricalAuth = append(vs.HistoricalAuth, D6HistAuthCase{
			Name: hc.name, ChainLen: len(hc.ch), Authenticated: r.Authenticated,
			HeaderCount: r.HeaderCount, ConstantSize: r.ConstantSize, Reason: r.Reason,
		})
	}

	// --- multi-shard anchor (real Merkle paths, real signatures over r*,
	//     partition/shard/config bound into the leaves) -----------------
	ws := d6Assignment()
	const anchorEpoch uint64 = 8
	anchorAssignmentID := sha256Bytes([]byte("d6-anchor-assignment-epoch-8"))
	cfg0 := sha256Bytes([]byte("agg-shard-0-config"))
	cfg1 := sha256Bytes([]byte("agg-shard-1-config"))
	zero := rep(0x00, 32)
	s0leaf := sha256Bytes([]byte("agg-shard-0-txleaf"))
	s1leaf := sha256Bytes([]byte("agg-shard-1-txleaf"))
	// Shard state roots: tx leaf folds with a zero sibling.
	s0root := hashNode(s0leaf, zero)
	s1root := hashNode(s1leaf, zero)
	// r* is over the two BOUND shard-anchor leaves (partition ‖ shard ‖
	// config ‖ shard state root), so relabelling any of those breaks it.
	bl0 := shardAnchorLeaf(0x41474701, "0", cfg0, s0root)
	bl1 := shardAnchorLeaf(0x41474701, "1", cfg1, s1root)
	rStar := hashNode(bl0, bl1)
	stmt := AnchorSealStatement(rStar, anchorEpoch, anchorAssignmentID)
	seal := AnchorSeal{
		RootStateRoot: rStar, Epoch: anchorEpoch, AssignmentID: anchorAssignmentID, Weights: ws,
		Signatures: SignAnchorSeal(stmt, []string{"root-a", "root-b", "root-c"}), // 10+6+5 = 21 >= 17
	}
	bundle := AnchorBundle{
		Seal: seal,
		ShardPaths: []ShardAnchorPath{
			{PartitionID: 0x41474701, ShardID: "0", ConfigHash: cfg0, ShardStateRoot: s0root, Path: []PathStep{{Sibling: bl1, Left: false}}},
			{PartitionID: 0x41474701, ShardID: "1", ConfigHash: cfg1, ShardStateRoot: s1root, Path: []PathStep{{Sibling: bl0, Left: true}}},
		},
	}
	leaves := []AnchoredLeaf{
		{PartitionID: 0x41474701, ShardID: "0", LeafHash: s0leaf, Path: []PathStep{{Sibling: zero, Left: false}}},
		{PartitionID: 0x41474701, ShardID: "1", LeafHash: s1leaf, Path: []PathStep{{Sibling: zero, Left: false}}},
	}
	okRes := VerifyAnchoredHistory(bundle, leaves)
	badLeaves := append([]AnchoredLeaf(nil), leaves...)
	badLeaves[1].LeafHash = rep(0x99, 32)
	badRes := VerifyAnchoredHistory(bundle, badLeaves)

	// seal below threshold: only root-e (weight 1) signs.
	lowSeal := seal
	lowSeal.Signatures = SignAnchorSeal(stmt, []string{"root-e"})
	lowRes := VerifyAnchoredHistory(AnchorBundle{Seal: lowSeal, ShardPaths: bundle.ShardPaths}, leaves)

	// zero-threshold / unsigned seal: no signatures at all. The derived
	// threshold is 17, weight 0 -> fails.
	unsignedSeal := seal
	unsignedSeal.Signatures = map[string][]byte{}
	unsignedRes := VerifyAnchoredHistory(AnchorBundle{Seal: unsignedSeal, ShardPaths: bundle.ShardPaths}, leaves)

	// forged signer: "root-a" entry actually signed by root-e's key.
	forgedSeal := seal
	forgedSeal.Signatures = map[string][]byte{
		"root-a": ForgeAnchorSignature(stmt, "root-a", "root-e")["root-a"],
		"root-b": seal.Signatures["root-b"],
		"root-c": seal.Signatures["root-c"],
	}
	forgedRes := VerifyAnchoredHistory(AnchorBundle{Seal: forgedSeal, ShardPaths: bundle.ShardPaths}, leaves)

	// relabelled shard path: partition 0x41474701 -> 0x99, keeping the same
	// state root and path. The bound leaf changes, so it no longer folds to
	// r*. Leaves relabelled to match.
	relabelBundle := AnchorBundle{Seal: seal, ShardPaths: []ShardAnchorPath{
		{PartitionID: 0x99, ShardID: "attacker", ConfigHash: cfg0, ShardStateRoot: s0root, Path: bundle.ShardPaths[0].Path},
		bundle.ShardPaths[1],
	}}
	relabelLeaves := []AnchoredLeaf{
		{PartitionID: 0x99, ShardID: "attacker", LeafHash: s0leaf, Path: leaves[0].Path},
		leaves[1],
	}
	relabelRes := VerifyAnchoredHistory(relabelBundle, relabelLeaves)

	// substituted r*: the attacker picks a new root r' and can rebuild
	// Merkle paths to it at will, but the honest signatures were made over
	// r*, so VerifySeal counts zero valid signatures for r' and the whole
	// bundle fails before any path is even considered.
	rPrime := hashNode(sha256Bytes([]byte("attacker-bl0")), sha256Bytes([]byte("attacker-bl1")))
	subSeal := AnchorSeal{RootStateRoot: rPrime, Epoch: anchorEpoch, AssignmentID: anchorAssignmentID, Weights: ws, Signatures: seal.Signatures}
	subBundle := AnchorBundle{Seal: subSeal, ShardPaths: []ShardAnchorPath{
		{PartitionID: 0x41474701, ShardID: "0", ConfigHash: cfg0, ShardStateRoot: s0root, Path: []PathStep{{Sibling: sha256Bytes([]byte("attacker-bl1")), Left: false}}},
	}}
	subRes := VerifyAnchoredHistory(subBundle, nil)

	// wrong epoch: same r*, signatures made for epoch 8, seal claims epoch 9.
	wrongEpochSeal := seal
	wrongEpochSeal.Epoch = 9
	wrongEpochRes := VerifyAnchoredHistory(AnchorBundle{Seal: wrongEpochSeal, ShardPaths: bundle.ShardPaths}, leaves)

	vs.MultiShardAnchor = []D6AnchorCase{
		{Name: "two_aggregator_shards_one_seal", Verified: okRes.Verified, SealVerifiedOnce: okRes.SealVerifiedOnce, SealWeight: okRes.SealWeight, SealThreshold: okRes.SealThreshold, ShardPathCount: okRes.ShardPathCount, TouchedShards: 2},
		{Name: "leaf_path_does_not_recompute", Verified: badRes.Verified, SealVerifiedOnce: badRes.SealVerifiedOnce, SealWeight: badRes.SealWeight, SealThreshold: badRes.SealThreshold, ShardPathCount: badRes.ShardPathCount, Reason: badRes.Reason},
		{Name: "seal_below_threshold", Verified: lowRes.Verified, SealVerifiedOnce: lowRes.SealVerifiedOnce, SealWeight: lowRes.SealWeight, SealThreshold: lowRes.SealThreshold, Reason: lowRes.Reason},
		{Name: "unsigned_seal_zero_weight", Verified: unsignedRes.Verified, SealWeight: unsignedRes.SealWeight, SealThreshold: unsignedRes.SealThreshold, Reason: unsignedRes.Reason},
		{Name: "forged_signer_entry_not_counted", Verified: forgedRes.Verified, SealVerifiedOnce: forgedRes.SealVerifiedOnce, SealWeight: forgedRes.SealWeight, SealThreshold: forgedRes.SealThreshold, Reason: forgedRes.Reason},
		{Name: "relabelled_shard_path_rejected", Verified: relabelRes.Verified, SealVerifiedOnce: relabelRes.SealVerifiedOnce, SealWeight: relabelRes.SealWeight, SealThreshold: relabelRes.SealThreshold, Reason: relabelRes.Reason},
		{Name: "substituted_root_no_valid_signatures", Verified: subRes.Verified, SealWeight: subRes.SealWeight, SealThreshold: subRes.SealThreshold, Reason: subRes.Reason},
		{Name: "wrong_epoch_seal_rejected", Verified: wrongEpochRes.Verified, SealWeight: wrongEpochRes.SealWeight, SealThreshold: wrongEpochRes.SealThreshold, Reason: wrongEpochRes.Reason},
	}

	// --- proof bundle: structural availability vs offline verification --
	pbSubject := sha256Bytes([]byte("exported-subject"))
	pbRoot := hashNode(shardAnchorLeaf(7, "0", cfg0, hashNode(pbSubject, zero)), zero)
	pbStmt := AnchorSealStatement(pbRoot, anchorEpoch, anchorAssignmentID)
	pbAnchor := AnchorBundle{
		Seal:       AnchorSeal{RootStateRoot: pbRoot, Epoch: anchorEpoch, AssignmentID: anchorAssignmentID, Weights: ws, Signatures: SignAnchorSeal(pbStmt, []string{"root-a", "root-b", "root-c"})},
		ShardPaths: []ShardAnchorPath{{PartitionID: 7, ShardID: "0", ConfigHash: cfg0, ShardStateRoot: hashNode(pbSubject, zero), Path: []PathStep{{Sibling: zero, Left: false}}}},
	}
	pbLeaf := AnchoredLeaf{PartitionID: 7, ShardID: "0", LeafHash: pbSubject, Path: []PathStep{{Sibling: zero, Left: false}}}
	pbGood := ProofBundle{Version: 1, ChainContext: []byte("ctx"), SubjectHash: pbSubject, Mode: AuthLiveCertificate, LiveAnchor: &pbAnchor, LiveLeaf: &pbLeaf, Receipt: []byte("r")}
	pbNaked := ProofBundle{Version: 1, ChainContext: []byte("ctx"), SubjectHash: pbSubject, Mode: AuthLiveCertificate, Receipt: []byte("r")}
	pbWeak := pbGood
	weakSeal := pbAnchor
	weakSeal.Seal.Signatures = SignAnchorSeal(pbStmt, []string{"root-e"})
	pbWeak.LiveAnchor = &weakSeal

	// The verifier's own authenticated trust anchor — assignment/epoch/id
	// come from here, never from the bundle.
	pbFresh := FreshnessPolicy{DeltaHoldRounds: 20_000, DeltaEvRounds: 8_000, MinRoundPeriodSeconds: 6,
		ChurnMarginSeconds: 3_600, AcquireLatencySeconds: 1_800, EnforcedRealTimeFloorSeconds: 100_000}
	pbTrust := VerifierTrustAnchor{Network: 1, ChainContext: []byte("ctx"), Epoch: anchorEpoch, BodyIdentity: anchorAssignmentID,
		Weights: ws, Freshness: pbFresh, CheckpointAgeSeconds: 10}

	// A bundle carrying its own one-member attacker assignment + attacker
	// signature, against an unrelated trusted checkpoint.
	attWs := WeightSet{d6Member("pb-attacker", 1)}
	attSub := sha256Bytes([]byte("pb-attacker-subject"))
	attRoot := hashNode(shardAnchorLeaf(7, "0", cfg0, hashNode(attSub, zero)), zero)
	attStmt := AnchorSealStatement(attRoot, anchorEpoch, anchorAssignmentID) // even copying the honest id
	attAnchor := AnchorBundle{
		Seal:       AnchorSeal{RootStateRoot: attRoot, Epoch: anchorEpoch, AssignmentID: anchorAssignmentID, Weights: attWs, Signatures: SignAnchorSeal(attStmt, []string{"pb-attacker"})},
		ShardPaths: []ShardAnchorPath{{PartitionID: 7, ShardID: "0", ConfigHash: cfg0, ShardStateRoot: hashNode(attSub, zero), Path: []PathStep{{Sibling: zero, Left: false}}}},
	}
	attLeaf := AnchoredLeaf{PartitionID: 7, ShardID: "0", LeafHash: attSub, Path: []PathStep{{Sibling: zero, Left: false}}}
	pbForged := ProofBundle{Version: 1, ChainContext: []byte("ctx"), SubjectHash: attSub, Mode: AuthLiveCertificate, LiveAnchor: &attAnchor, LiveLeaf: &attLeaf, Receipt: []byte("r")}

	pbStale := pbGood
	staleTrust := pbTrust
	staleTrust.CheckpointAgeSeconds = pbFresh.MaxCheckpointStalenessSeconds() + 1

	vs.ProofBundles = []D6ProofBundleCase{
		{Name: "live_with_verifying_anchor", Mode: "live_certificate", CarriesEvidence: pbGood.CarriesEvidence(), OfflineVerifies: pbGood.OfflineVerify(pbTrust),
			Note: "carries a certified seal + shard path proving the subject; verifies offline against the verifier's own trust anchor"},
		{Name: "live_receipt_only_no_certificate_proof", Mode: "live_certificate", CarriesEvidence: pbNaked.CarriesEvidence(), OfflineVerifies: pbNaked.OfflineVerify(pbTrust),
			Note: "non-empty context/subject/receipt but no anchor evidence — neither structurally complete nor offline-verifiable"},
		{Name: "live_anchor_below_threshold", Mode: "live_certificate", CarriesEvidence: pbWeak.CarriesEvidence(), OfflineVerifies: pbWeak.OfflineVerify(pbTrust),
			Note: "structurally complete but the seal is below the derived quorum — offline verification fails"},
		{Name: "forged_self_supplied_assignment", Mode: "live_certificate", CarriesEvidence: pbForged.CarriesEvidence(), OfflineVerifies: pbForged.OfflineVerify(pbTrust),
			Note: "a fresh one-member attacker assignment with a valid attacker signature (even copying the honest AssignmentID) does NOT verify: OfflineVerify re-checks against the trust anchor's Weights, not the bundle's"},
		{Name: "stale_checkpoint_policy", Mode: "live_certificate", CarriesEvidence: pbStale.CarriesEvidence(), OfflineVerifies: pbStale.OfflineVerify(staleTrust),
			Note: "the verifier's checkpoint is older than the freshness limit — no safety claim, verification fails"},
	}

	// --- lock witness refresh (real proofs) ------------------------
	tokenID := sha256Bytes([]byte("token-abc"))
	digest := sha256Bytes([]byte("permanent-lock-digest"))
	oldSib := sha256Bytes([]byte("old-sibling"))
	freshSib := sha256Bytes([]byte("fresh-sibling"))
	oldW := LockWitness{Digest: digest, RootStateRoot: hashNode(digest, oldSib), Path: []PathStep{{Sibling: oldSib, Left: false}}}
	freshW := LockWitness{Digest: digest, RootStateRoot: hashNode(digest, freshSib), Path: []PathStep{{Sibling: freshSib, Left: false}}}
	idUn, refreshed, fValid := RefreshLockWitness(tokenID, digest, oldW, freshW)
	otherDigest := sha256Bytes([]byte("some-other-digest"))
	badFresh := LockWitness{Digest: otherDigest, RootStateRoot: hashNode(otherDigest, zero), Path: []PathStep{{Sibling: zero, Left: false}}}
	_, _, badValid := RefreshLockWitness(tokenID, digest, oldW, badFresh)
	lid := TokenLockIdentity(tokenID, digest)
	vs.LockRefresh = []D6LockRefreshCase{
		{Name: "fresh_proof_same_digest", FreshWitnessValid: fValid, IdentityUnchanged: idUn, BackingRefreshed: refreshed, IdentityHex: hex.EncodeToString(lid[:])},
		{Name: "fresh_proof_wrong_digest_rejected", FreshWitnessValid: badValid},
	}

	// --- supply and backing ---------------------------------------
	sl := SupplyLedger{S0: 1_000_000_000, Burn: 12_345}
	vb := VaultBacking{VaultNativeBalance: 50_000, WUCTSupply: 8_000, WUCTContractNative: 8_000, BridgedTotalLiability: 45_000}
	vs.Supply = D6SupplyCase{
		S0: sl.S0, Burn: sl.Burn, NativeSupply: sl.NativeSupply(),
		VaultNative: vb.VaultNativeBalance, WUCTSupply: vb.WUCTSupply, WUCTContractNative: vb.WUCTContractNative,
		BridgedTotalLiability: vb.BridgedTotalLiability, BackingConsistent: vb.Consistent(),
		Note: "Vault native must cover O + C (the full bridge liability), not just O. WUCT is backed 1:1 by its own contract's native, separate from the vault.",
	}

	// --- custody walkthrough (with vault balance + solvency) ---------
	vs.Custody = WalkCustody(BridgeLedger{L: 100_000, D: 60_000, P: 55_000, Balance: 45_000}, 10_000)

	// --- custody solvency edge cases ------------------------------
	for i, sc := range []BridgeLedger{
		{L: 100, D: 100, P: 0, Balance: 100, Shortfall: 0}, // solvent
		{L: 100, D: 100, P: 0, Balance: 0, Shortfall: 0},   // INSOLVENT (the review's case)
		{L: 100, D: 100, P: 0, Balance: 60, Shortfall: 40}, // deficit recorded -> not solvent
		{L: 100, D: 40, P: 40, Balance: 60, Shortfall: 0},  // solvent: owes 60, holds 60
		{L: 100, D: 40, P: 40, Balance: 50, Shortfall: 0},  // identity does not close -> not solvent
	} {
		names := []string{"solvent_fully_backed", "insolvent_zero_balance", "insolvent_recorded_deficit", "solvent_partial_paid", "insolvent_identity_not_closed"}
		vs.CustodySolvency = append(vs.CustodySolvency, D6SolvencyCase{
			Name: names[i], L: sc.L, D: sc.D, P: sc.P, Balance: sc.Balance, Shortfall: sc.Shortfall,
			Owed: sc.Owed(), Solvent: sc.Solvent(),
		})
	}

	// --- token profile -----------------------------------------
	p := InitialEnshrinedProfile()
	vs.TokenProfile = D6ProfileCase{
		Transfer: p.Permits("transfer"), Burn: p.Permits("burn"),
		Split: p.Permits("split"), Merge: p.Permits("merge"), MintExt: p.Permits("mint_reason_extension"),
	}

	// --- redemption relation ---------------------------------
	full := RedemptionRelation{BindsNetwork: true, BindsConfig: true, BindsTrustBase: true, BindsNullifier: true, BindsLockRefs: true, BindsReleaseLeaves: true}
	direct, succinct := full, full
	direct.Path, succinct.Path = "direct", "succinct"
	vs.Redemption = D6RedemptionCase{
		Note:         "Direct (atomic, metered) and succinct (over-budget history) bind the same network/config/trust-base/nullifier/lock-refs/release-leaves.",
		SameRelation: SameSemanticRelation(direct, succinct),
	}

	return vs
}

func MarshalD6Vectors(vs D6VectorSet) ([]byte, error) {
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
