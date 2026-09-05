package evmroot

import "encoding/json"

// D6 vector set: historical trust, proof export, and custody accounting.

type D6VectorSet struct {
	GlobalSupplyObservable bool              `json:"global_execution_layer_supply_observable"`
	Checkpoint             D6CheckpointCase  `json:"checkpoint_and_windows"`
	HistoricalAuth         []D6HistAuthCase  `json:"historical_block_authentication"`
	MultiShardAnchor       D6AnchorCase      `json:"multi_shard_anchor"`
	LockRefresh            D6LockRefreshCase `json:"lock_witness_refresh"`
	Supply                 D6SupplyCase      `json:"supply_and_backing"`
	Custody                []CustodyStep     `json:"custody_walkthrough"`
	TokenProfile           D6ProfileCase     `json:"token_profile"`
	Redemption             D6RedemptionCase  `json:"redemption_relation"`
}

type D6CheckpointCase struct {
	Note                     string `json:"note"`
	Complete                 bool   `json:"checkpoint_complete"`
	DeltaHoldRounds          uint64 `json:"delta_hold_rounds"`
	MinRoundPeriodSeconds    uint64 `json:"min_round_period_seconds"`
	FreshnessLimitSeconds    uint64 `json:"freshness_limit_seconds"`
	WCert                    uint64 `json:"w_cert"`
	DeltaEv                  uint64 `json:"delta_ev"`
	NestingValid             bool   `json:"nesting_valid"` // W_cert <= Δ_ev < Δ_hold
	KeyRetainedForObligation bool   `json:"key_retained_for_outstanding_obligation"`
}

type D6HistAuthCase struct {
	Name          string `json:"name"`
	FromHead      uint64 `json:"from_head"`
	ToBlock       uint64 `json:"to_block"`
	HeaderChainOK bool   `json:"header_chain_ok"`
	Authenticated bool   `json:"authenticated"`
	HeaderCount   uint64 `json:"header_count"`
	ConstantSize  bool   `json:"constant_size"`
}

type D6AnchorCase struct {
	Note             string `json:"note"`
	Verified         bool   `json:"verified"`
	SealVerifiedOnce bool   `json:"seal_verified_once"`
	ShardPathCount   int    `json:"shard_path_count"`
	TouchedShards    int    `json:"touched_shards"`
}

type D6LockRefreshCase struct {
	Note              string `json:"note"`
	IdentityUnchanged bool   `json:"token_identity_unchanged"`
	BackingRefreshed  bool   `json:"historical_backing_refreshed"`
}

type D6SupplyCase struct {
	S0                uint64 `json:"s0"`
	Burn              uint64 `json:"burn"`
	NativeSupply      uint64 `json:"native_supply"`
	VaultNative       uint64 `json:"vault_native_balance"`
	WUCTSupply        uint64 `json:"wuct_supply"`
	BridgedOut        uint64 `json:"bridged_outstanding"`
	BackingConsistent bool   `json:"backing_not_double_counted"`
	Note              string `json:"note"`
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

	// --- checkpoint + windows ------------------------------------------
	cp := Checkpoint{
		NetworkID: 3, RootCommitment: rep(0xC0, 32), ConfigCommitment: rep(0xCF, 32),
		EVMHeadNumber: 900_000, EVMHeadHash: rep(0xB9, 32), EVMHeadStateRoot: rep(0x5E, 32), RootRound: 12_000,
	}
	const deltaHold, minPeriod, wCert, deltaEv = 200, 6, 50, 100
	vs.Checkpoint = D6CheckpointCase{
		Note: "Freshness limit is a client policy in elapsed time = Δ_hold × min round period; it is not W_cert and not the key-cache count. " +
			"Live cert age fits inside the evidence window, which fits inside retirement protection.",
		Complete:                 cp.Complete(),
		DeltaHoldRounds:          deltaHold,
		MinRoundPeriodSeconds:    minPeriod,
		FreshnessLimitSeconds:    CheckpointFreshnessLimitSeconds(deltaHold, minPeriod),
		WCert:                    wCert,
		DeltaEv:                  deltaEv,
		NestingValid:             NestingValid(wCert, deltaEv, deltaHold),
		KeyRetainedForObligation: KeyRetentionRequired(true, false),
	}

	// --- historical authentication (two distances; header count grows) --
	for _, hc := range []struct {
		name     string
		from, to uint64
		ok       bool
	}{
		{"near_history_ok", 900_000, 899_000, true},
		{"deep_history_ok", 900_000, 400_000, true},
		{"broken_chain", 900_000, 899_000, false},
	} {
		r := AuthenticateOldBlock(AuthPath{Mode: AuthCheckpointAncestry, FromHeadNumber: hc.from, ToBlockNumber: hc.to, HeaderChainOK: hc.ok})
		vs.HistoricalAuth = append(vs.HistoricalAuth, D6HistAuthCase{
			Name: hc.name, FromHead: hc.from, ToBlock: hc.to, HeaderChainOK: hc.ok,
			Authenticated: r.Authenticated, HeaderCount: r.HeaderCount, ConstantSize: r.ConstantSize,
		})
	}

	// --- multi-shard anchor: one seal, two aggregator shard paths -------
	anchor := AnchorBundle{
		SealSignaturesVerified: true, RootStateRoot: rep(0x2A, 32),
		ShardPaths: []ShardPath{
			{PartitionID: 0x41474701, ShardID: "0", ShardStateRoot: rep(0xA0, 32), PathToRootOK: true},
			{PartitionID: 0x41474701, ShardID: "1", ShardStateRoot: rep(0xA1, 32), PathToRootOK: true},
		},
	}
	leaves := []AnchoredLeaf{
		{PartitionID: 0x41474701, ShardID: "0", RoutingKey: rep(0x01, 8), LeafOK: true},
		{PartitionID: 0x41474701, ShardID: "1", RoutingKey: rep(0x02, 8), LeafOK: true},
	}
	ar := VerifyAnchoredHistory(anchor, leaves)
	vs.MultiShardAnchor = D6AnchorCase{
		Note:     "A history touching two aggregator shards verifies with one shared seal plus one shard path per touched shard; path count grows with touched shards, seal verification does not.",
		Verified: ar.Verified, SealVerifiedOnce: ar.SealVerifiedOnce, ShardPathCount: ar.ShardPathCount, TouchedShards: 2,
	}

	// --- lock witness refresh -----------------------------------------
	idUnchanged, refreshed := RefreshLockWitness(rep(0x7C, 32), rep(0x1C, 32), rep(0x01, 32), rep(0x02, 32))
	vs.LockRefresh = D6LockRefreshCase{
		Note:              "A recent proof of the same permanent lock digest refreshes historical backing; token identity does not include the refreshed witness.",
		IdentityUnchanged: idUnchanged, BackingRefreshed: refreshed,
	}

	// --- supply and backing -----------------------------------------
	sl := SupplyLedger{S0: 1_000_000_000, Burn: 12_345}
	vb := VaultBacking{VaultNativeBalance: 50_000, WUCTSupply: 8_000, BridgedOutstanding: 40_000}
	vs.Supply = D6SupplyCase{
		S0: sl.S0, Burn: sl.Burn, NativeSupply: sl.NativeSupply(),
		VaultNative: vb.VaultNativeBalance, WUCTSupply: vb.WUCTSupply, BridgedOut: vb.BridgedOutstanding,
		BackingConsistent: vb.Consistent(),
		Note:              "Native UCT, WUCT and bridged claims are distinct balances. WUCT is a separate wrapper; bridged outstanding (O = L - D) is covered by vault native UCT and never double-counted against WUCT.",
	}

	// --- custody walkthrough ----------------------------------------
	vs.Custody = WalkCustody(BridgeLedger{L: 100_000, D: 60_000, P: 55_000}, 10_000)

	// --- token profile --------------------------------------------
	p := InitialEnshrinedProfile()
	vs.TokenProfile = D6ProfileCase{
		Transfer: p.Permits("transfer"), Burn: p.Permits("burn"),
		Split: p.Permits("split"), Merge: p.Permits("merge"), MintExt: p.Permits("mint_reason_extension"),
	}

	// --- redemption relation ------------------------------------
	full := RedemptionRelation{BindsNetwork: true, BindsConfig: true, BindsTrustBase: true, BindsNullifier: true, BindsLockRefs: true, BindsReleaseLeaves: true}
	direct := full
	direct.Path = "direct"
	succinct := full
	succinct.Path = "succinct"
	vs.Redemption = D6RedemptionCase{
		Note:         "Direct (atomic, metered) and succinct (over-budget history) paths bind the same network/config/trust-base/nullifier/lock-refs/release-leaves — the same semantic relation on the common admitted token profile.",
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
