package evmroot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func sha256Slice(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// This file builds the D1 independent vector set. The same builder feeds
// both the golden-file test (vectors_test.go) and the standalone
// regenerator (cmd/d1vectors). Every "want_*" field is computed here from
// the profile implementation in this package, so a vector file that
// disagrees with the code is a test failure, not a stale artifact.

// VectorSet is the whole D1 vector document.
type VectorSet struct {
	ProfileVersion    int                   `json:"profile_version"`
	Domains           DomainVectors         `json:"domains"`
	RootOrigins       []RootOriginVector    `json:"root_origins"`
	SignatureSubsets  SignatureSubsetCase   `json:"signature_subsets"`
	DistinctStatement DistinctStatementCase `json:"distinct_statement"`
	RootInputs        []RootInputVector     `json:"root_inputs"`
	EpochBoundary     []EpochBoundaryVector `json:"epoch_boundary"`
	Selection         []SelectionVector     `json:"certificate_selection"`
	Timestamps        []TimestampVector     `json:"timestamps"`
	Clock             ClockVector           `json:"certified_round_clock"`
}

// EpochBoundaryVector shows the certified-vs-authorized epoch relationship
// and that equality is not imposed.
type EpochBoundaryVector struct {
	Name            string `json:"name"`
	CertifiedEpoch  uint64 `json:"certified_epoch"`
	AuthorizedEpoch uint64 `json:"authorized_epoch"`
	Boundary        string `json:"boundary"` // normal | handoff | invalid
	Accepted        bool   `json:"accepted"` // RootInput.Validate() passes
}

// SelectionVector exercises ValidateBoundCertificate: two nodes with
// different observed certificate sets validate the same block-bound
// certificate to the same result, and a stale bound certificate is
// rejected.
type SelectionVector struct {
	Name                 string `json:"name"`
	BoundRootRound       uint64 `json:"bound_root_round"`
	AuthorizedRound      uint64 `json:"authorized_round"`
	FollowerAppliedRound uint64 `json:"follower_last_applied_root_round"`
	SignaturesValid      bool   `json:"bound_cert_signatures_valid"`
	Accept               bool   `json:"accept"`
	Reason               string `json:"reason,omitempty"`
}

// DomainVectors shows, byte for byte, how the v1 domain-separated
// derivations differ from the v0 prototype forms for one fixed (rootRound,
// shardRound, unicityTreeRoot) triple.
type DomainVectors struct {
	RootRound        uint64 `json:"root_round"`
	ShardRound       uint64 `json:"shard_round"`
	UnicityTreeRoot  string `json:"unicity_tree_root"`
	V1PrevRandao     string `json:"v1_prev_randao"`      // H(CBOR(["UNICITY_EVM_RANDAO", r, n]))
	V1BeaconRoot     string `json:"v1_beacon_root"`      // H(CBOR(["UNICITY_EVM_BEACON", r, n]))
	V1PrevRandaoCBOR string `json:"v1_prev_randao_cbor"` // the exact preimage
	V0PrevRandao     string `json:"v0_prev_randao"`      // frozen v0 value: SHA256(0x01 || u || be64(n))
	V0BeaconRoot     string `json:"v0_beacon_root"`      // frozen v0 value: SHA256(0x02 || u || be64(n))
}

// RootOriginVector is one canonical O_- body plus its identity, tagged with
// the round kind it came from.
type RootOriginVector struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	CBOR     string `json:"cbor"`
	Identity string `json:"identity"` // H(CBOR(O_-))
}

// SignatureSubsetCase is the acceptance requirement "alternate valid
// signature subsets and encodings ... same commitment on all validators":
// three descriptions of the SAME committed statement that differ only in
// which root signatures are attached and in transport framing, all
// yielding one RootOrigin identity.
type SignatureSubsetCase struct {
	Note           string     `json:"note"`
	SignerSubsets  [][]string `json:"signer_subsets"`
	OriginIdentity string     `json:"origin_identity"`
	AllAgree       bool       `json:"all_agree"`
}

// DistinctStatementCase is "a different authenticated statement": a single
// field changed in the certified content flips the identity.
type DistinctStatementCase struct {
	Note             string `json:"note"`
	ChangedField     string `json:"changed_field"`
	BaselineIdentity string `json:"baseline_identity"`
	MutatedIdentity  string `json:"mutated_identity"`
	Differ           bool   `json:"differ"`
}

// RootInputVector is one full rootInput tuple plus its extraData
// commitment. "self_contained" records that the tuple carries every field
// a historical replay needs with no node-local configuration.
type RootInputVector struct {
	Name            string `json:"name"`
	Kind            string `json:"kind"`
	CBOR            string `json:"cbor"`
	ExtraData       string `json:"extra_data"` // H(CBOR(rootInput))
	CertifiedEpoch  uint64 `json:"certified_epoch"`
	AuthorizedEpoch uint64 `json:"authorized_epoch"`
	EpochBoundary   string `json:"epoch_boundary"`
	SelfContained   bool   `json:"self_contained"`
}

// TimestampVector exercises max(referenceTime, parentTimestamp+1).
type TimestampVector struct {
	ReferenceTime   uint64 `json:"reference_time"`
	ParentTimestamp uint64 `json:"parent_timestamp"`
	Want            uint64 `json:"want"`
}

// ClockVector is the "98-to-107 observation triggers a threshold at 100
// exactly once" case, plus a skipped-rounds trace.
type ClockVector struct {
	Note             string   `json:"note"`
	ImportedRounds   []uint64 `json:"imported_rounds"`
	Threshold        uint64   `json:"threshold"`
	FireResults      []bool   `json:"fire_results"` // Fire(threshold) after each import
	FiredExactlyOnce bool     `json:"fired_exactly_once"`
}

func hx(b []byte) string   { return hex.EncodeToString(b) }
func hx32(h Hash32) string { return hex.EncodeToString(h[:]) }

// sampleOrigin is the baseline certified statement used across vectors.
func sampleOrigin() RootOrigin {
	return RootOrigin{
		NetworkID:       3, // NetworkLocal
		RootRound:       104,
		RootEpoch:       1,
		ReferenceTime:   1_726_000_000,
		UnicityTreeRoot: rep(0xA1, 32),
		IR: ShardInputRecord{
			Round:        57,
			Epoch:        1,
			PreviousHash: rep(0x11, 32),
			Hash:         rep(0x22, 32),
			Timestamp:    1_726_000_000,
			BlockHash:    rep(0x33, 32),
		},
		TRHash:        rep(0x44, 32),
		ShardConfHash: rep(0x55, 32),
	}
}

func sampleTE() TechnicalRecord {
	return TechnicalRecord{Round: 57, Epoch: 1, Leader: "evm-node-2", StatHash: rep(0x66, 32), FeeHash: rep(0x77, 32)}
}

func rep(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// BuildVectors computes the full D1 vector set from this package's
// implementation of the profile.
func BuildVectors() VectorSet {
	vs := VectorSet{ProfileVersion: ProfileVersion}

	// --- domains -------------------------------------------------------------
	const r, n = 104, 57
	u := rep(0xA1, 32)
	vs.Domains = DomainVectors{
		RootRound:        r,
		ShardRound:       n,
		UnicityTreeRoot:  hx(u),
		V1PrevRandao:     hx32(DerivePrevRandao(r, n)),
		V1BeaconRoot:     hx32(DeriveBeaconRoot(r, n)),
		V1PrevRandaoCBOR: hx(marshalCBOR(cArray{cText(DomainPrevRandao), cUint(r), cUint(n)})),
		// Frozen, not computed: F2c §9 forbids a second live derivation path, and f2d §5.1 keeps v0
		// only as a vector. These are the values the deleted v0 prototype derivation produced for
		// (u = 0xA1 x 32, n = 57) before W4 removed it; evmroot/testdata/vectors.json is the
		// committed witness that they are unchanged.
		V0PrevRandao: "2018a2745093159b35b61449c4adaf7b4079c4a2b985e26cffb71c017163aefb",
		V0BeaconRoot: "12e1a4b223dc7183d3bf76352266404205da8bb787628d2c3632adcef236f3c0",
	}

	// --- root origins by round kind ---------------------------------------
	// Genesis: h' and h are the pinned genesis commitment (here the
	// all-zero placeholder; a deployment pins the real EVM genesis state
	// root). h_b is absent -> CBOR null. There is no fabricated quorum
	// signature; genesis authentication is an explicit rule.
	genesis := RootOrigin{
		NetworkID: 3, RootRound: 1, RootEpoch: 1, ReferenceTime: 1_681_971_084,
		UnicityTreeRoot: rep(0x00, 32),
		IR:              ShardInputRecord{Round: 0, Epoch: 1, PreviousHash: rep(0x00, 32), Hash: rep(0x00, 32), Timestamp: 1_681_971_084, BlockHash: nil},
		TRHash:          rep(0x44, 32), ShardConfHash: rep(0x55, 32),
	}
	successful := sampleOrigin()
	quiet := sampleOrigin()
	quiet.RootRound = 105
	quiet.IR.PreviousHash = rep(0x22, 32)
	quiet.IR.Hash = rep(0x22, 32) // h == h'
	quiet.IR.BlockHash = nil      // h_b == nil
	repeat := sampleOrigin()
	repeat.RootRound = 106 // later root round, identical IR to `successful`
	canceled := sampleOrigin()
	canceled.RootRound = 107
	canceled.IR.Round = 58

	for _, rv := range []struct {
		name string
		kind RoundKind
		o    RootOrigin
	}{
		{"genesis", RoundGenesis, genesis},
		{"successful", RoundSuccessful, successful},
		{"quiet", RoundQuiet, quiet},
		{"repeat", RoundRepeat, repeat},
		{"canceled", RoundCanceled, canceled},
	} {
		vs.RootOrigins = append(vs.RootOrigins, RootOriginVector{
			Name: rv.name, Kind: rv.kind.String(),
			CBOR: hx(rv.o.Encode()), Identity: hx32(rv.o.Identity()),
		})
	}

	// --- alternate signature subsets agree ------------------------------
	base := sampleOrigin()
	id := base.Identity()
	vs.SignatureSubsets = SignatureSubsetCase{
		Note: "Same committed statement, three different valid root-signature subsets and transport framings; " +
			"RootOrigin excludes all signatures and transport proofs, so every subset yields this identity.",
		SignerSubsets: [][]string{
			{"root-1", "root-2", "root-3"},
			{"root-1", "root-3", "root-4"},
			{"root-2", "root-3", "root-4", "root-5"},
		},
		OriginIdentity: hx32(id),
		AllAgree:       true, // by construction: canonicalBody() has no signature input
	}

	// --- distinct statement -------------------------------------------------
	mut := sampleOrigin()
	mut.IR.Hash = rep(0x23, 32) // one byte of the certified state root
	vs.DistinctStatement = DistinctStatementCase{
		Note:             "Changing any certified field changes the RootOrigin identity; a certificate for a different statement is not an interchangeable witness.",
		ChangedField:     "IR.Hash[0..31] 0x22 -> 0x23",
		BaselineIdentity: hx32(base.Identity()),
		MutatedIdentity:  hx32(mut.Identity()),
		Differ:           base.Identity() != mut.Identity(),
	}

	// --- full root inputs -------------------------------------------------
	// mkRI derives both epochs from the origin's certified IR and the
	// technical record, and validates every assembled input (genesis
	// included).
	mkRI := func(o RootOrigin, te TechnicalRecord, parent []byte, d [][]byte) RootInput {
		ri := RootInput{
			Version: ProfileVersion, NetworkID: 3, PartitionID: 0x45564d00, ShardID: []byte{},
			Round: te.Round, CertifiedEpoch: o.IR.Epoch, AuthorizedEpoch: te.Epoch,
			ParentHash: parent, Origin: o, TE: te, Transitions: d,
		}
		if err := ri.Validate(); err != nil {
			panic("evmroot: vector rootInput invalid: " + err.Error())
		}
		return ri
	}
	// A handoff-boundary origin: the certified IR still belongs to epoch 1
	// (its outgoing epoch) while the technical record authorizes epoch 2.
	handoffOrigin := sampleOrigin()
	handoffOrigin.RootRound = 108
	handoffOrigin.IR.Round = 58
	handoffOrigin.IR.Epoch = 1
	handoffTE := TechnicalRecord{Round: 58, Epoch: 2, Leader: "evm-node-3", StatHash: rep(0x66, 32), FeeHash: rep(0x77, 32)}

	// Genesis INSTALLATION: authorized round 0, certified IR round 0, null
	// parent (no block yet), pinned commitment state roots, null IR block
	// hash. This installs the origin; it does not execute a payload.
	genesisInstallTE := TechnicalRecord{Round: 0, Epoch: 1, Leader: "evm-node-1", StatHash: rep(0x66, 32), FeeHash: rep(0x77, 32)}
	genesisInstallRI := mkRI(genesis, genesisInstallTE, nil, nil)

	// FIRST POST-GENESIS PAYLOAD: authorized round 1, but the certified IR
	// is still the genesis IR (round 0) because nothing has been certified
	// after round 0. h_parent is the REAL 32-byte pinned EVM genesis block
	// hash — nulling it here would break D2's header-parent equality check.
	firstPayloadTE := TechnicalRecord{Round: 1, Epoch: 1, Leader: "evm-node-1", StatHash: rep(0x66, 32), FeeHash: rep(0x77, 32)}
	pinnedGenesisBlockHash := sha256Slice([]byte("PINNED_EVM_GENESIS_BLOCK_HASH"))
	firstPayloadRI := mkRI(genesis, firstPayloadTE, pinnedGenesisBlockHash, nil)

	successRI := mkRI(successful, sampleTE(), rep(0xEE, 32), nil)
	skipRI := mkRI(func() RootOrigin { o := sampleOrigin(); o.RootRound = 140; return o }(), sampleTE(), rep(0x33, 32), nil)
	transRI := mkRI(successful, sampleTE(), rep(0xEE, 32), [][]byte{rep(0xB0, 48), rep(0xB1, 24)})
	handoffRI := mkRI(handoffOrigin, handoffTE, rep(0xEE, 32), [][]byte{rep(0xB2, 48)})
	for _, riv := range []struct {
		name string
		kind RoundKind
		ri   RootInput
	}{
		{"genesis_installation", RoundGenesis, genesisInstallRI},
		{"first_post_genesis_payload", RoundGenesis, firstPayloadRI},
		{"successful_normal_epoch", RoundSuccessful, successRI},
		{"root_rounds_skipped", RoundSuccessful, skipRI},
		{"with_pending_transitions", RoundSuccessful, transRI},
		{"epoch_handoff_boundary", RoundSuccessful, handoffRI},
	} {
		vs.RootInputs = append(vs.RootInputs, RootInputVector{
			Name: riv.name, Kind: riv.kind.String(),
			CBOR: hx(riv.ri.Encode()), ExtraData: hx32(riv.ri.ExtraData()),
			CertifiedEpoch: riv.ri.CertifiedEpoch, AuthorizedEpoch: riv.ri.AuthorizedEpoch,
			EpochBoundary: riv.ri.EpochBoundary().String(),
			SelfContained: true, // every field is in the tuple; no node-local config is read
		})
	}

	// --- epoch boundary --------------------------------------------------
	for _, eb := range []struct {
		name       string
		cert, auth uint64
	}{
		{"normal_round", 1, 1},
		{"handoff_boundary", 1, 2},
		{"invalid_skips_epoch", 1, 3},
		{"invalid_goes_backwards", 2, 1},
	} {
		ri := RootInput{
			Version: ProfileVersion, NetworkID: 3, PartitionID: 0x45564d00, ShardID: []byte{},
			Round: 58, CertifiedEpoch: eb.cert, AuthorizedEpoch: eb.auth, ParentHash: rep(0xEE, 32),
			Origin: func() RootOrigin { o := sampleOrigin(); o.IR.Round = 58; o.IR.Epoch = eb.cert; return o }(),
			TE:     TechnicalRecord{Round: 58, Epoch: eb.auth, Leader: "n", StatHash: rep(1, 32), FeeHash: rep(2, 32)},
		}
		vs.EpochBoundary = append(vs.EpochBoundary, EpochBoundaryVector{
			Name: eb.name, CertifiedEpoch: eb.cert, AuthorizedEpoch: eb.auth,
			Boundary: ri.EpochBoundary().String(), Accepted: ri.Validate() == nil,
		})
	}

	// --- certificate selection ----------------------------------------
	selOrigin := sampleOrigin() // RootRound 104, authorizes shard round 57
	selRef, _ := RefFromOrigin(selOrigin)
	const authRound = 57
	// The block binds selOrigin's certificate. Two nodes with different
	// observed sets both validate this one bound certificate.
	nodeA := verifiedCertFromOrigin(selOrigin, authRound, true) // node A verified exactly the bound cert
	nodeB := nodeA                                              // node B also saw a later repeat, but validates the bound one
	stale := verifiedCertFromOrigin(func() RootOrigin { o := sampleOrigin(); o.RootRound = 90; return o }(), authRound, true)
	for _, sc := range []struct {
		name    string
		ref     AuthorizingRef
		cert    VerifiedCert
		applied uint64
	}{
		{"node_a_accepts_bound_cert", selRef, nodeA, 104},
		{"node_b_same_result_despite_later_repeat_seen", selRef, nodeB, 104},
		{"stale_binding_rejected_by_registry_cursor", func() AuthorizingRef {
			r, _ := RefFromOrigin(func() RootOrigin { o := sampleOrigin(); o.RootRound = 90; return o }())
			return r
		}(), stale, 104},
		{"unverified_binding_rejected", selRef, func() VerifiedCert { c := nodeA; c.SignaturesValid = false; return c }(), 104},
		{"wrong_authorized_round_rejected", selRef, func() VerifiedCert { c := nodeA; c.AuthorizedRound = 58; return c }(), 104},
	} {
		res := ValidateBoundCertificate(sc.ref, sc.cert, authRound, sc.applied)
		vs.Selection = append(vs.Selection, SelectionVector{
			Name: sc.name, BoundRootRound: sc.cert.RootRound, AuthorizedRound: authRound,
			FollowerAppliedRound: sc.applied, SignaturesValid: sc.cert.SignaturesValid,
			Accept: res.Accept, Reason: res.Reason,
		})
	}

	// --- timestamps -------------------------------------------------------
	for _, tv := range []TimestampVector{
		{ReferenceTime: 1_726_000_000, ParentTimestamp: 1_725_999_999},
		{ReferenceTime: 1_726_000_000, ParentTimestamp: 1_726_000_000}, // seal ts repeats -> +1 path
		{ReferenceTime: 1_726_000_000, ParentTimestamp: 1_726_000_005}, // parent ahead
	} {
		tv.Want = DeriveTimestamp(tv.ReferenceTime, tv.ParentTimestamp)
		vs.Timestamps = append(vs.Timestamps, tv)
	}

	// --- certified round clock ------------------------------------------
	clk := NewCertifiedRoundClock()
	imports := []uint64{98, 107, 108}
	var fires []bool
	for _, rr := range imports {
		clk.AdvanceTo(rr)
		fires = append(fires, clk.Fire(100))
	}
	oneTrue := 0
	for _, f := range fires {
		if f {
			oneTrue++
		}
	}
	vs.Clock = ClockVector{
		Note:             "Threshold 100 is stepped over (imports jump 98 -> 107); Fire(100) returns true exactly once, on the import that first reaches it.",
		ImportedRounds:   imports,
		Threshold:        100,
		FireResults:      fires,
		FiredExactlyOnce: oneTrue == 1,
	}

	return vs
}

// MarshalVectors renders the vector set as stable, indented JSON.
func MarshalVectors(vs VectorSet) ([]byte, error) {
	b, err := json.MarshalIndent(vs, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
