package evmroot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
)

// --- CBOR encoder: pin against RFC 8949 examples ---------------------------

func TestCBOR_RFC8949Examples(t *testing.T) {
	cases := []struct {
		item cborItem
		want string
	}{
		{cUint(0), "00"},
		{cUint(23), "17"},
		{cUint(24), "1818"},
		{cUint(255), "18ff"},
		{cUint(256), "190100"},
		{cUint(1000000), "1a000f4240"},
		{cUint(1000000000000), "1b000000e8d4a51000"},
		{cBytes(nil), "40"},
		{cBytes{1, 2, 3, 4}, "4401020304"},
		{cText(""), "60"},
		{cText("a"), "6161"},
		{cText("IETF"), "6449455446"},
		{cArray{}, "80"},
		{cArray{cUint(1), cUint(2), cUint(3)}, "83010203"},
	}
	for _, c := range cases {
		if got := hex.EncodeToString(marshalCBOR(c.item)); got != c.want {
			t.Errorf("encode(%v) = %s, want %s", c.item, got, c.want)
		}
	}
}

func TestCBOR_ArrayLengthHeadsAreShortest(t *testing.T) {
	// 24-element array must use the 1-byte-arg head 0x98, not 0x9818xx etc.
	big := make(cArray, 24)
	for i := range big {
		big[i] = cUint(0)
	}
	enc := marshalCBOR(big)
	if enc[0] != 0x98 || enc[1] != 24 {
		t.Fatalf("24-element array head = % x, want 98 18", enc[:2])
	}
}

// --- domain separation: v1 form, and its distinction from v0 -------------

func TestDomainHash_Deterministic(t *testing.T) {
	a := DerivePrevRandao(104, 57)
	b := DerivePrevRandao(104, 57)
	if a != b {
		t.Fatal("DerivePrevRandao not deterministic")
	}
	// preimage is exactly CBOR(["UNICITY_EVM_RANDAO", 104, 57])
	want := sha256.Sum256(marshalCBOR(cArray{cText(DomainPrevRandao), cUint(104), cUint(57)}))
	if a != Hash32(want) {
		t.Fatalf("prevRandao preimage mismatch: %x vs %x", a, want)
	}
}

func TestDomainHash_RandaoAndBeaconDiffer(t *testing.T) {
	if DerivePrevRandao(1, 1) == DeriveBeaconRoot(1, 1) {
		t.Fatal("prevRandao and parentBeaconBlockRoot collide for the same (r,n)")
	}
}

func TestDomainHash_UsesBothCounters(t *testing.T) {
	// v1 keys off (rootRound, shardRound); swapping them must change the output.
	if DerivePrevRandao(104, 57) == DerivePrevRandao(57, 104) {
		t.Fatal("derivation is symmetric in (r,n) — it must not be")
	}
}

// TestDomainHash_V1DiffersFromFrozenV0Vector compares the live v1 derivation against the frozen v0
// literal, not against live v0 code: F2c §9 forbids a second live derivation path, and f2d §5.1
// keeps v0 only as a vector. The literal is the v0 value for (u = 0xA1 x 32, n = 57), committed in
// evmroot/testdata/vectors.json.
func TestDomainHash_V1DiffersFromFrozenV0Vector(t *testing.T) {
	const frozenV0PrevRandao = "2018a2745093159b35b61449c4adaf7b4079c4a2b985e26cffb71c017163aefb"
	v1 := DerivePrevRandao(104, 57)
	if hx32(v1) == frozenV0PrevRandao {
		t.Fatal("v1 and the frozen v0 prevRandao derivations must not coincide — D1 is a versioned change")
	}
}

// --- RootOrigin: signature-free identity --------------------------------

func TestRootOrigin_StructuralIndependenceFromSignatures(t *testing.T) {
	// Structural check: canonicalBody has no field a signature map or tree
	// path could enter. The real signed-fixture proof is in
	// d1fixtures_test.go TestRootOrigin_TwoValidSignatureSubsetsAgree.
	statement := sampleOrigin()
	if !bytes.Equal(statement.Encode(), statement.Encode()) {
		t.Fatal("encoding not deterministic")
	}
	if err := statement.Validate(); err != nil {
		t.Fatalf("sample origin invalid: %v", err)
	}
}

func TestRootOrigin_DistinctStatementDistinctIdentity(t *testing.T) {
	a := sampleOrigin()
	b := sampleOrigin()
	b.IR.Hash = rep(0x23, 32)
	if a.Identity() == b.Identity() {
		t.Fatal("changing the certified state root did not change the identity")
	}
}

func TestRootOrigin_AllRoundKindsEncode(t *testing.T) {
	vs := BuildVectors()
	seen := map[string]string{}
	for _, rv := range vs.RootOrigins {
		if rv.CBOR == "" || rv.Identity == "" {
			t.Fatalf("%s: empty encoding", rv.Name)
		}
		if prev, ok := seen[rv.Identity]; ok {
			t.Fatalf("%s and %s share an identity %s", prev, rv.Name, rv.Identity)
		}
		seen[rv.Identity] = rv.Name
	}
	if len(seen) != 5 {
		t.Fatalf("expected 5 distinct round-kind origins, got %d", len(seen))
	}
}

// --- RootInput: extraData commitment, self-containment ------------------

func sampleRootInput() RootInput {
	o := sampleOrigin()
	return RootInput{
		Version: ProfileVersion, NetworkID: 3, PartitionID: 0x45564d00, ShardID: []byte{},
		Round: 57, CertifiedEpoch: o.IR.Epoch, AuthorizedEpoch: sampleTE().Epoch,
		ParentHash: rep(0xEE, 32), Origin: o, TE: sampleTE(),
	}
}

func TestRootInput_ExtraDataIsSHA256OfCBOR(t *testing.T) {
	ri := sampleRootInput()
	if err := ri.Validate(); err != nil {
		t.Fatalf("sample rootInput invalid: %v", err)
	}
	want := sha256.Sum256(ri.Encode())
	if ri.ExtraData() != Hash32(want) {
		t.Fatal("ExtraData is not H(CBOR(rootInput))")
	}
	if len(ri.ExtraData()) != 32 {
		t.Fatal("extraData commitment must be 32 bytes")
	}
}

func TestRootInput_VersionIsCommitted(t *testing.T) {
	a := sampleRootInput()
	b := a
	b.Version = 2
	if a.ExtraData() == b.ExtraData() {
		t.Fatal("profile version is not bound into the commitment")
	}
}

func TestRootInput_EpochBoundaryNotEqualityImposed(t *testing.T) {
	// A normal round has equal epochs.
	if sampleRootInput().EpochBoundary() != EpochNormal {
		t.Fatal("normal round not classified normal")
	}
	// The handoff boundary — certified epoch 1, authorized epoch 2 — is
	// accepted, not rejected. This is the sharding.go nextBlock case
	// (prevSI.TR.Epoch != prevSI.IR.Epoch).
	h := sampleRootInput()
	h.Round, h.CertifiedEpoch, h.AuthorizedEpoch = 58, 1, 2
	h.Origin.IR.Round, h.Origin.IR.Epoch = 58, 1
	h.TE = TechnicalRecord{Round: 58, Epoch: 2, Leader: "n", StatHash: rep(1, 32), FeeHash: rep(2, 32)}
	if h.EpochBoundary() != EpochHandoff {
		t.Fatalf("handoff boundary misclassified as %s", h.EpochBoundary())
	}
	if err := h.Validate(); err != nil {
		t.Fatalf("handoff-boundary rootInput rejected: %v", err)
	}
	// Two epochs apart, or backwards, is invalid.
	for _, bad := range [][2]uint64{{1, 3}, {2, 1}, {5, 0}} {
		x := sampleRootInput()
		x.CertifiedEpoch, x.AuthorizedEpoch = bad[0], bad[1]
		x.Origin.IR.Epoch = bad[0]
		x.TE.Epoch = bad[1]
		if x.EpochBoundary() != EpochInvalid || x.Validate() == nil {
			t.Fatalf("epochs %v accepted", bad)
		}
	}
}

func TestRootInput_RejectsMalformedWidths(t *testing.T) {
	base := sampleRootInput()
	for _, m := range []struct {
		name string
		mut  func(*RootInput)
	}{
		{"short unicity tree root", func(r *RootInput) { r.Origin.UnicityTreeRoot = rep(1, 31) }},
		{"long TRHash", func(r *RootInput) { r.Origin.TRHash = rep(1, 33) }},
		{"short IR.Hash", func(r *RootInput) { r.Origin.IR.Hash = rep(1, 16) }},
		{"non-genesis nil parent", func(r *RootInput) { r.ParentHash = nil }},
		{"quiet round with block hash", func(r *RootInput) {
			r.Origin.IR.Hash = rep(0x11, 32) // == PreviousHash -> quiet
			r.Origin.IR.BlockHash = rep(0x33, 32)
		}},
		{"empty transition entry", func(r *RootInput) { r.Transitions = [][]byte{{}} }},
	} {
		ri := base
		ri.Origin.IR.PreviousHash = rep(0x11, 32)
		ri.Origin.IR.Hash = rep(0x22, 32)
		m.mut(&ri)
		if err := ri.Validate(); err == nil {
			t.Errorf("%s: Validate accepted a malformed input", m.name)
		}
	}
}

// --- timestamp --------------------------------------------------------------

func TestDeriveTimestamp(t *testing.T) {
	if got := DeriveTimestamp(1000, 500); got != 1000 {
		t.Errorf("reference ahead: got %d want 1000", got)
	}
	if got := DeriveTimestamp(1000, 1000); got != 1001 {
		t.Errorf("equal -> +1: got %d want 1001", got)
	}
	if got := DeriveTimestamp(1000, 1005); got != 1006 {
		t.Errorf("parent ahead: got %d want 1006", got)
	}
}

// --- certified round clock ------------------------------------------------

func TestCertifiedRoundClock_FiresOnceAcrossSkippedRounds(t *testing.T) {
	c := NewCertifiedRoundClock()
	got := []bool{}
	for _, rr := range []uint64{98, 107, 108} {
		c.AdvanceTo(rr)
		got = append(got, c.Fire(100))
	}
	want := []bool{false, true, false}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Fire results %v, want %v", got, want)
		}
	}
}

func TestCertifiedRoundClock_DuplicateImportIsNoOp(t *testing.T) {
	c := NewCertifiedRoundClock()
	c.AdvanceTo(100)
	c.AdvanceTo(100)
	if !c.Fire(100) || c.Fire(100) {
		t.Fatal("duplicate same-round import broke single-fire semantics")
	}
}

func TestCertifiedRoundClock_BackwardsPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("moving the clock backwards did not panic")
		}
	}()
	c := NewCertifiedRoundClock()
	c.AdvanceTo(107)
	c.AdvanceTo(100) // selecting a certificate by local arrival, not by authorization
}

// --- golden file --------------------------------------------------------

func TestVectorsMatchGolden(t *testing.T) {
	const path = "testdata/vectors.json"
	got, err := MarshalVectors(BuildVectors())
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s (run: go run ./evmroot/cmd/d1vectors -update): %v", path, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale — regenerate with: go run ./evmroot/cmd/d1vectors -update", path)
	}
}
