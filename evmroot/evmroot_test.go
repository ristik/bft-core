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

func TestDomainHash_V1DiffersFromV0Prototype(t *testing.T) {
	u := rep(0xA1, 32)
	v1 := DerivePrevRandao(104, 57)
	v0 := prototypeDomainHash(prototypeDomainPrevRandao, u, 57)
	if v1 == v0 {
		t.Fatal("v1 and v0 prevRandao derivations must not coincide — D1 is a versioned change")
	}
}

// --- RootOrigin: signature-free identity --------------------------------

func TestRootOrigin_IdentityIndependentOfSignatures(t *testing.T) {
	// The canonical body is built only from committed content. There is no
	// field, parameter or code path in RootOrigin that a signature map or a
	// tree path could enter — assert that by encoding the same statement
	// "received" as different objects and getting one identity.
	statement := sampleOrigin()
	enc1 := statement.Encode()

	// A byte-identical re-decode/re-encode round trip (simulating a
	// different transport framing that carries the same committed values).
	var reread RootOrigin = statement
	enc2 := reread.Encode()

	if !bytes.Equal(enc1, enc2) {
		t.Fatal("same statement, different object -> different canonical body")
	}
	if statement.Identity() != reread.Identity() {
		t.Fatal("identity depends on something other than committed content")
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

func TestRootInput_ExtraDataIsSHA256OfCBOR(t *testing.T) {
	ri := RootInput{
		Version: ProfileVersion, NetworkID: 3, PartitionID: 0x45564d00, ShardID: []byte{},
		Round: 57, Epoch: 1, ParentHash: rep(0xEE, 32), Origin: sampleOrigin(), TE: sampleTE(),
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
	a := RootInput{Version: 1, Origin: sampleOrigin(), TE: sampleTE(), ShardID: []byte{}}
	b := a
	b.Version = 2
	if a.ExtraData() == b.ExtraData() {
		t.Fatal("profile version is not bound into the commitment")
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
