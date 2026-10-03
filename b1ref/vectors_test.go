package b1ref_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/unicitynetwork/bft-core/b1ref"
	"github.com/unicitynetwork/bft-core/b1ref/b1gen"
)

const (
	goldenPath = "testdata/b1-vectors-v1.json"
	goldenSeed = "b1-oracle-v1"
)

var update = flag.Bool("update", false, "rewrite the golden vector manifest")

// sentinels maps the manifest's sentinel names to the oracle's errors.
var sentinels = map[string]error{
	"ErrTruncated": b1ref.ErrTruncated, "ErrTrailingBytes": b1ref.ErrTrailingBytes, "ErrVersion": b1ref.ErrVersion,
	"ErrFlags": b1ref.ErrFlags, "ErrCount": b1ref.ErrCount, "ErrNonCanonical": b1ref.ErrNonCanonical,
	"ErrDuplicateMapKey": b1ref.ErrDuplicateMapKey, "ErrForbiddenCBOR": b1ref.ErrForbiddenCBOR,
	"ErrInvalidUTF8": b1ref.ErrInvalidUTF8, "ErrShape": b1ref.ErrShape, "ErrShardEncoding": b1ref.ErrShardEncoding,
	"ErrRSMTLength": b1ref.ErrRSMTLength, "ErrInputTooLarge": b1ref.ErrInputTooLarge, "ErrUCTooLarge": b1ref.ErrUCTooLarge,
	"ErrViewTooLarge": b1ref.ErrViewTooLarge, "ErrTooManyMembers": b1ref.ErrTooManyMembers, "ErrTooManySigs": b1ref.ErrTooManySigs,
	"ErrNodeIDTooLong": b1ref.ErrNodeIDTooLong, "ErrShardTooDeep": b1ref.ErrShardTooDeep, "ErrTooManySiblings": b1ref.ErrTooManySiblings,
	"ErrTooManySteps": b1ref.ErrTooManySteps, "ErrDepth": b1ref.ErrDepth, "ErrSummaryTooLong": b1ref.ErrSummaryTooLong,
	"ErrValueTooLarge": b1ref.ErrValueTooLarge,
	"ErrUnknownEpoch":  b1ref.ErrUnknownEpoch, "ErrViewHash": b1ref.ErrViewHash, "ErrBodyID": b1ref.ErrBodyID,
	"ErrNetwork": b1ref.ErrNetwork, "ErrSealEpoch": b1ref.ErrSealEpoch, "ErrOpenInterval": b1ref.ErrOpenInterval,
	"ErrBeforeStart": b1ref.ErrBeforeStart, "ErrAfterEnd": b1ref.ErrAfterEnd, "ErrFuture": b1ref.ErrFuture,
	"ErrStale": b1ref.ErrStale, "ErrWeightProfile": b1ref.ErrWeightProfile, "ErrViewDuplicate": b1ref.ErrViewDuplicate,
	"ErrPartition": b1ref.ErrPartition, "ErrShard": b1ref.ErrShard, "ErrShardConf": b1ref.ErrShardConf,
	"ErrTreeRoot": b1ref.ErrTreeRoot, "ErrStateRoot": b1ref.ErrStateRoot, "ErrIRHash": b1ref.ErrIRHash,
	"ErrSealMismatch": b1ref.ErrSealMismatch, "ErrUnknownSigner": b1ref.ErrUnknownSigner, "ErrSigFormat": b1ref.ErrSigFormat,
	"ErrSigRange": b1ref.ErrSigRange, "ErrSigInvalid": b1ref.ErrSigInvalid, "ErrQuorum": b1ref.ErrQuorum,
	"ErrRSMTZeroRoot": b1ref.ErrRSMTZeroRoot, "ErrRSMTFold": b1ref.ErrRSMTFold,
	"ErrDuplicateClaim": b1ref.ErrDuplicateClaim, "ErrClaimOrder": b1ref.ErrClaimOrder, "ErrViewOrder": b1ref.ErrViewOrder,
	"ErrViewKey": b1ref.ErrViewKey, "ErrViewKind": b1ref.ErrViewKind, "ErrViewEmpty": b1ref.ErrViewEmpty,
	"ErrNativeInvalid": b1ref.ErrNativeInvalid,
}

// notInVectors are reasons no manifest vector can reach: ErrTokens is
// subsumed by the byte bounds (unit-tested on the scanner), and the rest
// guard against native encoder/decoder failures on input the shape rules
// already admitted.
var notInVectors = map[string]bool{"ErrTokens": true, "ErrNativeDecode": true, "ErrReencode": true, "ErrFold": true}

func loadGolden(t testing.TB) (*b1gen.Manifest, []byte) {
	t.Helper()
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden manifest (go test ./b1ref -update): %v", err)
	}
	var m b1gen.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return &m, raw
}

func registry(t testing.TB, p *b1gen.PreState) *b1ref.Registry {
	t.Helper()
	if p == nil {
		return nil
	}
	reg := &b1ref.Registry{Network: p.Network, WCert: p.WCert, Origin: p.Origin, RootRound: p.ClockRound, Epochs: map[uint64]b1ref.EpochEntry{}}
	for _, e := range p.Epochs {
		vh, _ := hex.DecodeString(e.ViewHash)
		bi, _ := hex.DecodeString(e.BodyID)
		var ent b1ref.EpochEntry
		copy(ent.ViewHash[:], vh)
		copy(ent.BodyID[:], bi)
		ent.Start, ent.End = e.Start, e.End
		reg.Epochs[e.Epoch] = ent
	}
	return reg
}

func op(v b1gen.Vector) b1ref.Op {
	switch v.Op {
	case "UC_V1":
		return b1ref.OpUC
	case "SHARED_SEAL_V1":
		return b1ref.OpShared
	}
	return b1ref.OpMember
}

func evaluate(t testing.TB, v b1gen.Vector) (b1ref.Verdict, error) {
	t.Helper()
	req, err := hex.DecodeString(v.Request)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry(t, v.PreState)
	switch op(v) {
	case b1ref.OpUC:
		return b1ref.UC(req, reg)
	case b1ref.OpShared:
		return b1ref.Shared(req, reg)
	}
	return b1ref.Member(req)
}

// TestGoldenVectors runs every committed vector through the oracle and checks
// status, validity, the named sentinel, the returndata words and the gas.
func TestGoldenVectors(t *testing.T) {
	m, _ := loadGolden(t)
	if m.Format != b1gen.FormatVersion || m.Seed != goldenSeed {
		t.Fatalf("manifest %q seed %q", m.Format, m.Seed)
	}
	for _, v := range m.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			want, ok := sentinels[v.Expected.Sentinel]
			if v.Expected.Sentinel != "" && !ok {
				t.Fatalf("unknown sentinel name %q", v.Expected.Sentinel)
			}
			got, err := evaluate(t, v)
			switch v.Expected.Status {
			case "error":
				if err == nil {
					t.Fatalf("expected %s, got verdict %+v", v.Expected.Sentinel, got)
				}
				if !errors.Is(err, want) || !errors.Is(err, b1ref.ErrMalformed) || errors.Is(err, b1ref.ErrInvalid) {
					t.Fatalf("expected %s (malformed family), got %v", v.Expected.Sentinel, err)
				}
			case "ok":
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if got.Valid != *v.Expected.Valid {
					t.Fatalf("valid=%v want %v (why: %v)", got.Valid, *v.Expected.Valid, got.Why)
				}
				if got.Valid != (got.Why == nil) {
					t.Fatalf("valid=%v with why=%v", got.Valid, got.Why)
				}
				if want != nil && (!errors.Is(got.Why, want) || !errors.Is(got.Why, b1ref.ErrInvalid)) {
					t.Fatalf("expected false reason %s, got %v", v.Expected.Sentinel, got.Why)
				}
				if got.Gas != v.Expected.Gas {
					t.Fatalf("gas %d want %d", got.Gas, v.Expected.Gas)
				}
				if hex.EncodeToString(b1ref.Output(got.Valid)) != v.Expected.Output {
					t.Fatalf("output words differ")
				}
			default:
				t.Fatalf("status %q", v.Expected.Status)
			}
		})
	}
}

// TestGeneratorDeterministic requires two runs to agree byte for byte and the
// committed manifest to be exactly the generator's output for its seed.
func TestGeneratorDeterministic(t *testing.T) {
	a, err := b1gen.Build(goldenSeed).JSON()
	if err != nil {
		t.Fatal(err)
	}
	b, err := b1gen.Build(goldenSeed).JSON()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("two runs of the generator differ")
	}
	other, _ := b1gen.Build(goldenSeed + "x").JSON()
	if bytes.Equal(a, other) {
		t.Fatal("the seed does not reach the output")
	}
	if *update {
		if err := os.WriteFile(goldenPath, a, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, golden := loadGolden(t)
	if !bytes.Equal(a, golden) {
		t.Fatalf("committed %s is stale: regenerate with go test ./b1ref -update", goldenPath)
	}
}

// TestManifestCoversFamilies checks every non-deferred row of section 5 has
// vectors and every deferred one is marked.
func TestManifestCoversFamilies(t *testing.T) {
	m, _ := loadGolden(t)
	fams := map[string]int{}
	for _, v := range m.Vectors {
		fams[v.Family]++
	}
	for _, f := range []string{"Native certificates", "Quorum", "Time/history", "Paths/encoding", "Gas/resources"} {
		if fams[f] == 0 {
			t.Errorf("no vectors for family %q", f)
		}
	}
	if len(m.Deferred) == 0 {
		t.Error("deferred rows are not marked")
	}
	for _, d := range m.Deferred {
		if !strings.Contains(d.Reason, "layout-3") && !strings.Contains(d.Reason, "EVM") {
			t.Errorf("deferred row %q has no dependency reason", d.Row)
		}
	}
	// every false/error sentinel the oracle can name for a single perturbation is exercised
	seen := map[string]bool{}
	for _, v := range m.Vectors {
		seen[v.Expected.Sentinel] = true
	}
	for name := range sentinels {
		if !seen[name] {
			t.Errorf("sentinel %s has no vector", name)
		}
	}
}

// TestRunGas checks the charge boundary: the exact charge succeeds and one
// less fails with all forwarded gas consumed.
func TestRunGas(t *testing.T) {
	m, _ := loadGolden(t)
	checked := 0
	for _, v := range m.Vectors {
		if v.Expected.Status != "ok" || checked >= 12 && !strings.HasPrefix(v.ID, "quorum.max") {
			continue
		}
		checked++
		req, _ := hex.DecodeString(v.Request)
		reg := registry(t, v.PreState)
		out, used, err := b1ref.Run(op(v), req, reg, v.Expected.Gas)
		if err != nil || used != v.Expected.Gas || hex.EncodeToString(out) != v.Expected.Output {
			t.Fatalf("%s: exact charge: out=%x used=%d err=%v", v.ID, out, used, err)
		}
		out, used, err = b1ref.Run(op(v), req, reg, v.Expected.Gas-1)
		if !errors.Is(err, b1ref.ErrOutOfGas) || out != nil || used != v.Expected.Gas-1 {
			t.Fatalf("%s: charge-1: out=%x used=%d err=%v", v.ID, out, used, err)
		}
	}
	// malformed input consumes everything forwarded.
	for _, v := range m.Vectors {
		if v.Expected.Status != "error" {
			continue
		}
		req, _ := hex.DecodeString(v.Request)
		out, used, err := b1ref.Run(op(v), req, registry(t, v.PreState), 7_000_000)
		if err == nil || out != nil || used != 7_000_000 {
			t.Fatalf("%s: malformed must consume all gas: out=%x used=%d err=%v", v.ID, out, used, err)
		}
	}
}

// TestGasParity: an invalid last signature costs exactly what the valid call does.
func TestGasParity(t *testing.T) {
	m, _ := loadGolden(t)
	gas := map[string]uint64{}
	for _, v := range m.Vectors {
		gas[v.ID] = v.Expected.Gas
	}
	if gas["gas.4sigs.valid"] == 0 || gas["gas.4sigs.valid"] != gas["gas.4sigs.last-invalid"] {
		t.Fatalf("valid %d vs invalid-last %d", gas["gas.4sigs.valid"], gas["gas.4sigs.last-invalid"])
	}
}

// TestMaxGas pins the design's worst-case figures.
func TestMaxGas(t *testing.T) {
	if g := b1ref.UCGas(262144, 64, 64, 8, 2304); g != 5_294_304 {
		t.Fatalf("UC worst case %d", g)
	}
	if g := b1ref.RSMTGas(12392, 256); g != 264_522 {
		t.Fatalf("RSMT worst case %d", g)
	}
}

// TestRunOrder pins the order of the EVM-facing checks: the size bound, then
// the base-plus-bytes reservation, then parsing, then the full charge.
func TestRunOrder(t *testing.T) {
	m, _ := loadGolden(t)
	var good, malformed b1gen.Vector
	for _, v := range m.Vectors {
		switch v.ID {
		case "cert.single.ok":
			good = v
		case "enc.trailing":
			malformed = v
		}
	}
	req, _ := hex.DecodeString(good.Request)
	reg := registry(t, good.PreState)
	if _, used, err := b1ref.Run(b1ref.OpUC, make([]byte, b1ref.MaxCallBytes+1), reg, 10); !errors.Is(err, b1ref.ErrInputTooLarge) || used != 10 {
		t.Fatalf("oversized input with little gas: used=%d err=%v", used, err)
	}
	if _, _, err := b1ref.Run(b1ref.OpMember, make([]byte, b1ref.MaxRSMTInputBytes+1), nil, 10); !errors.Is(err, b1ref.ErrInputTooLarge) {
		t.Fatalf("oversized RSMT input: %v", err)
	}
	bad, _ := hex.DecodeString(malformed.Request)
	reserve := uint64(60000 + 16*len(bad))
	if _, used, err := b1ref.Run(b1ref.OpUC, bad, reg, reserve-1); !errors.Is(err, b1ref.ErrOutOfGas) || used != reserve-1 {
		t.Fatalf("below the reservation a malformed input is an out-of-gas, got used=%d err=%v", used, err)
	}
	if _, _, err := b1ref.Run(b1ref.OpUC, bad, reg, reserve); !errors.Is(err, b1ref.ErrMalformed) {
		t.Fatalf("at the reservation the input is parsed: %v", err)
	}
	if _, _, err := b1ref.Run(b1ref.OpUC, req, reg, good.Expected.Gas-1); !errors.Is(err, b1ref.ErrOutOfGas) {
		t.Fatalf("below the full charge: %v", err)
	}
}

// TestInputNotMutated: the verdict must not depend on, or alter, the caller's
// bytes (the native bit string decoder works in place, so the shard bytes are
// decoded from a copy).
func TestInputNotMutated(t *testing.T) {
	m, _ := loadGolden(t)
	for _, v := range m.Vectors {
		req, _ := hex.DecodeString(v.Request)
		before := append([]byte{}, req...)
		first, err1 := evaluateBytes(t, v, req)
		if !bytes.Equal(req, before) {
			t.Fatalf("%s: input modified", v.ID)
		}
		second, err2 := evaluateBytes(t, v, req)
		if first != second || (err1 == nil) != (err2 == nil) {
			t.Fatalf("%s: verdict not repeatable", v.ID)
		}
	}
}

func evaluateBytes(t testing.TB, v b1gen.Vector, req []byte) (verdict [3]uint64, err error) {
	reg := registry(t, v.PreState)
	var r b1ref.Verdict
	switch op(v) {
	case b1ref.OpUC:
		r, err = b1ref.UC(req, reg)
	case b1ref.OpShared:
		r, err = b1ref.Shared(req, reg)
	default:
		r, err = b1ref.Member(req)
	}
	if r.Valid {
		verdict[0] = 1
	}
	verdict[1] = r.Gas
	return verdict, err
}

// TestRecoveryByteIsPolicy shows the v restriction is B1 policy: the native
// verifier accepts the same signature with v = 2 and 255, B1 does not.
func TestRecoveryByteIsPolicy(t *testing.T) {
	m, _ := loadGolden(t)
	seed := m.Seed
	val := b1gen.ValidatorForTest(seed, "node00")
	msg := []byte("seal bytes")
	sig := val.Sign(msg, false)
	ver, err := nativeVerifier(val.Pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []byte{0, 1, 2, 255} {
		if err := ver.VerifyBytes(append(append([]byte{}, sig...), v), msg); err != nil {
			t.Fatalf("native verifier rejects v=%d: %v", v, err)
		}
	}
	got := map[string]string{}
	for _, v := range m.Vectors {
		got[v.ID] = v.Expected.Sentinel
	}
	for _, id := range []string{"quorum.sig.v2", "quorum.sig.v255"} {
		if got[id] != "ErrSigFormat" {
			t.Fatalf("%s: B1 must reject, got %q", id, got[id])
		}
	}
}

// TestProvisionalMarking: every open item is exercised by a provisional
// vector, and no provisional mark names an unknown item.
func TestProvisionalMarking(t *testing.T) {
	m, _ := loadGolden(t)
	items := map[string]bool{}
	for _, o := range m.OpenItems {
		items[o.ID] = false
	}
	for _, v := range m.Vectors {
		if v.Provisional == "" {
			continue
		}
		if _, ok := items[v.Provisional]; !ok {
			t.Fatalf("%s names unknown open item %s", v.ID, v.Provisional)
		}
		items[v.Provisional] = true
	}
	for id, used := range items {
		if !used {
			t.Errorf("open item %s has no provisional vector", id)
		}
	}
	if len(m.Notes) == 0 {
		t.Error("manifest carries no notes")
	}
}
