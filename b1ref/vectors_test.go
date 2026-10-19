package b1ref_test

import (
	"bytes"
	"encoding/binary"
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
	goldenPath = "testdata/b1-vectors-anyage.json"
	goldenSeed = "b1-any-age-v1"
)

var update = flag.Bool("update", false, "rewrite the golden vector manifest")

// sentinels maps the manifest's sentinel names to the oracle's errors.
var sentinels = map[string]error{
	"ErrTruncated": b1ref.ErrTruncated, "ErrTrailingBytes": b1ref.ErrTrailingBytes, "ErrVersion": b1ref.ErrVersion,
	"ErrFlags": b1ref.ErrFlags, "ErrCount": b1ref.ErrCount, "ErrNonCanonical": b1ref.ErrNonCanonical,
	"ErrDuplicateMapKey": b1ref.ErrDuplicateMapKey, "ErrForbiddenCBOR": b1ref.ErrForbiddenCBOR,
	"ErrInvalidUTF8": b1ref.ErrInvalidUTF8, "ErrShape": b1ref.ErrShape, "ErrShardEncoding": b1ref.ErrShardEncoding,
	"ErrShardSiblings": b1ref.ErrShardSiblings,
	"ErrRSMTLength":    b1ref.ErrRSMTLength, "ErrInputTooLarge": b1ref.ErrInputTooLarge, "ErrUCTooLarge": b1ref.ErrUCTooLarge,
	"ErrTooManySigs":   b1ref.ErrTooManySigs,
	"ErrNodeIDTooLong": b1ref.ErrNodeIDTooLong, "ErrShardTooDeep": b1ref.ErrShardTooDeep, "ErrTooManySiblings": b1ref.ErrTooManySiblings,
	"ErrTooManySteps": b1ref.ErrTooManySteps, "ErrDepth": b1ref.ErrDepth, "ErrSummaryTooLong": b1ref.ErrSummaryTooLong,
	"ErrValueTooLarge": b1ref.ErrValueTooLarge,
	"ErrNetwork":       b1ref.ErrNetwork, "ErrEpochBeforeGenesis": b1ref.ErrEpochBeforeGenesis, "ErrEpochNotUsable": b1ref.ErrEpochNotUsable,
	"ErrOriginNotReady": b1ref.ErrOriginNotReady, "ErrPhase": b1ref.ErrPhase,
	"ErrBeforeStart": b1ref.ErrBeforeStart, "ErrAfterEnd": b1ref.ErrAfterEnd, "ErrFuture": b1ref.ErrFuture,
	"ErrPartition": b1ref.ErrPartition, "ErrShard": b1ref.ErrShard, "ErrShardConf": b1ref.ErrShardConf,
	"ErrTreeRoot": b1ref.ErrTreeRoot, "ErrStateRoot": b1ref.ErrStateRoot, "ErrIRHash": b1ref.ErrIRHash,
	"ErrUnknownSigner": b1ref.ErrUnknownSigner, "ErrSigFormat": b1ref.ErrSigFormat,
	"ErrSigRange": b1ref.ErrSigRange, "ErrSigInvalid": b1ref.ErrSigInvalid, "ErrQuorum": b1ref.ErrQuorum,
	"ErrRSMTZeroRoot": b1ref.ErrRSMTZeroRoot, "ErrRSMTFold": b1ref.ErrRSMTFold, "ErrNativeInvalid": b1ref.ErrNativeInvalid,
	"ErrRegistryCommon": b1ref.ErrRegistryCommon, "ErrRegistryMissingEpoch": b1ref.ErrRegistryMissingEpoch,
	"ErrRegistryInvalidEpoch": b1ref.ErrRegistryInvalidEpoch,
}

// notInVectors are reasons no manifest vector can reach: ErrTokens is subsumed by the byte bounds (unit-tested on the scanner),
// ErrCertSteps by K * (256 + 32) = 4,608, ErrClaimConflict needs two different valid claims for one shard under one seal (a hash
// collision; its precedence is unit-tested), ErrHost is the state reader failing, and the rest guard against native
// encoder/decoder failures on input the shape rules already admitted.
var notInVectors = map[string]bool{"ErrTokens": true, "ErrNativeDecode": true, "ErrReencode": true, "ErrFold": true,
	"ErrCertSteps": true, "ErrClaimConflict": true, "ErrHost": true}

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

// state is the vector's registry words as every implementation reads them, and the verifier's pin.
func state(t testing.TB, p *b1gen.PreState) (b1ref.State, b1ref.Pins) {
	t.Helper()
	if p == nil {
		return nil, b1ref.Pins{}
	}
	w := b1ref.Words{}
	for _, sw := range p.Storage {
		w[word32(t, sw.Slot)] = word32(t, sw.Value)
	}
	return w, b1ref.Pins{GenesisCommitment: word32(t, p.PinnedGenesisCommitment), ProfileHash: word32(t, p.PinnedProfileHash)}
}

func word32(t testing.TB, s string) (w [32]byte) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad word %q", s)
	}
	copy(w[:], b)
	return
}

func op(v b1gen.Vector) b1ref.Op {
	if v.Op == "RSMT_MEMBER_V1" {
		return b1ref.OpMember
	}
	return b1ref.OpCertBatch
}

func evaluate(t testing.TB, v b1gen.Vector) (b1ref.Verdict, error) {
	t.Helper()
	req, err := hex.DecodeString(v.Request)
	if err != nil {
		t.Fatal(err)
	}
	return evaluateBytes(t, v, req)
}

func evaluateBytes(t testing.TB, v b1gen.Vector, req []byte) (b1ref.Verdict, error) {
	if op(v) == b1ref.OpMember {
		return b1ref.Member(req)
	}
	st, pins := state(t, v.PreState)
	return b1ref.Cert(req, st, pins)
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
			case "registry":
				if !errors.Is(err, want) || !errors.Is(err, b1ref.ErrInfrastructure) || errors.Is(err, b1ref.ErrMalformed) {
					t.Fatalf("expected registry failure %s, got verdict %+v err %v", v.Expected.Sentinel, got, err)
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
				out := b1ref.Output(got.Valid)
				if op(v) == b1ref.OpMember {
					out = b1ref.MemberOutput(got.Valid)
				}
				if hex.EncodeToString(out) != v.Expected.Output {
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

// TestManifestCoversFamilies checks every family has vectors and every reachable sentinel is exercised.
func TestManifestCoversFamilies(t *testing.T) {
	m, _ := loadGolden(t)
	fams := map[string]int{}
	for _, v := range m.Vectors {
		fams[v.Family]++
	}
	for _, f := range []string{"Native certificates", "Quorum", "Time/history", "Registry", "Reuse", "Topology", "Paths/encoding", "Gas/resources"} {
		if fams[f] == 0 {
			t.Errorf("no vectors for family %q", f)
		}
	}
	if len(m.Deferred) == 0 {
		t.Error("deferred rows are not marked")
	}
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

// TestRunGas checks the debit boundary on every structurally accepted certificate vector: at the exact charge the call returns its
// result (or its infrastructure failure, used 0), and one less is out of gas with all forwarded gas consumed and no work done.
// Malformed input consumes everything forwarded.
func TestRunGas(t *testing.T) {
	m, _ := loadGolden(t)
	for _, v := range m.Vectors {
		req, _ := hex.DecodeString(v.Request)
		st, pins := state(t, v.PreState)
		switch v.Expected.Status {
		case "ok", "registry":
			counts := countWork(t)
			out, used, err := b1ref.Run(op(v), req, st, pins, v.Expected.Gas-1)
			if !errors.Is(err, b1ref.ErrOutOfGas) || out != nil || used != v.Expected.Gas-1 || len(counts) != 0 {
				t.Fatalf("%s: charge-1: out=%x used=%d err=%v work=%v", v.ID, out, used, err, counts)
			}
			out, used, err = b1ref.Run(op(v), req, st, pins, v.Expected.Gas)
			if v.Expected.Status == "registry" {
				if !errors.Is(err, b1ref.ErrInfrastructure) || used != 0 || out != nil {
					t.Fatalf("%s: exact charge: out=%x used=%d err=%v", v.ID, out, used, err)
				}
				continue
			}
			if err != nil || used != v.Expected.Gas || hex.EncodeToString(out) != v.Expected.Output {
				t.Fatalf("%s: exact charge: out=%x used=%d err=%v", v.ID, out, used, err)
			}
		case "error":
			out, used, err := b1ref.Run(op(v), req, st, pins, 7_000_000)
			if err == nil || out != nil || used != 7_000_000 {
				t.Fatalf("%s: malformed must consume all gas: out=%x used=%d err=%v", v.ID, out, used, err)
			}
			if want := sentinels[v.Expected.Sentinel]; want == nil || !errors.Is(err, want) || !errors.Is(err, b1ref.ErrMalformed) {
				t.Fatalf("%s: Run returned %v, want %s in the malformed family", v.ID, err, v.Expected.Sentinel)
			}
		}
	}
}

// TestCounters: every valid certificate vector does exactly the work the manifest names, so native implementations can assert the
// same reuse with their own counters.
func TestCounters(t *testing.T) {
	m, _ := loadGolden(t)
	n := 0
	for _, v := range m.Vectors {
		if v.Op != "CERT_BATCH_V2" || v.Expected.Counters == nil {
			continue
		}
		counts := countWork(t)
		if _, err := evaluate(t, v); err != nil {
			t.Fatal(v.ID, err)
		}
		for kind, want := range v.Expected.Counters {
			if counts[kind] != want {
				t.Errorf("%s: %s = %d, want %d", v.ID, kind, counts[kind], want)
			}
		}
		if len(counts) != len(v.Expected.Counters) {
			t.Errorf("%s: counted %v, manifest names %v", v.ID, counts, v.Expected.Counters)
		}
		n++
	}
	if n < 20 {
		t.Fatalf("only %d vectors carry counters", n)
	}
}

// TestPermutationInvariance: reversing the claim order of a multi-claim vector keeps its verdict and gas (the reason may differ
// when several checks fail).
func TestPermutationInvariance(t *testing.T) {
	m, _ := loadGolden(t)
	n := 0
	for _, v := range m.Vectors {
		if v.Op != "CERT_BATCH_V2" || v.Expected.Status != "ok" || v.Expected.Grouping == nil || v.Expected.Grouping.K < 2 {
			continue
		}
		req, _ := hex.DecodeString(v.Request)
		rev := reverseClaims(t, req)
		a, err1 := evaluateBytes(t, v, req)
		b, err2 := evaluateBytes(t, v, rev)
		if err1 != nil || err2 != nil || a.Valid != b.Valid || a.Gas != b.Gas {
			t.Fatalf("%s: %+v/%v reversed %+v/%v", v.ID, a, err1, b, err2)
		}
		n++
	}
	if n < 10 {
		t.Fatalf("only %d multi-claim vectors", n)
	}
}

func reverseClaims(t *testing.T, req []byte) []byte {
	k := int(binary.BigEndian.Uint16(req[2:4]))
	var claims [][]byte
	pos := 4
	for i := 0; i < k; i++ {
		start := pos
		sl := int(binary.BigEndian.Uint16(req[pos+4:]))
		pos += 6 + sl + 96
		pos += 4 + int(binary.BigEndian.Uint32(req[pos:]))
		claims = append(claims, req[start:pos])
	}
	out := append([]byte{}, req[:4]...)
	for i := k - 1; i >= 0; i-- {
		out = append(out, claims[i]...)
	}
	if len(out) != len(req) {
		t.Fatal("reverse lost bytes")
	}
	return out
}

// TestGasParity: an invalid last signature costs exactly what the valid call does, and the per-epoch charge is the 16-member
// ceiling whatever the entry's size.
func TestGasParity(t *testing.T) {
	m, _ := loadGolden(t)
	gas := map[string]uint64{}
	for _, v := range m.Vectors {
		gas[v.ID] = v.Expected.Gas
	}
	if gas["gas.4sigs.valid"] == 0 || gas["gas.4sigs.valid"] != gas["gas.4sigs.last-invalid"] {
		t.Fatalf("valid %d vs invalid-last %d", gas["gas.4sigs.valid"], gas["gas.4sigs.last-invalid"])
	}
	if gas["reuse.witness.verified-first"] != gas["reuse.witness.altered-first"] {
		t.Fatal("claim order changed the charge")
	}
	// the epoch term is the 16-member ceiling: removing the byte and signature terms leaves one value for 1, 4 and 16 members
	rest := map[uint64]bool{}
	for _, v := range m.Vectors {
		if strings.HasPrefix(v.ID, "price.epoch-ceiling.") {
			g := v.Expected.Grouping
			rest[v.Expected.Gas-16*g.C-6000*g.Q] = true
		}
	}
	if len(rest) != 1 {
		t.Fatalf("the epoch charge depends on the entry's size: %v", rest)
	}
}

// countWork records the counted operations.
func countWork(t *testing.T) map[string]int {
	t.Helper()
	counts := map[string]int{}
	b1ref.SetWorkHook(func(kind string) { counts[kind]++ })
	t.Cleanup(func() { b1ref.SetWorkHook(nil) })
	return counts
}

// TestRunOrder pins the debit order: the size cap, then 60,000 + 16*C, then the header and G_scan, then the full scan, then G_batch.
func TestRunOrder(t *testing.T) {
	m, _ := loadGolden(t)
	var good, malformed b1gen.Vector
	for _, v := range m.Vectors {
		switch v.ID {
		case "cert.shared.ok":
			good = v
		case "frozen.malformed-last":
			malformed = v
		}
	}
	req, _ := hex.DecodeString(good.Request)
	st, pins := state(t, good.PreState)
	if _, used, err := b1ref.Run(b1ref.OpCertBatch, make([]byte, b1ref.MaxCallBytes+1), st, pins, 10); !errors.Is(err, b1ref.ErrInputTooLarge) || used != 10 {
		t.Fatalf("oversized input with little gas: used=%d err=%v", used, err)
	}
	if _, _, err := b1ref.Run(b1ref.OpMember, make([]byte, b1ref.MaxRSMTInputBytes+1), nil, b1ref.Pins{}, 10); !errors.Is(err, b1ref.ErrInputTooLarge) {
		t.Fatalf("oversized RSMT input: %v", err)
	}
	bad, _ := hex.DecodeString(malformed.Request)
	k := uint64(binary.BigEndian.Uint16(bad[2:4]))
	reserve := uint64(60000 + 16*len(bad))
	scan := b1ref.ScanGas(uint64(len(bad)), k)
	if _, used, err := b1ref.Run(b1ref.OpCertBatch, bad, st, pins, reserve-1); !errors.Is(err, b1ref.ErrOutOfGas) || used != reserve-1 {
		t.Fatalf("below 60,000+16C: used=%d err=%v", used, err)
	}
	if _, _, err := b1ref.Run(b1ref.OpCertBatch, append([]byte{1}, bad[1:]...), st, pins, reserve); !errors.Is(err, b1ref.ErrVersion) {
		t.Fatalf("at 60,000+16C the header is read: %v", err)
	}
	if _, _, err := b1ref.Run(b1ref.OpCertBatch, bad, st, pins, scan-1); !errors.Is(err, b1ref.ErrOutOfGas) {
		t.Fatalf("below G_scan the occurrences are not scanned: %v", err)
	}
	if _, _, err := b1ref.Run(b1ref.OpCertBatch, bad, st, pins, scan); !errors.Is(err, b1ref.ErrShape) {
		t.Fatalf("at G_scan the malformed last occurrence is found: %v", err)
	}
	if _, _, err := b1ref.Run(b1ref.OpCertBatch, req, st, pins, good.Expected.Gas-1); !errors.Is(err, b1ref.ErrOutOfGas) {
		t.Fatalf("below G_batch: %v", err)
	}
}

// TestInputNotMutated: the verdict must not depend on, or alter, the caller's bytes (the native bit string decoder works in place,
// so the shard bytes are decoded from a copy).
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
		if first.Valid != second.Valid || first.Gas != second.Gas || (err1 == nil) != (err2 == nil) {
			t.Fatalf("%s: verdict not repeatable", v.ID)
		}
	}
}

// TestRecoveryByteIsPolicy shows the signature rule is B1 policy and not the native rule: the native verifier takes only the canonical 65-byte
// recoverable signature (the recovery ID must recover the member's key) and refuses the compact 64-byte form, while B1 accepts r||s with a recovery
// byte 0 or 1 or none, verified compactly, and refuses every other byte. A library bump must not move either side.
func TestRecoveryByteIsPolicy(t *testing.T) {
	m, _ := loadGolden(t)
	val := b1gen.ValidatorForTest(m.Seed, "node00")
	msg := []byte("seal bytes")
	sig := val.Sign(msg, false)
	ver, err := nativeVerifier(val.Pub)
	if err != nil {
		t.Fatal(err)
	}
	if ver.VerifyBytes(sig[:64], msg) == nil {
		t.Fatal("the native verifier must refuse a compact 64-byte signature")
	}
	recovered := 0
	for _, v := range []byte{0, 1, 2, 3, 255} {
		if ver.VerifyBytes(append(append([]byte{}, sig[:64]...), v), msg) == nil {
			recovered++
		}
	}
	if recovered != 1 {
		t.Fatalf("the native verifier must accept exactly the recovery ID that recovers the key, accepted %d", recovered)
	}
	cv, ok := ver.(interface{ VerifyCompactBytes(sig, data []byte) error })
	if !ok {
		t.Fatal("the member verifier has no compact verification")
	}
	if err := cv.VerifyCompactBytes(sig[:64], msg); err != nil {
		t.Fatalf("compact verification of the same signature: %v", err)
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

// TestMaxGas pins the schedule's maximum: K = E = A = 16, Q = 256, P = 4,608 at the byte cap.
func TestMaxGas(t *testing.T) {
	if g := b1ref.BatchGas(b1ref.MaxCallBytes, 16, 16, 256, 16, 4608); g != 7_573_804 {
		t.Fatalf("batch worst case %d", g)
	}
	if g := b1ref.RSMTGas(12392, 256); g != 264_522 {
		t.Fatalf("RSMT worst case %d", g)
	}
}
