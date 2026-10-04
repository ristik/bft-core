package s1ref_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/unicitynetwork/bft-core/s1ref"
	"github.com/unicitynetwork/bft-core/s1ref/s1gen"
)

const (
	goldenPath = "testdata/s1-vectors-v1.json"
	goldenSeed = "s1-oracle-v1"
	q1Path     = "../network/protocol/abdrc/testdata/domain_bound_vectors.json"
)

var update = flag.Bool("update", false, "rewrite the golden vector manifest")

// sentinels maps the manifest's sentinel names to the oracle's errors.
var sentinels = map[string]error{
	"ErrTruncated": s1ref.ErrTruncated, "ErrTrailingBytes": s1ref.ErrTrailingBytes, "ErrVersion": s1ref.ErrVersion,
	"ErrFlags": s1ref.ErrFlags, "ErrCount": s1ref.ErrCount, "ErrNonCanonical": s1ref.ErrNonCanonical,
	"ErrDuplicateMapKey": s1ref.ErrDuplicateMapKey, "ErrForbiddenCBOR": s1ref.ErrForbiddenCBOR,
	"ErrInvalidUTF8": s1ref.ErrInvalidUTF8, "ErrShape": s1ref.ErrShape, "ErrReencode": s1ref.ErrReencode,
	"ErrViewKind": s1ref.ErrViewKind, "ErrScheme": s1ref.ErrScheme, "ErrSigShape": s1ref.ErrSigShape,
	"ErrInputTooLarge": s1ref.ErrInputTooLarge, "ErrViewTooLarge": s1ref.ErrViewTooLarge,
	"ErrEvidenceTooLarge": s1ref.ErrEvidenceTooLarge, "ErrTooManyMembers": s1ref.ErrTooManyMembers,
	"ErrNodeIDTooLong": s1ref.ErrNodeIDTooLong, "ErrDepth": s1ref.ErrDepth, "ErrTokens": s1ref.ErrTokens,

	"ErrUnknownEpoch": s1ref.ErrUnknownEpoch, "ErrViewHash": s1ref.ErrViewHash, "ErrBodyID": s1ref.ErrBodyID,
	"ErrSourceKind": s1ref.ErrSourceKind, "ErrNetwork": s1ref.ErrNetwork, "ErrEpochMismatch": s1ref.ErrEpochMismatch,
	"ErrOpenInterval": s1ref.ErrOpenInterval, "ErrBeforeStart": s1ref.ErrBeforeStart, "ErrAfterEnd": s1ref.ErrAfterEnd,
	"ErrSigningConfig": s1ref.ErrSigningConfig, "ErrSchemeEpoch": s1ref.ErrSchemeEpoch,
	"ErrViewEmpty": s1ref.ErrViewEmpty, "ErrViewOrder": s1ref.ErrViewOrder, "ErrViewDuplicate": s1ref.ErrViewDuplicate,
	"ErrWeightProfile": s1ref.ErrWeightProfile, "ErrViewKey": s1ref.ErrViewKey,
	"ErrUnknownAuthor": s1ref.ErrUnknownAuthor, "ErrVoteInfo": s1ref.ErrVoteInfo, "ErrBinding": s1ref.ErrBinding,
	"ErrStatement": s1ref.ErrStatement, "ErrSealSigMissing": s1ref.ErrSealSigMissing,
	"ErrSealSigForbidden": s1ref.ErrSealSigForbidden, "ErrSigRange": s1ref.ErrSigRange, "ErrSigInvalid": s1ref.ErrSigInvalid,
	"ErrPairScheme": s1ref.ErrPairScheme, "ErrPairSigner": s1ref.ErrPairSigner, "ErrPairContext": s1ref.ErrPairContext,
	"ErrPairSameStatement": s1ref.ErrPairSameStatement,
}

// notInVectors are reasons no manifest vector can reach, with where they are tested instead.
var notInVectors = map[string]string{
	"ErrTokens":   "unreachable by bytes (the input bound is below the token bound); unit-tested on the scanner",
	"ErrReencode": "guards native encoder differences on input the shape rules already admitted",
}

func loadGolden(t testing.TB) (*s1gen.Manifest, []byte) {
	t.Helper()
	raw, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden manifest (go test ./s1ref -update): %v", err)
	}
	var m s1gen.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return &m, raw
}

func unhex32(t testing.TB, s string) (out [32]byte) {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad 32-byte hex %q", s)
	}
	copy(out[:], b)
	return out
}

// contextOf turns the manifest's injected context into the oracle's Context.
func contextOf(t testing.TB, j *s1gen.ContextJSON) *s1ref.Context {
	t.Helper()
	if j == nil {
		return nil
	}
	c := &s1ref.Context{Network: j.Network, OpenEpoch: j.OpenEpoch, Epochs: map[uint64]s1ref.EpochEntry{}}
	for _, e := range j.Epochs {
		c.Epochs[e.Epoch] = s1ref.EpochEntry{ViewHash: unhex32(t, e.ViewHash), BodyID: unhex32(t, e.BodyID), SourceKind: e.SourceKind,
			Start: e.Start, End: e.End, Signing: s1ref.SigningConfig{Scheme: e.Scheme, Network: e.SigNetwork, Genesis: unhex32(t, e.Genesis)}}
	}
	return c
}

func requestOf(t testing.TB, v s1gen.Vector) []byte {
	t.Helper()
	b, err := hex.DecodeString(v.Request)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func evaluate(t testing.TB, v s1gen.Vector) (s1ref.Verdict, error) {
	t.Helper()
	return s1ref.Verify(requestOf(t, v), contextOf(t, v.Context))
}

// check compares a result with a vector's expectation and returns a mismatch
// description, empty when they agree.
func check(t testing.TB, v s1gen.Vector, got s1ref.Verdict, err error) string {
	want, ok := sentinels[v.Expected.Sentinel]
	if v.Expected.Sentinel != "" && !ok {
		t.Fatalf("unknown sentinel name %q", v.Expected.Sentinel)
	}
	switch v.Expected.Status {
	case "error":
		if err == nil {
			return "expected " + v.Expected.Sentinel + ", got a verdict"
		}
		if !errors.Is(err, want) || !errors.Is(err, s1ref.ErrMalformed) || errors.Is(err, s1ref.ErrInvalid) {
			return "expected " + v.Expected.Sentinel + " (malformed family), got " + err.Error()
		}
	case "ok":
		if err != nil {
			return "unexpected error: " + err.Error()
		}
		if got.Valid != *v.Expected.Valid {
			return "validity differs (why: " + errString(got.Why) + ")"
		}
		if got.Valid != (got.Why == nil) || got.Valid != (got.Offence != nil) {
			return "verdict is internally inconsistent"
		}
		if want != nil && (!errors.Is(got.Why, want) || !errors.Is(got.Why, s1ref.ErrInvalid) || errors.Is(got.Why, s1ref.ErrMalformed)) {
			return "expected false reason " + v.Expected.Sentinel + ", got " + errString(got.Why)
		}
		if got.Gas != v.Expected.Gas {
			return "gas differs"
		}
		if hex.EncodeToString(s1ref.Output(got)) != v.Expected.Output {
			return "output words differ"
		}
	default:
		t.Fatalf("status %q", v.Expected.Status)
	}
	return ""
}

func errString(err error) string {
	if err == nil {
		return "<nil>"
	}
	return err.Error()
}

// TestGoldenVectors runs every committed vector through the oracle and checks
// status, validity, the named sentinel with errors.Is, the returndata words and the gas.
func TestGoldenVectors(t *testing.T) {
	m, _ := loadGolden(t)
	if m.Format != s1gen.FormatVersion || m.Seed != goldenSeed {
		t.Fatalf("manifest %q seed %q", m.Format, m.Seed)
	}
	seen := map[string]bool{}
	for _, v := range m.Vectors {
		if seen[v.ID] {
			t.Fatalf("duplicate vector id %s", v.ID)
		}
		seen[v.ID] = true
		t.Run(v.ID, func(t *testing.T) {
			got, err := evaluate(t, v)
			if msg := check(t, v, got, err); msg != "" {
				t.Fatal(msg)
			}
		})
	}
}

// TestRunGas runs every vector through the EVM-facing wrapper: exactly the
// formula gas succeeds with the same bytes, one less is out of gas for every
// structurally admitted request, and a malformed one halts consuming all gas.
func TestRunGas(t *testing.T) {
	m, _ := loadGolden(t)
	for _, v := range m.Vectors {
		req, ctx := requestOf(t, v), contextOf(t, v.Context)
		switch v.Expected.Status {
		case "ok":
			out, used, err := s1ref.Run(req, ctx, v.Expected.Gas)
			if err != nil || used != v.Expected.Gas || hex.EncodeToString(out) != v.Expected.Output {
				t.Fatalf("%s: exact gas: out=%x used=%d err=%v", v.ID, out, used, err)
			}
			if _, used, err = s1ref.Run(req, ctx, v.Expected.Gas-1); !errors.Is(err, s1ref.ErrOutOfGas) || used != v.Expected.Gas-1 {
				t.Fatalf("%s: gas-1: used=%d err=%v", v.ID, used, err)
			}
			if _, _, err = s1ref.Run(req, ctx, v.Expected.Gas+12345); err != nil {
				t.Fatalf("%s: surplus gas: %v", v.ID, err)
			}
		case "error":
			const gas = 10_000_000
			out, used, err := s1ref.Run(req, ctx, gas)
			if out != nil || used != gas || !errors.Is(err, sentinels[v.Expected.Sentinel]) {
				t.Fatalf("%s: malformed must burn all gas: out=%x used=%d err=%v", v.ID, out, used, err)
			}
		}
	}
}

// TestGeneratorDeterministic requires two runs to agree byte for byte and the
// committed manifest to be exactly the generator's output for its seed.
func TestGeneratorDeterministic(t *testing.T) {
	q1, err := os.ReadFile(q1Path)
	if err != nil {
		t.Fatal(err)
	}
	build := func(seed string) []byte {
		m, err := s1gen.Build(seed, q1)
		if err != nil {
			t.Fatal(err)
		}
		b, err := m.JSON()
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	a, b := build(goldenSeed), build(goldenSeed)
	if !bytes.Equal(a, b) {
		t.Fatal("two runs of the generator differ")
	}
	if bytes.Equal(a, build(goldenSeed+"x")) {
		t.Fatal("the seed does not reach the output")
	}
	if *update {
		if err := os.WriteFile(goldenPath, a, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, golden := loadGolden(t)
	if !bytes.Equal(a, golden) {
		t.Fatalf("committed %s is stale: regenerate with go test ./s1ref -update", goldenPath)
	}
}

// TestManifestCoverage checks every error sentinel is reached by a vector (or
// is listed with where else it is tested), every family is present and the
// design's required fixtures exist.
func TestManifestCoverage(t *testing.T) {
	m, _ := loadGolden(t)
	used := map[string]bool{}
	fams := map[string]int{}
	ids := map[string]bool{}
	for _, v := range m.Vectors {
		used[v.Expected.Sentinel] = true
		fams[v.Family]++
		ids[v.ID] = true
	}
	for name := range sentinels {
		if !used[name] && notInVectors[name] == "" {
			t.Errorf("no vector reaches %s", name)
		}
	}
	for name := range notInVectors {
		if used[name] {
			t.Errorf("%s is listed as unreachable but a vector uses it", name)
		}
	}
	for _, f := range []string{"Q1 published vectors", "Single vote", "Statement rules", "Signatures", "Binding", "Context", "Trust view", "Encoding", "Equivocation pair", "Resources"} {
		if fams[f] == 0 {
			t.Errorf("no vectors for family %q", f)
		}
	}
	for _, id := range []string{
		"q1.legacy-vote.ok", "q1.committing-vote.ok", "q1.noncommitting-vote.ok", "s1.committing.ok",
		"pair.exec.ok", "pair.exec.reversed.ok", "pair.same-statement.alternate-signature", "pair.mixed.legacy-first",
		"sig.malformed.v2", "sig.high-s", "view.invalid-point.other-member", "enc.precedence.false-first-malformed-second",
		"s1.replay-other-network.ok", "res.members-64.pair-committing.ok",
	} {
		if !ids[id] {
			t.Errorf("missing required vector %s", id)
		}
	}
}

// frames splits a call into its view and evidence frames.
func frames(t testing.TB, in []byte) (hdr, view []byte, evs [][]byte) {
	t.Helper()
	hdr = in[:4]
	n := int(binary.BigEndian.Uint32(in[4:8]))
	view = in[8 : 8+n]
	rest := in[8+n:]
	for len(rest) > 0 {
		l := int(binary.BigEndian.Uint32(rest[:4]))
		evs = append(evs, rest[4:4+l])
		rest = rest[4+l:]
	}
	return hdr, view, evs
}

func reframe(hdr, view []byte, evs [][]byte) []byte {
	out := append([]byte{}, hdr...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(view)))
	out = append(out, view...)
	for _, e := range evs {
		out = binary.BigEndian.AppendUint32(out, uint32(len(e)))
		out = append(out, e...)
	}
	return out
}

// TestPairOrderInvariance: every pair vector, either order, gives identical
// status, verdict reason family, gas and bytes.
func TestPairOrderInvariance(t *testing.T) {
	m, _ := loadGolden(t)
	n := 0
	for _, v := range m.Vectors {
		req := requestOf(t, v)
		if v.Expected.Status != "ok" || len(req) < 4 || req[3] != 2 {
			continue
		}
		n++
		hdr, view, evs := frames(t, req)
		swapped := reframe(hdr, view, [][]byte{evs[1], evs[0]})
		a, errA := s1ref.Verify(req, contextOf(t, v.Context))
		b, errB := s1ref.Verify(swapped, contextOf(t, v.Context))
		if errA != nil || errB != nil {
			t.Fatalf("%s: %v %v", v.ID, errA, errB)
		}
		if a.Valid != b.Valid || a.Gas != b.Gas || !bytes.Equal(s1ref.Output(a), s1ref.Output(b)) {
			t.Fatalf("%s: order changes the result: %+v vs %+v", v.ID, a, b)
		}
	}
	if n < 12 {
		t.Fatalf("only %d pair vectors exercised", n)
	}
}

// TestConflictIdentity pins the offence identity rules: alternate conflicting
// pairs of one slot share a conflict ID; different slots, signers and signatures'
// forms do not change or share it.
func TestConflictIdentity(t *testing.T) {
	m, _ := loadGolden(t)
	byID := map[string]s1gen.Vector{}
	for _, v := range m.Vectors {
		byID[v.ID] = v
	}
	word := func(id string, i int) []byte {
		out, _ := hex.DecodeString(byID[id].Expected.Output)
		if len(out) != 384 {
			t.Fatalf("%s: output is %d bytes", id, len(out))
		}
		return out[32*i : 32*i+32]
	}
	const conflict, contentA, contentB, epoch, round = 9, 10, 11, 6, 7
	if !bytes.Equal(word("pair.exec.ok", conflict), word("pair.exec-alternate.ok", conflict)) {
		t.Fatal("alternate conflicting pairs of one slot must share a conflict ID")
	}
	if bytes.Equal(word("pair.exec.ok", contentA), word("pair.exec-alternate.ok", contentA)) &&
		bytes.Equal(word("pair.exec.ok", contentB), word("pair.exec-alternate.ok", contentB)) {
		t.Fatal("alternate pairs must have different content digests")
	}
	if bytes.Equal(word("pair.exec.ok", conflict), word("pair.seal-signatures.ok", conflict)) {
		t.Fatal("another signer's slot must have another conflict ID")
	}
	// A single scheme 2 vote reports the same conflict ID as the pair it belongs to.
	if !bytes.Equal(word("s2.noncommitting.ok", conflict), word("pair.exec.ok", conflict)) {
		t.Fatal("single vote and pair of one slot must share a conflict ID")
	}
	// Voting coordinates, never commit coordinates.
	for _, c := range []struct {
		id           string
		epoch, round byte
	}{{"s2.committing.ok", 2, 150}, {"q1.committing-vote.ok", 2, 12}, {"q1.noncommitting-vote.ok", 2, 12}} {
		if word(c.id, epoch)[31] != c.epoch || word(c.id, round)[31] != c.round {
			t.Fatalf("%s: epoch/round words %x %x", c.id, word(c.id, epoch), word(c.id, round))
		}
	}
	// Scheme 1 never asserts an offence: zero domain and conflict, content only.
	for _, id := range []string{"q1.legacy-vote.ok", "s1.noncommitting.ok", "s1.committing.ok"} {
		if word(id, 2)[31] != 1 || !allZero(word(id, 4)) || !allZero(word(id, conflict)) || !allZero(word(id, contentB)) {
			t.Fatalf("%s: scheme 1 output carries domain or conflict identity", id)
		}
	}
	// Null and empty legacy commit hashes are different statements.
	if bytes.Equal(word("enc.null-vs-empty.scheme1-null.ok", contentA), word("enc.null-vs-empty.scheme1-empty.ok", contentA)) {
		t.Fatal("legacy null and empty commit hash must have different content digests")
	}
	// Signature forms never change the content or the signer.
	for _, id := range []string{"s2.sig.65-v0.ok", "s2.sig.65-v1.ok", "s2.sig.alt-nonce.ok"} {
		if !bytes.Equal(word(id, contentA), word("s2.sig.64.ok", contentA)) || !bytes.Equal(word(id, 5), word("s2.sig.64.ok", 5)) {
			t.Fatalf("%s: signature form changed content or signer", id)
		}
	}
	// The null-form and the bstr0-form of a non-committing hash are one scheme 2 statement.
	if !bytes.Equal(word("s2.noncommitting.hash-bstr0.ok", contentA), word("s2.noncommitting.ok", contentA)) {
		t.Fatal("null and bstr0 commit hash of a non-committing vote must be one scheme 2 statement")
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

// TestFalseVsMalformedSplit: every false vector is a (1,false) with the full
// charge and the 64-byte output; every malformed one an error that is not a
// false reason; the families never overlap.
func TestFalseVsMalformedSplit(t *testing.T) {
	m, _ := loadGolden(t)
	var nFalse, nBad int
	for _, v := range m.Vectors {
		got, err := evaluate(t, v)
		switch {
		case err != nil:
			nBad++
			if !errors.Is(err, s1ref.ErrMalformed) || errors.Is(err, s1ref.ErrInvalid) {
				t.Fatalf("%s: %v", v.ID, err)
			}
		case !got.Valid:
			nFalse++
			if len(s1ref.Output(got)) != 64 || got.Offence != nil || !errors.Is(got.Why, s1ref.ErrInvalid) || errors.Is(got.Why, s1ref.ErrMalformed) {
				t.Fatalf("%s: %+v", v.ID, got)
			}
		default:
			if len(s1ref.Output(got)) != 384 || got.Offence == nil || got.Why != nil {
				t.Fatalf("%s: %+v", v.ID, got)
			}
		}
	}
	if nFalse < 100 || nBad < 80 {
		t.Fatalf("thin coverage: %d false, %d malformed", nFalse, nBad)
	}
}

// TestWorkOrder proves the gas reservation order: nothing expensive happens
// for a malformed or under-funded call, and a funded call verifies at most four
// signatures and parses every member key.
func TestWorkOrder(t *testing.T) {
	m, _ := loadGolden(t)
	var points, sigs int
	s1ref.SetWorkHook(func(kind string) {
		switch kind {
		case "point":
			points++
		case "signature":
			sigs++
		}
	})
	defer s1ref.SetWorkHook(nil)
	for _, v := range m.Vectors {
		req, ctx := requestOf(t, v), contextOf(t, v.Context)
		points, sigs = 0, 0
		switch v.Expected.Status {
		case "error":
			s1ref.Run(req, ctx, 10_000_000)
			if points != 0 || sigs != 0 {
				t.Fatalf("%s: malformed request did expensive work (%d points, %d signatures)", v.ID, points, sigs)
			}
		case "ok":
			s1ref.Run(req, ctx, v.Expected.Gas-1)
			if points != 0 || sigs != 0 {
				t.Fatalf("%s: under-funded request did expensive work (%d points, %d signatures)", v.ID, points, sigs)
			}
			s1ref.Run(req, ctx, v.Expected.Gas)
			if sigs > 4 {
				t.Fatalf("%s: %d signature verifications", v.ID, sigs)
			}
		}
	}
	// A fully valid request parses every member and verifies each signature once.
	for _, id := range []string{"res.members-64.pair-committing.ok", "s2.committing.ok", "s1.noncommitting.ok"} {
		for _, v := range m.Vectors {
			if v.ID != id {
				continue
			}
			points, sigs = 0, 0
			if _, _, err := s1ref.Run(requestOf(t, v), contextOf(t, v.Context), v.Expected.Gas); err != nil {
				t.Fatal(err)
			}
			wantSigs := map[string]int{"res.members-64.pair-committing.ok": 4, "s2.committing.ok": 2, "s1.noncommitting.ok": 1}[id]
			if sigs != wantSigs || points == 0 {
				t.Fatalf("%s: %d points %d signatures, want %d signatures", id, points, sigs, wantSigs)
			}
		}
	}
}

// checkNames are the semantic checks that can be disabled, with the reason a
// vector must expect for the disabled check to be noticed.
var checkNames = map[string]string{
	"network": "ErrNetwork", "unknown-epoch": "ErrUnknownEpoch", "view-hash": "ErrViewHash", "body-id": "ErrBodyID",
	"source-kind": "ErrSourceKind", "signing-config": "ErrSigningConfig", "view-empty": "ErrViewEmpty",
	"view-duplicate": "ErrViewDuplicate", "view-order": "ErrViewOrder", "view-weight": "ErrWeightProfile", "view-key": "ErrViewKey",
	"epoch-mismatch": "ErrEpochMismatch", "interval-open": "ErrOpenInterval", "interval-start": "ErrBeforeStart",
	"interval-end": "ErrAfterEnd", "scheme-epoch": "ErrSchemeEpoch", "unknown-author": "ErrUnknownAuthor",
	"seal-sig-forbidden": "ErrSealSigForbidden", "vote-info": "ErrVoteInfo", "binding": "ErrBinding",
	"commit-context": "ErrStatement", "seal-sig-missing": "ErrSealSigMissing", "noncommit-zero": "ErrStatement",
	"sig-range": "ErrSigRange", "sig-invalid": "ErrSigInvalid", "pair-scheme": "ErrPairScheme", "pair-signer": "ErrPairSigner",
	"pair-context": "ErrPairContext", "pair-same-statement": "ErrPairSameStatement",
}

// TestEveryCheckIsLoadBearing disables each semantic check in turn and
// requires a vector that expects that check's reason to notice, so no negative
// vector passes for a reason other than the check it claims to exercise. A new
// check without an entry here fails the first part.
func TestEveryCheckIsLoadBearing(t *testing.T) {
	var src []byte
	for _, f := range []string{"verify.go", "view.go", "evidence.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		src = append(src, b...)
	}
	found := map[string]bool{}
	for _, mt := range regexp.MustCompile(`skipped\("([a-z0-9-]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		found[mt[1]] = true
		if _, ok := checkNames[mt[1]]; !ok {
			t.Errorf("check %q has no entry in checkNames", mt[1])
		}
	}
	for name := range checkNames {
		if !found[name] {
			t.Errorf("checkNames lists %q but the oracle has no such check", name)
		}
	}
	m, _ := loadGolden(t)
	defer s1ref.SetSkip(nil)
	var names []string
	for n := range checkNames {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		s1ref.SetSkip(func(n string) bool { return n == name })
		noticed := false
		for _, v := range m.Vectors {
			if v.Expected.Sentinel != checkNames[name] {
				continue
			}
			got, err := evaluate(t, v)
			if check(t, v, got, err) != "" {
				noticed = true
				break
			}
		}
		if !noticed {
			t.Errorf("disabling check %q goes unnoticed by every vector expecting %s", name, checkNames[name])
		}
	}
	s1ref.SetSkip(nil)
	for _, v := range m.Vectors {
		got, err := evaluate(t, v)
		if msg := check(t, v, got, err); msg != "" {
			t.Fatalf("%s: hooks left installed: %s", v.ID, msg)
		}
	}
}

// TestManifestNotesAndPins keeps the manifest's qualifications in place.
func TestManifestNotesAndPins(t *testing.T) {
	m, _ := loadGolden(t)
	for _, k := range []string{"B", "Q", "G", "S1", "V2"} {
		if m.Pins[k] == "" {
			t.Errorf("missing pin %s", k)
		}
	}
	if !strings.Contains(strings.Join(m.Notes, " "), "injected precondition") || len(m.OpenItems) == 0 || len(m.Deferred) == 0 {
		t.Error("notes, open items or deferred rows missing")
	}
	q1, err := os.ReadFile(q1Path)
	if err != nil {
		t.Fatal(err)
	}
	if sum := sha256.Sum256(q1); m.SourceSHA256 != hex.EncodeToString(sum[:]) {
		t.Error("the manifest was generated from another Q1 vectors file")
	}
}
