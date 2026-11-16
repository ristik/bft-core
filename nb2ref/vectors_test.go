package nb2ref

import (
	"encoding/json"
	"errors"
	"math/big"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

var (
	genOnce  sync.Once
	genFile  *VectorFile
	genBytes []byte
	genErr   error
)

// generated builds the vector file once per test binary.
func generated(t *testing.T) (*VectorFile, []byte) {
	t.Helper()
	genOnce.Do(func() {
		genFile, genErr = Generate()
		if genErr == nil {
			genBytes, genErr = genFile.Encode()
		}
	})
	if genErr != nil {
		t.Fatal(genErr)
	}
	return genFile, genBytes
}

// TestVectorDigest: the generator reproduces the committed digest (native-bridge-plugins protocol/vectors/nb2 carries the
// file itself). Regenerate with go run ./nb2ref/cmd/nb2vectors and update testdata/nb2-vectors.json.sha256 after a deliberate change.
func TestVectorDigest(t *testing.T) {
	_, b := generated(t)
	want, err := os.ReadFile("testdata/nb2-vectors.json.sha256")
	if err != nil {
		t.Fatal(err)
	}
	if got := Digest(b); got != strings.TrimSpace(string(want)) {
		t.Fatalf("vector digest %s, committed %s: regenerate with go run ./nb2ref/cmd/nb2vectors", got, strings.TrimSpace(string(want)))
	}
}

// decoded is the vector file read back from its bytes, so the replay below uses only what a consumer sees.
func decoded(t *testing.T) *VectorFile {
	_, b := generated(t)
	var f VectorFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func trustOf(t *testing.T, d *Deployment) *TrustInput {
	tr, err := LoadTrustInput(d.TrustBundle, [32]byte(d.TrustGenesis))
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func sameExpect(got, want Expect) bool {
	return got.Error == want.Error && strings.Join(got.Args, ",") == strings.Join(want.Args, ",") && got.OnChain == want.OnChain &&
		string(got.Revert) == string(want.Revert)
}

func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// TestVectorReplay replays every vector from the file's bytes.
func TestVectorReplay(t *testing.T) {
	f := decoded(t)
	trust := map[string]*TrustInput{}
	cfg := map[string]*Config{}
	for name, d := range f.Deployments {
		trust[name] = trustOf(t, d)
		c, err := DecodeConfig(d.Gamma, BuildParams(d.Build))
		if err != nil {
			t.Fatal(err)
		}
		cfg[name] = c
	}
	for _, v := range f.Config {
		p := BuildParams(f.Deployments[v.Deployment].Build)
		_, err := DecodeConfig(v.Gamma, p)
		_, cerr := Construct(v.Gamma, Environment{Address: [20]byte(v.Address), ChainID: v.ChainID, VerifierCodeHash: [32]byte(v.CodeHash)}, p)
		if !sameExpect(expectOf(err), v.Verifier) || !sameExpect(expectOf(cerr), v.Constructor) {
			t.Errorf("config %s: %v / %v", v.ID, err, cerr)
		}
	}
	for _, v := range f.Verifier {
		gamma := f.Deployments[v.Deployment].Gamma
		if v.Gamma != nil {
			gamma = v.Gamma
		}
		vd, err := VerifyReturn(gamma, v.Evidence, trust[v.Deployment], BuildParams(f.Deployments[v.Deployment].Build))
		if v.Expect.Error != "" && !errors.Is(err, RuleByName(v.Expect.Error)) {
			t.Errorf("verifier %s: errors.Is(%v, Err%s) is false", v.ID, err, v.Expect.Error)
		}
		if !sameExpect(expectOf(err), v.Expect) {
			t.Errorf("verifier %s: %v, want %v", v.ID, err, v.Expect)
			continue
		}
		if err == nil {
			if string(vd.ABI()) != string(v.Verdict.ABI) {
				t.Errorf("verifier %s: verdict differs", v.ID)
			}
		}
	}
	for _, v := range f.Seal {
		if v.NoReceipt {
			if !sameJSON(sealResult(cfg[v.Deployment], nil), v.Result) {
				t.Errorf("seal %s: burn index without a receipt differs", v.ID)
			}
			continue
		}
		sr, err := VerifySealReceipt(cfg[v.Deployment], trust[v.Deployment], v.Receipt)
		if !sameExpect(expectOf(err), v.Expect) || (err != nil && RuleName(errorsUnwrapOnce(err)) != v.Inner) {
			t.Errorf("seal %s: %v", v.ID, err)
			continue
		}
		if err == nil && (v.Result == nil || !sameJSON(sealResult(cfg[v.Deployment], sr), v.Result)) {
			t.Errorf("seal %s: positive result (segment, heads, identifiers, burn index, start head) differs", v.ID)
		}
	}
	for _, v := range f.Gap {
		m, ok := GapRoot(v.K, [32]byte(v.Eta), v.Proof)
		if (ok && m == [32]byte(v.Root)) != (v.Expect.Error == "") {
			t.Errorf("gap %s", v.ID)
		}
	}
	for _, v := range f.Folds {
		pl := GapProofLen(v.K)
		var proofs [][]byte
		for i := 32; i+pl <= len(v.History); i += pl {
			proofs = append(proofs, v.History[i:i+pl])
		}
		x, err := FoldHistory([32]byte(v.Domain), v.K, [32]byte(v.Eta), v.Start, [32]byte(v.History[:32]), proofs)
		if err == nil && x != [32]byte(v.StoredHead) {
			err = ErrChainMismatch
		}
		if !sameExpect(expectOf(err), v.Expect) {
			t.Errorf("fold %s: %v", v.ID, err)
		}
	}
	for _, v := range f.SegmentLogs {
		seg, err := CheckSegmentLog([32]byte(v.Domain), v.K, v.Segment, [32]byte(v.ExpectBefore), v.Data)
		if !sameExpect(expectOf(err), v.Expect) {
			t.Errorf("segment log %s: %v", v.ID, err)
		}
		if err == nil && (seg.Root != [32]byte(v.Root) || seg.After != [32]byte(v.HeadAfter)) {
			t.Errorf("segment log %s: root or head differs", v.ID)
		}
	}
	for _, v := range f.Vault {
		replayVault(t, f, v, nil)
	}
	for _, v := range f.Wallet.Capacity {
		var err error
		if v.Stage == "preflight" {
			gb, gp := v.GasBase, v.GasPerProof
			err = CapacityPreflight(Preflight{LMax: v.LMax, LT: v.LT, LO: v.LO, K: v.K, A: v.A, CObs: v.CObs, Reserve: v.Reserve, UserGasLimit: v.UserGasLimit,
				GasAt: func(p uint64) uint64 { return gb + gp*p }})
		} else {
			err = CapacityExceeded(v.LMax, v.LT, v.LO, v.K, v.Proofs, v.GasLimit, v.UserGasLimit)
		}
		pMax, base := MaxProofs(v.LMax, v.LT, v.LO, v.K)
		if !sameExpect(expectOf(err), v.Expect) || pMax != v.PMax || base != v.BaseFits {
			t.Errorf("capacity %s: %v", v.ID, err)
		}
	}
	for _, v := range f.Wallet.Companions {
		if err := CheckCompanion(v.Status, v.Witnesses); !sameExpect(expectOf(err), v.Expect) {
			t.Errorf("companion %s: %v", v.ID, err)
		}
	}
	for _, v := range f.Wallet.StateReads {
		if err := CheckStateRead(v.StateReadOnly, v.Read, v.Verified, v.MaxJump); !sameExpect(expectOf(err), v.Expect) {
			t.Errorf("state read %s: %v", v.ID, err)
		}
	}
	if len(f.Primitives.Unlocks) == 0 {
		t.Error("no unlock recovery primitive vectors")
	}
	for _, v := range f.Primitives.Unlocks {
		key, err := ParseKey(v.Key)
		if err != nil {
			t.Fatalf("unlock %s: key: %v", v.ID, err)
		}
		if err := VerifyUnlockDigest(key, [32]byte(v.Digest), v.Unlock); !sameExpect(expectOf(err), v.Expect) {
			t.Errorf("unlock %s: %v, want %+v", v.ID, err, v.Expect)
		}
		// The SDK relation (ids 0..3) independently: a valid id 2/3 recovers the source key and verifies; NB2 still refuses it.
		if sdk := v.Unlock[64] <= 3 && sdkRecover(key, [32]byte(v.Digest), v.Unlock[:64], v.Unlock[64]) == nil; sdk != v.SDKValid {
			t.Errorf("unlock %s: SDK relation accepts = %v, vector says %v", v.ID, sdk, v.SDKValid)
		}
		if v.SDKValid && v.Unlock[64] >= 2 {
			var r, s secp256k1.ModNScalar
			r.SetByteSlice(v.Unlock[:32])
			s.SetByteSlice(v.Unlock[32:64])
			if !ecdsa.NewSignature(&r, &s).Verify(v.Digest, key) {
				t.Errorf("unlock %s: marked SDK-valid but the compact verification fails", v.ID)
			}
			if v.Expect.Error != "UnlockRecovery" {
				t.Errorf("unlock %s: a valid recovery ID %d must still be UnlockRecovery", v.ID, v.Unlock[64])
			}
		}
	}
	for _, v := range f.Primitives.MinterScalars {
		if _, err := MinterKeyFromScalar([32]byte(v.Scalar)); (err == nil) != v.Valid {
			t.Errorf("minter scalar %x: %v", v.Scalar, err)
		}
	}
}

// replayVault replays a vault vector; with skip set it stops after the first step whose expected error is skip and returns
// that step's outcome.
func replayVault(t *testing.T, f *VectorFile, v VaultVector, stopAt *Rule) (error, bool) {
	d := f.Deployments[v.Deployment]
	vt, err := NewVault(d.Gamma, Environment{Address: [20]byte(d.Vault), ChainID: d.ChainID, VerifierCodeHash: [32]byte(d.VerifierHash)}, BuildParams(d.Build))
	if err != nil {
		t.Fatal(err)
	}
	if h := v.Harness; h != nil {
		q, _ := new(big.Int).SetString(h.Outstanding, 10)
		var cur, prev [][32]byte
		for _, x := range h.Current {
			cur = append(cur, [32]byte(x))
		}
		for _, x := range h.Previous {
			prev = append(prev, [32]byte(x))
		}
		vt.SetState(h.Deposits, h.Segment, h.Population, q, [32]byte(h.Head), [32]byte(h.PrevHead), cur, prev)
	}
	for i := range v.Steps {
		st := v.Steps[i]
		before := len(vt.Events)
		err, inner := runStep(vt, &st)
		if stopAt != nil {
			if v.Steps[i].Expect.Error == stopAt.Name || v.Steps[i].Inner == stopAt.Name {
				return err, true
			}
			continue
		}
		if !sameExpect(expectOf(err), v.Steps[i].Expect) || RuleName(inner) != v.Steps[i].Inner {
			t.Errorf("vault %s step %d: %v inner %v, want %v", v.ID, i, err, inner, v.Steps[i].Expect)
			return nil, false
		}
		var evs []EventJSON
		for _, e := range vt.Events[before:] {
			evs = append(evs, eventJSON(vt.Cfg, e))
		}
		a, _ := json.Marshal(evs)
		b, _ := json.Marshal(v.Steps[i].Events)
		if len(evs) == 0 {
			a = []byte("[]")
		}
		if string(a) != string(b) {
			t.Errorf("vault %s step %d: events differ", v.ID, i)
		}
		if state := StateOf(vt); v.Steps[i].State == nil || !sameJSON(state, *v.Steps[i].State) {
			t.Errorf("vault %s step %d: state (accounting word, tag words, heads, buffers) differs", v.ID, i)
		}
	}
	if stopAt == nil {
		got, _ := json.Marshal(StateOf(vt))
		want, _ := json.Marshal(v.Final)
		if string(got) != string(want) {
			t.Errorf("vault %s: final state differs", v.ID)
		}
	}
	return nil, false
}

// vectoredRules is every rule some vector names, as its expected error, the inner rule of a seal receipt, or a vault step's
// inner error.
func vectoredRules(f *VectorFile) map[string]int {
	n := map[string]int{}
	for _, v := range f.Config {
		n[v.Verifier.Error]++
		n[v.Constructor.Error]++
	}
	for _, v := range f.Verifier {
		n[v.Expect.Error]++
	}
	for _, v := range f.Seal {
		n[v.Expect.Error]++
		n[v.Inner]++
	}
	for _, v := range f.Primitives.Unlocks {
		n[v.Expect.Error]++
	}
	for _, v := range f.Gap {
		n[v.Expect.Error]++
	}
	for _, v := range f.Folds {
		n[v.Expect.Error]++
	}
	for _, v := range f.SegmentLogs {
		n[v.Expect.Error]++
	}
	for _, v := range f.Vault {
		for _, s := range v.Steps {
			n[s.Expect.Error]++
			n[s.Inner]++
		}
	}
	for _, v := range f.Wallet.Capacity {
		n[v.Expect.Error]++
	}
	for _, v := range f.Wallet.StateReads {
		n[v.Expect.Error]++
	}
	for _, v := range f.Wallet.Companions {
		n[v.Expect.Error]++
	}
	delete(n, "")
	return n
}

// TestRuleCoverage: every section 14 rule has exactly one sentinel and at least one vector (Unlock has none: unreachable),
// and every vector names a rule.
func TestRuleCoverage(t *testing.T) {
	f, _ := generated(t)
	n := vectoredRules(f)
	seen := map[string]bool{}
	for _, r := range Rules() {
		if seen[r.Name] {
			t.Errorf("rule %s twice", r.Name)
		}
		seen[r.Name] = true
		if n[r.Name] == 0 {
			t.Errorf("rule %s has no vector", r.Name)
		}
		for _, o := range Rules() {
			if o != r && errors.Is(r, o) {
				t.Errorf("sentinel %s matches %s", r.Name, o.Name)
			}
		}
	}
	for name := range n {
		if RuleByName(name) == nil && name != "StateReadNotAdmitted" && name != "CompanionUnknown" && name != "CompanionProvider" {
			t.Errorf("vector names %q, not a rule", name)
		}
	}
	if len(Rules()) != len(specRules) {
		t.Errorf("%d rules, the spec lists %d", len(Rules()), len(specRules))
	}
	for _, s := range specRules {
		if RuleByName(s) == nil {
			t.Errorf("spec rule %s has no sentinel", s)
		}
	}
}

// specRules is section 14 of docs/design/native-bridge-v2.md (protocol 9), in order.
var specRules = strings.Fields(`Truncated Trailing NonCanonical Shape Tag Version Length IntRange InputTooLarge ConfigShape EvidenceShape
MintDomain DepositUC DepositHeader ReceiptPath ReceiptType ReceiptStatus LogIndex LogEmitter LogTopics LogData SecretOpening MintSalt
MintType MintOwner MintData MintReason
NotBurn BurnNotFinal BurnReason ReturnData ReturnDomain ReturnAsset ReturnAmount ReturnRecipient ReturnIndex
Predicate MintShape TransferData CDMismatch UnlockLength UnlockScalars UnlockRecovery UnlockKey RepeatedSID NoTransfers
DeadlineMismatch DeadlineExpired InclusionProof ReferenceTime SealNetwork SealEpoch NoEntryForEpoch CertStructure SealRoot QuorumNotMet
UnsupportedCertificateEncoding SplitJustif SplitProofCount SplitProofShape SplitManifest SplitBurn SplitProof SplitSum
BadHistoryLength FutureIndex StaleEndpoint BadGapProof ChainMismatch AlreadyPaid VerifierRefused VerifierBadReturn DomainMismatch
AssetMismatch ClaimMismatch BadRecipient ZeroAmount LiabilityUnderflow SegmentCounterExhausted PayoutFailed Reentrancy ZeroValue
BadFirstOwner LiabilityCap DepositCounterExhausted BadConfig
SealReceipt SegmentLog CapacityPreflight CapacityExceeded ImplausibleIndex EvidencePruned`)

// exempt are the rules TestDisableEachCheck does not remove, by category. A rule named here still has its isolated negative
// vector; only the "remove it and some vector passes" demonstration does not apply.
var exempt = map[string]string{
	// decoder: the check is the decoding itself; without it there is no value to continue with.
	"Truncated": "decoder", "Trailing": "decoder", "NonCanonical": "decoder", "Shape": "decoder", "Tag": "decoder",
	"Version": "decoder", "Length": "decoder", "IntRange": "decoder", "InputTooLarge": "decoder", "ConfigShape": "decoder",
	"Predicate": "decoder", "SplitJustif": "decoder", "SplitManifest": "decoder", "UnsupportedCertificateEncoding": "decoder",
	"ReceiptType": "decoder", "SegmentLog": "decoder", "BadConfig": "decoder",
	// semantic: removing the check leaves no well-defined next step (no root, no burn, no receipt, no key, no verdict).
	"MintReason": "semantic: the walk has no root", "NoTransfers": "semantic: no final transfer to judge",
	"BurnNotFinal": "semantic: the next transfer has no signing key", "NotBurn": "semantic: no return data",
	"ReturnData": "semantic: no R", "ReceiptPath": "semantic: no receipt without a path", "LogIndex": "semantic: no log",
	"SealNetwork": "semantic: no history to select from", "NoEntryForEpoch": "semantic: no entry to verify under",
	"VerifierRefused": "semantic: no verdict", "VerifierBadReturn": "semantic: no verdict",
	// redundant: another check of the frozen order refuses the same input next.
	"BadHistoryLength": "redundant: no proofs to fold", "BadGapProof": "redundant: the fold then fails as ChainMismatch",
	"FutureIndex": "redundant: a > c makes e > c, so StaleEndpoint follows",
	"Reentrancy":  "redundant: the inner call sees the identifier just paid (AlreadyPaid)",
	// arithmetic: a pure function of its inputs; its vectors are its whole specification.
	"LiabilityUnderflow": "arithmetic: a negative liability is unrepresentable", "CapacityPreflight": "arithmetic",
	"CapacityExceeded": "arithmetic", "ImplausibleIndex": "arithmetic",
	// wallet: wrappers and provider answers.
	"SealReceipt": "wallet: wraps the inner rule", "EvidencePruned": "wallet: a provider answer",
}

// TestDisableEachCheck gives one load-bearing example per rule: for every rule outside exempt it switches that rule's sentinel
// off (at every site bearing the name) and requires at least one of the rule's negative vectors to be accepted then. It is not a
// site-by-site mutation test of every check.
func TestDisableEachCheck(t *testing.T) {
	f := decoded(t)
	defer func() { disabled = nil }()
	trust := map[string]*TrustInput{}
	cfg := map[string]*Config{}
	for name, d := range f.Deployments {
		trust[name] = trustOf(t, d)
		cfg[name], _ = DecodeConfig(d.Gamma, BuildParams(d.Build))
	}
	var names []string
	for name := range vectoredRules(f) {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r := RuleByName(name)
		if r == nil || (exempt[name] != "" && os.Getenv("NB2_DISABLE_ALL") == "") {
			continue
		}
		disabled = map[*Rule]bool{r: true}
		var passed []string
		for _, v := range f.Verifier {
			if v.Expect.Error != name {
				continue
			}
			gamma := f.Deployments[v.Deployment].Gamma
			if v.Gamma != nil {
				gamma = v.Gamma
			}
			if _, err := VerifyReturn(gamma, v.Evidence, trust[v.Deployment], BuildParams(f.Deployments[v.Deployment].Build)); err == nil {
				passed = append(passed, v.ID)
			}
		}
		for _, v := range f.Seal {
			if v.Inner != name {
				continue
			}
			if _, err := VerifySealReceipt(cfg[v.Deployment], trust[v.Deployment], v.Receipt); err == nil {
				passed = append(passed, v.ID)
			}
		}
		for _, v := range f.Primitives.Unlocks {
			if key, err := ParseKey(v.Key); err == nil && v.Expect.Error == name && VerifyUnlockDigest(key, [32]byte(v.Digest), v.Unlock) == nil {
				passed = append(passed, v.ID)
			}
		}
		for _, v := range f.Vault {
			if err, hit := replayVault(t, f, v, r); hit && err == nil {
				passed = append(passed, v.ID)
			}
		}
		if len(passed) == 0 {
			t.Errorf("disabling %s lets no negative vector pass", name)
		} else {
			t.Logf("disabling %s passes %v", name, passed)
		}
	}
}
