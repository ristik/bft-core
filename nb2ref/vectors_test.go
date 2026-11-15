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
	return got.Error == want.Error && strings.Join(got.Args, ",") == strings.Join(want.Args, ",")
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
		_, err := VerifySealReceipt(cfg[v.Deployment], trust[v.Deployment], v.Receipt)
		if !sameExpect(expectOf(err), v.Expect) || (err != nil && RuleName(errorsUnwrapOnce(err)) != v.Inner) {
			t.Errorf("seal %s: %v", v.ID, err)
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
		_, err := CheckSegmentLog([32]byte(v.Domain), v.K, v.Segment, [32]byte(v.ExpectBefore), v.Data)
		if !sameExpect(expectOf(err), v.Expect) {
			t.Errorf("segment log %s: %v", v.ID, err)
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
		if !sameExpect(expectOf(err), v.Expect) || MaxProofs(v.LMax, v.LT, v.LO, v.K) != v.PMax {
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

// structural are the rules whose check is the decoding itself (or a shape without which the rest of the relation is undefined):
// removing them is not a meaningful single-check deletion. Each still has its isolated negative vector.
var structural = map[string]string{
	"Truncated": "decoder", "Trailing": "decoder", "NonCanonical": "decoder", "Shape": "decoder", "Tag": "decoder", "Version": "decoder",
	"Length": "decoder", "IntRange": "decoder", "InputTooLarge": "decoder", "ConfigShape": "decoder", "Predicate": "decoder",
	"SplitJustif": "decoder", "SplitManifest": "decoder (no root to allocate against)", "UnsupportedCertificateEncoding": "decoder",
	"ReceiptType": "decoder (no receipt to read)", "SegmentLog": "wallet decoder", "BadConfig": "constructor decoder",
	"MintReason": "the walk has no root without it", "NoTransfers": "a token without a final transfer has no burn to judge",
	"BurnNotFinal": "the next transfer has no signing key", "NotBurn": "a part without a burn has no return data",
	"ReturnData": "no R to judge", "ReceiptPath": "no receipt without a path", "LogIndex": "no log to read",
	"SealNetwork": "no entry to verify under", "NoEntryForEpoch": "no entry to verify under",
	"BadHistoryLength": "no proofs to fold", "BadGapProof": "a refused proof derives no root; folding on would fail as ChainMismatch",
	"FutureIndex":     "a > c makes e = a + P > c, so StaleEndpoint refuses it next",
	"VerifierRefused": "no verdict", "VerifierBadReturn": "no verdict", "LiabilityUnderflow": "a negative liability is unrepresentable",
	"Reentrancy":  "the inner call would see the identifier just paid (AlreadyPaid): the guard is not the only barrier in the model",
	"SealReceipt": "wrapper of the inner rule", "CapacityPreflight": "pure arithmetic", "CapacityExceeded": "pure arithmetic",
	"ImplausibleIndex": "pure arithmetic", "EvidencePruned": "a provider answer, no relation",
}

// TestDisableEachCheck removes each semantic check alone and requires at least one of its negative vectors to be accepted
// then: the check is load-bearing, and the vector isolates it.
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
		if r == nil || (structural[name] != "" && os.Getenv("NB2_DISABLE_ALL") == "") {
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
