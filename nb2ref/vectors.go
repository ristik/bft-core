package nb2ref

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// The shared vector file (NB2-03 acceptance): one versioned JSON document that TypeScript, Rust and Solidity consume, imported
// by its SHA-256 digest. Generate builds it deterministically; every vector is replayed against this reference while it is
// built, so a vector whose expectation does not hold is a generator error, never a committed vector.
//
// Regenerate with
//
//	go run ./nb2ref/cmd/nb2vectors -out <native-bridge-plugins>/protocol/vectors/nb2
//
// which writes nb2-vectors.json and nb2-vectors.json.sha256; nb2ref/testdata/nb2-vectors.json.sha256 pins the same digest here.

// VectorFileVersion is the vector file's own format version.
const VectorFileVersion = 1

// Hex is a byte string in JSON as 0x-prefixed lowercase hex.
type Hex []byte

func (h Hex) MarshalJSON() ([]byte, error) { return json.Marshal("0x" + hex.EncodeToString(h)) }

func (h *Hex) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	if !strings.HasPrefix(s, "0x") {
		return fmt.Errorf("hex without 0x")
	}
	d, err := hex.DecodeString(s[2:])
	*h = d
	return err
}

func h32(b [32]byte) Hex { return Hex(b[:]) }

// Expect is a vector's expected outcome: Error empty means acceptance.
type Expect struct {
	Error string   `json:"error,omitempty"`
	Args  []string `json:"args,omitempty"` // the custom error's arguments (vault errors), decimal or 0x hex
}

// VectorFile is the document.
type VectorFile struct {
	Version     int                    `json:"version"`
	Protocol    int                    `json:"nativeBridgeProtocolVersion"`
	Profile     Hex                    `json:"semanticProfileHash"`
	Spec        string                 `json:"specification"`
	Generator   string                 `json:"generator"`
	Admitted    map[string][]uint64    `json:"admittedParams"`
	Notes       []string               `json:"notes"`
	Rules       []RuleInfo             `json:"rules"`
	Deployments map[string]*Deployment `json:"deployments"`
	Config      []ConfigVector         `json:"config"`
	Verifier    []VerifierVector       `json:"verifier"`
	Seal        []SealReceiptVector    `json:"sealReceipts"`
	Gap         []GapVector            `json:"gapProofs"`
	Folds       []FoldVector           `json:"chainFolds"`
	SegmentLogs []SegmentLogVector     `json:"segmentLogs"`
	Vault       []VaultVector          `json:"vault"`
	Wallet      WalletVectors          `json:"wallet"`
	Primitives  PrimitiveVectors       `json:"primitives"`
}

// RuleInfo is one section 14 rule with its error selector H_E("<Name>(<args>)")[0..4].
type RuleInfo struct {
	Name      string `json:"name"`
	Section   string `json:"section"`
	Signature string `json:"signature"`
	Selector  Hex    `json:"selector"`
	Retry     bool   `json:"retryable,omitempty"`
	Reachable string `json:"unreachable,omitempty"` // why no input can raise it, when none can
}

// errorSignatures are the vault errors with arguments (section 13.3); every other rule is Name().
var errorSignatures = map[string]string{
	"LiabilityCap":       "LiabilityCap(uint256,uint256,uint256)",
	"BadHistoryLength":   "BadHistoryLength(uint256)",
	"FutureIndex":        "FutureIndex(uint64,uint64)",
	"StaleEndpoint":      "StaleEndpoint(uint64,uint64)",
	"BadGapProof":        "BadGapProof(uint256)",
	"AlreadyPaid":        "AlreadyPaid(bytes32)",
	"VerifierRefused":    "VerifierRefused(bytes)",
	"LiabilityUnderflow": "LiabilityUnderflow(uint256,uint256)",
	"BadConfig":          "BadConfig(uint256)",
}

// unreachable lists the rules no input can raise, with the reason (none since Unlock and MinterKey were dropped).
var unreachable = map[string]string{}

// Signature is the rule's error signature.
func (r *Rule) Signature() string {
	if s, ok := errorSignatures[r.Name]; ok {
		return s
	}
	return r.Name + "()"
}

// Deployment is one Γ with its trust-base history.
type Deployment struct {
	Build        string `json:"build"` // "production" or "test": the admitted (K, B) set
	Gamma        Hex    `json:"gamma"`
	Domain       Hex    `json:"domain"`
	K            uint64 `json:"K"`
	B            uint64 `json:"B"`
	TrustBundle  Hex    `json:"trustBundle"`
	TrustGenesis Hex    `json:"trustGenesisEntryId"`
	GenesisHead  Hex    `json:"genesisHead"`
	Vault        Hex    `json:"vault"`
	ChainID      uint64 `json:"chainId"`
	VerifierHash Hex    `json:"verifierCodeHash"`
}

// ConfigVector is a Γ judged by the verifier (decode only: ConfigShape) and by the vault constructor (BadConfig(field)) in
// the deployment's environment.
type ConfigVector struct {
	ID          string `json:"id"`
	Deployment  string `json:"deployment"`
	Gamma       Hex    `json:"gamma"`
	Address     Hex    `json:"address"`
	ChainID     uint64 `json:"chainId"`
	CodeHash    Hex    `json:"verifierCodeHash"`
	Verifier    Expect `json:"verifier"`
	Constructor Expect `json:"constructor"`
	Domain      Hex    `json:"domain,omitempty"`
}

// VerifierVector is verifyReturn(Γ, evidence) under the deployment's trust history.
type VerifierVector struct {
	ID         string       `json:"id"`
	Deployment string       `json:"deployment"`
	Note       string       `json:"note,omitempty"`
	Gamma      Hex          `json:"gamma,omitempty"` // when not the deployment's
	Evidence   Hex          `json:"evidence"`
	Expect     Expect       `json:"expect"`
	Verdict    *VerdictJSON `json:"verdict,omitempty"`
}

// VerdictJSON is the accepted tuple and its exact ABI return.
type VerdictJSON struct {
	Domain     Hex    `json:"domain"`
	Eta        Hex    `json:"eta"`
	MinSegment uint64 `json:"minSegment"`
	Asset      Hex    `json:"asset"`
	Recipient  Hex    `json:"recipient"`
	Amount     string `json:"amount"`
	ABI        Hex    `json:"abi"`
}

func verdictJSON(v *Verdict) *VerdictJSON {
	return &VerdictJSON{Domain: h32(v.Domain), Eta: h32(v.Eta), MinSegment: v.MinSegment, Asset: h32(v.Asset), Recipient: Hex(v.Recipient[:]),
		Amount: v.Amount.String(), ABI: v.ABI()}
}

// SealReceiptVector is a wallet's verification of a SegmentSealed receipt proof (section 12.2).
type SealReceiptVector struct {
	ID         string `json:"id"`
	Deployment string `json:"deployment"`
	Note       string `json:"note,omitempty"`
	Receipt    Hex    `json:"receipt"`
	Expect     Expect `json:"expect"`
	Inner      string `json:"innerRule,omitempty"` // the rule SealReceipt wraps
	Segment    uint64 `json:"segment,omitempty"`
	HeadAfter  Hex    `json:"headAfter,omitempty"`
	BurnIndex  uint64 `json:"burnIndex,omitempty"`
}

// GapVector is one gap proof against a set: root is M of the sorted ids; the proof is valid for eta iff Expect is empty.
type GapVector struct {
	ID     string `json:"id"`
	K      uint64 `json:"K"`
	IDs    []Hex  `json:"ids"`
	Root   Hex    `json:"root"`
	Eta    Hex    `json:"eta"`
	Proof  Hex    `json:"proof"`
	Expect Expect `json:"expect"` // BadGapProof (position 0) when invalid
}

// FoldVector is redeem step 3 alone: FoldHistory(D, K, eta, a, startHead, proofs) compared with the expected head.
type FoldVector struct {
	ID         string `json:"id"`
	Domain     Hex    `json:"domain"`
	K          uint64 `json:"K"`
	Eta        Hex    `json:"eta"`
	Start      uint64 `json:"a"`
	History    Hex    `json:"history"`
	StoredHead Hex    `json:"storedHead"`
	Expect     Expect `json:"expect"` // BadGapProof(position) or ChainMismatch
}

// SegmentLogVector is a wallet's check of one SegmentSealed log.
type SegmentLogVector struct {
	ID           string `json:"id"`
	Domain       Hex    `json:"domain"`
	K            uint64 `json:"K"`
	Segment      uint64 `json:"segment"`
	ExpectBefore Hex    `json:"expectedHeadBefore"`
	Data         Hex    `json:"data"`
	Expect       Expect `json:"expect"`
}

// VaultVector is a vault sequence from its constructed state (or a harness-injected one).
type VaultVector struct {
	ID         string      `json:"id"`
	Deployment string      `json:"deployment"`
	Note       string      `json:"note,omitempty"`
	Harness    *VaultState `json:"harnessState,omitempty"`
	Steps      []VaultStep `json:"steps"`
	Final      VaultState  `json:"final"`
}

// VaultState is the observable state: state() and the live buffers in arrival order.
type VaultState struct {
	Deposits    uint64 `json:"deposits"`
	Segment     uint64 `json:"segment"`
	Population  uint64 `json:"population"`
	Outstanding string `json:"outstanding"`
	Head        Hex    `json:"head"`
	PrevHead    Hex    `json:"previousHead"`
	Current     []Hex  `json:"current"`
	Previous    []Hex  `json:"previous"`
}

// VaultStep is one call.
type VaultStep struct {
	Op string `json:"op"` // "deposit" or "redeem"
	// deposit
	Value      string `json:"value,omitempty"`
	FirstOwner Hex    `json:"firstOwner,omitempty"`
	Rho        Hex    `json:"rho,omitempty"`
	// redeem
	ClaimedEta     Hex         `json:"claimedEta,omitempty"`
	ClaimedStart   uint64      `json:"claimedStart"`
	History        Hex         `json:"history,omitempty"`
	VerifierReturn Hex         `json:"verifierReturn,omitempty"`
	VerifierRevert Hex         `json:"verifierRevert,omitempty"`
	Recipient      string      `json:"recipient,omitempty"` // accepts | reverts | reenters-redeem | reenters-deposit
	Expect         Expect      `json:"expect"`
	Inner          string      `json:"innerError,omitempty"`
	Events         []EventJSON `json:"events"`
}

// EventJSON is one emitted log.
type EventJSON struct {
	Name   string `json:"name"`
	Topics []Hex  `json:"topics"`
	Data   Hex    `json:"data"`
}

func eventJSON(c *Config, e Event) EventJSON {
	switch e.Name {
	case "Deposited":
		return EventJSON{Name: e.Name, Topics: []Hex{h32(TopicDeposited), h32(u256u(e.N))}, Data: DepositedData(c.Domain(), e.Amount, e.Rho, e.FirstOwner)}
	case "Paid":
		var r [32]byte
		copy(r[12:], e.Recipient[:])
		return EventJSON{Name: e.Name, Topics: []Hex{h32(TopicPaid), h32(e.Eta), h32(r)}, Data: h32(u256(e.Amount))}
	default:
		return EventJSON{Name: e.Name, Topics: []Hex{h32(TopicSegmentSealed), h32(u256u(e.Segment))}, Data: SegmentSealedData(e.Before, e.After, e.IDs)}
	}
}

// WalletVectors are the pure wallet refusals.
type WalletVectors struct {
	Companions []CompanionVector `json:"companions"`
	Capacity   []CapacityVector  `json:"capacity"`
	StateReads []StateReadVector `json:"stateReads"`
}

// CapacityVector: stage "preflight" (history owed from a plus the reserve, bytes and gas) or "redemption" (proofs, gas).
type CapacityVector struct {
	ID           string `json:"id"`
	Stage        string `json:"stage"`
	LMax         uint64 `json:"maxEncodedTxBytes"`
	LT           uint64 `json:"evidenceBytes"`
	LO           uint64 `json:"otherBytes"`
	K            uint64 `json:"K"`
	PMax         uint64 `json:"pMax"`
	A            uint64 `json:"a,omitempty"`
	CObs         uint64 `json:"currentSegment,omitempty"`
	Reserve      uint64 `json:"returnReserveSegments,omitempty"`
	GasBase      uint64 `json:"gasBase,omitempty"`     // preflight gas model: gasBase + gasPerProof * (cObs - a + reserve)
	GasPerProof  uint64 `json:"gasPerProof,omitempty"` // (expected cost plus gasReserve, conservative)
	Proofs       uint64 `json:"proofs,omitempty"`
	GasLimit     uint64 `json:"gasLimit,omitempty"`
	UserGasLimit uint64 `json:"userGasLimit,omitempty"`
	Expect       Expect `json:"expect"`
}

// CompanionVector is one unicity_getSealCompanionV1 answer (section 12.7); non-rule outcomes are "CompanionUnknown" (retry)
// and "CompanionProvider" (use another provider).
type CompanionVector struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	Witnesses int    `json:"witnesses"`
	Expect    Expect `json:"expect"`
}

// StateReadVector is the stateReadOnly substitute for a seal receipt.
type StateReadVector struct {
	ID            string `json:"id"`
	StateReadOnly bool   `json:"stateReadOnly"`
	Read          uint64 `json:"read"`
	Verified      uint64 `json:"verified"`
	MaxJump       uint64 `json:"maxJump"`
	Expect        Expect `json:"expect"` // "" accepts; "StateReadNotAdmitted" is not a rule
}

// PrimitiveVectors are rule-level checks no whole input can reach.
type PrimitiveVectors struct {
	MinterScalars []MinterScalarVector `json:"minterScalars"`
	Constants     map[string]Hex       `json:"constants"`
}

// MinterScalarVector: the universal minter scalar is admitted iff 1 <= k < n (never reduced). No rule name: no token ID with
// an invalid scalar is known.
type MinterScalarVector struct {
	Scalar Hex  `json:"scalar"`
	Valid  bool `json:"valid"`
}

// expectOf renders an error as an expectation.
func expectOf(err error) Expect {
	if err == nil {
		return Expect{}
	}
	var ae *ArgsError
	if errors.As(err, &ae) {
		return Expect{Error: ae.Rule.Name, Args: ae.Args}
	}
	var pe *PositionError
	if errors.As(err, &pe) {
		return Expect{Error: pe.Rule.Name, Args: []string{fmt.Sprint(pe.Position)}}
	}
	var bc *BadConfigError
	if errors.As(err, &bc) {
		return Expect{Error: "BadConfig", Args: []string{fmt.Sprint(bc.Field)}}
	}
	if r := RuleOf(err); r != nil {
		return Expect{Error: r.Name}
	}
	for e, name := range map[error]string{ErrStateReadNotAdmitted: "StateReadNotAdmitted", ErrCompanionUnknown: "CompanionUnknown", ErrCompanionProvider: "CompanionProvider"} {
		if errors.Is(err, e) {
			return Expect{Error: name}
		}
	}
	return Expect{Error: "?" + err.Error()}
}

func deploymentOf(w *World) *Deployment {
	return &Deployment{Build: w.Build, Gamma: w.Gamma, Domain: h32(w.Cfg.Domain()), K: w.Cfg.K, B: w.Cfg.B, TrustBundle: w.Trust.Bundle,
		TrustGenesis: h32(w.Trust.ID()), GenesisHead: h32(GenesisHead(w.Cfg.Domain(), w.Cfg.K)), Vault: Hex(w.Cfg.Vault[:]),
		ChainID: w.Cfg.ChainID, VerifierHash: h32(w.Cfg.VerifierCodeHash)}
}

// gen is the generator's state.
type gen struct {
	f      *VectorFile
	worlds map[string]*World
	ids    map[string]bool
}

func (g *gen) id(s string) string {
	if g.ids[s] {
		panic("nb2: duplicate vector id " + s)
	}
	g.ids[s] = true
	return s
}

// Generate builds the vector file.
func Generate() (*VectorFile, error) {
	g := &gen{worlds: map[string]*World{}, ids: map[string]bool{}}
	g.f = &VectorFile{Version: VectorFileVersion, Protocol: NativeBridgeProtoVersion, Profile: h32(SemanticProfileHash),
		Spec:      "ristik/bft-core docs/design/native-bridge-v2.md (NB2-01, #1097), protocol 9; native-bridge-plugins protocol/interop.md",
		Generator: "go run ./nb2ref/cmd/nb2vectors -out <dir> (ristik/bft-core, NB2-03 #1099)",
		Admitted: map[string][]uint64{"productionK": keys(CandidateParams.K), "productionB": keys(CandidateParams.B),
			"testK": keys(TestParams.K), "testB": keys(TestParams.B)},
		Notes: []string{
			"Each deployment names its build: production admits only (K, B) = (64, 16) (#1098); test admits K in {4, 8}, B in {2, 4}; never both. Judge a deployment's Γ, tokens and vault under its own build.",
			"Every vector is replayed by the Go reference while the file is generated. A negative vector isolates one rule: every other check of the input holds.",
			"Errors are rule names (section 14); the on-chain error is <Name>() or the vault signature in rules[].signature with the args given.",
			"Deposit evidence is vectored inside whole tokens (verifier); seal receipts stand alone (sealReceipts).",
		},
		Deployments: map[string]*Deployment{}}
	for _, r := range Rules() {
		ri := RuleInfo{Name: r.Name, Section: r.Section, Signature: r.Signature(), Retry: r.Retry, Reachable: unreachable[r.Name]}
		sel := HE([]byte(ri.Signature))
		ri.Selector = Hex(sel[:4])
		g.f.Rules = append(g.f.Rules, ri)
	}
	for _, d := range []struct {
		name   string
		k, b   uint64
		shards int
	}{{"main", 64, 16, 1}, {"sharded", 64, 16, 2}, {"k4", 4, 2, 1}, {"k8", 8, 4, 1}} {
		w, err := NewWorld(d.k, d.b, d.shards)
		if err != nil {
			return nil, err
		}
		g.worlds[d.name] = w
		g.f.Deployments[d.name] = deploymentOf(w)
	}
	for _, step := range []func() error{g.configs, g.verifier, g.sealReceipts, g.gapProofs, g.folds, g.segmentLogs, g.vault, g.wallet, g.primitives} {
		if err := step(); err != nil {
			return nil, err
		}
	}
	return g.f, nil
}

func keys(m map[uint64]bool) []uint64 {
	var out []uint64
	for k := range m {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Encode is the file's exact bytes: indented JSON with a final newline.
func (f *VectorFile) Encode() ([]byte, error) {
	b, err := json.MarshalIndent(f, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Digest is the SHA-256 of the exact file bytes.
func Digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func checkExpect(id string, got error, want string) error {
	if g := expectOf(got).Error; g != want {
		return fmt.Errorf("nb2 vector %s: got %q (%v), want %q", id, g, got, want)
	}
	return nil
}

func amountString(v *big.Int) string { return v.String() }
