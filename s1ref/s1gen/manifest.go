package s1gen

import (
	"encoding/hex"
	"encoding/json"
)

// FormatVersion identifies the manifest layout.
const FormatVersion = "s1-vectors/1"

// Pins are the source revisions the design (s1-design.md) was written against.
var Pins = map[string]string{
	"B":  "1384caf2b61a4700980ec7b6bbda7fa10adcec7e (bft-core, B1 oracle #390)",
	"Q":  "e33070b608d6c28ea3740482250950434ad26bba (bft-core, Q1 #394)",
	"G":  "01ab63a83bf5 (bft-go-base)",
	"S1": "briefs/s1-design.md (2026-10-04, not yet reviewed)",
	"V2": "briefs/b1-design-v2.md",
}

// EpochJSON is the authenticated context of one voting epoch.
type EpochJSON struct {
	Epoch      uint64 `json:"epoch"`
	ViewHash   string `json:"viewHash"`
	BodyID     string `json:"bodyID"`
	SourceKind uint64 `json:"sourceKind"`
	Start      uint64 `json:"start"`
	End        uint64 `json:"end"`
	Scheme     uint64 `json:"scheme"`
	SigNetwork uint64 `json:"signingNetwork"`
	Genesis    string `json:"genesis"`
}

// ContextJSON is the explicit injected context of a vector.
type ContextJSON struct {
	Network   uint16      `json:"network"`
	OpenEpoch uint64      `json:"openEpoch"`
	Epochs    []EpochJSON `json:"epochs"`
}

// Expected is the result every implementation must reproduce. Status "error"
// is a precompile halt (Sentinel names the reason); status "ok" returns the
// 64-byte or 384-byte Output, with Valid=false carrying the false reason in
// Sentinel. Gas is the formula charge of an "ok" vector.
type Expected struct {
	Status   string `json:"status"`
	Valid    *bool  `json:"valid,omitempty"`
	Sentinel string `json:"sentinel,omitempty"`
	Output   string `json:"output,omitempty"`
	Gas      uint64 `json:"gas,omitempty"`
}

// Vector is one request with its injected context and expected result.
type Vector struct {
	ID           string            `json:"id"`
	Family       string            `json:"family"`
	Description  string            `json:"description"`
	Context      *ContextJSON      `json:"context,omitempty"`
	Request      string            `json:"request"`
	Intermediate map[string]string `json:"intermediate,omitempty"`
	Expected     Expected          `json:"expected"`
}

// Manifest is the JSON document exchanged between generators.
type Manifest struct {
	Format       string            `json:"format"`
	Seed         string            `json:"seed"`
	SourceSHA256 string            `json:"q1VectorsSHA256"`
	Pins         map[string]string `json:"pins"`
	Notes        []string          `json:"notes"`
	OpenItems    []OpenItem        `json:"openItems"`
	Vectors      []Vector          `json:"vectors"`
	Deferred     []Deferred        `json:"deferred"`
}

// JSON renders the manifest deterministically.
func (m *Manifest) JSON() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func hx(b []byte) string { return hex.EncodeToString(b) }

// Deferred names a design vector that needs more than a Go oracle.
type Deferred struct {
	Family string `json:"family"`
	Row    string `json:"row"`
	Reason string `json:"reason"`
}

// OpenItem is a point where the design is silent or narrower than the native
// code, and the oracle made a recorded choice. Vectors that depend on one
// name its ID in their description.
type OpenItem struct {
	ID       string `json:"id"`
	Question string `json:"question"`
	Choice   string `json:"choice"`
}

// OpenItems are the choices recorded while implementing the design.
var OpenItems = []OpenItem{
	{"S1-O1", "Scheme 1 VoteInfo exec is bstr32 in the design; the native RoundInfo.CurrentRootHash is a variable-length byte string that the legacy verifier hashes unchecked.", "bstr32 only, as designed: a legacy vote with another width is malformed (ErrShape), so such historical evidence is out of scope of this profile"},
	{"S1-O2", "\"Apply Q1 statement rules\" follows both scheme paragraphs; the legacy verifier applies only RoundInfo.IsValid, the binding and the signature.", "the Q1 statement rules (votesig preimage rules, commit network/epoch, empty seal of a non-committing vote) apply to scheme 2 only; scheme 1 gets native IsValid, the binding, the single signature and sealSignature=null"},
	{"S1-O3", "The design gives the signing configuration network no cross-check against N.", "a context whose signing configuration is invalid (unknown scheme, scheme 2 with zero G) or whose network differs from N is false (ErrSigningConfig): an authenticated context cannot legitimately carry one"},
	{"S1-O4", "An evidence record whose voting epoch differs from the carried view's epoch.", "false (ErrEpochMismatch): the view is authenticated for exactly one epoch, so it can authorise only votes of that epoch"},
}

// Notes qualify every number in the manifest.
var Notes = []string{
	"The context of each vector is an injected precondition of the oracle, not an authenticated state read.",
	"Gas values are results of the candidate formula 2000+16*B+1000*M+6000*S+2000*N in the design, not benchmarked values.",
	"Scheme 1 true results never assert a slashable offence: domainHash and conflictID are zero and the network is not a signed binding.",
	"Vectors named q1.* reuse the signed bytes of network/protocol/abdrc/testdata/domain_bound_vectors.json without re-signing; all others are signed here with fixed seeds.",
}
