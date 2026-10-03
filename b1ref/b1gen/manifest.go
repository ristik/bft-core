package b1gen

import (
	"encoding/hex"
	"encoding/json"
)

// FormatVersion identifies the manifest layout.
const FormatVersion = "b1-vectors/1"

// Pins are the source revisions the design (b1-design.md section 1) was
// written against.
var Pins = map[string]string{
	"B": "d519c8d8c6ab64313f53192b8f7e06c24a449769 (bft-core)",
	"C": "ce3e40b479de0a0ef8787d8830ba77189aa11171 (unicity-pos-contracts)",
	"G": "01ab63a83bf5 (bft-go-base)",
	"R": "696de8dc62fea8f2509168bf24a7c891f7b533d7 (rugregator)",
	"U": "b4e7cb0ace07eee70e753241e0139c4d42b516d4 (ureth)",
}

// EpochWords is the registry's words for one epoch.
type EpochWords struct {
	Epoch    uint64 `json:"epoch"`
	ViewHash string `json:"viewHash"`
	BodyID   string `json:"bodyID"`
	Start    uint64 `json:"start"`
	End      uint64 `json:"end"`
}

// PreState is the explicit registry context of a vector.
type PreState struct {
	Network    uint16       `json:"network"`
	WCert      uint64       `json:"wCert"`
	Origin     uint64       `json:"origin"`
	ClockRound uint64       `json:"clockRound"`
	Epochs     []EpochWords `json:"epochs"`
}

// Expected is the result every implementation must reproduce. Status "error"
// is a precompile halt (Sentinel names the reason); status "ok" returns the
// 64-byte Output, with Valid=false carrying the false reason in Sentinel.
type Expected struct {
	Status   string `json:"status"`
	Valid    *bool  `json:"valid,omitempty"`
	Sentinel string `json:"sentinel,omitempty"`
	Output   string `json:"output,omitempty"`
	Gas      uint64 `json:"gas,omitempty"`
}

// Vector is one request with its pre-state and expected result.
type Vector struct {
	ID           string            `json:"id"`
	Family       string            `json:"family"`
	Op           string            `json:"op"`
	Description  string            `json:"description"`
	PreState     *PreState         `json:"preState,omitempty"`
	Request      string            `json:"request"`
	SealSigBytes string            `json:"sealSigBytes,omitempty"`
	SealDigest   string            `json:"sealDigest,omitempty"`
	Intermediate map[string]string `json:"intermediate,omitempty"`
	Provisional  string            `json:"provisional,omitempty"` // open item ID, when the expectation is not frozen by the design
	Expected     Expected          `json:"expected"`
}

// Deferred names a section 5 row that depends on transition v4.
type Deferred struct {
	Family string `json:"family"`
	Row    string `json:"row"`
	Reason string `json:"reason"`
}

// Manifest is the JSON document exchanged between generators.
type Manifest struct {
	Format    string            `json:"format"`
	Seed      string            `json:"seed"`
	Pins      map[string]string `json:"pins"`
	Notes     []string          `json:"notes"`
	OpenItems []OpenItem        `json:"openItems"`
	Vectors   []Vector          `json:"vectors"`
	Deferred  []Deferred        `json:"deferred"`
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

// outputWords is abi.encode(uint256(1), bool(valid)).
func outputWords(valid bool) []byte {
	out := make([]byte, 64)
	out[31] = 1
	if valid {
		out[63] = 1
	}
	return out
}

// OpenItem is a classification the design leaves ambiguous. The generator and
// the oracle each carry a provisional choice, recorded here so that nobody
// mistakes it for a design decision; vectors that depend on one name its ID.
type OpenItem struct {
	ID       string `json:"id"`
	Question string `json:"question"`
	Choice   string `json:"provisionalChoice"`
}

// OpenItems are the review's ambiguities (b1-design-review.md finding 2).
var OpenItems = []OpenItem{
	{"O1", "A bstr33 view key that is not a secp256k1 point: structural or semantic?", "malformed (ErrViewKey)"},
	{"O2", "Signature of a wrong byte length, or 65 bytes with v outside {0,1}: structural or semantic?", "false (ErrSigFormat); the v restriction is B1 profile policy, the native verifier strips the byte unchecked"},
	{"O3", "Claims or members out of sorted order, and duplicates: structural or semantic?", "unsorted is malformed (ErrClaimOrder, ErrViewOrder); duplicates are false (ErrDuplicateClaim, ErrViewDuplicate)"},
	{"O4", "Null or wrongly typed nested objects and path items: structural or semantic?", "malformed (ErrShape)"},
	{"O5", "Null versus empty signature container in a seal: structural or semantic?", "null is malformed (ErrShape); an empty map is false through the native nonempty-signatures rule (ErrNativeInvalid)"},
	{"O6", "Unequal complete seals in a shared call, and the value of S for the gas count when no common seal exists.", "false (ErrSealMismatch); S is the signature-map size of the first claim's seal; the review suggests the maximum across claims instead"},
	{"O7", "Trust view with no members, unknown sourceKind, or weight other than 1.", "empty and unknown kind are malformed (ErrViewEmpty, ErrViewKind); weight is false (ErrWeightProfile)"},
	{"O8", "The design never says the seal epoch must equal the trust view epoch.", "required, false otherwise (ErrSealEpoch). Not a discretionary trust-source choice: the registry authenticates the view for one epoch, so a seal is authorised by that view only if the seal's own epoch is that epoch; any other seal epoch would let one epoch's key commitment authorise a seal claiming another"},
}

// Notes qualify every number in the manifest.
var Notes = []string{
	"The registry pre-state of each vector is an injected precondition of the oracle, not an authenticated registry read.",
	"Gas values are results of the candidate formula in the design, not benchmarked or on-chain measured values.",
	"Vectors marked provisional depend on an open item and are not final until the design freezes it.",
}
