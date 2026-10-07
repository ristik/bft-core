package b1gen

import (
	"encoding/hex"
	"encoding/json"
)

// FormatVersion identifies the manifest layout.
const FormatVersion = "b1-vectors/a-prime"

// Pins are the source revisions the design (b1-design-v4.md) was
// written against.
var Pins = map[string]string{
	"B": "c57f012af8284cab214353841070ce368c6b001e (bft-core)",
	"C": "deferred: PR3 has not started; no A-prime runtime pin",
	"G": "01ab63a83bf5 (bft-go-base)",
	"R": "696de8dc62fea8f2509168bf24a7c891f7b533d7 (rugregator)",
	"U": "7e76c4e5d74ebb4fd88548d350d7229160b634df (ureth)",
}

// EpochWords is the registry's words for one epoch.
type EpochWords struct {
	Epoch   uint64        `json:"epoch"`
	Members []MemberWords `json:"members"`
	BodyID  string        `json:"bodyID"`
	Start   uint64        `json:"start"`
	End     uint64        `json:"end"`
}

type MemberWords struct {
	NodeID string `json:"nodeID"`
	Key    string `json:"key"`
	Weight uint64 `json:"weight"`
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
	Format   string            `json:"format"`
	Seed     string            `json:"seed"`
	Pins     map[string]string `json:"pins"`
	Notes    []string          `json:"notes"`
	Vectors  []Vector          `json:"vectors"`
	Deferred []Deferred        `json:"deferred"`
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

var Notes = []string{
	"Registry pre-state is an injected simulation, never authenticated admission.",
	"Candidate A′ gas formulas require benchmarks before activation.",
	"The v4 classification table is frozen; no provisional caller classifications remain.",
}
