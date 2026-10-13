package b1gen

import (
	"encoding/hex"
	"encoding/json"
)

// FormatVersion identifies the manifest layout (briefs/b1-any-age-contract.md section 0).
const FormatVersion = "b1-vectors/any-age-v1"

// Pins are the sources the vectors are written against.
var Pins = map[string]string{
	"contract": "briefs/b1-any-age-contract.md (arch, 2026-10-14; rev2 review pending)",
	"design":   "briefs/b1-any-age-by-signatures.md (revised 2026-10-14)",
}

// EpochWords is one installed registry entry (contract section 1).
type EpochWords struct {
	Epoch              uint64        `json:"epoch"`
	BodyKind           uint64        `json:"bodyKind"`
	BodyID             string        `json:"bodyID"`
	ActivationCommitID string        `json:"activationCommitID"`
	Start              uint64        `json:"start"`
	End                uint64        `json:"end"`
	HasEnd             bool          `json:"hasEnd"`
	SigningScheme      uint64        `json:"signingScheme"`
	SigningConfigHash  string        `json:"signingConfigHash"`
	Members            []MemberWords `json:"members"`
}

type MemberWords struct {
	NodeID string `json:"nodeID"`
	Key    string `json:"key"`
	Weight uint64 `json:"weight"`
}

// SlotWord is one 32-byte registry word at the registry address.
type SlotWord struct {
	Slot  string `json:"slot"`
	Value string `json:"value"`
}

// PreState is a vector's registry state. The typed fields describe it; Storage is what every implementation reads: every
// nonzero word at the registry address, sorted by slot, after Overrides. PinnedProfileHash is what the verifier is built with.
type PreState struct {
	Network           uint16       `json:"network"`
	Phase             uint64       `json:"phase"`
	GenesisCommitment string       `json:"genesisCommitment"`
	ProfileHash       string       `json:"profileHash"`
	PinnedProfileHash string       `json:"pinnedProfileHash"`
	GenesisEpoch      uint64       `json:"genesisEpoch"`
	ImportedTip       uint64       `json:"importedTipEpoch"`
	OriginReady       bool         `json:"originReady"`
	Origin            uint64       `json:"originEpoch"`
	ClockRound        uint64       `json:"clockRound"`
	Epochs            []EpochWords `json:"epochs"`
	Overrides         []SlotWord   `json:"overrides,omitempty"`
	Storage           []SlotWord   `json:"storage"`
}

// Grouping is the canonical first-use grouping of a structurally accepted CERT_BATCH_V2 request (contract section 3).
type Grouping struct {
	C uint64 `json:"C"`
	K uint64 `json:"K"`
	E uint64 `json:"E"`
	S uint64 `json:"S"`
	Q uint64 `json:"Q"`
	A uint64 `json:"A"`
	P uint64 `json:"P"`
}

// Expected is the result every implementation must reproduce. Status "error" is a precompile halt (Sentinel names it), "registry"
// an infrastructure failure with no EVM result (Sentinel names it), and "ok" returns the 64-byte Output with the full Gas,
// Valid=false carrying the diagnostic reason in Sentinel. Counters are the work of a valid batch (contract section 3).
type Expected struct {
	Status   string         `json:"status"`
	Valid    *bool          `json:"valid,omitempty"`
	Sentinel string         `json:"sentinel,omitempty"`
	Output   string         `json:"output,omitempty"`
	Gas      uint64         `json:"gas,omitempty"`
	Grouping *Grouping      `json:"grouping,omitempty"`
	Counters map[string]int `json:"counters,omitempty"`
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

// Deferred names an acceptance row this corpus does not cover, and who does.
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

// outputWords is abi.encode(uint256(version), bool(valid)): version 2 for CERT_BATCH_V2, 1 for RSMT_MEMBER_V1.
func outputWords(version byte, valid bool) []byte {
	out := make([]byte, 64)
	out[31] = version
	if valid {
		out[63] = 1
	}
	return out
}

var Notes = []string{
	"Registry pre-state is an injected simulation, never authenticated admission.",
	"CERT_BATCH_V2 prices follow contract section 5, frozen for cross-stack implementation, not yet a measured safety certificate.",
	"Counters are given for valid batches only; a false batch's work follows the staged evaluator and is not part of the interface.",
	"Sentinels of false and registry results are diagnostic metadata: verdict, status and gas are the interface.",
}
