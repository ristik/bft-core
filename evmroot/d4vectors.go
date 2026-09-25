package evmroot

import "encoding/json"

// Version 2 changes the record, proof and anchor encodings. V1 fixture bytes
// are never parsed as V2. The model-crypto-only Ed25519 fixture is generated
// separately by testdata/generate_d4_vectors.go using only the Go standard library.
type D4VectorSet struct {
	Version       int            `json:"version"`
	TraceCoverage []string       `json:"trace_coverage"`
	Crypto        D4CryptoVector `json:"crypto"`
}
type D4CryptoVector struct {
	Profile              int               `json:"profile"`
	Scope                string            `json:"scope"`
	ControlPartition     string            `json:"control_partition"`
	RecordCBOR           string            `json:"record_cbor"`
	RecordID             string            `json:"record_id"`
	ControlCBOR          string            `json:"control_cbor"`
	ControlDigest        string            `json:"control_digest"`
	ShardRoot            string            `json:"shard_root"`
	Root                 string            `json:"root"`
	Path                 []D4PathVector    `json:"path"`
	VoteInfoCBOR         string            `json:"vote_info_cbor"`
	VoteInfoHash         string            `json:"vote_info_hash"`
	LedgerCommitInfoCBOR string            `json:"ledger_commit_info_cbor"`
	SealCBOR             string            `json:"seal_cbor"`
	Signatures           map[string]string `json:"signatures"`
	PublicKeys           map[string]string `json:"public_keys"`
	GenesisCBOR          string            `json:"genesis_cbor"`
	GenesisID            string            `json:"genesis_id"`
	PreFreezeSummary     string            `json:"pre_freeze_summary"`
	CandidateContextHash string            `json:"candidate_context_hash"`
}
type D4PathVector struct{ Key, Hash string }

func BuildD4Vectors() D4VectorSet                    { return D4VectorSet{Version: 2, TraceCoverage: D4TraceNames()} }
func MarshalD4Vectors(v D4VectorSet) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }
