package vrschema

import (
	"errors"
	"strconv"
)

// The proof configuration of a partition, as the fold judges it (design sections 3.5.4 and 6; rootchain/partitions verifyProofConfig).
// The fold uses only the PROTOCOL predicate below, a pure function of the PDR's partition parameters. Whether the local binary can
// verify a protocol-valid proof type (zkverifier.IsProofTypeAvailable, build tags) never enters a verdict: a root that lacks the
// support for an Accepted configuration fences at installation (ProofSupportMissing), like a node that lacks an activated rule.

// Partition parameter keys (zkverifier).
const (
	ParamProofType = "proof_type"
	ParamVKeyPath  = "vkey_path"
	ParamChainID   = "chain_id"
)

// ProtocolProofTypes are the proof types the protocol defines; "" and "none" are m-of-n only. risc0 has no verifier and is not one.
var ProtocolProofTypes = []string{"none", "exec", "aggregator_rsmt_v1", "aggregator_zk_v1", "sp1", "light_client"}

// Proof configuration refusals.
var (
	ErrProofType    = errors.New("UnknownProofType")
	ErrProofVKey    = errors.New("ProofVKeyPathMissing")
	ErrProofChainID = errors.New("ProofChainIDMissing")
)

// ProofConfigValid is the protocol predicate: an absent, empty or "none" proof type is valid; any other type must be a protocol
// proof type; sp1 needs a nonempty vkey_path and a chain_id; light_client needs a chain_id. A chain_id is a canonical decimal uint64
// (strconv.ParseUint base 10, as zkverifier.ParseChainIDFromParams).
func ProofConfigValid(params map[string]string) error {
	pt := params[ParamProofType]
	if pt == "" || pt == "none" {
		return nil
	}
	known := false
	for _, t := range ProtocolProofTypes {
		known = known || t == pt
	}
	if !known {
		return ErrProofType
	}
	chainID := func() bool {
		v, ok := params[ParamChainID]
		if !ok || v == "" {
			return false
		}
		_, err := strconv.ParseUint(v, 10, 64)
		return err == nil
	}
	switch pt {
	case "sp1":
		if params[ParamVKeyPath] == "" {
			return ErrProofVKey
		}
		if !chainID() {
			return ErrProofChainID
		}
	case "light_client":
		if !chainID() {
			return ErrProofChainID
		}
	}
	return nil
}
