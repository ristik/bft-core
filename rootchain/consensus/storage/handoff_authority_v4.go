package storage

import (
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// freezeV4Version is the Freeze companion of a V3 successor body whose primary candidate carries its EVM proof: everything the version-3
// companion carries and the canonical evmassign.PrimaryProof (the storage-proof witness of the election and custody state at the frozen
// parent, and the members' EVM possession proofs). The old committee's endorsement does not cover it (the endorsement fixes the record);
// block admission judges it against the frozen parent's certified state root, and it is retained with the companion for replay.
const freezeV4Version = 4

// FreezeV4Authorization is the version-4 freeze companion.
type FreezeV4Authorization struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Body       []byte
	Parent     []byte
	Candidate  []byte
	Preimage   []byte
	Receipts   []byte
	Signatures map[string]hex.Bytes
	Proof      []byte // canonical evmassign.PrimaryProof
}

func (a FreezeV4Authorization) Bytes() ([]byte, error) { return types.Cbor.Marshal(a) }

// weightedCompanion reports whether the companion version carries the V3 body rules (weights, receipts).
func weightedCompanion(version uint64) bool {
	return version == freezeV3Version || version == freezeV4Version
}
