package evmassign

import (
	"errors"

	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// NodeIDWordLen is the width of the custody-side NodeID.
const NodeIDWordLen = 32

// ErrNodeID reports a NodeID that has no custody-side word.
var ErrNodeID = errors.New("evmassign: empty NodeID")

// NodeIDWord is the canonical custody/registry encoding of a root or EVM NodeID: keccak256 of the NodeID's UTF-8 bytes.
//
// Root chain NodeIDs are libp2p peer-ID strings, a pure function of the signing key, and every candidate, trust base and possession
// message in this repository keeps them as strings. The custody contracts (unicity-pos-contracts#7) treat NodeIDs as opaque bytes32 and
// never parse them, so they need an injective fixed-width image, not the string. The word is derived, never carried: the string stays
// the identity here, the word is computed at the boundary, and the key hash beside it in every signed binding already authenticates
// the node. A rotated key therefore changes both the string and the word.
func NodeIDWord(nodeID string) ([NodeIDWordLen]byte, error) {
	var w [NodeIDWordLen]byte
	if nodeID == "" {
		return w, ErrNodeID
	}
	copy(w[:], ethcrypto.Keccak256([]byte(nodeID)))
	return w, nil
}
