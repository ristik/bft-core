package bridgeprofile

import "github.com/ethereum/go-ethereum/core/types"

// VerifyMPTEntry verifies a strict Ethereum Merkle-Patricia proof that key (the 32-byte hashed path) holds a value under root, or holds
// none. The supplied nodes are exactly the root-to-leaf (or root-to-divergence) path: a duplicate, unused or out-of-order node is
// refused for an exclusion proof as for an inclusion proof. It returns the stored value and present=true, or present=false for a key the
// trie provably does not hold (an empty trie needs no nodes). Other mismatches are errors.
func VerifyMPTEntry(root [32]byte, key [32]byte, nodes [][]byte) (value []byte, present bool, err error) {
	if root == [32]byte(types.EmptyRootHash) {
		if len(nodes) != 0 {
			return nil, false, ErrMPTExtraneous
		}
		return nil, false, nil
	}
	v, used, err := mptWalk(root, key, nodes)
	switch err {
	case nil:
		return v, true, nil
	case ErrMPTAbsent:
		if used != len(nodes) {
			return nil, false, ErrMPTExtraneous
		}
		return nil, false, nil
	}
	return nil, false, err
}
