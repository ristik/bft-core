package registryproof

import (
	"fmt"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

// GetProofResult is the part of an eth_getProof (EIP-1186) result this package reads. The summary fields
// a response also carries (balance, nonce, codeHash, storageHash and each storage value) are deliberately
// absent: JSON decoding drops them, and Verify decides every value from the proof nodes.
type GetProofResult struct {
	Address      common.Address       `json:"address"`
	AccountProof []hexutil.Bytes      `json:"accountProof"`
	StorageProof []StorageProofResult `json:"storageProof"`
}

// StorageProofResult is one storage entry of an eth_getProof result.
type StorageProofResult struct {
	Key   string          `json:"key"`
	Proof []hexutil.Bytes `json:"proof"`
}

// EvidenceFromGetProof arranges an eth_getProof result for the fixed key list, with header as the RLP of
// the block the request named by hash. It checks only that the response is about RegistryAddress and
// carries exactly one proof for each SlotNames key; it verifies nothing, and the result is untrusted
// until Verify accepts it. Nodes are shared with r: Verify copies them.
func EvidenceFromGetProof(header []byte, r GetProofResult) (Evidence, error) {
	return EvidenceFromGetProofFor(0, header, r)
}

// EvidenceFromGetProofFor is EvidenceFromGetProof for the given registry layout (zero or 1: v1, 2: v2).
func EvidenceFromGetProofFor(version uint64, header []byte, r GetProofResult) (Evidence, error) {
	lay, err := layoutFor(version)
	if err != nil {
		return Evidence{}, err
	}
	if r.Address != RegistryAddress {
		return Evidence{}, fmt.Errorf("%w: response is for %s, not %s", ErrAccountProof, r.Address, RegistryAddress)
	}
	if len(r.StorageProof) != len(lay.names) {
		return Evidence{}, fmt.Errorf("%w: %d storage proofs, want exactly %d", ErrStorageProof, len(r.StorageProof), len(lay.names))
	}
	ev := Evidence{Header: header, AccountProof: nodes(r.AccountProof), StorageProofs: make([][][]byte, len(lay.names))}
	seen := make([]bool, len(lay.names))
	for _, sp := range r.StorageProof {
		key, err := storageKey(sp.Key)
		if err != nil {
			return Evidence{}, fmt.Errorf("%w: %v", ErrStorageProof, err)
		}
		i := lay.slotIndex(key)
		if i < 0 {
			return Evidence{}, fmt.Errorf("%w: unexpected storage key %s", ErrStorageProof, key)
		}
		if seen[i] {
			return Evidence{}, fmt.Errorf("%w: duplicate proof for %s", ErrStorageProof, lay.names[i])
		}
		seen[i] = true
		ev.StorageProofs[i] = nodes(sp.Proof)
	}
	return ev, nil
}

// storageKey parses a response key. EIP-1186 permits a key as 32-byte data or as a quantity, so up to 64
// hex digits are accepted and left-padded; anything else is refused.
func storageKey(s string) (common.Hash, error) {
	digits, ok := strings.CutPrefix(s, "0x")
	if !ok || len(digits) == 0 || len(digits) > 2*common.HashLength {
		return common.Hash{}, fmt.Errorf("storage key %q is not 0x followed by 1 to 64 hex digits", s)
	}
	if len(digits)%2 == 1 {
		digits = "0" + digits
	}
	b, err := hexutil.Decode("0x" + digits)
	if err != nil {
		return common.Hash{}, fmt.Errorf("storage key %q: %v", s, err)
	}
	return common.BytesToHash(b), nil
}

func (l *layout) slotIndex(key common.Hash) int {
	for i := range l.slotKeys {
		if l.slotKeys[i] == key {
			return i
		}
	}
	return -1
}

func nodes(in []hexutil.Bytes) [][]byte {
	out := make([][]byte, len(in))
	for i, n := range in {
		out[i] = n
	}
	return out
}
