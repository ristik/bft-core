package registryproof

import (
	"bytes"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/unicitynetwork/bft-core/b1state"
)

// FreshB1 is a local API discriminator, never a stored or negotiated version.
// This deployment has one slot domain and no layoutVersion word.
const FreshB1 uint64 = 3

var layoutB1 = newLayout(FreshB1, append(b1state.OperationalSlots(), "b1.network", "b1.wCert", "b1.profileHash", "b1.initialized", "b1.head", "b1.count"), []string{"genesisCommitment", "config.shardConfHash", "assignment.epoch", "assignment.rootEpoch", "assignment.activeConfHash", "phase", "b1.network", "b1.wCert", "b1.profileHash", "b1.initialized", "b1.count"})

// VerifyWords verifies additional bounded storage proofs against the account
// storage root already authenticated by Verify. Values never come from RPC summaries.
func (s Snapshot) VerifyWords(keys []common.Hash, proofs [][][]byte) ([]common.Hash, error) {
	if s.r == nil || len(keys) != len(proofs) || len(keys) > 6+524*16 {
		return nil, ErrStorageProof
	}

	total := 0
	for _, proof := range proofs {
		if len(proof) > 64 {
			return nil, ErrBounds
		}
		size := 0
		for _, node := range proof {
			size += len(node)
			total += len(node)
			if len(node) > 1<<16 || size > 1<<20 || total > 64<<20 {
				return nil, ErrBounds
			}
		}
	}
	owned := make([][][]byte, len(proofs))
	for i, proof := range proofs {
		owned[i] = make([][]byte, len(proof))
		for j, node := range proof {
			owned[i][j] = bytes.Clone(node)
		}
	}
	out := make([]common.Hash, len(keys))
	for i, key := range keys {
		raw, present, err := provenValue(s.r.storageRoot, crypto.Keccak256(key[:]), owned[i])
		if err != nil {
			return nil, ErrStorageProof
		}
		if present {
			out[i], err = decodeWord(raw)
			if err != nil {
				return nil, ErrValue
			}
		}
	}
	return out, nil
}
