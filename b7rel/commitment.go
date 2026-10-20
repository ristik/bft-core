package b7rel

import (
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/b1state"
)

// CommitmentDomain separates C_e from every other registry hash.
var CommitmentDomain = [32]byte(ethcrypto.Keccak256Hash([]byte("unicity.seal-registry.v2/epoch-commitment")))

// EpochCommitment is C_e (design §3):
//
//	keccak256(CommitmentDomain || genesisCommitment || profileHash || word(epoch)
//	          || metadata words 0-4 and 7-10 || the 8 words of every member, in order)
//
// over the words the registry stores for the entry (b1state.Entry.StoredWords). The closure words 5 and 6 (end, hasEnd) are
// excluded, so C_e is fixed when the entry is written and does not change when the epoch closes. Every field is a 32-byte word,
// padding included, exactly as stored.
func EpochCommitment(genesisCommitment, profileHash [32]byte, e b1state.Entry) ([32]byte, error) {
	if err := e.Validate(); err != nil {
		return [32]byte{}, err
	}
	metadata, members := e.StoredWords()
	ws := [][32]byte{CommitmentDomain, genesisCommitment, profileHash, word(e.Epoch)}
	for f, w := range metadata {
		if f == 5 || f == 6 {
			continue
		}
		ws = append(ws, w)
	}
	for _, m := range members {
		ws = append(ws, m[:]...)
	}
	return keccakWords(ws...), nil
}
