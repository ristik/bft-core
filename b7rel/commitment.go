package b7rel

import (
	"github.com/unicitynetwork/bft-core/b1state"
)

// CommitmentDomain separates C_e from every other registry hash.
var CommitmentDomain = b1state.CommitmentDomain

// EpochCommitment is C_e (design §3), the value the seal registry caches at entry field b1state.CommitmentField:
//
//	keccak256(CommitmentDomain || genesisCommitment || profileHash || word(epoch)
//	          || metadata words 0-4 and 7-10 || the 8 words of every member, in order)
//
// over the words the registry stores for the entry (b1state.Entry.StoredWords). The closure words 5 and 6 (end, hasEnd) are
// excluded, so C_e is fixed when the entry is written and does not change when the epoch closes. Every field is a 32-byte word,
// padding included, exactly as stored.
func EpochCommitment(genesisCommitment, profileHash [32]byte, e b1state.Entry) ([32]byte, error) {
	return b1state.Deployment{GenesisCommitment: genesisCommitment, ProfileHash: profileHash}.EpochCommitment(e)
}
