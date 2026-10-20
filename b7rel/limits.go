package b7rel

import (
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/unicitynetwork/bft-core/b1state"
)

// Candidate ceilings of the first expanded profile (design §5): benchmark targets, not measured capacity. The final values are
// pinned only after worst-case proving and verifier measurements (step 5); changing any of them changes RelationID.
const (
	MaxLeaves          = 1024    // leaves of the whole history, mint and burn included
	MaxTransfers       = 1023    // transfers including the final burn
	MaxEpochs          = 64      // distinct root epochs whose certificates the history uses
	MaxAnchors         = 1024    // distinct UC anchors (and seals)
	MaxSemanticBytes   = 1 << 20 // the history projection
	MaxWitnessBytes    = 16 << 20
	MaxMembersPerEpoch = b1state.MaxMembers
	MaxRSMTSiblings    = 32
)

// RelationDomain names the relation; RelationID binds it to the limits above.
var RelationDomain = [32]byte(ethcrypto.Keccak256Hash([]byte("unicity.b7.relation.v1")))

// RelationID is keccak256(RelationDomain || the limits as 32-byte words, in the order of the constants above).
func RelationID() [32]byte {
	return keccakWords(RelationDomain, word(MaxLeaves), word(MaxTransfers), word(MaxEpochs), word(MaxAnchors), word(MaxSemanticBytes),
		word(MaxWitnessBytes), word(MaxMembersPerEpoch), word(MaxRSMTSiblings))
}

func word(v uint64) [32]byte { return b1state.Word(v) }

func keccakWords(ws ...[32]byte) [32]byte {
	b := make([]byte, 0, 32*len(ws))
	for _, w := range ws {
		b = append(b, w[:]...)
	}
	return [32]byte(ethcrypto.Keccak256Hash(b))
}
