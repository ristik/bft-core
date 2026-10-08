package evmstate

import (
	"fmt"

	"github.com/ethereum/go-ethereum/rpc"
)

// RPCWitnessSource builds primary witnesses from an execution client's eth_getProof at the frozen parent's block hash. It satisfies
// consensus.PrimaryWitnessSource.
type RPCWitnessSource struct {
	Client *rpc.Client
	Pins   Pins
}

// PrimaryWitness implements consensus.PrimaryWitnessSource.
func (s RPCWitnessSource) PrimaryWitness(frozenParent []byte, resultID [32]byte) ([]byte, error) {
	if len(frozenParent) != 32 {
		return nil, fmt.Errorf("%w: frozen parent is %d bytes", ErrBuild, len(frozenParent))
	}
	src := RPCProofSource{Client: s.Client}
	copy(src.BlockHash[:], frozenParent)
	return BuildPrimaryWitness(src, s.Pins, resultID)
}
