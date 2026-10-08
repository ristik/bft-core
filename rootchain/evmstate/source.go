package evmstate

import (
	"context"
	"errors"
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/evmassign"
)

// RPCWitnessSource builds primary witnesses from an execution client's eth_getProof at the frozen parent's block hash. It satisfies
// consensus.PrimaryWitnessSource.
type RPCWitnessSource struct {
	Client *rpc.Client
	Pins   Pins
}

// PrimaryWitness implements consensus.PrimaryWitnessSource.
func (s RPCWitnessSource) PrimaryWitness(ctx context.Context, frozenParent []byte, resultID [32]byte) ([]byte, error) {
	if len(frozenParent) != 32 {
		return nil, fmt.Errorf("%w: frozen parent is %d bytes", ErrBuild, len(frozenParent))
	}
	src := RPCProofSource{Client: s.Client}
	copy(src.BlockHash[:], frozenParent)
	return BuildPrimaryWitness(ctx, src, s.Pins, resultID)
}

type rpcHeader struct {
	Hash      hexutil.Bytes `json:"hash"`
	StateRoot hexutil.Bytes `json:"stateRoot"`
}

// PrimaryFacts implements consensus.PrimaryWitnessSource: the result's proven facts at the client's current head. The head is whatever
// the client says it is; the facts only filter what a root accepts into a plan, and Freeze admission re-judges the result at the
// certified frozen parent.
func (s RPCWitnessSource) PrimaryFacts(ctx context.Context, resultID [32]byte) (evmassign.PrimaryFacts, error) {
	var h rpcHeader
	hctx, cancel := context.WithTimeout(ctx, ClientDeadline)
	defer cancel()
	if err := s.Client.CallContext(hctx, &h, "eth_getBlockByNumber", "latest", false); err != nil {
		return evmassign.PrimaryFacts{}, errors.Join(ErrBuild, err)
	}
	if len(h.Hash) != 32 || len(h.StateRoot) != 32 {
		return evmassign.PrimaryFacts{}, fmt.Errorf("%w: malformed head header", ErrBuild)
	}
	src := RPCProofSource{Client: s.Client}
	copy(src.BlockHash[:], h.Hash)
	witness, err := BuildPrimaryWitness(ctx, src, s.Pins, resultID)
	if err != nil {
		return evmassign.PrimaryFacts{}, err
	}
	return Authority{Pins: s.Pins}.VerifyPrimary(witness, [32]byte(h.StateRoot), resultID)
}
