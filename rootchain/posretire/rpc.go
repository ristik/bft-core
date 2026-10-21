package posretire

import (
	"context"
	"math/big"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/unicitynetwork/bft-core/rootchain/evmstate"
)

// RPCChain is a Chain over an execution client's JSON-RPC: custody's RetirementRequested logs.
type RPCChain struct {
	Client  *rpc.Client
	Custody [20]byte
}

// Head implements Chain.
func (c RPCChain) Head(ctx context.Context) (uint64, error) {
	var out hexutil.Uint64
	if err := c.Client.CallContext(ctx, &out, "eth_blockNumber"); err != nil {
		return 0, err
	}
	return uint64(out), nil
}

type rpcLog struct {
	Topics      []hexutil.Bytes `json:"topics"`
	Data        hexutil.Bytes   `json:"data"`
	BlockNumber hexutil.Uint64  `json:"blockNumber"`
	Removed     bool            `json:"removed"`
}

// Requests implements Chain. A log that is not exactly custody's event shape (an id or generation beyond uint64, a wrong topic count or data
// width) is ignored: logs are scheduling hints and a malformed one authorizes nothing.
func (c RPCChain) Requests(ctx context.Context, from, to uint64) ([]Request, error) {
	var logs []rpcLog
	filter := map[string]any{
		"address":   hexutil.Encode(c.Custody[:]),
		"fromBlock": hexutil.EncodeUint64(from),
		"toBlock":   hexutil.EncodeUint64(to),
		"topics":    []any{hexutil.Encode(RequestedTopic[:])},
	}
	if err := c.Client.CallContext(ctx, &logs, "eth_getLogs", filter); err != nil {
		return nil, err
	}
	var out []Request
	for _, l := range logs {
		if l.Removed || len(l.Topics) != 2 || len(l.Data) != 32 || len(l.Topics[1]) != 32 {
			continue
		}
		id, ok1 := word64(l.Topics[1])
		generation, ok2 := word64(l.Data)
		if ok1 && ok2 {
			out = append(out, Request{Key: Key{ID: id, Generation: generation}, Block: uint64(l.BlockNumber)})
		}
	}
	return out, nil
}

func word64(w []byte) (uint64, bool) {
	if new(big.Int).SetBytes(w).BitLen() > 64 {
		return 0, false
	}
	return new(big.Int).SetBytes(w).Uint64(), true
}

// RPCProofs serves eth_getProof at an EVM block hash.
func RPCProofs(client *rpc.Client) Proofs {
	return func(blockHash [32]byte) evmstate.ProofSource {
		return evmstate.RPCProofSource{Client: client, BlockHash: blockHash}
	}
}
