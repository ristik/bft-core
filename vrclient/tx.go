package vrclient

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"
	"time"

	ethcommon "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// Tx is one owner transaction: no value, a VR or module call.
type Tx struct {
	To   ethcommon.Address
	Data []byte
}

// Plan is a transaction as it would be sent: decoded, simulated and priced at the current head.
type Plan struct {
	From    ethcommon.Address
	Tx      Tx
	Call    Call
	Gas     uint64 // the estimate; the transaction carries 13/10 of it
	Tip     *big.Int
	FeeCap  *big.Int
	BaseFee *big.Int
	// SimErr is why the simulation refused the transaction (a revert, decoded where VR or the module knows the error). A plan with a
	// SimErr is never sent.
	SimErr error
}

// Sender signs and sends owner transactions with the operator's EVM key.
type Sender struct {
	RPC     RPC
	Key     *ecdsa.PrivateKey
	ChainID *big.Int
	// Wait bounds the wait for a receipt (default 2 minutes).
	Wait time.Duration
	// Poll is the receipt poll interval (default 500 ms).
	Poll time.Duration
}

// From is the sender's address.
func (s Sender) From() ethcommon.Address { return ethcrypto.PubkeyToAddress(s.Key.PublicKey) }

// transientEstimate is the bound-execution node's refusal of an estimate built on a head that moved meanwhile; it is asked again.
const transientEstimate = "bound execution input rejected the block"

// Plan decodes, simulates (eth_estimateGas) and prices tx. The returned error is a transport failure; a refusal is Plan.SimErr.
func (s Sender) Plan(ctx context.Context, tx Tx) (Plan, error) {
	p := Plan{From: s.From(), Tx: tx, Tip: big.NewInt(1_000_000_000)}
	call, err := DecodeCall(tx.Data)
	if err != nil {
		return p, err
	}
	p.Call = call
	var head struct {
		BaseFee *hexutil.Big `json:"baseFeePerGas"`
	}
	if err := s.RPC.CallContext(ctx, &head, "eth_getBlockByNumber", "latest", false); err != nil {
		return p, err
	}
	p.FeeCap = new(big.Int).Set(p.Tip)
	if head.BaseFee != nil {
		p.BaseFee = head.BaseFee.ToInt()
		p.FeeCap.Add(new(big.Int).Mul(p.BaseFee, big.NewInt(2)), p.Tip)
	}
	est := map[string]any{"from": p.From, "to": tx.To, "data": hexutil.Bytes(tx.Data)}
	for attempt := 0; attempt < 6; attempt++ {
		var gas hexutil.Uint64
		err = s.RPC.CallContext(ctx, &gas, "eth_estimateGas", est)
		if err == nil {
			p.Gas = uint64(gas)
			return p, nil
		}
		if !strings.Contains(err.Error(), transientEstimate) {
			break
		}
		select {
		case <-ctx.Done():
			return p, ctx.Err()
		case <-time.After(time.Second):
		}
	}
	p.SimErr = WrapRevert(err)
	return p, nil
}

// MaxCost is the most the transaction can cost (gas limit x fee cap), in wei.
func (p Plan) MaxCost() *big.Int {
	if p.FeeCap == nil {
		return new(big.Int)
	}
	return new(big.Int).Mul(new(big.Int).SetUint64(p.Gas*13/10), p.FeeCap)
}

// String is the operator's preview of the plan.
func (p Plan) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  from: %s\n  to:   %s\n  call: %s\n", p.From.Hex(), p.Tx.To.Hex(), strings.ReplaceAll(p.Call.String(), "\n", "\n  "))
	if p.SimErr != nil {
		fmt.Fprintf(&b, "  simulation: REFUSED: %v\n", p.SimErr)
		return b.String()
	}
	fmt.Fprintf(&b, "  simulation: ok, gas %d (limit %d), max fee %s wei/gas, at most %s wei\n", p.Gas, p.Gas*13/10, p.FeeCap, p.MaxCost())
	return b.String()
}

// Log is one receipt log.
type Log struct {
	Address ethcommon.Address `json:"address"`
	Topics  []ethcommon.Hash  `json:"topics"`
	Data    hexutil.Bytes     `json:"data"`
}

// Receipt is the part of a receipt the CLI reads.
type Receipt struct {
	Status      hexutil.Uint64 `json:"status"`
	BlockNumber hexutil.Uint64 `json:"blockNumber"`
	GasUsed     hexutil.Uint64 `json:"gasUsed"`
	Logs        []Log          `json:"logs"`
}

// Send signs and sends a simulated plan as an EIP-1559 transaction and waits for its receipt; it fails unless the transaction succeeded.
func (s Sender) Send(ctx context.Context, p Plan) (ethcommon.Hash, *Receipt, error) {
	if p.SimErr != nil {
		return ethcommon.Hash{}, nil, fmt.Errorf("not sent: the simulation refused it: %w", p.SimErr)
	}
	var nonce hexutil.Uint64
	if err := s.RPC.CallContext(ctx, &nonce, "eth_getTransactionCount", p.From, "pending"); err != nil {
		return ethcommon.Hash{}, nil, err
	}
	to := p.Tx.To
	tx, err := types.SignNewTx(s.Key, types.LatestSignerForChainID(s.ChainID), &types.DynamicFeeTx{ChainID: s.ChainID, Nonce: uint64(nonce),
		GasTipCap: p.Tip, GasFeeCap: p.FeeCap, Gas: p.Gas * 13 / 10, To: &to, Data: p.Tx.Data})
	if err != nil {
		return ethcommon.Hash{}, nil, err
	}
	raw, err := tx.MarshalBinary()
	if err != nil {
		return ethcommon.Hash{}, nil, err
	}
	if err := s.RPC.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Bytes(raw)); err != nil {
		return tx.Hash(), nil, err
	}
	wait, poll := s.Wait, s.Poll
	if wait == 0 {
		wait = 2 * time.Minute
	}
	if poll == 0 {
		poll = 500 * time.Millisecond
	}
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		var r *Receipt
		if err := s.RPC.CallContext(ctx, &r, "eth_getTransactionReceipt", tx.Hash()); err != nil {
			return tx.Hash(), nil, err
		}
		if r != nil {
			if r.Status != 1 {
				return tx.Hash(), r, fmt.Errorf("transaction %s reverted in block %d", tx.Hash(), r.BlockNumber)
			}
			return tx.Hash(), r, nil
		}
		select {
		case <-ctx.Done():
			return tx.Hash(), nil, ctx.Err()
		case <-time.After(poll):
		}
	}
	return tx.Hash(), nil, fmt.Errorf("transaction %s was not mined within %s", tx.Hash(), wait)
}

// RegisteredID reads the id from a register receipt's Registered(id, owner, bindingRef) log.
func RegisteredID(r *Receipt, registry ethcommon.Address) (uint64, bool) {
	ev := VRABI.Events["Registered"]
	for _, l := range r.Logs {
		if l.Address == registry && len(l.Topics) == 3 && l.Topics[0] == ev.ID {
			return new(big.Int).SetBytes(l.Topics[1].Bytes()).Uint64(), true
		}
	}
	return 0, false
}
