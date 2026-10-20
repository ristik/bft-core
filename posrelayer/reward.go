package posrelayer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

// The relayer's reward transactions (T8 #47 / P7 #54, unicity-pos-contracts `RewardPool`). Every one of them is ordinary, permissionless EVM
// work: advancing the pool's timeline over the authenticated root records, closing the next interval, funding and a payee's claim. The relayer
// chooses neither an endpoint nor an interval length: the pool does, from the authenticated records. A wrong transaction is a revert.

const rewardABI = `[
 {"type":"function","name":"advanceRecords","stateMutability":"nonpayable","inputs":[{"type":"uint32"}],"outputs":[{"type":"uint32"}]},
 {"type":"function","name":"closeInterval","stateMutability":"nonpayable","inputs":[],"outputs":[{"name":"start","type":"uint64"},{"name":"end","type":"uint64"},{"name":"budget","type":"uint256"}]},
 {"type":"function","name":"claim","stateMutability":"nonpayable","inputs":[{"type":"uint256"},{"type":"address"}],"outputs":[]},
 {"type":"function","name":"fund","stateMutability":"payable","inputs":[],"outputs":[]},
 {"type":"function","name":"credits","stateMutability":"view","inputs":[{"type":"address"}],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"available","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"totalCredits","stateMutability":"view","inputs":[],"outputs":[{"type":"uint256"}]},
 {"type":"function","name":"nextStart","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"}]},
 {"type":"function","name":"recordCursor","stateMutability":"view","inputs":[],"outputs":[{"type":"uint64"}]}
]`

// MaxRecordsPerAdvance is RewardPool.MAX_RECORDS_PER_CALL.
const MaxRecordsPerAdvance = 2

var rewards abi.ABI

func init() {
	var err error
	if rewards, err = abi.JSON(strings.NewReader(rewardABI)); err != nil {
		panic(fmt.Sprintf("posrelayer: reward ABI: %v", err))
	}
}

// AdvanceRecordsCalldata is RewardPool.advanceRecords(n), n at most MaxRecordsPerAdvance.
func AdvanceRecordsCalldata(n uint32) ([]byte, error) {
	if n == 0 || n > MaxRecordsPerAdvance {
		return nil, fmt.Errorf("posrelayer: advanceRecords takes 1 to %d records", MaxRecordsPerAdvance)
	}
	return rewards.Pack("advanceRecords", n)
}

// CloseIntervalCalldata is RewardPool.closeInterval().
func CloseIntervalCalldata() ([]byte, error) { return rewards.Pack("closeInterval") }

// ClaimCalldata is RewardPool.claim(amount, to).
func ClaimCalldata(amount *big.Int, to [20]byte) ([]byte, error) {
	if amount == nil || amount.Sign() <= 0 {
		return nil, errors.New("posrelayer: a claim is for a positive amount")
	}
	return rewards.Pack("claim", amount, to)
}

// FundCalldata is RewardPool.fund(); the value is sent with the transaction.
func FundCalldata() ([]byte, error) { return rewards.Pack("fund") }

// RewardStep is the next piece of reward work the pool would accept.
type RewardStep struct {
	Kind string // "advance", "close" or "" (nothing the pool would accept now)
	Data []byte
}

// The reverts that only say "this step is not due": RewardPool.NothingToDo() and RewardPool.NotCaughtUp() (`cast sig`).
var (
	revertNothingToDo = []byte{0x5c, 0x52, 0xa8, 0x68}
	revertNotCaughtUp = []byte{0x12, 0x91, 0x63, 0x0f}
)

// executionReverted is the JSON-RPC code of an eth_call whose execution reverted (go-ethereum, reth).
const executionReverted = 3

// notNow reports a call the node executed and the POOL refused with one of the two reverts that mean "not due yet". Every other failure is
// returned: a transport error, a node error (for example -32000), and a pool revert of another kind (TimelineMismatch, RecordOutOfOrder,
// CommitteeTooLarge, ...), which is a real problem of the pool and never "idle".
func notNow(err error) (bool, error) {
	var re rpc.Error
	if !errors.As(err, &re) || re.ErrorCode() != executionReverted {
		return false, err
	}
	var de rpc.DataError
	if !errors.As(err, &de) {
		return false, fmt.Errorf("posrelayer: the pool call reverted without a reason: %w", err)
	}
	data, ok := de.ErrorData().(string)
	if !ok {
		return false, fmt.Errorf("posrelayer: the pool call reverted with unreadable data: %w", err)
	}
	raw, derr := hexutil.Decode(data)
	if derr != nil || len(raw) < 4 {
		return false, fmt.Errorf("posrelayer: the pool call reverted with unreadable data %q: %w", data, err)
	}
	if bytes.Equal(raw[:4], revertNothingToDo) || bytes.Equal(raw[:4], revertNotCaughtUp) {
		return true, nil
	}
	return false, fmt.Errorf("posrelayer: the pool refused with %x (not NothingToDo or NotCaughtUp): %w", raw[:4], err)
}

// NextRewardStep asks the pool, by simulation, what it would accept now: first to read the next authenticated records (up to the per-call
// bound), else to close the next interval. The order matters: the tail of the latest assignment closes only once the pool has read every record.
func NextRewardStep(ctx context.Context, rd Reader, pool [20]byte) (RewardStep, error) {
	adv, err := AdvanceRecordsCalldata(MaxRecordsPerAdvance)
	if err != nil {
		return RewardStep{}, err
	}
	if _, err := rd.Call(ctx, pool, adv); err == nil {
		return RewardStep{Kind: "advance", Data: adv}, nil
	} else if _, err := notNow(err); err != nil {
		return RewardStep{}, err
	}
	cl, err := CloseIntervalCalldata()
	if err != nil {
		return RewardStep{}, err
	}
	if _, err := rd.Call(ctx, pool, cl); err == nil {
		return RewardStep{Kind: "close", Data: cl}, nil
	} else if _, err := notNow(err); err != nil {
		return RewardStep{}, err
	}
	return RewardStep{}, nil
}

// RewardCredit is RewardPool.credits(payee) as the pool reports it.
func RewardCredit(ctx context.Context, rd Reader, pool, payee [20]byte) (*big.Int, error) {
	data, err := rewards.Pack("credits", payee)
	if err != nil {
		return nil, err
	}
	raw, err := rd.Call(ctx, pool, data)
	if err != nil {
		return nil, err
	}
	out, err := rewards.Unpack("credits", raw)
	if err != nil || len(out) != 1 {
		return nil, fmt.Errorf("posrelayer: credits answered %x", raw)
	}
	v, ok := out[0].(*big.Int)
	if !ok {
		return nil, fmt.Errorf("posrelayer: credits answered %T", out[0])
	}
	return v, nil
}
