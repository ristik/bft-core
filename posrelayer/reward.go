package posrelayer

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
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

// notNow reports a call the node executed and refused: the pool's own revert (NothingToDo, NotCaughtUp), which only says the step is not due. A
// transport failure is not that: it is returned, so a relayer never mistakes an unreachable node for an idle pool.
func notNow(err error) bool {
	var re rpc.Error
	return errors.As(err, &re)
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
	} else if !notNow(err) {
		return RewardStep{}, err
	}
	cl, err := CloseIntervalCalldata()
	if err != nil {
		return RewardStep{}, err
	}
	if _, err := rd.Call(ctx, pool, cl); err == nil {
		return RewardStep{Kind: "close", Data: cl}, nil
	} else if !notNow(err) {
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
