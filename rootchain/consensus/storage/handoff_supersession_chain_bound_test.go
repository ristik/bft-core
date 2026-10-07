package storage

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// chainOrchestration keeps a derived history of n committed, unacknowledged assignment steps above the acknowledged base (shard epoch 0).
type chainOrchestration struct {
	mockOrchestration
	steps []evmassign.ChainStep
	base  *types.PartitionDescriptionRecord
}

func newChainOrchestration(n int) chainOrchestration {
	o := chainOrchestration{base: &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, Epoch: 0}}
	for i := 1; i <= n; i++ {
		o.steps = append(o.steps, evmassign.ChainStep{ShardEpoch: uint64(i), RootEpoch: uint64(10 + i),
			ConfHash: bytes.Repeat([]byte{byte(i)}, 32), RecordID: bytes.Repeat([]byte{byte(0x80 + i)}, 32), CandidateDigest: bytes.Repeat([]byte{byte(0x40 + i)}, 32)})
	}
	return o
}

func (o chainOrchestration) DerivedChain(types.PartitionID, types.ShardID, uint64) ([]evmassign.ChainStep, error) {
	return o.steps, nil
}

func (o chainOrchestration) ShardConfigByEpoch(types.PartitionID, types.ShardID, uint64) (*types.PartitionDescriptionRecord, error) {
	return o.base, nil
}

// pendingShardOf is the shard state with those n committed steps unacknowledged: its IR is at the base (shard epoch 0), its technical
// record at the last step.
func pendingShardOf(o chainOrchestration) *ShardInfo {
	last := o.steps[len(o.steps)-1]
	return &ShardInfo{PartitionID: 8, ShardConfHash: last.ConfHash,
		IR: &types.InputRecord{Epoch: 0}, TR: certification.TechnicalRecord{Epoch: last.ShardEpoch}}
}

// supersedeChain is verifySupersession for a supersession bound to exactly the committed chain.
func supersedeChain(t *testing.T, n int) error {
	t.Helper()
	o := newChainOrchestration(n)
	si := pendingShardOf(o)
	chain, err := CommittedChain(o, si.PartitionID, si.ShardID, si.IR.Epoch)
	require.NoError(t, err)
	bound, err := chain.Supersession()
	require.NoError(t, err)
	return verifySupersession(bound, si, o)
}

// The unacknowledged chain is folded into one acknowledgement under handoff.MaxSupersessionSpan, so root admission refuses the
// supersession that would make it longer: a chain that ends AT the limit is accepted, one step more is refused with the sentinel.
func TestSupersessionChainLengthIsBoundedAtRootAdmission(t *testing.T) {
	span := int(handoff.MaxSupersessionSpan)
	t.Run("a short chain is superseded", func(t *testing.T) {
		require.NoError(t, supersedeChain(t, 1))
	})
	t.Run("the supersession that makes the chain exactly the span is accepted", func(t *testing.T) {
		require.NoError(t, supersedeChain(t, span-1), "%d committed steps plus this supersession is %d, the span", span-1, span)
	})
	t.Run("the supersession that would exceed the span is refused", func(t *testing.T) {
		for _, committed := range []int{span, span + 1, span + 20} {
			err := supersedeChain(t, committed)
			require.ErrorIs(t, err, ErrSupersessionChainTooLong, "%d committed steps", committed)
			require.ErrorIs(t, err, ErrSupersessionInvalid)
			require.ErrorIs(t, err, ErrHandoffRecord)
		}
	})
	t.Run("the refusal tells the operator to get the installed assignment acknowledged first", func(t *testing.T) {
		for _, err := range []error{CheckSupersessionChainLength(span), supersedeChain(t, span)} {
			require.ErrorIs(t, err, ErrSupersessionChainTooLong)
			require.ErrorContains(t, err, ChainTooLongAdvice)
			require.ErrorContains(t, err, "acknowledged first")
			require.ErrorContains(t, err, fmt.Sprintf("may not exceed %d", span), "and still names the limit")
		}
		require.NoError(t, CheckSupersessionChainLength(span-1), "no advice where there is no refusal")
	})
	t.Run("the shared rule is the same limit", func(t *testing.T) {
		require.NoError(t, CheckSupersessionChainLength(span-1))
		require.ErrorIs(t, CheckSupersessionChainLength(span), ErrSupersessionChainTooLong)
		require.ErrorIs(t, CheckSupersessionChainLength(-1), ErrSupersessionChainTooLong)
	})
	t.Run("the length refusal is not what refuses a short chain with a bad binding", func(t *testing.T) {
		o := newChainOrchestration(span - 1)
		si := pendingShardOf(o)
		chain, err := CommittedChain(o, si.PartitionID, si.ShardID, si.IR.Epoch)
		require.NoError(t, err)
		bound, err := chain.Supersession()
		require.NoError(t, err)
		bound.ChainCommitment = bytes.Repeat([]byte{0xee}, 32)
		err = verifySupersession(bound, si, o)
		require.ErrorIs(t, err, ErrSupersessionInvalid)
		require.NotErrorIs(t, err, ErrSupersessionChainTooLong)
	})
}
