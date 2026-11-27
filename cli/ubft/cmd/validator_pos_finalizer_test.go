package cmd

import (
	"context"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/vrclient"
)

func frozen(ids ...uint64) []vrclient.FrozenMember {
	out := make([]vrclient.FrozenMember, len(ids))
	for i, id := range ids {
		out[i] = vrclient.FrozenMember{Id: id}
	}
	return out
}

// #1323: the order is the frozen roster by ascending identity, whatever order the roster is read in; a non-member comes last.
func TestFinalizerRankIsTheAscendingRoster(t *testing.T) {
	roster := frozen(9, 2, 5, 7)
	for id, want := range map[uint64]int{2: 0, 5: 1, 7: 2, 9: 3, 4: 4, 1: 4, 10: 4} {
		require.Equal(t, want, finalizerRank(roster, id), "identity %d", id)
	}
	require.Equal(t, 0, finalizerRank(nil, 3))
}

func TestFinalizerDelayGrowsWithTheRankAndIsBounded(t *testing.T) {
	step := 30 * time.Second
	require.Zero(t, finalizerDelay(0, step))
	require.Equal(t, 30*time.Second, finalizerDelay(1, step))
	require.Equal(t, 90*time.Second, finalizerDelay(3, step))
	require.Equal(t, time.Duration(finalizerMaxRank)*step, finalizerDelay(finalizerMaxRank, step))
	require.Equal(t, time.Duration(finalizerMaxRank)*step, finalizerDelay(15, step), "the delay is bounded")
	require.Zero(t, finalizerDelay(5, 0), "a zero step: every member at once")
}

// At every chain time after readiness the members that may finalize are a prefix of the order: the lowest alone first, then one more rank per
// step, and from the last turn on everyone. Without a known readiness (older than the log window) everyone may.
func TestPlanFinalizerTurnOrdersTheMembers(t *testing.T) {
	const ready = 1_000
	step := 30 * time.Second
	for now := uint64(ready); now <= ready+uint64(finalizerMaxRank+2)*30; now += 5 { // a 30 s step
		due := 0
		for rank := 0; rank < 16; rank++ {
			if planFinalizerTurn(rank, step, finalizerReadiness{Known: true, ReadyAt: ready, Now: now}).Due {
				require.Equal(t, due, rank, "the due members are a prefix of the order at %d", now)
				due++
			}
		}
		want := min(int((now-ready)/30), finalizerMaxRank) + 1
		if want > finalizerMaxRank {
			want = 16 // the last turn is shared by every rank from finalizerMaxRank on
		}
		require.Equal(t, want, due, "at %d s after readiness", now-ready)
	}
	turn := planFinalizerTurn(2, step, finalizerReadiness{Known: true, ReadyAt: ready, Now: ready + 59})
	require.False(t, turn.Due)
	require.Equal(t, uint64(ready+60), turn.From)
	require.True(t, planFinalizerTurn(2, step, finalizerReadiness{Known: true, ReadyAt: ready, Now: ready + 60}).Due)
	require.True(t, planFinalizerTurn(5, step, finalizerReadiness{Now: ready}).Due, "readiness older than the window")
	require.True(t, planFinalizerTurn(5, 0, finalizerReadiness{Known: true, ReadyAt: ready, Now: ready}).Due, "step 0")
}

func TestReadyBlockIsTheLastProofOfTheResult(t *testing.T) {
	election, rid := common.Address{0xe1}, [32]byte{7}
	id := func(n byte) common.Hash { return common.Hash{31: n} }
	log := func(block uint64, member byte) popLog {
		return popLog{Address: election, Topics: []common.Hash{popAcceptedTopic, common.Hash(rid), id(member)}, BlockNumber: hexutil.Uint64(block)}
	}
	removed := log(99, 4)
	removed.Removed = true
	other := log(98, 4)
	other.Address = common.Address{0xe2}
	otherResult := log(97, 4)
	otherResult.Topics[1] = common.Hash{8}
	block, n := readyBlock([]popLog{log(10, 1), log(12, 2), log(11, 3), log(12, 3), removed, other, otherResult}, election, rid)
	require.Equal(t, uint64(12), block)
	require.Equal(t, 3, n, "distinct members only; removed, foreign and other-result logs do not count")
}

type fakeFinalizerClock struct {
	ready finalizerReadiness
	err   error
	calls int
}

func (c *fakeFinalizerClock) Readiness(context.Context, [32]byte, int) (finalizerReadiness, error) {
	c.calls++
	return c.ready, c.err
}

func TestAwaitFinalizerTurn(t *testing.T) {
	roster := frozen(1, 2, 3, 4)
	step := 30 * time.Second
	ctx := context.Background()
	t.Run("the lowest identity finalizes at once and reads no logs", func(t *testing.T) {
		c := &fakeFinalizerClock{err: errors.New("no logs")}
		var out strings.Builder
		due, err := awaitFinalizerTurn(ctx, &out, &finalizerOrder{ID: 1, Step: step, Clock: c}, [32]byte{1}, roster)
		require.NoError(t, err)
		require.True(t, due)
		require.Zero(t, c.calls)
		require.Empty(t, out.String())
	})
	t.Run("a later rank waits with one stable line, then takes over", func(t *testing.T) {
		c := &fakeFinalizerClock{ready: finalizerReadiness{Known: true, ReadyAt: 1000, Now: 1010}}
		o := &finalizerOrder{ID: 3, Step: step, Clock: c}
		var first, second strings.Builder
		due, err := awaitFinalizerTurn(ctx, &first, o, [32]byte{1}, roster)
		require.NoError(t, err)
		require.False(t, due)
		require.Contains(t, first.String(), "finalizer rank 2")
		c.ready.Now = 1055
		_, _ = awaitFinalizerTurn(ctx, &second, o, [32]byte{1}, roster)
		require.Equal(t, first.String(), second.String(), "the waiting line does not change while it waits")
		c.ready.Now = 1060
		var out strings.Builder
		due, err = awaitFinalizerTurn(ctx, &out, o, [32]byte{1}, roster)
		require.NoError(t, err)
		require.True(t, due)
		require.Contains(t, out.String(), "no lower finalizer rank finished")
	})
	t.Run("without the order every member stays live", func(t *testing.T) {
		var out strings.Builder
		due, err := awaitFinalizerTurn(ctx, &out, &finalizerOrder{ID: 4, Step: step, Clock: &fakeFinalizerClock{err: errors.New("eth_getLogs refused")}}, [32]byte{1}, roster)
		require.NoError(t, err)
		require.True(t, due)
		require.Contains(t, out.String(), "finalizer order unavailable")
	})
	t.Run("no order or a zero step", func(t *testing.T) {
		due, err := awaitFinalizerTurn(ctx, &strings.Builder{}, nil, [32]byte{1}, roster)
		require.NoError(t, err)
		require.True(t, due)
		due, err = awaitFinalizerTurn(ctx, &strings.Builder{}, &finalizerOrder{ID: 4, Clock: &fakeFinalizerClock{}}, [32]byte{1}, roster)
		require.NoError(t, err)
		require.True(t, due)
	})
}

// Four members poll the same ready result: only the designated finalizer sends finalizeCandidate and VR.publish; the others see the result
// published and send nothing. With the designated finalizer gone, the next rank sends them after its delay.
func TestPublishReadyResultSendsOnlyTheFinalizersTransactions(t *testing.T) {
	roster := frozen(1, 2, 3, 4)
	key, err := ethcrypto.GenerateKey()
	require.NoError(t, err)
	run := func(f *fakePosChain, id uint64, c *fakeFinalizerClock) string {
		var out strings.Builder
		require.NoError(t, publishReadyResult(context.Background(), &out, posPublishRun{
			Election: common.Address{0xe1}, Registry: common.Address{3}, Rid: [32]byte{1}, Members: roster, Chain: f,
			Sender: vrclient.Sender{RPC: f.serve(t, 4), Key: key, ChainID: big.NewInt(1), Poll: time.Millisecond},
			Order:  &finalizerOrder{ID: id, Step: 30 * time.Second, Clock: c}}))
		return out.String()
	}
	t.Run("the lowest finalizes, the others send nothing", func(t *testing.T) {
		f := &fakePosChain{pops: 4, vrState: 1, publishState: 2}
		c := &fakeFinalizerClock{ready: finalizerReadiness{Known: true, ReadyAt: 1000, Now: 1005}}
		for _, id := range []uint64{4, 3, 2} {
			run(f, id, c)
		}
		require.Empty(t, f.sent, "the later ranks wait")
		run(f, 1, c)
		require.Equal(t, []string{"finalize", "publish"}, f.sent)
		c.ready.Now = 2000 // long after every turn: the result is published, so nobody sends anything and nothing is printed
		for _, id := range []uint64{1, 2, 3, 4} {
			require.Empty(t, run(f, id, c), "identity %d", id)
		}
		require.Equal(t, []string{"finalize", "publish"}, f.sent)
	})
	t.Run("the next rank takes over from an absent finalizer", func(t *testing.T) {
		f := &fakePosChain{pops: 4, vrState: 1, publishState: 2}
		c := &fakeFinalizerClock{ready: finalizerReadiness{Known: true, ReadyAt: 1000, Now: 1029}}
		run(f, 2, c)
		run(f, 3, c)
		require.Empty(t, f.sent)
		c.ready.Now = 1030
		run(f, 2, c)
		run(f, 3, c)
		require.Equal(t, []string{"finalize", "publish"}, f.sent, "rank 1 finalized; rank 2 found it published")
	})
	t.Run("a finalizer that stopped after finalizeCandidate: the next rank only publishes", func(t *testing.T) {
		f := &fakePosChain{pops: 4, finalized: true, vrState: 1, publishState: 2}
		c := &fakeFinalizerClock{ready: finalizerReadiness{Known: true, ReadyAt: 1000, Now: 1031}}
		run(f, 2, c)
		require.Equal(t, []string{"publish"}, f.sent)
	})
}
