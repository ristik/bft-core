package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
// step, and from the last turn on everyone.
func TestPlanFinalizerTurnOrdersTheMembers(t *testing.T) {
	const ready = 1_000
	step := 30 * time.Second
	for now := uint64(ready); now <= ready+uint64(finalizerMaxRank+2)*30; now += 5 { // a 30 s step
		due := 0
		for rank := 0; rank < 16; rank++ {
			if planFinalizerTurn(rank, step, finalizerReadiness{ReadyAt: ready, Now: now}).Due {
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
	turn := planFinalizerTurn(2, step, finalizerReadiness{ReadyAt: ready, Now: ready + 59})
	require.False(t, turn.Due)
	require.Equal(t, uint64(ready+60), turn.From)
	require.True(t, planFinalizerTurn(2, step, finalizerReadiness{ReadyAt: ready, Now: ready + 60}).Due)
	require.True(t, planFinalizerTurn(5, 0, finalizerReadiness{ReadyAt: ready, Now: ready}).Due, "step 0")
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
	require.EqualValues(t, 12, block.BlockNumber)
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
		c := &fakeFinalizerClock{ready: finalizerReadiness{ReadyAt: 1000, Now: 1010}}
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
	t.Run("a later rank waits on an RPC error", func(t *testing.T) {
		var out strings.Builder
		due, err := awaitFinalizerTurn(ctx, &out, &finalizerOrder{ID: 4, Step: step, Clock: &fakeFinalizerClock{err: errors.New("eth_getLogs refused")}}, [32]byte{1}, roster)
		require.NoError(t, err)
		require.False(t, due)
		require.Contains(t, out.String(), "waits for a consistent read")
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
		c := &fakeFinalizerClock{ready: finalizerReadiness{ReadyAt: 1000, Now: 1005}}
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
		c := &fakeFinalizerClock{ready: finalizerReadiness{ReadyAt: 1000, Now: 1029}}
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
		c := &fakeFinalizerClock{ready: finalizerReadiness{ReadyAt: 1000, Now: 1031}}
		run(f, 2, c)
		require.Equal(t, []string{"publish"}, f.sent)
	})
}

type readinessRPC func(result any, method string, args []any) error

func (f readinessRPC) CallContext(_ context.Context, result any, method string, args ...any) error {
	return f(result, method, args)
}

func TestPosPublishReaderReadiness(t *testing.T) {
	election, result := common.Address{0xe1}, [32]byte{7}
	const members = 2
	for _, tc := range []struct {
		name                        string
		head, from, reservation     uint64
		incomplete, cutoffReady     bool
		missing, changed, empty     bool
		headNotReady, blockNotReady bool
		wantError                   string
	}{
		{name: "recent reservation", head: 12, from: 6, reservation: 6},
		{name: "look back through more than one reservation window", head: 9999, from: 9600, reservation: 9600},
		{name: "reservation predates the cap", head: 10000, from: 1},
		{name: "all proofs predate the cap", head: 10500, from: 501, incomplete: true, cutoffReady: true},
		{name: "some proofs predate the cap", head: 10500, from: 501, incomplete: true},
		{name: "incomplete recent proof history", head: 10500, from: 10490, reservation: 10490, incomplete: true, blockNotReady: true,
			wantError: "publication is not ready"},
		{name: "missing recent proof history", head: 10500, from: 10490, reservation: 10490, incomplete: true, empty: true,
			wantError: "incomplete finalizer proof history"},
		{name: "missing history at the window boundary", head: 10500, from: 501, incomplete: true, empty: true,
			wantError: "publication is not ready"},
		{name: "missing readiness header", head: 12, from: 6, reservation: 6, missing: true,
			wantError: "missing or mismatched finalizer header"},
		{name: "readiness log from another block", head: 12, from: 6, reservation: 6, changed: true,
			wantError: "readiness log is from a different block"},
		{name: "head state trails the proofs", head: 12, from: 6, reservation: 6, headNotReady: true,
			wantError: "publication is not ready"},
		{name: "readiness state trails the proofs", head: 12, from: 6, reservation: 6, blockNotReady: true,
			wantError: "publication is not ready"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := t.Context()
			last := tc.head - 1
			blockHash := func(n uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(n + 1)) }
			var windows [][2]uint64
			var popQueries int
			checks := make(map[common.Hash]int)
			rpc := readinessRPC(func(out any, method string, args []any) error {
				switch method {
				case "eth_getBlockByNumber":
					require.Len(t, args, 2)
					require.Equal(t, false, args[1])
					tag := args[0].(string)
					n, stamp := tc.head, uint64(100)
					if tag != "finalized" {
						n = hexutil.MustDecodeUint64(tag)
						stamp = 90
					}
					if n == last && tc.missing {
						return json.Unmarshal([]byte("null"), out)
					}
					if n == tc.from-1 && tc.cutoffReady {
						stamp = 50
					}
					return json.Unmarshal(fmt.Appendf(nil, `{"number":"%s","timestamp":"%s","hash":"%s"}`,
						hexutil.EncodeUint64(n), hexutil.EncodeUint64(stamp), blockHash(n).Hex()), out)
				case "eth_call":
					require.Len(t, args, 2)
					data, err := vrclient.PosCalldata(vrclient.PosPublishABI, "publication", result)
					require.NoError(t, err)
					require.Equal(t, map[string]any{"to": election, "data": hexutil.Bytes(data)}, args[0])
					selector := args[1].(map[string]any)
					h := common.HexToHash(selector["blockHash"].(string))
					require.Equal(t, map[string]any{"blockHash": h.Hex(), "requireCanonical": true}, selector)
					checks[h]++
					p := vrclient.PublicationRecord{}
					switch {
					case h == blockHash(tc.head) && !tc.headNotReady,
						h == blockHash(last) && !tc.blockNotReady,
						tc.cutoffReady && h == blockHash(tc.from-1):
						p.PopCount = members
					}
					*out.(*hexutil.Bytes), err = vrclient.PosPublishABI.Methods["publication"].Outputs.Pack(p)
					return err
				case "eth_getLogs":
					require.Len(t, args, 1)
					filter := args[0].(map[string]any)
					topics := filter["topics"].([]any)
					from := hexutil.MustDecodeUint64(filter["fromBlock"].(string))
					to := hexutil.MustDecodeUint64(filter["toBlock"].(string))
					require.Equal(t, map[string]any{"address": election, "fromBlock": hexutil.EncodeUint64(from),
						"toBlock": hexutil.EncodeUint64(to), "topics": []any{topics[0], common.Hash(result)}}, filter)
					require.LessOrEqual(t, to-from+1, uint64(finalizerLogWindow))
					logs := []popLog{}
					entry := func(n uint64, topic common.Hash, ids ...common.Hash) popLog {
						return popLog{Address: election, BlockNumber: hexutil.Uint64(n), BlockHash: blockHash(n),
							Topics: append([]common.Hash{topic, common.Hash(result)}, ids...)}
					}
					switch topics[0] {
					case electionOpenedTopic:
						windows = append(windows, [2]uint64{from, to})
						if tc.reservation >= from && tc.reservation <= to && tc.reservation != 0 {
							logs = append(logs, entry(tc.reservation, electionOpenedTopic))
						}
					case popAcceptedTopic:
						popQueries++
						require.Equal(t, tc.from, from, "scan from reservation or the capped start")
						require.Equal(t, tc.head, to)
						if !tc.incomplete {
							logs = append(logs, entry(last-1, popAcceptedTopic, common.Hash{31: 1}))
						}
						log := entry(last, popAcceptedTopic, common.Hash{31: 2})
						if tc.changed {
							log.BlockHash = common.Hash{0xff}
						}
						if !tc.cutoffReady && !tc.empty {
							logs = append(logs, log)
						}
					default:
						t.Fatalf("unexpected log topic %v", topics[0])
					}
					*out.(*[]popLog) = logs
				default:
					t.Fatalf("unexpected RPC method %s", method)
				}
				return nil
			})
			reader := posPublishReader{ch: &validatorChain{vr: vrclient.New(rpc, common.Address{})}, election: election}
			ready, err := reader.Readiness(ctx, result, members)
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
				want := finalizerReadiness{Now: 100, ReadyAt: 90}
				if tc.cutoffReady {
					want.ReadyAt = 50
				}
				require.Equal(t, want, ready)
			}
			require.Equal(t, 1, checks[blockHash(tc.head)])
			if tc.name == "look back through more than one reservation window" {
				require.Equal(t, [][2]uint64{{9744, 9999}, {9232, 9743}}, windows)
			}
			if tc.headNotReady {
				require.Zero(t, popQueries)
			} else {
				require.Equal(t, 1, popQueries)
			}
			if tc.cutoffReady || tc.incomplete {
				var out strings.Builder
				due, err := awaitFinalizerTurn(ctx, &out,
					&finalizerOrder{ID: 2, Step: 30 * time.Second, Clock: reader}, result, frozen(1, 2))
				require.NoError(t, err)
				require.Equal(t, tc.cutoffReady, due, out.String())
			}
		})
	}
}
