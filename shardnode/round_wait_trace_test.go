package shardnode

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

type waitTraceDisseminator struct {
	Disseminator
	await func(context.Context) (Block, error)
}

func (d waitTraceDisseminator) Await(ctx context.Context, _ uint64) (Block, error) {
	return d.await(ctx)
}

func TestFollowerWaitTraceIsEmittedAfterAwaitAndLatePoll(t *testing.T) {
	logs := &capturingHandler{}
	var firstAwait time.Time
	var awaits int
	lateBlock := Block{Hash: []byte{1}}
	round := &Round{
		nodeID:       "follower",
		awaitTimeout: time.Second,
		log:          slog.New(logs),
		disseminator: waitTraceDisseminator{await: func(ctx context.Context) (Block, error) {
			require.Empty(t, logs.records, "the log sink must not run before either Await")
			awaits++
			if awaits == 1 {
				firstAwait = time.Now()
				require.ErrorIs(t, context.Cause(ctx), errAwaitSuperseded)
				return Block{}, ctx.Err()
			}
			return lateBlock, nil
		}},
		watchSupersession: func(_ *types.UnicityCertificate, cut func()) func() {
			cut()
			return func() {}
		},
	}
	held := nonQuietIR(1, []byte{1}, []byte{2}, []byte{3})
	held.UnicitySeal = &types.UnicitySeal{RootChainRoundNumber: 5}
	block, _, err := round.produceBlock(t.Context(), BlockRef{}, Expectation{Round: 2}, nil, "leader", held, nil, nil)
	require.NoError(t, err)
	require.Equal(t, lateBlock, block)
	require.Equal(t, 2, awaits)
	require.Len(t, logs.records, 2)

	attrs := func(record slog.Record) map[string]slog.Value {
		values := make(map[string]slog.Value)
		record.Attrs(func(attr slog.Attr) bool {
			values[attr.Key] = attr.Value
			return true
		})
		return values
	}
	start, end := attrs(logs.records[0]), attrs(logs.records[1])
	require.Equal(t, "follower wait start", start["action"].String())
	require.False(t, start["startedAt"].Time().IsZero())
	require.False(t, start["startedAt"].Time().After(firstAwait))
	require.Equal(t, "follower wait end", end["action"].String())
	require.Equal(t, "superseded", end["outcome"].String())
	require.ErrorIs(t, end["error"].Any().(error), context.Canceled)
	require.GreaterOrEqual(t, end["waited"].Duration(), firstAwait.Sub(start["startedAt"].Time()))
}
