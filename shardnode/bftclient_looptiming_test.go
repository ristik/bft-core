package shardnode

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestLogLoopTimingLevels(t *testing.T) {
	cr := &certification.CertificationResponse{UC: *nonQuietIR(7, nil, []byte{1}, []byte{2})}
	cr.UC.UnicitySeal = &types.UnicitySeal{RootChainRoundNumber: 534}
	const msg = "bft client loop: delivered a certification response"
	for name, tc := range map[string]struct {
		handle time.Duration
		level  slog.Level
	}{
		"a quick handle is debug":    {50 * time.Millisecond, slog.LevelDebug},
		"a handle over 1 s is info":  {1500 * time.Millisecond, slog.LevelInfo},
		"exactly 1 s is info":        {time.Second, slog.LevelInfo},
		"just under 1 s stays debug": {999 * time.Millisecond, slog.LevelDebug},
	} {
		t.Run(name, func(t *testing.T) {
			h := &capturingHandler{}
			c := &BFTClient{log: slog.New(h)}
			c.logLoopTiming(context.Background(), cr, loopTiming{handle: tc.handle, backlog: 2, batch: 3})
			require.Equal(t, []string{msg}, h.atLevel(tc.level))
		})
	}
	t.Run("other messages are not logged", func(t *testing.T) {
		h := &capturingHandler{}
		c := &BFTClient{log: slog.New(h)}
		c.logLoopTiming(context.Background(), "not a response", loopTiming{})
		c.logLoopTiming(context.Background(), &certification.CertificationResponse{}, loopTiming{})
		require.Empty(t, h.records)
	})
}
