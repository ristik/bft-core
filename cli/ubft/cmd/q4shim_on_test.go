//go:build q4shim

package cmd

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/q4shim"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

type recNet struct{ sent chan any }

func (r recNet) Send(_ context.Context, msg any, _ ...peer.ID) error { r.sent <- msg; return nil }
func (recNet) ReceivedChannel() <-chan any                           { return nil }

// With the tag the wrapper installs a shim that reads the lane's control file and reports its status; without the directory it
// refuses to start rather than run unobserved.
func TestQ4ShimBuildIsDrivenByTheLaneDirectory(t *testing.T) {
	t.Setenv(q4ShimDirEnv, "")
	_, _, err := wrapRootNet(context.Background(), recNet{}, "self", nil, func(uint64) (votesig.Config, error) { return votesig.Config{}, nil }, slog.Default())
	require.Error(t, err)

	dir := t.TempDir()
	t.Setenv(q4ShimDirEnv, dir)
	net, stop, err := wrapRootNet(context.Background(), recNet{sent: make(chan any, 1)}, "self", nil, func(uint64) (votesig.Config, error) { return votesig.Config{}, nil }, slog.Default())
	require.NoError(t, err)
	defer stop()
	_, isShim := net.(*q4shim.Net)
	require.True(t, isShim)
	raw, err := json.Marshal(q4shim.Control{Gen: 5, Rules: []q4shim.Rule{{Name: "cut", Action: q4shim.Drop}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "control.json"), raw, 0o600))
	require.Eventually(t, func() bool {
		b, err := os.ReadFile(filepath.Join(dir, "status.json"))
		if err != nil {
			return false
		}
		var st q4shim.Status
		return json.Unmarshal(b, &st) == nil && st.Gen == 5
	}, 5*time.Second, 20*time.Millisecond)
}
