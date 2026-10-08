//go:build !q4shim

package cmd

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
)

type noNet struct{}

func (noNet) Send(context.Context, any, ...peer.ID) error { return nil }
func (noNet) ReceivedChannel() <-chan any                 { return nil }

// A binary built without the q4shim tag has no seam to the shim: the wrapper is the identity, and the shim package is not linked in.
func TestProductionBuildHasNoQ4Shim(t *testing.T) {
	net := noNet{}
	got, stop, err := wrapRootNet(context.Background(), net, "", nil, nil, nil)
	require.NoError(t, err)
	require.Equal(t, net, got)
	stop()

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain to list the dependencies")
	}
	out, err := exec.Command(goBin, "list", "-deps", "-f", "{{.ImportPath}}", "github.com/unicitynetwork/bft-core/cli/ubft").CombinedOutput()
	require.NoError(t, err, string(out))
	require.NotContains(t, string(out), "q4shim", "the production binary links the Q4 shim")
	require.True(t, strings.Contains(string(out), "rootchain/consensus"), "premise: the dependency list is the real one")
}
