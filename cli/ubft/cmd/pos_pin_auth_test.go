package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-core/vrclient"
)

// #1222: a pin file may carry the ids alone (the authority derives the deployment); a field it does carry must be well formed.
func TestPosPolicyFileDeploymentFieldsAreOptional(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "pin.json")
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
		return p
	}
	p, err := readPosPolicy(write(`{"ids":[5]}`))
	require.NoError(t, err)
	require.Equal(t, []uint64{5}, p.IDs)
	require.Equal(t, [32]byte{}, p.Network)
	require.Equal(t, [32]byte{}, p.ChainID)
	require.Equal(t, [20]byte{}, p.Election)

	p, err = readPosPolicy(write(`{"network":"0x` + strings.Repeat("11", 32) + `","chainId":7,"election":"0x00000000000000000000000000000000000000e1","ids":[5]}`))
	require.NoError(t, err)
	require.Equal(t, byte(7), p.ChainID[31])
	require.Equal(t, byte(0xe1), p.Election[19])

	_, err = readPosPolicy(write(`{"network":"0x11","ids":[5]}`))
	require.Error(t, err)
	_, err = readPosPolicy(write(`{"election":"nope","ids":[5]}`))
	require.Error(t, err)
}

type failingRPC struct{}

func (failingRPC) CallContext(context.Context, any, string, ...any) error {
	return errors.New("connection refused")
}

// The CLI's P85 source maps an unavailable read to the authority's pending refusal, and a missing pin to a refusal.
func TestPosDeploymentSourceMapsUnavailableToPending(t *testing.T) {
	g, c := [32]byte{1}, [32]byte{2}
	src := posDeploymentSource{vrclient.PosDeploymentReader{RPC: failingRPC{}, GenesisHash: &g, RegistryCode: &c}}
	_, err := src.ReadPosDeployment(context.Background(), signingauthority.PosQuery{NodeID: "n", EVMKey: []byte{2}, IDs: []uint64{5}})
	require.ErrorIs(t, err, signingauthority.ErrPosPending)

	src = posDeploymentSource{vrclient.PosDeploymentReader{RPC: failingRPC{}}}
	_, err = src.ReadPosDeployment(context.Background(), signingauthority.PosQuery{})
	require.Error(t, err)
	require.NotErrorIs(t, err, signingauthority.ErrPosPending)

	s, closeFn, err := newPosSource(context.Background(), "", vrFence{VR: true})
	require.NoError(t, err)
	closeFn()
	require.Nil(t, s, "no activation source, no P85 source")
}
