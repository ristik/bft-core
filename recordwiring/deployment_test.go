package recordwiring_test

import (
	"bytes"
	"context"
	gocrypto "crypto"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/registrygenesis"
)

func TestDeploymentIsBuiltFromCheckedConfiguration(t *testing.T) {
	c := certifiedchain.New(t, 3, 0)
	cfg, ex := configFor(t, c)
	d, err := recordwiring.NewDeployment(context.Background(), cfg, ex)
	require.NoError(t, err)
	require.True(t, d.Valid())

	sc := d.StoreContext()
	require.Equal(t, c.Full.NetworkID, sc.NetworkID)
	require.Equal(t, c.Full.PartitionID, sc.PartitionID)
	require.Equal(t, c.Genesis.FullShardConfHash().Bytes(), sc.FullShardConfHash)
	require.Equal(t, c.Genesis.ProofContext(), d.ProofContext())
	require.Equal(t, c.Genesis.StateRoot(), d.GenesisState())
	sc.FullShardConfHash[0] ^= 0xff
	require.Equal(t, c.Genesis.FullShardConfHash().Bytes(), d.StoreContext().FullShardConfHash, "the store context is returned as a copy")

	cfg.ExpectedGenesisHash = c.Genesis.EVMGenesisHash().Bytes()
	_, err = recordwiring.NewDeployment(context.Background(), cfg, ex)
	require.NoError(t, err, "an expected genesis hash that agrees is accepted")
}

func TestDeploymentRefusals(t *testing.T) {
	c := certifiedchain.New(t, 3, 1)
	other := bytes.Repeat([]byte{0x01}, 32)

	cases := map[string]struct {
		change func(cfg *recordwiring.DeploymentConfig, ex *stubExecutor)
		want   []error
	}{
		"a shard configuration with no seal_registry_genesis": {func(cfg *recordwiring.DeploymentConfig, _ *stubExecutor) {
			cfg.Shard = certifiedchain.Config(3)
		}, []error{recordwiring.ErrNotSealRegistryDeployment}},
		"a commitment that is not the one generated for the configured root epoch": {func(cfg *recordwiring.DeploymentConfig, _ *stubExecutor) {
			cfg.RootEpoch, cfg.TrustBases = 2, trustStore(t, c, 2)
		}, []error{recordwiring.ErrDeploymentConfig, registrygenesis.ErrGenesisMismatch}},
		"another setting changed under the same commitment": {func(cfg *recordwiring.DeploymentConfig, _ *stubExecutor) {
			changed := *c.Full
			changed.PartitionParams = maps.Clone(c.Full.PartitionParams)
			changed.T2Timeout = 7 * time.Second
			h, err := changed.Hash(gocrypto.SHA256)
			require.NoError(t, err)
			cfg.Shard, cfg.ShardConfHash = &changed, h
		}, []error{recordwiring.ErrDeploymentConfig}},
		"the node enforces another configuration hash": {func(cfg *recordwiring.DeploymentConfig, _ *stubExecutor) {
			cfg.ShardConfHash = other
		}, []error{recordwiring.ErrDeploymentConfig}},
		"no trust base for the configured root epoch": {func(cfg *recordwiring.DeploymentConfig, _ *stubExecutor) {
			cfg.TrustBases = trustStore(t, c, 2)
		}, []error{recordwiring.ErrTrustBase}},
		"the executor does not answer": {func(_ *recordwiring.DeploymentConfig, ex *stubExecutor) {
			ex.genesisErr = errors.New("connection refused")
		}, []error{recordwiring.ErrExecutorUnavailable}},
		"the executor's block 0 has another hash": {func(_ *recordwiring.DeploymentConfig, ex *stubExecutor) {
			ex.genesis.Hash = c.Blocks[1].Hash.Bytes()
		}, []error{recordwiring.ErrExecutorGenesis}},
		"the executor's block 0 has another state root": {func(_ *recordwiring.DeploymentConfig, ex *stubExecutor) {
			ex.genesis.StateRoot = c.Blocks[1].StateRoot.Bytes()
		}, []error{recordwiring.ErrExecutorGenesis}},
		"the executor reports a nonzero number for block 0": {func(_ *recordwiring.DeploymentConfig, ex *stubExecutor) {
			ex.genesis.Number = 1
		}, []error{recordwiring.ErrExecutorGenesis}},
		"EVM genesis parameters other than the deployment's": {func(cfg *recordwiring.DeploymentConfig, _ *stubExecutor) {
			cfg.EVM.GasLimit = 29_000_000
		}, []error{recordwiring.ErrExecutorGenesis}},
		"an expected genesis hash that disagrees": {func(cfg *recordwiring.DeploymentConfig, _ *stubExecutor) {
			cfg.ExpectedGenesisHash = c.Blocks[1].Hash.Bytes()
		}, []error{recordwiring.ErrExecutorGenesis}},
		"no shard configuration": {func(cfg *recordwiring.DeploymentConfig, _ *stubExecutor) {
			cfg.Shard = nil
		}, []error{recordwiring.ErrDeploymentConfig}},
		"no trust base store": {func(cfg *recordwiring.DeploymentConfig, _ *stubExecutor) {
			cfg.TrustBases = nil
		}, []error{recordwiring.ErrTrustBase}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, ex := configFor(t, c)
			tc.change(&cfg, ex)
			d, err := recordwiring.NewDeployment(context.Background(), cfg, ex)
			for _, want := range tc.want {
				require.ErrorIs(t, err, want)
			}
			require.False(t, d.Valid())
		})
	}
	t.Run("no executor", func(t *testing.T) {
		cfg, _ := configFor(t, c)
		_, err := recordwiring.NewDeployment(context.Background(), cfg, nil)
		require.ErrorIs(t, err, recordwiring.ErrExecutorUnavailable)
	})
}
