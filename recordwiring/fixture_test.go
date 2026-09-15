package recordwiring_test

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// stubExecutor answers the two reads the wiring may make. It embeds a nil Executor, so any other call,
// Commit and Build included, panics the test: W1 issues no finality-changing executor call.
type stubExecutor struct {
	shardnode.Executor
	genesis    shardnode.BlockRef
	genesisErr error
	head       shardnode.BlockRef
	headErr    error
}

func (s *stubExecutor) GenesisBlock(context.Context) (shardnode.BlockRef, error) {
	return s.genesis, s.genesisErr
}

func (s *stubExecutor) Head(context.Context) (shardnode.BlockRef, error) { return s.head, s.headErr }

func ref(b certifiedchain.Block) shardnode.BlockRef {
	return shardnode.BlockRef{Number: b.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes()}
}

func trustStore(t *testing.T, c *certifiedchain.Chain, epoch uint64) shardnode.TrustBaseStore {
	tb := *c.TrustBase
	tb.Epoch = epoch
	s, err := shardnode.NewFileTrustBaseStore(&tb, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	return s
}

// configFor is the deployment configuration of c, as the shard-node command builds it, with an executor at
// c's genesis.
func configFor(t *testing.T, c *certifiedchain.Chain) (recordwiring.DeploymentConfig, *stubExecutor) {
	return recordwiring.DeploymentConfig{
		Shard: c.Full, ShardConfHash: c.Genesis.FullShardConfHash().Bytes(), TrustBases: trustStore(t, c, 1),
		RootEpoch: 1, EVM: recordwiring.DefaultEVMParams,
	}, &stubExecutor{genesis: ref(c.Blocks[0])}
}

func mustDeployment(t *testing.T, c *certifiedchain.Chain) recordwiring.Deployment {
	cfg, ex := configFor(t, c)
	d, err := recordwiring.NewDeployment(context.Background(), cfg, ex)
	require.NoError(t, err)
	return d
}
