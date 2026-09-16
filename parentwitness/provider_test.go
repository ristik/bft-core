package parentwitness

import (
	"context"
	"errors"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registryproof"
)

type providerReader struct {
	evidence registryproof.Evidence
	found    bool
	err      error
	calls    int
	hash     common.Hash
}

func (r *providerReader) EvidenceByHash(_ context.Context, h common.Hash) (registryproof.Evidence, bool, error) {
	r.calls++
	r.hash = h
	return r.evidence, r.found, r.err
}

func TestProviderServesAnyExactBlockInPinnedContext(t *testing.T) {
	c, target := fixtureTarget(t)
	reader := &providerReader{evidence: c.Blocks[2].Evidence, found: true}
	p, err := NewProvider(target, reader)
	require.NoError(t, err)
	req := target.Request()
	req.BlockHash = c.Blocks[2].Hash
	resp, err := p.Serve(context.Background(), req)
	require.NoError(t, err)
	require.Equal(t, OutcomeFound, resp.Outcome)
	require.Equal(t, c.Blocks[2].Hash, reader.hash)
	raw, err := EncodeResponse(resp)
	require.NoError(t, err)
	otherTarget, err := NewTarget(TargetConfig{NetworkID: req.Context.NetworkID, PartitionID: req.Context.PartitionID, ShardID: req.Context.ShardID, FullShardConfHash: req.Context.FullShardConfHash, Registry: target.registry, BlockHash: req.BlockHash})
	require.NoError(t, err)
	verified, err := VerifyResponse(otherTarget, raw)
	require.NoError(t, err)
	require.True(t, verified.Found())
}

func TestProviderRefusalsDoNoExternalRead(t *testing.T) {
	_, target := fixtureTarget(t)
	reader := &providerReader{}
	p, _ := NewProvider(target, reader)
	zero := target.Request()
	zero.BlockHash = common.Hash{}
	resp, err := p.Serve(context.Background(), zero)
	require.ErrorIs(t, err, ErrInvalidRequest)
	require.Zero(t, resp)
	require.Zero(t, reader.calls)
	wrong := target.Request()
	wrong.Context.RootEpoch++
	resp, err = p.Serve(context.Background(), wrong)
	require.NoError(t, err)
	require.Equal(t, OutcomeWrongContext, resp.Outcome)
	require.Zero(t, reader.calls)
	_, err = EncodeResponse(resp)
	require.NoError(t, err, "every nil-error response is encodable")
	genesis := target.Request()
	genesis.BlockHash = genesis.Context.EVMGenesisHash
	resp, err = p.Serve(context.Background(), genesis)
	require.NoError(t, err)
	require.Equal(t, OutcomeInvalidRequest, resp.Outcome)
	require.Zero(t, reader.calls)
	_, err = EncodeResponse(resp)
	require.NoError(t, err)
}

func TestProviderUnavailableAndInvalidLocalEvidence(t *testing.T) {
	_, target := fixtureTarget(t)
	reader := &providerReader{}
	p, _ := NewProvider(target, reader)
	resp, err := p.Serve(context.Background(), target.Request())
	require.NoError(t, err)
	require.Equal(t, OutcomeUnavailable, resp.Outcome)
	reader.found = true
	reader.evidence = registryproof.Evidence{Header: []byte{1}, StorageProofs: make([][][]byte, registryproof.FieldCount)}
	_, err = p.Serve(context.Background(), target.Request())
	require.Error(t, err)
	reader.err = errors.New("store corrupt")
	reader.evidence = registryproof.Evidence{}
	_, err = p.Serve(context.Background(), target.Request())
	require.ErrorContains(t, err, "store corrupt")
}
