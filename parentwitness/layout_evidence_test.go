package parentwitness

import (
	"context"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

type evidenceMap map[common.Hash]registryproof.Evidence

func (m evidenceMap) EvidenceByHash(_ context.Context, h common.Hash) (registryproof.Evidence, bool, error) {
	e, ok := m[h]
	return e, ok, nil
}

func chainTarget(t *testing.T, c *certifiedchain.Chain, layout uint64, block common.Hash) Target {
	t.Helper()
	pc := registryproof.Context{RegistryAddress: registryproof.RegistryAddress, RegistryCodeHash: c.Pins.RegistryCodeHash,
		GenesisCommitment: c.Genesis.GenesisCommitment(), FullShardConfHash: c.Genesis.FullShardConfHash(), ShardEpoch: 0, RootEpoch: 1,
		EVMGenesisHash: c.Blocks[0].Hash, Layout: layout}
	target, err := NewTarget(TargetConfig{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: pc.FullShardConfHash, Registry: pc, BlockHash: block})
	require.NoError(t, err)
	return target
}

func serve(t *testing.T, c *certifiedchain.Chain, layout uint64, i int, mutate func(registryproof.Evidence) registryproof.Evidence) (Response, error) {
	t.Helper()
	ev := c.Blocks[i].Evidence
	if mutate != nil {
		ev = mutate(ev)
	}
	p, err := NewProvider(chainTarget(t, c, layout, c.Blocks[i].Hash), evidenceMap{c.Blocks[i].Hash: ev})
	require.NoError(t, err)
	return p.Serve(context.Background(), chainTarget(t, c, layout, c.Blocks[i].Hash).Request())
}

// A layout-2 chain certifies past block 1: the parent witness of every block after the first is a 30-proof layout-2
// evidence, which the proof count (once a layout-1 constant) refused, stalling the EVM at height 1.
func TestLayout2ChainServesAndVerifiesParentWitnessesPastBlockOne(t *testing.T) {
	c := certifiedchain.NewV2(t, 3, 3)
	for i := 1; i <= 3; i++ {
		require.Len(t, c.Blocks[i].Evidence.StorageProofs, registryproof.FieldCountV2)
		resp, err := serve(t, c, 2, i, nil)
		require.NoError(t, err, "block %d", i)
		require.Equal(t, OutcomeFound, resp.Outcome)
	}
	// The same holds for the layout-1 deployment: its 28 proofs are not disturbed.
	c1 := certifiedchain.New(t, 3, 2)
	for i := 1; i <= 2; i++ {
		require.Len(t, c1.Blocks[i].Evidence.StorageProofs, registryproof.FieldCount)
		resp, err := serve(t, c1, 0, i, nil)
		require.NoError(t, err)
		require.Equal(t, OutcomeFound, resp.Outcome)
	}
}

// The required proof count is the registry layout's own: any other count is refused with ErrProofCount.
func TestEvidenceProofCountIsTheLayoutsOwn(t *testing.T) {
	c2 := certifiedchain.NewV2(t, 3, 1)
	c1 := certifiedchain.New(t, 3, 1)
	drop := func(e registryproof.Evidence) registryproof.Evidence {
		e.StorageProofs = e.StorageProofs[:len(e.StorageProofs)-2]
		return e
	}
	add := func(e registryproof.Evidence) registryproof.Evidence {
		e.StorageProofs = append(append([][][]byte(nil), e.StorageProofs...), nil)
		return e
	}
	_, err := serve(t, c2, 2, 1, drop) // 28 proofs for layout 2
	require.ErrorIs(t, err, ErrProofCount)
	_, err = serve(t, c2, 2, 1, add) // 31 proofs for layout 2
	require.ErrorIs(t, err, ErrProofCount)
	_, err = serve(t, c1, 0, 1, add) // 29 proofs for layout 1
	require.ErrorIs(t, err, ErrProofCount)
	// A layout-2 evidence presented to a layout-1 target (and the reverse) is refused, not read as the other registry.
	_, err = serve(t, c2, 0, 1, nil)
	require.ErrorIs(t, err, ErrProofCount)
	_, err = serve(t, c1, 2, 1, nil)
	require.ErrorIs(t, err, ErrProofCount)
	_, err = ownEvidence(c2.Blocks[1].Evidence, 3)
	require.ErrorIs(t, err, ErrBounds, "an unknown layout has no proof count")
}
