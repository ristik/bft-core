package signingauthority

import (
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

func recoveryFixture(t *testing.T, primary *q3fixture.Fixture, acknowledged bool, edit func(*evmassign.Candidate)) *q3fixture.Fixture {
	t.Helper()
	_, installed, err := activatedOf(primary)
	require.NoError(t, err)
	state, err := storage.NewShardInfo(installed, crypto.SHA256)
	require.NoError(t, err)
	if acknowledged {
		state.IR.Epoch = installed.Epoch
	} else {
		state.IR.Epoch = primary.ShardConf.Epoch
	}
	base, err := evmassign.PDRHash(primary.ShardConf)
	require.NoError(t, err)
	record := primary.History.Tip()
	handoff, _, ok := record.Handoff()
	require.True(t, ok)
	chain, err := evmassign.ChainCommit(primary.Body.Epoch-1, primary.ShardConf.Epoch, base[:], [][]byte{handoff.RecordID})
	require.NoError(t, err)
	return q3fixture.New(t, q3fixture.Options{After: primary, Assignment: true, Recovery: true, Installed: installed, ShardState: state, MutateCandidate: func(c *evmassign.Candidate) {
		c.Supersedes = &evmassign.Supersession{SupersededH: handoff.RecordID, BaseRootEpoch: primary.Body.Epoch - 1,
			BaseShardEpoch: primary.ShardConf.Epoch, BaseActiveHash: base[:], ChainLen: 1, ChainCommitment: chain[:]}
		if edit != nil {
			edit(c)
		}
	}})
}

func TestVerifiedRecoveryReentersAnExcludedAuthority(t *testing.T) {
	ctx := context.Background()
	primary := q3fixture.New(t, q3fixture.Options{Assignment: true, UTB: true})
	_, dropped := keptAndDropped(t, primary)
	recovery := recoveryFixture(t, primary, false, nil)
	a := proofAuthority(t, primary, dropped)
	res, err := a.AdvanceWithProof(ctx, bundleOf(t, primary))
	require.NoError(t, err)
	require.True(t, res.Retired)
	_, err = a.ReplaceSession()
	require.ErrorIs(t, err, ErrRetired)

	res, err = a.AdvanceWithProof(ctx, bundleOf(t, recovery))
	require.NoError(t, err)
	require.Equal(t, uint64(3), res.LineageEpoch)
	require.True(t, res.Advanced, "the verified recovery restored the excluded identity")
	require.False(t, res.Retired)
	_, err = a.ReplaceSession()
	require.NoError(t, err)
}
