package signingauthority

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
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
	oldSession, err := a.ReplaceSession()
	require.NoError(t, err)
	old := a.Enrollment()
	a.irAckSeen = true
	a.rec = record{scopeVersion: a.scopeVersion, reserved: 41, unsigned: []byte{1}, digest: sha256.Sum256([]byte{1}), authorizationID: []byte{2}}

	res, err := a.AdvanceWithProof(ctx, bundleOf(t, primary))
	require.NoError(t, err)
	require.True(t, res.Retired)
	_, err = a.ReplaceSession()
	require.ErrorIs(t, err, ErrRetired)
	require.ErrorIs(t, a.Sign(oldSession), ErrFenced)

	replayed, err := a.AdvanceWithProof(ctx, bundleOf(t, primary))
	require.NoError(t, err)
	require.True(t, replayed.Replay && replayed.Retired)

	// An untrusted relay can't consume the recovery by withholding its candidate.
	_, err = a.AdvanceWithProof(ctx, bundleWith(t, recovery, recovery.Snapshot, nil))
	require.ErrorIs(t, err, ErrLineageUnverified)
	require.Equal(t, uint64(2), a.Status().LineageEpoch)

	res, err = a.AdvanceWithProof(ctx, bundleOf(t, recovery))
	require.NoError(t, err)
	require.Equal(t, uint64(3), res.LineageEpoch)
	require.True(t, res.Advanced, "the verified recovery restored the excluded identity")
	require.False(t, res.Retired)
	require.Equal(t, old.ShardEpoch+2, res.ShardEpoch)
	require.True(t, a.irBaseKnown)
	require.Equal(t, old.ShardEpoch, a.irBase)
	require.False(t, a.Status().SessionIssued)
	require.Equal(t, uint64(41), a.rec.reserved)
	require.ErrorIs(t, a.Sign(oldSession), ErrFenced)
	_, err = a.ReplaceSession()
	require.NoError(t, err)
	active := a.Status()
	for _, f := range []*q3fixture.Fixture{primary, recovery} {
		res, err := a.AdvanceWithProof(ctx, bundleOf(t, f))
		require.NoError(t, err)
		require.True(t, res.Replay)
		require.False(t, res.Advanced || res.Retired)
		require.Equal(t, active.Generation, a.Status().Generation)
		require.True(t, a.Status().SessionIssued)
	}
}

func TestExclusionRecoveryEligibilityEndsAtTheNextActivation(t *testing.T) {
	ctx := context.Background()
	primary := q3fixture.New(t, q3fixture.Options{Assignment: true})
	_, dropped := keptAndDropped(t, primary)
	a := proofAuthority(t, primary, dropped)
	_, err := a.AdvanceWithProof(ctx, bundleOf(t, primary))
	require.NoError(t, err)
	require.NotNil(t, a.recovery)

	_, installed, err := activatedOf(primary)
	require.NoError(t, err)
	rootOnly := q3fixture.New(t, q3fixture.Options{After: primary, Installed: installed})
	res, err := a.AdvanceWithProof(ctx, bundleOf(t, rootOnly))
	require.NoError(t, err)
	require.True(t, res.Retired)
	require.False(t, res.Advanced)
	require.Nil(t, a.recovery)
	_, err = a.ReplaceSession()
	require.ErrorIs(t, err, ErrRetired)
}

func TestExcludedAuthorityRefusesNonmatchingRecovery(t *testing.T) {
	for _, tc := range []struct {
		name         string
		acknowledged bool
		edit         func(*evmassign.Candidate)
		lineageError bool
	}{
		{name: "the primary acknowledged", acknowledged: true},
		{name: "different authorization", lineageError: true, edit: func(c *evmassign.Candidate) {
			auth := *c.Authorization
			auth.ResultID = bytes.Clone(auth.ResultID)
			auth.ResultID[0] ^= 1
			c.Authorization = &auth
		}},
		{name: "different replaced assignment", lineageError: true, edit: func(c *evmassign.Candidate) {
			c.ReplacedAssignment[0] ^= 1
		}},
		{name: "different committed handoff", edit: func(c *evmassign.Candidate) {
			c.Supersedes.SupersededH = bytes.Clone(c.Supersedes.SupersededH)
			c.Supersedes.SupersededH[0] ^= 1
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			primary := q3fixture.New(t, q3fixture.Options{Assignment: true})
			_, dropped := keptAndDropped(t, primary)
			a := proofAuthority(t, primary, dropped, WithUncheckedAdvance())
			_, err := a.AdvanceWithProof(ctx, bundleOf(t, primary))
			require.NoError(t, err)
			recovery := recoveryFixture(t, primary, tc.acknowledged, tc.edit)
			res, err := a.AdvanceWithProof(ctx, bundleOf(t, recovery))
			if tc.lineageError {
				require.ErrorIs(t, err, ErrLineageUnverified)
				require.Equal(t, uint64(2), a.Status().LineageEpoch)
			} else {
				require.NoError(t, err)
				require.Equal(t, uint64(3), res.LineageEpoch)
				require.False(t, res.Advanced)
			}
			require.True(t, a.Status().Retired)
			require.Equal(t, uint64(1), a.Status().RootEpoch)
			_, err = a.ReplaceSession()
			require.ErrorIs(t, err, ErrRetired)
			require.ErrorIs(t, a.AdvanceEpoch(ctx, recovery.Successor, primary.History.Tip().Projection()), ErrRetired)
		})
	}
}
