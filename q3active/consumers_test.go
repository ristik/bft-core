package q3active_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-core/signingauthority"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// The guarded lookup is what each consumer of root trust is given: the same value satisfies every one of their trust interfaces.
var (
	_ shardnode.TrustBaseStore       = (*q3active.Guarded)(nil)
	_ shardnode.HandoffHistory       = (*q3active.GuardedHandoff)(nil)
	_ signingauthority.TrustBases    = (*q3active.Guarded)(nil)
	_ certifiedstore.TrustBases      = (*q3active.Guarded)(nil)
	_ rootinput.TrustBases           = (*q3active.Guarded)(nil)
	_ weightvalidation.ModeSource    = (*q3active.Guarded)(nil)
	_ q3active.HandoffInstaller      = (*recordingHistory)(nil)
	_ q3active.TrustLookup           = (*q3active.GuardedHandoff)(nil)
	_ interface{ BoundTo(any) bool } = (*q3active.GuardedHandoff)(nil)
)

func signed(t *testing.T, f *q3fixture.Fixture, data []byte, who ...int) map[string]hex.Bytes {
	t.Helper()
	out := map[string]hex.Bytes{}
	for _, i := range who {
		n := f.NewNodes[i]
		sig, err := n.Signer.SignBytes(data)
		require.NoError(t, err)
		out[n.PeerConf.ID.String()] = sig
	}
	return out
}

// Certificates of the activated epoch are authenticated by the weighted quorum of the verified projection, through any consumer's
// lookup: the heavy member and one light one are 7 of 9, three light members are 3 and the heavy one alone is 6.
func TestCertificateConsumersCountTheVerifiedWeights(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{}) // NewNodes[0] weighs 6
	p := newProcess(t, f)
	rt := p.start()
	require.NoError(t, rt.Recover(ctx))
	data := []byte("unicity seal")

	// before the activation completes, no consumer can authenticate under the epoch
	for name, lookup := range map[string]q3active.TrustLookup{"shard": rt.Trust(nil), "authority": rt.Trust(nil), "handoff": rt.Handoff(&recordingHistory{})} {
		_, err := lookup.GetByEpoch(ctx, 2)
		require.ErrorIs(t, err, q3format.ErrUnknownEpoch, name)
	}
	require.NoError(t, rt.Activate(ctx, p.bundle()))

	for name, lookup := range map[string]q3active.TrustLookup{"shard": rt.Trust(nil), "authority": rt.Trust(nil), "handoff": rt.Handoff(&recordingHistory{})} {
		t.Run(name, func(t *testing.T) {
			tb, err := lookup.GetByEpoch(ctx, 2)
			require.NoError(t, err)
			verifier := quorumweight.Checked(tb)
			require.NoError(t, verifier.VerifyQuorumSignatures(data, signed(t, f, data, 0, 1)), "6+1 reaches 7")
			require.NoError(t, verifier.VerifyQuorumSignatures(data, signed(t, f, data, 0, 1, 2, 3)))
			err = verifier.VerifyQuorumSignatures(data, signed(t, f, data, 1, 2, 3))
			require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached, "three light members are 3 of 9, and three of the four members")
			err = verifier.VerifyQuorumSignatures(data, signed(t, f, data, 0))
			require.ErrorIs(t, err, quorumweight.ErrQuorumNotReached, "the heavy member alone is 6 of 9")
		})
	}

	t.Run("the genesis epoch keeps its unit quorum", func(t *testing.T) {
		tb, err := rt.Trust(nil).GetByEpoch(ctx, 1)
		require.NoError(t, err)
		require.EqualValues(t, 3, tb.QuorumThreshold)
	})
}

// recordingHistory is the shard node's legacy history: it installs whatever it is given and says so.
type recordingHistory struct {
	installs int
	err      error
}

func (h *recordingHistory) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return nil, errors.New("no legacy epoch")
}

func (h *recordingHistory) InstallHandoff(context.Context, handoffdelivery.Bundle, types.PartitionID, types.ShardID, []byte) (handoffdelivery.Verified, error) {
	h.installs++
	return handoffdelivery.Verified{}, h.err
}

func TestAnOldPeerCannotInstallAnActivatedEpochIntoTheShardHistory(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := newProcess(t, f)
	rt := p.start()
	require.NoError(t, rt.Recover(ctx))
	base := &recordingHistory{}
	history := rt.Handoff(base)

	legacy := func(fromEpoch uint64) handoffdelivery.Bundle {
		var b handoffdelivery.Bundle
		b.Proof.Record.Epoch = fromEpoch
		return b
	}
	// before the activation the base history decides
	_, err := history.InstallHandoff(ctx, legacy(1), 8, types.ShardID{}, nil)
	require.NoError(t, err)
	require.Equal(t, 1, base.installs)

	require.NoError(t, rt.Activate(ctx, p.bundle()))
	_, err = history.InstallHandoff(ctx, legacy(1), 8, types.ShardID{}, nil)
	require.ErrorIs(t, err, q3active.ErrLegacyBundle, "a legacy bundle for the activated epoch 2")
	require.Equal(t, 1, base.installs, "the base history was not asked")

	_, err = history.InstallHandoff(ctx, legacy(2), 8, types.ShardID{}, nil)
	require.NoError(t, err, "a handoff out of the activated epoch is not the activation")
	require.Equal(t, 2, base.installs)

	boom := errors.New("the base refuses")
	base.err = boom
	_, err = history.InstallHandoff(ctx, legacy(5), 8, types.ShardID{}, nil)
	require.ErrorIs(t, err, boom, "the base's refusal passes through")

	_, err = history.InstallHandoff(ctx, legacy(^uint64(0)), 8, types.ShardID{}, nil)
	require.ErrorIs(t, err, handoffdelivery.ErrBundle)
	require.True(t, history.BoundTo(rt))
}
