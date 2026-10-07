package consensus

import (
	"context"
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	"github.com/unicitynetwork/bft-go-base/types"
)

// A coupled activation installs the successor EVM assignment with the root committee: the weighted validators of the committed
// candidate become the shard's configuration from A*, in every manager's orchestration, derived from the retained body and candidate.
func TestCoupledActivationInstallsTheWeightedAssignment(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	anchor := c.activateAll()
	require.EqualValues(t, 6, anchor.Slot)
	key := types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}
	for _, r := range c.replicas {
		before, err := r.orchestration.ShardConfigs(6)
		require.NoError(t, err)
		require.EqualValues(t, 0, before[key].Epoch, "before A* the retired assignment is in force")
		confs, err := r.orchestration.ShardConfigs(7)
		require.NoError(t, err)
		conf := confs[key]
		require.EqualValues(t, 1, conf.Epoch, "the committed successor assignment")
		require.EqualValues(t, 7, conf.EpochStart, "active from the committed boundary")
		var weights []uint64
		var total uint64
		for _, v := range conf.Validators {
			weights = append(weights, v.Stake)
			total += v.Stake
		}
		require.ElementsMatch(t, []uint64{6, 1, 1, 1}, weights, "the EVM weights mirror the root weights")
		require.EqualValues(t, 9, total)
		activated, ok := r.rt.Activated(2)
		require.True(t, ok)
		require.NoError(t, r.manager.HoldsVerifiedEpoch(activated))
	}
}

// The candidate is the one the committed record binds or nothing is installed: every refusal leaves the stores untouched.
func TestCoupledInstallRefusesAnyOtherCandidate(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{Assignment: true})
	h, err := q3format.NewHistory(f.Old)
	require.NoError(t, err)
	verified, err := h.VerifyEnvelope(f.Envelope)
	require.NoError(t, err)
	entry := verified.Tip()
	fresh := func(t *testing.T) *q3Replica {
		r := newQ3Replica(t, f, f.NewNodes[0])
		r.mustOpen(false)
		t.Cleanup(r.close)
		require.NoError(t, r.trust.BindSigningAuthority(verified))
		return r
	}
	flipped := append([]byte(nil), f.Candidate...)
	flipped[len(flipped)/2] ^= 1
	for name, candidate := range map[string][]byte{
		"a candidate of other bytes":    flipped,
		"a truncated candidate":         f.Candidate[:len(f.Candidate)-1],
		"a candidate of another record": q3fixture.New(t, q3fixture.Options{Assignment: true, MutateCandidate: func(c *evmassign.Candidate) { c.Attempt++ }}).Candidate,
	} {
		t.Run(name, func(t *testing.T) {
			r := fresh(t)
			_, err := r.manager.InstallVerifiedEpoch(entry, f.Proof, f.Snapshot, candidate)
			require.ErrorIs(t, err, ErrQ3Candidate)
			require.ErrorIs(t, err, storage.ErrAssignmentHistory)
			_, err = r.trust.GetByEpoch(2)
			require.ErrorIs(t, err, tbstore.ErrNotFound, "nothing was installed")
			require.Nil(t, r.manager.epochAnchor)
			confs, err := r.orchestration.ShardConfigs(7)
			require.NoError(t, err)
			require.EqualValues(t, 0, confs[types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}].Epoch, "the retired assignment is still the only one")
		})
	}
	t.Run("the candidate of a root-only record", func(t *testing.T) {
		plain := q3fixture.New(t, q3fixture.Options{Chain: f})
		ph, err := q3format.NewHistory(plain.Old)
		require.NoError(t, err)
		pv, err := ph.VerifyEnvelope(plain.Envelope)
		require.NoError(t, err)
		r := newQ3Replica(t, plain, plain.NewNodes[0])
		r.mustOpen(false)
		t.Cleanup(r.close)
		require.NoError(t, r.trust.BindSigningAuthority(pv))
		_, err = r.manager.InstallVerifiedEpoch(pv.Tip(), plain.Proof, plain.Snapshot, f.Candidate)
		require.ErrorIs(t, err, ErrQ3Candidate)
	})
	t.Run("acceptance control", func(t *testing.T) {
		r := fresh(t)
		_, err := r.manager.InstallVerifiedEpoch(entry, f.Proof, f.Snapshot, f.Candidate)
		require.NoError(t, err)
		require.NoError(t, r.manager.HoldsVerifiedEpoch(entry))
	})
}

// A restart of a coupled activation rebuilds the verified history from the journal, finds the derived assignment in the
// orchestration, and the manager comes up holding exactly the activated epoch; the assignment is not derived a second time
// differently (the derived write is idempotent, a conflicting one refuses).
func TestCoupledActivationSurvivesARestart(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	anchor := c.activateAll()
	ctx := context.Background()
	key := types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}
	for _, r := range c.replicas {
		r.close()
		r.mustOpen(true)
		require.Equal(t, anchor, r.manager.epochAnchor, "the durable anchor is recovered")
		require.NoError(t, r.rt.Recover(ctx))
		require.NoError(t, r.rt.Admit(2))
		confs, err := r.orchestration.ShardConfigs(7)
		require.NoError(t, err)
		require.EqualValues(t, 1, confs[key].Epoch, "the derived assignment is still the one in force")
		require.EqualValues(t, 7, r.manager.trustBase.Load().QuorumThreshold)
	}
}

// The request history of a runtime serves the anchor and the weighted mirrored assignment the verified history activated, and the
// resolver derives the EVM request context from it: W=9, Q=5, the heavy member alone certifies, three light members cannot, and
// before the boundary round the committed assignment is collection-only.
func TestTheRequestHistoryServesTheActivatedWeightedAssignment(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	c.activateAll()
	r := c.heavy()
	hist, err := r.rt.RequestHistory(q3active.RequestHistoryConfig{Candidates: r.manager.blockStore,
		Anchor: func(types.PartitionID, types.ShardID) (*types.PartitionDescriptionRecord, error) {
			return c.f.ShardConf, nil
		},
		HashAlg: crypto.SHA256, Network: q3fixture.Network, Version: 1})
	require.NoError(t, err)
	chain, err := hist.Chain(q3fixture.PartitionID, types.ShardID{})
	require.NoError(t, err)
	require.Len(t, chain, 2, "the anchor and the activated assignment")

	parent := r.manager.blockStore.ShardInfo(q3fixture.PartitionID, types.ShardID{})
	require.NotNil(t, parent)
	parentID := []byte("verified parent block")
	t.Run("at the boundary the weighted context is in force", func(t *testing.T) {
		view, err := storage.ResolveParentView(hist, nil, parent, parentID, 7, crypto.SHA256, storage.PurposeCertify, nil)
		require.NoError(t, err)
		ctx := view.Context()
		require.EqualValues(t, 9, ctx.TotalWeight())
		require.EqualValues(t, 5, ctx.Threshold(), "EVM Q=5 of W=9")
		var weights []uint64
		for _, id := range ctx.NodeIDs() {
			w, err := ctx.SignerWeight(id)
			require.NoError(t, err)
			weights = append(weights, w)
		}
		require.ElementsMatch(t, []uint64{6, 1, 1, 1}, weights)
		require.True(t, ctx.QuorumReached(6), "the heavy member alone certifies")
		require.False(t, ctx.QuorumReached(3), "three light members cannot")
		require.True(t, ctx.QuorumReached(5))
		require.False(t, ctx.QuorumReached(4))
		rootEpoch, rootBody, err := hist.RootIdentity(7)
		require.NoError(t, err)
		require.EqualValues(t, 2, rootEpoch)
		id := c.f.Body.Identity()
		require.Equal(t, id[:], rootBody)
	})
	t.Run("before the boundary the retired unit assignment is the one certifying", func(t *testing.T) {
		view, err := storage.ResolveParentView(hist, nil, parent, parentID, 6, crypto.SHA256, storage.PurposeCertify, nil)
		require.NoError(t, err)
		require.EqualValues(t, 3, view.Context().TotalWeight(), "the three unit validators of the anchor")
		require.EqualValues(t, 2, view.Context().Threshold())
	})
	t.Run("the root identity of an earlier round is the genesis epoch's", func(t *testing.T) {
		epoch, _, err := hist.RootIdentity(3)
		require.NoError(t, err)
		require.EqualValues(t, 1, epoch)
	})
	t.Run("an unretained candidate is a missing history, never the anchor alone", func(t *testing.T) {
		empty, err := r.rt.RequestHistory(q3active.RequestHistoryConfig{Candidates: noCandidates{},
			Anchor: func(types.PartitionID, types.ShardID) (*types.PartitionDescriptionRecord, error) {
				return c.f.ShardConf, nil
			},
			HashAlg: crypto.SHA256, Network: q3fixture.Network, Version: 1})
		require.NoError(t, err)
		_, err = empty.Chain(q3fixture.PartitionID, types.ShardID{})
		require.ErrorIs(t, err, q3active.ErrRequestHistory)
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	})
}

type noCandidates struct{}

func (noCandidates) HandoffCandidate([]byte) ([]byte, error) { return nil, nil }
