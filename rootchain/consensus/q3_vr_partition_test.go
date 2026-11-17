package consensus

import (
	"context"
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// The production request history after a VR activation (VT-06d/e, astra review of #1181): a coupled handoff whose committed candidate is a
// candidate v6 with an AddPartition (partition 10), an UpdatePartition (partition 9: a new T2 timeout) and a ReplaceAggregatorValidators
// (partition 11: new validators). Every replica installs it through InstallVerifiedEpoch; the runtime's request history, over the
// manager's retained candidates, serves the EVM assignment, the real activations of the two replaced shards (never "unchanged"
// continuations) and the new partition's anchor at the adding handoff; the resolver then judges a certification request of each changed
// shard under its new configuration from the boundary round, and under the old one before it.

const (
	vrUpdated  types.PartitionID = 9
	vrAdded    types.PartitionID = 10
	vrReplaced types.PartitionID = 11
)

func vrRegistry(t *testing.T) func(extra []*types.PartitionDescriptionRecord) []vrschema.RegistryChange {
	return func(extra []*types.PartitionDescriptionRecord) []vrschema.RegistryChange {
		byPartition := map[types.PartitionID]*types.PartitionDescriptionRecord{}
		for _, c := range extra {
			byPartition[c.PartitionID] = c
		}
		cbor := func(v any) []byte {
			b, err := types.Cbor.Marshal(v)
			require.NoError(t, err)
			return b
		}
		_, infos := testutils.CreateTestNodes(t, 2)
		added := &types.PartitionDescriptionRecord{Version: 1, NetworkID: q3fixture.Network, PartitionID: vrAdded, PartitionTypeID: 10, TypeIDLen: 8,
			UnitIDLen: 256, T2Timeout: 3 * time.Second, Validators: infos}
		add, err := vrschema.EncodeChange(vrschema.KindAddPartition, cbor(added), []byte{0x80})
		require.NoError(t, err)

		cur := byPartition[vrUpdated]
		succ, err := evmassign.NewSuccessor(cur, cur.Validators)
		require.NoError(t, err)
		succ.T2Timeout = 9 * time.Second
		h, err := evmassign.PDRHash(cur)
		require.NoError(t, err)
		update, err := vrschema.EncodeChange(vrschema.KindUpdatePartition, uint64(vrUpdated), cur.ShardID.Bytes(), h, cbor(succ))
		require.NoError(t, err)

		old := byPartition[vrReplaced]
		_, next := testutils.CreateTestNodes(t, 1)
		repl, err := evmassign.NewSuccessor(old, next)
		require.NoError(t, err)
		oh, err := evmassign.PDRHash(old)
		require.NoError(t, err)
		replace, err := vrschema.EncodeChange(vrschema.KindReplaceAggregator, uint64(vrReplaced), old.ShardID.Bytes(), oh, cbor(repl), []byte{0x80})
		require.NoError(t, err)
		return []vrschema.RegistryChange{{ID: 5, Kind: uint64(vrschema.KindAddPartition), Payload: add},
			{ID: 6, Kind: uint64(vrschema.KindUpdatePartition), Payload: update}, {ID: 7, Kind: uint64(vrschema.KindReplaceAggregator), Payload: replace}}
	}
}

// v5Only is a candidate source that serves only the v5 view (no committed-preimage capability).
type v5Only struct{ src q3active.CandidateSource }

func (v v5Only) HandoffCandidate(id []byte) ([]byte, error) { return v.src.HandoffCandidate(id) }

func TestTheRequestHistoryServesAVRActivationsPartitionChanges(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true, Registry: vrRegistry(t),
		ExtraShards: []q3fixture.ExtraShard{{Partition: vrUpdated, Validators: 1, TypeID: 9}, {Partition: vrReplaced, Validators: 1, TypeID: 11}}})
	c.activateAll()
	r := c.heavy()
	key := func(p types.PartitionID) types.PartitionShardID {
		return types.PartitionShardID{PartitionID: p, ShardID: types.ShardID{}.Key()}
	}
	confs, err := r.orchestration.ShardConfigs(7)
	require.NoError(t, err)
	require.EqualValues(t, 0, confs[key(vrAdded)].Epoch, "the addition installed at the boundary")
	require.EqualValues(t, 1, confs[key(vrUpdated)].Epoch)
	require.Equal(t, 9*time.Second, confs[key(vrUpdated)].T2Timeout)
	require.EqualValues(t, 1, confs[key(vrReplaced)].Epoch)
	hashOf := func(p *types.PartitionDescriptionRecord) []byte {
		h, err := p.Hash(crypto.SHA256)
		require.NoError(t, err)
		return h
	}
	history := func(src q3active.CandidateSource) *q3active.RequestHistory {
		h, err := r.rt.RequestHistory(q3active.RequestHistoryConfig{Candidates: src,
			Anchor: func(p types.PartitionID, s types.ShardID) (*types.PartitionDescriptionRecord, error) {
				return r.orchestration.ShardConfigByEpoch(p, s, 0)
			}, HashAlg: crypto.SHA256, Network: q3fixture.Network, Version: 1})
		require.NoError(t, err)
		return h
	}
	body := c.f.Body.Identity()
	check := func(t *testing.T, hist *q3active.RequestHistory) {
		evm, err := hist.Chain(q3fixture.PartitionID, types.ShardID{})
		require.NoError(t, err, "the EVM assignment of a v6-bound body")
		require.Len(t, evm, 2)
		for _, p := range []types.PartitionID{vrUpdated, vrReplaced} {
			chain, err := hist.Chain(p, types.ShardID{})
			require.NoError(t, err, "partition %d", p)
			require.Len(t, chain, 2, "partition %d: the anchor and the real activation", p)
			require.Equal(t, hashOf(confs[key(p)]), chain[1].PDRHash(), "partition %d: the replaced configuration, not an unchanged continuation", p)
			require.Equal(t, body[:], chain[1].RootBody())
		}
		added, err := hist.Chain(vrAdded, types.ShardID{})
		require.NoError(t, err)
		require.Len(t, added, 1, "the new partition's history begins at the adding handoff")
		require.Equal(t, hashOf(confs[key(vrAdded)]), added[0].PDRHash())
		require.Equal(t, body[:], added[0].RootBody(), "anchored under the adding handoff's root identity")
	}
	hist := history(r.manager)
	check(t, hist)

	t.Run("a certification request of a changed shard is judged under its new configuration from the boundary", func(t *testing.T) {
		for _, p := range []types.PartitionID{vrUpdated, vrReplaced} {
			parent := r.manager.blockStore.ShardInfo(p, types.ShardID{})
			require.NotNil(t, parent)
			view, err := storage.ResolveParentView(hist, nil, parent, []byte("verified parent block"), 7, crypto.SHA256, storage.PurposeCertify, nil)
			require.NoError(t, err, "partition %d", p)
			pdr, err := view.PDR()
			require.NoError(t, err)
			require.Equal(t, hashOf(confs[key(p)]), hashOf(pdr), "partition %d", p)
			require.EqualValues(t, 1, view.ExpectedTR().Epoch, "partition %d: the successor record derived from the verified parent", p)
			require.ElementsMatch(t, validatorIDs(confs[key(p)]), view.Context().NodeIDs(), "partition %d", p)
			if p == vrUpdated {
				require.Equal(t, 9*time.Second, view.T2Timeout(), "the reloaded T2 timeout")
			}
			before, err := storage.ResolveParentView(hist, nil, parent, []byte("verified parent block"), 6, crypto.SHA256, storage.PurposeCertify, nil)
			require.NoError(t, err)
			old, err := before.PDR()
			require.NoError(t, err)
			require.EqualValues(t, 0, old.Epoch, "partition %d: before the boundary the old configuration certifies", p)
		}
	})
	t.Run("replay: an invalidated history derives the same chains", func(t *testing.T) {
		hist.Invalidate()
		check(t, hist)
	})
	t.Run("a source that serves only the v5 view fails closed", func(t *testing.T) {
		_, err := history(v5Only{r.manager}).Chain(vrUpdated, types.ShardID{})
		require.ErrorIs(t, err, q3active.ErrRequestHistory)
		require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	})
	t.Run("recovery: a restarted replica serves the same chains", func(t *testing.T) {
		r.close()
		r.mustOpen(true)
		require.NoError(t, r.rt.Recover(context.Background()))
		require.NoError(t, r.rt.Admit(2))
		check(t, history(r.manager))
	})
}

func validatorIDs(p *types.PartitionDescriptionRecord) []string {
	out := make([]string, 0, len(p.Validators))
	for _, v := range p.Validators {
		out = append(out, v.NodeID)
	}
	return out
}
