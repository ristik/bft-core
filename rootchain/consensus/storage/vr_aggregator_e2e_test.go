package storage_test

import (
	"crypto"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/vradmit"
	"github.com/unicitynetwork/bft-core/vrschema"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Aggregator set from VR through the real block executor (VT-06a, ReplaceAggregatorValidators; design section 6.3): the aggregator shard
// of partition 9 gets a second validator. The change is bound by VR, the Freeze v5 admits it with the fold's verdict, H commits, the epoch
// switch installs the successor with the EVM assignment, and the first block of the new epoch advances the shard's configuration.

type vxAggFault int

const (
	vxAggOK vxAggFault = iota
	vxAggStale
	vxAggBadPoP
	vxAggConfigChanged
)

// newVXAggregators is the VR fixture with one kind 6 change (id 5) of the aggregator shard of partition 9: validators {agg-1} become
// {agg-1, agg-2}. The fault makes it name a stale configuration, carry a PoP of another change id, or change a non-membership field.
func newVXAggregators(t *testing.T, fault vxAggFault) *vxPartitions {
	f := &vxPartitions{vxFixture: newVXFixture(t)}
	f.current.Epoch, f.current.EpochStart = 0, 1
	succ, err := evmassign.NewSuccessor(f.current, f.succ.Validators)
	require.NoError(t, err)
	f.succ = succ
	kd, err := evmassign.IdentitiesDigest(f.k)
	require.NoError(t, err)
	f.baseHash, err = evmassign.AssignmentHash(f.current, kd)
	require.NoError(t, err)

	f.agg = &types.PartitionDescriptionRecord{Version: 1, NetworkID: vxNetwork, PartitionID: 9, PartitionTypeID: 9, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 2500 * time.Millisecond, Epoch: 0, EpochStart: 1, PartitionParams: map[string]string{"proof_type": "aggregator_rsmt_v1"},
		Validators: []*types.NodeInfo{vxNodeInfo(t, 40, "agg-1")}}
	f.aggNext, err = evmassign.NewSuccessor(f.agg, []*types.NodeInfo{vxNodeInfo(t, 40, "agg-1"), vxNodeInfo(t, 43, "agg-2")})
	require.NoError(t, err)
	if fault == vxAggConfigChanged {
		f.aggNext.T2Timeout = 7 * time.Second
	}
	raw, err := types.Cbor.Marshal(f.aggNext)
	require.NoError(t, err)
	popID := uint64(5)
	if fault == vxAggBadPoP {
		popID = 6
	}
	var pops []evmassign.PoP
	for i, seed := range []byte{40, 43} {
		v := f.aggNext.Validators[i]
		msg, err := vrschema.ChangePoPMessage(vxNetwork, vrschema.ValidatorRegistry, popID, 9, f.agg.ShardID.Bytes(), raw, v.NodeID)
		require.NoError(t, err)
		sig, err := vxMkKey(t, seed).signer.SignBytes(msg)
		require.NoError(t, err)
		pops = append(pops, evmassign.PoP{NodeID: v.NodeID, Key: v.SigKey, Signature: sig})
	}
	popRaw, err := types.Cbor.Marshal(pops)
	require.NoError(t, err)
	replaced := f.agg
	if fault == vxAggStale {
		moved := *f.agg
		moved.T2Timeout += time.Second
		replaced = &moved
	}
	expected, err := evmassign.PDRHash(replaced)
	require.NoError(t, err)
	payload, err := vrschema.EncodeChange(vrschema.KindReplaceAggregator, uint64(9), f.agg.ShardID.Bytes(), expected, raw, popRaw)
	require.NoError(t, err)
	f.extraShards = []*types.PartitionDescriptionRecord{f.agg}
	verdict := uint64(vrschema.VerdictAccepted)
	switch fault {
	case vxAggStale:
		verdict = uint64(vrschema.VerdictConflict)
	case vxAggBadPoP:
		verdict = uint64(vrschema.VerdictBadPoP)
	case vxAggConfigChanged:
		verdict = uint64(vrschema.VerdictInvalid)
	}
	f.extraChanges = []vrschema.RegistryChange{{ID: 5, Kind: uint64(vrschema.KindReplaceAggregator), Payload: payload, Verdict: verdict}}
	f.build()
	f.orch = f.realOrchestration(t)
	return f
}

func TestVRReplaceAggregatorsThroughTheExecutor(t *testing.T) {
	f := newVXAggregators(t, vxAggOK)
	checkpoint, commit, retained := f.committed(t)
	require.Zero(t, vradmitStaged(t, checkpoint))

	before, err := f.orch.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	require.Len(t, before[vxAgg].Validators, 1, "nothing installs before the commit is installed")

	require.NoError(t, storage.InstallCommittedForTest(retained, f.orch, checkpoint, commit))
	confs, err := f.orch.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	require.EqualValues(t, 1, confs[vxAgg].Epoch)
	require.EqualValues(t, commit.ActivationRound, confs[vxAgg].EpochStart)
	require.Len(t, confs[vxAgg].Validators, 2)
	require.Equal(t, 2500*time.Millisecond, confs[vxAgg].T2Timeout, "only the validators changed")
	earlier, err := f.orch.ShardConfigs(commit.ActivationRound - 1)
	require.NoError(t, err)
	require.Len(t, earlier[vxAgg].Validators, 1, "the old set stays in force before the activation round")
	require.NoError(t, storage.InstallCommittedForTest(retained, f.orch, checkpoint, commit), "idempotent")

	first, err := f.activate(t, checkpoint, commit, retained)
	require.NoError(t, err)
	agg := first.ShardState.States[vxAgg]
	require.Equal(t, confHash(t, confs[vxAgg]), []byte(agg.ShardConfHash), "the shard switches to the new validator set at the boundary")
	require.EqualValues(t, 1, agg.TR.Epoch)
	again, err := f.activate(t, checkpoint, commit, retained)
	require.NoError(t, err)
	require.Equal(t, first.RootHash, again.RootHash, "replay")

	// a second root derives the same set from the same committed bytes
	other := f.realOrchestration(t)
	require.NoError(t, storage.InstallCommittedForTest(retained, other, checkpoint, commit))
	oc, err := other.ShardConfigs(commit.ActivationRound)
	require.NoError(t, err)
	require.Equal(t, confHash(t, confs[vxAgg]), confHash(t, oc[vxAgg]))
}

func TestVRReplaceAggregatorsFaultsAreRejectedAndInstallNothing(t *testing.T) {
	for name, fault := range map[string]vxAggFault{"stale expected hash": vxAggStale, "PoP of another change id": vxAggBadPoP, "config field changed": vxAggConfigChanged} {
		t.Run(name, func(t *testing.T) {
			f := newVXAggregators(t, fault)
			checkpoint, commit, retained := f.committed(t)
			require.NotZero(t, vradmitStaged(t, checkpoint), "rejected")
			require.NoError(t, storage.InstallCommittedForTest(retained, f.orch, checkpoint, commit))
			confs, err := f.orch.ShardConfigs(commit.ActivationRound)
			require.NoError(t, err)
			require.EqualValues(t, 0, confs[vxAgg].Epoch)
			require.Len(t, confs[vxAgg].Validators, 1)
			first, err := f.activate(t, checkpoint, commit, retained)
			require.NoError(t, err)
			require.EqualValues(t, 0, first.ShardState.States[vxAgg].TR.Epoch)

			// a Freeze that claims Accepted is not what the fold gives
			g := newVXAggregators(t, fault)
			g.extraChanges[0].Verdict = uint64(vrschema.VerdictAccepted)
			g.build()
			g.orch = g.realOrchestration(t)
			gen := g.genesis()
			prep := g.must(gen, g.block(gen, 11, 1_010, [][]byte{g.record("prepare", 0, 11).Bytes()}))
			_, err = g.exec(prep, g.block(prep, 12, 1_020, [][]byte{g.record("freeze", 0, 12).Bytes(), g.freezeV5(0)}))
			require.ErrorIs(t, err, vradmit.ErrVerdicts)
		})
	}
}

func TestVRReplaceAggregatorsWaitsForTheShardsAcknowledgement(t *testing.T) {
	f := newVXAggregators(t, vxAggOK)
	g := f.genesis()
	g.ShardState.States[vxAgg].TR.Epoch++
	prep := f.must(g, f.block(g, 11, 1_010, [][]byte{f.record("prepare", 0, 11).Bytes()}))
	_, err := f.exec(prep, f.block(prep, 12, 1_020, [][]byte{f.record("freeze", 0, 12).Bytes(), f.freezeV5(0)}))
	require.ErrorIs(t, err, vradmit.ErrAckGate)
}

// The request history (what a shard's nodes and consumers verify) carries a kind 6 change as a registry activation: the new validator set
// is in force from the committed activation round, and a continuation never proves the shard unchanged.
func TestVRRequestActivationOfAnAggregatorReplacement(t *testing.T) {
	f := newVXAggregators(t, vxAggOK)
	_, record, retained := f.committed(t)
	entry := vxEntry{f, record}
	v6 := retained.v6[string(record.NextBodyID)]

	previous, err := storage.NewRequestAnchor(f.agg, crypto.SHA256, record.Epoch, record.PredecessorBodyID, 1)
	require.NoError(t, err)
	_, err = storage.RequestContinuationFromVerifiedV3(previous, entry, v6, crypto.SHA256, 1)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory, "an Accepted kind 6 never proves the shard unchanged")
	act, ok, err := storage.RegistryActivationFromVerifiedV3(previous, entry, record, v6, crypto.SHA256, 1)
	require.NoError(t, err)
	require.True(t, ok)
	activated, err := evmassign.Activate(f.aggNext, record.ActivationRound)
	require.NoError(t, err)
	require.Equal(t, confHash(t, activated), act.PDRHash())

	moved := *f.agg
	moved.T2Timeout += time.Second
	stale, err := storage.NewRequestAnchor(&moved, crypto.SHA256, record.Epoch, record.PredecessorBodyID, 1)
	require.NoError(t, err)
	_, _, err = storage.RegistryActivationFromVerifiedV3(stale, entry, record, v6, crypto.SHA256, 1)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory, "a configuration other than the one it replaces")
}
