package consensus

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
)

// #941: without a request history (a root whose verified history holds no activation: the default dispatch) the request verifier reads a
// shard's proof configuration from its committed ShardInfo, and a root built from a committed head by newRootBlock had none: the verifier took
// the shard for one without a proof and accepted a broken envelope. Two routes, both with the RSMT shards of the F8 topology:
//   - activated: the fixture's running root, whose root block its epoch activation built from the handoff checkpoint (NewRootBlock);
//   - recovered: a root that recovered from that root's state message the way onStateResponse does (NewFromState, then newRecoveryVerifier).
//
// Both must hold the configuration's parameters and refuse the broken envelope for its proof, and take the valid request.
func TestRecoveredRootRefusesABrokenEnvelope(t *testing.T) {
	c := newEqualLiveOptions(t, 2*time.Second, traceTopology(t, "f8"), "H", "a", "b", "c")
	c.start(c.all()...)
	c.warm(3, c.all()...)
	shards := liveShards(c, false)
	establish(t, c, "H", shards)
	for _, name := range c.all() { // a still state: no T2 repeat moves a shard between building a request and judging it
		c.stop(name)
	}
	n := c.nodes[c.idx("H")]
	m := n.r.manager

	sm, err := m.blockStore.GetState()
	require.NoError(t, err)
	raw, err := types.Cbor.Marshal(sm)
	require.NoError(t, err)
	var received abdrc.StateMsg // as it arrives from the peer
	require.NoError(t, types.Cbor.Unmarshal(raw, &received))
	require.Nil(t, received.CommittedHead.Anchor, "the fixture's head is a state head, the NewFromState route of onStateResponse")
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "recovered.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	recovered, err := storage.NewFromState(m.params.HashAlgorithm, received.CommittedHead, db, m.orchestration, m.log, m.params.NetworkProfileVersion)
	require.NoError(t, err)

	// no request history: the dispatch of a root without an activation, on both stores
	activated, err := NewIRChangeReqVerifier(m.params, m.blockStore)
	require.NoError(t, err)
	afterRecovery, err := newRecoveryVerifier(m.params, recovered, activated)
	require.NoError(t, err)
	require.Nil(t, afterRecovery.RequestHistory())

	round := m.pacemaker.GetCurrentRound() + 1
	judged := 0
	for _, s := range shards {
		if !s.rsmt {
			continue
		}
		judged++
		ir := func(req *IRChangeRequest) *drctypes.IRChangeReq {
			require.NotNil(t, req, s)
			return &drctypes.IRChangeReq{Partition: s.partition, Shard: s.shard, CertReason: drctypes.Quorum, Requests: req.Requests}
		}
		valid, broken := ir(shardRequest(t, n.r, s, false, false)), ir(shardRequest(t, n.r, s, false, true))
		view, enabled, err := m.RequestView(s.partition, s.shard)
		require.NoError(t, err)
		require.True(t, enabled)
		pdr, err := view.PDR()
		require.NoError(t, err)
		require.Equal(t, "aggregator_rsmt_v1", pdr.GetPartitionParams()["proof_type"], "the configuration of shard %s", s)
		held := assert.Equal(t, pdr.GetPartitionParams(), m.blockStore.ShardInfo(s.partition, s.shard).PartitionParams, "activated store: the proof configuration of shard %s", s)
		held = assert.Equal(t, pdr.GetPartitionParams(), recovered.ShardInfo(s.partition, s.shard).PartitionParams, "recovered store: the proof configuration of shard %s", s) && held
		require.True(t, held)
		for _, v := range []struct {
			name     string
			verifier *IRChangeReqVerifier
		}{{"activated", activated}, {"recovered", afterRecovery}} {
			_, err := v.verifier.VerifyRequest(round, valid)
			require.NoError(t, err, "%s: shard %s, the valid request", v.name, s)
			_, err = v.verifier.VerifyRequest(round, broken)
			require.ErrorIs(t, err, ErrProofInvalid, "%s: shard %s, the broken envelope", v.name, s)
			require.ErrorIs(t, err, zkverifier.ErrInvalidProofFormat, "%s: shard %s", v.name, s)
		}
	}
	require.Equal(t, 3, judged, "the F8 topology's three RSMT shards")
}
