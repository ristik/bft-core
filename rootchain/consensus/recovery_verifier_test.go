package consensus

import (
	"bytes"
	"crypto"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
)

// stubHistory is a request history that is only ever compared, never consulted.
type stubHistory struct{ storage.RequestHistory }

func (stubHistory) Network() uint64 { return 3 }

// The verifier a recovery builds executes the recovery blocks, so it must already carry the request history of the verifier it replaces: a weighted EVM assignment
// has no unit request context on its ShardInfo (resetTrustBase leaves it nil, MemberCount is 0), and under the legacy dispatch every change request of that shard is
// refused ("IR Change Request contains more requests than registered partition nodes"): a root that lagged a weighted epoch behind could never catch up.
func TestRecoveryVerifierCarriesTheRequestHistoryBeforeAnyBlockIsExecuted(t *testing.T) {
	params := NewConsensusParams()
	var store *storage.BlockStore // only used as the (non-nil interface) state monitor; never called
	replaced, err := NewIRChangeReqVerifier(params, store)
	require.NoError(t, err)
	replaced.SetRequestHistory(stubHistory{})

	v, err := newRecoveryVerifier(params, store, replaced)
	require.NoError(t, err)
	require.NotNil(t, v.RequestHistory(), "the replacement verifier selects the view-aware branch from its first block")
	require.Equal(t, replaced.RequestHistory(), v.RequestHistory())
	var _ storage.RequestViewVerifier = v

	t.Run("a deployment without a history keeps the legacy dispatch", func(t *testing.T) {
		legacy, err := NewIRChangeReqVerifier(params, store)
		require.NoError(t, err)
		v, err := newRecoveryVerifier(params, store, legacy)
		require.NoError(t, err)
		require.Nil(t, v.RequestHistory())
		v, err = newRecoveryVerifier(params, store, nil)
		require.NoError(t, err)
		require.Nil(t, v.RequestHistory())
	})
}

// The recovery's replacement verifier is built only through the manager's recoveryVerifier: a direct NewIRChangeReqVerifier in onStateResponse, or the history carried after the
// recovery blocks are added, brings the legacy dispatch back for exactly the blocks that matter.
func TestOnStateResponseBuildsItsVerifierOnlyThroughTheManagersRecoveryVerifier(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "consensus_manager.go", nil, 0)
	require.NoError(t, err)
	var calls []string
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "onStateResponse" {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				switch fun := c.Fun.(type) {
				case *ast.Ident:
					calls = append(calls, fun.Name)
				case *ast.SelectorExpr:
					calls = append(calls, fun.Sel.Name)
				}
			}
			return true
		})
	}
	require.NotEmpty(t, calls, "onStateResponse was not found")
	require.Contains(t, calls, "recoveryVerifier")
	require.NotContains(t, calls, "newRecoveryVerifier", "the manager's own verifier is the one the replaced history is carried from")
	require.NotContains(t, calls, "NewIRChangeReqVerifier")
	require.NotContains(t, calls, "carryRequestHistory", "the history is carried when the verifier is built, before the recovery blocks are added")
}

// Behaviour: in an activated weighted epoch a recovery block that carries a signed weighted proof of the EVM shard is executed by the verifier the recovery builds, and
// refused by one without the request history (the legacy dispatch judges the proof against the bare ShardInfo, which has no unit request context for a weighted assignment).
func TestTheRecoveryVerifierExecutesAWeightedProofTheLegacyDispatchRefuses(t *testing.T) {
	c := newQ3Cluster(t, q3fixture.Options{Assignment: true})
	for _, r := range c.replicas {
		selectRuntimeRequestHistory(t, r)
	}
	anchor := c.activateAll()
	r := c.heavy()
	view, enabled, err := r.manager.RequestView(q3fixture.PartitionID, types.ShardID{})
	require.NoError(t, err)
	require.True(t, enabled)
	tr := view.ExpectedTR()
	uc, err := view.PreviousUC()
	require.NoError(t, err)
	proof := &rctypes.IRChangeReq{Partition: q3fixture.PartitionID, Shard: types.ShardID{}, CertReason: rctypes.Quorum}
	for _, id := range view.Context().NodeIDs() {
		if w, err := view.SignerWeight(id); err != nil || w != 6 {
			require.NoError(t, err)
			continue
		}
		bcr := &certification.BlockCertificationRequest{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}, NodeID: id, InputRecord: &types.InputRecord{
			Version: 1, Epoch: tr.Epoch, RoundNumber: tr.Round, PreviousHash: view.PreviousStateHash(), Hash: bytes.Repeat([]byte{0x81}, 32), BlockHash: bytes.Repeat([]byte{0x82}, 32),
			SummaryValue: []byte{3}, Timestamp: uc.UnicitySeal.Timestamp}}
		require.NoError(t, bcr.Sign(c.f.EVMSigners[id]))
		proof.Requests = append(proof.Requests, bcr)
	}
	require.Len(t, proof.Requests, 1, "the heavy entity alone is a quorum of the weighted request context")
	block := &rctypes.BlockData{Version: 2, Epoch: 2, Round: 7, Anchor: anchor, Payload: &rctypes.Payload{Version: 2, Requests: []*rctypes.IRChangeReq{proof}}}
	parent, err := r.manager.blockStore.Block(anchor.Slot)
	require.NoError(t, err)
	extend := func(v *IRChangeReqVerifier) (*storage.ExecutedBlock, error) {
		return parent.Extend(block, v, r.orchestration, crypto.SHA256, r.manager.log)
	}

	legacy, err := NewIRChangeReqVerifier(r.manager.params, r.manager.blockStore)
	require.NoError(t, err)
	require.Nil(t, legacy.RequestHistory())
	_, err = extend(legacy)
	// "certification request verification failed" is the legacy dispatch's own prefix (IRChangeReqVerifier.VerifyIRChangeReq): the view-aware branch never produces it. The
	// reason behind it differs by state: the live wedge showed the member count of the nil request context, this harness's committed anchor an out-of-date round.
	require.ErrorContains(t, err, "verifying change request: certification request verification failed")

	recovery, err := r.manager.recoveryVerifier(r.manager.blockStore)
	require.NoError(t, err)
	require.Same(t, r.manager.irReqVerifier.RequestHistory(), recovery.RequestHistory())
	executed, err := extend(recovery)
	require.NoError(t, err)
	shard := executed.ShardState.States[types.PartitionShardID{PartitionID: q3fixture.PartitionID, ShardID: types.ShardID{}.Key()}]
	require.Equal(t, proof.Requests[0].InputRecord, shard.IR, "the recovery executes the signed heavy proof")
}
