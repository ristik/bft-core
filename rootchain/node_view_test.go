package rootchain

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	p2peer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/zkverifier"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Collector admission through the resolved request view (Q2-C3), driven through Node.onBlockCertificationRequest with the real
// consensus.RequestViewResolver over a committed activation history and a verified parent, not through the buffer alone.

const (
	fxNetwork = 5
	fxVersion = 7
	fxRootEp  = 3
)

var fxBody = bytes.Repeat([]byte{0xA0}, 32)

// fxHistory is the committed history of one shard: its anchor assignment.
type fxHistory struct{ anchor *storage.RequestActivation }

func (h fxHistory) Chain(types.PartitionID, types.ShardID) ([]*storage.RequestActivation, error) {
	return []*storage.RequestActivation{h.anchor}, nil
}
func (fxHistory) Network() uint64 { return fxNetwork }
func (fxHistory) Version() uint64 { return fxVersion }
func (fxHistory) RootIdentity(uint64) (uint64, []byte, error) {
	return fxRootEp, fxBody, nil
}

// viewCM is the consensus manager a collector talks to when the view-aware branch is selected: its RequestView resolves through
// the real resolver for the next root round, as ConsensusManager.RequestView does, and it records what the node asks of it.
type viewCM struct {
	mu       sync.Mutex
	resolver *consensus.RequestViewResolver
	enabled  bool
	round    uint64 // the current root round
	res      chan *certification.CertificationResponse
	si       *storage.ShardInfo // the committed ShardInfo, which admission must not use
	siCalls  int
	certs    []consensus.IRChangeRequest
	resolved []storage.RequestPurpose
}

func (c *viewCM) ShardInfo(types.PartitionID, types.ShardID) (*storage.ShardInfo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.siCalls++
	return c.si, nil
}
func (c *viewCM) CertificationResult() <-chan *certification.CertificationResponse { return c.res }
func (c *viewCM) Run(context.Context) error                                        { return nil }
func (c *viewCM) RequestCertification(_ context.Context, cr consensus.IRChangeRequest) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certs = append(c.certs, cr)
	return nil
}

func (c *viewCM) RequestView(p types.PartitionID, s types.ShardID) (*storage.RequestRoundView, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.enabled {
		return nil, false, nil
	}
	c.resolved = append(c.resolved, storage.PurposeCollect)
	view, err := c.resolver.ResolveView(p, s, c.round+1, storage.PurposeCollect)
	return view, true, err
}

// weightedPDR is the type-8 configuration of the coupled EVM assignment with its root side (fresh root keys, mirrored weights).
func weightedPDR(t *testing.T, base *types.PartitionDescriptionRecord, infos []*types.NodeInfo) (*types.PartitionDescriptionRecord, *quorumweight.Coupling) {
	t.Helper()
	pdr := *base
	pdr.PartitionTypeID = evmassign.EVMPartitionTypeID
	pdr.Validators = infos
	var root []evmassign.RootMember
	var bind []evmassign.Binding
	for _, v := range infos {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		ver, err := s.Verifier()
		require.NoError(t, err)
		key, err := ver.MarshalPublicKey()
		require.NoError(t, err)
		root = append(root, evmassign.RootMember{NodeID: "root-" + v.NodeID, Key: key, Weight: v.Stake})
		bind = append(bind, evmassign.Binding{RootNodeID: "root-" + v.NodeID, EVMNodeID: v.NodeID})
	}
	return &pdr, &quorumweight.Coupling{RootEpoch: fxRootEp, RootBodyID: fxBody, Root: root, Bindings: bind}
}

type fixture struct {
	t        *testing.T
	nodes    []*testutils.TestNode
	infos    []*types.NodeInfo
	pdr      *types.PartitionDescriptionRecord
	coupling *quorumweight.Coupling // set for a weighted (type-8) assignment
	si       *storage.ShardInfo     // the parent state: committed, verified
	parentID []byte
	cm       *viewCM
	node     *Node
	sent     *[]any
	histErr  error
}

type fxOpts struct {
	weights    []uint64          // nil: unit weights
	params     map[string]string // the PDR's partition parameters
	committed  map[string]string // different parameters on the committed ShardInfo (a stale or forged policy selection)
	shardRound uint64
}

func newFixture(t *testing.T, o fxOpts) *fixture {
	t.Helper()
	nodes, infos := testutils.CreateTestNodes(t, 4)
	// the coupled assignment's validators and root bindings are strictly ordered by node id
	order := make([]int, len(infos))
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return infos[order[a]].NodeID < infos[order[b]].NodeID })
	sortedNodes, sortedInfos := make([]*testutils.TestNode, len(nodes)), make([]*types.NodeInfo, len(infos))
	for i, j := range order {
		sortedNodes[i], sortedInfos[i] = nodes[j], infos[j]
	}
	nodes, infos = sortedNodes, sortedInfos
	for i := range infos {
		infos[i].Stake = 1
		if o.weights != nil {
			infos[i].Stake = o.weights[i]
		}
	}
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: fxNetwork, PartitionID: 1, PartitionTypeID: 1, ShardID: types.ShardID{},
		UnitIDLen: 256, TypeIDLen: 32, T2Timeout: 2500 * time.Millisecond, Epoch: 2, EpochStart: 1, Validators: infos, PartitionParams: o.params}
	f := &fixture{t: t, nodes: nodes, infos: infos, pdr: pdr}
	if o.weights != nil {
		f.pdr, f.coupling = weightedPDR(t, pdr, infos)
	}
	pdr = f.pdr
	f.setParent(o.shardRound, pdr)
	if o.committed != nil || o.params != nil {
		// the committed ShardInfo carries its own (possibly different) proof parameters, on a unit copy
		cp := *f.pdr
		cp.PartitionParams = o.committed
		cp.Validators = nil
		for _, v := range f.pdr.Validators {
			cp.Validators = append(cp.Validators, &types.NodeInfo{NodeID: v.NodeID, SigKey: v.SigKey, Stake: 1})
		}
		si, err := storage.NewShardInfo(&cp, crypto.SHA256)
		require.NoError(t, err)
		si.LastCR = f.si.LastCR
		f.cm.si = si
	}
	return f
}

// setParent builds the verified parent state at the given shard round and the node over it.
func (f *fixture) setParent(shardRound uint64, pdr *types.PartitionDescriptionRecord) {
	f.t.Helper()
	// ShardInfo is unit-only: a weighted configuration is installed on a unit copy and bound to its own hash, as the committed
	// history's parent state is
	unit := *pdr
	unit.Validators = nil
	for _, v := range pdr.Validators {
		unit.Validators = append(unit.Validators, &types.NodeInfo{NodeID: v.NodeID, SigKey: v.SigKey, Stake: 1})
	}
	si, err := storage.NewShardInfo(&unit, crypto.SHA256)
	require.NoError(f.t, err)
	hash, err := pdr.Hash(crypto.SHA256)
	require.NoError(f.t, err)
	si.ShardConfHash = hash
	si.RootHash = bytes.Repeat([]byte{0x5C + byte(shardRound)}, 32)
	si.TR.Round += shardRound
	ir := &types.InputRecord{Version: 1, RoundNumber: si.TR.Round, PreviousHash: []byte{1}, Hash: si.RootHash, BlockHash: []byte{2}, SummaryValue: []byte{3},
		Timestamp: 1000, Epoch: si.TR.Epoch}
	si.LastCR = &certification.CertificationResponse{Partition: 1, Technical: si.TR, UC: types.UnicityCertificate{Version: 1, InputRecord: ir,
		UnicityTreeCertificate: &types.UnicityTreeCertificate{Version: 1, Partition: 1},
		UnicitySeal:            &types.UnicitySeal{Version: 1, NetworkID: fxNetwork, RootChainRoundNumber: 10, Timestamp: 1000, Hash: []byte{4}}}}
	require.NoError(f.t, si.LastCR.SetTechnicalRecord(si.TR))
	require.NoError(f.t, si.LastCR.IsValid(), "premise: the last response is one a rejection can carry")
	f.si, f.parentID = si, bytes.Repeat([]byte{0x9D, byte(shardRound)}, 16)
	var anchor *storage.RequestActivation
	if f.coupling != nil {
		anchor, err = storage.NewIsolatedWeightedRequestAnchor(pdr, crypto.SHA256, f.coupling, fxRootEp, fxBody, fxVersion)
	} else {
		anchor, err = storage.NewRequestAnchor(pdr, crypto.SHA256, fxRootEp, fxBody, fxVersion)
	}
	require.NoError(f.t, err)
	parent := func(types.PartitionID, types.ShardID) (*storage.ShardInfo, []byte, *types.InputRecord, error) {
		if f.histErr != nil {
			return nil, nil, nil, f.histErr
		}
		return f.si, f.parentID, nil, nil
	}
	resolver, err := consensus.NewRequestViewResolver(fxHistory{anchor}, crypto.SHA256, parent, nil)
	require.NoError(f.t, err)
	if f.cm == nil {
		f.cm = &viewCM{resolver: resolver, enabled: true, round: 11, res: make(chan *certification.CertificationResponse), si: si}
		var sent []any
		f.sent = &sent
		net := mockPartitionNet{send: func(_ context.Context, msg any, _ ...p2peer.ID) error {
			f.cm.mu.Lock()
			defer f.cm.mu.Unlock()
			sent = append(sent, msg)
			return nil
		}}
		node, err := New(&network.Peer{}, net, f.cm, testobservability.Default(f.t))
		require.NoError(f.t, err)
		f.node = node
	} else {
		f.cm.mu.Lock()
		f.cm.resolver = resolver
		f.cm.si = si
		f.cm.mu.Unlock()
	}
}

// view is what the collector resolves now.
func (f *fixture) view() *storage.RequestRoundView {
	f.t.Helper()
	v, enabled, err := f.cm.RequestView(1, types.ShardID{})
	require.NoError(f.t, err)
	require.True(f.t, enabled)
	return v
}

// request is a signed certification request of node i for the view's expected round, epoch, state and timestamp.
func (f *fixture) request(i int, v *storage.RequestRoundView, group byte, mut func(*certification.BlockCertificationRequest)) *certification.BlockCertificationRequest {
	f.t.Helper()
	tr := v.ExpectedTR()
	req := &certification.BlockCertificationRequest{PartitionID: 1, ShardID: types.ShardID{}, NodeID: f.infos[i].NodeID, InputRecord: &types.InputRecord{
		Version: 1, RoundNumber: tr.Round, Epoch: tr.Epoch, PreviousHash: v.PreviousStateHash(), Hash: []byte{group}, BlockHash: []byte{8}, SummaryValue: []byte{3},
		Timestamp: 1000}}
	if mut != nil {
		mut(req)
	}
	require.NoError(f.t, req.Sign(f.nodes[i].Signer))
	return req
}

func (f *fixture) certs() []consensus.IRChangeRequest {
	f.cm.mu.Lock()
	defer f.cm.mu.Unlock()
	return append([]consensus.IRChangeRequest(nil), f.cm.certs...)
}

func (f *fixture) sentCount() int {
	f.cm.mu.Lock()
	defer f.cm.mu.Unlock()
	return len(*f.sent)
}

func (f *fixture) submit(req *certification.BlockCertificationRequest) error {
	return f.node.onBlockCertificationRequest(context.Background(), req)
}

// counted is how many requests the buffer holds for the shard.
func (f *fixture) counted() int {
	f.node.incomingRequests.mu.RLock()
	defer f.node.incomingRequests.mu.RUnlock()
	if rs, ok := f.node.incomingRequests.store[partitionShard{partition: 1, shard: types.ShardID{}.Key()}]; ok {
		return len(rs.nodeRequest)
	}
	return 0
}

// status is the buffer's status under the view the collector resolves now.
func (f *fixture) status() QuorumStatus {
	return f.node.incomingRequests.IsConsensusReceived(1, types.ShardID{}, f.view())
}

// The same requests reach a quorum or not by the resolved view's weights, in the node, end to end. Under the mirrored (6,1,1,1)
// assignment the EVM quorum is 5 of 9: the heavy node alone is a quorum and three light nodes are not. Under the unit assignment
// of the same four keys the quorum is 3 of 4, so the heavy node's request alone is not.
func TestCollectorCountsWithTheResolvedViewWeights(t *testing.T) {
	t.Run("weighted (6,1,1,1): the heavy node alone is a quorum", func(t *testing.T) {
		f := newFixture(t, fxOpts{weights: []uint64{6, 1, 1, 1}})
		v := f.view()
		require.EqualValues(t, 9, v.TotalWeight())
		require.EqualValues(t, 5, v.Threshold())
		require.NoError(t, f.submit(f.request(0, v, 9, nil)))
		certs := f.certs()
		require.Len(t, certs, 1, "weight 6 of 9 asks for certification")
		require.Equal(t, consensus.Quorum, certs[0].Reason)
		require.Len(t, certs[0].Requests, 1)
		// the proof the node hands on is what independent verification accepts under a view resolved for certification
		cv, err := f.cm.resolver.ResolveView(1, types.ShardID{}, 12, storage.PurposeCertify)
		require.NoError(t, err)
		_, err = cv.VerifyIRChangeReq(&rctypes.IRChangeReq{Partition: 1, Shard: types.ShardID{}, CertReason: rctypes.Quorum, Requests: certs[0].Requests}, 4)
		require.NoError(t, err)
	})
	t.Run("weighted: three light nodes are not a quorum, however many agree", func(t *testing.T) {
		f := newFixture(t, fxOpts{weights: []uint64{6, 1, 1, 1}})
		v := f.view()
		for i := 1; i <= 3; i++ {
			require.NoError(t, f.submit(f.request(i, v, 9, nil)))
		}
		require.Empty(t, f.certs(), "3 of 9 is below the threshold 5")
		require.Equal(t, QuorumInProgress, f.status(), "the heavy node, unseen, could still complete it")
		require.Equal(t, 3, f.counted())
		require.NoError(t, f.submit(f.request(0, v, 9, nil)))
		require.Len(t, f.certs(), 1, "with the heavy node: 9 of 9")
	})
	t.Run("weighted: the heavy node against the lights makes no group a quorum of the rest", func(t *testing.T) {
		f := newFixture(t, fxOpts{weights: []uint64{6, 1, 1, 1}})
		v := f.view()
		require.NoError(t, f.submit(f.request(1, v, 20, nil)))
		require.NoError(t, f.submit(f.request(2, v, 21, nil)))
		require.NoError(t, f.submit(f.request(3, v, 22, nil)))
		require.Empty(t, f.certs(), "three results of weight 1: the unseen heavy node could still make any of them 7")
		require.NoError(t, f.submit(f.request(0, v, 23, nil)))
		certs := f.certs()
		require.Len(t, certs, 1)
		require.Equal(t, consensus.Quorum, certs[0].Reason, "the heavy node's own result alone is 6 of 9")
	})
	t.Run("unit: the heavy node's request alone is not a quorum of four", func(t *testing.T) {
		f := newFixture(t, fxOpts{})
		v := f.view()
		require.EqualValues(t, 4, v.TotalWeight())
		require.EqualValues(t, 3, v.Threshold())
		require.NoError(t, f.submit(f.request(0, v, 9, nil)))
		require.Empty(t, f.certs(), "1 of 4 under the unit assignment")
		require.NoError(t, f.submit(f.request(1, v, 9, nil)))
		require.Empty(t, f.certs(), "2 of 4")
		require.NoError(t, f.submit(f.request(2, v, 9, nil)))
		require.Len(t, f.certs(), 1, "3 of 4 is the unit quorum")
	})
	t.Run("unit: three different results out of four members make a quorum impossible", func(t *testing.T) {
		f := newFixture(t, fxOpts{})
		v := f.view()
		for i := 0; i < 3; i++ {
			require.NoError(t, f.submit(f.request(i, v, byte(20+i), nil)))
		}
		certs := f.certs()
		require.Len(t, certs, 1)
		require.Equal(t, consensus.QuorumNotPossible, certs[0].Reason)
	})
}

// Admission uses the view: the committed ShardInfo is read for nothing but the last response a rejection carries.
func TestCollectorAdmissionDoesNotUseTheCommittedShardInfo(t *testing.T) {
	f := newFixture(t, fxOpts{weights: []uint64{6, 1, 1, 1}})
	v := f.view()
	require.NoError(t, f.submit(f.request(1, v, 9, nil)))
	require.NoError(t, f.submit(f.request(0, v, 9, nil)))
	require.Len(t, f.certs(), 1)
	require.Zero(t, f.cm.siCalls, "an admitted request never touches the committed ShardInfo")
	require.Equal(t, []storage.RequestPurpose{storage.PurposeCollect}, f.cm.resolved[:1], "it is resolved for collection")
}

// A stale view or request is refused with the stale identity, the node is told why, and nothing was counted.
func TestCollectorRefusesStaleRequests(t *testing.T) {
	t.Run("a request for an older shard round", func(t *testing.T) {
		f := newFixture(t, fxOpts{weights: []uint64{6, 1, 1, 1}})
		v := f.view()
		old := f.request(0, v, 9, func(r *certification.BlockCertificationRequest) { r.InputRecord.RoundNumber-- })
		err := f.submit(old)
		require.ErrorIs(t, err, storage.ErrStaleRequestContext)
		require.ErrorIs(t, err, quorumweight.ErrRequestContext)
		require.ErrorIs(t, err, rctypes.ErrInvalidRequest)
		require.Equal(t, 1, f.sentCount(), "the node is sent the last certification response with the refusal")
		require.Zero(t, f.counted(), "nothing was counted")
		require.NoError(t, f.submit(f.request(1, v, 9, nil)), "the refusal left the buffer usable")
		require.Equal(t, 1, f.counted())
	})
	t.Run("a request for another previous state", func(t *testing.T) {
		f := newFixture(t, fxOpts{})
		v := f.view()
		err := f.submit(f.request(0, v, 9, func(r *certification.BlockCertificationRequest) {
			r.InputRecord.PreviousHash = bytes.Repeat([]byte{7}, 32)
		}))
		require.ErrorIs(t, err, storage.ErrStaleRequestContext)
		require.Empty(t, f.certs())
	})
	t.Run("a request for another timestamp", func(t *testing.T) {
		f := newFixture(t, fxOpts{})
		v := f.view()
		err := f.submit(f.request(0, v, 9, func(r *certification.BlockCertificationRequest) { r.InputRecord.Timestamp++ }))
		require.ErrorIs(t, err, storage.ErrStaleRequestContext)
	})
	t.Run("the parent advances: counted requests are retired, never retallied under the new view", func(t *testing.T) {
		f := newFixture(t, fxOpts{}) // unit: quorum 3 of 4
		v := f.view()
		require.NoError(t, f.submit(f.request(0, v, 9, nil)))
		require.NoError(t, f.submit(f.request(1, v, 9, nil)))
		require.Equal(t, 2, f.counted())
		f.setParent(1, f.pdr) // the shard certified a round: its anchor, round and previous state moved on
		v2 := f.view()
		require.NotEqual(t, v.ViewKey(), v2.ViewKey())
		// one request for the new round: were the two old signatures retallied it would be a quorum of three
		require.NoError(t, f.submit(f.request(2, v2, 9, nil)))
		require.Empty(t, f.certs(), "the old signatures do not count under the new view")
		require.Equal(t, 1, f.counted())
		// and a request for the old round, replayed, is stale
		require.ErrorIs(t, f.submit(f.request(3, v, 9, nil)), storage.ErrStaleRequestContext)
		require.NoError(t, f.submit(f.request(0, v2, 9, nil)))
		require.NoError(t, f.submit(f.request(1, v2, 9, nil)))
		require.Len(t, f.certs(), 1, "three requests of the new view are the quorum")
	})
	t.Run("an unknown signer and a bad signature keep their own identities", func(t *testing.T) {
		f := newFixture(t, fxOpts{})
		v := f.view()
		req := f.request(0, v, 9, nil)
		req.NodeID = "not-a-member"
		require.ErrorIs(t, f.submit(req), storage.ErrNodeNotInTrustBase)
		bad := f.request(0, v, 9, nil)
		bad.InputRecord.Hash = []byte{10} // signed over another hash
		require.ErrorIs(t, f.submit(bad), quorumweight.ErrInvalidSignature)
		require.Empty(t, f.certs())
	})
}

// No view, no admission: a resolution failure is a refusal that wraps the assignment-history identity; the committed
// ShardInfo is not consulted instead.
func TestCollectorRefusesWhenTheViewCannotBeResolved(t *testing.T) {
	f := newFixture(t, fxOpts{})
	v := f.view()
	req := f.request(0, v, 9, nil)
	f.histErr = errors.New("parent state is unavailable")
	err := f.submit(req)
	require.ErrorIs(t, err, storage.ErrAssignmentHistory)
	require.Empty(t, f.certs())
	require.Zero(t, f.cm.siCalls, "nothing was answered from the committed ShardInfo")
	require.Equal(t, 0, f.sentCount())
	f.histErr = nil
	require.NoError(t, f.submit(req), "acceptance control: the same request with the view resolvable")
}

// The proof is dispatched from the view's PDR parameters and expected shard epoch, not from the committed ShardInfo.
func TestCollectorDispatchesTheProofFromTheView(t *testing.T) {
	rsmt := map[string]string{"proof_type": "aggregator_rsmt_v1"}
	t.Run("the view's parameters require a proof the committed ShardInfo does not", func(t *testing.T) {
		f := newFixture(t, fxOpts{params: rsmt, committed: map[string]string{}})
		v := f.view()
		req := f.request(0, v, 9, nil) // no proof attached
		err := f.submit(req)
		require.ErrorIs(t, err, zkverifier.ErrInvalidProofFormat)
		require.ErrorContains(t, err, "ZK proof verification failed", "the view's policy decides: a missing proof is refused")
		require.Equal(t, 1, f.sentCount(), "with CertStatusProofInvalid")
		require.Empty(t, f.certs())
		require.Zero(t, f.counted(), "a refused proof counts for nothing")
	})
	t.Run("the committed ShardInfo's parameters cannot require a proof the view does not", func(t *testing.T) {
		f := newFixture(t, fxOpts{committed: rsmt})
		v := f.view()
		require.NoError(t, f.submit(f.request(0, v, 9, nil)), "the view has no proof policy: forged or stale committed parameters are not read")
	})
	t.Run("a proof of another shard epoch is refused with the stale identity", func(t *testing.T) {
		f := newFixture(t, fxOpts{params: rsmt, committed: rsmt})
		v := f.view()
		req := f.request(0, v, 9, func(r *certification.BlockCertificationRequest) { r.InputRecord.Epoch++ })
		err := f.submit(req)
		require.ErrorIs(t, err, storage.ErrStaleRequestContext)
		require.ErrorIs(t, err, quorumweight.ErrRequestContext)
		require.Empty(t, f.certs())
		// the dispatch itself refuses a proof whose epoch is not the view's, whatever admitted the request before it
		err = f.node.verifyZKProof(context.Background(), req, zkTarget{partition: 1, shard: types.ShardID{}, epoch: v.ExpectedTR().Epoch, params: rsmt, viewed: true})
		require.ErrorIs(t, err, storage.ErrStaleRequestContext)
		legacy := f.node.verifyZKProof(context.Background(), req, zkTarget{partition: 1, shard: types.ShardID{}, epoch: v.ExpectedTR().Epoch, params: rsmt})
		require.NotErrorIs(t, legacy, storage.ErrStaleRequestContext, "the legacy dispatch is unchanged: it never compared the request epoch")
	})
}

// Legacy dispatch is untouched: a manager without the view-aware branch, or one that reports it disabled, is admitted, proven and
// counted under the committed ShardInfo exactly as before.
func TestCollectorKeepsTheLegacyDispatchWithoutViews(t *testing.T) {
	f := newFixture(t, fxOpts{})
	v := f.view()
	f.cm.enabled = false
	f.cm.si.LastCR = f.si.LastCR
	// the committed ShardInfo admits what it always did
	req := f.request(0, v, 9, nil)
	require.NoError(t, f.cm.si.ValidRequest(req), "premise: the committed ShardInfo accepts this request")
	require.NoError(t, f.submit(req))
	require.Positive(t, f.cm.siCalls, "the legacy path reads the committed ShardInfo")
	require.Equal(t, QuorumInProgress, f.node.incomingRequests.IsConsensusReceived(1, types.ShardID{}, f.cm.si), "counted under it")
	require.NoError(t, f.submit(f.request(1, v, 9, nil)))
	require.NoError(t, f.submit(f.request(2, v, 9, nil)))
	certs := f.certs()
	require.Len(t, certs, 1, "unit quorum of 3 of 4")
	require.Equal(t, consensus.Quorum, certs[0].Reason)

	// a ConsensusManager without RequestView at all (the existing mocks) is the same dispatch
	plain := mockConsensusManager{shardInfo: func(types.PartitionID, types.ShardID) (*storage.ShardInfo, error) { return f.cm.si, nil },
		requestCert: func(context.Context, consensus.IRChangeRequest) error { return nil }}
	_, isSource := any(plain).(RequestViewSource)
	require.False(t, isSource)
}

// A view resolved before its activation round collects only: requests are admitted and counted, but a decisive outcome is
// not certified, and the shard's buffer is cleared so that the requests sent again from the activation round on are counted
// afresh under the view then in force.
type collectionOnly struct{ *storage.RequestRoundView }

func (collectionOnly) CollectionOnly() bool { return true }

func TestCollectionOnlyViewNeverCertifies(t *testing.T) {
	f := newFixture(t, fxOpts{weights: []uint64{6, 1, 1, 1}})
	v := f.view()
	co := collectionOnly{v}
	ctx := context.Background()
	require.NoError(t, f.node.collectUnderView(ctx, f.request(1, v, 9, nil), co))
	require.Equal(t, 1, f.counted(), "requests are counted under a collection-only view")
	require.NoError(t, f.node.collectUnderView(ctx, f.request(0, v, 9, nil), co), "the quorum is reached")
	require.Empty(t, f.certs(), "but a collection-only view is never a certification capability")
	require.Zero(t, f.counted(), "the decided outcome was not kept")
	// from the activation round on the same requests are counted and certified
	require.NoError(t, f.submit(f.request(1, v, 9, nil)))
	require.NoError(t, f.submit(f.request(0, v, 9, nil)))
	require.Len(t, f.certs(), 1)
}
