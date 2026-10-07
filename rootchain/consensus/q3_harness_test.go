package consensus

import (
	"context"
	"crypto"
	"crypto/sha256"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

// toggledConsumer is a participant whose wiring to the runtime can be switched off: an authority that was not given the guarded
// lookup, say. It is a Consumer for the install journal and nothing else.
type toggledConsumer struct {
	inner q3active.Consumer
	off   atomic.Bool
}

func (c *toggledConsumer) BoundTo(a any) bool { return !c.off.Load() && c.inner.BoundTo(a) }

// q3Replica is one root validator with real durable stores, a verified Q3 history and an install journal. open builds it from what
// the previous incarnation left on disk, so close then open is a process restart.
type q3Replica struct {
	t    *testing.T
	f    *q3fixture.Fixture
	node *testutils.TestNode
	dir  string

	// the stores that survive a restart: bolt files in dir, and key-value databases that stand for durable ones
	trustDB, journalDB, historyDB *memorydb.MemoryDB

	db            *storage.BoltDB
	orchestration *partitions.Orchestration
	net           *testnetwork.MockNet
	trust         *tbstore.TrustBaseStore
	history       *trusthistorystore.Store
	manager       *ConsensusManager
	rt            *q3active.Runtime
	shard         *q3active.Guarded
	authority     *toggledConsumer
	opened        int
	// incumbent, when set, replaces the fixture's committee as the shard's recorded genesis baseline: the authenticated incumbent the
	// candidate's recovery authorization is compared with
	incumbent []evmassign.Identity

	// link, when set, is the manager's network in place of the mock one (a live cluster over skewedNet); durable opens the bolt files
	// with fsync on, the stores a restart claims to read back
	link    RootNet
	durable bool
	// weightedLeader activates the weighted leader policy (#403) for epoch 2 at every start that finds the epoch installed: the policy is
	// the operator's startup configuration, not durable state
	weightedLeader bool
}

func newQ3Replica(t *testing.T, f *q3fixture.Fixture, node *testutils.TestNode) *q3Replica {
	t.Helper()
	return &q3Replica{t: t, f: f, node: node, dir: t.TempDir(), trustDB: memorydb.New(), journalDB: memorydb.New(), historyDB: memorydb.New()}
}

func (r *q3Replica) id() peer.ID { return r.node.PeerConf.ID }

// open starts the process. withQ3 false is a binary that does not know the Q3 history: it gets the manager options of before.
func (r *q3Replica) open(withQ3 bool) error {
	t := r.t
	t.Helper()
	obs := testobservability.Default(t)
	var dbOpts []storage.BoltOption
	if !r.durable {
		dbOpts = append(dbOpts, storage.WithNoSync())
	}
	db, err := storage.NewBoltStorage(filepath.Join(r.dir, "root.db"), dbOpts...)
	require.NoError(t, err)
	r.db = &db
	var orchOpts []partitions.StoreOption
	if !r.durable {
		orchOpts = append(orchOpts, partitions.WithNoSync())
	}
	orchestration, err := partitions.NewOrchestration(5, filepath.Join(r.dir, "orchestration.db"), obs.Logger(), orchOpts...)
	require.NoError(t, err)
	r.orchestration = orchestration
	require.NoError(t, orchestration.AddShardConfig(r.f.ShardConf))
	// the shard's authenticated genesis baseline: the committee the first handoff's recovery authorization names
	baseline := r.f.Incumbent
	if r.incumbent != nil {
		baseline = r.incumbent
	}
	if len(baseline) > 0 { // only a coupled fixture has a baseline; a root-only handoff keeps none
		require.NoError(t, orchestration.SetGenesisIdentities(r.f.ShardConf.PartitionID, r.f.ShardConf.ShardID, baseline))
	}
	trust, err := tbstore.NewTrustBaseStore(r.trustDB, obs.Logger())
	require.NoError(t, err)
	if _, err := trust.GetByEpoch(1); err != nil {
		require.NoError(t, trust.Store(r.f.Old))
	}
	r.trust = trust
	if r.weightedLeader {
		if _, err := trust.GetByEpoch(2); err == nil {
			require.NoError(t, trust.ActivateLeaderPolicy(2, tbstore.LeaderPolicyWeightedV1))
		}
	}
	historyID := sha256.Sum256([]byte("q3-activation-integration"))
	history, err := trusthistorystore.Open(context.Background(), r.historyDB, r.f.Old, historyID, trustactivation.Verifier{})
	require.NoError(t, err)
	r.history = history
	r.net = testnetwork.NewRootMockNetwork()
	rt, err := q3active.New(q3active.Config{DB: r.journalDB, Genesis: r.f.Old})
	require.NoError(t, err)
	r.rt = rt
	params := *NewConsensusParams()
	params.NetworkProfileVersion = storage.ProfileHandoff
	opts := []Option{WithConsensusParams(params), WithRecoveryProfile2(history)}
	if withQ3 {
		require.NoError(t, trust.BindSigningAuthority(rt))
		opts = append(opts, WithQ3(rt))
	}
	var rootNet RootNet = r.net
	if r.link != nil {
		rootNet = r.link
	}
	manager, err := NewConsensusManager(r.id(), trust, orchestration, rootNet, r.node.Signer, db, obs, opts...)
	if err != nil {
		r.release()
		return err
	}
	r.manager = manager
	if r.opened == 0 {
		// the first start holds the old epoch's committed checkpoint, as the stopped old committee leaves it
		manager.blockStore, err = storage.NewFromState(crypto.SHA256, r.f.Snapshot, db, orchestration, obs.Logger(), storage.ProfileHandoff)
		require.NoError(t, err)
	}
	r.opened++
	r.shard = rt.Trust(nil)
	r.authority = &toggledConsumer{inner: rt.Trust(nil)}
	if withQ3 {
		require.NoError(t, rt.Attach(q3active.Participants{Root: manager, Safety: manager.safety, Shard: r.shard, Authority: r.authority}))
	}
	return nil
}

func (r *q3Replica) mustOpen(withQ3 bool) {
	r.t.Helper()
	require.NoError(r.t, r.open(withQ3))
}

func (r *q3Replica) release() {
	if r.manager != nil {
		r.manager.pacemaker.Stop()
		r.manager = nil
	}
	if r.db != nil {
		_ = r.db.Close()
		r.db = nil
	}
	if r.orchestration != nil {
		_ = r.orchestration.Close()
		r.orchestration = nil
	}
}

// close is the crash: whatever was not persisted is gone.
func (r *q3Replica) close() { r.release() }

func (r *q3Replica) bundle() q3active.Bundle {
	return q3active.Bundle{Envelope: r.f.EnvelopeBytes, Snapshot: r.f.Snapshot, Candidate: r.f.Candidate}
}

// activate runs the whole activation and starts the successor's consensus at the anchor.
func (r *q3Replica) activate() {
	t := r.t
	t.Helper()
	ctx := context.Background()
	require.NoError(t, r.rt.Recover(ctx))
	require.NoError(t, r.rt.Activate(ctx, r.bundle()))
	r.startConsensus()
}

func (r *q3Replica) startConsensus() {
	require.NotNil(r.t, r.manager.epochAnchor)
	r.manager.pacemaker.Reset(context.Background(), r.manager.epochAnchor.Slot, nil, nil)
}

// q3Cluster is the four successor validators, in the fixture's member order: index 0 is the heavy one.
type q3Cluster struct {
	t        *testing.T
	f        *q3fixture.Fixture
	replicas []*q3Replica
	proposal *abdrc.ProposalMsg // the first successor proposal
}

func newQ3Cluster(t *testing.T, o q3fixture.Options) *q3Cluster {
	t.Helper()
	f := q3fixture.New(t, o)
	c := &q3Cluster{t: t, f: f}
	for _, n := range f.NewNodes {
		r := newQ3Replica(t, f, n)
		r.mustOpen(true)
		t.Cleanup(r.close)
		c.replicas = append(c.replicas, r)
	}
	return c
}

func (c *q3Cluster) byID(id peer.ID) *q3Replica {
	for _, r := range c.replicas {
		if r.id() == id {
			return r
		}
	}
	c.t.Fatalf("no replica %s", id)
	return nil
}

func (c *q3Cluster) activateAll() *rctypes.EpochAnchor {
	c.t.Helper()
	for _, r := range c.replicas {
		r.activate()
	}
	anchor := c.replicas[0].manager.epochAnchor
	for _, r := range c.replicas {
		require.Equal(c.t, anchor, r.manager.epochAnchor)
	}
	return anchor
}

var _ = types.NetworkID(0)
