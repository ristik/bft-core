package consensus

import (
	"context"
	"crypto"
	"crypto/sha256"
	"path/filepath"
	"sort"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/trustactivation"
	"github.com/unicitynetwork/bft-core/trusthistorystore"
)

// restartedRoot is a root that was stopped before it installed the successor epoch (its store holds the old epoch's head) and is brought
// up the way the lane brings it up after a handoff: the manager is built, then the verified epoch genesis is installed. It is the
// same node as `source`: same identity, same signer.
func restartedRoot(t *testing.T, source *anchorReplica) *ConsensusManager {
	t.Helper()
	old, err := source.store.GetByEpoch(1)
	require.NoError(t, err)
	trust, err := tbstore.NewTrustBaseStore(memorydb.New(), testobservability.Default(t).Logger())
	require.NoError(t, err)
	require.NoError(t, trust.Store(old))
	obs := testobservability.Default(t)
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "restarted.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	bodyID := source.body.Identity()
	require.NoError(t, db.StoreHandoffBody(bodyID[:], source.body.Encode()))
	identity := sha256.Sum256([]byte("root-recovery-epoch-test"))
	history, err := trusthistorystore.Open(context.Background(), memorydb.New(), old, identity, trustactivation.Verifier{Signing: trust.SigningConfig})
	require.NoError(t, err)
	params := *NewConsensusParams()
	params.NetworkProfileVersion = storage.ProfileHandoff
	cm, err := NewConsensusManager(source.manager.id, trust, source.manager.orchestration, testnetwork.NewRootMockNetwork(),
		source.manager.safety.signer, db, obs, WithConsensusParams(params), WithRecoveryProfile2(history))
	require.NoError(t, err)
	cm.blockStore, err = storage.NewFromState(crypto.SHA256, source.oldHead, db, source.manager.orchestration, obs.Logger(), storage.ProfileHandoff)
	require.NoError(t, err)
	_, err = cm.InstallEpochGenesis(source.proof, source.oldHead, source.body)
	require.NoError(t, err)
	t.Cleanup(cm.pacemaker.Stop)
	return cm
}

// anchorCluster drives the four replicas of newAnchorReplicas through ordinary rounds past the epoch anchor: every replica processes each
// proposal, the next leader collects the votes and proposes. proposals[i] is the proposal of round anchor.Slot+1+i.
type anchorCluster struct {
	t         *testing.T
	replicas  map[peer.ID]*anchorReplica
	anchor    *rctypes.EpochAnchor
	proposals []*abdrc.ProposalMsg
}

func newAnchorCluster(t *testing.T) *anchorCluster {
	replicas, anchor, _ := newAnchorReplicas(t, 4)
	return startAnchorCluster(t, replicas, anchor)
}

// startAnchorCluster opens the first round of the new epoch on replicas built by newAnchorReplicas or newWeightedAnchorReplicas.
func startAnchorCluster(t *testing.T, replicas map[peer.ID]*anchorReplica, anchor *rctypes.EpochAnchor) *anchorCluster {
	c := &anchorCluster{t: t, replicas: replicas, anchor: anchor}
	ctx := context.Background()
	// The anchor round was committed by the old epoch; the first round of the new one starts from it.
	firstReplica(replicas).manager.processQC(ctx, &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{Epoch: 1, RoundNumber: anchor.Slot + 1}})
	leader, err := firstReplica(replicas).manager.leaderSelector.GetLeaderForRound(anchor.Slot + 1)
	require.NoError(t, err)
	replicas[leader].manager.processNewRoundEvent(ctx)
	c.proposals = append(c.proposals, replicas[leader].net.WaitRootProposal(t))
	return c
}

// advance delivers the latest proposal to every replica, then lets the next leader collect the votes and propose again.
func (c *anchorCluster) advance() *abdrc.ProposalMsg {
	c.t.Helper()
	ctx := context.Background()
	last := c.proposals[len(c.proposals)-1]
	for _, replica := range c.replicas {
		replica.net.ResetSentMessages(network.ProtocolRootVote)
		require.NoError(c.t, replica.manager.onProposalMsg(ctx, last))
	}
	next, err := firstReplica(c.replicas).manager.leaderSelector.GetLeaderForRound(last.Block.Round + 1)
	require.NoError(c.t, err)
	c.replicas[next].manager.pacemaker.setState(ctx, pmsRoundMatured)
	for _, replica := range c.replicas {
		if c.replicas[next].manager.pacemaker.GetCurrentRound() > last.Block.Round {
			break
		}
		votes := replica.net.SentMessages(network.ProtocolRootVote)
		require.Len(c.t, votes, 1)
		require.NoError(c.t, c.replicas[next].manager.onVoteMsg(ctx, votes[0].Message.(*abdrc.VoteMsg)))
	}
	proposal := c.replicas[next].net.WaitRootProposal(c.t)
	c.proposals = append(c.proposals, proposal)
	return proposal
}

// state is the current StateMsg of the replica that led the latest round.
func (c *anchorCluster) state() *abdrc.StateMsg {
	c.t.Helper()
	last := c.proposals[len(c.proposals)-1]
	leader, err := firstReplica(c.replicas).manager.leaderSelector.GetLeaderForRound(last.Block.Round)
	require.NoError(c.t, err)
	state, err := c.replicas[leader].manager.blockStore.GetState()
	require.NoError(c.t, err)
	return state
}

// pastTheFirstSuccessor advances until the committed head is neither the anchor nor its first successor: the first state a restarting root
// can recover from, and one that still contains QCs that commit nothing.
func (c *anchorCluster) pastTheFirstSuccessor() *abdrc.StateMsg {
	c.t.Helper()
	for i := 0; i < 8; i++ {
		if st := c.state(); st.CommittedHead.Anchor == nil && st.CommittedHead.Block.Anchor == nil {
			return st
		}
		c.advance()
	}
	c.t.Fatal("the committed head never moved past the first successor of the anchor")
	return nil
}

// commitsNothing is the commit info of a QC that commits nothing (SafetyModule.constructCommitInfo).
func commitsNothing(qc *rctypes.QuorumCert) bool {
	return qc != nil && qc.LedgerCommitInfo != nil && qc.LedgerCommitInfo.Epoch == 0 &&
		qc.LedgerCommitInfo.RootChainRoundNumber == 0 && len(qc.LedgerCommitInfo.Hash) == 0
}

func hasQCThatCommitsNothing(state *abdrc.StateMsg) bool {
	if commitsNothing(state.CommittedHead.Block.Qc) || commitsNothing(state.CommittedHead.Qc) {
		return true
	}
	for _, block := range state.Pending {
		if commitsNothing(block.Qc) {
			return true
		}
	}
	return false
}

func recoverTo(t *testing.T, cm *ConsensusManager, state *abdrc.StateMsg) error {
	t.Helper()
	// The round the root recovers to is the one its peers are at; a malformed state is recovered "to" the last round it names.
	var to uint64 = 1
	if state.CommittedHead != nil && state.CommittedHead.Block != nil {
		to = state.CommittedHead.Block.Round
	}
	for _, b := range state.Pending {
		if b != nil && b.Round > to {
			to = b.Round
		}
	}
	_, err := cm.recovery.Set(&rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: to + 1, ParentRoundNumber: to, Epoch: cm.trustBase.Load().GetEpoch()}})
	require.NoError(t, err)
	return cm.onStateResponse(context.Background(), state)
}

// A root restarted into the new epoch while its peers are already in it recovers from a peer's state, though that state contains QCs that
// commit nothing (the first QCs after the anchor, and every QC after a timed-out round, such as the rounds the not yet recovered root
// leads). Those QCs used to be refused as "crossing the epoch" because their empty commit info has epoch 0, so the root stayed stuck while
// each round it led cost a timeout (#366). All four roots are restarted in order; every one rejoins and then votes on the next proposal
// like the rest of the cluster.
func TestRolledRootsRejoinFromStatesWithQCsThatCommitNothing(t *testing.T) {
	c := newAnchorCluster(t)
	// While the committed head is the anchor itself recovery works as before (an anchor head). The first block after the anchor carries the
	// anchor instead of a QC; recovering from it is a typed wait, and nothing changes.
	wait := restartedRoot(t, firstReplica(c.replicas))
	before := wait.blockStore.RootAnchor()
	sawFirstSuccessor := false
	for i := 0; i < 6 && !(c.state().CommittedHead.Anchor == nil && c.state().CommittedHead.Block.Anchor == nil); i++ {
		if state := c.state(); state.CommittedHead.Anchor == nil && state.CommittedHead.Block.Anchor != nil && state.CommittedHead.Block.Qc == nil {
			sawFirstSuccessor = true
			err := recoverTo(t, wait, state)
			require.ErrorIs(t, err, abdrc.ErrRecoveryEpoch, "a head that is the first successor of the anchor is a wait")
			require.True(t, wait.recovery.InRecovery())
			require.Equal(t, before, wait.blockStore.RootAnchor())
		}
		c.advance()
	}
	require.True(t, sawFirstSuccessor, "premise: the cluster passed through a head that is the first successor of the anchor")
	state := c.state()
	require.True(t, hasQCThatCommitsNothing(state), "premise: the state a restarting root receives right after the anchor contains a QC that commits nothing")

	ids := make([]string, 0, len(c.replicas))
	byID := make(map[string]*anchorReplica, len(c.replicas))
	for id, replica := range c.replicas {
		ids = append(ids, id.String())
		byID[id.String()] = replica
	}
	sort.Strings(ids) // the order of the restarts: every root exactly once
	require.Len(t, ids, 4)
	for _, id := range ids {
		source := byID[id]
		root := restartedRoot(t, source)
		err := recoverTo(t, root, state)
		require.NoError(t, err, "root %s must recover from a state that contains a QC that commits nothing", id)
		require.False(t, root.recovery.InRecovery(), "root %s", id)
		adopted, err := root.blockStore.GetState()
		require.NoError(t, err)
		require.Equal(t, state.CommittedHead.Block.Round, adopted.CommittedHead.Block.Round, "root %s adopted the peers' committed head", id)
		require.Equal(t, len(state.Pending), len(adopted.Pending), "root %s adopted the peers' pending blocks", id)
		last := state.Pending[len(state.Pending)-1].Round
		require.GreaterOrEqual(t, root.pacemaker.GetCurrentRound(), last, "root %s is at the cluster's round, not stuck behind it", id)
	}
}

// commitsNothingInNextEpoch is a QC of the state's own shape that commits nothing (the empty seal, as taken from a QC of the state that does) but
// votes in the next epoch, its vote hash kept consistent. It goes into a slot that the epoch rule inspects BEFORE any signature is verified (the head
// block's own QC is refused earlier, as an inconsistent block, and so cannot test the rule): refusing it with the typed epoch error is the epoch rule,
// whereas a rule that waived the vote epoch for the empty seal would let it through to the signature check and fail there with another error.
func commitsNothingInNextEpoch(t *testing.T, s *abdrc.StateMsg) *rctypes.QuorumCert {
	t.Helper()
	var src *rctypes.QuorumCert
	for _, qc := range append([]*rctypes.QuorumCert{s.CommittedHead.Block.Qc, s.CommittedHead.Qc, s.CommittedHead.CommitQc}, pendingQCs(s)...) {
		if commitsNothing(qc) {
			src = qc
			break
		}
	}
	require.NotNil(t, src, "premise: a QC of the state commits nothing, so this case would not test what it names")
	info := *src.VoteInfo
	info.Epoch++
	h, err := info.Hash(crypto.SHA256)
	require.NoError(t, err)
	seal := *src.LedgerCommitInfo
	seal.PreviousHash = h
	qc := *src
	qc.VoteInfo, qc.LedgerCommitInfo = &info, &seal
	return &qc
}

func pendingQCs(s *abdrc.StateMsg) []*rctypes.QuorumCert {
	var qcs []*rctypes.QuorumCert
	for _, b := range s.Pending {
		qcs = append(qcs, b.Qc)
	}
	return qcs
}

// What recovery still refuses, with a typed error and without changing the store: a state of another epoch, and a state whose commit info
// names another epoch's block.
func TestRecoveryStillRefusesStateOfAnotherEpochWithTypedErrors(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	require.True(t, hasQCThatCommitsNothing(state), "premise: the state contains a QC that commits nothing")
	for name, mutate := range map[string]func(*abdrc.StateMsg){
		"a head QC that commits nothing but votes in another epoch":        func(s *abdrc.StateMsg) { s.CommittedHead.Qc = commitsNothingInNextEpoch(t, s) },
		"a head commit QC that commits nothing but votes in another epoch": func(s *abdrc.StateMsg) { s.CommittedHead.CommitQc = commitsNothingInNextEpoch(t, s) },
		"a pending QC that commits nothing but votes in another epoch":     func(s *abdrc.StateMsg) { s.Pending[0].Qc = commitsNothingInNextEpoch(t, s) },
		"a block of another epoch in the pending suffix":                   func(s *abdrc.StateMsg) { s.Pending[len(s.Pending)-1].Epoch++ },
		"a head block of another epoch":                                    func(s *abdrc.StateMsg) { s.CommittedHead.Block.Epoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			root := restartedRoot(t, firstReplica(c.replicas))
			bad := *state
			bad.Pending = append([]*rctypes.BlockData(nil), state.Pending...)
			for i, b := range bad.Pending {
				cp := *b
				bad.Pending[i] = &cp
			}
			head := *state.CommittedHead
			blk := *head.Block
			head.Block = &blk
			bad.CommittedHead = &head
			mutate(&bad)
			before := root.blockStore.RootAnchor()
			err := recoverTo(t, root, &bad)
			require.Error(t, err)
			if name != "a head block of another epoch" { // that one is refused earlier, as an inconsistent control checkpoint
				require.ErrorIs(t, err, abdrc.ErrRecoveryEpoch)
			}
			require.True(t, root.recovery.InRecovery(), "a refused state leaves the root in recovery")
			require.Equal(t, before, root.blockStore.RootAnchor(), "and its anchor unchanged")
		})
	}
}

// A peer chooses every field of a StateMsg. Whatever it sends, onStateResponse refuses without panicking and leaves the root in recovery.
func TestOnStateResponseRefusesMalformedStateWithoutPanicking(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	for name, mutate := range map[string]func(*abdrc.StateMsg){
		"a nil pending block":             func(s *abdrc.StateMsg) { s.Pending = append(append([]*rctypes.BlockData(nil), s.Pending...), nil) },
		"only a nil pending block":        func(s *abdrc.StateMsg) { s.Pending = []*rctypes.BlockData{nil} },
		"no committed head":               func(s *abdrc.StateMsg) { s.CommittedHead = nil },
		"a head without its block":        func(s *abdrc.StateMsg) { h := *s.CommittedHead; h.Block = nil; s.CommittedHead = &h },
		"a head without its QC":           func(s *abdrc.StateMsg) { h := *s.CommittedHead; h.Qc = nil; s.CommittedHead = &h },
		"a head without its commit QC":    func(s *abdrc.StateMsg) { h := *s.CommittedHead; h.CommitQc = nil; s.CommittedHead = &h },
		"a head without a control record": func(s *abdrc.StateMsg) { h := *s.CommittedHead; h.Control = nil; s.CommittedHead = &h },
		"a head without its shard info":   func(s *abdrc.StateMsg) { h := *s.CommittedHead; h.ShardInfo = nil; s.CommittedHead = &h },
		"a pending QC without vote info": func(s *abdrc.StateMsg) {
			p := make([]*rctypes.BlockData, len(s.Pending))
			for i, b := range s.Pending {
				cp := *b
				if cp.Qc != nil {
					q := *cp.Qc
					q.VoteInfo = nil
					cp.Qc = &q
				}
				p[i] = &cp
			}
			s.Pending = p
		},
	} {
		t.Run(name, func(t *testing.T) {
			root := restartedRoot(t, firstReplica(c.replicas))
			bad := *state
			mutate(&bad)
			require.NotPanics(t, func() {
				err := recoverTo(t, root, &bad)
				require.Error(t, err)
			})
			require.True(t, root.recovery.InRecovery())
		})
	}
}
