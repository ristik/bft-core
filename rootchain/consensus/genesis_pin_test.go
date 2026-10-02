package consensus

import (
	"crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The manager pins the genesis QC its own software builds, in both network profiles: the verifiers accept an unsigned round-1 QC only when it
// is that one.
func TestConsensusManagerPinsTheLocalGenesisQC(t *testing.T) {
	pinOf := func(t *testing.T, cm *ConsensusManager, want *rctypes.QuorumCert) {
		t.Helper()
		pin, err := rctypes.GenesisPinOf(want)
		require.NoError(t, err)
		require.Equal(t, pin, cm.trustBaseStore.GenesisPin())
	}
	built := func(t *testing.T, cm *ConsensusManager) *rctypes.QuorumCert {
		t.Helper()
		genesis, err := storage.NewGenesisBlock(cm.orchestration.NetworkID(), crypto.SHA256, cm.params.NetworkProfileVersion)
		require.NoError(t, err)
		return genesis.CommitQc
	}

	t.Run("legacy profile: the QC the fresh store holds verifies, another round-1 QC does not", func(t *testing.T) {
		cm, _, _ := initConsensusManager(t, testnetwork.NewRootMockNetwork())
		tb, err := cm.trustBaseStore.GetByEpoch(rctypes.GenesisRootEpoch)
		require.NoError(t, err)
		held := cm.blockStore.GetHighQc()
		pinOf(t, cm, held) // this fixture's genesis block carries a shard, so its QC is not the one the software builds for an empty store
		require.NotEqual(t, built(t, cm).VoteInfo.CurrentRootHash, held.VoteInfo.CurrentRootHash, "premise")
		require.EqualValues(t, rctypes.GenesisRootRound, held.GetRound(), "premise: a fresh store holds the genesis QC")
		require.NoError(t, held.Verify(tb, cm.trustBaseStore.GenesisPin()))

		other := *held
		info := *held.VoteInfo
		info.CurrentRootHash = []byte{9, 9, 9}
		h, err := info.Hash(crypto.SHA256)
		require.NoError(t, err)
		seal := *held.LedgerCommitInfo
		seal.PreviousHash, seal.Hash = h, info.CurrentRootHash
		other.VoteInfo, other.LedgerCommitInfo = &info, &seal
		require.ErrorIs(t, other.Verify(tb, cm.trustBaseStore.GenesisPin()), rctypes.ErrNotGenesisQC)
	})

	// A store that has moved past round 1 no longer holds the genesis block: the pin is the one the software builds.
	t.Run("handoff profile, a store past round 1", func(t *testing.T) {
		cm := restartedRoot(t, firstReplica(newAnchorCluster(t).replicas))
		_, err := cm.blockStore.Block(rctypes.GenesisRootRound)
		require.Error(t, err, "premise: the genesis block is gone")
		pinOf(t, cm, built(t, cm))
	})
}

// A peer's state message cannot carry a round-1 QC of its own making in the head's QC slots or the pending suffix: round 1 is the genesis round, and
// the one QC of it that verifies without signatures is the local genesis QC.
func TestRecoveryRefusesAFabricatedRoundOneQCInTheState(t *testing.T) {
	c := newAnchorCluster(t)
	state := c.pastTheFirstSuccessor()
	epoch := state.CommittedHead.Block.Epoch
	fabricated := func() *rctypes.QuorumCert {
		info := &rctypes.RoundInfo{Version: 1, RoundNumber: rctypes.GenesisRootRound, Epoch: epoch, Timestamp: state.CommittedHead.Block.Timestamp, CurrentRootHash: []byte{9, 9, 9}}
		h, err := info.Hash(crypto.SHA256)
		require.NoError(t, err)
		return &rctypes.QuorumCert{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, RootChainRoundNumber: rctypes.GenesisRootRound, Epoch: epoch,
			Hash: []byte{9, 9, 9}, PreviousHash: h}}
	}
	for name, mutate := range map[string]func(*abdrc.StateMsg){
		"the head's QC":        func(s *abdrc.StateMsg) { s.CommittedHead.Qc = fabricated() },
		"the head's commit QC": func(s *abdrc.StateMsg) { s.CommittedHead.CommitQc = fabricated() },
		"a pending block's QC": func(s *abdrc.StateMsg) { s.Pending[0].Qc = fabricated() },
	} {
		t.Run(name, func(t *testing.T) {
			bad := *state
			head := *state.CommittedHead
			bad.CommittedHead = &head
			bad.Pending = append([]*rctypes.BlockData(nil), state.Pending...)
			first := *bad.Pending[0]
			bad.Pending[0] = &first
			mutate(&bad)
			root := genesisProbe(t, c)
			before := root.blockStore.RootAnchor()
			err := recoverTo(t, root, &bad)
			require.ErrorIs(t, err, rctypes.ErrNotGenesisQC)
			require.False(t, root.frontier.faulted.Load(), "refused at verification, before any write")
			require.Equal(t, before, root.blockStore.RootAnchor())
		})
	}
}

// genesisProbe is a restarted root with a frontier sampler, to read whether recovery latched its fault.
func genesisProbe(t *testing.T, c *anchorCluster) *ConsensusManager {
	t.Helper()
	root := restartedRoot(t, firstReplica(c.replicas))
	root.frontier = &frontierSampler{}
	return root
}

// The manager's own recovery verification takes the pin: a root recovers from a peer's state whose head is the genesis block, and the same state
// with a round-1 QC of the peer's own making is refused, both through onStateResponse (not the verification helpers). A manager that dropped the
// pin from that call would refuse the first as well.
func TestManagerRecoveryVerifiesTheGenesisHeadWithItsPin(t *testing.T) {
	// Each case has its own manager: recovery is entered once per manager.
	genesisState := func(t *testing.T) (*ConsensusManager, *abdrc.StateMsg) {
		t.Helper()
		cm, _, _ := initConsensusManager(t, testnetwork.NewRootMockNetwork())
		state, err := cm.blockStore.GetState()
		require.NoError(t, err)
		require.EqualValues(t, rctypes.GenesisRootRound, state.CommittedHead.Block.Round, "premise: the head is the genesis block")
		require.EqualValues(t, rctypes.GenesisRootRound, state.CommittedHead.Qc.GetRound(), "premise: its QC is the genesis QC")
		require.Empty(t, state.Pending)
		return cm, state
	}
	fabricated := func(t *testing.T, held *rctypes.QuorumCert) *rctypes.QuorumCert {
		info := *held.VoteInfo
		info.CurrentRootHash = []byte{9, 9, 9}
		h, err := info.Hash(crypto.SHA256)
		require.NoError(t, err)
		seal := *held.LedgerCommitInfo
		seal.PreviousHash, seal.Hash = h, info.CurrentRootHash
		return &rctypes.QuorumCert{VoteInfo: &info, LedgerCommitInfo: &seal}
	}

	t.Run("the genesis head verifies against the manager's pin", func(t *testing.T) {
		cm, state := genesisState(t)
		require.NoError(t, recoverTo(t, cm, state))
	})
	for name, mutate := range map[string]func(*testing.T, *abdrc.StateMsg){
		"the head's QC": func(t *testing.T, s *abdrc.StateMsg) { s.CommittedHead.Qc = fabricated(t, s.CommittedHead.Qc) },
		"the head's commit QC": func(t *testing.T, s *abdrc.StateMsg) {
			s.CommittedHead.CommitQc = fabricated(t, s.CommittedHead.CommitQc)
		},
	} {
		t.Run("a fabricated round-1 QC as "+name+" is refused", func(t *testing.T) {
			cm, state := genesisState(t)
			bad := *state
			head := *state.CommittedHead
			bad.CommittedHead = &head
			mutate(t, &bad)
			require.ErrorIs(t, recoverTo(t, cm, &bad), rctypes.ErrNotGenesisQC)
		})
	}
}
