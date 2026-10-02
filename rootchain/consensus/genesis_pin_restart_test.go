package consensus

import (
	"context"
	"crypto"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"

	testnetwork "github.com/unicitynetwork/bft-core/internal/testutils/network"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	"github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	tbstore "github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
	"github.com/unicitynetwork/bft-core/rootchain/testutils"
)

// A manager restarted after the first real QC (round 2) but before the genesis block is pruned still pins the genesis QC. The genesis block's
// CommitQc is replaced by the round-2 certificate on that commit, so the pin must come from its Qc, which stays the genesis QC.
func TestConsensusManagerEarlyRestartKeepsTheGenesisPin(t *testing.T) {
	profiles := map[string]uint64{"legacy profile": storage.ProfileLegacy, "handoff profile": storage.ProfileHandoff}
	for name, profile := range profiles {
		t.Run(name, func(t *testing.T) {
			mockNet := testnetwork.NewRootMockNetwork()
			rootNode := testutils.NewTestNode(t)
			trustBase := trustbase.NewTrustBaseFromSigners(t, map[string]abcrypto.Signer{rootNode.PeerConf.ID.String(): rootNode.Signer})
			observe := testobservability.Default(t)
			dir := t.TempDir()
			orchestration, err := partitions.NewOrchestration(5, filepath.Join(dir, "orchestration.db"), observe.Logger())
			require.NoError(t, err)
			t.Cleanup(func() { _ = orchestration.Close() })
			rootDB, err := storage.NewBoltStorage(filepath.Join(dir, "root.db"))
			require.NoError(t, err)
			t.Cleanup(func() { _ = rootDB.Close() })
			newTBStore := func() *tbstore.TrustBaseStore {
				s, err := tbstore.NewTrustBaseStore(memorydb.New(), observe.Logger())
				require.NoError(t, err)
				require.NoError(t, s.Store(trustBase))
				return s
			}
			params := *NewConsensusParams()
			params.NetworkProfileVersion = profile

			cm, err := NewConsensusManager(rootNode.PeerConf.ID, newTBStore(), orchestration, mockNet, rootNode.Signer, rootDB, observe, WithConsensusParams(params))
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runDone := make(chan error, 1)
			go func() { runDone <- cm.Run(ctx) }()

			getState := &abdrc.StateRequestMsg{NodeId: rootNode.PeerConf.ID.String()}
			mockNet.WaitReceive(t, getState)
			genesisState := testutils.MockAwaitMessage[*abdrc.StateMsg](t, mockNet, network.ProtocolRootStateResp)
			require.NoError(t, genesisState.Verify(crypto.SHA256, trustBase, cm.trustBaseStore.GenesisPin()))

			// advance to round 2: the first quorum-signed QC commits the genesis block
			lastProposal := testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
			mockNet.WaitReceive(t, lastProposal)
			vote := testutils.MockAwaitMessage[*abdrc.VoteMsg](t, mockNet, network.ProtocolRootVote)
			mockNet.WaitReceive(t, vote)
			testutils.MockAwaitMessage[*abdrc.ProposalMsg](t, mockNet, network.ProtocolRootProposal)
			mockNet.WaitReceive(t, getState)
			stateMsg := testutils.MockAwaitMessage[*abdrc.StateMsg](t, mockNet, network.ProtocolRootStateResp)
			require.EqualValues(t, 1, stateMsg.CommittedHead.Qc.GetRound())
			require.EqualValues(t, 2, stateMsg.CommittedHead.CommitQc.GetRound(), "premise: the commit QC of the genesis block is the round-2 one")
			require.NoError(t, stateMsg.Verify(crypto.SHA256, trustBase, cm.trustBaseStore.GenesisPin()))

			cancel()
			require.ErrorIs(t, <-runDone, context.Canceled)
			persisted, err := cm.blockStore.Block(drctypes.GenesisRootRound)
			require.NoError(t, err, "premise: the genesis block is not pruned yet")
			require.EqualValues(t, 2, persisted.CommitQc.GetRound(), "premise: the stored CommitQc is no longer the genesis QC")
			genuine := persisted.Qc
			require.EqualValues(t, 1, genuine.GetRound())

			restarted, err := NewConsensusManager(rootNode.PeerConf.ID, newTBStore(), orchestration, testnetwork.NewRootMockNetwork(), rootNode.Signer, rootDB, observe, WithConsensusParams(params))
			require.NoError(t, err)
			pin := restarted.trustBaseStore.GenesisPin()
			require.NoError(t, genuine.Verify(trustBase, pin), "the genuine round-1 QC is refused after an early restart")
			require.NoError(t, stateMsg.Verify(crypto.SHA256, trustBase, pin), "the state that verified before the restart is refused after it")

			// a forged round-1 QC is still refused
			forged := *genuine
			info := *genuine.VoteInfo
			info.CurrentRootHash = []byte{9, 9, 9}
			h, err := info.Hash(crypto.SHA256)
			require.NoError(t, err)
			seal := *genuine.LedgerCommitInfo
			seal.PreviousHash, seal.Hash = h, info.CurrentRootHash
			forged.VoteInfo, forged.LedgerCommitInfo = &info, &seal
			require.ErrorIs(t, forged.Verify(trustBase, pin), drctypes.ErrNotGenesisQC)
		})
	}
}
