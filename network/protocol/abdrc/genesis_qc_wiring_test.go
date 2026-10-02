package abdrc

import (
	gocrypto "crypto"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	testsig "github.com/unicitynetwork/bft-core/internal/testutils/sig"
	testtb "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// A vote of the first real round carries the genesis QC as its high QC. The verifier takes the store's pin: the local genesis QC verifies, any
// other round-1 QC (a peer chooses every field) is refused with the typed error, and so is the genesis QC when no pin is set.
func Test_VoteMsg_Verify_GenesisHighQc(t *testing.T) {
	s1, _ := testsig.CreateSignerAndVerifier(t)
	tbs, err := trustbase.NewTrustBaseStore(memorydb.New(), logger.New(t))
	require.NoError(t, err)
	require.NoError(t, tbs.Store(testtb.NewTrustBaseFromSigners(t, map[string]crypto.Signer{"1": s1})))

	genesisQC := func(root []byte) *drctypes.QuorumCert {
		info := &drctypes.RoundInfo{Version: 1, RoundNumber: drctypes.GenesisRootRound, Epoch: drctypes.GenesisRootEpoch, Timestamp: types.GenesisTime, CurrentRootHash: root}
		h, err := info.Hash(gocrypto.SHA256)
		require.NoError(t, err)
		return &drctypes.QuorumCert{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, NetworkID: 5, RootChainRoundNumber: 1,
			Epoch: drctypes.GenesisRootEpoch, Timestamp: types.GenesisTime, Hash: root, PreviousHash: h}}
	}
	voteWith := func(t *testing.T, highQc *drctypes.QuorumCert) *VoteMsg {
		t.Helper()
		info := &drctypes.RoundInfo{Version: 1, RoundNumber: 2, ParentRoundNumber: 1, Epoch: drctypes.GenesisRootEpoch, Timestamp: types.GenesisTime, CurrentRootHash: []byte{7}}
		h, err := info.Hash(gocrypto.SHA256)
		require.NoError(t, err)
		vote := &VoteMsg{VoteInfo: info, LedgerCommitInfo: &types.UnicitySeal{Version: 1, PreviousHash: h}, HighQc: highQc, Author: "1"}
		require.NoError(t, vote.Sign(s1))
		return vote
	}

	local := genesisQC([]byte{1, 2, 3})
	require.ErrorIs(t, voteWith(t, local).Verify(tbs), drctypes.ErrNotGenesisQC, "no pin: nothing says the QC is the local genesis QC")

	pin, err := drctypes.GenesisPinOf(local)
	require.NoError(t, err)
	tbs.SetGenesisPin(pin)
	require.NoError(t, voteWith(t, genesisQC([]byte{1, 2, 3})).Verify(tbs), "the local genesis QC")
	require.ErrorIs(t, voteWith(t, genesisQC([]byte{9, 9, 9})).Verify(tbs), drctypes.ErrNotGenesisQC, "another round-1 QC, its hashes consistent")
}
