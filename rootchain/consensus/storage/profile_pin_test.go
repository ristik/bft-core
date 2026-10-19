package storage

import (
	"crypto"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// The handoff profile is number 3: the execution rule of ristik/bft-core#640 (a shard's configuration switch is applied by the root, and no
// request is applied to a switching shard in its switching block) is not readable by a node of the profile before it, and the other way
// round. The pin is in the blocks (version 3), in the payloads and in the store's own metadata.

func openBolt(t *testing.T) (BoltDB, string) {
	path := filepath.Join(t.TempDir(), "root.db")
	db, err := NewBoltStorage(path, WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func TestTheStoreRecordsItsProfileAndRefusesAnother(t *testing.T) {
	require.EqualValues(t, 3, ProfileHandoff, "profile 2 is the profile before the transition rule")
	db, _ := openBolt(t)
	s, err := New(crypto.SHA256, db, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.NoError(t, err)
	require.NotNil(t, s)
	got, found, err := db.NetworkProfile()
	require.NoError(t, err)
	require.True(t, found)
	require.EqualValues(t, 3, got)
	_, err = New(crypto.SHA256, db, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.NoError(t, err, "the same profile reopens")
	_, err = New(crypto.SHA256, db, emptyOrchestration(), logger.New(t), ProfileLegacy)
	require.ErrorIs(t, err, ErrNetworkProfile, "a store of the handoff profile is not read as the legacy one")
	_, err = New(crypto.SHA256, db, emptyOrchestration(), logger.New(t), 2)
	require.ErrorIs(t, err, ErrNetworkProfile, "profile 2 is not a profile of this binary")
}

func TestAProfile2StoreIsRefusedEvenWhenItsStateSatisfiesTheNewInvariants(t *testing.T) {
	// a store of the earlier handoff profile: it recorded profile 2 (a root of that rule never pinned; the pin below stands for any
	// store that names it), and holds a genesis whose state is valid under the new rule too
	db, _ := openBolt(t)
	require.NoError(t, db.SetNetworkProfile(2))
	_, err := New(crypto.SHA256, db, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.ErrorIs(t, err, ErrNetworkProfile)

	// a store that holds blocks and never recorded a profile was written by a root before the pin
	unpinned, _ := openBolt(t)
	genesis, err := NewGenesisBlock(5, crypto.SHA256, ProfileHandoff)
	require.NoError(t, err)
	require.NoError(t, unpinned.WriteBlock(genesis, true))
	_, err = New(crypto.SHA256, unpinned, emptyOrchestration(), logger.New(t), ProfileHandoff)
	require.ErrorIs(t, err, ErrNetworkProfile)
	_, found, err := unpinned.NetworkProfile()
	require.NoError(t, err)
	require.False(t, found, "a refusal pins nothing")
}

func TestVersionTwoAndMixedBlockAndPayloadVersionsFailBeforeVotingOrPersistence(t *testing.T) {
	s := profileStore(t)
	parent := mustBlock(t, s, 1)
	qc := &rctypes.QuorumCert{VoteInfo: &rctypes.RoundInfo{RoundNumber: 1, Epoch: 1, CurrentRootHash: parent.RootHash}}
	for name, block := range map[string]*rctypes.BlockData{
		"the retired version 2":                     {Version: 2, Round: 2, Epoch: 1, Payload: &rctypes.Payload{Version: 2}, Qc: qc},
		"block 3 with a version 2 payload":          {Version: 3, Round: 2, Epoch: 1, Payload: &rctypes.Payload{Version: 2}, Qc: qc},
		"block 2 with a version 3 payload":          {Version: 2, Round: 2, Epoch: 1, Payload: &rctypes.Payload{Version: 3}, Qc: qc},
		"the legacy version in the handoff profile": {Version: 1, Round: 2, Epoch: 1, Payload: &rctypes.Payload{}, Qc: qc},
		"an unknown version":                        {Version: 4, Round: 2, Epoch: 1, Payload: &rctypes.Payload{Version: 3}, Qc: qc},
		"a version 3 block with a legacy payload":   {Version: 3, Round: 2, Epoch: 1, Payload: &rctypes.Payload{}, Qc: qc},
	} {
		_, err := s.Add(block, nil)
		require.Error(t, err, name)
		_, err = s.Block(2)
		require.Error(t, err, "%s: nothing was added", name)
	}
	ok, err := s.Add(&rctypes.BlockData{Version: 3, Round: 2, Epoch: 1, Payload: &rctypes.Payload{Version: 3}, Qc: qc}, nil)
	require.NoError(t, err)
	require.NotEmpty(t, ok)
}
