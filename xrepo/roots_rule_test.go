package xrepo

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/identityfix"
	"github.com/unicitynetwork/bft-core/internal/testutils/logger"
	"github.com/unicitynetwork/bft-core/rootchain/partitions"
)

// rootsCustodyIDs commits a primary candidate that names the fixture's election result, and then a recovery, into a real
// Orchestration store and returns the ids the root's own rule (Orchestration.CustodyAssignmentID, the one the closure path reads)
// gives for J's and K's epochs, with the assignment hashes of the same two epochs. The scenario names J by the first value: the
// suite never applies the formula itself, so a root that chose the assignment hash for a primary (P85 run 27, fixed by #577)
// changes the records and fails the golden test.
func rootsCustodyIDs(t *testing.T, result [32]byte) (primary, primaryHash, recovery, recoveryHash [32]byte) {
	t.Helper()
	const partition = types.PartitionID(8)
	var validators []*types.NodeInfo
	for _, id := range []string{"ev-a", "ev-b"} {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		validators = append(validators, &types.NodeInfo{NodeID: id, SigKey: pub, Stake: 1})
	}
	genesis := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partition, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256,
		T2Timeout: 5 * time.Second, Epoch: 0, EpochStart: 1, PartitionParams: map[string]string{"seal_registry_genesis": "g"}, Validators: validators}
	root := []evmassign.RootMember{{NodeID: "r-a", Key: bytes.Repeat([]byte{1}, 33), Weight: 1}, {NodeID: "r-b", Key: bytes.Repeat([]byte{2}, 33), Weight: 1}}
	ids := identityfix.Identities(root, genesis, []evmassign.Binding{{RootNodeID: "r-a", EVMNodeID: "ev-a"}, {RootNodeID: "r-b", EVMNodeID: "ev-b"}})

	o, err := partitions.NewOrchestration(5, filepath.Join(t.TempDir(), "orchestration.db"), logger.New(t), partitions.WithNoSync())
	require.NoError(t, err)
	defer func() { require.NoError(t, o.Close()) }()
	require.NoError(t, o.AddShardConfig(genesis))
	require.NoError(t, o.SetGenesisIdentities(partition, types.ShardID{}, ids))

	install := func(last *types.PartitionDescriptionRecord, kind, epoch, start uint64) *types.PartitionDescriptionRecord {
		succ, err := evmassign.NewSuccessor(last, []*types.NodeInfo{last.Validators[0], last.Validators[1]})
		require.NoError(t, err)
		raw, err := types.Cbor.Marshal(succ)
		require.NoError(t, err)
		c := identityfix.Shaped(evmassign.Candidate{Version: evmassign.CandidateVersion, Predecessor: bytes.Repeat([]byte{byte(epoch)}, 32), Assignment: raw,
			Authorization: &evmassign.Authorization{ResultID: bytes.Clone(result[:])}})
		if kind == evmassign.KindRecovery {
			c.Kind, c.PoPs, c.ReplacedAssignment = evmassign.KindRecovery, nil, bytes.Repeat([]byte{4}, 32)
		}
		require.Equal(t, result, c.ResultID(), "the committed candidate names the fixture's election result")
		prov, err := identityfix.ProvenanceFor(c, byte(epoch), epoch+1)
		require.NoError(t, err)
		pb, err := prov.Bytes()
		require.NoError(t, err)
		activated, err := evmassign.Activate(succ, start)
		require.NoError(t, err)
		require.NoError(t, o.InstallDerivedShardConfig(activated, pb))
		return activated
	}
	read := func(epoch uint64) (custody, hash [32]byte) {
		custody, err := o.CustodyAssignmentID(partition, types.ShardID{}, epoch)
		require.NoError(t, err)
		_, hash, err = o.AcknowledgedIdentities(partition, types.ShardID{}, epoch)
		require.NoError(t, err)
		return custody, hash
	}
	j := install(genesis, evmassign.KindPrimary, 1, 7)
	primary, primaryHash = read(1)
	install(j, evmassign.KindRecovery, 2, 9)
	recovery, recoveryHash = read(2)
	return primary, primaryHash, recovery, recoveryHash
}
