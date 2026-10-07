package storage

import (
	"testing"

	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/weightvalidation"
)

func assignmentWith(t *testing.T, weights ...uint64) *types.PartitionDescriptionRecord {
	t.Helper()
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: 8, PartitionTypeID: 8, TypeIDLen: 8, UnitIDLen: 256, T2Timeout: 2500000000, Epoch: 1}
	for i, w := range weights {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pub, err := v.MarshalPublicKey()
		require.NoError(t, err)
		pdr.Validators = append(pdr.Validators, &types.NodeInfo{NodeID: string(rune('a' + i)), SigKey: pub, Stake: w})
	}
	return pdr
}

// The assignment rules by mode: the unit rules are evmassign's unchanged, the weighted rules take the bounded weights of a Q3
// activation and nothing else is relaxed.
func TestValidateAssignmentByMode(t *testing.T) {
	unit, weighted := weightvalidation.ModeUnit, weightvalidation.ModeWeighted
	require.NoError(t, validateAssignment(assignmentWith(t, 1, 1, 1), unit))
	require.NoError(t, validateAssignment(assignmentWith(t, 1, 1, 1), weighted))
	require.NoError(t, validateAssignment(assignmentWith(t, 6, 1, 1, 1), weighted))
	require.ErrorIs(t, validateAssignment(assignmentWith(t, 6, 1, 1, 1), unit), evmassign.ErrAssignment, "weights are a Q3 activation's")
	unordered := assignmentWith(t, 1, 1, 1)
	unordered.Validators[0], unordered.Validators[2] = unordered.Validators[2], unordered.Validators[0]
	require.ErrorIs(t, validateAssignment(unordered, unit), evmassign.ErrValidators, "the unit rules include evmassign's own set rules, strict order among them")
	require.ErrorIs(t, validateAssignment(nil, unit), evmassign.ErrAssignment)
	require.ErrorIs(t, validateAssignment(nil, weighted), evmassign.ErrAssignment)

	require.ErrorIs(t, validateAssignment(assignmentWith(t, 0, 1, 1), weighted), evmassign.ErrAssignment, "a zero weight")
	require.ErrorIs(t, validateAssignment(assignmentWith(t, 1<<41, 1, 1), weighted), evmassign.ErrAssignment, "a weight over the cap")

	started := assignmentWith(t, 6, 1, 1, 1)
	started.EpochStart = 9
	require.ErrorIs(t, validateAssignment(started, weighted), evmassign.ErrEpoch, "the activation round is the commit's, not the candidate's")
	started = assignmentWith(t, 1, 1, 1)
	started.EpochStart = 9
	require.ErrorIs(t, validateAssignment(started, unit), evmassign.ErrEpoch)
}
