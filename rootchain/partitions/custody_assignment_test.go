package partitions

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
)

// The contracts key a primary election result's assignment by PrimaryAssignmentID(result); the genesis assignment and a recovery's by the
// assignment hash. The closure of an epoch names custody's key (P85 run 27: J's closure named J's hash and custody did not know it).
func TestCustodyKeysAPrimaryByItsResultAndEveryOtherAssignmentByItsHash(t *testing.T) {
	hash := [32]byte{0xaa}
	result := bytes.Repeat([]byte{0x11}, 32)
	var resultID [32]byte
	copy(resultID[:], result)

	primary := evmassign.Candidate{Kind: evmassign.KindPrimary, Authorization: &evmassign.Authorization{ResultID: result}}
	require.Equal(t, evmassign.PrimaryAssignmentID(resultID), custodyAssignmentOf(primary, hash))
	require.NotEqual(t, hash, custodyAssignmentOf(primary, hash))

	unsetKind := evmassign.Candidate{Authorization: &evmassign.Authorization{ResultID: result}} // the zero Kind is read as primary
	require.Equal(t, evmassign.PrimaryAssignmentID(resultID), custodyAssignmentOf(unsetKind, hash))

	recovery := evmassign.Candidate{Kind: evmassign.KindRecovery, Authorization: &evmassign.Authorization{ResultID: result}}
	require.Equal(t, hash, custodyAssignmentOf(recovery, hash), "a recovery re-installs K under its assignment hash")
	require.Equal(t, hash, custodyAssignmentOf(evmassign.Candidate{}, hash), "no authorization: an operator candidate keeps its hash")
}
