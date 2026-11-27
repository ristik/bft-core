package engineapi

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/recordsfeed"
	"github.com/unicitynetwork/bft-core/rootinput"
)

// bft-core#1067, case 1: a root-record import that cannot be derived because the root log is not available here yet makes the block
// unjudged (syncing), not invalid: recovery retries instead of stopping on a finalized-branch conflict. An inconsistent import stays invalid.
func TestAnUnavailableRootLogIsNotAnInvalidBlock(t *testing.T) {
	unavailable := errors.Join(rootinput.ErrRecordsAdmission, fmt.Errorf("cursor: %w", errors.Join(recordsfeed.ErrUnavailable, errors.New("mirror m1: no cut"))))
	require.True(t, sourceUnavailable(unavailable))
	require.True(t, errors.Is(unavailable, recordsfeed.ErrUnavailable), "still the same sentinel for errors.Is")
	require.False(t, sourceUnavailable(rootinput.ErrRecordsAdmission), "an import that differs is invalid")
	require.False(t, sourceUnavailable(errors.Join(rootinput.ErrRecordsAdmission, recordsfeed.ErrAuth)), "an unauthenticated log is invalid")
	require.False(t, sourceUnavailable(nil))
}
