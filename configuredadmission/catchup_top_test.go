package configuredadmission

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// topRecorder is an archive catch-up whose walk cannot start from any top it is given; it records the tops.
type topRecorder struct{ tops [][]byte }

func (f *topRecorder) Walk(_ context.Context, _ shardnode.BlockRef, top []byte, _ time.Time) (bool, int, error) {
	f.tops = append(f.tops, bytes.Clone(top))
	return false, 0, errors.New("archive chain passes the retained anchor's height without reaching it")
}
func (f *topRecorder) Live(shardnode.BlockRef) bool { return false }
func (f *topRecorder) Page(context.Context, shardnode.BlockRef, int) ([]shardnode.JournalFetchEntry, int, error) {
	return nil, 0, errors.New("unused")
}
func (f *topRecorder) Drop()                                      {}
func (f *topRecorder) AdvanceFrontier(context.Context, int) error { return nil }

// An earlier certified target the walk could not start from is not offered again (bft-core#1071: the staging joiner's catch-up had
// passed such a target, and the rotation of earlier targets offered it again as the one before the current target): the next calls
// start from the current target.
func TestACatchUpDoesNotRetryAnEarlierTopItCouldNotWalkFrom(t *testing.T) {
	stale, target := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{3}, 32)
	cu := &topRecorder{}
	r := &ExecutionRecovery{ArchiveCatchUp: cu, catchUpSeen: stale}
	after := shardnode.BlockRef{Number: 636, Hash: bytes.Repeat([]byte{9}, 32), StateRoot: bytes.Repeat([]byte{8}, 32)}
	for range 3 {
		require.ErrorIs(t, r.catchUpPage(context.Background(), after, target, nil, true), ErrRecoveryUnavailable)
	}
	require.Equal(t, [][]byte{stale, target, target}, cu.tops, "the stale top is tried once")
}
