package cmd

import (
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

type fakeMembers map[peer.ID]bool

func (f fakeMembers) IsShardValidator(partition types.PartitionID, _ types.ShardID, id peer.ID) bool {
	return partition == 8 && f[id]
}

// The records feed serves the validators named at the root's start, the other roots, and the members of each configured shard's installed
// configuration, so a validator that joined by an assignment is served without a root restart; nobody else.
func TestRecordsFeedServesTheInstalledAssignmentsMembers(t *testing.T) {
	ids := make([]peer.ID, 5)
	for i := range ids {
		ids[i] = peerIDOf(t)
	}
	named, otherRoot, joiner, installedButOtherShard, stranger := ids[0], ids[1], ids[2], ids[3], ids[4]
	static := map[peer.ID]struct{}{named: {}}
	confs := []*types.PartitionDescriptionRecord{{PartitionID: 8}}
	members := fakeMembers{joiner: true}
	allowed := recordsFeedAllowed(static, confs, members, func(id peer.ID) bool { return id == otherRoot })

	require.True(t, allowed(named), "named by the configuration at start")
	require.True(t, allowed(otherRoot), "another root")
	require.True(t, allowed(joiner), "a member of the installed configuration that the start configuration did not name")
	require.False(t, allowed(stranger))

	// the installed configuration of a shard the root is not configured with grants nothing
	other := recordsFeedAllowed(static, []*types.PartitionDescriptionRecord{{PartitionID: 9}}, fakeMembers{installedButOtherShard: true}, func(peer.ID) bool { return false })
	require.False(t, other(installedButOtherShard))

	// a candidate whose assignment is not installed yet is refused until it is
	candidate := peerIDOf(t)
	require.False(t, allowed(candidate), "a candidate that is not installed is refused")
	members[candidate] = true
	require.True(t, allowed(candidate), "and served once the installed configuration names it")

	// the membership follows the installed configuration: a validator it stops naming is no longer served
	members[joiner] = false
	require.False(t, allowed(joiner))
}
