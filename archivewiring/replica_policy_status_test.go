package archivewiring

import (
	"crypto/sha256"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/archivepolicy"
)

// refreshAt is the shard node's refreshArchivePolicy at one installed assignment: derive the replicas and switch to them.
func refreshAt(t *testing.T, p *ReplicaPolicy, writer peer.ID, validators []peer.ID, epoch uint64) bool {
	t.Helper()
	derived, err := archivepolicy.Select(writer, validators, epoch)
	require.NoError(t, err)
	encoded, err := derived.Encode()
	require.NoError(t, err)
	switched, err := p.Switch(derived.Replicas, sha256.Sum256(encoded), encoded, epoch)
	require.NoError(t, err)
	return switched
}

// bft-core#1044: a writer whose re-derived replica set is unchanged keeps its policy, so the policy's shard epoch and the version stay at the
// last real switch. The status then also reports the latest epoch the policy was checked against (checkedShardEpoch): the one an operator
// compares between writers. Checking changes no version and wakes no consumer.
func TestTheStatusReportsTheEpochThePolicyWasLastCheckedAt(t *testing.T) {
	v := func(b byte) peer.ID { return peer.ID([]byte{0x12, 0x20, b}) }
	writer := v(0x01)
	members := []peer.ID{writer, v(0x02), v(0x03), v(0x04)}
	joiner := v(0x09) // after every current replica in the writer's circular order: the writer's selection does not take it

	initial, err := archivepolicy.Select(writer, members, 1)
	require.NoError(t, err)
	encoded, err := initial.Encode()
	require.NoError(t, err)
	p, err := NewReplicaPolicy(initial.Replicas, sha256.Sum256(encoded), encoded, 1)
	require.NoError(t, err)
	before := p.Snapshot()
	require.Equal(t, uint64(1), before.Checked)
	changed := p.Changed()

	// epochs 2-4: a joiner comes and goes, and the writer's replicas stay the same
	require.False(t, refreshAt(t, p, writer, append(members, joiner), 2))
	require.False(t, refreshAt(t, p, writer, append(members, joiner), 3))
	require.False(t, refreshAt(t, p, writer, members, 4))
	select {
	case <-changed:
		t.Fatal("a check that keeps the policy is not a policy change")
	default:
	}
	report := PolicyReportOf(p.Snapshot())
	require.Equal(t, before.Version, report.Version, "the policy is unchanged")
	require.Equal(t, uint64(1), report.ShardEpoch, "the epoch the policy in force was derived from")
	require.Equal(t, uint64(4), report.CheckedShardEpoch, "the latest installed epoch it was checked against")
	require.Equal(t, before.Digest, p.Snapshot().Digest, "the digest of the policy in force is kept")

	// a late or repeated refresh of an earlier epoch does not move the checked epoch back
	require.False(t, refreshAt(t, p, writer, members, 3))
	require.Equal(t, uint64(4), p.Snapshot().Checked)

	// epoch 5 retires v(0x03): the replicas change, and the policy and both epochs move to 5
	require.True(t, refreshAt(t, p, writer, []peer.ID{writer, v(0x02), v(0x04), joiner}, 5))
	<-changed
	report = PolicyReportOf(p.Snapshot())
	require.Equal(t, before.Version+1, report.Version)
	require.Equal(t, uint64(5), report.ShardEpoch)
	require.Equal(t, uint64(5), report.CheckedShardEpoch)

	// an explicit pair never switches and is never re-derived: its epochs stay where it started
	legacy, err := NewReplicaPolicy([]peer.ID{v(0x02), v(0x03)}, [32]byte{}, nil, 1)
	require.NoError(t, err)
	_, err = legacy.Switch([]peer.ID{v(0x02), v(0x03), v(0x04)}, [32]byte{1}, []byte{1}, 6)
	require.NoError(t, err)
	require.Equal(t, uint64(1), legacy.Snapshot().Checked)
}
