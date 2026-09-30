package archivewiring

import (
	"context"
	"testing"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/archive"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
)

func TestReadOperatorStatusUsesFixtureJournalAndReceiptArchive(t *testing.T) {
	t.Parallel()
	f := newWiringFixture(t, 2)
	local, err := archive.Open(t.TempDir() + "/archive")
	require.NoError(t, err)
	q, rec := f.record(t, 1)
	rec.Extensions = map[string][]byte{archive.ReceiptListKey: {0xc0}}
	require.NoError(t, local.Put(q, rec))
	progress := [2]ReplicaProgress{
		{Replica: "replica-a", LastAcknowledgedHeight: 2},
		{Replica: "replica-b", LastAcknowledgedHeight: 1, Error: "timeout"},
	}
	authority := &AuthorityReport{Reachable: true, RootEpoch: 2, ShardEpoch: 1, ReservedRound: 17}
	ids := testpeer.GeneratePeerIDs(t, 2)
	replicas := [2]peer.ID{ids[0], ids[1]}
	status, err := ReadOperatorStatus(context.Background(), f.store, f.context, f.limits, local, f.subject,
		replicas, 2, []uint64{2}, progress, authority)
	require.NoError(t, err)
	require.Equal(t, uint64(2), status.CurrentRootEpoch)
	require.Equal(t, []uint64{2}, status.ActivatedHandoffs)
	require.Equal(t, 2, status.Journal.CandidatesUsed)
	require.Equal(t, f.limits.Candidates, status.Journal.CandidatesCap)
	require.NotNil(t, status.LatestLocalV2)
	require.Equal(t, uint64(2), status.LatestLocalV2.Height)
	require.NotNil(t, status.CertifiedTip)
	require.Equal(t, uint64(2), status.CertifiedTip.Height)
	require.Equal(t, replicas[0].String(), status.Replicas[0].Replica)
	require.Equal(t, uint64(2), status.Replicas[0].LastAcknowledgedHeight)
	require.Equal(t, "timeout", status.Replicas[1].Error)
	require.Equal(t, uint64(17), status.Authority.ReservedRound)
}
