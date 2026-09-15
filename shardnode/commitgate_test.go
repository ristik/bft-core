package shardnode_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// TestRound_CommitsWaitForTheFinalityGate: with a gate installed by SetFinalityGate, as Node.SetCommitObserver
// does without recovery, the round's commit waits while another party holds the gate, and then commits and
// reports. This is what lets a certified-record capturer read the head and commit its store transaction without
// the executor moving in between (#14 W2).
func TestRound_CommitsWaitForTheFinalityGate(t *testing.T) {
	ctx := context.Background()
	const nodeID = "node"
	r, fake, sub, obs := observedRound(t, nodeID)
	gate := shardnode.NewFinalityGate()
	r.SetFinalityGate(gate)

	require.NoError(t, r.HandleCertificate(ctx, genesisUC(1000), tr(1, 0, nodeID)))
	fake.AddEntries([]byte("a transaction"))
	require.NoError(t, r.HandleCertificate(ctx, certifyFrom(sub.last(t), 2, 1000), tr(2, 0, nodeID)))
	req2 := sub.last(t)

	release, err := gate.Hold(ctx, "certified-record-publication")
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- r.HandleCertificate(ctx, certifyFrom(req2, 3, 1000), tr(3, 0, nodeID)) }()

	deadline := time.Now().Add(10 * time.Second)
	for gate.Waiting() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	require.Equal(t, 1, gate.Waiting(), "the round's commit waits for the held gate")
	head, err := fake.Head(ctx)
	require.NoError(t, err)
	require.NotEqual(t, []byte(req2.InputRecord.BlockHash), []byte(head.Hash), "nothing is committed while the gate is held")
	require.Empty(t, obs.commits())

	release()
	require.NoError(t, <-done)
	head, err = fake.Head(ctx)
	require.NoError(t, err)
	require.Equal(t, []byte(req2.InputRecord.BlockHash), []byte(head.Hash))
	require.Len(t, obs.commits(), 1)
}
