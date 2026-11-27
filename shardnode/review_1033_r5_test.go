package shardnode

import (
	"context"
	"crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"
	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	"github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
	"testing"
	"time"
)

// Keep outgoing handshakes stubbed as in the original fixture. The receive
// channel and self-enqueue below use the real LibP2PNetwork implementation.
type reviewR5ReceiveNet struct{ *network.LibP2PNetwork }

func (reviewR5ReceiveNet) Send(context.Context, any, ...peer.ID) error { return nil }

// Review r5 (#1033): over the real LibP2PNetwork, a repeat certificate queued behind a duplicate, an equal-round conflict and an invalid
// response ends the stale wait on its arrival. The shard consumer sees the receive queue's backlog only while an unbudgeted network hands
// out the buffered queue itself.
func TestReviewR5RealNetworkRepeatBehindDuplicate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	f := newConfBindingFixture(t)
	zero := make([]byte, 32)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID, T2Timeout: 2500000000}
	confHash, err := pdr.Hash(crypto.SHA256)
	require.NoError(t, err)
	input := &types.InputRecord{Version: 1, RoundNumber: 952, PreviousHash: zero, Hash: []byte("state-952"), BlockHash: []byte("block-952"), SummaryValue: []byte{}, Timestamp: 1}
	response := func(rootRound, nextRound uint64, leader string) *certification.CertificationResponse {
		t.Helper()
		trec := &certification.TechnicalRecord{Round: nextRound, Epoch: 0, Leader: leader, StatHash: zero, FeeHash: zero}
		trHash, hashErr := trec.Hash()
		require.NoError(t, hashErr)
		ir := *input
		ir.SummaryValue = []byte{}
		uc := testcertificates.CreateUnicityCertificate(t, f.signer, &ir, pdr, rootRound, zero, trHash)
		return &certification.CertificationResponse{Partition: authPartitionID, Shard: types.ShardID{}, Technical: *trec, UC: *uc}
	}
	seed := response(952, 953, "v1")
	first := response(953, 953, "v1")
	duplicate := response(953, 953, "v1")
	conflict := response(953, 953, "v2") // the same root round, a different technical record
	wrongShard := response(960, 953, "v1")
	wrongShard.Partition = authPartitionID + 1
	repeat := response(954, 953, "v1")

	p := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	net, err := network.NewLibP2PNetwork(p, 16, observability.NOPObservability())
	require.NoError(t, err)
	t.Cleanup(net.Close)
	require.NoError(t, net.RegisterSendProtocols([]network.SendProtocolDescription{{ProtocolID: network.ProtocolUnicityCertificates, MsgType: certification.CertificationResponse{}, Timeout: time.Second}}))
	driver := &waitDriver{ended: map[uint64]string{}, inWait: make(chan uint64, 4), budget: 5 * time.Second}
	client, err := NewBFTClient(p, reviewR5ReceiveNet{net}, f.signer, authPartitionID, types.ShardID{}, confHash, stubTrustBaseStore{tb: f.tb}, driver, nil,
		BFTClientOptions{HandshakeNodes: 1, CertNodes: 1, HeartbeatInterval: time.Hour, InactivityTimeout: 24 * time.Hour})
	require.NoError(t, err)
	driver.client = client
	require.NoError(t, client.SeedLUC(&seed.UC))
	runDone := make(chan error, 1)
	go func() { runDone <- client.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(time.Second):
			t.Error("Run did not stop")
		}
	})

	require.NoError(t, net.Send(ctx, first, p.ID()))
	select {
	case root := <-driver.inWait:
		require.Equal(t, uint64(953), root)
	case <-time.After(2 * time.Second):
		t.Fatal("the driver never started waiting")
	}
	for _, resp := range []*certification.CertificationResponse{duplicate, conflict, wrongShard} {
		require.NoError(t, net.Send(ctx, resp, p.ID()))
	}
	time.Sleep(300 * time.Millisecond)
	_, ended := driver.snapshot()
	require.Empty(t, ended, "a duplicate, an equal-round conflict and an invalid response must not end the wait")

	sent := time.Now()
	require.NoError(t, net.Send(ctx, repeat, p.ID()))
	require.Eventually(t, func() bool { _, e := driver.snapshot(); return e[953] != "" }, time.Second, 5*time.Millisecond)
	_, ended = driver.snapshot()
	require.Equal(t, "cancelled", ended[953])
	require.Less(t, time.Since(sent), time.Second, "the wait ended on the repeat's arrival, not on its 5 s budget")

	require.Eventually(t, func() bool { got, _ := driver.snapshot(); return len(got) > 0 && got[len(got)-1] == 954 }, 2*time.Second, 5*time.Millisecond)
	got, _ := driver.snapshot()
	require.Equal(t, uint64(953), got[0])
	require.Contains(t, got, uint64(954), "and the repeat itself was delivered next")
}
