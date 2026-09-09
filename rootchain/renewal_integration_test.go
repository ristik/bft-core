package rootchain

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	p2peer "github.com/libp2p/go-libp2p/core/peer"
	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testobservability "github.com/unicitynetwork/bft-core/internal/testutils/observability"
	testpeer "github.com/unicitynetwork/bft-core/internal/testutils/peer"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/network/protocol/handshake"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// staticTrustBase is the shard client's view of the root chain's signing set.
type staticTrustBase struct{ tb *types.RootTrustBaseV1 }

func (s staticTrustBase) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return s.tb, nil
}

// unapplicableDriver is a shard node whose executor cannot apply anything, which is the state that
// keeps a certificate unapplied and its retransmissions being re-delivered.
type unapplicableDriver struct{ calls atomic.Int64 }

func (d *unapplicableDriver) HandleCertificate(context.Context, *types.UnicityCertificate, *certification.TechnicalRecord) error {
	d.calls.Add(1)
	return errors.New("executor unavailable")
}

// loopbackNet wires a real BFTClient to a real rootchain Node: what the client sends to the root
// chain is handed to the root's own handler, and what the root sends back is fed into the client's
// received channel. Nothing about either side's behaviour is simulated.
type loopbackNet struct {
	received    chan any
	handshakes  atomic.Int64
	requests    atomic.Int64
	onHandshake func(*handshake.Handshake)
}

func (n *loopbackNet) Send(_ context.Context, msg any, _ ...p2peer.ID) error {
	switch m := msg.(type) {
	case handshake.Handshake:
		n.handshakes.Add(1)
		n.onHandshake(&m)
	case *certification.BlockCertificationRequest:
		n.requests.Add(1)
	}
	return nil
}

func (n *loopbackNet) ReceivedChannel() <-chan any { return n.received }

/*
Test_RenewalDoesNotLoopAgainstTheRealHandshake wires the root chain's ACTUAL handshake answer back
into a real BFTClient while the shard's application keeps failing.

Both halves of the loop are the production code. The root answers a handshake immediately with its
current certificate, outside the subscription quota (Node.onHandshake). The shard re-delivers a
certificate whose application failed, because that is how a transient executor failure recovers. If
renewal is driven by those re-deliveries the two feed each other: failed application, handshake, the
same certificate back, failed application — no new certificate and no timer required.

What must hold: handshake traffic stops growing for one certificate, new certified progress still
renews even though applying it fails, and application eventually succeeding changes none of it.
*/
func Test_RenewalDoesNotLoopAgainstTheRealHandshake(t *testing.T) {
	// The shard node's own peer identity is what the root chain authorizes, so the validator set is
	// built from it rather than from an unrelated id.
	shardPeer := testpeer.CreatePeer(t, testpeer.CreatePeerConfiguration(t))
	nodeID := shardPeer.ID()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	verifier, err := signer.Verifier()
	require.NoError(t, err)
	publicKey, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)

	const partition = types.PartitionID(8)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: partition}
	zero := make([]byte, 32)
	technicalFor := func(round uint64) certification.TechnicalRecord {
		return certification.TechnicalRecord{Round: round, Epoch: 0, Leader: nodeID.String(), StatHash: zero, FeeHash: zero}
	}
	// A genuinely signed certificate the shard client will verify, and the response the root chain
	// answers a handshake with.
	response := func(round, rootRound uint64) *certification.CertificationResponse {
		tr := technicalFor(round + 1)
		trHash, err := tr.Hash()
		require.NoError(t, err)
		ir := &types.InputRecord{
			Version: 1, RoundNumber: round, PreviousHash: zero, Hash: zero, BlockHash: nil,
			SummaryValue: []byte{}, Timestamp: 1,
		}
		uc := testcertificates.CreateUnicityCertificate(t, signer, ir, pdr, rootRound, zero, trHash)
		return &certification.CertificationResponse{Partition: partition, Shard: types.ShardID{}, Technical: tr, UC: *uc}
	}

	current := response(5, 41)
	var currentPtr atomic.Pointer[certification.CertificationResponse]
	currentPtr.Store(current)

	// The root chain, real, with its partition network feeding whatever it sends into the client.
	net := &loopbackNet{received: make(chan any, 64)}
	rootNode, err := New(&network.Peer{}, mockPartitionNet{
		send: func(_ context.Context, msg any, _ ...p2peer.ID) error {
			net.received <- msg
			return nil
		},
	}, mockConsensusManager{
		shardInfo: func(types.PartitionID, types.ShardID) (*storage.ShardInfo, error) {
			return newMockShardInfo(t, nodeID.String(), publicKey, *currentPtr.Load()), nil
		},
	}, testobservability.NOPObservability())
	require.NoError(t, err)
	net.onHandshake = func(h *handshake.Handshake) { require.NoError(t, rootNode.onHandshake(t.Context(), h)) }

	driver := &unapplicableDriver{}
	client, err := shardnode.NewBFTClient(shardPeer, net, signer, partition, types.ShardID{},
		staticTrustBase{tb: tb}, driver, nil, shardnode.DefaultBFTClientOptions)
	require.NoError(t, err)
	client.SeedLUC(&response(4, 40).UC)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { defer close(done); _ = client.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })

	// Run starts with a handshake of its own; the root answers with the current certificate, whose
	// application fails, and everything after that is the loop under test.
	require.Eventually(t, func() bool { return driver.calls.Load() >= 1 }, 5*time.Second, 10*time.Millisecond,
		"the client must have processed the certificate the handshake answered with")

	// Give the loop every chance to run away, then check it did not.
	time.Sleep(500 * time.Millisecond)
	settled := net.handshakes.Load()
	time.Sleep(500 * time.Millisecond)
	require.Equal(t, settled, net.handshakes.Load(),
		"handshake traffic must stop growing while one certificate is retried")
	require.Zero(t, net.requests.Load(), "and this node signed nothing: it is not voting")

	// New certified progress still renews, even though applying it fails too.
	next := response(6, 42)
	currentPtr.Store(next)
	before := net.handshakes.Load()
	net.received <- next
	require.Eventually(t, func() bool { return net.handshakes.Load() > before }, 5*time.Second, 10*time.Millisecond,
		"a certificate this node has not seen renews the subscription even though it could not apply it")
	require.Less(t, net.handshakes.Load(), before+3,
		"and renewing on it does not restart the loop either")
}
