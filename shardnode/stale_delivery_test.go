package shardnode

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

/*
seqExecutor is a minimal in-package Executor.

shardnode/executortest imports shardnode (for its conformance suite), so an INTERNAL test cannot
import it without a cycle — and this test has to be internal, because handleMessage and the luc
cursor it needs to observe are unexported. Hence a local one rather than the shared Fake.

It is deliberately tiny and does only what a round sequence needs: keep a committed head, produce a
block whose hash and state root move when there are pending entries and stay put when there are not.
That "stay put" behaviour is what makes a round quiet, which is the shape this test needs.
*/
type seqExecutor struct {
	mu       sync.Mutex
	head     BlockRef
	pending  []byte
	building map[BuildID]Block
	blocks   map[string]Block
	nextID   uint64
}

func newSeqExecutor() *seqExecutor {
	return &seqExecutor{building: map[BuildID]Block{}, blocks: map[string]Block{}}
}

func (e *seqExecutor) addEntries(b []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.pending = append(e.pending, b...)
}

func (e *seqExecutor) Head(context.Context) (BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.head, nil
}

func (e *seqExecutor) Build(_ context.Context, p RoundParams) (BuildID, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.nextID++
	id := BuildID(string(rune('a' + e.nextID)))
	blk := Block{Number: p.Parent.Number + 1, ParentHash: p.Parent.Hash}
	if len(e.pending) > 0 {
		// A real block: both the block hash and the resulting state move.
		h := sha256.Sum256(append([]byte("blk"), append([]byte{byte(p.Round)}, e.pending...)...))
		sr := sha256.Sum256(append([]byte("state"), append([]byte{byte(p.Round)}, e.pending...)...))
		blk.Hash, blk.StateRoot, blk.Raw = h[:], sr[:], append([]byte(nil), e.pending...)
		blk.BlockSize = uint64(len(blk.Raw))
	} else {
		// Nothing to execute: the state does not move, which is what makes the round quiet.
		blk.StateRoot = e.head.StateRoot
	}
	e.building[id] = blk
	return id, nil
}

func (e *seqExecutor) Seal(_ context.Context, id BuildID) (Block, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	blk, ok := e.building[id]
	if !ok {
		return Block{}, errors.New("no such build")
	}
	delete(e.building, id)
	if len(blk.Hash) != 0 {
		e.blocks[string(blk.Hash)] = blk
		e.pending = nil
	}
	return blk, nil
}

func (e *seqExecutor) Verify(_ context.Context, b Block, _ RoundParams) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(b.Hash) != 0 {
		e.blocks[string(b.Hash)] = b
	}
	return StatusValid, nil
}

func (e *seqExecutor) Commit(_ context.Context, hash Hash) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(hash) == 0 {
		return StatusSyncing, nil
	}
	blk, ok := e.blocks[string(hash)]
	if !ok {
		return StatusSyncing, nil
	}
	e.head = BlockRef{Number: blk.Number, Hash: blk.Hash, StateRoot: blk.StateRoot}
	return StatusValid, nil
}

/*
TestStaleDeliveryDuringRoundSequence is the evidence #93 still owed after the classifier fix: that a
delayed certificate arriving MID-SEQUENCE is harmless in operation, not merely classified correctly
in isolation.

The unit tests decide what ClassifyUC returns and what the handler does with one certificate. This
one runs an actual round sequence — the real BFTClient dispatch entry point, the real Round driver
and an in-memory test Executor — certifies several rounds, injects an authentic certificate the node has already
moved past, and asserts the shard carries on exactly as if it had never arrived.

Why not the chaos harness: a stale delivery cannot be forced there. It happens when a node subscribed
to several root nodes receives the certified sequence out of order, which is timing-dependent, and
scripts/chaos-evm.sh has no way to provoke it. That is why the harness run reported in #102 is a
no-regression result rather than coverage of this path, and why this test exists instead.
*/
// staleTestSubmitter stands in for the network side of BFTClient: it records every certification
// request the round driver produces, which is how this test observes that nothing is re-submitted.
type staleTestSubmitter struct {
	mu  sync.Mutex
	got []*certification.BlockCertificationRequest
}

func (s *staleTestSubmitter) Submit(_ context.Context, req *certification.BlockCertificationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.got = append(s.got, req)
	return nil
}

func (s *staleTestSubmitter) last(t *testing.T) *certification.BlockCertificationRequest {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.got, "no certification request was submitted")
	return s.got[len(s.got)-1]
}

func (s *staleTestSubmitter) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.got)
}

func TestStaleDeliveryDuringRoundSequence(t *testing.T) {
	ctx := context.Background()
	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID}
	zero := make([]byte, 32)

	fake := newSeqExecutor()
	sub := &staleTestSubmitter{}
	nodeID := "stale-delivery-node"

	logs := &capturingHandler{}
	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { require.NoError(t, provider.Shutdown(context.Background())) })
	metrics, err := NewMetrics(provider.Meter("stale-delivery-test"))
	require.NoError(t, err)
	staleCount := func() int64 {
		var data metricdata.ResourceMetrics
		require.NoError(t, reader.Collect(ctx, &data))
		var total int64
		for _, scope := range data.ScopeMetrics {
			for _, m := range scope.Metrics {
				if m.Name == "shardnode.uc.stale" {
					sum, ok := m.Data.(metricdata.Sum[int64])
					require.True(t, ok)
					for _, point := range sum.DataPoints {
						total += point.Value
					}
				}
			}
		}
		return total
	}
	c := &BFTClient{
		metrics:        metrics,
		partitionID:    authPartitionID,
		shardID:        types.ShardID{},
		nodeID:         nodeID,
		trustBaseStore: stubTrustBaseStore{tb: tb},
		log:            slog.New(logs),
	}
	round := NewRound(nodeID, authPartitionID, types.ShardID{}, fake,
		NewLoopbackDisseminator(), signer, sub, nil)
	c.SetDriver(round)

	technicalFor := func(next uint64) *certification.TechnicalRecord {
		return &certification.TechnicalRecord{
			Round: next, Epoch: 0, Leader: nodeID, StatHash: zero, FeeHash: zero,
		}
	}
	// certify turns whatever the node just submitted into the certificate the root chain would
	// return for it, signed for real.
	certify := func(req *certification.BlockCertificationRequest, rootRound uint64) *certification.CertificationResponse {
		t.Helper()
		tr := technicalFor(req.InputRecord.RoundNumber + 1)
		trHash, err := tr.Hash()
		require.NoError(t, err)
		uc := testcertificates.CreateUnicityCertificate(t, signer, req.InputRecord, pdr, rootRound, zero, trHash)
		require.NoError(t, uc.Verify(tb, crypto.SHA256, authPartitionID, types.ShardID{}, uc.ShardConfHash))
		return &certification.CertificationResponse{
			Partition: authPartitionID, Shard: types.ShardID{}, Technical: *tr, UC: *uc,
		}
	}

	// --- genesis and three certified rounds, including a non-quiet block ---
	genesisTR := technicalFor(1)
	genesisTRHash, err := genesisTR.Hash()
	require.NoError(t, err)
	genesisIR := &types.InputRecord{
		Version: 1, RoundNumber: 0, PreviousHash: nil, Hash: nil,
		BlockHash: nil, SummaryValue: []byte{}, Timestamp: 1000,
	}
	genesisUC := testcertificates.CreateUnicityCertificate(t, signer, genesisIR, pdr, 10, zero, genesisTRHash)
	require.NoError(t, c.handleCertificationResponse(ctx, &certification.CertificationResponse{
		Partition: authPartitionID, Shard: types.ShardID{}, Technical: *genesisTR, UC: *genesisUC,
	}))

	rootRound := uint64(11)
	var responses []*certification.CertificationResponse
	for i := 0; i < 3; i++ {
		if i == 1 {
			fake.addEntries([]byte("a real block, so the sequence is not all quiet"))
		}
		req := sub.last(t)
		resp := certify(req, rootRound)
		rootRound++
		responses = append(responses, resp)
		require.NoError(t, c.handleCertificationResponse(ctx, resp),
			"round %d must be accepted", req.InputRecord.RoundNumber)
	}

	// State the node is in before the stale delivery, so "unchanged" is a real assertion.
	beforeLUC := c.luc
	beforeHead, err := fake.Head(ctx)
	require.NoError(t, err)
	beforeSubmissions := sub.count()
	require.GreaterOrEqual(t, beforeLUC.GetRoundNumber(), uint64(3), "the sequence really advanced")
	require.NotEmpty(t, beforeHead.Hash,
		"the sequence must contain a real committed block, or 'the executor is unchanged' proves nothing")

	require.EqualValues(t, 0, staleCount())
	t.Run("a delayed certificate changes nothing", func(t *testing.T) {
		// The first round's certificate, re-delivered after the node has moved two rounds past
		// it — exactly what a second root node or a retransmission produces.
		// handleMessage is the real dispatch entry point Run feeds from the network, so this
		// exercises type dispatch and error reporting, not just the response handler.
		c.handleMessage(ctx, responses[0])
		require.EqualValues(t, 1, staleCount(), "the stale metric must record the injected delivery")

		require.Same(t, beforeLUC, c.luc, "the observation cursor must not move")
		head, err := fake.Head(ctx)
		require.NoError(t, err)
		require.Equal(t, beforeHead, head, "the executor must not be driven backwards")
		require.Equal(t, beforeSubmissions, sub.count(), "nothing may be re-submitted")

		require.Empty(t, logs.atLevel(slog.LevelError), "a delayed certificate is not an error")
		require.False(t, logs.anyMentions("equivocat"))
		require.False(t, logs.anyMentions("impossible certificate ordering"))

		// And it really did travel the stale path rather than being dropped as a duplicate or
		// never classified at all — without this the assertions above would hold for a handler
		// that silently discarded the message.
		require.Contains(t, logs.atLevel(slog.LevelDebug), "stale UC, ignoring",
			"the delayed certificate must be classified as stale, not merely ignored")
	})

	t.Run("and the shard keeps certifying afterwards", func(t *testing.T) {
		// The point of the whole test: the stale delivery must not have wedged anything. Without
		// this, the assertions above would also pass on a node that had simply stopped.
		fake.addEntries([]byte("another real block, after the stale delivery"))
		req := sub.last(t)
		require.NoError(t, c.handleCertificationResponse(ctx, certify(req, rootRound)))
		// The response above certifies the already-built quiet round and builds the next
		// non-quiet block. Certify that block too, so recovery means executed progress.
		require.NoError(t, c.handleCertificationResponse(ctx, certify(sub.last(t), rootRound+1)))
		afterHead, err := fake.Head(ctx)
		require.NoError(t, err)
		require.NotEqual(t, beforeHead.Hash, afterHead.Hash)
		require.Greater(t, afterHead.Number, beforeHead.Number)
		require.Equal(t, beforeSubmissions+2, sub.count())
		require.Greater(t, c.luc.GetRoundNumber(), beforeLUC.GetRoundNumber(),
			"the sequence continued past the round it was at when the stale certificate arrived")
		require.Empty(t, logs.atLevel(slog.LevelError))
	})
}
