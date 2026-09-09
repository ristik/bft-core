package shardnode

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	testcertificates "github.com/unicitynetwork/bft-core/internal/testutils/certificates"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// retryExecutor holds a block that is present but not yet canonical, and can be made to report it
// unavailable — the difference between "the executor does not have the payload" and "it rejected
// the payload", which is what the retry contract turns on. Written in-package for the same reason
// as steadyExecutor: executortest imports shardnode.
type retryExecutor struct {
	mu        sync.Mutex
	head      BlockRef
	held      map[string]BlockRef
	available bool
	queued    []byte
	commits   []Hash
}

func (e *retryExecutor) Head(context.Context) (BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.head, nil
}

func (e *retryExecutor) GenesisBlock(context.Context) (BlockRef, error) {
	return BlockRef{Number: 0, Hash: []byte{0x00}, StateRoot: []byte{0x00}}, nil
}

func (e *retryExecutor) Commit(_ context.Context, hash Hash) (Status, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.commits = append(e.commits, hash)
	if bytes.Equal(e.head.Hash, hash) {
		return StatusValid, nil // already canonical: idempotent by contract
	}
	if !e.available {
		return StatusSyncing, nil // unavailable, not invalid — retryable
	}
	b, ok := e.held[string(hash)]
	if !ok {
		return StatusSyncing, nil
	}
	e.head = b
	return StatusValid, nil
}

func (e *retryExecutor) Build(context.Context, RoundParams) (BuildID, error) { return "b", nil }

// Seal returns a candidate that CHANGES when the executor's queue does, which is what a real
// executor does between one round attempt and the next. A replay that rebuilds instead of re-sending
// therefore produces different bytes, and a test can see it.
func (e *retryExecutor) Seal(context.Context, BuildID) (Block, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.queued) == 0 {
		return Block{Number: e.head.Number, Hash: e.head.Hash, StateRoot: e.head.StateRoot, ParentHash: e.head.Hash}, nil
	}
	sum := sha256.Sum256(append(append([]byte(nil), e.head.StateRoot...), e.queued...))
	return Block{
		Number: e.head.Number + 1, Hash: sum[:], StateRoot: sum[:], ParentHash: e.head.Hash,
		Raw: e.queued, BlockSize: uint64(len(e.queued)),
	}, nil
}

// queue makes the next candidate different, the way an arriving transaction would.
func (e *retryExecutor) queue(b []byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.queued = append(e.queued, b...)
}

func (e *retryExecutor) Verify(context.Context, Block, RoundParams) (Status, error) {
	return StatusValid, nil
}

func (e *retryExecutor) makeAvailable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.available = true
}

func (e *retryExecutor) snapshot() (BlockRef, int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.head, len(e.commits)
}

// refusingSubmitter is a transport that never delivers, recording what it was asked to send.
type refusingSubmitter struct {
	mu   sync.Mutex
	sent []*certification.BlockCertificationRequest
}

func (s *refusingSubmitter) Submit(_ context.Context, req *certification.BlockCertificationRequest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, req)
	return errors.New("transport failure")
}

func (s *refusingSubmitter) requests() []*certification.BlockCertificationRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*certification.BlockCertificationRequest(nil), s.sent...)
}

// countingDriver wraps a RoundDriver and counts deliveries, so a test can distinguish "the handler
// dropped it" from "the driver ran and failed".
type countingDriver struct {
	inner RoundDriver
	mu    sync.Mutex
	calls int
}

func (d *countingDriver) HandleCertificate(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
	d.mu.Lock()
	d.calls++
	d.mu.Unlock()
	return d.inner.HandleCertificate(ctx, uc, tr)
}

func (d *countingDriver) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

/*
TestFailedDeliveryIsRetriedByDuplicate drives the REAL handler and a REAL Round through the sequence
the retry contract is written for (design §5): an authenticated certificate whose application fails
because the executor does not yet have the payload, the retransmissions that follow, the payload
becoming available, and recovery to the exact certified head.

The gap it closes. handleCertificationResponse advances `c.luc` — the observation cursor — before
calling the driver, and returned early for every UCDuplicate. So a driver failure left the cursor
ahead of what was actually applied, and the retransmission that would retry it was classified a
duplicate and dropped: the failure was never retried by any route, and the node stayed behind while
holding, or about to hold, the very block it needed. Observed and applied are different facts and
only the first had a cursor.

The other half matters as much: a duplicate arriving after a SUCCESSFUL delivery must still be
dropped, or a node would drive — and sign — a completed round twice. The last step asserts that.
*/
func TestFailedDeliveryIsRetriedByDuplicate(t *testing.T) {
	ctx := context.Background()

	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID}
	zero := make([]byte, 32)

	s0 := bytes.Repeat([]byte{0xc0}, 32)
	s1 := bytes.Repeat([]byte{0xc1}, 32)
	b0 := bytes.Repeat([]byte{0xd0}, 32)
	b1 := bytes.Repeat([]byte{0xd1}, 32)

	technicalFor := func(round uint64) *certification.TechnicalRecord {
		return &certification.TechnicalRecord{Round: round, Epoch: 0, Leader: "retry-node", StatHash: zero, FeeHash: zero}
	}
	trHash, err := technicalFor(6).Hash()
	require.NoError(t, err)
	ir5 := &types.InputRecord{
		Version: 1, RoundNumber: 5, PreviousHash: s0, Hash: s1, BlockHash: b1,
		SummaryValue: []byte{}, Timestamp: 1,
	}
	uc5 := testcertificates.CreateUnicityCertificate(t, signer, ir5, pdr, 41, zero, trHash)

	// The executor is one certified block behind and does not yet have the payload.
	exec := &retryExecutor{
		head:      BlockRef{Number: 4, Hash: b0, StateRoot: s0},
		held:      map[string]BlockRef{string(b1): {Number: 5, Hash: b1, StateRoot: s1}},
		available: false,
	}
	sub := &countingSubmitter{}
	round := NewRound("retry-node", authPartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), signer, sub, nil)
	drv := &countingDriver{inner: round}

	client := &BFTClient{
		partitionID:    authPartitionID,
		shardID:        types.ShardID{},
		nodeID:         "retry-node",
		trustBaseStore: stubTrustBaseStore{tb: tb},
		driver:         drv,
	}
	respond := func(uc *types.UnicityCertificate) *certification.CertificationResponse {
		return &certification.CertificationResponse{
			Partition: authPartitionID, Shard: types.ShardID{}, Technical: *technicalFor(6), UC: *uc,
		}
	}

	// 1. First delivery: authenticated, observed, and it fails to apply — the payload is not there.
	err = client.handleCertificationResponse(ctx, respond(uc5))
	require.Error(t, err)
	require.ErrorContains(t, err, "unavailable in the executor",
		"unavailable is not invalid: this is the retryable case")
	require.Equal(t, 1, drv.count())
	require.NotNil(t, client.unapplied, "the certificate is observed but NOT applied, and that is recorded")
	require.Equal(t, uint64(5), client.luc.GetRoundNumber(), "the observation cursor did advance")
	require.Empty(t, sub.rounds(), "nothing may be signed from an unreconciled executor")

	// 2. A retransmission of the same certificate, still unavailable. This is the delivery that
	//    used to be dropped as a duplicate, taking the only retry route with it.
	err = client.handleCertificationResponse(ctx, respond(uc5))
	require.Error(t, err)
	require.Equal(t, 2, drv.count(), "a duplicate of an unapplied certificate is a retry, not a no-op")
	require.Empty(t, sub.rounds())

	// 3. The payload arrives (a resync completes, a peer serves the block). The next
	//    retransmission recovers to the EXACT certified head and the node votes again.
	exec.makeAvailable()
	require.NoError(t, client.handleCertificationResponse(ctx, respond(uc5)))
	require.Equal(t, 3, drv.count())
	require.Nil(t, client.unapplied, "applied: the retry marker is cleared")

	head, commits := exec.snapshot()
	require.Equal(t, b1, []byte(head.Hash), "P-id: recovery lands on the certified BLOCK")
	require.Equal(t, s1, []byte(head.StateRoot))
	require.Equal(t, []uint64{6}, sub.rounds(), "and exactly one round is signed")

	// 4. A further duplicate of the now-applied certificate is an ordinary no-op. Without this,
	//    the retry route would drive and sign a completed round again on every retransmission.
	require.NoError(t, client.handleCertificationResponse(ctx, respond(uc5)))
	require.Equal(t, 3, drv.count(), "a duplicate of an APPLIED certificate must not reach the driver")
	require.Equal(t, []uint64{6}, sub.rounds(), "and must not produce a second signature")
	_, commitsAfter := exec.snapshot()
	require.Equal(t, commits, commitsAfter, "nor touch the executor")
}

/*
TestDeliverySeparatesApplicationFromSending drives the real handler over a real Round through the
two failures that look alike from the outside and must not be treated alike.

An application failure means the certificate was not applied and the retransmission should retry it.
A SEND failure means it was applied and the next round's request did not reach the root chain — and
retrying that delivery would re-enter the round with a proposal the root chain has certified nothing
about, which is the path that finalised an uncertified block. The two are separated by
ErrSubmissionFailed.
*/
func TestDeliverySeparatesApplicationFromSending(t *testing.T) {
	ctx := context.Background()

	signer, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	tb, ok := testtrustbase.NewTrustBase(t, signer).(*types.RootTrustBaseV1)
	require.True(t, ok)
	pdr := &types.PartitionDescriptionRecord{Version: 1, NetworkID: 5, PartitionID: authPartitionID}
	zero := make([]byte, 32)

	s0 := bytes.Repeat([]byte{0xe0}, 32)
	s1 := bytes.Repeat([]byte{0xe1}, 32)
	b0 := bytes.Repeat([]byte{0xf0}, 32)
	b1 := bytes.Repeat([]byte{0xf1}, 32)

	technicalFor := func(round uint64) *certification.TechnicalRecord {
		return &certification.TechnicalRecord{Round: round, Epoch: 0, Leader: "send-node", StatHash: zero, FeeHash: zero}
	}
	trHash, err := technicalFor(6).Hash()
	require.NoError(t, err)
	// Round 5 certified the block this executor is already on, so the round applies cleanly and
	// the only thing that can fail is the send.
	ir5 := &types.InputRecord{
		Version: 1, RoundNumber: 5, PreviousHash: s0, Hash: s1, BlockHash: b1,
		SummaryValue: []byte{}, Timestamp: 1,
	}
	uc5 := testcertificates.CreateUnicityCertificate(t, signer, ir5, pdr, 41, zero, trHash)

	newFixture := func(sub Submitter) (*BFTClient, *countingDriver, *retryExecutor) {
		exec := &retryExecutor{
			head:      BlockRef{Number: 5, Hash: b1, StateRoot: s1},
			held:      map[string]BlockRef{string(b0): {Number: 4, Hash: b0, StateRoot: s0}},
			available: true,
		}
		round := NewRound("send-node", authPartitionID, types.ShardID{}, exec, NewLoopbackDisseminator(), signer, sub, nil)
		drv := &countingDriver{inner: round}
		return &BFTClient{
			partitionID:    authPartitionID,
			shardID:        types.ShardID{},
			nodeID:         "send-node",
			trustBaseStore: stubTrustBaseStore{tb: tb},
			driver:         drv,
		}, drv, exec
	}
	respond := func(uc *types.UnicityCertificate) *certification.CertificationResponse {
		return &certification.CertificationResponse{
			Partition: authPartitionID, Shard: types.ShardID{}, Technical: *technicalFor(6), UC: *uc,
		}
	}

	t.Run("a send failure leaves the certificate applied, so its duplicate is not re-driven", func(t *testing.T) {
		sub := &refusingSubmitter{}
		client, drv, exec := newFixture(sub)

		err := client.handleCertificationResponse(ctx, respond(uc5))
		require.ErrorIs(t, err, ErrSubmissionFailed)
		require.Equal(t, 1, drv.count())
		require.Nil(t, client.unapplied, "the certificate WAS applied; only the send failed")

		_, commits := exec.snapshot()
		sent := sub.requests()
		require.Len(t, sent, 3, "the same request is retried, bounded")
		for _, again := range sent[1:] {
			require.Equal(t, sent[0].Signature, again.Signature, "identical bytes, never a re-sign")
		}

		// The retransmission, which is what used to re-enter the round.
		require.NoError(t, client.handleCertificationResponse(ctx, respond(uc5)))
		require.Equal(t, 1, drv.count(), "a duplicate of an APPLIED certificate must not reach the driver")
		afterHead, afterCommits := exec.snapshot()
		require.Equal(t, commits, afterCommits, "and must not commit anything")
		require.Equal(t, b1, []byte(afterHead.Hash), "the executor is where the certificate left it")
		require.Len(t, sub.requests(), 3, "no second signed request for the same round")
	})

	t.Run("a persistence failure after a successful send is an application failure, and retrying it commits nothing uncertified", func(t *testing.T) {
		// persistingDriver saves the certificate after the driver returns. A failure there means
		// the round ran but the checkpoint did not survive, so the delivery is retried — and the
		// retry must not mistake the next round's proposal for something certified.
		sub := &countingSubmitter{}
		client, drv, exec := newFixture(sub)
		// A directory the process may enter but not write in: SaveLUC creates its directory if it
		// is missing, so an absent path is not a failure — an unwritable one is.
		roDir := filepath.Join(t.TempDir(), "read-only")
		require.NoError(t, os.Mkdir(roDir, 0o500))
		t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })
		client.driver = &persistingDriver{driver: drv, store: NewFileStore(filepath.Join(roDir, "luc.cbor"))}

		err := client.handleCertificationResponse(ctx, respond(uc5))
		require.ErrorContains(t, err, "persisting certificate")
		require.NotNil(t, client.unapplied, "the checkpoint is part of applying it")
		require.Equal(t, []uint64{6}, sub.rounds(), "the round was submitted before the store failed")

		_, commits := exec.snapshot()
		// The executor's next candidate would now be a DIFFERENT block — a transaction arrived
		// between the two deliveries, which is the ordinary case, not a contrived one.
		exec.queue([]byte("a transaction that arrived between the two deliveries"))
		first := sub.requests()[0]

		_ = client.handleCertificationResponse(ctx, respond(uc5))
		require.Equal(t, 2, drv.count(), "the duplicate retries the delivery, which is the point")
		_, afterCommits := exec.snapshot()
		require.Equal(t, commits, afterCommits,
			"the round-6 proposal is not certified by round 5's certificate and must not be committed")

		// And the part the previous revision missed: the retry must not REBUILD. Two different
		// signed input records for one round, under one authorizing certificate, is equivocation
		// however it came about — a full mempool between two deliveries is enough to produce it.
		sent := sub.requests()
		require.Len(t, sent, 2, "the identical request is re-sent")
		require.Equal(t, first.InputRecord.RoundNumber, sent[1].InputRecord.RoundNumber)
		require.Equal(t, []byte(first.InputRecord.Hash), []byte(sent[1].InputRecord.Hash),
			"the same round under the same certificate must produce the same input record")
		require.Equal(t, []byte(first.InputRecord.BlockHash), []byte(sent[1].InputRecord.BlockHash))
		require.Equal(t, first.Signature, sent[1].Signature, "and the same signature over it")
	})
}
