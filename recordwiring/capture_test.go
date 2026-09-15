package recordwiring_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// witnessRPC is a JSON-RPC stand-in for the execution client's plain endpoint. It serves the chain's real
// headers and proofs by exact block hash, and records every call.
type witnessRPC struct {
	mu         sync.Mutex
	blocks     map[common.Hash]certifiedchain.Block
	missing    map[common.Hash]bool
	expired    map[common.Hash]bool
	substitute map[common.Hash]common.Hash
	gates      map[common.Hash]chan struct{}
	entered    chan common.Hash
	calls      []string
}

func newWitnessRPC(c *certifiedchain.Chain) *witnessRPC {
	r := &witnessRPC{
		blocks: map[common.Hash]certifiedchain.Block{}, missing: map[common.Hash]bool{}, expired: map[common.Hash]bool{},
		substitute: map[common.Hash]common.Hash{}, gates: map[common.Hash]chan struct{}{}, entered: make(chan common.Hash, 16),
	}
	for _, b := range c.Blocks {
		r.blocks[b.Hash] = b
	}
	return r
}

// gate makes acquisition of h wait, after announcing on entered, until the returned function is called.
func (r *witnessRPC) gate(h common.Hash) func() {
	ch := make(chan struct{})
	r.mu.Lock()
	r.gates[h] = ch
	r.mu.Unlock()
	return sync.OnceFunc(func() { close(ch) })
}

func (r *witnessRPC) callsFor(h common.Hash) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []string
	for _, c := range r.calls {
		if bytes.HasSuffix([]byte(c), []byte(h.Hex())) {
			out = append(out, c)
		}
	}
	return out
}

func (r *witnessRPC) Call(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	var h common.Hash
	switch method {
	case "debug_getRawHeader":
		h = params[0].(common.Hash)
	case "eth_getProof":
		h = params[2].(map[string]any)["blockHash"].(common.Hash)
	default:
		return nil, &registrywitness.RPCError{Code: -32601, Message: "method not found"}
	}
	r.mu.Lock()
	r.calls = append(r.calls, method+" "+h.Hex())
	gate, missing, expired := r.gates[h], r.missing[h], r.expired[h]
	served := h
	if s, ok := r.substitute[h]; ok {
		served = s
	}
	b, ok := r.blocks[served]
	r.mu.Unlock()

	if gate != nil && method == "debug_getRawHeader" {
		r.entered <- h
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if expired {
		return nil, &registrywitness.RPCError{Code: -32602, Message: "distance to target block exceeds maximum proof window"}
	}
	if missing || !ok {
		return json.RawMessage("null"), nil
	}
	if method == "debug_getRawHeader" {
		return json.Marshal(hexutil.Bytes(b.Evidence.Header))
	}
	res := registryproof.GetProofResult{Address: registryproof.RegistryAddress, AccountProof: hexNodes(b.Evidence.AccountProof)}
	for i := range registryproof.SlotNames {
		key := registryproof.SlotKey(i)
		res.StorageProof = append(res.StorageProof, registryproof.StorageProofResult{Key: hexutil.Encode(key[:]), Proof: hexNodes(b.Evidence.StorageProofs[i])})
	}
	return json.Marshal(res)
}

func hexNodes(in [][]byte) []hexutil.Bytes {
	out := make([]hexutil.Bytes, len(in))
	for i, n := range in {
		out[i] = n
	}
	return out
}

// headExecutor answers Head only. It embeds a nil Executor, so a Commit, Build or any other call panics the
// test: capture issues no executor action.
type headExecutor struct {
	shardnode.Executor
	mu    sync.Mutex
	head  shardnode.BlockRef
	err   error
	calls int
}

func (e *headExecutor) Head(context.Context) (shardnode.BlockRef, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.calls++
	return e.head, e.err
}

func (e *headExecutor) set(b certifiedchain.Block) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.head = ref(b)
}

type captureHarness struct {
	t       *testing.T
	c       *certifiedchain.Chain
	d       recordwiring.Deployment
	path    string
	store   *certifiedstore.Store
	rpc     *witnessRPC
	exec    *headExecutor
	cap     *recordwiring.Capturer
	results chan recordwiring.CaptureResult
	cancel  context.CancelFunc
	done    chan struct{}
	closed  bool
}

func newCaptureHarness(t *testing.T, blocks int) *captureHarness {
	c := certifiedchain.New(t, 3, blocks)
	h := &captureHarness{
		t: t, c: c, d: mustDeployment(t, c), path: filepath.Join(t.TempDir(), "certified.db"),
		rpc: newWitnessRPC(c), exec: &headExecutor{head: ref(c.Blocks[0])}, results: make(chan recordwiring.CaptureResult, 64),
	}
	s, err := recordwiring.OpenStore(h.path, 8)
	require.NoError(t, err)
	h.store = s
	h.cap, err = recordwiring.NewCapturer(recordwiring.CaptureConfig{
		Deployment: h.d, Store: s, RPC: h.rpc, Executor: h.exec, AcquireTimeout: 20 * time.Second,
		OnResult: func(r recordwiring.CaptureResult) { h.results <- r },
	})
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	h.cancel, h.done = cancel, make(chan struct{})
	go func() {
		defer close(h.done)
		_ = h.cap.Run(ctx)
	}()
	t.Cleanup(func() {
		h.stop()
		h.closeStore()
	})
	return h
}

func (h *captureHarness) stop() {
	h.cancel()
	<-h.done
}

func (h *captureHarness) closeStore() {
	if !h.closed {
		h.closed = true
		require.NoError(h.t, h.store.Close())
	}
}

// publish writes blocks directly, as an earlier capture would have.
func (h *captureHarness) publish(blocks ...int) {
	for _, i := range blocks {
		uc, tr := h.c.Certificate(i)
		b := h.c.Blocks[i]
		require.NoError(h.t, h.store.Publish(context.Background(), h.d.StoreContext(), certifiedstore.Record{
			BlockHash: b.Hash, BlockNumber: b.Number, StateRoot: b.StateRoot, PartitionRound: b.Round,
			Certificate: uc, Technical: tr, Witness: b.Evidence,
		}))
	}
}

func (h *captureHarness) commit(i int) shardnode.CertifiedCommit {
	return h.commitWith(i, h.c.Signer, nil)
}

// commitWith is the commit of block i with its input record or technical record changed and signed by signer.
func (h *captureHarness) commitWith(i int, signer abcrypto.Signer, change func(ir *types.InputRecord, tr *certification.TechnicalRecord)) shardnode.CertifiedCommit {
	b := h.c.Blocks[i]
	ir, tr := h.c.InputRecord(i), certifiedchain.Technical(b.Round)
	if change != nil {
		change(ir, tr)
	}
	return shardnode.CertifiedCommit{Certificate: h.c.Certify(signer, ir, tr, 4+b.Round), Technical: tr, BlockHash: b.Hash.Bytes()}
}

func (h *captureHarness) next() recordwiring.CaptureResult {
	select {
	case r := <-h.results:
		return r
	case <-time.After(30 * time.Second):
		h.t.Fatal("no capture result")
		return recordwiring.CaptureResult{}
	}
}

// resultsFor waits for n results and returns them by block hash.
func (h *captureHarness) resultsFor(n int) map[common.Hash]recordwiring.CaptureResult {
	out := map[common.Hash]recordwiring.CaptureResult{}
	for range n {
		r := h.next()
		out[r.Attempt.BlockHash] = r
	}
	return out
}

func (h *captureHarness) awaitEntered(want common.Hash) {
	select {
	case got := <-h.rpc.entered:
		require.Equal(h.t, want, got)
	case <-time.After(30 * time.Second):
		h.t.Fatal("acquisition did not start")
	}
}

func (h *captureHarness) head() common.Hash {
	l, err := h.store.Load(context.Background(), h.d.StoreContext())
	require.NoError(h.t, err)
	return l.BlockHash()
}

func (h *captureHarness) keys() []string {
	k, err := h.store.Keys()
	require.NoError(h.t, err)
	return k
}

func TestCapturePublishesEachCommittedBlock(t *testing.T) {
	h := newCaptureHarness(t, 2)
	h.publish(0)
	for _, i := range []int{1, 2} {
		b := h.c.Blocks[i]
		h.exec.set(b)
		h.cap.ObserveCommit(h.commit(i))
		r := h.next()
		require.Equal(t, recordwiring.CapturePublished, r.Outcome, "%v", r.Err)
		require.Equal(t, b.Hash, r.Attempt.BlockHash)
		require.Equal(t, b.Number, r.BlockNumber)

		l, err := h.store.Load(context.Background(), h.d.StoreContext())
		require.NoError(t, err)
		require.Equal(t, b.Hash, l.BlockHash())
		require.Equal(t, b.Number, l.BlockNumber())
		require.Equal(t, b.Round, l.PartitionRound())
		require.Equal(t, []string{"debug_getRawHeader " + b.Hash.Hex(), "eth_getProof " + b.Hash.Hex()}, h.rpc.callsFor(b.Hash),
			"witness(B) is requested by B's exact hash, once")
	}
	require.Equal(t, 2, h.exec.calls, "one head read per attempt, and no other executor call")
}

func TestCaptureFailuresKeepThePriorRecord(t *testing.T) {
	stranger, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)

	cases := map[string]struct {
		prior   []int
		arrange func(h *captureHarness) shardnode.CertifiedCommit
		want    recordwiring.CaptureOutcome
		wantErr error
	}{
		"the client does not have the witness": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.rpc.missing[h.c.Blocks[2].Hash] = true
			h.exec.set(h.c.Blocks[2])
			return h.commit(2)
		}, recordwiring.CaptureWitnessUnavailable, registrywitness.ErrUnavailable},
		"the block is behind the client's proof window": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.rpc.expired[h.c.Blocks[2].Hash] = true
			h.exec.set(h.c.Blocks[2])
			return h.commit(2)
		}, recordwiring.CaptureWitnessUnavailable, registrywitness.ErrUnavailable},
		"the client answers with another block's witness": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.rpc.substitute[h.c.Blocks[2].Hash] = h.c.Blocks[1].Hash
			h.exec.set(h.c.Blocks[2])
			return h.commit(2)
		}, recordwiring.CaptureWitnessInvalid, registrywitness.ErrInvalid},
		"the certificate names another round than the witness executed": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.exec.set(h.c.Blocks[2])
			return h.commitWith(2, h.c.Signer, func(ir *types.InputRecord, tr *certification.TechnicalRecord) {
				ir.RoundNumber, tr.Round = 9, 10
			})
		}, recordwiring.CaptureWitnessMismatch, recordwiring.ErrWitnessMismatch},
		"the certificate names another state than the witness proves": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.exec.set(h.c.Blocks[2])
			return h.commitWith(2, h.c.Signer, func(ir *types.InputRecord, _ *certification.TechnicalRecord) {
				ir.Hash = bytes.Repeat([]byte{0x07}, 32)
			})
		}, recordwiring.CaptureWitnessMismatch, recordwiring.ErrWitnessMismatch},
		"the executor's head cannot be read": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.exec.err = errors.New("connection refused")
			return h.commit(2)
		}, recordwiring.CaptureExecutorUnavailable, recordwiring.ErrExecutorUnavailable},
		"the executor is no longer at the block": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.exec.set(h.c.Blocks[3])
			return h.commit(2)
		}, recordwiring.CaptureExecutorMoved, recordwiring.ErrExecutorMoved},
		// One identity field differs in each of the next three, so each comparison is needed on its own.
		"the executor holds another block at the same height and state": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			other := h.c.ExecutedWith(h.c.Blocks[1], 2, 6, []byte("another block at height 2"))
			require.Equal(h.t, h.c.Blocks[2].StateRoot, other.StateRoot, "premise: same state, another block")
			require.NotEqual(h.t, h.c.Blocks[2].Hash, other.Hash)
			h.exec.set(other)
			return h.commit(2)
		}, recordwiring.CaptureExecutorMoved, recordwiring.ErrExecutorMoved},
		"the executor reports the block's hash and state at another number": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.exec.set(h.c.Blocks[2])
			h.exec.head.Number = 3
			return h.commit(2)
		}, recordwiring.CaptureExecutorMoved, recordwiring.ErrExecutorMoved},
		"the executor reports the block's hash and number at another state": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.exec.set(h.c.Blocks[2])
			h.exec.head.StateRoot = h.c.Blocks[1].StateRoot.Bytes()
			return h.commit(2)
		}, recordwiring.CaptureExecutorMoved, recordwiring.ErrExecutorMoved},
		"a later record is already durable": {[]int{0, 1, 2, 3}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.exec.set(h.c.Blocks[2])
			return h.commit(2)
		}, recordwiring.CaptureStale, certifiedstore.ErrStaleRecord},
		"the store refuses the record": {[]int{0, 1}, func(h *captureHarness) shardnode.CertifiedCommit {
			h.exec.set(h.c.Blocks[2])
			return h.commitWith(2, stranger, nil)
		}, recordwiring.CapturePublishFailed, certifiedstore.ErrCertificate},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			h := newCaptureHarness(t, 3)
			h.publish(tc.prior...)
			prior, keys := h.head(), h.keys()
			commit := tc.arrange(h)

			h.cap.ObserveCommit(commit)
			r := h.next()
			require.Equal(t, tc.want, r.Outcome, "%v", r.Err)
			require.ErrorIs(t, r.Err, tc.wantErr)
			require.Equal(t, prior, h.head(), "the prior record stays the head")
			require.Equal(t, keys, h.keys(), "nothing is written or deleted")
		})
	}

	t.Run("the store fails", func(t *testing.T) {
		h := newCaptureHarness(t, 2)
		h.publish(0, 1)
		h.closeStore()
		h.exec.set(h.c.Blocks[2])
		h.cap.ObserveCommit(h.commit(2))
		r := h.next()
		require.Equal(t, recordwiring.CapturePublishFailed, r.Outcome, "%v", r.Err)

		s, err := recordwiring.OpenStore(h.path, 8)
		require.NoError(t, err)
		defer func() { require.NoError(t, s.Close()) }()
		l, err := s.Load(context.Background(), h.d.StoreContext())
		require.NoError(t, err)
		require.Equal(t, h.c.Blocks[1].Hash, l.BlockHash())
	})

	t.Run("the proof window message is reported", func(t *testing.T) {
		h := newCaptureHarness(t, 2)
		h.publish(0, 1)
		h.rpc.expired[h.c.Blocks[2].Hash] = true
		h.exec.set(h.c.Blocks[2])
		h.cap.ObserveCommit(h.commit(2))
		require.ErrorContains(t, h.next().Err, "proof window")
	})
}

func TestCaptureDuplicateDeliveryAcquiresOnce(t *testing.T) {
	h := newCaptureHarness(t, 2)
	h.publish(0)

	h.exec.set(h.c.Blocks[1])
	h.cap.ObserveCommit(h.commit(1))
	require.Equal(t, recordwiring.CapturePublished, h.next().Outcome)
	h.cap.ObserveCommit(h.commit(1))
	r := h.next()
	require.Equal(t, recordwiring.CaptureDuplicate, r.Outcome, "a re-delivery after publication")
	require.Len(t, h.rpc.callsFor(h.c.Blocks[1].Hash), 2)

	release := h.rpc.gate(h.c.Blocks[2].Hash)
	h.exec.set(h.c.Blocks[2])
	h.cap.ObserveCommit(h.commit(2))
	h.awaitEntered(h.c.Blocks[2].Hash)
	h.cap.ObserveCommit(h.commit(2))
	r = h.next()
	require.Equal(t, recordwiring.CaptureDuplicate, r.Outcome, "a re-delivery while the block is in flight")
	release()
	require.Equal(t, recordwiring.CapturePublished, h.next().Outcome)
	require.Len(t, h.rpc.callsFor(h.c.Blocks[2].Hash), 2, "the witness is acquired once")
	require.Equal(t, h.c.Blocks[2].Hash, h.head())
}

func TestCaptureWhileTheNodeAdvances(t *testing.T) {
	t.Run("the executor commits the next block while capture is in flight", func(t *testing.T) {
		h := newCaptureHarness(t, 3)
		h.publish(0, 1)
		b2, b3 := h.c.Blocks[2], h.c.Blocks[3]
		release := h.rpc.gate(b2.Hash)
		h.exec.set(b2)
		h.cap.ObserveCommit(h.commit(2))
		h.awaitEntered(b2.Hash)
		h.exec.set(b3)
		h.cap.ObserveCommit(h.commit(3))
		release()

		got := h.resultsFor(2)
		require.Equal(t, recordwiring.CaptureExecutorMoved, got[b2.Hash].Outcome, "%v", got[b2.Hash].Err)
		require.Equal(t, recordwiring.CapturePublished, got[b3.Hash].Outcome, "%v", got[b3.Hash].Err)
		require.Equal(t, b3.Hash, h.head())
		require.NotContains(t, h.keys(), fmt.Sprintf("record/%020d/%x", b2.Round, b2.Hash.Bytes()), "the overtaken block is not published")
	})

	t.Run("newer committed blocks replace a pending attempt", func(t *testing.T) {
		h := newCaptureHarness(t, 4)
		h.publish(0, 1)
		b2, b3, b4 := h.c.Blocks[2], h.c.Blocks[3], h.c.Blocks[4]
		release := h.rpc.gate(b2.Hash)
		h.exec.set(b2)
		h.cap.ObserveCommit(h.commit(2))
		h.awaitEntered(b2.Hash)
		h.cap.ObserveCommit(h.commit(3))
		h.exec.set(b4)
		h.cap.ObserveCommit(h.commit(4))
		require.Equal(t, recordwiring.CaptureSuperseded, h.next().Outcome)
		release()

		got := h.resultsFor(2)
		require.Equal(t, recordwiring.CaptureExecutorMoved, got[b2.Hash].Outcome)
		require.Equal(t, recordwiring.CapturePublished, got[b4.Hash].Outcome, "%v", got[b4.Hash].Err)
		require.Empty(t, h.rpc.callsFor(b3.Hash), "a superseded attempt acquires nothing")
		require.Equal(t, b4.Hash, h.head())
	})

	t.Run("an older commit delivered after a newer one is pending", func(t *testing.T) {
		h := newCaptureHarness(t, 4)
		h.publish(0, 1)
		b2, b3, b4 := h.c.Blocks[2], h.c.Blocks[3], h.c.Blocks[4]
		release := h.rpc.gate(b3.Hash)
		h.exec.set(b3)
		h.cap.ObserveCommit(h.commit(3))
		h.awaitEntered(b3.Hash)
		h.cap.ObserveCommit(h.commit(4))
		h.cap.ObserveCommit(h.commit(2))
		r := h.next()
		require.Equal(t, recordwiring.CaptureSuperseded, r.Outcome)
		require.Equal(t, b2.Hash, r.Attempt.BlockHash)
		h.exec.set(b4)
		release()

		got := h.resultsFor(2)
		require.Equal(t, recordwiring.CaptureExecutorMoved, got[b3.Hash].Outcome)
		require.Equal(t, recordwiring.CapturePublished, got[b4.Hash].Outcome, "%v", got[b4.Hash].Err)
		require.Empty(t, h.rpc.callsFor(b2.Hash))
		require.Equal(t, b4.Hash, h.head())
	})
}

func TestCaptureAcrossRestart(t *testing.T) {
	reloadAfter := func(t *testing.T, h *captureHarness, at certifiedchain.Block) recordwiring.ReloadResult {
		h.stop()
		h.closeStore()
		s, err := recordwiring.OpenStore(h.path, 8)
		require.NoError(t, err)
		defer func() { require.NoError(t, s.Close()) }()
		return recordwiring.Reload(context.Background(), s, h.d, &stubExecutor{genesis: ref(h.c.Blocks[0]), head: ref(at)})
	}

	t.Run("stopped before publication", func(t *testing.T) {
		h := newCaptureHarness(t, 3)
		h.publish(0, 1)
		b2 := h.c.Blocks[2]
		h.rpc.gate(b2.Hash)
		h.exec.set(b2)
		h.cap.ObserveCommit(h.commit(2))
		h.awaitEntered(b2.Hash)
		h.cap.ObserveCommit(h.commit(3))

		res := reloadAfter(t, h, b2)
		got := h.resultsFor(2)
		require.Equal(t, recordwiring.CaptureStopped, got[b2.Hash].Outcome, "%v", got[b2.Hash].Err)
		require.Equal(t, recordwiring.CaptureStopped, got[h.c.Blocks[3].Hash].Outcome, "the pending attempt is reported")
		require.Equal(t, recordwiring.OutcomeExecutorAhead, res.Outcome, "the executor applied a block whose record was never published")
		require.Equal(t, h.c.Blocks[1].Hash, res.Record.BlockHash())
	})

	t.Run("stopped after publication", func(t *testing.T) {
		h := newCaptureHarness(t, 2)
		h.publish(0, 1)
		b2 := h.c.Blocks[2]
		h.exec.set(b2)
		h.cap.ObserveCommit(h.commit(2))
		require.Equal(t, recordwiring.CapturePublished, h.next().Outcome)

		res := reloadAfter(t, h, b2)
		require.Equal(t, recordwiring.OutcomeDurableReady, res.Outcome, "%v", res.Err)
		require.Equal(t, b2.Hash, res.Record.BlockHash())
	})
}

func TestCaptureRefusesAMalformedCommit(t *testing.T) {
	h := newCaptureHarness(t, 2)
	commit := h.commit(2)
	commit.BlockHash = h.c.Blocks[1].Hash.Bytes()
	h.cap.ObserveCommit(commit)
	r := h.next()
	require.Equal(t, recordwiring.CaptureMalformed, r.Outcome)
	h.cap.ObserveCommit(shardnode.CertifiedCommit{})
	require.Equal(t, recordwiring.CaptureMalformed, h.next().Outcome)
	require.Empty(t, h.rpc.callsFor(h.c.Blocks[1].Hash))
	require.Empty(t, h.rpc.callsFor(h.c.Blocks[2].Hash))
}
