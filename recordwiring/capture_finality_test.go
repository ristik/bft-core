package recordwiring_test

import (
	"context"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/recordwiring"
	"github.com/unicitynetwork/bft-core/shardnode"
)

func waitUntil(cond func() bool) bool {
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(time.Millisecond)
	}
	return true
}

// movingTrust runs move on every trust base lookup: publication verifies certificates after witness acquisition,
// so this moves the executor in the middle of that verification.
type movingTrust struct {
	shardnode.TrustBaseStore
	move func()
}

func (s *movingTrust) GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	if s.move != nil {
		s.move()
	}
	return s.TrustBaseStore.GetByEpoch(ctx, epoch)
}

// TestCapturePublicationIsSerializedWithFinality is P1 of the review of #162: the final head read and the store
// transaction happen under the node's finality gate, so a commit either waits for B's record to become durable
// or is seen by the head read, and an overtaken block is never published.
func TestCapturePublicationIsSerializedWithFinality(t *testing.T) {
	t.Run("the executor moved while the record was being verified", func(t *testing.T) {
		h := newCaptureHarness(t, 3)
		h.stop()
		h.publish(0, 1)
		prior, keys := h.head(), h.keys()
		cfg, genesisExec := configFor(t, h.c)
		trust := &movingTrust{TrustBaseStore: cfg.TrustBases}
		cfg.TrustBases = trust
		d, err := recordwiring.NewDeployment(context.Background(), cfg, genesisExec)
		require.NoError(t, err)
		h.exec.set(h.c.Blocks[2])
		trust.move = func() { h.exec.set(h.c.Blocks[3]) }

		results := make(chan recordwiring.CaptureResult, 4)
		c, err := recordwiring.NewCapturer(recordwiring.CaptureConfig{
			Deployment: d, Store: h.store, RPC: h.rpc, Executor: h.exec, Finality: h.gate,
			OnResult: func(r recordwiring.CaptureResult) { results <- r },
		})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = c.Run(ctx)
		}()
		defer func() {
			cancel()
			<-done
		}()

		c.ObserveCommit(h.commit(2))
		select {
		case r := <-results:
			require.Equal(t, recordwiring.CaptureExecutorMoved, r.Outcome, "%v", r.Err)
		case <-time.After(30 * time.Second):
			t.Fatal("no capture result")
		}
		require.Equal(t, prior, h.head())
		require.Equal(t, keys, h.keys())
	})

	t.Run("a commit arriving after the final head read waits until the record is durable", func(t *testing.T) {
		h := newCaptureHarness(t, 3)
		h.publish(0, 1)
		b2, b3 := h.c.Blocks[2], h.c.Blocks[3]
		h.exec.set(b2)

		type advance struct {
			durable common.Hash
			err     error
		}
		advanced := make(chan advance, 1)
		waited := make(chan bool, 1)
		h.exec.onHead(func() {
			go func() {
				release, err := h.gate.Hold(context.Background(), "round-commit")
				if err != nil {
					advanced <- advance{err: err}
					return
				}
				l, err := h.store.Load(context.Background(), h.d.StoreContext())
				h.exec.set(b3)
				release()
				advanced <- advance{durable: l.BlockHash(), err: err}
			}()
			waited <- waitUntil(func() bool { return h.gate.Waiting() == 1 })
		})

		h.cap.ObserveCommit(h.commit(2))
		r := h.next()
		require.Equal(t, recordwiring.CapturePublished, r.Outcome, "%v", r.Err)
		require.True(t, <-waited, "premise: the commit was waiting on the gate during publication")
		select {
		case a := <-advanced:
			require.NoError(t, a.err)
			require.Equal(t, b2.Hash, a.durable, "the commit proceeded only after B's record was durable")
		case <-time.After(30 * time.Second):
			t.Fatal("the commit never proceeded")
		}
		head, err := h.exec.Head(context.Background())
		require.NoError(t, err)
		require.Equal(t, b3.Hash.Bytes(), []byte(head.Hash))
	})

	t.Run("the store head changes after preparation", func(t *testing.T) {
		h := newCaptureHarness(t, 3)
		h.publish(0, 1)
		b2 := h.c.Blocks[2]
		h.exec.set(b2)
		release, err := h.gate.Hold(context.Background(), "round-commit")
		require.NoError(t, err)

		h.cap.ObserveCommit(h.commit(2))
		require.True(t, waitUntil(func() bool { return h.gate.Waiting() == 1 }), "premise: capture has prepared and waits for the gate")
		h.publish(2) // another publisher makes the same block the head meanwhile
		keys := h.keys()
		release()

		r := h.next()
		require.Equal(t, recordwiring.CaptureStale, r.Outcome, "%v", r.Err)
		require.ErrorIs(t, r.Err, certifiedstore.ErrHeadChanged)
		require.Equal(t, b2.Hash, h.head())
		require.Equal(t, keys, h.keys(), "the capture writes nothing over the head it did not decide against")
	})

	t.Run("a commit already holding the gate is seen by the final head read", func(t *testing.T) {
		h := newCaptureHarness(t, 3)
		h.publish(0, 1)
		prior, keys := h.head(), h.keys()
		h.exec.set(h.c.Blocks[2])
		release, err := h.gate.Hold(context.Background(), "round-commit")
		require.NoError(t, err)

		h.cap.ObserveCommit(h.commit(2))
		require.True(t, waitUntil(func() bool { return h.gate.Waiting() == 1 }), "premise: publication waits for the commit")
		h.exec.set(h.c.Blocks[3])
		release()

		r := h.next()
		require.Equal(t, recordwiring.CaptureExecutorMoved, r.Outcome, "%v", r.Err)
		require.Equal(t, prior, h.head())
		require.Equal(t, keys, h.keys())
	})
}
