package rootevidence

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/trustbase"
)

// DefaultQueue is the number of received votes the observer holds between the network and its worker.
const DefaultQueue = 1024

// Observer is the ingress tap of the evidence service. Offer is called with every decoded vote before any consensus filter; it never blocks
// and never fails the caller: the vote is queued for a single worker that verifies the signed statement and commits it to the journal. A full
// queue or a failed journal write is an explicit coverage gap (Gaps, Healthy), never an error of consensus and never a silent success.
type Observer struct {
	journal *Journal
	tbs     *trustbase.TrustBaseStore
	log     *slog.Logger
	queue   chan *abdrc.VoteMsg

	dropped  atomic.Uint64 // votes lost because the queue was full
	failed   atomic.Uint64 // statements that verified but could not be committed
	rejected atomic.Uint64 // votes without a verifying statement
	kept     atomic.Uint64
}

// NewObserver creates an observer over the journal. queue is the queue length (0 selects DefaultQueue).
func NewObserver(j *Journal, tbs *trustbase.TrustBaseStore, log *slog.Logger, queue int) *Observer {
	if queue <= 0 {
		queue = DefaultQueue
	}
	if log == nil {
		log = slog.Default()
	}
	return &Observer{journal: j, tbs: tbs, log: log, queue: make(chan *abdrc.VoteMsg, queue)}
}

// Offer queues a vote for observation. A nil observer ignores it, so the tap can stay in the consensus path unconditionally.
func (o *Observer) Offer(v *abdrc.VoteMsg) {
	if o == nil || v == nil {
		return
	}
	select {
	case o.queue <- v:
	default:
		o.dropped.Add(1)
	}
}

// Run processes the queue until the context ends.
func (o *Observer) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case v := <-o.queue:
			o.process(ctx, v)
		}
	}
}

func (o *Observer) process(ctx context.Context, v *abdrc.VoteMsg) {
	obs, err := Observe(v, o.tbs)
	if err != nil {
		o.rejected.Add(1)
		o.log.DebugContext(ctx, "vote statement not kept as evidence", "error", err)
		return
	}
	switch res, err := o.journal.Record(obs); {
	case err != nil:
		o.failed.Add(1)
		o.log.ErrorContext(ctx, "evidence journal write failed: coverage is incomplete", "error", err, "budget", errors.Is(err, ErrBudget))
	case res == Paired:
		o.kept.Add(1)
		o.log.WarnContext(ctx, "two different signed statements of one slot", "author", obs.Author, "epoch", obs.Epoch, "round", obs.Round)
	case res == Stored:
		o.kept.Add(1)
	}
}

// Stats are the observer's counters.
type Stats struct{ Kept, Rejected, Dropped, Failed uint64 }

// Stats returns the counters.
func (o *Observer) Stats() Stats {
	return Stats{Kept: o.kept.Load(), Rejected: o.rejected.Load(), Dropped: o.dropped.Load(), Failed: o.failed.Load()}
}

// Gaps is the number of votes the observer knows it did not capture: queue overflow and failed journal writes.
func (o *Observer) Gaps() uint64 {
	if o == nil {
		return 0
	}
	return o.dropped.Load() + o.failed.Load()
}

// Healthy is false once a gap exists; the export advertises it.
func (o *Observer) Healthy() bool { return o.Gaps() == 0 }
