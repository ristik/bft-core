package recordwiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/certifiedstore"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// Outcome is what a restart established about the durable record and the executor. The outcomes are
// distinct situations with different answers, so none is folded into another.
type Outcome int

const (
	// OutcomeNoRecord: the store has no head record. Not durable-ready for anything.
	OutcomeNoRecord Outcome = iota
	// OutcomeRecordUntrusted: the head record is damaged, foreign, of an unknown version or does not
	// verify. No older retained record is used in its place.
	OutcomeRecordUntrusted
	// OutcomeExecutorUnavailable: the record verified, and the executor's head could not be read.
	OutcomeExecutorUnavailable
	// OutcomeExecutorBehind: the executor is below the recorded block. The record's certificate authorizes
	// committing that block; this unit does not issue that commit.
	OutcomeExecutorBehind
	// OutcomeExecutorAhead: the executor is above the recorded block, so the association for its newer head
	// was lost. Readiness needs that block's own record.
	OutcomeExecutorAhead
	// OutcomeExecutorDiverged: the executor holds another block at the recorded height. A fault.
	OutcomeExecutorDiverged
	// OutcomeDurableReady: the record verified and the executor's head is the recorded block by number, hash
	// and state root. This is durable readiness for B, not readiness for B's child, which also needs
	// continuity to the held certificate.
	OutcomeDurableReady
)

func (o Outcome) String() string {
	switch o {
	case OutcomeNoRecord:
		return "no-record"
	case OutcomeRecordUntrusted:
		return "record-untrusted"
	case OutcomeExecutorUnavailable:
		return "executor-unavailable"
	case OutcomeExecutorBehind:
		return "executor-behind"
	case OutcomeExecutorAhead:
		return "executor-ahead"
	case OutcomeExecutorDiverged:
		return "executor-diverged"
	case OutcomeDurableReady:
		return "durable-ready"
	default:
		return fmt.Sprintf("outcome(%d)", int(o))
	}
}

// ReloadResult is one reload, reported in full.
type ReloadResult struct {
	Outcome Outcome
	// Record is the re-verified head record; Record.BlockNumber etc. are meaningful only when HasRecord.
	Record    certifiedstore.Loaded
	HasRecord bool
	// Head is the executor's head, when it was read.
	Head shardnode.BlockRef
	// Err carries the refusal or failure behind every outcome other than OutcomeDurableReady.
	Err error
}

var (
	ErrExecutorBehind   = errors.New("recordwiring: the executor is behind the durable record")
	ErrExecutorAhead    = errors.New("recordwiring: the executor is ahead of the durable record")
	ErrExecutorDiverged = errors.New("recordwiring: the executor holds another block at the durable record's height")
)

/*
Reload is the restart sequence of the F6a contract §6: load and re-verify the head record under the
deployment's context, then compare the live executor's head with it by exact identity.

It reads and decides only. It never falls back to an older record, the legacy certificate file, the
executor's head or a zero cursor, it issues no executor call that changes finality, and it writes nothing.
*/
func Reload(ctx context.Context, store *certifiedstore.Store, d Deployment, executor shardnode.Executor) ReloadResult {
	if store == nil || !d.Valid() || executor == nil {
		return ReloadResult{Outcome: OutcomeRecordUntrusted, Err: errors.New("recordwiring: reload needs a store, a checked deployment and an executor")}
	}
	loaded, err := store.Load(ctx, d.StoreContext())
	switch {
	case errors.Is(err, certifiedstore.ErrNoRecord):
		return ReloadResult{Outcome: OutcomeNoRecord, Err: err}
	case err != nil:
		return ReloadResult{Outcome: OutcomeRecordUntrusted, Err: err}
	}
	res := ReloadResult{Record: loaded, HasRecord: true}

	head, err := executor.Head(ctx)
	if err != nil {
		res.Outcome, res.Err = OutcomeExecutorUnavailable, fmt.Errorf("%w: head: %w", ErrExecutorUnavailable, err)
		return res
	}
	res.Head = head
	number, hash, state := loaded.BlockNumber(), loaded.BlockHash(), loaded.StateRoot()
	switch {
	case head.Number < number:
		res.Outcome, res.Err = OutcomeExecutorBehind, fmt.Errorf("%w: executor at %d, record at %d", ErrExecutorBehind, head.Number, number)
	case head.Number > number:
		res.Outcome, res.Err = OutcomeExecutorAhead, fmt.Errorf("%w: executor at %d, record at %d", ErrExecutorAhead, head.Number, number)
	case !bytes.Equal(head.Hash, hash.Bytes()) || !bytes.Equal(head.StateRoot, state.Bytes()):
		res.Outcome, res.Err = OutcomeExecutorDiverged, fmt.Errorf("%w: height %d, executor hash %x state %x, record hash %s state %s",
			ErrExecutorDiverged, number, head.Hash, head.StateRoot, hash, state)
	default:
		res.Outcome = OutcomeDurableReady
	}
	return res
}
