package consensus

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/logger"
	"github.com/unicitynetwork/bft-core/monitoring"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
	"github.com/unicitynetwork/bft-core/vradmit"
)

// A refused handoff record must not stall the root chain (#1306). A leader trial-executes every proposal that orders a handoff record before
// it signs it; when its own executor refuses the record, it leaves the record out and proposes an ordinary block instead. A refusal every
// honest root reaches on the same parent (deterministic) is remembered per handoff identity and record kind, so the leader neither orders
// nor trial-executes it again; a refusal of an input this root lacks (local) drops the record for that round only. The memory is
// leader-local proposal hygiene: voters judge every block by the unchanged executor and consult it never, so a root that wrongly holds an
// output refused can only drop its own proposals of it. Nothing is persisted: after a restart the first leader round finds the refusal again.

// The refusal classes (the class label of unicity_root_handoff_refused_total).
const (
	handoffRefusedDeterministic = "deterministic"
	handoffRefusedLocal         = "local"
)

// maxHandoffRefusals bounds the memory: each intent contributes at most a Prepare or a Freeze and its Commit, and entries of a dead intent
// are pruned.
const maxHandoffRefusals = 8

// HandoffRefused is one remembered refusal, as the status reports it.
type HandoffRefused struct {
	Kind    string // the record kind: prepare, freeze, commit or abort
	Epoch   uint64
	Attempt uint64
	Body    [32]byte // the successor body the record names
	// Intent and Result are the VR intent digest and election result, when the refused record is of the VR plan this root holds
	Intent     [32]byte
	Result     [32]byte
	Reason     string
	FirstRound uint64
	LastRound  uint64
	Count      uint64 // the rounds this leader left the record out
}

// handoffRefusalKey is a handoff identity (network, epoch, predecessor, attempt, successor body) and a record kind. A later attempt, another
// epoch or another body (a candidate of another view) is another key, judged once again.
type handoffRefusalKey struct {
	id   [32]byte
	kind string
}

func refusalKey(network, epoch uint64, predecessor []byte, attempt uint64, body []byte, kind string) handoffRefusalKey {
	h := sha256.New()
	var w [8]byte
	for _, v := range []uint64{network, epoch, attempt} {
		binary.BigEndian.PutUint64(w[:], v)
		h.Write(w[:])
	}
	binary.BigEndian.PutUint64(w[:], uint64(len(predecessor)))
	h.Write(w[:])
	h.Write(predecessor)
	h.Write(body)
	var k handoffRefusalKey
	copy(k.id[:], h.Sum(nil))
	k.kind = kind
	return k
}

func recordRefusalKey(r evmroot.OrderedHandoffRecord) handoffRefusalKey {
	return refusalKey(r.Network, r.Epoch, r.PredecessorBodyID, r.Attempt, r.NextBodyID, r.Kind)
}

type handoffRefusals struct {
	mu sync.Mutex
	m  map[handoffRefusalKey]*HandoffRefused
	// logged are the keys of the local refusals already logged at warning level (a local refusal is retried every round, logged once)
	logged map[handoffRefusalKey]struct{}
}

// firstLocal reports whether a local refusal of the key is seen for the first time (bounded: an overfull set starts again).
func (h *handoffRefusals) firstLocal(k handoffRefusalKey) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.logged[k]; ok {
		return false
	}
	if h.logged == nil || len(h.logged) >= 4*maxHandoffRefusals {
		h.logged = map[handoffRefusalKey]struct{}{}
	}
	h.logged[k] = struct{}{}
	return true
}

// seen reports whether the key is remembered, counting the round it is left out in.
func (h *handoffRefusals) seen(k handoffRefusalKey, round uint64) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.m[k]
	if ok && round > e.LastRound {
		e.LastRound = round
		e.Count++
	}
	return ok
}

// add remembers a refusal; false when it was already remembered.
func (h *handoffRefusals) add(k handoffRefusalKey, e HandoffRefused) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.m[k]; ok {
		return false
	}
	if h.m == nil {
		h.m = map[handoffRefusalKey]*HandoffRefused{}
	}
	for len(h.m) >= maxHandoffRefusals {
		var oldest handoffRefusalKey
		first := true
		for key, v := range h.m {
			if first || v.LastRound < h.m[oldest].LastRound {
				oldest, first = key, false
			}
		}
		delete(h.m, oldest)
	}
	h.m[k] = &e
	return true
}

// prune drops the entries drop reports dead.
func (h *handoffRefusals) prune(drop func(*HandoffRefused) bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, e := range h.m {
		if drop(e) {
			delete(h.m, k)
		}
	}
}

func (h *handoffRefusals) reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.m, h.logged = nil, nil
}

func (h *handoffRefusals) len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.m)
}

func (h *handoffRefusals) list() []HandoffRefused {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]HandoffRefused, 0, len(h.m))
	for _, e := range h.m {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].FirstRound < out[j].FirstRound })
	return out
}

// HandoffRefusals are the handoff records this root's leader rounds leave out as refused (#1306): what the q3 status reports.
func (x *ConsensusManager) HandoffRefusals() []HandoffRefused { return x.refused.list() }

// handoffRefusalClass tells a refusal every honest root reaches on the same parent (registry-mode admission, a Freeze v5 that does not match
// the derived intent, any other refusal of the record by the executor's rules) from one this root cannot judge yet: VR input or a witness it
// lacks, an acknowledgement still pending. An error of no known kind is local: it costs one trial a round, never a memory.
func handoffRefusalClass(err error) string {
	switch {
	case errors.Is(err, storage.ErrVRUnavailable), errors.Is(err, storage.ErrWitnessUnavailable), errors.Is(err, storage.ErrNoWitnessStore),
		errors.Is(err, storage.ErrAssignmentAckPending):
		return handoffRefusedLocal
	case errors.Is(err, vradmit.ErrAdmission), errors.Is(err, storage.ErrVRFreeze):
		return handoffRefusedDeterministic
	}
	return handoffRefusedLocal
}

// refusedHandoff reports whether the proposal's handoff records are a remembered refusal; the leader then leaves them out without a trial.
func (x *ConsensusManager) refusedHandoff(records [][]byte, round uint64) bool {
	if len(records) == 0 {
		return false
	}
	r, err := storage.DecodeOrderedHandoffRecord(records[0])
	if err != nil {
		return false
	}
	return x.refused.seen(recordRefusalKey(r), round)
}

// admitOwnHandoff trial-executes the leader's block that orders handoff records, before it is signed, on the parent's state exactly as every
// voter will (#1306). It reports whether the records stay in the proposal; a refusal is noted (and remembered when deterministic) and the
// caller proposes an ordinary block instead.
func (x *ConsensusManager) admitOwnHandoff(ctx context.Context, block *drctypes.BlockData) bool {
	trial := x.handoffTrial
	if trial == nil {
		trial = func(b *drctypes.BlockData) error { return x.blockStore().TrialExecute(b, x.irReqVerifier) }
	}
	err := trial(block)
	if err == nil {
		return true
	}
	r, derr := storage.DecodeOrderedHandoffRecord(block.Payload.HandoffRecords[0])
	if derr != nil {
		x.log.WarnContext(ctx, "root handoff: the leader leaves out a record its own executor refuses", "round", block.Round, logger.Error(err))
		x.noteHandoffRefusedMetric("unknown", handoffRefusedLocal)
		return false
	}
	x.noteHandoffRefused(ctx, recordRefusalKey(r), r.Kind, r.Epoch, r.Attempt, r.NextBodyID, block.Round, err)
	return false
}

// noteHandoffRefused logs, counts and (for a deterministic refusal) remembers that this leader leaves out the handoff step of the key. Either
// is logged at warning level once per key (a Commit at error level: an endorsed Freeze has no lapse, the EVM stays frozen until an old-set
// Abort), a repeated local one at debug level.
func (x *ConsensusManager) noteHandoffRefused(ctx context.Context, key handoffRefusalKey, kind string, epoch, attempt uint64, body []byte, round uint64, err error) {
	class := handoffRefusalClass(err)
	x.noteHandoffRefusedMetric(kind, class)
	e := HandoffRefused{Kind: kind, Epoch: epoch, Attempt: attempt, Reason: err.Error(), FirstRound: round, LastRound: round, Count: 1}
	copy(e.Body[:], body)
	if x.vr != nil && x.vr.svc != nil {
		if p, ok := x.vr.svc.Prepared(); ok && p.Attempt == attempt && p.Body.Identity() == e.Body {
			e.Intent, e.Result = p.Intent, p.Result
		}
	}
	attrs := []any{"round", round, "kind", kind, "epoch", epoch, "attempt", attempt, "body", fmt.Sprintf("%x", e.Body[:8]), "class", class}
	if e.Intent != ([32]byte{}) {
		attrs = append(attrs, "intent", fmt.Sprintf("%x", e.Intent[:8]), "result", fmt.Sprintf("%x", e.Result[:]))
	}
	attrs = append(attrs, logger.Error(err))
	level := slog.LevelWarn
	if kind == "commit" {
		level = slog.LevelError
	}
	if class != handoffRefusedDeterministic {
		if !x.refused.firstLocal(key) {
			level = slog.LevelDebug
		}
		x.log.Log(ctx, level, "root handoff: the leader leaves out a record this root cannot judge yet, this round only", attrs...)
		return
	}
	if !x.refused.add(key, e) {
		return
	}
	x.log.With(attrs...).Log(ctx, level, "VR handoff: the leader leaves out a refused "+kind, monitoring.Event(monitoring.EvVRHandoffRefused))
}

func (x *ConsensusManager) noteHandoffRefusedMetric(kind, class string) {
	if x.handoffRefusedCnt != nil {
		x.handoffRefusedCnt.WithLabelValues(kind, class).Inc()
	}
}

// pruneHandoffRefusals drops the refusals of a dead intent: another epoch, a passed attempt, or (on a VR chain) an intent this root no longer
// holds the certificate of.
func (x *ConsensusManager) pruneHandoffRefusals(control *evmroot.ControlState) {
	if control == nil || x.refused.len() == 0 {
		return
	}
	var held *[32]byte
	if x.vr != nil && x.vr.svc != nil {
		if p, ok := x.vr.svc.Prepared(); ok {
			held = &p.Intent
		} else {
			held = &[32]byte{}
		}
	}
	x.refused.prune(func(e *HandoffRefused) bool {
		if e.Epoch != control.Epoch || e.Attempt < control.Attempt {
			return true
		}
		return held != nil && e.Intent != ([32]byte{}) && e.Intent != *held
	})
}
