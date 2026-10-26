package archivewiring

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// FrontierWorker advances only over contiguous, certified journal entries.
// Publication and certification have their own independent loops.
type FrontierWorker struct {
	Journal  *configuredprogress.Store
	Context  configuredprogress.Context
	Limits   configuredprogress.JournalLimits
	Archive  *archive.Store
	Subject  archive.Context
	Replicas []peer.ID
	// PolicyDigest, when set, binds new frontier records to the archive policy that selected Replicas (two or three, canonical order):
	// each record then names the two replicas that actually hold a verified copy. Zero keeps the legacy two-replica records, for
	// exactly two Replicas.
	PolicyDigest    [32]byte
	Host            shardnode.EvidenceHost
	TransportLimits Limits
	Log             *slog.Logger
	// Finalized bounds pruning to the execution head this node has actually
	// committed. An archive copy can arrive before local EL finality does.
	Finalized          func(context.Context) (shardnode.BlockRef, error)
	auditCursor        uint64
	lastCapacityWarn   time.Time
	lastNoProgressWarn time.Time
	// advancing serializes frontier advances: the worker's own passes and Advance from a long catch-up (#769) would otherwise
	// invalidate each other's planned coverage (frontier.ErrStale) on every pass.
	advancing sync.Mutex
}

// passCoverage is how many blocks one worker pass covers; busyPassCoverage while the journal is at least publisherBusyPercent full. A pass every two
// seconds at four blocks covers two blocks a second, which is about what a transaction burst produces: a journal that is already behind (after a restart
// every block is pending again) then never catches up and fills (bft-core#876).
const (
	passCoverage     = 4
	busyPassCoverage = 16
)

func (w *FrontierWorker) Run(ctx context.Context) error {
	if w.Log == nil {
		w.Log = slog.New(slog.DiscardHandler)
	}
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		if err := w.Pass(ctx); err != nil && ctx.Err() == nil {
			w.Log.WarnContext(ctx, "certified frontier waiting", "err", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Pass runs one pass and, at debug level, logs how long each step took (bft-core#728 trace: whether failing passes keep the journal store busy).
func (w *FrontierWorker) Pass(ctx context.Context) error {
	start, last := time.Now(), time.Now()
	var steps []slog.Attr
	mark := func(name string) {
		now := time.Now()
		steps = append(steps, slog.Duration(name, now.Sub(last)))
		last = now
	}
	err := w.pass(ctx, mark)
	if w.Log != nil {
		attrs := append([]slog.Attr{slog.Duration("total", time.Since(start))}, steps...)
		if err != nil {
			attrs = append(attrs, slog.String("err", err.Error()))
		}
		w.Log.LogAttrs(ctx, slog.LevelDebug, "archive: frontier worker pass", attrs...)
	}
	return err
}

func (w *FrontierWorker) pass(ctx context.Context, mark func(string)) error {
	if w.Journal == nil || w.Archive == nil || !validReplicas(w.Replicas) || w.PolicyDigest == ([32]byte{}) && len(w.Replicas) != 2 {
		return ErrConfig
	}
	err := w.audit(ctx)
	mark("audit")
	if err != nil {
		return err
	}
	return w.advance(ctx, mark, passCoverage)
}

// Advance covers and prunes up to max consecutive certified blocks above the frontier, as a pass does after its audit, under the same
// rules: each block at or below local execution finality, retained receipt-complete in the local archive, and read back verified from
// two replicas. A long catch-up (#769) calls it after each admitted page so that the journal stays inside its limits. It does not
// advance past a block it cannot cover; that is not an error unless no block is covered and the first one is missing.
func (w *FrontierWorker) Advance(ctx context.Context, max int) error {
	if w.Journal == nil || w.Archive == nil || !validReplicas(w.Replicas) || w.PolicyDigest == ([32]byte{}) && len(w.Replicas) != 2 || max <= 0 {
		return ErrConfig
	}
	return w.advance(ctx, func(string) {}, max)
}

func (w *FrontierWorker) advance(ctx context.Context, mark func(string), max int) error {
	w.advancing.Lock()
	defer w.advancing.Unlock()
	err := w.Journal.VerifyFrontierCopies(ctx, w.Context, w.Limits)
	mark("verifyCopies")
	if err != nil {
		return err
	}
	// A crash after the frontier commit but before prune leaves this work for
	// the next pass. Prune itself is idempotent.
	if f, err := w.Journal.LoadFrontier(ctx, w.Context, w.Limits); err != nil {
		return err
	} else if f.Anchor != nil && f.Floor < f.Anchor.Height && !f.Anchor.Migrated() {
		if err := w.Journal.PruneFrontier(ctx, w.Context, w.Limits); err != nil {
			return err
		}
	}
	image, err := w.Journal.LoadJournal(ctx, w.Context, w.Limits)
	if err != nil {
		return err
	}
	w.warnCapacity(ctx, image)
	if max == passCoverage {
		usage := JournalUsage{CandidatesUsed: len(image.Candidates), CandidatesCap: w.Limits.Candidates, ObservationsUsed: len(image.Observations),
			ObservationsCap: w.Limits.Observations, BytesUsed: image.Bytes, BytesCap: w.Limits.Bytes}
		if usage.Percent() >= publisherBusyPercent {
			max = busyPassCoverage
		}
	}
	var finalized shardnode.BlockRef
	if w.Finalized != nil {
		finalized, err = w.Finalized(ctx)
		if err != nil {
			return fmt.Errorf("reading local execution finality before pruning: %w", err)
		}
	}
	height, sequence, epoch, round := uint64(0), uint64(0), w.Subject.RootEpoch, uint64(0)
	if image.Frontier != nil && image.Frontier.Anchor != nil {
		height, sequence, round = image.Frontier.Anchor.Height, image.Frontier.Anchor.Sequence, image.Frontier.Anchor.Round
		if image.Frontier.Anchor.Epoch != 0 {
			epoch = image.Frontier.Anchor.Epoch
		}
	} else if image.Restored != nil {
		height, round = image.Restored.Height, image.Restored.RootRound
		for _, entry := range image.Candidates {
			if entry.Certified && entry.Candidate.Number == height {
				epoch = entry.ResultingUC.GetRootEpoch()
				break
			}
		}
	}
	var covered []frontier.Coverage
	stopped := "no certified block above the frontier anchor"
	availability := ReplicaAvailability{Context: ctx, Host: w.Host, Replicas: w.Replicas, Limits: w.TransportLimits}
	unreachable := make(map[int]bool) // replicas that failed a read-back in this pass: not asked again for later blocks
	for _, entry := range certifiedEntries(image) {
		if entry.Candidate.Number <= height {
			continue
		}
		stopped = fmt.Sprintf("block %d is the first above the frontier anchor %d", entry.Candidate.Number, height)
		if w.Finalized != nil && entry.Candidate.Number > finalized.Number {
			stopped = fmt.Sprintf("block %d is above local execution finality %d", entry.Candidate.Number, finalized.Number)
			break
		}
		if w.Finalized != nil && entry.Candidate.Number == finalized.Number && !bytes.Equal(entry.Candidate.Hash, finalized.Hash) {
			return ErrBinding
		}
		if entry.Candidate.Number != height+1 || entry.ResultingUC.GetRootEpoch() < epoch || entry.ResultingUC.GetRootEpoch() == epoch && entry.ResultingUC.GetRootRoundNumber() <= round {
			stopped = fmt.Sprintf("block %d does not follow the frontier anchor %d (root position %d/%d against the anchor's %d/%d)", entry.Candidate.Number, height, entry.ResultingUC.GetRootEpoch(), entry.ResultingUC.GetRootRoundNumber(), epoch, round)
			break
		}
		var hash, state [32]byte
		copy(hash[:], entry.Candidate.Hash)
		copy(state[:], entry.Candidate.StateRoot)
		q := archive.Request{Context: w.Subject, BlockHash: hash}
		rec, err := w.Archive.GetReceiptComplete(q)
		if err != nil {
			if errors.Is(err, archive.ErrUnavailable) {
				if len(covered) == 0 {
					return fmt.Errorf("%w: receipt-complete archive record missing for block %x", archive.ErrUnavailable, q.BlockHash)
				}
				stopped = fmt.Sprintf("block %d has no receipt-complete local archive record", entry.Candidate.Number)
				break
			}
			return err
		}
		_, expected, err := FromJournal(ctx, w.Context, w.Subject, nil, entry)
		if err != nil {
			return err
		}
		if !SameArchiveCore(q, rec, expected) {
			return ErrBinding
		}
		digest, err := archive.ManifestDigest(q, rec)
		if err != nil {
			return err
		}
		request, err := archive.EncodeRequest(q)
		if err != nil {
			return err
		}
		ack := sha256.Sum256(request)
		holders, err := w.holders(availability, q, digest, unreachable)
		if err != nil {
			if len(covered) == 0 {
				return err
			}
			stopped = fmt.Sprintf("block %d: %v", entry.Candidate.Number, err)
			break
		}
		sequence++
		record := frontier.Record{Sequence: sequence, Height: entry.Candidate.Number, Epoch: entry.ResultingUC.GetRootEpoch(), Round: entry.ResultingUC.GetRootRoundNumber(), StateRoot: state, Subject: q, PolicyDigest: w.PolicyDigest}
		for i, index := range holders {
			record.Acks[i] = frontier.Acknowledgment{Replica: w.Replicas[index].String(), RequestDigest: ack, ManifestDigest: digest}
		}
		covered = append(covered, frontier.Coverage{Anchor: record, Material: rec})
		height, epoch, round = entry.Candidate.Number, entry.ResultingUC.GetRootEpoch(), entry.ResultingUC.GetRootRoundNumber()
		if len(covered) == max {
			break
		}
	}
	if len(covered) == 0 {
		w.warnNoProgress(ctx, image, stopped, finalized)
		return nil
	}
	if err := w.Journal.AdvanceFrontier(ctx, w.Context, w.Limits, covered); err != nil {
		return fmt.Errorf("frontier advance: %w", err)
	}
	return w.Journal.PruneFrontier(ctx, w.Context, w.Limits)
}

// warnCapacity logs once a minute while the hot journal is at or above capacityWarnPercent of any limit. The hard limits stop admission,
// so this is the operator's lead time to restore two archive copies.
func (w *FrontierWorker) warnCapacity(ctx context.Context, image configuredprogress.JournalSnapshot) {
	usage := JournalUsage{CandidatesUsed: len(image.Candidates), CandidatesCap: w.Limits.Candidates, ObservationsUsed: len(image.Observations),
		ObservationsCap: w.Limits.Observations, BytesUsed: image.Bytes, BytesCap: w.Limits.Bytes}
	pct := usage.Percent()
	if w.Log == nil || pct < capacityWarnPercent || time.Since(w.lastCapacityWarn) < time.Minute {
		return
	}
	w.lastCapacityWarn = time.Now()
	w.Log.WarnContext(ctx, "execution journal is near its limit: pruning needs two verified archive copies", "percent", pct,
		"candidates", usage.CandidatesUsed, "candidatesCap", usage.CandidatesCap, "observations", usage.ObservationsUsed, "observationsCap", usage.ObservationsCap,
		"bytes", usage.BytesUsed, "bytesCap", usage.BytesCap)
}

// warnNoProgress says why a pass that found the journal near a limit covered nothing: without it a full journal with a worker that
// silently covers zero blocks looks the same as a healthy one (#843: a rejoined node's journal filled and stayed full).
func (w *FrontierWorker) warnNoProgress(ctx context.Context, image configuredprogress.JournalSnapshot, stopped string, finalized shardnode.BlockRef) {
	usage := JournalUsage{CandidatesUsed: len(image.Candidates), CandidatesCap: w.Limits.Candidates, ObservationsUsed: len(image.Observations),
		ObservationsCap: w.Limits.Observations, BytesUsed: image.Bytes, BytesCap: w.Limits.Bytes}
	if w.Log == nil || usage.Percent() < capacityWarnPercent || time.Since(w.lastNoProgressWarn) < 10*time.Second {
		return
	}
	w.lastNoProgressWarn = time.Now()
	w.Log.WarnContext(ctx, "certified frontier covered nothing while the journal is near its limit", "reason", stopped, "percent", usage.Percent(),
		"candidates", usage.CandidatesUsed, "certified", len(certifiedEntries(image)), "finalized", finalized.Number)
}

// holders names, as indexes into Replicas in canonical order, the two replicas whose verified read-back returned this exact record: the
// acknowledgments the frontier record will carry. A third replica is consulted only when one of the first two does not hold the copy, and
// one that failed earlier in the pass is not asked again, so a stopped peer costs one dial per pass rather than one per block. Legacy
// two-replica records are verified by the journal when it plans the advance, as before.
func (w *FrontierWorker) holders(availability ReplicaAvailability, q archive.Request, digest [32]byte, unreachable map[int]bool) ([2]int, error) {
	if w.PolicyDigest == ([32]byte{}) {
		return [2]int{0, 1}, nil
	}
	var found []int
	for i, id := range w.Replicas {
		if unreachable[i] {
			continue
		}
		if err := availability.VerifyAvailable(id.String(), q, digest); err != nil {
			unreachable[i] = true
			continue
		}
		if found = append(found, i); len(found) == replicaCopies {
			return [2]int{found[0], found[1]}, nil
		}
	}
	return [2]int{}, fmt.Errorf("%w: %d of %d archive replicas hold a verified copy, two required", frontier.ErrAcknowledgment, len(found), len(w.Replicas))
}

// One bounded page per pass audits every committed promise within minutes at
// the default cadence. A surviving verified copy repairs a missing local or
// replica copy before further frontier advancement.
func (w *FrontierWorker) audit(ctx context.Context) error {
	if w.Host == nil {
		return nil
	} // tests inject the journal's availability adapter
	current, err := w.Journal.LoadFrontier(ctx, w.Context, w.Limits)
	if err != nil {
		return err
	}
	if current.Anchor == nil {
		return nil
	}
	if current.CoverageBase == nil {
		return configuredprogress.ErrUntrusted
	}
	baseHeight := current.CoverageBase.Height
	if w.auditCursor < baseHeight {
		w.auditCursor = baseHeight
	}
	// At a two-second cadence there are 43,200 passes per day. Scale the
	// bounded page count with promised history so a full sweep stays within
	// that interval as the chain grows.
	quota := int((current.Anchor.Height + 43199) / 43200)
	if quota < 4 {
		quota = 4
	}
	availability := ReplicaAvailability{Context: ctx, Host: w.Host, Replicas: w.Replicas, Limits: w.TransportLimits}
	binding := CertifiedBinding{Context: w.Context, Subject: w.Subject}
	down := make(map[peer.ID]bool)
	for quota > 0 {
		pageLimit := quota
		if pageLimit > 64 {
			pageLimit = 64
		}
		page, err := w.Journal.LoadCoverage(ctx, w.Context, w.Limits, w.auditCursor, pageLimit)
		if err != nil {
			return err
		}
		if len(page) == 0 {
			w.auditCursor = baseHeight
			return nil
		}
		for _, r := range page {
			rec, err := w.Archive.Get(r.Subject)
			if err != nil {
				verified := false
				for _, id := range w.Replicas {
					rec, err = readReplica(ctx, w.Host, id, r.Subject, r.Acks[0].ManifestDigest, w.TransportLimits)
					if err == nil && binding.VerifyCertified(r, rec) == nil {
						verified = true
						break
					}
				}
				if !verified {
					return frontier.ErrUnavailable
				}
				if err := w.Archive.Put(r.Subject, rec); err != nil {
					return err
				}
			}
			digest, err := archive.ManifestDigest(r.Subject, rec)
			if err != nil || digest != r.Acks[0].ManifestDigest || binding.VerifyCertified(r, rec) != nil {
				return frontier.ErrInvalid
			}
			if w.ensureCopies(ctx, availability, down, r, rec) < replicaCopies {
				return frontier.ErrUnavailable
			}
			w.auditCursor = r.Height
		}
		quota -= len(page)
	}
	return nil
}

// ensureCopies counts the configured replicas holding a verified copy of the position after repairing what it can. It keeps going past two:
// the acknowledgers come first, so the two copies pruning needs are restored before the optional third, and a replica that returns after
// pruning is backfilled by the same bounded sweep. Callers need only replicaCopies. A failed replica is rewritten from the local record;
// down collects the replicas that failed both the read and the rewrite, for the rest of the pass. A retired replica (dropped, or outside
// the configured set) is neither verified nor repaired.
func (w *FrontierWorker) ensureCopies(ctx context.Context, availability ReplicaAvailability, down map[peer.ID]bool, r frontier.Record, rec *archive.Record) int {
	ackers := make(map[peer.ID]bool, len(r.Acks))
	var order []peer.ID
	for _, ack := range r.Acks {
		for _, configured := range w.Replicas {
			if !ack.Dropped() && configured.String() == ack.Replica {
				ackers[configured] = true
				order = append(order, configured)
			}
		}
	}
	for _, configured := range w.Replicas {
		if !ackers[configured] {
			order = append(order, configured)
		}
	}
	copies := 0
	for _, id := range order {
		if down[id] {
			continue
		}
		if availability.VerifyAvailable(id.String(), r.Subject, r.Acks[0].ManifestDigest) != nil &&
			PutAndReadBack(ctx, w.Host, id, r.Subject, rec, w.TransportLimits) != nil {
			down[id] = true // neither a read nor a rewrite worked: a stopped peer costs one dial per pass, not one per position
			continue
		}
		copies++
	}
	return copies
}

func readReplica(ctx context.Context, host shardnode.EvidenceHost, id peer.ID, q archive.Request, want [32]byte, limits Limits) (*archive.Record, error) {
	request, err := archive.EncodeRequest(q)
	if err != nil {
		return nil, err
	}
	answer, err := exchange(ctx, host, id, append([]byte{2}, request...), limits)
	if err != nil {
		return nil, err
	}
	response, err := archive.DecodeFor(q, answer)
	if err != nil || response.Outcome != archive.OK || response.Record == nil {
		return nil, frontier.ErrUnavailable
	}
	digest, err := archive.ManifestDigest(q, response.Record)
	if err != nil || digest != want {
		return nil, frontier.ErrUnavailable
	}
	return response.Record, nil
}
