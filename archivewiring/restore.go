package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

var ErrRestore = errors.New("archive restore: certified replay refused")

// ArchiveRestore replays authenticated archive records from the checked
// execution genesis. Its archive and journal directories must be fresh. The
// paired Engine remains at genesis finality until the whole target is checked.
type ArchiveRestore struct {
	Journal       *configuredprogress.Store
	Context       configuredprogress.Context
	JournalLimits configuredprogress.JournalLimits
	Archive       *archive.Store
	Subject       archive.Context
	Replicas      [2]peer.ID
	Host          shardnode.EvidenceHost
	Limits        Limits
	// Retry bounds the wait for a replica that cannot serve a record right now (zero value: DefaultFetchRetry).
	Retry   FetchRetry
	Adapter RestoreExecutor
	Genesis shardnode.BlockRef
	TipUC   *types.UnicityCertificate
	TipTR   *certification.TechnicalRecord
}

// SingleEpochRestore is kept for callers of the original single-epoch route.
type SingleEpochRestore = ArchiveRestore

// RestoreExecutor is the paired seal-import and finality surface used by the
// existing execution recovery coordinator. Production supplies *Adapter.
type RestoreExecutor interface {
	Head(context.Context) (shardnode.BlockRef, error)
	Finalized(context.Context) (shardnode.BlockRef, error)
	Header(context.Context, shardnode.Hash) (shardnode.BlockRef, shardnode.Hash, error)
	Verify(context.Context, shardnode.Block, shardnode.RoundParams) (shardnode.Status, error)
	RecoveryForkchoice(context.Context, shardnode.Hash, shardnode.Hash) (shardnode.Status, error)
	Commit(context.Context, shardnode.Hash) (shardnode.Status, error)
}

type restoredBlock struct {
	q      archive.Request
	height uint64
	state  [32]byte
}

func (r *ArchiveRestore) Restore(ctx context.Context) error {
	if r == nil || r.Journal == nil || r.Archive == nil || r.Adapter == nil || r.Host == nil ||
		r.Replicas[0] == "" || r.Replicas[1] == "" || r.Replicas[0] == r.Replicas[1] ||
		r.TipUC == nil || r.TipTR == nil || r.TipUC.InputRecord == nil || len(r.Genesis.Hash) != 32 || !r.Limits.valid() {
		return fmt.Errorf("%w: incomplete restore configuration", ErrRestore)
	}
	if _, err := rootinput.AuthenticateObservationV2(ctx, r.Context.Observation, r.TipUC, r.TipTR); err != nil {
		return fmt.Errorf("%w: tip pin: %v", ErrRestore, err)
	}
	image, err := r.Journal.LoadJournal(ctx, r.Context, r.JournalLimits)
	if err != nil {
		return fmt.Errorf("%w: loading BFT journal: %v", ErrRestore, err)
	}
	if image.RestoreBase != nil {
		// A prior replay may have committed its verified pin and EL finality,
		// then failed while repairing a missing observation body. Resume that
		// repair from the durable pin instead of requiring another disk wipe.
		expected := shardnode.BlockRef{Number: image.RestoreBase.Height, Hash: image.RestoreBase.Hash[:], StateRoot: image.RestoreBase.StateRoot[:]}
		if image.Frontier != nil && image.Frontier.Anchor != nil && image.Frontier.Anchor.Height > expected.Number {
			expected = shardnode.BlockRef{Number: image.Frontier.Anchor.Height,
				Hash: image.Frontier.Anchor.Subject.BlockHash[:], StateRoot: image.Frontier.Anchor.StateRoot[:]}
		}
		head, headErr := r.Adapter.Head(ctx)
		finalized, finalErr := r.Adapter.Finalized(ctx)
		if headErr != nil || finalErr != nil || !sameBlockRef(head, expected) || !sameBlockRef(finalized, expected) {
			return restoreCause(errors.Join(headErr, finalErr), "retry requires the EL head and finality at the verified restore base: head=%v finalized=%v", headErr, finalErr)
		}
		return r.backfillRestoredObservations(ctx)
	}
	if len(image.Observations) != 0 || len(image.Candidates) != 0 || image.Restored != nil || image.Frontier != nil {
		return fmt.Errorf("%w: BFT journal is not empty: %v", ErrRestore, err)
	}
	head, err := r.Adapter.Head(ctx)
	if err != nil || !sameBlockRef(head, r.Genesis) {
		return restoreCause(err, "EL head must be the checked genesis on an empty disk: %v", err)
	}
	finalized, err := r.Adapter.Finalized(ctx)
	if err != nil || !sameBlockRef(finalized, r.Genesis) {
		return restoreCause(err, "EL finalized head must be the checked genesis: %v", err)
	}
	replayCtx := ctx
	if adapter, ok := r.Adapter.(interface {
		HistoricalContext(context.Context) context.Context
	}); ok {
		replayCtx = adapter.HistoricalContext(ctx)
	}
	target, err := r.findTarget(ctx)
	if err != nil {
		return err
	}
	var reverse []restoredBlock
	current := target
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		q, rec, result, _, header, err := r.fetchChecked(ctx, current)
		if err != nil {
			return fmt.Errorf("%w: block %x: %w", ErrRestore, current, err)
		}
		if len(reverse) == 0 && !r.matchesTip(result) {
			return fmt.Errorf("%w: selected record does not match pinned tip state", ErrRestore)
		}
		if len(reverse) > 0 && reverse[len(reverse)-1].height != header.Number.Uint64()+1 {
			return fmt.Errorf("%w: archive block height gap", ErrRestore)
		}
		if err := r.Archive.Put(q, rec); err != nil {
			return fmt.Errorf("%w: retaining authenticated block: %v", ErrRestore, err)
		}
		reverse = append(reverse, restoredBlock{q: q, height: header.Number.Uint64(), state: [32]byte(header.Root)})
		if header.Number.Uint64() == 1 {
			if !bytes.Equal(header.ParentHash[:], r.Genesis.Hash) {
				return fmt.Errorf("%w: archive does not reach configured genesis", ErrRestore)
			}
			break
		}
		if header.Number.Uint64() == 0 || header.ParentHash == common.Hash(current) {
			return fmt.Errorf("%w: archive parent cycle or invalid height", ErrRestore)
		}
		current = [32]byte(header.ParentHash)
	}
	parent := r.Genesis
	var firstUC *types.UnicityCertificate
	var firstTR *certification.TechnicalRecord
	var targetUC *types.UnicityCertificate
	var targetTR *certification.TechnicalRecord
	var targetBlock shardnode.Block
	for i := len(reverse) - 1; i >= 0; i-- {
		item := reverse[i]
		rec, err := r.Archive.Get(item.q)
		if err != nil {
			return err
		}
		original, originalTR, resulting, resultingTR, err := decodeRestorePairs(rec)
		if err != nil {
			return err
		}
		if firstUC == nil {
			firstUC, firstTR = original, originalTR
		}
		block, err := engineapi.BlockFromArchive(item.q, rec, original.GetRootRoundNumber(), resulting.InputRecord.RoundNumber)
		if err != nil || block.Number != parent.Number+1 || !bytes.Equal(block.ParentHash, parent.Hash) {
			return fmt.Errorf("%w: reconstructed payload breaks parent chain: %v", ErrRestore, err)
		}
		seal, err := shardnode.SealHash(original)
		if err != nil {
			return err
		}
		params := shardnode.RoundParams{Round: resulting.InputRecord.RoundNumber, Epoch: originalTR.Epoch,
			Timestamp: original.UnicitySeal.Timestamp, SealHash: seal, Leader: originalTR.Leader, Parent: parent,
			AuthorizingCertificate: original, AuthorizingTechnicalRecord: originalTR}
		status, err := r.Adapter.Verify(replayCtx, block, params)
		if err != nil || status != shardnode.StatusValid {
			return restoreCause(err, "paired seal import %d returned %s: %v", block.Number, status, err)
		}
		status, err = r.Adapter.RecoveryForkchoice(ctx, block.Hash, r.Genesis.Hash)
		if err != nil || status != shardnode.StatusValid {
			return restoreCause(err, "advancing replay head %d returned %s: %v", block.Number, status, err)
		}
		parent = shardnode.BlockRef{Number: block.Number, Hash: block.Hash, StateRoot: block.StateRoot}
		targetUC, targetTR, targetBlock = resulting, resultingTR, block
	}
	if !bytes.Equal(parent.StateRoot, r.TipUC.InputRecord.Hash) {
		return fmt.Errorf("%w: replayed state differs from pinned tip", ErrRestore)
	}
	status, err := r.Adapter.Commit(ctx, parent.Hash)
	if err != nil || status != shardnode.StatusValid {
		return restoreCause(err, "finalizing replay target: %s: %v", status, err)
	}
	head, err = r.Adapter.Head(ctx)
	if err != nil || !sameBlockRef(head, parent) {
		return restoreCause(err, "EL head differs from replay target: %v", err)
	}
	finalized, err = r.Adapter.Finalized(ctx)
	if err != nil || !sameBlockRef(finalized, parent) {
		return restoreCause(err, "EL finalized head differs from replay target: %v", err)
	}
	if err := r.recordTip(ctx, firstUC, firstTR, targetUC, targetTR, targetBlock, reverse[0]); err != nil {
		return err
	}
	return r.backfillRestoredObservations(ctx)
}

// backfillRestoredObservations resolves any certificate body obligation in
// the replayed range from a locally or remotely retained, independently
// verified archive record. It never clears an observation without importing
// the matching body through the journal's normal historical-candidate path.
func (r *ArchiveRestore) backfillRestoredObservations(ctx context.Context) error {
	image, err := r.Journal.LoadJournal(ctx, r.Context, r.JournalLimits)
	if err != nil {
		return err
	}
	if image.CoverageBase == nil || image.CoverageBase.Height == 0 {
		return fmt.Errorf("%w: restored observation repair has no verified archive base", ErrRestore)
	}
	for _, observation := range image.Observations {
		if !observation.Unresolved {
			continue
		}
		if err := r.backfillRestoredObservation(ctx, image.CoverageBase.Height, observation); err != nil {
			return err
		}
	}
	return nil
}

func (r *ArchiveRestore) backfillRestoredObservation(ctx context.Context, baseHeight uint64, observation configuredprogress.JournalObservation) error {
	if observation.UC == nil || observation.UC.InputRecord == nil || len(observation.TargetHash) != 32 ||
		!bytes.Equal(observation.TargetHash, observation.UC.InputRecord.BlockHash) {
		return fmt.Errorf("%w: unresolved restored observation has no certified block hash", configuredprogress.ErrUntrusted)
	}
	var q archive.Request
	q.Context = r.Subject
	copy(q.BlockHash[:], observation.TargetHash)
	record, original, originalTR, result, resultTR, header, err := r.verifiedRestoreRecord(ctx, q, observation.UC)
	if err != nil {
		return fmt.Errorf("%w: restored observation body %x is unavailable or unverified", configuredprogress.ErrUnavailable, q.BlockHash)
	}
	if header.Number.Uint64() > baseHeight {
		return nil // outside the verified restore range
	}
	if result.InputRecord == nil || !bytes.Equal(result.InputRecord.BlockHash, observation.TargetHash) ||
		!bytes.Equal(result.InputRecord.Hash, observation.UC.InputRecord.Hash) ||
		result.InputRecord.RoundNumber != observation.UC.InputRecord.RoundNumber {
		return fmt.Errorf("%w: archived certificate does not bind restored observation %x", configuredprogress.ErrUntrusted, q.BlockHash)
	}
	block, err := engineapi.BlockFromArchive(q, record, original.GetRootRoundNumber(), result.InputRecord.RoundNumber)
	if err != nil || block.Number == 0 || block.Number != header.Number.Uint64() ||
		!bytes.Equal(block.Hash, observation.TargetHash) || !bytes.Equal(block.StateRoot, observation.UC.InputRecord.Hash) {
		return fmt.Errorf("%w: archived restored body differs from certificate %x", configuredprogress.ErrUntrusted, q.BlockHash)
	}
	candidate := configuredprogress.JournalCandidate{
		Round: observation.UC.InputRecord.RoundNumber, Number: block.Number, ParentNumber: block.Number - 1,
		Hash: bytes.Clone(block.Hash), StateRoot: bytes.Clone(block.StateRoot), ParentHash: bytes.Clone(block.ParentHash),
		ParentState: bytes.Clone(observation.UC.InputRecord.PreviousHash), Raw: bytes.Clone(block.Raw),
		BlockSize: block.BlockSize, StateSize: block.StateSize, AuthorizingUC: original, AuthorizingTR: originalTR,
	}
	if err := r.Journal.PutHistoricalCertifiedJournalCandidate(ctx, r.Context, r.JournalLimits, candidate, result, resultTR); err != nil {
		return fmt.Errorf("backfilling archived restored body %x: %w", q.BlockHash, err)
	}
	if err := r.Journal.BackfillJournalObservation(ctx, r.Context, r.JournalLimits, observation.UC, observation.TR); err != nil {
		return fmt.Errorf("backfilling restored certificate at epoch %d round %d: %w",
			observation.UC.GetRootEpoch(), observation.UC.GetRoundNumber(), err)
	}
	return nil
}

func (r *ArchiveRestore) verifiedRestoreRecord(ctx context.Context, q archive.Request, expected *types.UnicityCertificate) (*archive.Record, *types.UnicityCertificate,
	*certification.TechnicalRecord, *types.UnicityCertificate, *certification.TechnicalRecord, *gethtypes.Header, error) {
	check := func(rec *archive.Record) (*types.UnicityCertificate, *certification.TechnicalRecord, *types.UnicityCertificate,
		*certification.TechnicalRecord, *gethtypes.Header, error) {
		original, originalTR, result, resultTR, err := decodeRestorePairs(rec)
		if err != nil {
			return nil, nil, nil, nil, nil, err
		}
		if _, _, err := r.checkRecord(q, rec); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		var header gethtypes.Header
		if err := rlp.DecodeBytes(rec.Header, &header); err != nil || header.Number == nil || header.Hash() != common.Hash(q.BlockHash) {
			return nil, nil, nil, nil, nil, archive.ErrInvalid
		}
		if result.InputRecord == nil || expected == nil || expected.InputRecord == nil ||
			!bytes.Equal(result.InputRecord.BlockHash, expected.InputRecord.BlockHash) ||
			!bytes.Equal(result.InputRecord.Hash, expected.InputRecord.Hash) ||
			result.InputRecord.RoundNumber != expected.InputRecord.RoundNumber ||
			!bytes.Equal(result.InputRecord.BlockHash, q.BlockHash[:]) || !bytes.Equal(result.InputRecord.Hash, header.Root[:]) {
			return nil, nil, nil, nil, nil, archive.ErrInvalid
		}
		block, err := engineapi.BlockFromArchive(q, rec, original.GetRootRoundNumber(), result.InputRecord.RoundNumber)
		if err != nil || block.Number != header.Number.Uint64() || !bytes.Equal(block.Hash, q.BlockHash[:]) || !bytes.Equal(block.StateRoot, header.Root[:]) {
			return nil, nil, nil, nil, nil, archive.ErrInvalid
		}
		return original, originalTR, result, resultTR, &header, nil
	}
	if rec, err := r.Archive.Get(q); err == nil {
		if original, originalTR, result, resultTR, header, checkErr := check(rec); checkErr == nil {
			return rec, original, originalTR, result, resultTR, header, nil
		}
	}
	var (
		gotRec                  *archive.Record
		gotOriginal, gotResult  *types.UnicityCertificate
		gotOriginalTR, gotResTR *certification.TechnicalRecord
		gotHeader               *gethtypes.Header
	)
	err := r.retryFetch(ctx, fmt.Sprintf("restored observation body %x", q.BlockHash), func() (bool, error) {
		transient := false
		var lastFetch error
		for _, id := range r.Replicas {
			rec, err := Fetch(ctx, r.Host, id, q, r.Limits)
			if err != nil {
				transient = transient || transientFetchError(ctx, err)
				lastFetch = err
				continue
			}
			original, originalTR, result, resultTR, header, checkErr := check(rec)
			if checkErr != nil {
				continue
			}
			_ = r.Archive.Put(q, rec) // a stale/corrupt local copy must not hide a verified replica.
			gotRec, gotOriginal, gotOriginalTR, gotResult, gotResTR, gotHeader = rec, original, originalTR, result, resultTR, header
			return false, nil
		}
		return transient, unavailableBecause(lastFetch)
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}
	return gotRec, gotOriginal, gotOriginalTR, gotResult, gotResTR, gotHeader, nil
}

func sameBlockRef(a, b shardnode.BlockRef) bool {
	return a.Number == b.Number && bytes.Equal(a.Hash, b.Hash) && bytes.Equal(a.StateRoot, b.StateRoot)
}

func decodeRestorePairs(rec *archive.Record) (*types.UnicityCertificate, *certification.TechnicalRecord, *types.UnicityCertificate, *certification.TechnicalRecord, error) {
	if rec == nil {
		return nil, nil, nil, nil, archive.ErrInvalid
	}
	var a, b types.UnicityCertificate
	var at, bt certification.TechnicalRecord
	if types.Cbor.Unmarshal(rec.OriginalUC, &a) != nil || types.Cbor.Unmarshal(rec.OriginalTR, &at) != nil ||
		types.Cbor.Unmarshal(rec.ResultingUC, &b) != nil || types.Cbor.Unmarshal(rec.ResultingTR, &bt) != nil || b.InputRecord == nil {
		return nil, nil, nil, nil, archive.ErrInvalid
	}
	return &a, &at, &b, &bt, nil
}

func (r *ArchiveRestore) matchesTip(result *types.UnicityCertificate) bool {
	if result == nil || result.InputRecord == nil || r.TipUC.InputRecord == nil ||
		result.InputRecord.RoundNumber > r.TipUC.InputRecord.RoundNumber ||
		!bytes.Equal(result.InputRecord.Hash, r.TipUC.InputRecord.Hash) {
		return false
	}
	if len(r.TipUC.InputRecord.BlockHash) == 32 {
		return bytes.Equal(result.InputRecord.BlockHash, r.TipUC.InputRecord.BlockHash)
	}
	return true
}

// FetchRetry bounds how long a restore waits for archive replicas that cannot serve a record at the
// moment, for example because the source validators' global archive stream limit is reached while
// they catch replicas up. Only fetch failures are retried; a record that was delivered and failed
// verification is never retried and never accepted.
type FetchRetry struct {
	Initial time.Duration // first backoff
	Max     time.Duration // backoff ceiling
	Total   time.Duration // total wait before the restore fails with archive.ErrUnavailable
}

// DefaultFetchRetry waits up to 150s per record (the restore lanes allow 180s end to end).
var DefaultFetchRetry = FetchRetry{Initial: 200 * time.Millisecond, Max: 5 * time.Second, Total: 150 * time.Second}

func (p FetchRetry) orDefault() FetchRetry {
	if p == (FetchRetry{}) {
		return DefaultFetchRetry
	}
	return p
}

// retryFetch runs attempt until it succeeds, reports a non-transient failure, or the total wait is
// spent. attempt reports transient=true only when a replica could not deliver (stream reset, limit,
// transport error, not-found); verification failures are not transient.
func (r *ArchiveRestore) retryFetch(ctx context.Context, what string, attempt func() (transient bool, err error)) error {
	policy := r.Retry.orDefault()
	started := time.Now()
	delay := policy.Initial
	for tries := 1; ; tries++ {
		transient, err := attempt()
		if err == nil {
			return nil
		}
		if !transient {
			// transientFetchError reports false once the context is done, so a restore cancelled or timed out during an attempt
			// arrives here carrying the replica's failure. The caller asked to stop, and must be able to tell that from a replica
			// that refused: keep both causes.
			if cause := ctx.Err(); cause != nil {
				return fmt.Errorf("%w: restore stopped while fetching %s: %w", cause, what, err)
			}
			return err
		}
		remaining := policy.Total - time.Since(started)
		if remaining <= 0 {
			return fmt.Errorf("%w: %s still unavailable from both replicas after %d attempts over %s (replicas saturated, refusing this node, or missing the record): %w",
				archive.ErrUnavailable, what, tries, policy.Total, err)
		}
		wait := min(delay, remaining)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		delay = min(delay*2, policy.Max)
	}
}

// unavailableBecause is archive.ErrUnavailable carrying the last replica failure, so that a final error still names the cause (for
// example archivewiring.ErrPeerNotAllowed when the replicas have not admitted this node yet) to errors.Is.
func unavailableBecause(last error) error {
	if last == nil {
		return archive.ErrUnavailable
	}
	return errors.Join(archive.ErrUnavailable, last)
}

// transientFetchError reports whether a failed replica fetch may succeed later.
func transientFetchError(ctx context.Context, err error) bool {
	return err != nil && ctx.Err() == nil && !errors.Is(err, archive.ErrInvalid)
}

func (r *ArchiveRestore) findTarget(ctx context.Context) ([32]byte, error) {
	if len(r.TipUC.InputRecord.BlockHash) == 32 {
		var hash [32]byte
		copy(hash[:], r.TipUC.InputRecord.BlockHash)
		return hash, nil
	}
	query := archive.RoundRequest{Context: r.Subject, Round: r.TipUC.InputRecord.RoundNumber}
	var found [32]byte
	err := r.retryFetch(ctx, "quiet-tip record", func() (bool, error) {
		transient := false
		var lastFetch error
		for _, id := range r.Replicas {
			q, rec, err := FetchLatest(ctx, r.Host, id, query, r.Limits)
			if err != nil {
				transient = transient || transientFetchError(ctx, err)
				lastFetch = err
				continue
			}
			result, _, err := r.checkRecord(q, rec)
			if err == nil && r.matchesTip(result) {
				found = q.BlockHash
				return false, nil
			}
		}
		return transient, unavailableBecause(lastFetch)
	})
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return [32]byte{}, err
		}
		return [32]byte{}, fmt.Errorf("%w: neither replica supplied a certified record matching the quiet tip state: %w", ErrRestore, err)
	}
	return found, nil
}

func (r *ArchiveRestore) fetchChecked(ctx context.Context, hash [32]byte) (q archive.Request, rec *archive.Record, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, header *gethtypes.Header, err error) {
	err = r.retryFetch(ctx, fmt.Sprintf("archive record %x", hash), func() (bool, error) {
		var transient bool
		q, rec, uc, tr, header, transient, err = r.fetchCheckedOnce(ctx, hash)
		return transient, err
	})
	if err != nil {
		return archive.Request{}, nil, nil, nil, nil, err
	}
	return q, rec, uc, tr, header, nil
}

func (r *ArchiveRestore) fetchCheckedOnce(ctx context.Context, hash [32]byte) (archive.Request, *archive.Record, *types.UnicityCertificate, *certification.TechnicalRecord, *gethtypes.Header, bool, error) {
	q := archive.Request{Context: r.Subject, BlockHash: hash}
	transient := false
	var lastFetch error
	for _, id := range r.Replicas {
		rec, err := Fetch(ctx, r.Host, id, q, r.Limits)
		if err != nil {
			transient = transient || transientFetchError(ctx, err)
			lastFetch = err
			continue
		}
		if !archive.HasReceiptList(rec) {
			source, ok := r.Adapter.(ReceiptSource)
			if !ok {
				continue
			}
			envelopes, captureErr := source.GetBlockReceipts(ctx, q.BlockHash)
			if captureErr != nil {
				continue
			}
			rec, captureErr = WithReceiptList(rec, envelopes)
			if captureErr != nil {
				continue
			}
			// Backfill publishes to both independent copies and requires complete
			// read-backs before the record can serve as pruning coverage.
			complete := true
			for _, replica := range r.Replicas {
				if putErr := PutAndReadBack(ctx, r.Host, replica, q, rec, r.Limits); putErr != nil {
					transient = transient || transientFetchError(ctx, putErr)
					lastFetch = putErr
					complete = false
					break
				}
			}
			if !complete {
				continue
			}
		}
		uc, tr, err := r.checkRecord(q, rec)
		if err == nil {
			var header gethtypes.Header
			if err = rlp.DecodeBytes(rec.Header, &header); err == nil {
				return q, rec, uc, tr, &header, false, nil
			}
		}
	}
	return archive.Request{}, nil, nil, nil, nil, transient, unavailableBecause(lastFetch)
}

func (r *ArchiveRestore) checkRecord(q archive.Request, rec *archive.Record) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	_, _, result, tr, err := decodeRestorePairs(rec)
	if err != nil || result.GetRootEpoch() > r.TipUC.GetRootEpoch() {
		return nil, nil, ErrRestore
	}
	var header gethtypes.Header
	if rlp.DecodeBytes(rec.Header, &header) != nil || header.Number == nil {
		return nil, nil, archive.ErrInvalid
	}
	fr := frontier.Record{Height: header.Number.Uint64(), Epoch: result.GetRootEpoch(), Round: result.GetRootRoundNumber(), StateRoot: [32]byte(header.Root), Subject: q}
	if err := (CertifiedBinding{Context: r.Context, Subject: r.Subject}).VerifyCertified(fr, rec); err != nil {
		return nil, nil, err
	}
	return result, tr, nil
}

func (r *ArchiveRestore) recordTip(ctx context.Context, firstUC *types.UnicityCertificate, firstTR *certification.TechnicalRecord, resultUC *types.UnicityCertificate, resultTR *certification.TechnicalRecord, block shardnode.Block, item restoredBlock) error {
	if firstUC == nil || firstTR == nil || resultUC == nil || resultTR == nil {
		return ErrRestore
	}
	if firstUC.GetRootEpoch() != r.TipUC.GetRootEpoch() {
		candidate, err := r.restoreCandidate(ctx, resultUC, block, item)
		if err != nil {
			return err
		}
		return r.Journal.InstallReplayedTip(ctx, r.Context, r.JournalLimits, candidate, resultUC, resultTR, r.TipUC, r.TipTR,
			configuredprogress.RestoreAnchor{Height: block.Number, Hash: item.q.BlockHash, StateRoot: item.state, RootRound: resultUC.GetRootRoundNumber()})
	}
	for _, pair := range []struct {
		uc *types.UnicityCertificate
		tr *certification.TechnicalRecord
	}{{firstUC, firstTR}, {resultUC, resultTR}, {r.TipUC, r.TipTR}} {
		observed, err := rootinput.AuthenticateObservationV2(ctx, r.Context.Observation, pair.uc, pair.tr)
		if err != nil {
			return err
		}
		// The last record's candidate is inserted before its resulting UC so
		// the journal never records an unresolved certified body.
		if pair.uc == resultUC {
			candidate, err := r.restoreCandidate(ctx, resultUC, block, item)
			if err != nil {
				return err
			}
			if err := r.Journal.PutJournalCandidate(ctx, r.Context, r.JournalLimits, candidate); err != nil {
				return err
			}
		}
		prepared, _, err := r.Journal.PrepareObservation(ctx, r.Context, observed)
		if err != nil {
			return err
		}
		if _, _, err := r.Journal.CommitObservation(prepared); err != nil {
			return err
		}
	}
	return r.Journal.InstallRestoreAnchor(ctx, r.Context, r.JournalLimits, configuredprogress.RestoreAnchor{
		Height: block.Number, Hash: item.q.BlockHash, StateRoot: item.state, RootRound: resultUC.GetRootRoundNumber(),
	})
}

func (r *ArchiveRestore) restoreCandidate(ctx context.Context, resultUC *types.UnicityCertificate, block shardnode.Block, item restoredBlock) (configuredprogress.JournalCandidate, error) {
	rec, err := r.Archive.Get(item.q)
	if err != nil {
		return configuredprogress.JournalCandidate{}, err
	}
	original, originalTR, _, _, err := decodeRestorePairs(rec)
	if err != nil {
		return configuredprogress.JournalCandidate{}, err
	}
	var parentState []byte
	if block.Number == 1 {
		parentState = r.Genesis.StateRoot
	} else {
		parent, _, err := r.Adapter.Header(ctx, block.ParentHash)
		if err != nil {
			return configuredprogress.JournalCandidate{}, err
		}
		parentState = parent.StateRoot
	}
	return configuredprogress.JournalCandidate{Round: resultUC.InputRecord.RoundNumber, Number: block.Number,
		ParentNumber: block.Number - 1, Hash: block.Hash, StateRoot: block.StateRoot, ParentHash: block.ParentHash,
		ParentState: parentState, Raw: block.Raw, BlockSize: block.BlockSize, StateSize: block.StateSize,
		AuthorizingUC: original, AuthorizingTR: originalTR}, nil
}

// restoreError is an ErrRestore refusal that also carries the executor's cause, so a caller can tell a stopped context
// (context.Canceled, context.DeadlineExceeded) or any typed executor failure from a refusal of the restored state. The
// message text is the ErrRestore text followed by the formatted detail, exactly as the former "%w: ...: %v" refusals read.
type restoreError struct {
	msg   string
	cause error
}

func (e *restoreError) Error() string { return e.msg }

func (e *restoreError) Unwrap() []error {
	if e.cause == nil {
		return []error{ErrRestore}
	}
	return []error{ErrRestore, e.cause}
}

// restoreCause builds an ErrRestore refusal whose message is unchanged by the executor cause being wrapped. cause may be
// nil, when the refusal is a value mismatch rather than an executor failure.
func restoreCause(cause error, format string, args ...any) error {
	return &restoreError{msg: fmt.Sprintf("%v: "+format, append([]any{ErrRestore}, args...)...), cause: cause}
}
