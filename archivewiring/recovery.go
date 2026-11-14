package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ethereum/go-ethereum/common"
	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/configuredprogress"
	"github.com/unicitynetwork/bft-core/engineapi"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	ErrArchiveRecoveryUnavailable = errors.New("archive recovery: certified record unavailable")
	ErrArchiveRecoveryInvalid     = errors.New("archive recovery: certified record invalid")
	// ErrArchiveSuffixTooLong marks a FetchSuffix refusal for length alone: the chain may well be valid, and a long catch-up
	// (ArchivePlan) can bring it in page by page (#769).
	ErrArchiveSuffixTooLong = errors.New("archive recovery: suffix longer than one recovery")
)

// RecoverySource reads a certified suffix from local immutable storage first,
// then configured archive replicas. Certificate, header, body, state root and
// archive context are checked before entries are returned to journal recovery.
type RecoverySource struct {
	Context  configuredprogress.Context
	Subject  archive.Context
	Local    *archive.Store
	Host     shardnode.EvidenceHost
	Replicas []peer.ID
	// Policy, when set, replaces Replicas with its current snapshot's readable replicas (the current ones, then the retained holders).
	Policy *ReplicaPolicy
	// Followed, when set, lists extra non-root sources (follow sources) asked after the replicas: a non-active follower reads them under
	// their public budget. Their records are verified exactly like a replica's.
	Followed  func() []peer.ID
	Limits    Limits
	MaxBlocks int
	Log       *slog.Logger
}

func (s *RecoverySource) FetchSuffix(ctx context.Context, after shardnode.BlockRef, target []byte) ([]shardnode.JournalFetchEntry, error) {
	if s == nil || s.Local == nil || len(after.Hash) != 32 || len(after.StateRoot) != 32 || len(target) != 32 || !s.Limits.valid() {
		return nil, ErrArchiveRecoveryUnavailable
	}
	max := s.MaxBlocks
	if max <= 0 || max > 256 {
		max = 256
	}
	var reverse []shardnode.JournalFetchEntry
	current := common.BytesToHash(target)
	for len(reverse) < max {
		q := archive.Request{Context: s.Subject, BlockHash: current}
		// the target alone first: its certified height says how long the suffix is, so a gap longer than one recovery costs one record
		want := 1
		if len(reverse) > 0 {
			want = min(max-len(reverse), int(reverse[len(reverse)-1].Block.Number-after.Number-1))
		}
		got, err := s.fetchVerifiedChain(ctx, q, [32]byte(after.Hash), want)
		if err != nil {
			return nil, fmt.Errorf("%w: %x: %v", ErrArchiveRecoveryUnavailable, current, err)
		}
		for _, v := range got {
			entry := v.entry
			if len(reverse) == 0 && entry.Block.Number > after.Number && entry.Block.Number-after.Number > uint64(max) {
				// the target's certified height alone says the suffix is longer than one recovery: walking max records to find out
				// cost max round trips (bft-core#1066)
				return nil, fmt.Errorf("%w: %w: suffix of %d records exceeds %d", ErrArchiveRecoveryInvalid, ErrArchiveSuffixTooLong, entry.Block.Number-after.Number, max)
			}
			reverse = append(reverse, entry)
			if bytes.Equal(entry.Block.ParentHash, after.Hash) {
				if entry.Block.Number != after.Number+1 {
					return nil, fmt.Errorf("%w: suffix does not join retained anchor", ErrArchiveRecoveryInvalid)
				}
				for i, j := 0, len(reverse)-1; i < j; i, j = i+1, j-1 {
					reverse[i], reverse[j] = reverse[j], reverse[i]
				}
				parentState := bytes.Clone(after.StateRoot)
				for i := range reverse {
					reverse[i].ParentState = parentState
					parentState = bytes.Clone(reverse[i].Block.StateRoot)
				}
				return reverse, nil
			}
			if entry.Block.Number <= after.Number+1 || len(entry.Block.ParentHash) != 32 {
				// every record of the walk is verified: a chain that comes down to the anchor's height without containing the anchor proves it is not on it
				if len(reverse) > 1 || entry.Block.Number > after.Number {
					return nil, fmt.Errorf("%w: %w: archive suffix does not reach retained anchor", ErrArchiveRecoveryInvalid, shardnode.ErrCertifiedChainForksAnchor)
				}
				return nil, fmt.Errorf("%w: archive suffix does not reach retained anchor", ErrArchiveRecoveryInvalid)
			}
			if n := len(reverse); n > 1 && entry.Block.Number+1 != reverse[n-2].Block.Number {
				return nil, fmt.Errorf("%w: archive block %x is at height %d, its child at %d", ErrArchiveRecoveryInvalid, current, entry.Block.Number, reverse[n-2].Block.Number)
			}
			current = common.BytesToHash(entry.Block.ParentHash)
			if len(reverse) >= max {
				break
			}
		}
	}
	return nil, fmt.Errorf("%w: %w: suffix exceeds %d records", ErrArchiveRecoveryInvalid, ErrArchiveSuffixTooLong, max)
}

func frontierRecordForRecovery(q archive.Request, header *gethtypes.Header, result *types.UnicityCertificate) frontier.Record {
	return frontier.Record{Height: header.Number.Uint64(), Epoch: result.GetRootEpoch(), Round: result.GetRootRoundNumber(), StateRoot: [32]byte(header.Root), Subject: q}
}

// verifiedRecord is one authenticated record of a walk.
type verifiedRecord struct {
	entry shardnode.JournalFetchEntry
	q     archive.Request
	rec   *archive.Record
	local bool
}

// fetchVerifiedChain returns, newest first, the verified record of q and of up to max-1 of its ancestors, stopping before stop: one record
// when the local archive holds q, else as many as one replica's chain read (FetchChain) yields in one exchange. Every record is
// authenticated (decodeEntry) under the request for the hash its child names, exactly as a single read is; the first record a replica
// gets wrong ends that replica's answer, and the next replica is asked only when the first record could not be had. A replica without the
// chain read is asked with a single read. The walk is round-trip bound otherwise (bft-core#1066).
func (s *RecoverySource) fetchVerifiedChain(ctx context.Context, q archive.Request, stop [32]byte, max int) ([]verifiedRecord, error) {
	if max <= 1 {
		entry, rec, local, err := s.fetchVerifiedRecord(ctx, q)
		if err != nil {
			return nil, err
		}
		return []verifiedRecord{{entry: entry, q: q, rec: rec, local: local}}, nil
	}
	var failures []error
	if s.Local != nil {
		rec, err := s.Local.Get(q) // the base representation, on purpose, as in fetchVerifiedRecord (bft-core#876)
		if err == nil {
			entry, verifyErr := s.decodeEntry(ctx, q, rec)
			if verifyErr == nil {
				return []verifiedRecord{{entry: entry, q: q, rec: rec, local: true}}, nil
			}
			err = verifyErr
		}
		failures = append(failures, fmt.Errorf("local archive: %w", err))
		s.logRejected(ctx, "local", q, err)
	}
	for _, id := range s.readable() {
		if id == "" || s.Host == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		chain, err := FetchChain(ctx, s.Host, id, q, stop, max, s.Limits)
		var reset *StreamResetError
		if err != nil && errors.As(err, &reset) && (errors.Is(err, ErrHandler) || errors.Is(err, ErrPeerNotAllowed)) && ctx.Err() == nil {
			// a replica without the chain read refuses it as an unknown operation: ask it for the one record
			var rec *archive.Record
			if rec, err = Fetch(ctx, s.Host, id, q, s.Limits); err == nil {
				chain = []ChainRecord{{Request: q, Record: rec}}
			}
		}
		var out []verifiedRecord
		for _, c := range chain {
			entry, verifyErr := s.decodeEntry(ctx, c.Request, c.Record)
			if verifyErr != nil {
				if len(out) == 0 {
					err = verifyErr
				} else {
					s.logRejected(ctx, id.String(), c.Request, verifyErr)
				}
				break
			}
			out = append(out, verifiedRecord{entry: entry, q: c.Request, rec: c.Record})
		}
		if len(out) > 0 {
			return out, nil
		}
		if err == nil {
			err = ErrReplica
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr // the walk's time is spent: not a failure of this copy
		}
		failures = append(failures, fmt.Errorf("replica %s: %w", id, err))
		s.logRejected(ctx, id.String(), q, err)
	}
	if len(failures) == 0 {
		return nil, archive.ErrUnavailable
	}
	return nil, fmt.Errorf("all archive copies failed verification or retrieval: %w", errors.Join(failures...))
}

// readable is the replica list a read asks, then the follow sources.
func (s *RecoverySource) readable() []peer.ID {
	replicas := s.Replicas
	if s.Policy != nil {
		replicas = s.Policy.Snapshot().Readable()
	}
	if s.Followed != nil {
		replicas = append(append([]peer.ID(nil), replicas...), s.Followed()...)
	}
	return replicas
}

// logRejected logs a refused copy. A local miss is the normal case of a walk (the local archive is filled by it) and logs at debug.
func (s *RecoverySource) logRejected(ctx context.Context, source string, q archive.Request, err error) {
	if s.Log == nil {
		return
	}
	level := slog.LevelWarn
	if source == "local" && errors.Is(err, archive.ErrUnavailable) {
		level = slog.LevelDebug
	}
	s.Log.Log(ctx, level, "archive recovery source rejected", "source", source, "block", fmt.Sprintf("%x", q.BlockHash), "error", err)
}

// fetchVerifiedRecord reads and authenticates one record and reports whether it came from the local archive. Every copy it
// accepts is receipt-complete: the certified binding validates the receipt list against the header (ValidateReceiptCommitments), so
// a long catch-up that retains these records holds the local copies the frontier needs.
func (s *RecoverySource) fetchVerifiedRecord(ctx context.Context, q archive.Request) (shardnode.JournalFetchEntry, *archive.Record, bool, error) {
	var failures []error
	if s.Local != nil {
		// The base representation is read here on purpose (bft-core#876): the record is authenticated below and nothing compares it with a journal-derived manifest; a selected variant certifies the same input record.
		rec, err := s.Local.Get(q)
		if err == nil {
			entry, verifyErr := s.decodeEntry(ctx, q, rec)
			if verifyErr == nil {
				return entry, rec, true, nil
			}
			err = verifyErr
		}
		failures = append(failures, fmt.Errorf("local archive: %w", err))
		s.logRejected(ctx, "local", q, err)
	}
	for _, id := range s.readable() {
		if id == "" || s.Host == nil {
			continue
		}
		rec, err := Fetch(ctx, s.Host, id, q, s.Limits)
		if err == nil {
			var entry shardnode.JournalFetchEntry
			entry, err = s.decodeEntry(ctx, q, rec)
			if err == nil {
				return entry, rec, false, nil
			}
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return shardnode.JournalFetchEntry{}, nil, false, ctxErr // the caller's time is spent: not a failure of this copy
		}
		failures = append(failures, fmt.Errorf("replica %s: %w", id, err))
		s.logRejected(ctx, id.String(), q, err)
	}
	if len(failures) == 0 {
		return shardnode.JournalFetchEntry{}, nil, false, archive.ErrUnavailable
	}
	return shardnode.JournalFetchEntry{}, nil, false, fmt.Errorf("all archive copies failed verification or retrieval: %w", errors.Join(failures...))
}

func (s *RecoverySource) decodeEntry(ctx context.Context, q archive.Request, rec *archive.Record) (shardnode.JournalFetchEntry, error) {
	var original, resulting types.UnicityCertificate
	var originalTR, resultingTR certification.TechnicalRecord
	if rec == nil || types.Cbor.Unmarshal(rec.OriginalUC, &original) != nil || types.Cbor.Unmarshal(rec.OriginalTR, &originalTR) != nil ||
		types.Cbor.Unmarshal(rec.ResultingUC, &resulting) != nil || types.Cbor.Unmarshal(rec.ResultingTR, &resultingTR) != nil || original.InputRecord == nil || resulting.InputRecord == nil {
		return shardnode.JournalFetchEntry{}, ErrBinding
	}
	var header gethtypes.Header
	if rlp.DecodeBytes(rec.Header, &header) != nil || header.Number == nil || header.Hash() != q.BlockHash {
		return shardnode.JournalFetchEntry{}, ErrBinding
	}
	fr := frontierRecordForRecovery(q, &header, &resulting)
	if err := (CertifiedBinding{Context: s.Context, Subject: s.Subject}).VerifyCertified(fr, rec); err != nil {
		return shardnode.JournalFetchEntry{}, fmt.Errorf("certified binding: %w", err)
	}
	block, err := engineapi.BlockFromArchive(q, rec, original.GetRootRoundNumber(), resulting.InputRecord.RoundNumber)
	if err != nil || block.Number != header.Number.Uint64() || !bytes.Equal(block.Hash, q.BlockHash[:]) || !bytes.Equal(block.StateRoot, header.Root[:]) {
		return shardnode.JournalFetchEntry{}, fmt.Errorf("archive body/header mismatch: %v", err)
	}
	return shardnode.JournalFetchEntry{Block: block, ParentState: bytes.Clone(original.InputRecord.Hash), Round: originalTR.Round,
		AuthorizingUC: &original, AuthorizingTR: &originalTR, ResultingUC: &resulting, ResultingTR: &resultingTR}, nil
}
