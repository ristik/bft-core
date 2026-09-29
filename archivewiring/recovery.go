package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"

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
)

// RecoverySource reads a certified suffix from local immutable storage first,
// then configured archive replicas. Certificate, header, body, state root and
// archive context are checked before entries are returned to journal recovery.
type RecoverySource struct {
	Context   configuredprogress.Context
	Subject   archive.Context
	Local     *archive.Store
	Host      shardnode.EvidenceHost
	Replicas  [2]peer.ID
	Limits    Limits
	MaxBlocks int
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
		rec, err := s.Local.Get(q)
		if err != nil {
			rec, err = s.fetchReplica(ctx, q)
		}
		if err != nil {
			return nil, fmt.Errorf("%w: %x: %v", ErrArchiveRecoveryUnavailable, current, err)
		}
		entry, err := s.decodeEntry(ctx, q, rec)
		if err != nil {
			return nil, fmt.Errorf("%w: %x: %v", ErrArchiveRecoveryInvalid, current, err)
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
			return nil, fmt.Errorf("%w: archive suffix does not reach retained anchor", ErrArchiveRecoveryInvalid)
		}
		current = common.BytesToHash(entry.Block.ParentHash)
	}
	return nil, fmt.Errorf("%w: suffix exceeds %d records", ErrArchiveRecoveryInvalid, max)
}

func frontierRecordForRecovery(q archive.Request, header *gethtypes.Header, result *types.UnicityCertificate) frontier.Record {
	return frontier.Record{Height: header.Number.Uint64(), Epoch: result.GetRootEpoch(), Round: result.GetRootRoundNumber(), StateRoot: [32]byte(header.Root), Subject: q}
}

func (s *RecoverySource) fetchReplica(ctx context.Context, q archive.Request) (*archive.Record, error) {
	var last error
	for _, id := range s.Replicas {
		if id == "" || s.Host == nil {
			continue
		}
		rec, err := Fetch(ctx, s.Host, id, q, s.Limits)
		if err == nil {
			return rec, nil
		}
		last = err
	}
	if last == nil {
		last = archive.ErrUnavailable
	}
	return nil, last
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
