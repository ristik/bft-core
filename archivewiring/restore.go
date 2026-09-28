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
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

var ErrRestore = errors.New("archive restore: certified replay refused")

// SingleEpochRestore replays authenticated archive records from the checked
// execution genesis. Its archive and journal directories must be fresh. The
// paired Engine remains at genesis finality until the whole target is checked.
type SingleEpochRestore struct {
	Journal       *configuredprogress.Store
	Context       configuredprogress.Context
	JournalLimits configuredprogress.JournalLimits
	Archive       *archive.Store
	Subject       archive.Context
	Replicas      [2]peer.ID
	Host          shardnode.EvidenceHost
	Limits        Limits
	Adapter       RestoreExecutor
	Genesis       shardnode.BlockRef
	TipUC         *types.UnicityCertificate
	TipTR         *certification.TechnicalRecord
}

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

func (r *SingleEpochRestore) Restore(ctx context.Context) error {
	if r == nil || r.Journal == nil || r.Archive == nil || r.Adapter == nil || r.Host == nil ||
		r.Replicas[0] == "" || r.Replicas[1] == "" || r.Replicas[0] == r.Replicas[1] ||
		r.TipUC == nil || r.TipTR == nil || r.TipUC.InputRecord == nil || len(r.Genesis.Hash) != 32 || !r.Limits.valid() {
		return fmt.Errorf("%w: incomplete restore configuration", ErrRestore)
	}
	if r.TipUC.GetRootEpoch() != r.Context.Observation.RootEpoch {
		return fmt.Errorf("%w: pin crosses the configured root epoch", ErrRestore)
	}
	if _, err := rootinput.AuthenticateObservationV2(ctx, r.Context.Observation, r.TipUC, r.TipTR); err != nil {
		return fmt.Errorf("%w: tip pin: %v", ErrRestore, err)
	}
	image, err := r.Journal.LoadJournal(ctx, r.Context, r.JournalLimits)
	if err != nil || len(image.Observations) != 0 || len(image.Candidates) != 0 || image.Restored != nil || image.Frontier != nil {
		return fmt.Errorf("%w: BFT journal is not empty: %v", ErrRestore, err)
	}
	head, err := r.Adapter.Head(ctx)
	if err != nil || !sameBlockRef(head, r.Genesis) {
		return fmt.Errorf("%w: EL head must be the checked genesis on an empty disk: %v", ErrRestore, err)
	}
	finalized, err := r.Adapter.Finalized(ctx)
	if err != nil || !sameBlockRef(finalized, r.Genesis) {
		return fmt.Errorf("%w: EL finalized head must be the checked genesis: %v", ErrRestore, err)
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
			return fmt.Errorf("%w: block %x: %v", ErrRestore, current, err)
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
		status, err := r.Adapter.Verify(ctx, block, params)
		if err != nil || status != shardnode.StatusValid {
			return fmt.Errorf("%w: paired seal import %d returned %s: %v", ErrRestore, block.Number, status, err)
		}
		status, err = r.Adapter.RecoveryForkchoice(ctx, block.Hash, r.Genesis.Hash)
		if err != nil || status != shardnode.StatusValid {
			return fmt.Errorf("%w: advancing replay head %d returned %s: %v", ErrRestore, block.Number, status, err)
		}
		parent = shardnode.BlockRef{Number: block.Number, Hash: block.Hash, StateRoot: block.StateRoot}
		targetUC, targetTR, targetBlock = resulting, resultingTR, block
	}
	if !bytes.Equal(parent.StateRoot, r.TipUC.InputRecord.Hash) {
		return fmt.Errorf("%w: replayed state differs from pinned tip", ErrRestore)
	}
	status, err := r.Adapter.Commit(ctx, parent.Hash)
	if err != nil || status != shardnode.StatusValid {
		return fmt.Errorf("%w: finalizing replay target: %s: %v", ErrRestore, status, err)
	}
	head, err = r.Adapter.Head(ctx)
	if err != nil || !sameBlockRef(head, parent) {
		return fmt.Errorf("%w: EL head differs from replay target: %v", ErrRestore, err)
	}
	if err := r.recordTip(ctx, firstUC, firstTR, targetUC, targetTR, targetBlock, reverse[0]); err != nil {
		return err
	}
	return nil
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

func (r *SingleEpochRestore) matchesTip(result *types.UnicityCertificate) bool {
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

func (r *SingleEpochRestore) findTarget(ctx context.Context) ([32]byte, error) {
	if len(r.TipUC.InputRecord.BlockHash) == 32 {
		var hash [32]byte
		copy(hash[:], r.TipUC.InputRecord.BlockHash)
		return hash, nil
	}
	query := archive.RoundRequest{Context: r.Subject, Round: r.TipUC.InputRecord.RoundNumber}
	for _, id := range r.Replicas {
		q, rec, err := FetchLatest(ctx, r.Host, id, query, r.Limits)
		if err != nil {
			continue
		}
		result, _, err := r.checkRecord(q, rec)
		if err == nil && r.matchesTip(result) {
			return q.BlockHash, nil
		}
	}
	return [32]byte{}, fmt.Errorf("%w: neither replica supplied a certified record matching the quiet tip state", ErrRestore)
}

func (r *SingleEpochRestore) fetchChecked(ctx context.Context, hash [32]byte) (archive.Request, *archive.Record, *types.UnicityCertificate, *certification.TechnicalRecord, *gethtypes.Header, error) {
	q := archive.Request{Context: r.Subject, BlockHash: hash}
	for _, id := range r.Replicas {
		rec, err := Fetch(ctx, r.Host, id, q, r.Limits)
		if err != nil {
			continue
		}
		uc, tr, err := r.checkRecord(q, rec)
		if err == nil {
			var header gethtypes.Header
			if err = rlp.DecodeBytes(rec.Header, &header); err == nil {
				return q, rec, uc, tr, &header, nil
			}
		}
	}
	return archive.Request{}, nil, nil, nil, nil, archive.ErrUnavailable
}

func (r *SingleEpochRestore) checkRecord(q archive.Request, rec *archive.Record) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	_, _, result, tr, err := decodeRestorePairs(rec)
	if err != nil || result.GetRootEpoch() != r.TipUC.GetRootEpoch() {
		return nil, nil, ErrRestore
	}
	var header gethtypes.Header
	if rlp.DecodeBytes(rec.Header, &header) != nil || header.Number == nil {
		return nil, nil, archive.ErrInvalid
	}
	fr := frontier.Record{Height: header.Number.Uint64(), Round: result.GetRootRoundNumber(), StateRoot: [32]byte(header.Root), Subject: q}
	if err := (CertifiedBinding{Context: r.Context, Subject: r.Subject}).VerifyCertified(fr, rec); err != nil {
		return nil, nil, err
	}
	return result, tr, nil
}

func (r *SingleEpochRestore) recordTip(ctx context.Context, firstUC *types.UnicityCertificate, firstTR *certification.TechnicalRecord, resultUC *types.UnicityCertificate, resultTR *certification.TechnicalRecord, block shardnode.Block, item restoredBlock) error {
	if firstUC == nil || firstTR == nil || resultUC == nil || resultTR == nil {
		return ErrRestore
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
			rec, err := r.Archive.Get(item.q)
			if err != nil {
				return err
			}
			original, originalTR, _, _, err := decodeRestorePairs(rec)
			if err != nil {
				return err
			}
			var parentState []byte
			if block.Number == 1 {
				parentState = r.Genesis.StateRoot
			} else {
				// The preceding certified archive record was retained while
				// walking the chain; the replayed parent is independently known.
				parent, _, err := r.Adapter.Header(ctx, block.ParentHash)
				if err != nil {
					return err
				}
				parentState = parent.StateRoot
			}
			candidate := configuredprogress.JournalCandidate{Round: resultUC.InputRecord.RoundNumber, Number: block.Number,
				ParentNumber: block.Number - 1, Hash: block.Hash, StateRoot: block.StateRoot,
				ParentHash: block.ParentHash, ParentState: parentState, Raw: block.Raw,
				BlockSize: block.BlockSize, StateSize: block.StateSize, AuthorizingUC: original, AuthorizingTR: originalTR}
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
