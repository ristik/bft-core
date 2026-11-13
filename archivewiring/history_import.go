package archivewiring

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	gethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/unicitynetwork/bft-core/archive"
	"github.com/unicitynetwork/bft-core/frontier"
	"github.com/unicitynetwork/bft-go-base/types"
)

// HistoryVerifier is the verified historical import of a replica (bft-core#1030): it accepts a publication that this node's own journal
// and coverage cannot vouch for (a block below its restore base, or one it never held hot) when
//
//   - the local archive already holds an authenticated record of the same block, with identical header and body bytes. A restore
//     fetches every block from its trusted pin back to genesis and authenticates each one (its hash is the parent hash of an
//     authenticated child, its certificates verify under this node's trust base) before it stores it; the publisher and the other
//     verifiers store only certified blocks of this node's own chain. So the block is known, independently of the sender; and
//   - the offered record's certificates authenticate under this node's own trust base and certify exactly that block (header, body,
//     receipts, companion and the root position: CertifiedBinding).
//
// The offered record may be another representation of the block (another valid certificate pair, bft-core#876): it is then stored as a
// variant, next to what is held, so the writer's exact manifest can be read back. Nothing stored is replaced, and nothing is accepted for
// a block this node does not already know: ordinary publication is not weakened.
func HistoryVerifier(local *archive.Store, binding CertifiedBinding) Verifier {
	return func(_ context.Context, q archive.Request, rec *archive.Record) error {
		if local == nil || rec == nil {
			return ErrBinding
		}
		held, err := local.Get(q)
		if err != nil {
			return fmt.Errorf("%w: this replica holds no authenticated record of block %x", ErrUncertified, q.BlockHash[:8])
		}
		if !bytes.Equal(held.Header, rec.Header) || !bytes.Equal(held.Body, rec.Body) {
			return fmt.Errorf("%w: the offered record is not the block this replica holds", ErrBinding)
		}
		r, err := certifiedRecordOf(q, rec)
		if err != nil {
			return err
		}
		if err := binding.VerifyCertified(r, rec); err != nil {
			return fmt.Errorf("%w: the offered certificates do not certify the held block: %v", ErrBinding, err)
		}
		return nil
	}
}

// certifiedRecordOf is the frontier view of an archive record (its height, state root and resulting root position), for the binding check.
func certifiedRecordOf(q archive.Request, rec *archive.Record) (frontier.Record, error) {
	var header gethtypes.Header
	var uc types.UnicityCertificate
	if rlp.DecodeBytes(rec.Header, &header) != nil || header.Number == nil || types.Cbor.Unmarshal(rec.ResultingUC, &uc) != nil || uc.InputRecord == nil {
		return frontier.Record{}, ErrBinding
	}
	return frontier.Record{Height: header.Number.Uint64(), Epoch: uc.GetRootEpoch(), Round: uc.GetRootRoundNumber(), StateRoot: [32]byte(header.Root), Subject: q}, nil
}

// ChainVerifiers accepts what the first of the verifiers accepts; a refusal by all reports each reason.
func ChainVerifiers(verifiers ...Verifier) Verifier {
	return func(ctx context.Context, q archive.Request, rec *archive.Record) error {
		var refused error
		for _, v := range verifiers {
			err := v(ctx, q, rec)
			if err == nil {
				return nil
			}
			refused = errors.Join(refused, err)
		}
		if refused == nil {
			return ErrBinding
		}
		return refused
	}
}
