package shardnode

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

// CertifiedCommit is one block the round committed on a certificate's authority: the executor's Commit
// returned StatusValid for BlockHash, which the certificate's input record names. Certificate and Technical
// are copies the receiver may keep.
type CertifiedCommit struct {
	Certificate *types.UnicityCertificate
	Technical   *certification.TechnicalRecord
	BlockHash   Hash
}

/*
CommitObserver is told about every block the round commits: one a certificate the round itself processed
certified (#14 W2), and one authenticated anchor recovery brought the executor to (#14 W3b-2). ObserveCommit
is called with the round lock held, after the executor's Commit and before the next round is driven, so it must
return promptly, must not call back into the node, and must do any slow work elsewhere. A recovery commit
reports the certificate that certified the block, which across a quiet tail is not the certificate in hand.
Quiet certificates, repeats and re-deliveries commit nothing and are not reported. Being told is not an
authorization: nothing the observer does changes what the round builds, validates or signs.
*/
type CommitObserver interface {
	ObserveCommit(CertifiedCommit)
}

// notifyCommit reports a certified commit to the observer, with copies it may keep. A certificate that cannot
// be copied is logged and not reported; the round is never failed for it.
func (r *Round) notifyCommit(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, block Hash) {
	if r.commitObserver == nil {
		return
	}
	ucCopy, trCopy, err := copyCertified(uc, tr)
	if err != nil {
		if r.log != nil {
			r.log.WarnContext(ctx, "not reporting a certified commit: the certificate could not be copied",
				slog.String("err", err.Error()), slog.Uint64("round", uc.GetRoundNumber()))
		}
		return
	}
	r.commitObserver.ObserveCommit(CertifiedCommit{Certificate: ucCopy, Technical: trCopy, BlockHash: bytes.Clone(block)})
}

// copyCertified deep-copies a certificate and its technical record through canonical CBOR.
func copyCertified(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) (*types.UnicityCertificate, *certification.TechnicalRecord, error) {
	ucBytes, err := types.Cbor.Marshal(uc)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding certificate: %w", err)
	}
	trBytes, err := types.Cbor.Marshal(tr)
	if err != nil {
		return nil, nil, fmt.Errorf("encoding technical record: %w", err)
	}
	var ucCopy types.UnicityCertificate
	if err := types.Cbor.Unmarshal(ucBytes, &ucCopy); err != nil {
		return nil, nil, fmt.Errorf("decoding certificate: %w", err)
	}
	var trCopy certification.TechnicalRecord
	if err := types.Cbor.Unmarshal(trBytes, &trCopy); err != nil {
		return nil, nil, fmt.Errorf("decoding technical record: %w", err)
	}
	return &ucCopy, &trCopy, nil
}
