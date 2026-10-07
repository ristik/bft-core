package types

import (
	"errors"
	"fmt"
)

// ErrTimestampProof refuses a block time not bound by its verified certificate.
// Certificate signature verification must precede this structural binding check.
var ErrTimestampProof = errors.New("block timestamp lacks matching authenticated proof")

func VerifyTimestampProof(block *BlockData, qc *QuorumCert) error {
	if block == nil || qc == nil || qc.VoteInfo == nil {
		return ErrTimestampProof
	}
	info := qc.VoteInfo
	if info.Epoch != block.Epoch || info.RoundNumber != block.Round || info.Timestamp == 0 || info.Timestamp != block.Timestamp {
		return fmt.Errorf("%w: block round %d", ErrTimestampProof, block.Round)
	}
	return nil
}
