package shardnode

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"
)

// Expectation is what the root chain's ShardInfo.ValidRequest will check
// against the next BlockCertificationRequest — derived from the last
// CertificationResponse this node accepted. Building it once per round and
// asserting it locally (via ValidateLocal) before ever sending anything is
// what turns a stale-round bug into a local test failure naming the wrong
// field, instead of a silent quorum miss thirty seconds later. See
// bft-core/rootchain/consensus/storage/sharding.go's ValidRequest for the
// root chain's own copy of these checks.
type Expectation struct {
	Round        uint64
	Epoch        uint64
	PreviousHash []byte // last certified state root
	Timestamp    uint64 // last UnicitySeal.Timestamp
}

// BuildInputRecord constructs the InputRecord for the next
// BlockCertificationRequest from what the round produced.
//
// quiet reports whether the round produced no state change: when true,
// hash must equal exp.PreviousHash exactly (the caller — round.go — is
// responsible for that; BuildInputRecord does not compute state, only
// assembles the record) and the resulting IR carries a nil BlockHash, per
// the root chain's rule that an unchanged state hash requires a nil block
// hash. See bft-go-base/types/input_record.go IsValid.
func BuildInputRecord(exp Expectation, hash, blockHash []byte, quiet bool) (*types.InputRecord, error) {
	if exp.Round == 0 {
		return nil, errors.New("shardnode: round number is unassigned — did the framework receive a TechnicalRecord yet?")
	}
	ir := &types.InputRecord{
		Version:         1,
		RoundNumber:     exp.Round,
		Epoch:           exp.Epoch,
		PreviousHash:    exp.PreviousHash,
		Hash:            hash,
		SummaryValue:    []byte{}, // must be non-nil once RoundNumber > 0; content unused by exec-mode
		Timestamp:       exp.Timestamp,
		SumOfEarnedFees: 0,
		ETHash:          nil,
	}
	if quiet {
		if !bytes.Equal(ir.Hash, ir.PreviousHash) {
			return nil, fmt.Errorf("shardnode: quiet round but hash %x != previousHash %x", ir.Hash, ir.PreviousHash)
		}
		ir.BlockHash = nil
	} else {
		if bytes.Equal(hash, exp.PreviousHash) {
			return nil, errors.New("shardnode: non-quiet round produced an unchanged state hash — this must be reported as quiet instead")
		}
		ir.BlockHash = blockHash
	}
	return ir, ir.IsValid()
}

// ValidateLocal re-checks an InputRecord against Expectation the same way
// the root chain's ShardInfo.ValidRequest will, so a mismatch is caught
// before the request ever reaches the wire — see the field-by-field
// mapping in docs/shard-protocol.md.
func ValidateLocal(ir *types.InputRecord, exp Expectation) error {
	if ir == nil {
		return errors.New("input record is nil")
	}
	if err := ir.IsValid(); err != nil {
		return fmt.Errorf("input record: %w", err)
	}
	if ir.RoundNumber != exp.Round {
		return fmt.Errorf("round number: have %d, root chain expects %d", ir.RoundNumber, exp.Round)
	}
	if ir.Epoch != exp.Epoch {
		return fmt.Errorf("epoch: have %d, root chain expects %d", ir.Epoch, exp.Epoch)
	}
	if !bytes.Equal(ir.PreviousHash, exp.PreviousHash) {
		return fmt.Errorf("previous hash: have %x, root chain's last certified state is %x", ir.PreviousHash, exp.PreviousHash)
	}
	if ir.Timestamp != exp.Timestamp {
		return fmt.Errorf("timestamp: have %d, last UnicitySeal.Timestamp is %d", ir.Timestamp, exp.Timestamp)
	}
	return nil
}

// ExpectationFromCertificate derives the next round's Expectation from a
// CertificationResponse's UC and TechnicalRecord — the framework's single
// point of truth for "what must our next request look like", so
// bftclient.go and round.go never compute this independently and risk
// disagreeing.
func ExpectationFromCertificate(uc *types.UnicityCertificate, round, epoch uint64) (Expectation, error) {
	if uc == nil || uc.InputRecord == nil || uc.UnicitySeal == nil {
		return Expectation{}, errors.New("shardnode: certificate is incomplete")
	}
	return Expectation{
		Round:        round,
		Epoch:        epoch,
		PreviousHash: uc.InputRecord.Hash,
		Timestamp:    uc.UnicitySeal.Timestamp,
	}, nil
}
