package handoffdelivery

import (
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

// ErrClosure reports a terminal bundle that does not establish a closure.
var ErrClosure = errors.New("handoff delivery: bundle does not establish a closure")

// ClosureHistory is the root's committed history a closure is judged against. Nothing in it comes from the bundle's submitter.
type ClosureHistory interface {
	// TrustBase is the trust base of the closed root epoch and the signing configuration of its commit certificates.
	TrustBase(epoch uint64) (*types.RootTrustBaseV1, votesig.Config, error)
	// Assignment is the EVM shard's installed configuration hash at the root round the handoff was ordered, with the frozen identity
	// records and the assignment hash of the assignment that configuration carries (the one H terminates).
	Assignment(orderRound uint64) (confHash []byte, identities []evmassign.Identity, assignmentID [32]byte, err error)
}

// ClosureEvidence is what a verified terminal bundle establishes about the closed epoch (see storage.ClosureFacts).
type ClosureEvidence struct {
	ClosedEpoch  uint64
	BundleID     [32]byte
	HRecordID    [32]byte
	HRound       uint64
	TerminalRoot [32]byte
	AssignmentID [32]byte
	Closed       []evmassign.Identity
}

// ClosureVerifier verifies terminal bundles of the (one) EVM shard.
type ClosureVerifier struct {
	Partition types.PartitionID
	Shard     types.ShardID
	History   ClosureHistory
}

// Verify checks the canonical bundle bytes against the closed epoch's own committee and the shard configuration installed when H was
// ordered. The committee that signed the committed record must be the closed epoch's (the proof verifier binds the record's epoch to the
// trust base it is given), so a bundle of another handoff, or one signed by a later committee, is not a closure of this epoch.
func (v ClosureVerifier) Verify(witness []byte, closedEpoch uint64) (ClosureEvidence, error) {
	bundle, err := DecodeBundle(witness)
	if err != nil {
		return ClosureEvidence{}, errors.Join(ErrClosure, err)
	}
	old, cfg, err := v.History.TrustBase(closedEpoch)
	if err != nil {
		return ClosureEvidence{}, errors.Join(ErrClosure, err)
	}
	confHash, ids, assignmentID, err := v.History.Assignment(bundle.Proof.Record.OrderedRound)
	if err != nil {
		return ClosureEvidence{}, errors.Join(ErrClosure, err)
	}
	verified, err := VerifySigning(bundle, old, cfg, v.Partition, v.Shard, confHash)
	if err != nil {
		return ClosureEvidence{}, errors.Join(ErrClosure, err)
	}
	if verified.Record.SignerEpoch != closedEpoch {
		return ClosureEvidence{}, fmt.Errorf("%w: the record was committed by epoch %d, not the closed epoch %d", ErrClosure, verified.Record.SignerEpoch, closedEpoch)
	}
	identity, err := SemanticIdentity(bundle)
	if err != nil {
		return ClosureEvidence{}, errors.Join(ErrClosure, err)
	}
	return ClosureEvidence{ClosedEpoch: closedEpoch, BundleID: identity, HRecordID: verified.Record.RecordID, HRound: verified.Record.OrderRound,
		TerminalRoot: verified.Record.StateRoot, AssignmentID: assignmentID, Closed: ids}, nil
}
