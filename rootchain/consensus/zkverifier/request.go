package zkverifier

import (
	"fmt"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Outcome is what the configured-proof check did with a request.
type Outcome int

const (
	// Verified - the configured proof of the transition checked out.
	Verified Outcome = iota
	// Disabled - the shard's configuration names no proof (m-of-n mode); the aggregator's signatures are the whole predicate.
	Disabled
	// SkippedSync - both roots are empty: a handshake or subscription request, no transition.
	SkippedSync
	// SkippedGenesis - the previous root is empty: the first state-changing block is sent from heaven.
	SkippedGenesis
)

// Target is the configuration a request's proof is judged under: the shard, its epoch and the partition parameters in force.
type Target struct {
	Partition types.PartitionID
	Shard     types.ShardID
	Epoch     uint64
	Params    map[string]string
}

// VerifyRequest is the one place a request's configured consistency proof is judged. The root that receives the request (Node intake) and
// every root that validates it again before voting (the IR change verifier, on the proposal and replay paths) call it, so no root takes
// another's word that the proof held. The proof is checked against the request's own roots, block hash and reference time (the input
// record's timestamp, which the signature covers). Disabled, sync and genesis requests are the explicit exceptions; a T2 repeat carries no
// requests, so there is nothing to check.
func (r *Registry) VerifyRequest(req *certification.BlockCertificationRequest, t Target) (Outcome, error) {
	ir := req.InputRecord
	if ir == nil {
		return Verified, fmt.Errorf("input record is nil")
	}
	verifier, err := r.GetVerifier(t.Partition, t.Shard, t.Epoch, t.Params)
	if err != nil {
		return Verified, fmt.Errorf("getting verifier for partition %s: %w", t.Partition, err)
	}
	if !verifier.IsEnabled() {
		return Disabled, nil
	}
	if len(ir.PreviousHash) == 0 && len(ir.Hash) == 0 {
		return SkippedSync, nil
	}
	if len(ir.PreviousHash) == 0 {
		return SkippedGenesis, nil
	}
	if rt, ok := verifier.(ReferenceTimeVerifier); ok {
		// the stored leaf values bind the round's reference time, which is the request's input record timestamp
		err = rt.VerifyProofAt(req.ZkProof, ir.PreviousHash, ir.Hash, ir.BlockHash, ir.Timestamp)
	} else {
		err = verifier.VerifyProof(req.ZkProof, ir.PreviousHash, ir.Hash, ir.BlockHash)
	}
	if err != nil {
		return Verified, fmt.Errorf("ZK proof verification failed: %w", err)
	}
	return Verified, nil
}
