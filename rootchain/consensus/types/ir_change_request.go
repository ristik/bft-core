package types

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/internal/quorumweight"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	abhash "github.com/unicitynetwork/bft-go-base/hash"
	"github.com/unicitynetwork/bft-go-base/types"
)

const (
	Quorum IRChangeReason = iota
	QuorumNotPossible
	T2Timeout
)

type (
	IRChangeReason uint8

	IRChangeReq struct {
		_          struct{} `cbor:",toarray"`
		Partition  types.PartitionID
		Shard      types.ShardID
		CertReason IRChangeReason
		// IR change (quorum or no quorum possible of block certification requests)
		Requests []*certification.BlockCertificationRequest
	}

	// RequestVerifier decides which requests are valid for the shard round (ValidRequest: signature, membership and
	// continuity) and carries the weights they are counted with.
	RequestVerifier interface {
		RequestWeights
		ValidRequest(req *certification.BlockCertificationRequest) error
	}

	CertRequestVerifier interface {
		IRRound() uint64
		IRPreviousHash() []byte
	}

	sha256Hash [sha256.Size]byte
)

func (r IRChangeReason) String() string {
	switch r {
	case Quorum:
		return "quorum"
	case QuorumNotPossible:
		return "no-quorum"
	case T2Timeout:
		return "timeout"
	}
	return fmt.Sprintf("unknown IR change reason %d", int(r))
}

func (x *IRChangeReq) IsValid() error {
	// ignore other values for now, just make sure it is not negative
	if x.CertReason > T2Timeout {
		return withSentinels{fmt.Errorf("unknown reason (%d)", x.CertReason), []error{ErrInvalidRequest}}
	}
	return nil
}

func (x *IRChangeReq) Verify(tb RequestVerifier, luc *types.UnicityCertificate, rootRound, t2InRounds uint64) (*types.InputRecord, error) {
	if tb == nil {
		return nil, errors.New("RequestVerifier is unassigned")
	}
	if err := x.IsValid(); err != nil {
		return nil, fmt.Errorf("invalid IR Change Request: %w", err)
	}
	// quick sanity check, there cannot be more requests than known partition nodes (a member count, not a weight)
	if uint64(len(x.Requests)) > uint64(tb.MemberCount()) {
		return nil, withSentinels{errors.New("IR Change Request contains more requests than registered partition nodes"), []error{ErrInvalidRequest}}
	}
	// verify IR change proof: every request is validated and counted from the proof alone, never from a claimed total
	tally := NewRequestTally(tb)
	for _, req := range x.Requests {
		if req == nil {
			return nil, fmt.Errorf("invalid partition %s proof: %w: nil request", x.Partition, ErrInvalidRequest)
		}
		if x.Partition != req.PartitionID || !x.Shard.Equal(req.ShardID) {
			return nil, withSentinels{fmt.Errorf("shard of the change request is %s-%s but block certification request is for %s=%s",
				x.Partition, x.Shard, req.PartitionID, req.ShardID), []error{ErrInvalidRequest}}
		}
		if err := tb.ValidRequest(req); err != nil {
			// an unknown signer and a bad signature keep their own identities; any other refusal is a malformed request
			if !errors.Is(err, ErrInvalidRequest) && !errors.Is(err, quorumweight.ErrUnknownSigner) && !errors.Is(err, quorumweight.ErrInvalidSignature) {
				err = withSentinels{err, []error{ErrInvalidRequest}}
			}
			return nil, fmt.Errorf("invalid certification request: %w", err)
		}
		// the group of the request: its IR and sizes
		hash, err := abhash.HashValues(crypto.SHA256, req.InputRecord, req.BlockSize, req.StateSize)
		if err != nil {
			return nil, withSentinels{fmt.Errorf("failed to calculate hash: %w", err), []error{ErrInvalidRequest}}
		}
		if err := tally.Add(req.NodeID, sha256Hash(hash)); err != nil {
			if errors.Is(err, quorumweight.ErrDuplicateSigner) {
				return nil, withSentinels{fmt.Errorf("invalid partition %s proof: contains duplicate request from node %v", x.Partition, req.NodeID),
					[]error{quorumweight.ErrDuplicateSigner, ErrInvalidRequest}}
			}
			return nil, fmt.Errorf("invalid certification request: %w", err)
		}
	}
	// match request type to proof
	switch x.CertReason {
	case Quorum:
		if err := tally.Validate(); err != nil {
			return nil, withSentinels{fmt.Errorf("invalid partition %s proof: %w", x.Partition, err), []error{ErrInvalidRequest}}
		}
		// 1. require that all input records served as proof are the same
		// reject requests carrying redundant info, there is no use for proofs that do not participate in quorum
		// perhaps this is a bit harsh, but let's not waste bandwidth
		if tally.Groups() != 1 {
			return nil, withSentinels{fmt.Errorf("invalid partition %s quorum proof: contains proofs for different state hashes", x.Partition), []error{ErrInvalidRequest}}
		}
		// 2. the matching weight must reach the threshold, more than 50% of the total
		if !tally.QuorumReached() {
			return nil, withSentinels{fmt.Errorf("invalid partition %s quorum proof: not enough requests to prove quorum (got %d, need %d)", x.Partition, tally.Matching(), tb.Threshold()),
				[]error{quorumweight.ErrQuorumNotReached, ErrInvalidRequest}}
		}
		// if any request did not extend previous state the whole IRChange request is rejected in validation step
		// NB! there was at least one request, otherwise we would not be here
		return x.Requests[0].InputRecord, nil
	case QuorumNotPossible:
		if err := tally.Validate(); err != nil {
			return nil, withSentinels{fmt.Errorf("invalid partition %s proof: %w", x.Partition, err), []error{ErrInvalidRequest}}
		}
		if tally.QuorumReached() {
			return nil, withSentinels{fmt.Errorf("can't certify 'no quorum' as one input already does have quorum (%d votes, quorum is %d)", tally.Matching(), tb.Threshold()), []error{ErrInvalidRequest}}
		}
		// Verify that enough weight has voted for different IR change: even if all the weight still missing (W-R) joined
		// the heaviest group, M+U must be strictly below Q. M+U == Q is still possible.
		impossible, err := tally.QuorumImpossible()
		if err != nil {
			return nil, withSentinels{fmt.Errorf("invalid partition %s 'no quorum' proof: %w", x.Partition, err), []error{ErrInvalidRequest}}
		}
		if !impossible {
			return nil, withSentinels{fmt.Errorf("not enough votes to prove 'no quorum' - it is possible to get %d votes, quorum is %d",
				tb.TotalWeight()-tally.Received()+tally.Matching(), tb.Threshold()), []error{ErrInvalidRequest}}
		}
		// initiate repeat UC
		return luc.InputRecord.NewRepeatIR(), nil
	case T2Timeout:
		// timeout does not carry proof in form of certification requests
		// again this is not fatal in itself, but we should not encourage redundant info
		if len(x.Requests) != 0 {
			return nil, withSentinels{fmt.Errorf("invalid partition %s timeout proof: proof contains requests", x.Partition), []error{ErrInvalidRequest}}
		}

		// validate timeout against LUC age
		idleRounds := rootRound - luc.GetRootRoundNumber()
		if idleRounds < t2InRounds {
			return nil, withSentinels{fmt.Errorf("invalid partition %s timeout proof: time from latest UC %v, timeout in rounds %v",
				x.Partition, idleRounds, t2InRounds), []error{ErrInvalidRequest}}
		}
		// initiate repeat UC
		return luc.InputRecord.NewRepeatIR(), nil
	}
	// should be unreachable, since validate method already makes sure that reason is known
	return nil, fmt.Errorf("invalid request: unknown certification reason %v", x.CertReason)
}

func (x *IRChangeReq) String() string {
	return fmt.Sprintf("%s->%s", x.Partition, x.CertReason)
}
