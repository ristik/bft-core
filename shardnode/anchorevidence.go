package shardnode

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

/*
Authenticated execution-anchor recovery across a quiet tail — the VERIFICATION half.

WHY THIS EXISTS. A shard node that returns behind a certified block cannot recover while the shard
stays quiet: quiet certificates carry no block hash, so nothing it receives names the block its
executor is missing, and it refuses `no-anchor` indefinitely. Measured on a real devnet (#111,
docs/design/f1-baseline.md §5.7.3): 20 certified rounds over two minutes, every one quiet, every
anchor decision `unchanged`, the executor a block behind — and recovery on the first poll after a
single non-quiet round. The missing capability is authenticated evidence that NAMES a block, not the
payload; see the design record in docs/design/f6b-quiet-tail-anchor-recovery.md.

WHAT THIS FILE IS, AND IS NOT. It is the predicate: given a candidate evidence bundle, does it
authenticate an execution anchor for the state this node is currently being asked to build on? It is
deliberately NOT wired into Round: nothing calls VerifyAnchorEvidence in production yet, because the
transport that fetches a bundle, the resource policy around it and the decision of who may serve one
are all still design questions. The predicate is here first because it is the part whose correctness
is decidable now, in fixtures, and because every one of those later decisions has to be checked
against it rather than the other way round.

WHAT IT NEVER DOES. It authorizes no signing (P-sign, #105, is untouched: a recovered executor is
not a licence to vote), it fetches no payload (a separate decision — the client's own ancestor
acquisition through the standard Engine API is what obtained the missing block in every run
measured so far), and it trusts nothing supplied alongside the evidence. Trust bases come from the
node's own configured store, keyed by the epoch the certificate names, and the partition, shard and
configuration are the running node's own.
*/

// AnchorEvidence is what a returning node must obtain to name the block its executor is missing.
//
// It is a chain, not a certificate: the source names the block, and the certificates after it are
// what connect that block to the certificate the node already holds. Anything less is a claim about
// history rather than a proof of it — §3.3.1 of the stage-2 design shows a missed non-quiet interval
// returning to the same state root behind a DIFFERENT block, which a source certificate alone
// cannot exclude.
type AnchorEvidence struct {
	// Source is the non-quiet certificate that certified the block, with the technical record bound
	// to it — the record is what assigns the next round, and contiguity is checked against that
	// assignment rather than against round+1.
	Source          *types.UnicityCertificate
	SourceTechnical *certification.TechnicalRecord

	// Tail is every certificate from the round Source assigned, in order, up to and including the
	// one the node itself already holds. Each carries the technical record bound to it.
	Tail []EvidenceLink
}

// EvidenceLink is one certificate of the tail with its bound technical record.
type EvidenceLink struct {
	UC        *types.UnicityCertificate
	Technical *certification.TechnicalRecord
}

// AnchorEvidenceLimits bounds the work a bundle may cost before it is refused. An unbounded chain
// is a denial-of-service surface offered by whoever serves the evidence, so exceeding a bound is a
// NAMED refusal and never a truncation: a shortened chain is not evidence of anything.
type AnchorEvidenceLimits struct {
	MaxCertificates int // including the source
	MaxBytes        int // total encoded size of the certificates
}

// DefaultAnchorEvidenceLimits are starting values, to be revisited against a measured quiet tail.
// 512 certificates is the same order as the persisted-continuity bound in the stage-2 design; 1 MiB
// bounds the file independently of validator-set size, which drives per-certificate size.
var DefaultAnchorEvidenceLimits = AnchorEvidenceLimits{MaxCertificates: 512, MaxBytes: 1 << 20}

// AnchorEvidenceContext is what the node knows about ITSELF: the configuration a bundle has to
// match, and the certificate it currently holds. None of it comes from the evidence.
type AnchorEvidenceContext struct {
	PartitionID   types.PartitionID
	ShardID       types.ShardID
	ShardConfHash []byte // may be nil while F2 (#10) has not plumbed it through; see Verify below
	TrustBases    TrustBaseStore

	// Held is the certificate this node has itself verified and is being asked to build on. The
	// evidence must end exactly here, or it is about some other point in the chain.
	Held *types.UnicityCertificate
}

// Named outcomes. Every refusal says which rule rejected the bundle, so a log line maps to a case
// in the design record rather than to a generic failure.
var (
	ErrEvidenceUnauthenticated = errors.New("anchor evidence: a certificate did not verify against the configured trust base")
	ErrEvidenceWrongContext    = errors.New("anchor evidence: a certificate is for another partition, shard, epoch or configuration")
	ErrEvidenceGap             = errors.New("anchor evidence: a certificate is not the round its predecessor assigned")
	ErrEvidenceNotQuiet        = errors.New("anchor evidence: a certificate after the source is not quiet at the source's state")
	ErrEvidenceSourceQuiet     = errors.New("anchor evidence: the source certificate names no block")
	ErrEvidenceUnconnected     = errors.New("anchor evidence: the chain does not end at the certificate this node holds")
	ErrEvidenceExhausted       = errors.New("anchor evidence: the chain exceeds the configured bounds")
	ErrEvidenceEpochChange     = errors.New("anchor evidence: the chain crosses an epoch boundary, which this predicate does not support")
	ErrEvidenceMalformed       = errors.New("anchor evidence: the bundle is structurally incomplete")
)

/*
VerifyAnchorEvidence decides whether a bundle authenticates an execution anchor for the state this
node is being asked to build on, and returns that anchor if it does.

The order of the checks is deliberate: cheap structural rejections first, then per-certificate
authentication, then the chain properties. A caller may therefore refuse a malformed or oversized
bundle without doing any signature work on it.
*/
func VerifyAnchorEvidence(ctx context.Context, ev AnchorEvidence, c AnchorEvidenceContext, limits AnchorEvidenceLimits) (*ExecutionAnchor, error) {
	if ev.Source == nil || ev.Source.InputRecord == nil || ev.SourceTechnical == nil || c.Held == nil || c.Held.InputRecord == nil {
		return nil, ErrEvidenceMalformed
	}
	if limits.MaxCertificates > 0 && len(ev.Tail)+1 > limits.MaxCertificates {
		return nil, fmt.Errorf("%w: %d certificates, limit %d", ErrEvidenceExhausted, len(ev.Tail)+1, limits.MaxCertificates)
	}
	if len(ev.Source.InputRecord.BlockHash) == 0 {
		return nil, ErrEvidenceSourceQuiet
	}

	// Size is measured from the canonical encoding the signatures cover, not from a field count.
	if limits.MaxBytes > 0 {
		total := 0
		for _, uc := range append([]*types.UnicityCertificate{ev.Source}, ucsOf(ev.Tail)...) {
			b, err := types.Cbor.Marshal(uc)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrEvidenceMalformed, err)
			}
			total += len(b)
			if total > limits.MaxBytes {
				return nil, fmt.Errorf("%w: over %d bytes", ErrEvidenceExhausted, limits.MaxBytes)
			}
		}
	}

	sourceEpoch := ev.Source.InputRecord.Epoch
	verify := func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
		if uc == nil || uc.InputRecord == nil || tr == nil {
			return ErrEvidenceMalformed
		}
		if uc.InputRecord.Epoch != sourceEpoch {
			// An epoch change moves the validator set and the configuration with it. Recovering
			// across one is a different problem, and saying so is safer than deciding it here.
			return fmt.Errorf("%w: source epoch %d, certificate epoch %d", ErrEvidenceEpochChange, sourceEpoch, uc.InputRecord.Epoch)
		}
		// The context checks come FIRST and are their own refusal. uc.Verify would also reject a
		// certificate for another partition, shard or configuration, but it reports that the same
		// way it reports a bad signature — and the two are different situations: one is a provider
		// serving the wrong chain, the other is a provider serving a forgery. Checking here keeps
		// them apart in the refusal name, and the values compared are the RUNNING NODE's own
		// configuration, never anything travelling with the evidence.
		if uc.GetPartitionID() != c.PartitionID {
			return fmt.Errorf("%w: certificate is for partition %d, this node runs %d", ErrEvidenceWrongContext, uc.GetPartitionID(), c.PartitionID)
		}
		if !uc.GetShardID().Equal(c.ShardID) {
			return fmt.Errorf("%w: certificate is for shard %s, this node runs %s", ErrEvidenceWrongContext, uc.GetShardID(), c.ShardID)
		}
		if len(c.ShardConfHash) != 0 && !bytes.Equal(uc.ShardConfHash, c.ShardConfHash) {
			return fmt.Errorf("%w: certificate names shard configuration %x, this node runs %x", ErrEvidenceWrongContext, uc.ShardConfHash, c.ShardConfHash)
		}
		// The trust base comes from the node's own store, keyed by the root epoch the certificate
		// names — never from anything travelling with the evidence. An unknown epoch is a refusal,
		// not a reason to accept.
		tb, err := c.TrustBases.GetByEpoch(ctx, uc.GetRootEpoch())
		if err != nil {
			return fmt.Errorf("%w: root epoch %d: %w", ErrEvidenceUnauthenticated, uc.GetRootEpoch(), err)
		}
		if err := uc.Verify(tb, crypto.SHA256, c.PartitionID, c.ShardID, c.ShardConfHash); err != nil {
			return fmt.Errorf("%w: %w", ErrEvidenceUnauthenticated, err)
		}
		// The technical record is bound to the certificate by hash; an unbound one would let a
		// provider choose the assignment the contiguity check is made against.
		trHash, err := tr.Hash()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrEvidenceMalformed, err)
		}
		if !bytes.Equal(trHash, uc.TRHash) {
			return fmt.Errorf("%w: technical record is not the one this certificate commits to", ErrEvidenceWrongContext)
		}
		return nil
	}

	if err := verify(ev.Source, ev.SourceTechnical); err != nil {
		return nil, err
	}

	// The chain: each certificate must be the round its predecessor ASSIGNED, quiet, and at the
	// source's state. Assignment, not round+1 — the root chain abandons rounds, and testing the
	// arithmetic instead invalidated honest evidence (docs/design/f6b-quiet-uc-recovery.md §3.3.2).
	state := ev.Source.InputRecord.Hash
	expectedNext := ev.SourceTechnical.Round
	last := ev.Source
	for i, link := range ev.Tail {
		if err := verify(link.UC, link.Technical); err != nil {
			return nil, fmt.Errorf("tail[%d]: %w", i, err)
		}
		ir := link.UC.InputRecord
		if ir.RoundNumber != expectedNext {
			return nil, fmt.Errorf("%w: round %d arrived where %d was assigned", ErrEvidenceGap, ir.RoundNumber, expectedNext)
		}
		if len(ir.BlockHash) != 0 || !bytes.Equal(ir.Hash, state) || !bytes.Equal(ir.PreviousHash, state) {
			return nil, fmt.Errorf("%w: round %d", ErrEvidenceNotQuiet, ir.RoundNumber)
		}
		expectedNext = link.Technical.Round
		last = link.UC
	}

	// It must end where this node stands: the same partition round, at the same state. Evidence
	// that stops short proves something about the past and nothing about now — and §6.1's
	// replayable-checkpoint counterexample is exactly a complete, correctly signed chain that ends
	// too early.
	//
	// The ROOT round is deliberately not compared. A repeat certificate re-certifies the same
	// partition round at a later root round after a timeout, and it is ordinary for a node to hold
	// one; requiring the provider to have ended on the same root round would refuse honest evidence
	// for a reason that has nothing to do with the shard's history. Partition round and state are
	// the whole claim.
	if last.GetRoundNumber() != c.Held.GetRoundNumber() {
		return nil, fmt.Errorf("%w: chain ends at partition round %d, this node holds %d",
			ErrEvidenceUnconnected, last.GetRoundNumber(), c.Held.GetRoundNumber())
	}
	if !bytes.Equal(c.Held.InputRecord.Hash, state) {
		// Same round, different state: the two certificates disagree about one round, and both
		// authenticate. Nothing here can say which is the shard's history, so neither is used.
		return nil, fmt.Errorf("%w: the chain proves state %x for round %d, this node holds %x",
			ErrEvidenceUnconnected, state, last.GetRoundNumber(), c.Held.InputRecord.Hash)
	}

	return &ExecutionAnchor{
		BlockHash:        Hash(ev.Source.InputRecord.BlockHash),
		StateRoot:        Hash(ev.Source.InputRecord.Hash),
		Round:            ev.Source.InputRecord.RoundNumber,
		fromGenesisRound: len(ev.Source.InputRecord.PreviousHash) == 0,
	}, nil
}

func ucsOf(links []EvidenceLink) []*types.UnicityCertificate {
	out := make([]*types.UnicityCertificate, 0, len(links))
	for _, l := range links {
		out = append(out, l.UC)
	}
	return out
}
