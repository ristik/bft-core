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
	ErrEvidenceWrongContext    = errors.New("anchor evidence: a certificate is for another partition, shard or configuration")
	ErrEvidenceGap             = errors.New("anchor evidence: a certificate is not the round its predecessor assigned")
	ErrEvidenceNotQuiet        = errors.New("anchor evidence: a certificate after the source is not quiet at the source's state")
	ErrEvidenceSourceQuiet     = errors.New("anchor evidence: the source certificate names no block")
	ErrEvidenceUnconnected     = errors.New("anchor evidence: the chain does not reach the round this node holds")
	ErrEvidenceConflict        = errors.New("anchor evidence: the chain and this node's own certificate make conflicting authenticated statements about the same round")
	ErrEvidenceExhausted       = errors.New("anchor evidence: the bundle exceeds the configured bounds")
	ErrEvidenceEpochChange     = errors.New("anchor evidence: the chain crosses an epoch boundary, which this predicate does not support")
	ErrEvidenceMalformed       = errors.New("anchor evidence: the bundle is structurally incomplete")
	ErrEvidenceLimitsInvalid   = errors.New("anchor evidence: the caller supplied no positive resource bound")
)

/*
Retryable says whether trying a DIFFERENT provider could plausibly produce a bundle that verifies.

It is a property of the refusal, not of the provider, and getting it wrong in either direction
costs: treating every refusal as fatal lets one unhelpful or malicious peer end a recovery attempt
that a second peer would have completed, and treating every refusal as retryable spends bandwidth
re-asking about facts of the shard's own history that no provider can change.

Everything a provider controls — what it serves, how much of it, whether it is honest, whether it
is current — is retryable. A truncated or stale chain (Unconnected) is the ordinary case of a peer
that simply has less than the requester needs, and is emphatically NOT evidence that other peers are
equally unhelpful. Only two outcomes are not about the provider:

  - EpochChange: the shard's history genuinely crosses an epoch boundary. Every honest provider will
    say the same thing, because it is true.
  - Conflict: this node's own authenticated certificate and an authenticated chain disagree about
    one round. That is a statement about the certified history, and no third party can adjudicate
    it. It must surface as a refusal, not as a reason to shop for a provider that agrees.
*/
func Retryable(err error) bool {
	switch {
	case err == nil:
		return false
	case errors.Is(err, ErrEvidenceEpochChange), errors.Is(err, ErrEvidenceConflict),
		errors.Is(err, ErrEvidenceLimitsInvalid):
		return false
	default:
		return true
	}
}

/*
VerifyAnchorEvidence decides whether a bundle authenticates an execution anchor for the state this
node is being asked to build on, and returns that anchor if it does.

The order of the checks is deliberate, and is part of the contract rather than an implementation
detail: structural rejection, then the resource bounds over the COMPLETE bundle, and only then any
hashing or signature work. A caller may therefore refuse an oversized bundle at a cost proportional
to reading it once, and nothing an adversary puts in a bundle can buy cryptographic work before the
bound has been applied.
*/
func VerifyAnchorEvidence(ctx context.Context, ev AnchorEvidence, c AnchorEvidenceContext, limits AnchorEvidenceLimits) (*ExecutionAnchor, error) {
	if ev.Source == nil || ev.Source.InputRecord == nil || ev.SourceTechnical == nil || c.Held == nil || c.Held.InputRecord == nil {
		return nil, ErrEvidenceMalformed
	}
	// Both bounds must be positive. A zero previously meant "unlimited", which is the wrong default
	// for a value an integration can forget to set: forgetting must fail loudly, not silently
	// remove the bound that the rest of this function relies on.
	if limits.MaxCertificates <= 0 || limits.MaxBytes <= 0 {
		return nil, fmt.Errorf("%w: MaxCertificates=%d MaxBytes=%d", ErrEvidenceLimitsInvalid, limits.MaxCertificates, limits.MaxBytes)
	}
	if len(ev.Tail)+1 > limits.MaxCertificates {
		return nil, fmt.Errorf("%w: %d certificates, limit %d", ErrEvidenceExhausted, len(ev.Tail)+1, limits.MaxCertificates)
	}

	// The size bound covers the WHOLE bundle — every certificate AND every technical record. The
	// technical records are attacker-controlled bundle content too: Leader is a string and StatHash
	// and FeeHash are byte strings, so an otherwise small certificate can carry a megabyte of
	// technical record. Measuring only the certificates left tr.Hash() to be handed that megabyte,
	// after signature verification had already been paid for.
	//
	// This is a bound on the bundle as this process holds it, and NOT a network allocation bound:
	// by the time it runs, a decoder has already materialised whatever arrived. The transport that
	// eventually fetches a bundle must cap its own read and decode independently, and that cap is
	// a separate decision recorded in §4 of the design record.
	encoded, err := types.Cbor.Marshal(ev)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvidenceMalformed, err)
	}
	if len(encoded) > limits.MaxBytes {
		return nil, fmt.Errorf("%w: bundle encodes to %d bytes, limit %d", ErrEvidenceExhausted, len(encoded), limits.MaxBytes)
	}

	if len(ev.Source.InputRecord.BlockHash) == 0 {
		return nil, ErrEvidenceSourceQuiet
	}

	// sourceEpoch is the shard epoch the WHOLE bundle, and this node's own held certificate, must
	// be in. An epoch change moves the validator set and the configuration with it; recovering
	// across one is a different problem, and saying so is safer than deciding it here.
	sourceEpoch := ev.Source.InputRecord.Epoch

	// authenticate is everything that must hold of a single certificate on its own, independently
	// of where it sits in the chain. It is applied to every certificate in the bundle AND to this
	// node's own held certificate: "held" means this node verified it when it arrived, but the
	// recovery context is a different question from the delivery context, and re-checking it here
	// costs one signature verification and closes the case where the two differ.
	authenticate := func(uc *types.UnicityCertificate) error {
		if uc == nil || uc.InputRecord == nil {
			return ErrEvidenceMalformed
		}
		if uc.InputRecord.Epoch != sourceEpoch {
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
		return nil
	}

	// bindTechnical checks that the technical record travelling with a certificate is the one the
	// certificate commits to. An unbound record would let whoever serves the evidence choose the
	// assignment that contiguity is judged against.
	bindTechnical := func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
		if tr == nil {
			return ErrEvidenceMalformed
		}
		trHash, err := tr.Hash()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrEvidenceMalformed, err)
		}
		if !bytes.Equal(trHash, uc.TRHash) {
			return fmt.Errorf("%w: technical record is not the one this certificate commits to", ErrEvidenceWrongContext)
		}
		return nil
	}

	verify := func(uc *types.UnicityCertificate, tr *certification.TechnicalRecord) error {
		if err := authenticate(uc); err != nil {
			return err
		}
		return bindTechnical(uc, tr)
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

		// REPEAT NORMALISATION. A repeat certificate re-certifies a round the root chain already
		// certified, at a later root round, with the SAME input record and a NEW technical record —
		// which means a new assignment. It is an ordinary product of a root-chain timeout, so a
		// literal transcript of what a provider observed contains repeats, and rejecting them as a
		// gap would make honest evidence unrepresentable.
		//
		// The rule: same partition round as the certificate just accepted, byte-identical input
		// record, strictly later root round. It supersedes only the ASSIGNMENT; it does not extend
		// the interval, because the interval is keyed by partition round (§3.3.3) and a repeat
		// covers a round already covered. Requiring a strictly later root round is what stops a
		// provider replaying one repeat to rewrite the assignment freely.
		if ir.RoundNumber == last.InputRecord.RoundNumber {
			sameIR, err := sameInputRecord(link.UC, last)
			if err != nil {
				return nil, fmt.Errorf("tail[%d]: %w: %w", i, ErrEvidenceMalformed, err)
			}
			if !sameIR {
				return nil, fmt.Errorf("tail[%d]: %w: two certificates for round %d disagree",
					i, ErrEvidenceConflict, ir.RoundNumber)
			}
			if link.UC.GetRootRoundNumber() <= last.GetRootRoundNumber() {
				return nil, fmt.Errorf("tail[%d]: %w: repeat of round %d at root round %d does not follow root round %d",
					i, ErrEvidenceGap, ir.RoundNumber, link.UC.GetRootRoundNumber(), last.GetRootRoundNumber())
			}
			expectedNext = link.Technical.Round
			last = link.UC
			continue
		}

		if ir.RoundNumber != expectedNext {
			return nil, fmt.Errorf("%w: round %d arrived where %d was assigned", ErrEvidenceGap, ir.RoundNumber, expectedNext)
		}
		if len(ir.BlockHash) != 0 || !bytes.Equal(ir.Hash, state) || !bytes.Equal(ir.PreviousHash, state) {
			return nil, fmt.Errorf("%w: round %d", ErrEvidenceNotQuiet, ir.RoundNumber)
		}
		expectedNext = link.Technical.Round
		last = link.UC
	}

	// THE TERMINAL BINDING. The chain must end at the certificate this node is actually being asked
	// to build on — and "the certificate", not "a certificate with the same round number and the
	// same state root". Round and state alone were not enough: a genuinely signed round-16
	// certificate at the same state that NAMES A BLOCK is a different statement about round 16 than
	// a quiet one, and the block hash is exactly what P-id gates signing on.
	//
	// So the held certificate is put through the same authentication and the same recovery context
	// as the evidence — which is also what makes an epoch change at the endpoint fire the epoch
	// contract instead of being ignored — and then the two input records are compared as the signed
	// objects they are.
	if err := authenticate(c.Held); err != nil {
		return nil, fmt.Errorf("held certificate: %w", err)
	}
	if last.GetRoundNumber() != c.Held.GetRoundNumber() {
		// Evidence that stops short proves something about the past and nothing about now — §6.1's
		// replayable-checkpoint counterexample is exactly a complete, correctly signed chain that
		// ends too early. This is a provider that has less than the requester needs, so it is
		// retryable against another provider.
		return nil, fmt.Errorf("%w: chain reaches partition round %d, this node holds %d",
			ErrEvidenceUnconnected, last.GetRoundNumber(), c.Held.GetRoundNumber())
	}
	// Identity is InputRecord.Bytes() — the canonical encoding the root chain's signatures actually
	// cover, which is also what uc.go uses to decide equivocation. It distinguishes nil from empty,
	// and it cannot silently omit a field added later, which a field-by-field comparison written
	// out here would. The root round and the signature set are deliberately outside it, so an
	// honest repeat of the held round still matches.
	sameIR, err := sameInputRecord(last, c.Held)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvidenceMalformed, err)
	}
	if !sameIR {
		// Two authenticated certificates make different statements about one round. Nothing here
		// can adjudicate that, and no other provider can either — it is not an availability
		// problem, so it must not be retried away.
		return nil, fmt.Errorf("%w: round %d — the chain ends at state %x block %x, this node holds state %x block %x",
			ErrEvidenceConflict, last.GetRoundNumber(),
			last.InputRecord.Hash, last.InputRecord.BlockHash,
			c.Held.InputRecord.Hash, c.Held.InputRecord.BlockHash)
	}
	// Redundant given the identity check above, and kept because it is the one line that states the
	// property the anchor is actually claiming: the state the chain proves is the state this node
	// is being asked to build on.
	if !bytes.Equal(c.Held.InputRecord.Hash, state) {
		return nil, fmt.Errorf("%w: the chain proves state %x for round %d, this node holds %x",
			ErrEvidenceConflict, state, last.GetRoundNumber(), c.Held.InputRecord.Hash)
	}

	return &ExecutionAnchor{
		BlockHash:        Hash(ev.Source.InputRecord.BlockHash),
		StateRoot:        Hash(ev.Source.InputRecord.Hash),
		Round:            ev.Source.InputRecord.RoundNumber,
		fromGenesisRound: len(ev.Source.InputRecord.PreviousHash) == 0,
	}, nil
}
