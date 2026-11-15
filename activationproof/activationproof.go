/*
Package activationproof verifies a root activation for a party that holds no root state of its own: a signing authority advancing
its scope (#1085), and the shard node's installer, which shares the candidate and configuration rules below.

Everything is verified from a pin the verifier was enrolled with (the deployment's genesis root trust base and whether its chain is
a UTB chain), extended only by activation bundles the verifier authenticates itself, one epoch at a time. A bundle is the root's
staged activation (q3active.Bundle): the envelope whose last link is the activation, the old committee's committed checkpoint and the
committed candidate preimage. Nothing here takes a result, a projection or a configuration from whoever supplies the bundle.
*/
package activationproof

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-go-base/types"
)

var (
	// ErrLineage is a bundle that does not extend (or exactly repeat) the verifier's lineage: a wrong network or genesis, a broken
	// predecessor, an old commit the previous committee did not sign, a conflicting entry, a skipped epoch.
	ErrLineage = errors.New("activationproof: the activation does not extend the verified lineage")
	// ErrCandidate is a committed candidate that is not the one the activated body binds, or not a coupled assignment of that body's own
	// committee.
	ErrCandidate = errors.New("activationproof: the delivered candidate is not the one the activated V3 body binds")
	// ErrShard is a checkpoint that does not certify this shard at the configuration the verifier holds, or an activated configuration
	// that is not this shard's.
	ErrShard = errors.New("activationproof: the activation does not carry this shard's configuration")
)

// MaxBundleBytes bounds one bundle; the transport's frame bounds it further.
const MaxBundleBytes = q3format.MaxEnvelopeBytes

// Lineage is a verifier's own authenticated root history: the Q3 history rooted at its pinned genesis, and for every epoch the root
// trust base a certificate of that epoch is verified with, hash-chained the way a root installs it (PreviousEntryHash is the
// predecessor's hash). It is immutable: Extend returns a new one.
type Lineage struct {
	hist  *q3format.History
	trust []*types.RootTrustBaseV1 // trust[i] is epoch hist.FirstEpoch()+i
}

// NewLineage starts a lineage at the deployment's genesis root trust base (epoch 1). utb says the chain is a UTB chain.
func NewLineage(genesis *types.RootTrustBaseV1, utb bool) (*Lineage, error) {
	if genesis == nil {
		return nil, fmt.Errorf("%w: no genesis pin", ErrLineage)
	}
	h, err := q3format.NewHistory(genesis)
	if err != nil {
		return nil, errors.Join(ErrLineage, err)
	}
	if utb {
		h = h.WithUTBGenesis()
	}
	return &Lineage{hist: h, trust: []*types.RootTrustBaseV1{h.Tip().Projection()}}, nil
}

// Tip is the last epoch the lineage holds.
func (l *Lineage) Tip() uint64 { return l.hist.Tip().Epoch() }

// Network is the pinned network.
func (l *Lineage) Network() types.NetworkID { return types.NetworkID(l.hist.Network()) }

// Trust is the root trust base of an epoch the lineage holds (a copy).
func (l *Lineage) Trust(epoch uint64) (*types.RootTrustBaseV1, error) {
	first := l.hist.FirstEpoch()
	if epoch < first || epoch-first >= uint64(len(l.trust)) {
		return nil, fmt.Errorf("%w: epoch %d is not in the lineage (tip %d)", ErrLineage, epoch, l.Tip())
	}
	e, err := l.hist.ForEpoch(epoch)
	if err != nil {
		return nil, errors.Join(ErrLineage, err)
	}
	tb := e.Projection()
	tb.PreviousEntryHash = bytes.Clone(l.trust[epoch-first].PreviousEntryHash)
	return tb, nil
}

// Step is one verified bundle: the epoch it activates, whether it only repeated an entry the lineage already held, and what an
// installer of that epoch needs from it.
type Step struct {
	Epoch  uint64
	Replay bool
	Entry  q3format.Entry
	Proof  handoff.OldCommitProof
	Bundle q3active.Bundle
}

// Extend authenticates one bundle against the lineage and returns the lineage it extends to, leaving l unchanged. A bundle for an epoch
// the lineage holds must be exactly that entry (Replay); otherwise it must activate the next epoch: an earlier epoch missing from the
// lineage is ErrLineage (send the bundles in epoch order), never a reason to trust the bundle's own claim.
func (l *Lineage) Extend(raw []byte) (*Lineage, Step, error) {
	if len(raw) == 0 || len(raw) > MaxBundleBytes {
		return nil, Step{}, fmt.Errorf("%w: a bundle of %d bytes", ErrLineage, len(raw))
	}
	b, env, err := q3active.DecodeBundle(raw)
	if err != nil {
		return nil, Step{}, errors.Join(ErrLineage, err)
	}
	// one activation per bundle: the last link is the activation, and every earlier one must be an entry the lineage already holds
	// (VerifyEnvelope then only checks that it is exactly that entry), so one call verifies at most one new link
	link := env.Links[len(env.Links)-1]
	epoch := link.Body.Epoch
	tip := l.Tip()
	if epoch > tip+1 {
		return nil, Step{}, fmt.Errorf("%w: epoch %d, the lineage holds epochs up to %d: send the bundles in order", ErrLineage, epoch, tip)
	}
	next, err := l.hist.VerifyEnvelope(env)
	if err != nil {
		return nil, Step{}, errors.Join(ErrLineage, err)
	}
	entry, err := next.ForEpoch(epoch)
	if err != nil || entry.Claim() != link.Claim {
		return nil, Step{}, fmt.Errorf("%w: the verified history derives another record for epoch %d", ErrLineage, epoch)
	}
	var proof handoff.OldCommitProof
	if err := types.Cbor.Unmarshal(link.Proof, &proof); err != nil {
		return nil, Step{}, fmt.Errorf("%w: old commit proof: %v", ErrLineage, err)
	}
	step := Step{Epoch: epoch, Replay: epoch <= tip, Entry: entry, Proof: proof, Bundle: b}
	if step.Replay {
		return l, step, nil
	}
	prev := l.trust[len(l.trust)-1]
	prevID, err := prev.Hash(crypto.SHA256)
	if err != nil {
		return nil, Step{}, err
	}
	tb := entry.Projection()
	tb.PreviousEntryHash = prevID
	trust := append(append([]*types.RootTrustBaseV1(nil), l.trust...), tb)
	return &Lineage{hist: next, trust: trust}, step, nil
}

// Transition is what an activation installs for one shard: the full configuration hash it certifies from the activation, and the
// activated configuration of a coupled change (nil for a root-only change, which keeps the configuration).
type Transition struct {
	NextConfHash []byte
	Conf         *types.PartitionDescriptionRecord
}

// ShardTransition verifies, for one shard, the activation of step (a non-replay Extend of prev): the old committee's commit once more
// under prev's own keys, weights and scheme of the epoch it ends, the committed checkpoint against that commit and against activeConf
// (the configuration hash the verifier holds for the shard: a checkpoint of another configuration is refused, which also authenticates
// the verifier's own), and the committed candidate against the activated body. It returns the configuration the shard runs from the
// activation.
func ShardTransition(prev *Lineage, step Step, partition types.PartitionID, shard types.ShardID, activeConf []byte) (Transition, error) {
	verified, _, ok := step.Entry.Handoff()
	if !ok || step.Epoch < 2 || prev.Tip()+1 != step.Epoch {
		return Transition{}, fmt.Errorf("%w: epoch %d is not the activation that follows %d", ErrLineage, step.Epoch, prev.Tip())
	}
	old, err := prev.Trust(step.Epoch - 1)
	if err != nil {
		return Transition{}, err
	}
	oldSigning, err := prev.hist.Signing(step.Epoch - 1)
	if err != nil {
		return Transition{}, errors.Join(ErrLineage, err)
	}
	rec, err := handoff.VerifyOldCommitProofSigning(step.Proof, old, oldSigning)
	if err != nil || !bytes.Equal(rec.RecordID[:], verified.RecordID) {
		return Transition{}, fmt.Errorf("%w: the proof is not the one that activated epoch %d", ErrLineage, step.Epoch)
	}
	if _, err := handoffdelivery.VerifySnapshot(step.Proof, rec, step.Bundle.Snapshot, partition, shard, activeConf); err != nil {
		return Transition{}, errors.Join(ErrShard, err)
	}
	if err := AuthenticateCandidate(step.Entry, step.Proof.Record, step.Bundle.Candidate); err != nil {
		return Transition{}, err
	}
	next, conf, err := NextConf(activeConf, step.Proof, step.Bundle.Candidate)
	if err != nil {
		return Transition{}, err
	}
	if conf != nil && (conf.PartitionID != partition || !conf.ShardID.Equal(shard) || conf.NetworkID != prev.Network()) {
		return Transition{}, fmt.Errorf("%w: the activated configuration is for network %d partition %d shard %s", ErrShard, conf.NetworkID, conf.PartitionID, conf.ShardID)
	}
	return Transition{NextConfHash: next, Conf: conf}, nil
}

// AuthenticateCandidate checks the delivered candidate preimage against the verified entry before anything is installed from it: its
// digest is the one the body's change record binds (for this network, predecessor, attempt and earliest activation), it is the
// candidate of THIS handoff, its coupled assignment is valid, and its root members are exactly the body's committee, entity for entity
// and weight for weight. An absent preimage must be the operator candidate the body's own members derive (a root-only change), so a
// candidate cannot be dropped.
func AuthenticateCandidate(entry q3format.Entry, r evmroot.OrderedHandoffRecord, candidate []byte) error {
	body, err := q3format.DecodeBody(entry.BodyEncoding())
	if err != nil {
		return errors.Join(ErrCandidate, err)
	}
	var digest [32]byte
	if len(candidate) != 0 {
		digest = sha256.Sum256(candidate)
	} else if digest, err = evmroot.D4OperatorCandidateDigest(body.Members); err != nil {
		return errors.Join(ErrCandidate, err)
	}
	if !bytes.Equal(body.ChangeRecordHash, evmroot.D4CandidateContextHash(r.Network, r.PredecessorBodyID, r.Attempt, digest[:], body.EarliestActivation)) {
		return fmt.Errorf("%w: its digest is not the body's change record", ErrCandidate)
	}
	if len(candidate) == 0 {
		return nil
	}
	c, err := evmassign.DecodeCandidate(candidate)
	if err != nil {
		return errors.Join(ErrCandidate, err)
	}
	if c.Network != r.Network || !bytes.Equal(c.Predecessor, r.PredecessorBodyID) || c.Attempt != r.Attempt {
		return fmt.Errorf("%w: it is the candidate of another handoff", ErrCandidate)
	}
	if _, err := c.Successor(); err != nil { // the assignment's own validity, proofs of possession and coupling
		return errors.Join(ErrCandidate, err)
	}
	if len(c.RootMembers) != len(body.Members) {
		return fmt.Errorf("%w: %d root members for a committee of %d", ErrCandidate, len(c.RootMembers), len(body.Members))
	}
	committee := make(map[string]evmroot.Member, len(body.Members))
	for _, m := range body.Members {
		committee[m.NodeID] = m
	}
	for _, m := range c.RootMembers {
		b, ok := committee[m.NodeID]
		if !ok || b.Weight != m.Weight || !bytes.Equal(b.ConsensusKey, m.Key) {
			return fmt.Errorf("%w: root member %q is not the body's", ErrCandidate, m.NodeID)
		}
	}
	return nil
}

// NextConf is the full shard configuration hash the root certifies once the activation takes effect, and the configuration itself for
// a coupled change: the candidate's activated assignment, or the unchanged configuration (nil) for a root-only one (the same rule
// handoffdelivery.Verify applies to a V2 bundle).
func NextConf(active []byte, proof handoff.OldCommitProof, candidate []byte) ([]byte, *types.PartitionDescriptionRecord, error) {
	if len(candidate) == 0 {
		return bytes.Clone(active), nil, nil
	}
	_, activated, err := evmassign.ActivatedFromPreimage(candidate, proof.Record.ActivationRound)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: candidate: %w", ErrCandidate, err)
	}
	h, err := activated.Hash(crypto.SHA256)
	if err != nil || len(h) != 32 {
		return nil, nil, fmt.Errorf("%w: activated configuration hash", ErrCandidate)
	}
	return h, activated, nil
}
