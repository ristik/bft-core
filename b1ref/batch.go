package b1ref

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/b1state"
	"github.com/unicitynetwork/bft-go-base/crypto"
)

// batch is the verification-local state of one call (briefs/b1-any-age-by-signatures.md section 5). Within it each distinct epoch entry
// is read and validated once and its keys parsed once, each distinct complete seal is checked once, and each distinct claim is folded
// once. It is created for one evaluation and dropped with it: nothing carries across calls, and only successes are remembered, so a
// failure is never turned into a later success.
type batch struct {
	reg    *Registry
	epochs map[uint64]*epochAuth
	seals  map[string]struct{} // complete seal bytes, signatures included, that verified
	claims map[string]struct{} // complete claims (claimed tuple and certificate bytes) whose folds held
}

// epochAuth is one epoch's authority as read from the registry in this call.
type epochAuth struct {
	entry     EpochEntry
	members   map[string]member // parsed on first use
	threshold uint64
}

func newBatch(reg *Registry) *batch {
	return &batch{reg: reg, epochs: map[uint64]*epochAuth{}, seals: map[string]struct{}{}, claims: map[string]struct{}{}}
}

// eval folds every distinct claim, then checks every distinct seal in order of first appearance, and returns the first reason the
// relation fails. A seal that verified does not excuse any claim from its own folds and bindings.
func (b *batch) eval(claims []claim) error {
	for i := range claims {
		key := claimKey(&claims[i])
		if _, ok := b.claims[key]; ok {
			continue
		}
		if err := ucFolds(&claims[i]); err != nil {
			return fmt.Errorf("claim %d: %w", i, err)
		}
		b.claims[key] = struct{}{}
	}
	for i := range claims {
		if _, ok := b.seals[string(claims[i].sealRaw)]; ok {
			continue
		}
		if err := b.seal(&claims[i]); err != nil {
			return err
		}
		b.seals[string(claims[i].sealRaw)] = struct{}{}
	}
	return nil
}

// claimKey is the complete identity of a claim: every claimed field and the certificate bytes, length-prefixed so no two claims share
// a key. A certificate reused for a different claimed tuple is a different claim and is folded on its own.
func claimKey(c *claim) string {
	k := make([]byte, 0, 4+2+len(c.shardBytes)+3*32+len(c.ucRaw))
	k = binary.BigEndian.AppendUint32(k, c.partition)
	k = binary.BigEndian.AppendUint16(k, uint16(len(c.shardBytes)))
	k = append(k, c.shardBytes...)
	k = append(k, c.shardConf[:]...)
	k = append(k, c.stateRoot[:]...)
	k = append(k, c.irHash[:]...)
	return string(append(k, c.ucRaw...))
}

// seal checks one complete seal: the network, the any-age interval relation of its own round against its epoch's authenticated
// interval and the usable origin, and then every signature and the quorum. There is no certificate-age window: a certificate of
// any admitted epoch is accepted while start_e <= r <= O and, for a closed epoch, r < end_e.
func (b *batch) seal(c *claim) error {
	seal := c.uc.UnicitySeal
	if uint64(seal.NetworkID) != uint64(b.reg.Network) {
		return ErrNetwork
	}
	if seal.Epoch > b.reg.Origin {
		return ErrSealEpoch
	}
	auth, err := b.epoch(seal.Epoch)
	if err != nil {
		return err
	}
	r := seal.RootChainRoundNumber
	if r < auth.entry.Start {
		return ErrBeforeStart
	}
	if auth.entry.End != nil && r >= *auth.entry.End {
		return ErrAfterEnd
	}
	if auth.entry.End == nil && seal.Epoch != b.reg.Origin {
		return ErrOpenInterval
	}
	if r > b.reg.RootRound {
		return ErrFuture
	}
	return b.verifySignatures(c, auth)
}

// epoch reads and validates one epoch entry, once per call.
func (b *batch) epoch(e uint64) (*epochAuth, error) {
	if auth, ok := b.epochs[e]; ok {
		return auth, nil
	}
	work("epoch-load")
	entry, ok := b.reg.Epochs[e]
	if !ok {
		return nil, ErrUnknownEpoch
	}
	if entry.Epoch != e {
		return nil, ErrInfrastructure
	}
	if err := entry.Validate(); err != nil {
		return nil, errors.Join(ErrInfrastructure, err)
	}
	total, err := entry.TotalWeight()
	if err != nil {
		return nil, errors.Join(ErrInfrastructure, err)
	}
	threshold, err := b1state.Threshold(total)
	if err != nil {
		return nil, errors.Join(ErrInfrastructure, err)
	}
	auth := &epochAuth{entry: entry, threshold: threshold}
	b.epochs[e] = auth
	return auth, nil
}

// keys parses the epoch's member keys, once per call and only when a seal of the epoch reaches its signatures.
func (a *epochAuth) keys() (map[string]member, error) {
	if a.members != nil {
		return a.members, nil
	}
	members := make(map[string]member, len(a.entry.Members))
	for _, m := range a.entry.Members {
		work("point")
		ver, err := crypto.NewVerifierSecp256k1(m.Key[:])
		if err != nil {
			return nil, errors.Join(ErrInfrastructure, err)
		}
		members[m.NodeID] = member{weight: m.Weight, ver: ver}
	}
	a.members = members
	return members, nil
}

// verifySignatures checks every supplied signature over SHA256(Seal.SigBytes()) and then the quorum. Any unknown signer or bad
// signature fails the seal even when the rest reach quorum; the loop does not stop at the first failure.
func (b *batch) verifySignatures(c *claim, auth *epochAuth) error {
	sigBytes, err := c.uc.UnicitySeal.SigBytes()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFold, err)
	}
	members, err := auth.keys()
	if err != nil {
		return err
	}
	work("quorum")
	var first error
	good := uint64(0)
	for _, kv := range c.sigs.pairs() {
		m, ok := members[string(kv[0])]
		if !ok {
			first = firstErr(first, ErrUnknownSigner)
			continue
		}
		if err := checkSignature(&m, kv[1], sigBytes); err != nil {
			first = firstErr(first, err)
			continue
		}
		good += m.weight
	}
	if first != nil {
		return first
	}
	if good < auth.threshold {
		return ErrQuorum
	}
	return nil
}
