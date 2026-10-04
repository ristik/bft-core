package trustbase

import (
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
)

var (
	// ErrSigningHistory is returned when the signing configuration of an epoch cannot be established from the authenticated
	// history: an unknown epoch, or an activation that does not fit the recorded ones.
	ErrSigningHistory = errors.New("signing configuration history")
)

// signingRegistry is the authenticated history of the epochs that activated the domain-bound scheme. The scheme is a
// property of the root epoch, so signing, verification and the epoch's weights change together at one epoch boundary; no
// wall-clock switch, flag or seal-version heuristic exists. An epoch with no activation at or below it is scheme 1.
//
// A store that is bound to the verified, durable history (BindSigningAuthority) takes every epoch's configuration from it and
// from nothing else: ActivateSigning is refused, and an epoch the history does not hold is an error, never scheme 1. Production
// has no caller of ActivateSigning (TestNoProductionCallerOfActivateSigning); it is the seam for tests of the signing rules.
type signingRegistry struct {
	byEpoch   map[uint64]votesig.Config
	authority SigningAuthority
}

// SigningAuthority is the verified history that decides each epoch's signing configuration (q3format.History, retained durably
// by q3active). Its answer for an unknown epoch must be an error.
type SigningAuthority interface {
	Signing(epoch uint64) (votesig.Config, error)
}

// sameAuthority is identity of a comparable authority; a value of an uncomparable type is never the same one, so binding it twice is
// refused rather than a panic.
func sameAuthority(a, b SigningAuthority) bool {
	return reflect.TypeOf(a).Comparable() && a == b
}

// BindSigningAuthority makes the verified history the only source of signing configurations. It is refused if an in-memory
// activation was already recorded (two sources would disagree) or another authority is bound.
func (s *TrustBaseStore) BindSigningAuthority(a SigningAuthority) error {
	if a == nil {
		return fmt.Errorf("%w: no authority", ErrSigningHistory)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.signing.byEpoch) != 0 {
		return fmt.Errorf("%w: an in-memory activation is already recorded", ErrSigningHistory)
	}
	if s.signing.authority != nil && !sameAuthority(s.signing.authority, a) {
		return fmt.Errorf("%w: another authority is bound", ErrSigningHistory)
	}
	s.signing.authority = a
	return nil
}

// ActivateSigning records that the given epoch is the first to sign with cfg (scheme 2). The epoch's trust base must be
// installed; the scheme never goes back (an activation below a recorded one is refused); installing the same record again
// is a no-op and a different record for the same epoch is refused.
func (s *TrustBaseStore) ActivateSigning(epoch uint64, cfg votesig.Config) error {
	if cfg.Scheme != votesig.SchemeDomainBound {
		return fmt.Errorf("%w: only scheme 2 is an activation, got %d", ErrSigningHistory, cfg.Scheme)
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	tb, err := s.GetByEpoch(epoch)
	if err != nil {
		return fmt.Errorf("%w: epoch %d has no trust base: %w", ErrSigningHistory, epoch, err)
	}
	if cfg.Network != uint64(tb.NetworkID) {
		return fmt.Errorf("%w: configuration network %d differs from the trust base network %d", ErrSigningHistory, cfg.Network, tb.NetworkID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signing.authority != nil {
		return fmt.Errorf("%w: the store takes its configurations from the verified history", ErrSigningHistory)
	}
	if s.signing.byEpoch == nil {
		s.signing.byEpoch = make(map[uint64]votesig.Config)
	}
	if prev, ok := s.signing.byEpoch[epoch]; ok {
		if prev != cfg {
			return fmt.Errorf("%w: epoch %d already activated with another configuration", ErrSigningHistory, epoch)
		}
		return nil
	}
	for e, prev := range s.signing.byEpoch {
		if e > epoch {
			return fmt.Errorf("%w: epoch %d is below the recorded activation at epoch %d", ErrSigningHistory, epoch, e)
		}
		if prev.Genesis != cfg.Genesis || prev.Network != cfg.Network {
			return fmt.Errorf("%w: the root-chain genesis identity changed at epoch %d", ErrSigningHistory, epoch)
		}
	}
	s.signing.byEpoch[epoch] = cfg
	return nil
}

// SigningConfig is the signing configuration of the epoch's messages: the activation record of the latest activated epoch
// at or below it (scheme 2), or the legacy configuration (scheme 1) when none is. It is an error for an epoch with no
// installed trust base: missing history is not an implicit legacy choice.
func (s *TrustBaseStore) SigningConfig(epoch uint64) (votesig.Config, error) {
	tb, err := s.GetByEpoch(epoch)
	if err != nil {
		return votesig.Config{}, fmt.Errorf("%w: epoch %d: %w", ErrSigningHistory, epoch, err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if a := s.signing.authority; a != nil {
		cfg, err := a.Signing(epoch)
		if err != nil {
			return votesig.Config{}, fmt.Errorf("%w: epoch %d: %w", ErrSigningHistory, epoch, err)
		}
		if cfg.Network != uint64(tb.NetworkID) {
			return votesig.Config{}, fmt.Errorf("%w: epoch %d: history network %d differs from the trust base network %d", ErrSigningHistory, epoch, cfg.Network, tb.NetworkID)
		}
		return cfg, nil
	}
	epochs := make([]uint64, 0, len(s.signing.byEpoch))
	for e := range s.signing.byEpoch {
		epochs = append(epochs, e)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] > epochs[j] })
	for _, e := range epochs {
		if e <= epoch {
			return s.signing.byEpoch[e], nil
		}
	}
	return votesig.Config{Scheme: votesig.SchemeLegacy, Network: uint64(tb.NetworkID)}, nil
}
