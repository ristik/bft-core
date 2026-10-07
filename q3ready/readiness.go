// Package q3ready is candidate-bound readiness for the Q3 handoff: no successor candidate is proposed unless every successor
// validator entity has checked its own BFT node, its delegated shard/authority service and its paired execution client against
// the candidate, and signed a receipt that names the network, genesis, predecessor, attempt, candidate, body and tuple.
//
// It negotiates nothing. A deployment has one protocol; a report is an accountable declaration by a co-hosted service, never an
// input to the verified q3format.History, which remains the only authority for a configuration.
package q3ready

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/unicitynetwork/bft-core/q3format"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

var (
	// ErrNotReady is returned when a component of an entity does not support the candidate; no receipt is signed.
	ErrNotReady = errors.New("q3ready: entity is not ready for the candidate")
	// ErrReadinessRefused is returned when a candidate may not be proposed: some successor member has no valid receipt.
	ErrReadinessRefused = errors.New("q3ready: readiness refused")
	// ErrComponent is returned when a component's report names another chain or candidate than the one attested.
	ErrComponent = errors.New("q3ready: component report does not match the candidate")
	// ErrProbe is returned when a component cannot be asked at all.
	ErrProbe = errors.New("q3ready: component unavailable")
	// ErrExecutionIdentity is returned when the execution client's genesis or code hash is not the pinned one.
	ErrExecutionIdentity = errors.New("q3ready: execution client genesis or code is not the pinned one")
)

// ServiceReport is what a BFT node or a delegated shard/authority service reports about itself: the chain it is bound to and
// the candidate it has staged. It is a claim by a co-hosted service, not an attestation.
type ServiceReport struct {
	Network uint64
	Genesis [32]byte
	Staged  [32]byte // the candidate digest the service has staged
}

// Service is one of the entity's own services.
type Service interface {
	Report(ctx context.Context) (ServiceReport, error)
}

// ExecutionReport is the paired execution client's loaded identity: its genesis and code hash.
type ExecutionReport struct{ GenesisHash, CodeHash []byte }

// ExecutionPin is the genesis and code hash the operator pinned locally for the execution client. The pin is never taken from the
// report under test: that would compare a value with itself.
type ExecutionPin struct{ GenesisHash, CodeHash []byte }

// Check refuses a report that is not the pinned identity, and a missing pin.
func (p ExecutionPin) Check(r ExecutionReport) error {
	switch {
	case len(p.GenesisHash) == 0 || len(p.CodeHash) == 0:
		return fmt.Errorf("%w: no pin configured", ErrExecutionIdentity)
	case !bytes.Equal(r.GenesisHash, p.GenesisHash) || !bytes.Equal(r.CodeHash, p.CodeHash):
		return ErrExecutionIdentity
	}
	return nil
}

// Execution is the paired execution client, queried for its loaded identity.
type Execution interface {
	Report(ctx context.Context) (ExecutionReport, error)
}

// Entity is the three components a successor validator entity must have checked before it signs readiness.
type Entity struct {
	NodeID    string
	BFT       Service
	Authority Service
	Execution Execution
}

// Attest checks every component of the entity against the candidate that rc binds and, only when all of them support it, signs
// the receipt with the entity's root key. Any component failure, in any order, yields no receipt. Pre-Commit readiness attests
// staged candidate support; the installed activation proof does not exist yet and is not asked for. The receipt is an
// accountable declaration, not remote attestation and not a promise of future uptime.
func (e Entity) Attest(ctx context.Context, rc q3format.ReceiptContext, cfg q3format.ProtocolConfig, want ExecutionPin, signer abcrypto.Signer) (q3format.Receipt, error) {
	if err := cfg.Validate(); err != nil {
		return q3format.Receipt{}, err
	}
	if cfg.Network != rc.Network || cfg.Genesis != rc.Genesis || cfg.Identity() != rc.Config {
		return q3format.Receipt{}, fmt.Errorf("%w: tuple is not the one the receipt names", ErrComponent)
	}
	for _, c := range []struct {
		name string
		svc  Service
	}{{"bft node", e.BFT}, {"shard/authority service", e.Authority}} {
		if c.svc == nil {
			return q3format.Receipt{}, fmt.Errorf("%w: %s: %w", ErrNotReady, c.name, ErrProbe)
		}
		r, err := c.svc.Report(ctx)
		if err != nil {
			return q3format.Receipt{}, fmt.Errorf("%w: %s: %w: %v", ErrNotReady, c.name, ErrProbe, err)
		}
		if err := checkService(r, rc); err != nil {
			return q3format.Receipt{}, fmt.Errorf("%w: %s: %w", ErrNotReady, c.name, err)
		}
	}
	if e.Execution == nil {
		return q3format.Receipt{}, fmt.Errorf("%w: execution client: %w", ErrNotReady, ErrProbe)
	}
	x, err := e.Execution.Report(ctx)
	if err != nil {
		return q3format.Receipt{}, fmt.Errorf("%w: execution client: %w: %v", ErrNotReady, ErrProbe, err)
	}
	if err := want.Check(x); err != nil {
		return q3format.Receipt{}, fmt.Errorf("%w: execution client: %w", ErrNotReady, err)
	}
	return q3format.SignReceipt(rc, e.NodeID, signer)
}

func checkService(r ServiceReport, rc q3format.ReceiptContext) error {
	switch {
	case r.Network != rc.Network || r.Genesis != rc.Genesis:
		return fmt.Errorf("%w: bound to another network or genesis", ErrComponent)
	case !bytes.Equal(r.Staged[:], rc.CandidateDigest[:]):
		return fmt.Errorf("%w: staged candidate %x, want %x", ErrComponent, r.Staged, rc.CandidateDigest)
	}
	return nil
}

// RequireReadiness is the gate before the activating Commit is proposed (and the deterministic check old validators repeat
// when executing it): rc must be the context of b and every successor member must have exactly one valid receipt under its
// root key. A missing receipt refuses the candidate; the membership or threshold is never lowered to proceed.
func RequireReadiness(b q3format.BodyV3, rc q3format.ReceiptContext, receipts []q3format.Receipt) error {
	if err := q3format.VerifyReceipts(b, rc, receipts); err != nil {
		return fmt.Errorf("%w: %w", ErrReadinessRefused, err)
	}
	return nil
}
