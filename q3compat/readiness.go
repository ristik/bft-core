package q3compat

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/unicitynetwork/bft-core/q3format"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
)

var (
	// ErrNotReady is returned when a component of an entity does not support the candidate; no receipt is signed.
	ErrNotReady = errors.New("q3compat: entity is not ready for the candidate")
	// ErrReadinessRefused is returned when a candidate may not be proposed: some successor member has no valid receipt.
	ErrReadinessRefused = errors.New("q3compat: readiness refused")
	// ErrComponent is returned when a component's report names another chain, candidate or protocol than the one attested.
	ErrComponent = errors.New("q3compat: component report does not match the candidate")
	// ErrProbe is returned when a component cannot be asked at all.
	ErrProbe = errors.New("q3compat: component unavailable")
)

// ServiceReport is what a BFT node or a delegated shard/authority service reports about itself: the chain it is bound to, the
// peer protocols it runs and the candidate it has staged. It is a claim by a co-hosted service, not an attestation.
type ServiceReport struct {
	Network   uint64
	Genesis   [32]byte
	Protocols []string
	Staged    [32]byte // the candidate digest the service has staged
}

// Service is one of the entity's own services.
type Service interface {
	Report(ctx context.Context) (ServiceReport, error)
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
func (e Entity) Attest(ctx context.Context, rc q3format.ReceiptContext, cfg q3format.ProtocolConfig, want ExecutionRequirement, signer abcrypto.Signer) (q3format.Receipt, error) {
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
		if err := checkService(r, rc, cfg); err != nil {
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
	if err := want.Check(x, cfg); err != nil {
		return q3format.Receipt{}, fmt.Errorf("%w: execution client: %w", ErrNotReady, err)
	}
	return q3format.SignReceipt(rc, e.NodeID, signer)
}

func checkService(r ServiceReport, rc q3format.ReceiptContext, cfg q3format.ProtocolConfig) error {
	switch {
	case r.Network != rc.Network || r.Genesis != rc.Genesis:
		return fmt.Errorf("%w: bound to another network or genesis", ErrComponent)
	case !slices.Contains(r.Protocols, cfg.RequiredPeerProtocol):
		return fmt.Errorf("%w: %q not supported", ErrProtocol, cfg.RequiredPeerProtocol)
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
