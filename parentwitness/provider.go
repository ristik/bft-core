package parentwitness

import (
	"bytes"
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/unicitynetwork/bft-core/registryproof"
)

type EvidenceByHash interface {
	EvidenceByHash(context.Context, common.Hash) (registryproof.Evidence, bool, error)
}

// Provider is a pure inactive adapter. It performs no peer admission, transport, retry or lookup
// policy; its reader is already bound to an owned local configured-progress context.
type Provider struct {
	context  Context
	registry registryproof.Context
	reader   EvidenceByHash
}

func NewProvider(target Target, reader EvidenceByHash) (*Provider, error) {
	if !target.Valid() || reader == nil {
		return nil, ErrContext
	}
	return &Provider{context: target.Request().Context, registry: target.registry, reader: reader}, nil
}

func (p *Provider) Serve(ctx context.Context, request Request) (Response, error) {
	if p == nil || p.reader == nil {
		return Response{}, ErrContext
	}
	owned, err := ownProviderRequest(request)
	if err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrInvalidRequest, err)
	}
	if !sameContext(p.context, owned.Context) {
		return Response{Request: owned, Outcome: OutcomeWrongContext, Detail: "wrong context"}, nil
	}
	if owned.BlockHash == owned.Context.EVMGenesisHash {
		return Response{Request: owned, Outcome: OutcomeInvalidRequest, Detail: "genesis block unsupported"}, nil
	}
	evidence, found, err := p.reader.EvidenceByHash(ctx, owned.BlockHash)
	if err != nil {
		return Response{}, fmt.Errorf("parent witness provider read: %w", err)
	}
	if !found {
		return Response{Request: owned, Outcome: OutcomeUnavailable, Detail: "not retained"}, nil
	}
	ownedEvidence, err := ownEvidence(evidence, p.registry.Layout)
	if err != nil {
		return Response{}, fmt.Errorf("parent witness provider evidence: %w", err)
	}
	if _, err := registryproof.Verify(p.registry, owned.BlockHash, ownedEvidence); err != nil {
		return Response{}, fmt.Errorf("parent witness provider evidence: %w", err)
	}
	return Response{Request: owned, Outcome: OutcomeFound, Evidence: ownedEvidence}, nil
}

func ownProviderRequest(r Request) (Request, error) {
	if err := validateRequest(r); err != nil {
		return Request{}, err
	}
	c, err := contextFromWire(contextToWire(r.Context))
	if err != nil {
		return Request{}, err
	}
	return Request{Context: c, BlockHash: r.BlockHash}, nil
}

func sameContext(a, b Context) bool {
	aw, bw := contextToWire(a), contextToWire(b)
	ab, _ := marshalCanonical(aw)
	bb, _ := marshalCanonical(bw)
	return bytes.Equal(ab, bb)
}
