package storage

import "github.com/unicitynetwork/bft-core/internal/quorumweight"

// RequestContext is the request context an activation counts under, for the external tests of the weighted selection.
func (a *RequestActivation) RequestContext() *quorumweight.RequestContext { return a.ctx }
