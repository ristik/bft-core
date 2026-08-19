package shardnode

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/unicitynetwork/bft-go-base/types"
)

// TrustBaseStore resolves the root trust base active for a given root epoch.
// The consumer (bftclient.go) uses it to verify Unicity Certificates and to
// pick which root nodes to talk to.
type TrustBaseStore interface {
	GetByEpoch(ctx context.Context, epoch uint64) (*types.RootTrustBaseV1, error)
}

// FileTrustBaseStore is a single-epoch, file-backed TrustBaseStore: it holds
// exactly one trust base, loaded once at startup, and serves it only for
// that exact epoch. That is deliberately less than aggregator-go's
// TrustBaseManager (which fetches new trust bases from a root node's REST
// API as epochs roll over) — the framework's exec-mode PoC runs a single
// epoch throughout, so epoch rollover is explicitly out of scope (see
// docs/engine-api-adapter-plan.md §10, "Deliberately out of scope").
//
// A request for any other epoch is refused, not served from the loaded
// trust base anyway: trust base selection is what UC signature
// verification and root-node selection both key off, and epoch mismatch is
// exactly the situation where trusting the wrong one is a silent gap.
// Refusing is also the honest reflection of the out-of-scope decision above
// — if a caller ever asks for a different epoch, that means an epoch
// change happened, and this store is telling the truth about not
// supporting it rather than quietly pretending to.
type FileTrustBaseStore struct {
	mu  sync.RWMutex
	tb  *types.RootTrustBaseV1
	log *slog.Logger
}

func NewFileTrustBaseStore(tb *types.RootTrustBaseV1, log *slog.Logger) (*FileTrustBaseStore, error) {
	if tb == nil {
		return nil, fmt.Errorf("trust base is nil")
	}
	if log != nil {
		log.Info("loaded trust base", slog.Uint64("epoch", tb.GetEpoch()), slog.Int("rootNodes", len(tb.GetRootNodes())))
	}
	return &FileTrustBaseStore{tb: tb, log: log}, nil
}

func (s *FileTrustBaseStore) GetByEpoch(_ context.Context, epoch uint64) (*types.RootTrustBaseV1, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.tb.GetEpoch() != epoch {
		return nil, fmt.Errorf("shardnode: no trust base for epoch %d — this node only holds epoch %d (single-epoch store; epoch changes are out of scope, see docs/engine-api-adapter-plan.md §10)",
			epoch, s.tb.GetEpoch())
	}
	return s.tb, nil
}
