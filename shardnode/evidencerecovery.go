package shardnode

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/libp2p/go-libp2p/core/peer"

	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/certification"
)

/*
The recovery lifecycle, assembled.

Four pieces have shipped separately and each was reviewable on its own: what a node RETAINS so it can
help (§6.1), the WIRE that carries it (§6.2), the REQUESTER that decides who to ask and what an
answer is worth (§6.3), and the APPLIER that decides whether a verified target reaches the executor
(§6.4). None of them was constructed by production startup. This is that construction, kept in one
file so the whole lifecycle can be read at once rather than reassembled from four constructors.

TWO HALVES, INDEPENDENTLY SWITCHABLE. Serving evidence and recovering from it are different
decisions with different costs. A node can retain and serve without ever recovering (it helps others
and takes no new dependency itself), and — less usefully but legitimately, for a node that trusts
nobody to serve it — recover without serving. The options say so rather than implying it.

WHAT THIS DOES NOT DO. It does not sign, does not make a node eligible to sign (P-sign, #105), and
does not change what P-id demands. A recovered executor is a node that can build again, not a node
that has been re-authorized to vote.
*/

// EvidenceProviders is the shard's other validators, in the order they should be asked. It is the
// same set the disseminator sends blocks to, and it is supplied rather than discovered: who a node
// asks for evidence is a deployment decision, not something this package should infer.
type EvidenceProviders []peer.ID

func (p EvidenceProviders) EvidenceProviders() []peer.ID { return []peer.ID(p) }

// transportFetcher is EvidenceFetcher over the real wire. It exists to keep the requester's policy
// testable without a network, and to keep the transport unaware of policy: one provider, one
// request, no decisions (§6.2).
type transportFetcher struct {
	host   EvidenceHost
	limits EvidenceTransportLimits
}

func (f *transportFetcher) Fetch(ctx context.Context, provider peer.ID, req EvidenceRequest) (AnchorEvidence, error) {
	return RequestAnchorEvidence(ctx, f.host, provider, req, f.limits)
}

// RecoveryOptions is what a deployment decides about the lifecycle.
type RecoveryOptions struct {
	// Serve makes this node retain what it observes and answer other nodes' requests for it.
	Serve bool
	// Recover makes this node obtain and apply evidence for its own missing anchor.
	Recover bool

	// Providers is who to ask, used only when Recover is set. Empty means recovery is configured
	// and has nobody to ask, which is reported as such rather than silently doing nothing.
	Providers EvidenceProviders

	Buffer    EvidenceBufferLimits
	Transport EvidenceTransportLimits
	Evidence  AnchorEvidenceLimits
	Budget    RecoveryBudget
	Apply     ApplyBudget
}

// DefaultRecoveryOptions serves and does not recover.
//
// Serving is the half with no new dependency: a node retains certificates it has already
// authenticated and answers bounded requests, which costs memory it can measure and helps peers it
// cannot otherwise help. Recovering takes a dependency on peers being willing to answer, and it
// ends in a finality-changing executor call — worth switching on deliberately, per deployment,
// which is what #92's open acceptance run is for.
func DefaultRecoveryOptions() RecoveryOptions {
	return RecoveryOptions{
		Serve:     true,
		Recover:   false,
		Buffer:    DefaultEvidenceBufferLimits,
		Transport: DefaultEvidenceTransportLimits,
		Evidence:  DefaultAnchorEvidenceLimits,
		Budget:    DefaultRecoveryBudget,
		Apply:     DefaultApplyBudget,
	}
}

// RecoveryStack is the assembled lifecycle. Every field may be nil: what is present is what the
// options asked for, and every use site guards, so a node running neither half behaves exactly as
// it did before any of this existed.
type RecoveryStack struct {
	Buffer    *EvidenceBuffer
	Server    *EvidenceServer
	Requester *EvidenceRequester
	Applier   *TargetApplier
	Gate      *FinalityGate

	log      *slog.Logger
	closeOne sync.Once
}

// RecoveryDeps is what the stack needs from the node around it.
type RecoveryDeps struct {
	Host          EvidenceHost // the libp2p peer, for serving and for asking
	Executor      Executor
	PartitionID   types.PartitionID
	ShardID       types.ShardID
	ShardConfHash []byte
	TrustBases    TrustBaseStore
	Gate          *FinalityGate
	Log           *slog.Logger
}

/*
NewRecoveryStack builds the halves the options ask for, and refuses a configuration that cannot do
what it says.

The refusals matter more than the construction. "Recover with no providers" and "serve with no host"
are configurations that look enabled and do nothing, and a node that silently does nothing about its
own recovery is the failure mode #92 started from — a node sitting behind a block, refusing rounds,
with no line in the log saying why.
*/
func NewRecoveryStack(opts RecoveryOptions, deps RecoveryDeps) (*RecoveryStack, error) {
	if !opts.Serve && !opts.Recover {
		return nil, nil
	}
	if deps.Executor == nil {
		return nil, fmt.Errorf("recovery lifecycle: no executor")
	}
	if deps.Host == nil {
		return nil, fmt.Errorf("recovery lifecycle: no libp2p host, so this node can neither serve evidence nor ask for it")
	}
	if deps.Gate == nil {
		return nil, fmt.Errorf("recovery lifecycle: no finality gate — recovery commits, and it must be serialized against the round's own (see finality.go)")
	}

	st := &RecoveryStack{Gate: deps.Gate, log: deps.Log}

	if opts.Serve {
		buf, err := NewEvidenceBuffer(opts.Buffer)
		if err != nil {
			return nil, fmt.Errorf("recovery lifecycle: evidence buffer: %w", err)
		}
		srv, err := NewEvidenceServer(buf, opts.Transport, deps.Log)
		if err != nil {
			return nil, fmt.Errorf("recovery lifecycle: evidence server: %w", err)
		}
		srv.Register(deps.Host)
		st.Buffer, st.Server = buf, srv
	}

	if opts.Recover {
		if len(opts.Providers) == 0 {
			return nil, fmt.Errorf("recovery lifecycle: recovery is enabled with no providers to ask — a node that cannot ask anybody recovers nothing, which is the situation this exists to fix")
		}
		req, err := NewEvidenceRequester(RecoveryConfig{
			PartitionID:   deps.PartitionID,
			ShardID:       deps.ShardID,
			ShardConfHash: deps.ShardConfHash,
			TrustBases:    deps.TrustBases,
			Fetcher:       &transportFetcher{host: deps.Host, limits: opts.Transport},
			Providers:     opts.Providers,
			Limits:        opts.Evidence,
			Budget:        opts.Budget,
			Log:           deps.Log,
		})
		if err != nil {
			return nil, fmt.Errorf("recovery lifecycle: requester: %w", err)
		}
		app, err := NewTargetApplier(ApplyConfig{
			Executor: deps.Executor,
			Source:   req,
			Budget:   opts.Apply,
			Gate:     deps.Gate,
			Log:      deps.Log,
		})
		if err != nil {
			req.Close()
			return nil, fmt.Errorf("recovery lifecycle: applier: %w", err)
		}
		st.Requester, st.Applier = req, app
	}
	return st, nil
}

// Close stops background work. Idempotent, and safe on a nil stack so a caller need not branch.
func (s *RecoveryStack) Close() {
	if s == nil {
		return
	}
	s.closeOne.Do(func() {
		if s.Requester != nil {
			s.Requester.Close()
		}
	})
}

// observe feeds one authenticated certificate to both halves. It never fails a round: what is
// retained is what this node has ALREADY authenticated, so failing to retain it costs only this
// node's ability to help — an availability property, logged rather than escalated (§6.2).
func (s *RecoveryStack) observe(ctx context.Context, uc *types.UnicityCertificate, tr *certification.TechnicalRecord, nodeID string) {
	if s == nil {
		return
	}
	if s.Buffer != nil {
		if err := s.Buffer.Observe(uc, tr); err != nil && s.log != nil {
			s.log.LogAttrs(ctx, slog.LevelWarn, "evidence buffer refused an observation",
				slog.String("err", err.Error()),
				slog.Uint64("round", uc.GetRoundNumber()),
				slog.String("nodeID", nodeID))
		}
	}
	if s.Requester != nil {
		if err := s.Requester.Observe(uc, tr); err != nil && s.log != nil {
			s.log.LogAttrs(ctx, slog.LevelWarn, "recovery requester refused an observation",
				slog.String("err", err.Error()),
				slog.Uint64("round", uc.GetRoundNumber()),
				slog.String("nodeID", nodeID))
		}
	}
}

/*
seek asks for an anchor this node cannot produce from what it has observed.

It is called from the refusal paths and NOT on every certificate, which is the whole of its resource
policy: a node that can explain the state it is being asked to build on needs no evidence, and asking
anyway would make every healthy node a permanent load on every other. Need itself is bounded,
coalescing and non-blocking (§6.3), so calling it from under the round lock costs no I/O.
*/
func (s *RecoveryStack) seek(ctx context.Context, reason string, nodeID string) {
	if s == nil || s.Requester == nil {
		return
	}
	err := s.Requester.Need()
	if s.log == nil {
		return
	}
	level, msg := slog.LevelInfo, "asking peers for authenticated evidence of the missing anchor"
	if err != nil {
		level, msg = slog.LevelDebug, "not asking peers for evidence"
	}
	attrs := []slog.Attr{
		slog.String("reason", reason),
		slog.String("nodeID", nodeID),
	}
	if err != nil {
		attrs = append(attrs, slog.String("outcome", err.Error()))
	}
	s.log.LogAttrs(ctx, level, msg, attrs...)
}

// apply makes one bounded attempt to bring the executor to an evidence-verified block for the
// certificate held. It reports the executor's new head and whether the node is now recovered.
func (s *RecoveryStack) apply(ctx context.Context, uc *types.UnicityCertificate, head BlockRef, nodeID string) (BlockRef, ApplyResult, bool) {
	if s == nil || s.Applier == nil {
		return head, ApplyResult{Outcome: ApplyNotAttempted}, false
	}
	binding, err := BindingFor(uc)
	if err != nil {
		return head, ApplyResult{Outcome: ApplyNoTarget, Err: err}, false
	}
	// Carry a retained target onto the certificate held NOW, first, and synchronously. It is local
	// work over what this node observed itself — no network — and without it every attempt would
	// find a target for the PREVIOUS certificate and refuse it, forever. See Refresh.
	if s.Requester != nil {
		if rerr := s.Requester.Refresh(ctx); rerr != nil && s.log != nil {
			s.log.LogAttrs(ctx, slog.LevelDebug, "no verified target could be carried to the certificate held",
				slog.String("err", rerr.Error()),
				slog.Uint64("heldRound", binding.Round),
				slog.String("nodeID", nodeID))
		}
	}
	res := s.Applier.Apply(ctx, binding, head)
	if s.log != nil {
		level := slog.LevelInfo
		if res.Outcome != ApplyApplied {
			level = slog.LevelDebug
		}
		attrs := []slog.Attr{
			slog.String("outcome", res.Outcome.String()),
			slog.Bool("retryable", res.Outcome.Retryable()),
			slog.Uint64("heldRound", binding.Round),
			slog.String("nodeID", nodeID),
		}
		if res.Err != nil {
			attrs = append(attrs, slog.String("err", res.Err.Error()))
		}
		s.log.LogAttrs(ctx, level, "authenticated-evidence recovery attempt", attrs...)
	}
	return res.Head, res, res.Outcome == ApplyApplied
}
