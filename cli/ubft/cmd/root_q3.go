package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/keyvaluedb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3delivery"
	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	"github.com/unicitynetwork/bft-go-base/types"
	"github.com/unicitynetwork/bft-go-base/types/hex"
)

// The Q3 acceptance lane's root node: a verified Q3 history, the install journal and the V3 handoff pipeline, enabled by --q3-lane and by
// nothing else. A node started without it constructs no runtime and behaves exactly as before.
const q3JournalDBFileName = "q3-journal.db"

// newRootQ3Runtime opens the install journal and rebuilds the verified history from the pinned genesis trust base and every staged bundle.
func newRootQ3Runtime(journal keyvaluedb.KeyValueDB, genesis *types.RootTrustBaseV1) (*q3active.Runtime, error) {
	rt, err := q3active.New(q3active.Config{DB: journal, Genesis: genesis})
	if err != nil {
		return nil, fmt.Errorf("q3 runtime: %w", err)
	}
	return rt, nil
}

// attachRootQ3 wires the runtime's participants: the manager is the root installer and the safety module the signing gate. A root process
// hosts no shard node and no signing authority, so those two participants are the runtime's own guarded lookups, which are bound to it by
// construction. Recover completes any unfinished installation and checks every finished one before anything is admitted.
func attachRootQ3(ctx context.Context, rt *q3active.Runtime, cm *consensus.ConsensusManager) error {
	if err := rt.Attach(q3active.Participants{Root: cm, Safety: cm.SafetyModule(), Shard: rt.Trust(nil), Authority: rt.Trust(nil)}); err != nil {
		return fmt.Errorf("q3 runtime: %w", err)
	}
	if err := rt.Recover(ctx); err != nil {
		return fmt.Errorf("q3 runtime recovery: %w", err)
	}
	return nil
}

// q3BundleProvider serves the activation bundle of a successor epoch from this node's own committed old tip, or as the journal staged it.
type q3BundleProvider struct {
	cm *consensus.ConsensusManager
	rt *q3active.Runtime
}

func (p q3BundleProvider) Q3Bundle(_ context.Context, epoch uint64) (q3active.Bundle, error) {
	// an activation this node has already staged is served from the journal: once the roots have moved on, the committed tree no longer
	// holds the old tip its live evidence needs
	if b, ok, err := p.rt.StagedBundle(epoch); err != nil || ok {
		return b, err
	}
	link, head, candidate, err := p.cm.Q3ActivationEvidence(epoch)
	if err != nil {
		return q3active.Bundle{}, err
	}
	return p.rt.BundleFor(link, head, candidate)
}

// installQ3Epochs activates every successor epoch up to the target, each from this node's own committed evidence when it holds it and
// otherwise from a root peer, and always through the runtime's journal: nothing a peer serves is trusted before the runtime has verified
// it against the history and every participant has installed it.
func installQ3Epochs(ctx context.Context, host handoffdelivery.Host, peers []peer.AddrInfo, rt *q3active.Runtime, cm *consensus.ConsensusManager, target uint64) error {
	provider := q3BundleProvider{cm: cm, rt: rt}
	for epoch := cm.InstalledRootEpoch() + 1; epoch <= target; epoch++ {
		bundle, err := provider.Q3Bundle(ctx, epoch)
		if err != nil {
			fetched := false
			for _, root := range peers {
				if bundle, err = q3delivery.Request(ctx, host, root.ID, epoch); err == nil {
					fetched = true
					break
				}
			}
			if !fetched {
				return fmt.Errorf("no root peer served verified activation of epoch %d: %w", epoch, errors.Join(err, errNoQ3Bundle))
			}
		}
		if err := rt.Activate(ctx, bundle); err != nil {
			return fmt.Errorf("install activation of epoch %d: %w", epoch, err)
		}
	}
	return nil
}

var errNoQ3Bundle = errors.New("activation bundle unavailable")

// rootHandoffQ3Planner is the V3 plan of the operator endpoint, implemented by a manager wired to a verified Q3 history.
type rootHandoffQ3Planner interface {
	PlanHandoffV3(*types.RootTrustBaseV1, *evmassign.Proposal, []byte) (abdrc.HandoffApprovalMsg, error)
}

// rootQ3CandidateResponse is a V3 candidate for the operator to collect readiness receipts over.
type rootQ3CandidateResponse struct {
	Body              hex.Bytes `json:"body"`
	Candidate         hex.Bytes `json:"candidate"`
	CandidatePreimage hex.Bytes `json:"candidatePreimage,omitempty"`
	Attempt           uint64    `json:"attempt"`
	ActivationRound   uint64    `json:"activationRound"`
}

// rootQ3CandidateHandler returns the candidate PlanV3Candidate derives from this validator's committed state. It registers nothing.
func rootQ3CandidateHandler(operator interface {
	PlanV3Candidate(*types.RootTrustBaseV1, *evmassign.Proposal) (consensus.V3Candidate, error)
}) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !localOperatorRequest(w, r) {
			return
		}
		var request rootHandoffPlanRequest
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&request) != nil {
			http.Error(w, "invalid candidate request", http.StatusBadRequest)
			return
		}
		c, err := operator.PlanV3Candidate(request.NextTrustBase, request.EVMAssignment)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(rootQ3CandidateResponse{Body: c.Body.Encode(), Candidate: c.Candidate[:], CandidatePreimage: c.CandidatePreimage,
			Attempt: c.Attempt, ActivationRound: c.ActivationRound})
	}
}
