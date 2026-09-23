package shardnode

import (
	"context"
	"sync"
	"time"
)

// ProofEvidence is diagnostic context for the proof used by this round's
// derivation and Verify. It grants no authorization of its own.
type ProofEvidence struct {
	SnapshotID string
	VerifiedAt time.Time
}

type proofEvidenceKey struct{}

type proofEvidenceSlot struct {
	mu sync.Mutex
	v  ProofEvidence
}

// WithProofEvidence scopes proof telemetry to one certificate handling call.
func WithProofEvidence(ctx context.Context) context.Context {
	return context.WithValue(ctx, proofEvidenceKey{}, &proofEvidenceSlot{})
}

// RecordProofEvidence records the exact verified snapshot used by the adapter.
func RecordProofEvidence(ctx context.Context, v ProofEvidence) {
	if slot, ok := ctx.Value(proofEvidenceKey{}).(*proofEvidenceSlot); ok {
		slot.mu.Lock()
		slot.v = v
		slot.mu.Unlock()
	}
}

// CurrentProofEvidence reads the last successful derivation or Verify in this call.
func CurrentProofEvidence(ctx context.Context) ProofEvidence {
	if slot, ok := ctx.Value(proofEvidenceKey{}).(*proofEvidenceSlot); ok {
		slot.mu.Lock()
		defer slot.mu.Unlock()
		return slot.v
	}
	return ProofEvidence{}
}
