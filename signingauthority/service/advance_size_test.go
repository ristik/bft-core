package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	"github.com/unicitynetwork/bft-core/signingauthority"
)

// The largest legitimate activation a signing authority is handed fits the operator frame (astra on #1087): a coupled handoff to the
// largest committee admission allows, with its assignment (every member an EVM validator with its proof of possession and binding,
// every member's readiness receipt), encoded as the root serves it and wrapped in the operator request, is below MaxAdvanceProofBytes and
// MaxFrameBytes, and the transport carries it to the authority (which refuses it here only because this authority has no lineage pin).
// The B1 registry ceiling (16) is the deployed bound; the Q3 body's own (256) is measured too.
func TestTheLargestLegitimateActivationFitsTheOperatorFrame(t *testing.T) {
	for name, members := range map[string]int{"B1 registry ceiling": evmassign.B1MaxValidators, "Q3 body ceiling": q3format.MaxMembers} {
		t.Run(name, func(t *testing.T) {
			if members > evmassign.B1MaxValidators && testing.Short() {
				t.Skip("a 256-member fixture")
			}
			weights := make([]uint64, members)
			for i := range weights {
				weights[i] = 1
			}
			fx := q3fixture.New(t, q3fixture.Options{Assignment: true, Weights: weights})
			raw, err := q3active.EncodeBundle(q3active.Bundle{Envelope: fx.EnvelopeBytes, Snapshot: fx.Snapshot, Candidate: fx.Candidate})
			require.NoError(t, err)
			frame, err := types.Cbor.Marshal(wireRequest{Version: protocolVersion, Op: uint64(opAdvanceWithProof), Credential: make([]byte, CredentialBytes), Payload: raw})
			require.NoError(t, err)
			t.Logf("%d members: bundle %d bytes, frame %d bytes (bound %d)", members, len(raw), len(frame), MaxFrameBytes)
			require.LessOrEqual(t, len(raw), MaxAdvanceProofBytes)
			require.LessOrEqual(t, len(frame), MaxFrameBytes)

			f := newFixture(t)
			_, err = f.operator.AdvanceWithProof(context.Background(), raw)
			require.ErrorIs(t, err, signingauthority.ErrLineageUnverified, "carried to the authority, not refused by the transport")
		})
	}
}
