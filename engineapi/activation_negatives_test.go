package engineapi

// W5: F2c §10's remaining activation negatives, submitted at the adapter level — through
// Adapter.Build and Adapter.Verify, the call sites §10 calls "integration". Negatives 2, 4 and 4b
// are already submitted at the rootinput level in rootinput/wiring_contract_test.go; these make the
// adapter-level claim, which is stronger for 2 (the fabricable scalar no longer reaches the output,
// and the governing input cannot be forged) and is the realizable-consensus claim for 4 and 4b (two
// nodes over one fixture, given one block, reach opposite verdicts).
//
// Tests only: no production file changes with this unit.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
)

// --- Negative 2 ---------------------------------------------------------------
//
// F2c §10.2: a fabricated RoundParams is structurally indistinguishable from a genuine one. After
// W4 the adapter reads neither p.SealHash nor p.Timestamp, so the adapter-level claim splits in two:
// the scalars a caller can fabricate must not reach the output, and the input that does govern —
// the certified authorization — must not be forgeable.

// TestAdapter_Build_RefusesACertificateTheTrustBaseDidNotSign is §10.2's second half: the value
// that does govern cannot be fabricated. A certificate carrying fewer than quorum signatures is
// refused by Build as a named rootinput class, not as an opaque failure.
func TestAdapter_Build_RefusesACertificateTheTrustBaseDidNotSign(t *testing.T) {
	f := newDerivationFixture(t)
	// One signature from a four-node trust base whose quorum is three: authentic-looking, and not a
	// verdict this trust base ever produced.
	forged, forgedTR := f.certWithPDR(t, f.pdr, 4, 5, 50, 1)
	a := NewAdapter(Config{
		EngineURL: "http://127.0.0.1:1", EthURL: "http://127.0.0.1:1", Secret: Secret{},
		Verifier: f.verifier(CursorNotActivated()),
	}, nil)

	_, err := a.Build(context.Background(), shardnode.RoundParams{
		Round: 5, Parent: shardnode.BlockRef{Hash: f.parent},
		AuthorizingCertificate: forged, AuthorizingTechnicalRecord: forgedTR,
	})
	require.ErrorIs(t, err, rootinput.ErrUnauthenticated,
		"an unauthenticated certificate must arrive as its own rootinput class")
}

// --- Negative 4 ---------------------------------------------------------------

// --- Negative 4b --------------------------------------------------------------
