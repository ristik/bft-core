package cmd

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
)

// recordingReadinessHooks stands in for *shardnode.Node so the install step can be exercised without
// building a peer, network, executor and trust base store.
type recordingReadinessHooks struct {
	child    bool
	observer bool
}

func (r *recordingReadinessHooks) SetChildReadiness(shardnode.ChildReadiness) {
	r.child = true
}

func (r *recordingReadinessHooks) SetCertificateObserver(shardnode.CertificateObserver) {
	r.observer = true
}

// TestGateFlagRequiresTheRecordStore covers the two halves of the record gate's opt-in at the command
// layer: the flag alone is a named refusal checked before anything is built, and with the store the
// wiring installs both hooks. The gate reads the durable record, so a node asked to gate without one
// has nothing to decide from and must not start.
func TestGateFlagRequiresTheRecordStore(t *testing.T) {
	t.Run("alone it stops startup with the named refusal", func(t *testing.T) {
		err := validateCertifiedRecordFlags("", true)
		require.ErrorIs(t, err, ErrCertifiedRecordGateNeedsStore)
		require.Contains(t, err.Error(), "--certified-record-gate")
		require.Contains(t, err.Error(), "--certified-record-store")
	})

	t.Run("with the store it installs both hooks", func(t *testing.T) {
		require.NoError(t, validateCertifiedRecordFlags("/var/lib/ubft/certified.db", true))

		hooks := &recordingReadinessHooks{}
		installCertifiedRecordGate(hooks, nil, nil)
		require.True(t, hooks.child, "the readiness gate is installed")
		require.True(t, hooks.observer, "and the observer that feeds it")
	})
}
