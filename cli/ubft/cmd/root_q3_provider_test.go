package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
)

// Once an epoch is activated the provider serves it from the journal: the manager (nil here, as a root that has moved on holds no live
// evidence for it) is never asked.
func TestTheBundleProviderServesACompletedActivationWithoutTheCommittedTree(t *testing.T) {
	f := q3fixture.New(t, q3fixture.Options{})
	p := q3process.New(t, f)
	rt := p.Start()
	require.NoError(t, rt.Recover(context.Background()))
	require.NoError(t, rt.Activate(context.Background(), p.Bundle()))

	provider := q3BundleProvider{cm: nil, rt: rt}
	b, err := provider.Q3Bundle(context.Background(), f.Claim.Epoch)
	require.NoError(t, err)
	require.NotEmpty(t, b.Envelope)
	require.NotNil(t, b.Snapshot)
}
