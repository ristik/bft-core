package q3active_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3process"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
)

var ctx = context.Background()

// process wraps the shared simulated process with the short names of these tests.
type process struct {
	*q3process.Process
	root                     *q3process.Root
	safety, shard, authority *q3process.Consumer
}

func newProcess(t *testing.T, f *q3fixture.Fixture) *process {
	p := q3process.New(t, f)
	return &process{Process: p, root: p.Root, safety: p.Safety, shard: p.Shard, authority: p.Authority}
}

func (p *process) start() *q3active.Runtime { return p.Start() }
func (p *process) bundle() q3active.Bundle  { return p.Bundle() }

func epoch2(t *testing.T, rt *q3active.Runtime) q3format.Entry {
	t.Helper()
	e, err := rt.History().ForEpoch(2)
	require.NoError(t, err)
	return e
}
