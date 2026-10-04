// Package q3process is one simulated process of the Q3 activation tests: a durable install journal, participants with the state
// they keep across restarts, and a runtime that is rebuilt on every start. The participants are fakes that record what they were
// asked to install; the real stores are exercised by the consensus package's integration tests.
package q3process

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/q3fixture"
	"github.com/unicitynetwork/bft-core/keyvaluedb/memorydb"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-core/q3format"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

// Root is the root consensus manager's durable state: what it holds after InstallVerifiedEpoch, shared across simulated restarts.
type Root struct {
	mu       sync.Mutex
	Held     map[uint64]q3format.Claim
	Installs int
	// OnInstall runs inside the install, while the runtime is not yet complete.
	OnInstall func(q3format.Entry)
	FailWith  error
}

func NewRoot() *Root { return &Root{Held: map[uint64]q3format.Claim{}} }

func (f *Root) InstallVerifiedEpoch(e q3format.Entry, _ handoff.OldCommitProof, head *abdrc.CommittedBlock, candidate []byte) (*rctypes.EpochAnchor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.FailWith != nil {
		return nil, f.FailWith
	}
	if head == nil || len(candidate) != 0 {
		return nil, errors.New("the root needs the checkpoint and no candidate")
	}
	if f.OnInstall != nil {
		f.OnInstall(e)
	}
	f.Installs++
	f.Held[e.Epoch()] = e.Claim()
	return &rctypes.EpochAnchor{}, nil
}

func (f *Root) HoldsVerifiedEpoch(e q3format.Entry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Held[e.Epoch()] != e.Claim() {
		return errors.New("the root does not hold the epoch")
	}
	return nil
}

// Consumer is a safety module, shard lookup or authority: bound to whatever runtime it is told.
type Consumer struct {
	mu    sync.Mutex
	bound any
}

func (c *Consumer) BoundTo(a any) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bound != nil && c.bound == a
}

func (c *Consumer) Bind(a any) { c.mu.Lock(); c.bound = a; c.mu.Unlock() }

// Process is one simulated process.
type Process struct {
	T                        *testing.T
	F                        *q3fixture.Fixture
	DB                       *memorydb.MemoryDB
	Root                     *Root
	Safety, Shard, Authority *Consumer
	RT                       *q3active.Runtime
	// SkipBinding names a participant ("safety", "shard", "authority") that is not wired to the runtime on the next start.
	SkipBinding string
}

func New(t *testing.T, f *q3fixture.Fixture) *Process {
	return &Process{T: t, F: f, DB: memorydb.New(), Root: NewRoot(), Safety: &Consumer{}, Shard: &Consumer{}, Authority: &Consumer{}}
}

// Start is a process start: New over the durable journal, then the participants attach and bind.
func (p *Process) Start() *q3active.Runtime {
	p.T.Helper()
	rt, err := q3active.New(q3active.Config{DB: p.DB, Genesis: p.F.Old})
	require.NoError(p.T, err)
	p.Attach(rt)
	return rt
}

func (p *Process) Attach(rt *q3active.Runtime) {
	p.T.Helper()
	for name, c := range map[string]*Consumer{"safety": p.Safety, "shard": p.Shard, "authority": p.Authority} {
		if p.SkipBinding == name {
			c.Bind(nil)
			continue
		}
		c.Bind(rt)
	}
	require.NoError(p.T, rt.Attach(q3active.Participants{Root: p.Root, Safety: p.Safety, Shard: p.Shard, Authority: p.Authority}))
	p.RT = rt
}

// Bundle is the staged bundle of the fixture's activation.
func (p *Process) Bundle() q3active.Bundle {
	return q3active.Bundle{Envelope: p.F.EnvelopeBytes, Snapshot: p.F.Snapshot}
}
