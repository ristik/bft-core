package consensus

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	drctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

var errNotAdmitted = errors.New("activation is not installed")

// scriptedGate admits the epochs it was told to and counts every question.
type scriptedGate struct {
	mu      sync.Mutex
	refused map[uint64]error
	asked   []uint64
}

func (g *scriptedGate) Admit(epoch uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.asked = append(g.asked, epoch)
	return g.refused[epoch]
}

func (g *scriptedGate) refuse(epoch uint64, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.refused == nil {
		g.refused = map[uint64]error{}
	}
	g.refused[epoch] = err
}

func gated(t *testing.T, r *decisionRig, g ActivationGate, resolver SigningResolver) (*SafetyModule, storage.BoltDB) {
	t.Helper()
	r.closeDB()
	db, err := storage.NewBoltStorage(r.path, storage.WithNoSync())
	require.NoError(t, err)
	r.db = &db
	t.Cleanup(r.closeDB)
	opts := []SafetyOption{WithActivationGate(g)}
	if resolver != nil {
		opts = append(opts, WithDomainBoundSigning(resolver, func(uint64) (CommittedBlockInfo, error) { return r.executed, nil }))
	}
	m, err := NewSafetyModule(types.NetworkID(r.cfg.Network), "node1", r.signer, db, opts...)
	require.NoError(t, err)
	return m, db
}

func TestTheActivationGateAdmitsTheSigningOfAnAdmittedEpoch(t *testing.T) {
	r := newDecisionRig(t)
	g := &scriptedGate{}
	m, _ := gated(t, r, g, r.scheme2())
	v, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	r.verifyVote(v)
	require.Equal(t, []uint64{1}, g.asked, "the module asked about its vote's epoch")
}

func TestTheActivationGateRefusesBeforeAnythingIsSignedOrRecorded(t *testing.T) {
	r := newDecisionRig(t)
	g := &scriptedGate{}
	g.refuse(1, errNotAdmitted)
	m, db := gated(t, r, g, r.scheme2())
	before := db.GetHighestVotedRound()

	_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.ErrorIs(t, err, errNotAdmitted)
	d, derr := db.Decision(storage.DecisionVote, 1, 5)
	require.NoError(t, derr)
	require.Nil(t, d, "no decision is recorded for an epoch that is not admitted")
	require.Equal(t, before, db.GetHighestVotedRound())

	// the same module signs once the epoch is admitted: the refusal left no state behind
	g.refuse(1, nil)
	v, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	r.verifyVote(v)
}

func TestTheActivationGateIsAskedAtEverySigningAndNotCached(t *testing.T) {
	r := newDecisionRig(t)
	g := &scriptedGate{}
	m, _ := gated(t, r, g, r.scheme2())
	_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.NoError(t, err)
	g.refuse(1, errNotAdmitted) // the installation no longer verifies
	_, err = m.MakeVote(r.committingBlock(6), hash32(1), nil, nil)
	require.ErrorIs(t, err, errNotAdmitted)
}

func TestAGatedModuleWithoutSigningHistoryNeverFallsBackToSchemeOne(t *testing.T) {
	r := newDecisionRig(t)
	m, db := gated(t, r, &scriptedGate{}, nil)
	_, err := m.MakeVote(r.committingBlock(5), hash32(1), nil, nil)
	require.ErrorIs(t, err, ErrNoSigningHistory)
	d, derr := db.Decision(storage.DecisionVote, 1, 5)
	require.NoError(t, derr)
	require.Nil(t, d)
	_, err = m.RecordedTimeout(1, 5)
	require.ErrorIs(t, err, ErrNoSigningHistory)
	_, tc := r.nonCommittingBlock(8)
	hqc := tc.Timeout.HighQc
	require.ErrorIs(t, m.SignTimeout(abdrc.NewTimeoutMsg(drctypes.NewTimeout(8, 1, hqc), "node1", tc), tc), ErrNoSigningHistory)

	// without the gate the legacy behaviour is unchanged: no resolver means scheme 1
	plain, err := NewSafetyModule(types.NetworkID(r.cfg.Network), "node1", r.signer, db)
	require.NoError(t, err)
	cfg, err := plain.config(1)
	require.NoError(t, err)
	require.EqualValues(t, 1, cfg.Scheme)
}

func TestTheActivationGateCoversTimeoutsAndTheirRebroadcast(t *testing.T) {
	c := newPairedCommittee(t)
	g := &scriptedGate{}
	db, err := storage.NewBoltStorage(filepath.Join(t.TempDir(), "rc.db"), storage.WithNoSync())
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	m, err := NewSafetyModule(types.NetworkID(c.cfg.Network), "1", c.signers["1"], db, WithDomainBoundSigning(c.store, nil), WithActivationGate(g))
	require.NoError(t, err)
	qc := pairedQC(t, c, 12)
	previous := precedingTC(t, c, 13, qc)

	g.refuse(2, errNotAdmitted)
	msg := abdrc.NewTimeoutMsg(drctypes.NewTimeout(14, 2, qc), "1", previous)
	require.ErrorIs(t, m.SignTimeout(msg, previous), errNotAdmitted)
	require.Empty(t, msg.Signature)
	d, err := db.Decision(storage.DecisionTimeout, 2, 14)
	require.NoError(t, err)
	require.Nil(t, d)

	g.refuse(2, nil)
	require.NoError(t, m.SignTimeout(msg, previous))
	g.refuse(2, errNotAdmitted)
	_, err = m.RecordedTimeout(2, 14)
	require.ErrorIs(t, err, errNotAdmitted, "a recorded timeout is not sent again for an epoch that is not admitted")
	g.refuse(2, nil)
	again, err := m.RecordedTimeout(2, 14)
	require.NoError(t, err)
	require.NotNil(t, again)
}

func TestSafetyModuleBoundTo(t *testing.T) {
	r := newDecisionRig(t)
	g := &scriptedGate{}
	m, _ := gated(t, r, g, r.scheme2())
	require.True(t, m.BoundTo(g))
	require.False(t, m.BoundTo(&scriptedGate{}), "another gate")
	require.False(t, m.BoundTo(nil))
	require.False(t, m.BoundTo("gate"), "not a gate")
	plain, err := NewSafetyModule(types.NetworkID(r.cfg.Network), "node1", r.signer, m.storage)
	require.NoError(t, err)
	require.False(t, plain.BoundTo(g), "a module with no gate is bound to nothing")
	require.False(t, plain.BoundTo(nil))
}
