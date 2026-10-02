package configuredprogress

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

// terminalFixture is a deployment with two assignment changes activated: shard epoch 1 (configuration h1) and shard epoch 2 (h2). The
// terminal certificate of the handoff that ends epoch 2 carries h2, while the node's durable store already holds certificates of epoch 1.
type terminalFixture struct {
	*fixture
	pdr  [3]*types.PartitionDescriptionRecord
	conf [3][32]byte
}

func newTerminalFixture(t *testing.T) *terminalFixture {
	f := newFixture(t, 3)
	tf := &terminalFixture{fixture: f}
	tf.pdr[0] = f.c.Full
	for epoch := 1; epoch <= 2; epoch++ {
		succ, err := evmassign.NewSuccessor(tf.pdr[epoch-1], tf.pdr[epoch-1].Validators)
		require.NoError(t, err)
		succ.Validators[0].NodeID = "validator-" + string(rune('1'+epoch))
		tf.pdr[epoch], err = evmassign.Activate(succ, uint64(10*epoch))
		require.NoError(t, err)
	}
	for i, p := range tf.pdr {
		h, err := evmassign.PDRHash(p)
		require.NoError(t, err)
		tf.conf[i] = h
	}
	require.NotEqual(t, f.origin.FullShardConfHash().Bytes(), tf.conf[1][:], "premise: epoch 1 is not the genesis configuration")
	require.NotEqual(t, tf.conf[1], tf.conf[2])
	return tf
}

// installed is a node's per-epoch configuration set (what ShardConfSet.ForEpoch serves).
func (f *terminalFixture) installed(epochs ...uint64) func(uint64) ([]byte, bool) {
	set := map[uint64][]byte{}
	for _, e := range epochs {
		set[e] = bytes.Clone(f.conf[e][:])
	}
	set[0] = f.origin.FullShardConfHash().Bytes()
	return func(e uint64) ([]byte, bool) { h, ok := set[e]; return bytes.Clone(h), ok }
}

func (f *terminalFixture) withInstalled(epochs ...uint64) Context {
	c := f.ctx
	c.Observation.ConfForEpoch = f.installed(epochs...)
	return c
}

// certified is the certificate of ir at shard epoch `epoch` (technical record round `round`), signed under that epoch's configuration at
// root round `root`, authenticated under ctx's observation context.
func (f *terminalFixture) certified(t *testing.T, ctx Context, ir *types.InputRecord, epoch, round, root uint64) (rootinput.VerifiedObservationV2, error) {
	t.Helper()
	tr := terminalTechnical(round, epoch)
	uc := f.c.CertifyFor(f.pdr[epoch], f.c.Signer, ir, tr, root)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, err := f.c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), f.c.Signer))
	return rootinput.AuthenticateObservationV2(context.Background(), ctx.Observation, uc, tr)
}

func (f *terminalFixture) firstIR() *types.InputRecord {
	b := f.c.Blocks[1]
	return &types.InputRecord{Version: 1, RoundNumber: b.Round, Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + b.Round, BlockHash: b.Hash.Bytes()}
}

// storeWithEpochOneState is a store that already holds the first certified observation, at shard epoch 1: what a validator that took part in
// the first assignment has when the next handoff's terminal certificate arrives.
func (f *terminalFixture) storeWithEpochOneState(t *testing.T) *Store {
	t.Helper()
	base := f.withInstalled(1, 2)
	s, _ := f.open(10)
	_, _, err := s.Initialize(context.Background(), base)
	require.NoError(t, err)
	o, err := f.certified(t, base, f.firstIR(), 1, 2, 5)
	require.NoError(t, err)
	p, _, err := s.PrepareObservation(context.Background(), base, o)
	require.NoError(t, err)
	_, _, err = s.CommitObservation(p)
	require.NoError(t, err)
	return s
}

func terminalTechnical(round, epoch uint64) *certification.TechnicalRecord {
	tr := &certification.TechnicalRecord{Round: round, Epoch: epoch, Leader: "leader"}
	tr.StatHash, tr.FeeHash = make([]byte, 32), make([]byte, 32)
	tr.StatHash[0], tr.FeeHash[0] = 0xa1, 0xa2
	return tr
}

// singleEpochOnly is the first TerminalContext (#358): a resolver that knows only the terminal epoch. It is the control for the tests below.
func singleEpochOnly(c Context, conf []byte, epoch uint64) Context {
	c.Observation.ConfForEpoch = func(e uint64) ([]byte, bool) {
		if e != epoch {
			return nil, false
		}
		return bytes.Clone(conf), true
	}
	return c
}

// The terminal certificate of a later epoch is recorded under the genesis-bound store, authenticated under exactly the verified snapshot's
// configuration for its own epoch, while the durable state the store already holds, at other epochs, keeps verifying under the node's
// installed set. A resolver that knew only the terminal epoch (#358) refused that stored state and stopped a joiner at the folded
// supersession (run8a); the genesis-pin override before it was refused as another configured origin (run7m).
func TestTerminalContextRecordsTheTerminalCertificateBesideStoredStateOfOtherEpochs(t *testing.T) {
	f := newTerminalFixture(t)
	terminalIR := f.c.InputRecord(2) // the ordinary block after the first certified one
	base := f.withInstalled(1)       // epoch 2 is not installed yet: its assignment is what this handoff activates

	t.Run("control: a resolver that knows only the terminal epoch refuses the stored epoch-1 state", func(t *testing.T) {
		s := f.storeWithEpochOneState(t)
		only := singleEpochOnly(base, f.conf[2][:], 2)
		o, err := f.certified(t, only, terminalIR, 2, 3, 6)
		require.NoError(t, err, "the terminal certificate itself authenticates")
		_, _, err = s.PrepareObservation(context.Background(), only, o)
		require.ErrorIs(t, err, rootinput.ErrConfEpochUnknown)
		require.NotErrorIs(t, err, rootinput.ErrUnauthenticated)
	})
	t.Run("the delegating context records it", func(t *testing.T) {
		s := f.storeWithEpochOneState(t)
		tc, err := TerminalContext(base, f.conf[2][:], 2)
		require.NoError(t, err)
		require.Equal(t, f.origin.FullShardConfHash().Bytes(), tc.Observation.ShardConfHash, "the store stays bound to the genesis origin")
		o, err := f.certified(t, tc, terminalIR, 2, 3, 6)
		require.NoError(t, err)
		p, _, err := s.PrepareObservation(context.Background(), tc, o)
		require.NoError(t, err)
		_, _, err = s.CommitObservation(p)
		require.NoError(t, err)
	})
	t.Run("another epoch is answered by the installed set, never by the terminal epoch's hash", func(t *testing.T) {
		tc, err := TerminalContext(base, f.conf[2][:], 2)
		require.NoError(t, err)
		for epoch, want := range map[uint64][]byte{0: f.origin.FullShardConfHash().Bytes(), 1: f.conf[1][:], 2: f.conf[2][:]} {
			got, ok := tc.Observation.ConfForEpoch(epoch)
			require.True(t, ok, "epoch %d", epoch)
			require.Equal(t, want, got, "epoch %d", epoch)
		}
	})
	t.Run("an epoch nothing is installed for is still refused", func(t *testing.T) {
		genesisOnly := f.withInstalled() // only epoch 0 is installed
		tc, err := TerminalContext(genesisOnly, f.conf[2][:], 2)
		require.NoError(t, err)
		_, ok := tc.Observation.ConfForEpoch(7)
		require.False(t, ok)
		// A certificate of epoch 1 while the terminal context names epoch 2 and epoch 1 is not installed: not a forgery, not resolvable.
		_, err = f.certified(t, tc, f.firstIR(), 1, 2, 5)
		require.ErrorIs(t, err, rootinput.ErrConfEpochUnknown)
		require.NotErrorIs(t, err, rootinput.ErrUnauthenticated)
	})
	t.Run("a verified configuration that contradicts an installed one is refused", func(t *testing.T) {
		installedBoth := f.withInstalled(1, 2)
		_, err := TerminalContext(installedBoth, f.conf[1][:], 2) // the snapshot claims epoch 1's hash for epoch 2
		require.ErrorIs(t, err, ErrTerminalConfConflict)
		tc, err := TerminalContext(installedBoth, f.conf[2][:], 2)
		require.NoError(t, err, "the same hash for the same epoch is consistent")
		got, ok := tc.Observation.ConfForEpoch(2)
		require.True(t, ok)
		require.Equal(t, f.conf[2][:], got)
	})
	t.Run("a different configuration for the terminal epoch is not authenticated", func(t *testing.T) {
		other := f.conf[2]
		other[0] ^= 1
		tc, err := TerminalContext(base, other[:], 2)
		require.NoError(t, err)
		_, err = f.certified(t, tc, terminalIR, 2, 3, 6)
		require.ErrorIs(t, err, rootinput.ErrUnauthenticated)
		require.NotErrorIs(t, err, rootinput.ErrConfEpochUnknown)
	})
	t.Run("without an installed set only the terminal epoch resolves, and the caller's context is not modified", func(t *testing.T) {
		tc, err := TerminalContext(f.ctx, f.conf[2][:], 2)
		require.NoError(t, err)
		_, ok := tc.Observation.ConfForEpoch(1)
		require.False(t, ok)
		got, ok := tc.Observation.ConfForEpoch(2)
		require.True(t, ok)
		require.Equal(t, f.conf[2][:], got)
		require.Nil(t, f.ctx.Observation.ConfForEpoch)
	})
}
