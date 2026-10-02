package configuredprogress

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-go-base/types"
)

// terminalFixture is a deployment whose first assignment change has been activated: the terminal certificate of the epoch it ends
// (shard epoch 1) carries the successor's configuration hash, not the genesis one. A second handoff ends exactly such an epoch.
type terminalFixture struct {
	*fixture
	pdr  *types.PartitionDescriptionRecord
	conf [32]byte
}

func newTerminalFixture(t *testing.T) *terminalFixture {
	f := newFixture(t, 3)
	succ, err := evmassign.NewSuccessor(f.c.Full, f.c.Full.Validators)
	require.NoError(t, err)
	succ.Validators[0].NodeID = "validator-2"
	pdr, err := evmassign.Activate(succ, 10)
	require.NoError(t, err)
	conf, err := evmassign.PDRHash(pdr)
	require.NoError(t, err)
	require.NotEqual(t, f.origin.FullShardConfHash().Bytes(), conf[:], "premise: the epoch's configuration is not the genesis one")
	return &terminalFixture{fixture: f, pdr: pdr, conf: conf}
}

// terminal is the first certified block's certificate, signed under the successor configuration with a technical record at shard epoch 1,
// authenticated under ctx's observation context.
func (f *terminalFixture) terminal(t *testing.T, ctx Context) (rootinput.VerifiedObservationV2, error) {
	t.Helper()
	b := f.c.Blocks[1]
	ir := &types.InputRecord{Version: 1, RoundNumber: b.Round, Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + b.Round, BlockHash: b.Hash.Bytes()}
	tr := terminalTechnical(2, 1)
	uc := f.c.CertifyFor(f.pdr, f.c.Signer, ir, tr, 5)
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

func terminalTechnical(round, epoch uint64) *certification.TechnicalRecord {
	tr := &certification.TechnicalRecord{Round: round, Epoch: epoch, Leader: "leader"}
	tr.StatHash, tr.FeeHash = make([]byte, 32), make([]byte, 32)
	tr.StatHash[0], tr.FeeHash[0] = 0xa1, 0xa2
	return tr
}

// The terminal certificate of a later epoch is recorded under the genesis-bound store, authenticated under exactly the configuration
// installed for its own shard epoch. The old way of building the context, overriding Observation.ShardConfHash, was refused as another
// configured origin, which stopped the node at its second assignment handoff. PrepareObservation re-authenticates the observation and
// compares its origin identity (observation.go), so the success case also exercises that check.
func TestTerminalCertificateOfALaterEpochIsRecordedUnderItsOwnConfiguration(t *testing.T) {
	f := newTerminalFixture(t)
	store := func(t *testing.T) *Store {
		s, _ := f.open(10)
		_, _, err := s.Initialize(context.Background(), f.ctx)
		require.NoError(t, err)
		return s
	}

	t.Run("the override of the genesis pin is refused as another configured origin", func(t *testing.T) {
		old := f.ctx
		old.Observation.ShardConfHash = f.conf[:]
		o, err := f.terminal(t, old)
		require.NoError(t, err, "the certificate itself authenticates under its own configuration")
		_, _, err = store(t).PrepareObservation(context.Background(), old, o)
		require.ErrorIs(t, err, ErrContext)
	})
	t.Run("the per-epoch resolver records it", func(t *testing.T) {
		tc := TerminalContext(f.ctx, f.conf[:], 1)
		require.Equal(t, f.origin.FullShardConfHash().Bytes(), tc.Observation.ShardConfHash, "the store stays bound to the genesis origin")
		o, err := f.terminal(t, tc)
		require.NoError(t, err)
		s := store(t)
		p, _, err := s.PrepareObservation(context.Background(), tc, o)
		require.NoError(t, err)
		_, _, err = s.CommitObservation(p)
		require.NoError(t, err)
	})
	t.Run("another shard epoch has no configuration", func(t *testing.T) {
		good := TerminalContext(f.ctx, f.conf[:], 1)
		o, err := f.terminal(t, good)
		require.NoError(t, err)
		for _, epoch := range []uint64{0, 2} {
			wrong := TerminalContext(f.ctx, f.conf[:], epoch)
			_, err := f.terminal(t, wrong)
			require.ErrorIs(t, err, rootinput.ErrConfEpochUnknown)
			require.NotErrorIs(t, err, rootinput.ErrUnauthenticated, "an unknown epoch is not a forgery")
			_, _, err = store(t).PrepareObservation(context.Background(), wrong, o)
			require.ErrorIs(t, err, rootinput.ErrConfEpochUnknown)
			require.NotErrorIs(t, err, ErrContext)
		}
	})
	t.Run("a different configuration for the right epoch is not authenticated", func(t *testing.T) {
		other := f.conf
		other[0] ^= 1
		_, err := f.terminal(t, TerminalContext(f.ctx, other[:], 1))
		require.ErrorIs(t, err, rootinput.ErrUnauthenticated)
		require.NotErrorIs(t, err, rootinput.ErrConfEpochUnknown)
	})
	t.Run("the caller's context is not modified", func(t *testing.T) {
		before := f.ctx.Observation.ConfForEpoch
		_ = TerminalContext(f.ctx, f.conf[:], 1)
		require.Nil(t, before)
		require.Nil(t, f.ctx.Observation.ConfForEpoch)
	})
}
