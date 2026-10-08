package posclosure

import (
	"crypto"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/votesig"
	"github.com/unicitynetwork/bft-go-base/types"
)

type fakeTB struct {
	tb     *types.RootTrustBaseV1
	err    error
	cfgErr error
	asked  []uint64
}

func (f *fakeTB) GetByEpoch(e uint64) (*types.RootTrustBaseV1, error) {
	f.asked = append(f.asked, e)
	return f.tb, f.err
}
func (f *fakeTB) SigningConfig(uint64) (votesig.Config, error) {
	return votesig.Config{Scheme: votesig.SchemeLegacy}, f.cfgErr
}

type fakeOrch struct {
	conf    *types.PartitionDescriptionRecord
	confErr error
	idsErr  error
	rounds  []uint64
	epochs  []uint64
}

func (o *fakeOrch) ShardConfig(_ types.PartitionID, _ types.ShardID, round uint64) (*types.PartitionDescriptionRecord, error) {
	o.rounds = append(o.rounds, round)
	return o.conf, o.confErr
}
func (o *fakeOrch) AcknowledgedIdentities(_ types.PartitionID, _ types.ShardID, epoch uint64) ([]evmassign.Identity, [32]byte, error) {
	o.epochs = append(o.epochs, epoch)
	return []evmassign.Identity{{Weight: 3}}, [32]byte{0xa7}, o.idsErr
}

func TestHistoryReadsTheClosedEpochAndTheConfigurationInstalledAtH(t *testing.T) {
	conf := &types.PartitionDescriptionRecord{Version: 1, PartitionID: 8, PartitionTypeID: 1, TypeIDLen: 8, UnitIDLen: 256, NetworkID: 5, Epoch: 3, EpochStart: 9}
	tbs, orch := &fakeTB{tb: &types.RootTrustBaseV1{Epoch: 2}}, &fakeOrch{conf: conf}
	h := History{Partition: 8, TrustBases: tbs, Orchestration: orch}

	tb, cfg, err := h.TrustBase(2)
	require.NoError(t, err)
	require.EqualValues(t, 2, tb.Epoch)
	require.Equal(t, votesig.SchemeLegacy, cfg.Scheme)
	require.Equal(t, []uint64{2}, tbs.asked)

	hash, ids, assignment, err := h.Assignment(4)
	require.NoError(t, err)
	want, err := conf.Hash(crypto.SHA256)
	require.NoError(t, err)
	require.Equal(t, want, hash, "the hash the root stores in the snapshot's shard entry")
	require.Equal(t, []uint64{4}, orch.rounds)
	require.Equal(t, []uint64{3}, orch.epochs, "the identities of the configuration's own shard epoch")
	require.Equal(t, []evmassign.Identity{{Weight: 3}}, ids)
	require.Equal(t, [32]byte{0xa7}, assignment)

	boom := errors.New("gone")
	for name, run := range map[string]func() error{
		"no trust base":    func() error { _, _, err := History{TrustBases: &fakeTB{err: boom}}.TrustBase(2); return err },
		"a nil trust base": func() error { _, _, err := History{TrustBases: &fakeTB{}}.TrustBase(2); return err },
		"no signing config": func() error {
			_, _, err := History{TrustBases: &fakeTB{tb: tbs.tb, cfgErr: boom}}.TrustBase(2)
			return err
		},
		"no configuration": func() error {
			_, _, _, err := History{Orchestration: &fakeOrch{confErr: boom}}.Assignment(4)
			return err
		},
		"a nil configuration": func() error { _, _, _, err := History{Orchestration: &fakeOrch{}}.Assignment(4); return err },
		"no identity records": func() error {
			_, _, _, err := History{Orchestration: &fakeOrch{conf: conf, idsErr: boom}}.Assignment(4)
			return err
		},
	} {
		require.ErrorIs(t, run(), ErrHistory, name)
	}
}

func TestAuthorityConvertsAVerifiedBundleToFacts(t *testing.T) {
	f := handoffbundle.New(t)
	b := handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	raw, err := handoffdelivery.EncodeBundle(b)
	require.NoError(t, err)
	hist := fixedHistory{old: f.Old, hash: f.ConfHash}
	a := Authority{Verifier: handoffdelivery.ClosureVerifier{Partition: f.Partition, Shard: f.Shard, History: hist}}
	facts, err := a.VerifyClosure(raw, f.Proof.Record.Epoch)
	require.NoError(t, err)
	id, err := handoffdelivery.SemanticIdentity(b)
	require.NoError(t, err)
	require.Equal(t, id, facts.BundleID)
	require.Equal(t, f.Proof.Record.Epoch, facts.ClosedEpoch)
	require.Equal(t, f.Proof.Record.OrderedRound, facts.HRound)
	require.Equal(t, [32]byte(f.Proof.Record.ID()), facts.HRecordID)
	require.Equal(t, [32]byte(f.Snapshot.CommitQc.LedgerCommitInfo.Hash), facts.TerminalRoot)
	require.Equal(t, [32]byte{0xa7}, facts.AssignmentID)
	require.Len(t, facts.Closed, 1)
	_, err = a.VerifyClosure(raw[:len(raw)-1], f.Proof.Record.Epoch)
	require.ErrorIs(t, err, handoffdelivery.ErrClosure)
}

type fixedHistory struct {
	old  *types.RootTrustBaseV1
	hash []byte
}

func (h fixedHistory) TrustBase(uint64) (*types.RootTrustBaseV1, votesig.Config, error) {
	return h.old, votesig.Config{Scheme: votesig.SchemeLegacy}, nil
}
func (h fixedHistory) Assignment(uint64) ([]byte, []evmassign.Identity, [32]byte, error) {
	return h.hash, []evmassign.Identity{{Weight: 1}}, [32]byte{0xa7}, nil
}
