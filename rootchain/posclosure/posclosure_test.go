package posclosure

import (
	"context"
	"crypto"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/handoffbundle"
	"github.com/unicitynetwork/bft-core/rootchain/consensus/storage"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
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
	ids  []evmassign.Identity
}

func (h fixedHistory) assignment() [32]byte { return [32]byte{0xa7} }

func (h fixedHistory) TrustBase(uint64) (*types.RootTrustBaseV1, votesig.Config, error) {
	return h.old, votesig.Config{Scheme: votesig.SchemeLegacy}, nil
}
func (h fixedHistory) Assignment(uint64) ([]byte, []evmassign.Identity, [32]byte, error) {
	ids := h.ids
	if ids == nil {
		ids = []evmassign.Identity{{Weight: 1}}
	}
	return h.hash, ids, h.assignment(), nil
}

type fixedSource struct {
	bundle *handoffdelivery.Bundle
	err    error
	asked  []uint64
}

func (s *fixedSource) HandoffBundle(_ context.Context, epoch uint64) (*handoffdelivery.Bundle, error) {
	s.asked = append(s.asked, epoch)
	return s.bundle, s.err
}

func TestProposerBuildsTheControlTheExecutorWillVerify(t *testing.T) {
	f := handoffbundle.New(t)
	b := handoffdelivery.Bundle{Proof: f.Proof, Body: f.Body, Snapshot: f.Snapshot}
	closed := []evmassign.Identity{testIdentity(1, 6), testIdentity(2, 1)}
	hist := fixedHistory{old: f.Old, hash: f.ConfHash, ids: closed}
	auth := Authority{Verifier: handoffdelivery.ClosureVerifier{Partition: f.Partition, Shard: f.Shard, History: hist}}
	dep := storage.PosDeployment{RootNetwork: 5, Deployment: evmassign.Deployment{NetworkWord: [32]byte{1}, ChainID: [32]byte{31: 9}, Custody: [20]byte{19: 5}}}
	src := &fixedSource{bundle: &b}
	p := Proposer{Source: src, Authority: auth, Deployment: dep}

	c, witness, err := p.Closure(f.Proof.Record.Epoch, f.Proof.Record.Epoch+1, 9)
	require.NoError(t, err)
	require.Equal(t, []uint64{f.Proof.Record.Epoch + 1}, src.asked, "the bundle that opens the epoch after the closed one")
	raw, err := handoffdelivery.EncodeBundle(b)
	require.NoError(t, err)
	require.Equal(t, raw, witness)
	require.Equal(t, sha256.Sum256(raw), c.WitnessHash)
	require.EqualValues(t, rctypes.OpCloseLiability, c.Op)
	require.Equal(t, dep.RootNetwork, c.Network)
	require.Equal(t, dep.ChainID, c.ChainID)
	require.Equal(t, dep.Custody, c.Custody)
	require.EqualValues(t, f.Proof.Record.Epoch+1, c.OrderingEpoch)
	require.EqualValues(t, 9, c.OrderingRound)
	id, err := handoffdelivery.SemanticIdentity(b)
	require.NoError(t, err)
	require.Equal(t, rctypes.CloseContext{ClosedEpoch: f.Proof.Record.Epoch, BundleSemanticID: id}, *c.Close)

	d, err := storage.DecodeClosureData(c.Data)
	require.NoError(t, err)
	require.Equal(t, hist.assignment(), d.AssignmentID)
	require.Equal(t, f.Proof.Record.OrderedRound, d.HRound)
	require.Equal(t, [32]byte(f.Proof.Record.ID()), d.HRecordID)
	require.Equal(t, [32]byte(f.Snapshot.CommitQc.LedgerCommitInfo.Hash), d.TerminalRoot)
	wantE, err := evmassign.AssignmentExposureDigest(dep.Deployment, d.AssignmentID, closed)
	require.NoError(t, err)
	wantK, err := evmassign.KeyHistoryDigest(closed)
	require.NoError(t, err)
	require.Equal(t, wantE, d.ExposureDigest)
	require.Equal(t, wantK, d.KeyHistoryDigest)

	// nothing is proposed from a bundle that is missing, is of another epoch, or whose identity records cannot form the digests
	src.err = errors.New("not archived")
	_, _, err = p.Closure(f.Proof.Record.Epoch, 3, 9)
	require.ErrorIs(t, err, ErrHistory)
	src.err, src.bundle = nil, nil
	_, _, err = p.Closure(f.Proof.Record.Epoch, 3, 9)
	require.ErrorIs(t, err, ErrHistory)
	src.bundle = &b
	_, _, err = p.Closure(f.Proof.Record.Epoch+1, 3, 9)
	require.ErrorIs(t, err, handoffdelivery.ErrClosure)
	hist.ids = []evmassign.Identity{testIdentity(2, 1), testIdentity(1, 6)}
	bad := Proposer{Source: src, Deployment: dep, Authority: Authority{Verifier: handoffdelivery.ClosureVerifier{Partition: f.Partition, Shard: f.Shard, History: hist}}}
	_, _, err = bad.Closure(f.Proof.Record.Epoch, 3, 9)
	require.ErrorIs(t, err, evmassign.ErrCustodyDigest)
}

func testIdentity(id byte, weight uint64) evmassign.Identity {
	sid := make([]byte, 32)
	sid[31] = id
	key := make([]byte, 33)
	key[0], key[1] = 2, id
	return evmassign.Identity{StakingID: sid, Generation: 1, RootNodeID: "r", RootKey: key, EVMNodeID: "e", EVMKey: key, Weight: weight, RawWeight: weight,
		OperatorPayee: make([]byte, 20), ExposureDigest: make([]byte, 32)}
}
