package rootinput

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmassign"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

// assignmentFixture is a sealRegistry/v2 deployment with the genesis assignment and two successor EVM
// assignments. Parent P is the last certified block; the registry still shows the genesis assignment
// until an acknowledgement is imported.
type assignmentFixture struct {
	c      *certifiedchain.Chain
	origin registrygenesis.GenesisOrigin
	blocks []certifiedchain.Block
	pdr    [3]*types.PartitionDescriptionRecord // epoch 0 (genesis), 1, 2
	hash   [3][32]byte
}

func newAssignmentFixture(t *testing.T) *assignmentFixture {
	c := certifiedchain.NewV2(t, 3, 0)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(c.Genesis.GenesisJSON(), &doc))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
	for k := range alloc {
		if strings.EqualFold(strings.TrimPrefix(k, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
			delete(alloc, k)
		}
	}
	doc["alloc"], _ = json.Marshal(alloc)
	source, err := json.Marshal(doc)
	require.NoError(t, err)
	art, err := registrygenesis.PinnedArtifactV2()
	require.NoError(t, err)
	p, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), c.Pins, art, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	o := p.Origin()
	require.Equal(t, c.Genesis.FullShardConfHash(), o.FullShardConfHash())
	b0 := certifiedchain.Block{Hash: o.BlockHash(), StateRoot: o.StateRoot(), Evidence: o.Evidence()}
	b1 := c.Executed(b0, 1, 5)
	f := &assignmentFixture{c: c, origin: o, blocks: []certifiedchain.Block{b0, b1}}
	f.pdr[0] = c.Full
	for epoch := 1; epoch <= 2; epoch++ {
		succ, err := evmassign.NewSuccessor(f.pdr[epoch-1], f.pdr[epoch-1].Validators)
		require.NoError(t, err)
		succ.Validators[0].NodeID = "validator-" + string(rune('1'+epoch))
		f.pdr[epoch], err = evmassign.Activate(succ, uint64(10*epoch))
		require.NoError(t, err)
	}
	for i, p := range f.pdr {
		h, err := evmassign.PDRHash(p)
		require.NoError(t, err)
		f.hash[i] = h
	}
	return f
}

func (f *assignmentFixture) snapshot(t *testing.T, b certifiedchain.Block, active registryproof.Assignment) registryproof.Snapshot {
	ctx := f.origin.ProofContext()
	ctx.Active = active
	s, err := registryproof.Verify(ctx, b.Hash, b.Evidence)
	require.NoError(t, err)
	return s
}

func (f *assignmentFixture) obsContext(rootEpoch uint64, extra ...[32]byte) ObservationContextV2 {
	c := ObservationContextV2{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: f.origin.FullShardConfHash().Bytes(),
		RootEpoch: rootEpoch, TrustBases: stubTrustBases{tb: f.trust(rootEpoch)}}
	for _, h := range extra {
		c.AlsoAcceptConfHashes = append(c.AlsoAcceptConfHashes, bytes.Clone(h[:]))
	}
	return c
}

func (f *assignmentFixture) trust(epoch uint64) *types.RootTrustBaseV1 {
	tb := *f.c.TrustBase
	tb.Epoch = epoch
	tb.Signatures = nil
	return &tb
}

// certify signs the certificate of ir/tr over pdr under the given root epoch, as the root that activated it.
func (f *assignmentFixture) certify(t *testing.T, pdr *types.PartitionDescriptionRecord, ir *types.InputRecord, tr *certification.TechnicalRecord, root, rootEpoch uint64) *types.UnicityCertificate {
	uc := f.c.CertifyFor(pdr, f.c.Signer, ir, tr, root)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Epoch = rootEpoch
	uc.UnicitySeal.Signatures = nil
	v, err := f.c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), f.c.Signer))
	return uc
}

func (f *assignmentFixture) irAt(b certifiedchain.Block, prev certifiedchain.Block, epoch uint64) *types.InputRecord {
	return &types.InputRecord{Version: 1, RoundNumber: b.Round, Epoch: epoch, PreviousHash: prev.StateRoot.Bytes(),
		Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 1_700_000_000 + b.Round, BlockHash: b.Hash.Bytes()}
}

func technicalAt(epoch, round uint64) *certification.TechnicalRecord {
	tr := certifiedchain.Technical(round - 1)
	tr.Epoch, tr.Round = epoch, round
	return tr
}

func (f *assignmentFixture) step(rootOld, shardOld uint64, oldHash, newHash [32]byte, commit byte, parent common.Hash) handoff.EVMTransition {
	tr := handoff.EVMTransition{OldRootEpoch: rootOld, NewRootEpoch: rootOld + 1, OldShardEpoch: shardOld, NewShardEpoch: shardOld + 1,
		OldActiveConfHash: oldHash, NewActiveConfHash: newHash, NextBodyID: [32]byte{1}, GenesisID: [32]byte{2}}
	tr.Ack = handoff.AckRecord{FrozenID: [32]byte{3}, CommitID: [32]byte{commit}, FrozenParent: parent, SuccessorParent: parent,
		SuccessorTR: [32]byte{5}, EVMRound: 11}
	return tr
}

func (f *assignmentFixture) derive(t *testing.T, parent certifiedchain.Block, snap registryproof.Snapshot, round uint64, o VerifiedObservationV2, transition []byte) (ResultV2, error) {
	return DeriveV2(ContextV2{Genesis: f.origin, Parent: snap, Round: round, ParentHash: parent.Hash.Bytes(),
		TransitionsPending: len(transition) != 0, Transition: transition}, o)
}

func TestAssignmentAcknowledgementDerivesWithNonzeroEpochs(t *testing.T) {
	f := newAssignmentFixture(t)
	p := f.blocks[1]
	snap := f.snapshot(t, p, registryproof.Assignment{Set: true, ShardEpoch: 0, RootEpoch: 1, ActiveConfHash: f.origin.FullShardConfHash()})
	// The new root recertifies P with the successor assignment's configuration and technical record.
	ir := f.irAt(p, f.blocks[0], 0)
	tr := technicalAt(1, 11)
	uc := f.certify(t, f.pdr[1], ir, tr, 12, 2)
	o, err := AuthenticateObservationV2(context.Background(), f.obsContext(2, f.hash[1]), uc, tr)
	require.NoError(t, err)

	ack := f.step(1, 0, f.hash[0], f.hash[1], 0xa1, p.Hash)
	raw, err := ack.Encode()
	require.NoError(t, err)
	r, err := f.derive(t, p, snap, 11, o, raw)
	require.NoError(t, err)
	require.EqualValues(t, 0, r.Input.CertifiedEpoch)
	require.EqualValues(t, 1, r.Input.AuthorizedEpoch)
	require.Len(t, r.Input.Transitions, 1)

	t.Run("ordinary execution after the acknowledgement runs at nonzero epochs", func(t *testing.T) {
		post := f.c.ExecutedState(p, 2, 13, []byte("ack"), map[string]common.Hash{
			"assignment.epoch": word(1), "assignment.rootEpoch": word(2), "assignment.activeConfHash": common.Hash(f.hash[1]),
			"transition.cursor": word(1), "transition.bodyID": word(7), "transition.genesisID": word(8), "transition.frozenID": word(9),
			"transition.commitID": word(10), "transition.frozenParent": common.Hash(p.Hash), "transition.successorTR": word(12), "origin.rootEpoch": word(2),
		})
		postSnap := f.snapshot(t, post, registryproof.Assignment{Set: true, ShardEpoch: 1, RootEpoch: 2, ActiveConfHash: common.Hash(f.hash[1])})
		ir2 := f.irAt(post, p, 1)
		tr2 := technicalAt(1, 12)
		uc2 := f.certify(t, f.pdr[1], ir2, tr2, 14, 2)
		o2, err := AuthenticateObservationV2(context.Background(), f.obsContext(2, f.hash[1]), uc2, tr2)
		require.NoError(t, err)
		r2, err := f.derive(t, post, postSnap, 12, o2, nil)
		require.NoError(t, err)
		require.EqualValues(t, 1, r2.Input.CertifiedEpoch)
		require.EqualValues(t, 1, r2.Input.AuthorizedEpoch)
		require.Empty(t, r2.Input.Transitions)
	})

	for name, tc := range map[string]struct {
		mutate func(*handoff.EVMTransition)
		want   string
	}{
		"old root epoch is not the registry's":  {func(t *handoff.EVMTransition) { t.OldRootEpoch, t.NewRootEpoch = 2, 3 }, "registry assignment"},
		"old shard epoch is not the registry's": {func(t *handoff.EVMTransition) { t.OldShardEpoch, t.NewShardEpoch = 1, 2 }, "registry assignment"},
		"old hash is not the registry's":        {func(t *handoff.EVMTransition) { t.OldActiveConfHash = f.hash[2] }, "registry assignment"},
		"another frozen parent":                 {func(t *handoff.EVMTransition) { t.Ack.FrozenParent[0] ^= 1; t.Ack.SuccessorParent = t.Ack.FrozenParent }, "registry assignment"},
		"new shard epoch is not the authorized": {func(t *handoff.EVMTransition) { t.NewShardEpoch = 2; t.NewRootEpoch = 3; t.SupersessionSpan = 0 }, "registry assignment"},
		"new hash is not the certificate's":     {func(t *handoff.EVMTransition) { t.NewActiveConfHash = f.hash[2] }, "does not match the certified origin"},
	} {
		t.Run(name, func(t *testing.T) {
			bad := ack
			tc.mutate(&bad)
			raw, err := bad.Encode()
			if err != nil {
				t.Skipf("mutation is refused by the transition codec itself: %v", err)
			}
			_, err = f.derive(t, p, snap, 11, o, raw)
			require.ErrorIs(t, err, ErrV2Context)
			require.ErrorContains(t, err, tc.want)
		})
	}
}

func TestAcknowledgementIsBoundToTheCertifiedOriginAndAuthorizedEpoch(t *testing.T) {
	f := newAssignmentFixture(t)
	p := f.blocks[1]
	snap := f.snapshot(t, p, registryproof.Assignment{})
	ack := f.step(1, 0, f.hash[0], f.hash[1], 0xa1, p.Hash)
	raw, err := ack.Encode()
	require.NoError(t, err)

	t.Run("authorized epoch differs from the transition's new epoch", func(t *testing.T) {
		tr := technicalAt(2, 11) // the technical record authorizes epoch 2, the transition installs 1
		uc := f.certify(t, f.pdr[1], f.irAt(p, f.blocks[0], 0), tr, 12, 2)
		o, err := AuthenticateObservationV2(context.Background(), f.obsContext(2, f.hash[1]), uc, tr)
		require.NoError(t, err)
		_, err = f.derive(t, p, snap, 11, o, raw)
		require.ErrorIs(t, err, ErrV2Context)
		require.ErrorContains(t, err, "does not match the certified origin and authorized assignment")
	})
	t.Run("certified IR epoch differs from the transition's old epoch", func(t *testing.T) {
		tr := technicalAt(1, 11)
		uc := f.certify(t, f.pdr[1], f.irAt(p, f.blocks[0], 1), tr, 12, 2) // IR already at epoch 1
		o, err := AuthenticateObservationV2(context.Background(), f.obsContext(2, f.hash[1]), uc, tr)
		require.NoError(t, err)
		_, err = f.derive(t, p, snap, 11, o, raw)
		require.ErrorIs(t, err, ErrV2Context)
		require.ErrorContains(t, err, "does not match the certified origin and authorized assignment")
	})
}

func TestSupersessionAcknowledgementFoldsTheCommittedSpan(t *testing.T) {
	f := newAssignmentFixture(t)
	p := f.blocks[1]
	snap := f.snapshot(t, p, registryproof.Assignment{Set: true, ShardEpoch: 0, RootEpoch: 1, ActiveConfHash: f.origin.FullShardConfHash()})
	ir := f.irAt(p, f.blocks[0], 0)
	tr := technicalAt(2, 21)
	uc := f.certify(t, f.pdr[2], ir, tr, 22, 3)
	o, err := AuthenticateObservationV2(context.Background(), f.obsContext(3, f.hash[1], f.hash[2]), uc, tr)
	require.NoError(t, err)

	first := f.step(1, 0, f.hash[0], f.hash[1], 0xa1, p.Hash)
	second := f.step(2, 1, f.hash[1], f.hash[2], 0xa2, p.Hash)
	folded, err := handoff.FoldTransitions([]handoff.EVMTransition{first, second})
	require.NoError(t, err)
	raw, err := folded.Encode()
	require.NoError(t, err)
	r, err := f.derive(t, p, snap, 21, o, raw)
	require.NoError(t, err)
	require.EqualValues(t, 0, r.Input.CertifiedEpoch)
	require.EqualValues(t, 2, r.Input.AuthorizedEpoch)

	t.Run("a late acknowledgement of the superseded assignment is refused", func(t *testing.T) {
		// The superseded set signs at shard epoch 1 over its own configuration; the authorized assignment is 2.
		late := f.certify(t, f.pdr[1], ir, technicalAt(1, 21), 22, 3)
		lateObs, err := AuthenticateObservationV2(context.Background(), f.obsContext(3, f.hash[1], f.hash[2]), late, technicalAt(1, 21))
		require.NoError(t, err)
		_, err = f.derive(t, p, snap, 21, lateObs, raw)
		require.ErrorIs(t, err, ErrV2Context)
		require.ErrorContains(t, err, "does not match the certified origin")
	})
	t.Run("the folded span must name the registry base", func(t *testing.T) {
		bad := folded
		bad.OldRootEpoch, bad.NewRootEpoch = 2, 4
		raw, err := bad.Encode()
		require.NoError(t, err)
		_, err = f.derive(t, p, snap, 21, o, raw)
		require.ErrorIs(t, err, ErrV2Context)
	})
	t.Run("a chain that does not continue is refused by the fold", func(t *testing.T) {
		gap := f.step(3, 1, f.hash[1], f.hash[2], 0xa2, p.Hash)
		_, err := handoff.FoldTransitions([]handoff.EVMTransition{first, gap})
		require.ErrorIs(t, err, handoff.ErrBoundary)
	})
}

func TestEpochGuardsAreAuthenticatedValuesNotConstants(t *testing.T) {
	f := newAssignmentFixture(t)
	p := f.blocks[1]
	ir := f.irAt(p, f.blocks[0], 0)

	t.Run("an authorized epoch behind the certified one is refused", func(t *testing.T) {
		ir := f.irAt(p, f.blocks[0], 1)
		tr := technicalAt(0, 11)
		uc := f.certify(t, f.pdr[0], ir, tr, 12, 1)
		_, err := AuthenticateObservationV2(context.Background(), f.obsContext(1), uc, tr)
		require.True(t, IsUnsupportedObservationV2(err), "%v", err)
		require.ErrorContains(t, err, "behind certified epoch")
	})
	t.Run("a certificate over an uninstalled configuration is not authenticated", func(t *testing.T) {
		tr := technicalAt(1, 11)
		uc := f.certify(t, f.pdr[1], ir, tr, 12, 2)
		_, err := AuthenticateObservationV2(context.Background(), f.obsContext(2), uc, tr)
		require.ErrorIs(t, err, ErrUnauthenticated, "an assignment the verifier has not installed from verified history is not accepted")
	})
	t.Run("ordinary execution refuses an authorized epoch the registry has not acknowledged", func(t *testing.T) {
		snap := f.snapshot(t, p, registryproof.Assignment{})
		tr := technicalAt(1, 11)
		uc := f.certify(t, f.pdr[1], ir, tr, 12, 1)
		o, err := AuthenticateObservationV2(context.Background(), f.obsContext(1, f.hash[1]), uc, tr)
		require.NoError(t, err)
		_, err = f.derive(t, p, snap, 11, o, nil)
		require.ErrorIs(t, err, ErrV2Context)
		require.ErrorContains(t, err, "differs from the registry assignment")
	})
	t.Run("the root input refuses an authorized epoch ahead of the certified one without a transition", func(t *testing.T) {
		ri := evmroot.RootInputV2{Version: evmroot.ProfileVersionV2, NetworkID: 3, PartitionID: 8, ShardID: []byte{0x80}, Round: 11,
			CertifiedEpoch: 0, AuthorizedEpoch: 1, ParentHash: bytes.Repeat([]byte{1}, 32),
			TE: evmroot.TechnicalRecord{Round: 11, Epoch: 1, Leader: "l", StatHash: bytes.Repeat([]byte{1}, 32), FeeHash: bytes.Repeat([]byte{2}, 32)}}
		ri.Origin = evmroot.RootOriginV2{NetworkID: 3, RootRound: 12, RootEpoch: 2, UnicityTreeRoot: bytes.Repeat([]byte{1}, 32), InputVersion: 1,
			IR:     evmroot.ShardInputRecord{Round: 1, Epoch: 0, PreviousHash: bytes.Repeat([]byte{2}, 32), Hash: bytes.Repeat([]byte{3}, 32), BlockHash: bytes.Repeat([]byte{4}, 32)},
			TRHash: bytes.Repeat([]byte{5}, 32), ShardConfHash: bytes.Repeat([]byte{6}, 32)}
		require.ErrorContains(t, ri.Validate(), "without an acknowledgement transition")
		ri.Transitions = [][]byte{{1}}
		require.NoError(t, ri.Validate())
		ri.CertifiedEpoch = 3
		require.ErrorContains(t, ri.Validate(), "differ from the certified origin")
		ri.CertifiedEpoch, ri.AuthorizedEpoch = 0, 0
		require.ErrorContains(t, ri.Validate(), "differ from the certified origin")
	})
}

func word(v uint64) common.Hash { return common.BigToHash(new(big.Int).SetUint64(v)) }
