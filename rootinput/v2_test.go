package rootinput

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	testtrustbase "github.com/unicitynetwork/bft-core/internal/testutils/trustbase"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	abcrypto "github.com/unicitynetwork/bft-go-base/crypto"
	"github.com/unicitynetwork/bft-go-base/types"
)

type v2Fixture struct {
	c      *certifiedchain.Chain
	origin registrygenesis.GenesisOrigin
	blocks []certifiedchain.Block
}

type callbackTrust struct {
	tb       *types.RootTrustBaseV1
	callback func()
}

type failingTrust struct{ err error }

func (s failingTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	return nil, s.err
}

func (s callbackTrust) GetByEpoch(context.Context, uint64) (*types.RootTrustBaseV1, error) {
	s.callback()
	return s.tb, nil
}

func newV2Fixture(t *testing.T) *v2Fixture {
	c := certifiedchain.New(t, 3, 0)
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
	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	p, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), c.Pins, art, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	o := p.Origin()
	require.Equal(t, c.Genesis.FullShardConfHash(), o.FullShardConfHash())
	b0 := certifiedchain.Block{Hash: o.BlockHash(), StateRoot: o.StateRoot(), Evidence: o.Evidence()}
	b1 := c.Executed(b0, 1, 5)
	b2 := c.Executed(b1, 2, 6)
	return &v2Fixture{c: c, origin: o, blocks: []certifiedchain.Block{b0, b1, b2}}
}
func (f *v2Fixture) obsContext() ObservationContextV2 {
	return ObservationContextV2{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: f.origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: stubTrustBases{tb: f.c.TrustBase}}
}
func (f *v2Fixture) snapshot(t *testing.T, i int) registryproof.Snapshot {
	s, e := registryproof.Verify(f.origin.ProofContext(), f.blocks[i].Hash, f.blocks[i].Evidence)
	require.NoError(t, e)
	return s
}
func (f *v2Fixture) signed(t *testing.T, ir *types.InputRecord, authorized, root uint64) (VerifiedObservationV2, *types.UnicityCertificate) {
	tr := certifiedchain.Technical(authorized - 1)
	tr.Round = authorized
	uc := f.signedRaw(t, ir, tr, root)
	o, e := AuthenticateObservationV2(context.Background(), f.obsContext(), uc, tr)
	require.NoError(t, e)
	return o, uc
}

func TestV2BootstrapFirstCertifiedOrdinaryAndQuiet(t *testing.T) {
	f := newV2Fixture(t)
	t.Run("bootstrap timeout assignment", func(t *testing.T) {
		ir := &types.InputRecord{Version: 1}
		o, _ := f.signed(t, ir, 7, 4)
		require.Equal(t, evmroot.OriginBootstrapV2, o.Class())
		r, e := DeriveV2(ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 0), Round: 7, ParentHash: f.blocks[0].Hash.Bytes()}, o)
		require.NoError(t, e)
		p, e := r.Input.Origin.CertifiedProjection()
		require.NoError(t, e)
		require.Zero(t, p)
		require.Equal(t, f.blocks[0].Hash.Bytes(), r.Input.ParentHash)
	})
	t.Run("first certified uses B1 subject and B0 predecessor", func(t *testing.T) {
		b := f.blocks[1]
		ir := &types.InputRecord{Version: 1, RoundNumber: 1, Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 9, BlockHash: b.Hash.Bytes()}
		o, _ := f.signed(t, ir, 2, 5)
		r, e := DeriveV2(ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 1), Round: 2, ParentHash: b.Hash.Bytes()}, o)
		require.NoError(t, e)
		require.Equal(t, b.Hash.Bytes(), r.Input.ParentHash)
		bad := f.snapshot(t, 0)
		_, e = DeriveV2(ContextV2{Genesis: f.origin, Parent: bad, Round: 2, ParentHash: f.blocks[0].Hash.Bytes()}, o)
		require.ErrorIs(t, e, ErrV2Ancestry)
		repeat, _ := f.signed(t, ir, 3, 6)
		_, e = DeriveV2(ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 1), Round: 3, ParentHash: b.Hash.Bytes()}, repeat)
		require.NoError(t, e, "the exact first-certified statement may receive a later assignment")
		_, e = DeriveV2(ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 2), Round: 3, ParentHash: f.blocks[2].Hash.Bytes()}, repeat)
		require.ErrorIs(t, e, ErrV2Ancestry, "a valid but unchosen witness cannot replace B1")
		wrongParent := f.blocks[0]
		wrongParent.Hash = common.HexToHash("0xdead")
		wrongChild := f.c.Executed(wrongParent, 1, 5)
		wrongIR := &types.InputRecord{Version: 1, RoundNumber: 1, Hash: wrongChild.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 9, BlockHash: wrongChild.Hash.Bytes()}
		wrongObs, _ := f.signed(t, wrongIR, 2, 5)
		wrongSnapshot, err := registryproof.Verify(f.origin.ProofContext(), wrongChild.Hash, wrongChild.Evidence)
		require.NoError(t, err)
		_, e = DeriveV2(ContextV2{Genesis: f.origin, Parent: wrongSnapshot, Round: 2, ParentHash: wrongChild.Hash.Bytes()}, wrongObs)
		require.ErrorIs(t, e, ErrV2Ancestry, "a matching B1 subject with a non-B0 decoded predecessor is refused")
		stale, _ := f.signed(t, ir, 3, 4)
		_, e = DeriveV2(ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 1), Round: 3, ParentHash: b.Hash.Bytes()}, stale)
		require.ErrorIs(t, e, ErrNotPinned, "origin root round must not trail the committed cursor")
	})
	t.Run("ordinary block and quiet", func(t *testing.T) {
		b := f.blocks[2]
		ir := &types.InputRecord{Version: 1, RoundNumber: 2, PreviousHash: f.blocks[1].StateRoot.Bytes(), Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 10, BlockHash: b.Hash.Bytes()}
		o, _ := f.signed(t, ir, 3, 6)
		_, e := DeriveV2(ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 2), Round: 3, ParentHash: b.Hash.Bytes()}, o)
		require.NoError(t, e)
		q := &types.InputRecord{Version: 1, RoundNumber: 3, PreviousHash: b.StateRoot.Bytes(), Hash: b.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 11}
		qo, _ := f.signed(t, q, 4, 7)
		_, e = DeriveV2(ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 2), Round: 4, ParentHash: b.Hash.Bytes()}, qo)
		require.NoError(t, e)
	})
}

func TestV2DerivationBindsSingleInstalledTransition(t *testing.T) {
	f := newV2Fixture(t)
	o, _ := f.signed(t, &types.InputRecord{Version: 1}, 7, 4)
	// DeriveV2 receives an already authenticated successor observation.
	o.rootEpoch, o.origin.RootEpoch = 2, 2
	var tr handoff.EVMTransition
	tr.OldEpoch, tr.NewEpoch = 1, 2
	tr.NextBodyID, tr.GenesisID = [32]byte{1}, [32]byte{2}
	tr.Ack.FrozenID, tr.Ack.CommitID = [32]byte{3}, [32]byte{4}
	copy(tr.Ack.FrozenParent[:], f.blocks[0].Hash.Bytes())
	tr.Ack.SuccessorParent = tr.Ack.FrozenParent
	tr.Ack.SuccessorTR, tr.Ack.EVMRound = [32]byte{5}, 7
	encoded, err := tr.Encode()
	require.NoError(t, err)
	c := ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 0), Round: 7,
		ParentHash: f.blocks[0].Hash.Bytes(), TransitionsPending: true, Transition: encoded}
	result, err := DeriveV2(c, o)
	require.NoError(t, err)
	require.Equal(t, [][]byte{encoded}, result.Input.Transitions)
	require.Equal(t, result.Input.ExtraData(), result.Commitment)
	c.Transition = nil
	_, err = DeriveV2(c, o)
	require.ErrorIs(t, err, ErrUnsupported)
	c.Transition = encoded
	c.TransitionsPending = false
	_, err = DeriveV2(c, o)
	require.ErrorIs(t, err, ErrUnsupported)
	c.TransitionsPending = true
	tr.Ack.FrozenParent[0] ^= 1
	tr.Ack.SuccessorParent = tr.Ack.FrozenParent
	c.Transition, err = tr.Encode()
	require.NoError(t, err)
	_, err = DeriveV2(c, o)
	require.ErrorIs(t, err, ErrV2Context)
}

func TestV2AcknowledgementRebindsAfterT2Timeout(t *testing.T) {
	f := newV2Fixture(t)
	assigned := uint64(8) // initial successor assignment was 7; T2 advanced it
	technical := certifiedchain.Technical(assigned - 1)
	technical.Round = assigned
	uc := f.signedRaw(t, &types.InputRecord{Version: 1}, technical, 5)
	uc.UnicitySeal.Epoch = 2
	uc.UnicitySeal.Signatures = nil
	verifier, err := f.c.Signer.Verifier()
	require.NoError(t, err)
	key, err := verifier.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(key)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), f.c.Signer))
	newBase := *f.c.TrustBase
	newBase.Epoch = 2
	newBase.Signatures = nil
	observationContext := f.obsContext()
	observationContext.RootEpoch = 2
	observationContext.TrustBases = stubTrustBases{tb: &newBase}
	o, err := AuthenticateObservationV2(context.Background(), observationContext, uc, technical)
	require.NoError(t, err)

	template := handoff.EVMTransition{OldEpoch: 1, NewEpoch: 2, NextBodyID: [32]byte{1}, GenesisID: [32]byte{2},
		Ack: handoff.AckRecord{FrozenID: [32]byte{3}, CommitID: [32]byte{4},
			SuccessorTR: [32]byte{5}, EVMRound: assigned - 1}}
	copy(template.Ack.FrozenParent[:], f.blocks[0].Hash.Bytes())
	template.Ack.SuccessorParent = template.Ack.FrozenParent
	templateBytes, err := template.Encode()
	require.NoError(t, err)
	c := ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 0), Round: assigned,
		ParentHash: f.blocks[0].Hash.Bytes(), TransitionsPending: true, Transition: templateBytes}
	r, err := DeriveV2(c, o)
	require.NoError(t, err)
	require.Len(t, r.Input.Transitions, 1)
	bound, err := handoff.DecodeEVMTransition(r.Input.Transitions[0])
	require.NoError(t, err)
	require.Equal(t, assigned, bound.Ack.EVMRound)
	template.Ack.EVMRound = assigned
	require.Equal(t, template, bound, "only the actual authenticated shard round changes")
	require.NotEqual(t, templateBytes, r.Input.Transitions[0])

	// Once the acknowledgement was applied, the parent is no longer pending.
	c.TransitionsPending = false
	_, err = DeriveV2(c, o)
	require.ErrorIs(t, err, ErrUnsupported, "a second acknowledgement is refused")
}

func TestV2AuthenticationRefusalsAreOnTheNewPath(t *testing.T) {
	f := newV2Fixture(t)
	ir := &types.InputRecord{Version: 1}
	tr := certifiedchain.Technical(0)
	tr.Round = 1
	uc := f.signedRaw(t, ir, tr, 4)

	t.Run("mismatched technical record", func(t *testing.T) {
		other := *tr
		other.Round = 2
		_, err := AuthenticateObservationV2(context.Background(), f.obsContext(), uc, &other)
		require.ErrorIs(t, err, ErrUnauthenticated)
	})
	t.Run("wrong configured network", func(t *testing.T) {
		c := f.obsContext()
		c.NetworkID = 4
		_, err := AuthenticateObservationV2(context.Background(), c, uc, tr)
		require.ErrorIs(t, err, ErrWrongContext)
	})
	t.Run("wrong pinned root epoch", func(t *testing.T) {
		c := f.obsContext()
		c.RootEpoch = 2
		_, err := AuthenticateObservationV2(context.Background(), c, uc, tr)
		require.ErrorIs(t, err, ErrV2Context)
	})
	t.Run("foreign signing key", func(t *testing.T) {
		foreignSigner, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		foreignUC := f.c.Certify(foreignSigner, ir, tr, 4)
		foreignUC.UnicitySeal.NetworkID = 3
		foreignUC.UnicitySeal.Signatures = nil
		v, err := foreignSigner.Verifier()
		require.NoError(t, err)
		pk, err := v.MarshalPublicKey()
		require.NoError(t, err)
		id, err := network.NodeIDFromPublicKeyBytes(pk)
		require.NoError(t, err)
		require.NoError(t, foreignUC.UnicitySeal.Sign(id.String(), foreignSigner))
		_, err = AuthenticateObservationV2(context.Background(), f.obsContext(), foreignUC, tr)
		require.ErrorIs(t, err, ErrUnauthenticated)
	})
	obs, _ := f.signed(t, ir, 1, 4)
	_, err := DeriveV2(ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 0), Round: 2, ParentHash: f.blocks[0].Hash.Bytes()}, obs)
	require.ErrorIs(t, err, ErrNotPinned, "the caller-pinned assigned round must match authenticated TR")
}

func TestV2QuorumSubsetAuthenticationAndContextRefusals(t *testing.T) {
	f := newV2Fixture(t)
	// Build a root trust base independently of the one-member certified EVM fixture so
	// signature-subset behavior is exercised by the v2 authentication path.
	var signers []abcrypto.Signer
	var ids []string
	for i := 0; i < 4; i++ {
		s, err := abcrypto.NewInMemorySecp256K1Signer()
		require.NoError(t, err)
		v, err := s.Verifier()
		require.NoError(t, err)
		pk, err := v.MarshalPublicKey()
		require.NoError(t, err)
		id, err := network.NodeIDFromPublicKeyBytes(pk)
		require.NoError(t, err)
		signers, ids = append(signers, s), append(ids, id.String())
	}
	tb, ok := testtrustbase.NewTrustBase(t, signers...).(*types.RootTrustBaseV1)
	require.True(t, ok)
	c := f.obsContext()
	c.TrustBases = stubTrustBases{tb: tb}
	ir := &types.InputRecord{Version: 1}
	tr := certifiedchain.Technical(6)
	tr.Round = 7
	makeUC := func(indices ...int) *types.UnicityCertificate {
		uc := f.c.Certify(f.c.Signer, ir, tr, 4)
		uc.UnicitySeal.NetworkID = 3
		uc.UnicitySeal.Signatures = nil
		for _, i := range indices {
			require.NoError(t, uc.UnicitySeal.Sign(ids[i], signers[i]))
		}
		return uc
	}
	var want []byte
	for _, subset := range [][]int{{0, 1, 2}, {0, 1, 3}, {0, 2, 3}} {
		uc := makeUC(subset...)
		o, err := AuthenticateObservationV2(context.Background(), c, uc, tr)
		require.NoError(t, err, "valid quorum subset %v", subset)
		derived, err := DeriveV2(ContextV2{Genesis: f.origin, Parent: f.snapshot(t, 0), Round: 7, ParentHash: f.blocks[0].Hash.Bytes()}, o)
		require.NoError(t, err, "derive with valid quorum subset %v", subset)
		if want == nil {
			want = derived.Encoded
		} else {
			require.Equal(t, want, derived.Encoded, "canonical v2 bytes must not depend on the signer subset")
		}
	}
	_, err := AuthenticateObservationV2(context.Background(), c, makeUC(0, 1), tr)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.ErrorContains(t, err, "quorum not reached", "sub-quorum must be rejected")
	foreign, err := abcrypto.NewInMemorySecp256K1Signer()
	require.NoError(t, err)
	foreignUC := makeUC(0, 1)
	v, err := foreign.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	foreignID, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, foreignUC.UnicitySeal.Sign(foreignID.String(), foreign))
	_, err = AuthenticateObservationV2(context.Background(), c, foreignUC, tr)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.ErrorContains(t, err, "quorum not reached", "a non-member signer must be rejected")

	valid := makeUC(0, 1, 2)
	wrongPartition := c
	wrongPartition.PartitionID++
	_, err = AuthenticateObservationV2(context.Background(), wrongPartition, valid, tr)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.ErrorContains(t, err, "invalid partition identifier", "wrong partition must be rejected")
	wrongShard := c
	_, wrongShard.ShardID = c.ShardID.Split()
	_, err = AuthenticateObservationV2(context.Background(), wrongShard, valid, tr)
	require.ErrorIs(t, err, ErrUnauthenticated)
	require.ErrorContains(t, err, "invalid shard ID", "wrong shard must be rejected")
}

func TestV2UnsupportedClassifierRequiresDirectPostAuthenticationRefusal(t *testing.T) {
	f := newV2Fixture(t)
	ir := &types.InputRecord{Version: 1, SumOfEarnedFees: 1}
	tr := certifiedchain.Technical(0)
	tr.Round = 1
	uc := f.signedRaw(t, ir, tr, 4)
	_, err := AuthenticateObservationV2(context.Background(), f.obsContext(), uc, tr)
	require.True(t, IsUnsupportedObservationV2(err))
	require.ErrorIs(t, err, ErrV2Shape)

	c := f.obsContext()
	c.TrustBases = failingTrust{err: fmt.Errorf("provider: %w", ErrV2Shape)}
	_, err = AuthenticateObservationV2(context.Background(), c, uc, tr)
	require.False(t, IsUnsupportedObservationV2(err), "a callback-controlled sentinel is not authenticated evidence")
	require.ErrorIs(t, err, ErrV2Shape)
}

func TestV2ExactBootstrapAndOwnedObservation(t *testing.T) {
	f := newV2Fixture(t)
	for name, mut := range map[string]func(*types.InputRecord){"fees": func(ir *types.InputRecord) { ir.SumOfEarnedFees = 1 }, "summary": func(ir *types.InputRecord) { ir.SummaryValue = []byte{} }, "et hash": func(ir *types.InputRecord) { ir.ETHash = []byte{1} }} {
		t.Run(name, func(t *testing.T) {
			ir := &types.InputRecord{Version: 1}
			mut(ir)
			tr := certifiedchain.Technical(0)
			tr.Round = 1
			uc := f.signedRaw(t, ir, tr, 4)
			_, e := AuthenticateObservationV2(context.Background(), f.obsContext(), uc, tr)
			require.ErrorIs(t, e, ErrV2Shape)
		})
	}
	ir := &types.InputRecord{Version: 1}
	o, uc := f.signed(t, ir, 1, 4)
	before := o.OriginIdentity()
	uc.InputRecord.Hash = []byte{1}
	got := o.OriginIdentity()
	require.Equal(t, before, got)
	copyUC := o.Certificate()
	copyUC.InputRecord.BlockHash = []byte{2}
	require.Equal(t, before, o.OriginIdentity())
}

func TestV2AuthenticationCopiesInputsBeforeTrustCallback(t *testing.T) {
	f := newV2Fixture(t)
	ir := &types.InputRecord{Version: 1}
	tr := certifiedchain.Technical(0)
	tr.Round = 1
	uc := f.signedRaw(t, ir, tr, 4)
	c := f.obsContext()
	c.TrustBases = callbackTrust{tb: f.c.TrustBase, callback: func() {
		uc.InputRecord.Hash = []byte{1}
		tr.Round = 99
		c.ShardConfHash[0] ^= 0xff
	}}
	o, err := AuthenticateObservationV2(context.Background(), c, uc, tr)
	require.NoError(t, err)
	require.Equal(t, evmroot.OriginBootstrapV2, o.Class())
	require.Equal(t, uint64(1), o.TechnicalRecord().Round)
	require.Nil(t, o.Certificate().InputRecord.Hash)
}

func (f *v2Fixture) signedRaw(t *testing.T, ir *types.InputRecord, tr *certification.TechnicalRecord, root uint64) *types.UnicityCertificate {
	uc := f.c.Certify(f.c.Signer, ir, tr, root)
	uc.UnicitySeal.NetworkID = 3
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

func TestV2RejectsAlternateVerifiedProofContext(t *testing.T) {
	f := newV2Fixture(t)
	pc := f.origin.ProofContext()
	alternate := pc
	alternate.RegistryCodeHash = common.HexToHash("0x1234")
	f.c.Pins.RegistryCodeHash = alternate.RegistryCodeHash
	altBlock := f.c.Executed(f.blocks[0], 1, 5)
	ir := &types.InputRecord{Version: 1, RoundNumber: 1, Hash: altBlock.StateRoot.Bytes(), SummaryValue: []byte{}, Timestamp: 9, BlockHash: altBlock.Hash.Bytes()}
	o, _ := f.signed(t, ir, 2, 5)
	// The alternate account and proof genuinely verify with identical registry storage under another
	// code pin. Matching storage words therefore cannot substitute for exact proof-context identity.
	s, e := registryproof.Verify(alternate, altBlock.Hash, altBlock.Evidence)
	require.NoError(t, e)
	_, e = DeriveV2(ContextV2{Genesis: f.origin, Parent: s, Round: 2, ParentHash: altBlock.Hash.Bytes()}, o)
	require.ErrorIs(t, e, ErrV2Context)
}

func TestV2RefusesEmptyOptionalSignedBytes(t *testing.T) {
	o := evmroot.RootOriginV2{NetworkID: 3, RootRound: 1, RootEpoch: 1, UnicityTreeRoot: bytes.Repeat([]byte{1}, 32), InputVersion: 1, TRHash: bytes.Repeat([]byte{2}, 32), ShardConfHash: bytes.Repeat([]byte{3}, 32)}
	o.IR.Hash = []byte{}
	_, e := o.Class()
	require.Error(t, e)
}
