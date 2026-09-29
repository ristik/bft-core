package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/evmroot"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/handoffdelivery"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/network/protocol/abdrc"
	"github.com/unicitynetwork/bft-core/network/protocol/certification"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/rootinput"
	"github.com/unicitynetwork/bft-core/shardnode"
	"github.com/unicitynetwork/bft-go-base/types"
)

func TestAdapterRequiresCanonicalTransitionFromConfiguredEpoch(t *testing.T) {
	verifier, params, _ := bootstrapAdapterFixture(t)
	a, closeFn := newTestAdapterWithVerifier(t, newMockReth(t, Secret{}), newMockReth(t, Secret{}), verifier)
	defer closeFn()
	verifier.Transition = []byte{0x80}
	_, err := a.deriveV2(context.Background(), params, params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.ErrorIs(t, err, rootinput.ErrV2Context)
	tx := handoff.EVMTransition{OldEpoch: 2, NewEpoch: 3, NextBodyID: [32]byte{1}, GenesisID: [32]byte{2},
		Ack: handoff.AckRecord{FrozenID: [32]byte{3}, CommitID: [32]byte{4}, FrozenParent: [32]byte{5},
			SuccessorParent: [32]byte{5}, SuccessorTR: [32]byte{6}, EVMRound: 1}}
	verifier.Transition, err = tx.Encode()
	require.NoError(t, err)
	_, err = a.deriveV2(context.Background(), params, params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.ErrorIs(t, err, rootinput.ErrV2Context)
	tx.OldEpoch, tx.NewEpoch = 1, 2
	verifier.Transition, err = tx.Encode()
	require.NoError(t, err)
	_, err = a.deriveV2(context.Background(), params, params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.True(t, rootinput.IsUnsupportedObservationV2(err), "valid installed transition reaches certificate authentication: %v", err)
}

func TestAdapterInstallsConsecutiveTransitions(t *testing.T) {
	a := NewAdapter(Config{Verifier: &VerifierContext{RootEpoch: 1}}, nil)
	makeTransition := func(old uint64, marker byte) []byte {
		t.Helper()
		tx := handoff.EVMTransition{OldEpoch: old, NewEpoch: old + 1,
			NextBodyID: [32]byte{marker}, GenesisID: [32]byte{marker + 1},
			Ack: handoff.AckRecord{FrozenID: [32]byte{marker + 2}, CommitID: [32]byte{marker + 3},
				FrozenParent: [32]byte{marker + 4}, SuccessorParent: [32]byte{marker + 4},
				SuccessorTR: [32]byte{marker + 5}, EVMRound: 1}}
		raw, err := tx.Encode()
		require.NoError(t, err)
		return raw
	}
	first, second := makeTransition(1, 1), makeTransition(2, 9)
	require.ErrorIs(t, a.InstallEpochTransition(second), rootinput.ErrV2Context)
	require.NoError(t, a.InstallEpochTransition(first))
	require.NoError(t, a.InstallEpochTransition(first))
	require.ErrorIs(t, a.InstallEpochTransition(makeTransition(1, 20)), rootinput.ErrV2Context)
	require.NoError(t, a.InstallEpochTransition(second))
	require.NoError(t, a.InstallEpochTransition(second))
	_, err := a.deriveV2(context.Background(), shardnode.RoundParams{}, nil, nil)
	require.ErrorIs(t, err, rootinput.ErrContextIncomplete,
		"a dynamically installed second transition reaches observation authentication")
	require.ErrorIs(t, a.InstallEpochTransition(first), rootinput.ErrV2Context)
}

func TestAdapterSelectsEachInstalledHandoffTransition(t *testing.T) {
	v := &VerifierContext{transitions: make(map[uint64]handoff.EVMTransition)}
	for old := uint64(1); old <= 2; old++ {
		tx := handoff.EVMTransition{OldEpoch: old, NewEpoch: old + 1, NextBodyID: [32]byte{1}, GenesisID: [32]byte{2},
			Ack: handoff.AckRecord{FrozenID: [32]byte{3}, CommitID: [32]byte{4}, FrozenParent: [32]byte{5},
				SuccessorParent: [32]byte{5}, SuccessorTR: [32]byte{6}, EVMRound: 1}}
		v.transitions[old] = tx
	}
	for old := uint64(1); old <= 2; old++ {
		raw, err := v.transitionFor(old, old+1)
		require.NoError(t, err)
		decoded, err := handoff.DecodeEVMTransition(raw)
		require.NoError(t, err)
		require.Equal(t, old, decoded.OldEpoch)
		require.Equal(t, old+1, decoded.NewEpoch)
	}
	_, err := v.transitionFor(1, 3)
	require.ErrorIs(t, err, rootinput.ErrV2Context)
}

type fixedEpochAuthority struct{}

func (fixedEpochAuthority) CurrentRootEpoch() (uint64, bool) { return 2, true }

func TestTransitionLookupFailsClosed(t *testing.T) {
	v := new(VerifierContext)
	_, err := v.transitionFor(1, 2)
	require.ErrorIs(t, err, rootinput.ErrV2Context, "missing installed transition")
	v.Transition = []byte{0x80}
	_, err = v.transitionFor(1, 2)
	require.ErrorIs(t, err, rootinput.ErrV2Context, "malformed legacy transition")
	tx := handoff.EVMTransition{OldEpoch: 2, NewEpoch: 3, NextBodyID: [32]byte{1}, GenesisID: [32]byte{2},
		Ack: handoff.AckRecord{FrozenID: [32]byte{3}, CommitID: [32]byte{4}, FrozenParent: [32]byte{5},
			SuccessorParent: [32]byte{5}, SuccessorTR: [32]byte{6}, EVMRound: 7}}
	v.Transition, err = tx.Encode()
	require.NoError(t, err)
	_, err = v.transitionFor(1, 3)
	require.ErrorIs(t, err, rootinput.ErrV2Context, "wrong predecessor epoch")
	_, err = v.transitionFor(2, 4)
	require.ErrorIs(t, err, rootinput.ErrV2Context, "wrong successor epoch")
	_, err = v.transitionFor(2, 3)
	require.NoError(t, err)
	v.EpochAuthority = fixedEpochAuthority{}
	_, err = v.transitionFor(2, 3)
	require.ErrorIs(t, err, rootinput.ErrV2Context, "verified history cannot use a legacy transition")
}

func TestInstalledTransitionUsesCommittedSuccessorRound(t *testing.T) {
	tr := &certification.TechnicalRecord{Round: 41}
	hash, err := tr.Hash()
	require.NoError(t, err)
	bundle := handoffdelivery.Bundle{Body: evmroot.TrustBaseBodyV2{Epoch: 2}}
	bundle.Proof.Record.Epoch = 1
	bundle.Proof.Record.NextBodyID = bytes.Repeat([]byte{1}, 32)
	bundle.Proof.Record.FrozenID = bytes.Repeat([]byte{2}, 32)
	bundle.Proof.Record.SuccessorTRHash = hash
	bundle.Proof.Control.FrozenParent = bytes.Repeat([]byte{3}, 32)
	checked := handoffdelivery.Verified{Genesis: evmroot.EpochGenesis{Epoch: 2}, Shard: abdrc.ShardInfo{TR: tr}}
	v := new(VerifierContext)
	require.NoError(t, v.InstallHandoffTransition(bundle, checked))
	require.NoError(t, v.InstallHandoffTransition(bundle, checked), "reinstalling the same verified handoff is idempotent")
	raw, err := v.transitionFor(1, 2)
	require.NoError(t, err)
	transition, err := handoff.DecodeEVMTransition(raw)
	require.NoError(t, err)
	require.Equal(t, uint64(41), transition.Ack.EVMRound)
	checked.Shard.TR = &certification.TechnicalRecord{Round: 42}
	require.ErrorIs(t, v.InstallHandoffTransition(bundle, checked), handoff.ErrBoundary)
	checked.Shard.TR = tr
	bundle.Proof.Control.FrozenParent[0] ^= 1
	require.ErrorIs(t, v.InstallHandoffTransition(bundle, checked), handoff.ErrSuccessor)
}

func TestDeriveV2PropagatesMissingBoundaryTransition(t *testing.T) {
	verifier, params, _ := bootstrapAdapterFixture(t)
	c := certifiedchain.New(t, 3, 0)
	var doc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(c.Genesis.GenesisJSON(), &doc))
	var alloc map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc["alloc"], &alloc))
	for key := range alloc {
		if strings.EqualFold(strings.TrimPrefix(key, "0x"), strings.TrimPrefix(registryproof.RegistryAddress.Hex(), "0x")) {
			delete(alloc, key)
		}
	}
	doc["alloc"], _ = json.Marshal(alloc)
	source, err := json.Marshal(doc)
	require.NoError(t, err)
	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	pins := c.Pins
	pins.RootEpoch = 2
	prepared, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), pins, art, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	otherOrigin := prepared.Origin()
	verifier.BootstrapSnapshot, err = registryproof.Verify(otherOrigin.ProofContext(), otherOrigin.BlockHash(), otherOrigin.Evidence())
	require.NoError(t, err)
	a := NewAdapter(Config{Verifier: verifier}, nil)
	_, err = a.deriveV2(context.Background(), params, params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.ErrorIs(t, err, rootinput.ErrV2Context, "a mismatched verified parent requires its own installed transition")
}

func bootstrapAdapterFixture(t *testing.T) (*VerifierContext, shardnode.RoundParams, rootinput.ResultV2) {
	t.Helper()
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
	prepared, err := registrygenesis.PrepareGenesisJSON(certifiedchain.Config(3), c.Pins, art, source, registrygenesis.GenesisJSONLimits{})
	require.NoError(t, err)
	origin := prepared.Origin()
	snapshot, err := registryproof.Verify(origin.ProofContext(), origin.BlockHash(), origin.Evidence())
	require.NoError(t, err)
	tr := certifiedchain.Technical(0)
	tr.Round = 1
	uc := c.Certify(c.Signer, &types.InputRecord{Version: 1}, tr, 4)
	uc.UnicitySeal.NetworkID = 3
	uc.UnicitySeal.Signatures = nil
	v, err := c.Signer.Verifier()
	require.NoError(t, err)
	pk, err := v.MarshalPublicKey()
	require.NoError(t, err)
	id, err := network.NodeIDFromPublicKeyBytes(pk)
	require.NoError(t, err)
	require.NoError(t, uc.UnicitySeal.Sign(id.String(), c.Signer))
	verifier := &VerifierContext{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, ShardConfHash: origin.FullShardConfHash().Bytes(), RootEpoch: 1, TrustBases: fixtureTrustBases{tb: c.TrustBase}, Cursor: CursorNotActivated(), GenesisOrigin: origin, BootstrapSnapshot: snapshot}
	params := shardnode.RoundParams{Round: 1, Parent: shardnode.BlockRef{Number: 0, Hash: origin.BlockHash().Bytes(), StateRoot: origin.StateRoot().Bytes()}, AuthorizingCertificate: uc, AuthorizingTechnicalRecord: tr}
	observation, err := rootinput.AuthenticateObservationV2(context.Background(), rootinput.ObservationContextV2{NetworkID: verifier.NetworkID, PartitionID: verifier.PartitionID, ShardID: verifier.ShardID, ShardConfHash: verifier.ShardConfHash, RootEpoch: verifier.RootEpoch, TrustBases: verifier.TrustBases}, uc, tr)
	require.NoError(t, err)
	want, err := rootinput.DeriveV2(rootinput.ContextV2{Genesis: origin, Parent: snapshot, Round: params.Round, ParentHash: params.Parent.Hash}, observation)
	require.NoError(t, err)
	return verifier, params, want
}

func TestAdapterBuildDuplicateJobIsUnavailableNotBlockInvalid(t *testing.T) {
	verifier, params, _ := bootstrapAdapterFixture(t)
	engine := newMockReth(t, Secret{})
	eth := newMockReth(t, Secret{})
	message := "duplicate payload id"
	var requests [][]json.RawMessage
	payloadID := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		require.Len(t, args, 3)
		requests = append(requests, args)
		if len(requests) == 1 {
			return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
		}
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusInvalid, ValidationError: &message}}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	_, err := a.Build(context.Background(), params)
	require.NoError(t, err)
	// The second adapter has fresh process state and the same certified parent.
	restarted := NewAdapter(Config{EngineURL: a.engine.url, EthURL: a.eth.url, Secret: a.engine.secret, Verifier: verifier}, nil)
	_, err = restarted.Build(context.Background(), params)
	require.ErrorIs(t, err, shardnode.ErrBuildUnavailable)
	require.ErrorContains(t, err, message)
	require.Len(t, requests, 2)
	for i, label := range []string{"pre-restart", "post-restart"} {
		t.Logf("%s parent=%s attributes=%s sealInput=%s", label, requests[i][0], requests[i][1], requests[i][2])
	}
	require.Equal(t, string(requests[0][0]), string(requests[1][0]))
	require.Equal(t, string(requests[0][1]), string(requests[1][1]))
	require.Equal(t, string(requests[0][2]), string(requests[1][2]))
}

func TestAdapterV2BootstrapBuildSendsCanonicalInput(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine := newMockReth(t, Secret{})
	eth := newMockReth(t, Secret{})
	var captured SealBuildInput
	var attrs UnicityPayloadAttributes
	payloadID := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		require.Len(t, args, 3)
		require.NoError(t, json.Unmarshal(args[1], &attrs))
		require.NoError(t, json.Unmarshal(args[2], &captured))
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &payloadID}, nil
	})
	engine.on("engine_getPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		payload := samplePayload()
		payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
		payload.BlockNumber = 1
		payload.Timestamp = attrs.Timestamp
		payload.PrevRandao = attrs.PrevRandao
		payload.FeeRecipient = attrs.SuggestedFeeRecipient
		payload.ExtraData = want.Commitment[:]
		payload.Withdrawals = attrs.Withdrawals
		return GetPayloadWithSealV1Response{ExecutionPayload: payload, SealCompanion: SealCompanion{RootInput: want.Encoded, Provenance: "build"}}, nil
	})
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	engine.on("engine_forkchoiceUpdatedV3", func(json.RawMessage) (any, *rpcError) {
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	a.feeCollector = [20]byte{19: 0xad}
	id, err := a.Build(context.Background(), params)
	require.NoError(t, err)
	require.Empty(t, captured.Transitions, "the profile-off bootstrap sends an empty transition list")
	require.Equal(t, want.Input.Encode(), []byte(captured.RootInput))
	require.Equal(t, want.Encoded, []byte(captured.RootInput))
	require.Equal(t, data32(want.Commitment), attrs.Commitment)
	require.Equal(t, DeriveAttributesV2(want.Input, ParentHeader{}, a.feeCollector), attrs.PayloadAttributesV3)
	require.Equal(t, data20(a.feeCollector), attrs.SuggestedFeeRecipient)
	firstAttrs, firstInput := attrs, captured
	changed := params
	changed.Timestamp = params.Timestamp + 42
	changed.SealHash = fixedHashBytes(0x99)
	_, err = a.Build(context.Background(), changed)
	require.NoError(t, err)
	require.Equal(t, firstAttrs, attrs, "fabricable round scalars cannot change v2 execution attributes")
	require.Equal(t, firstInput, captured, "fabricable round scalars cannot change canonical root input")
	block, err := a.Seal(context.Background(), id)
	require.NoError(t, err)
	require.NotEmpty(t, block.Raw)
	status, err := a.Verify(context.Background(), block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
	status, err = a.Commit(context.Background(), block.Hash)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
}

func TestAdapterV2BuildSendsTransitionInEngineSealInput(t *testing.T) {
	verifier, params, derived := bootstrapAdapterFixture(t)
	transition := handoff.EVMTransition{OldEpoch: 1, NewEpoch: 2, NextBodyID: [32]byte{1}, GenesisID: [32]byte{2},
		Ack: handoff.AckRecord{FrozenID: [32]byte{3}, CommitID: [32]byte{4}, FrozenParent: [32]byte{5},
			SuccessorParent: [32]byte{5}, SuccessorTR: [32]byte{6}, EVMRound: params.Round}}
	encoded, err := transition.Encode()
	require.NoError(t, err)
	derived.Input.Transitions = [][]byte{encoded}
	derived.Encoded = derived.Input.Encode()
	derived.Commitment = derived.Input.ExtraData()

	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	var captured SealBuildInput
	pid := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		require.NoError(t, json.Unmarshal(args[2], &captured))
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &pid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	_, err = a.buildDerived(context.Background(), params, derived)
	require.NoError(t, err)
	require.Equal(t, []data{data(encoded)}, captured.Transitions)
}

func TestAdapterV2PostGenesisFailsClosed(t *testing.T) {
	verifier, params, _ := bootstrapAdapterFixture(t)
	params.Parent.Number = 1
	a := NewAdapter(Config{Verifier: verifier}, nil)
	_, err := a.Build(context.Background(), params)
	require.ErrorIs(t, err, ErrParentWitnessUnavailable)
}

func TestAdapterV2BootstrapVerifyBoundCompanion(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine := newMockReth(t, Secret{})
	eth := newMockReth(t, Secret{})
	sealCalls := 0
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		sealCalls++
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	attrs := DeriveAttributesV2(want.Input, ParentHeader{}, a.feeCollector)
	payload := samplePayload()
	payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
	payload.BlockNumber = 1
	payload.Timestamp = attrs.Timestamp
	payload.PrevRandao = attrs.PrevRandao
	payload.FeeRecipient = attrs.SuggestedFeeRecipient
	payload.ExtraData = want.Commitment[:]
	payload.Withdrawals = attrs.Withdrawals
	witnesses, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.NoError(t, err)
	companion := &SealCompanion{RootInput: want.Input.Encode(), Witnesses: witnesses, Provenance: "build"}
	block, err := EncodeBlockWithSealCompanion(payload, companion)
	require.NoError(t, err)
	status, err := a.Verify(context.Background(), block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
	require.Equal(t, 1, sealCalls)

	companion.RootInput[0] ^= 1
	bad, err := EncodeBlockWithSealCompanion(payload, companion)
	require.NoError(t, err)
	status, err = a.Verify(context.Background(), bad, params)
	require.ErrorIs(t, err, ErrCompanionBinding)
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Equal(t, 1, sealCalls)

	missing, err := EncodeBlockWithSealCompanion(payload, nil)
	require.NoError(t, err)
	status, err = a.Verify(context.Background(), missing, params)
	require.ErrorIs(t, err, ErrCompanionMissing)
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Equal(t, 1, sealCalls)

	companion.RootInput = want.Encoded
	companion.Witnesses = nil
	wrongWitnesses, err := EncodeBlockWithSealCompanion(payload, companion)
	require.NoError(t, err)
	status, err = a.Verify(context.Background(), wrongWitnesses, params)
	require.ErrorIs(t, err, ErrCompanionWitnesses)
	require.Equal(t, shardnode.StatusInvalid, status)
	require.Equal(t, 1, sealCalls)

	params.Parent.Number = 1
	status, err = a.Verify(context.Background(), block, params)
	require.ErrorIs(t, err, ErrParentWitnessUnavailable)
	require.Equal(t, shardnode.StatusSyncing, status)
	require.Equal(t, 1, sealCalls)
}

func TestAdapterV2MapsEnginePayloadStatuses(t *testing.T) {
	for _, tc := range []struct {
		engine PayloadStatus
		want   shardnode.Status
	}{
		{PayloadStatusValid, shardnode.StatusValid},
		{PayloadStatusSyncing, shardnode.StatusSyncing},
		{PayloadStatusAccepted, shardnode.StatusAccepted},
		{PayloadStatusInvalid, shardnode.StatusInvalid},
		{PayloadStatusInvalidBlockHash, shardnode.StatusInvalid},
	} {
		t.Run(string(tc.engine), func(t *testing.T) {
			verifier, params, want := bootstrapAdapterFixture(t)
			engine := newMockReth(t, Secret{})
			eth := newMockReth(t, Secret{})
			engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
				return PayloadStatusV1{Status: tc.engine}, nil
			})
			eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
				return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash()), Timestamp: 0}, nil
			})
			a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
			defer closeFn()
			attrs := DeriveAttributesV2(want.Input, ParentHeader{}, a.feeCollector)
			payload := samplePayload()
			payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
			payload.BlockNumber = 1
			payload.Timestamp = attrs.Timestamp
			payload.PrevRandao = attrs.PrevRandao
			payload.FeeRecipient = attrs.SuggestedFeeRecipient
			payload.ExtraData = want.Commitment[:]
			payload.Withdrawals = attrs.Withdrawals
			witnesses, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
			require.NoError(t, err)
			block, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: witnesses})
			require.NoError(t, err)
			status, err := a.Verify(context.Background(), block, params)
			require.NoError(t, err)
			require.Equal(t, tc.want, status)
		})
	}
}
