package engineapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/handoff"
	"github.com/unicitynetwork/bft-core/shardnode"
)

var pairTestGenesis = [32]byte{0x52, 31: 0x52}

func pairTestConfig(verifierGenesis [32]byte) *PairConfig {
	return &PairConfig{Pins: PairPins{NetworkID: 3, RootGenesisID: [32]byte{0x51, 31: 0x51}}, ExecutionGenesis: verifierGenesis}
}

func pairSealConfigHandler(network uint64, root [32]byte) func(json.RawMessage) (any, *rpcError) {
	return func(json.RawMessage) (any, *rpcError) {
		n, r := network, data32(root)
		return struct {
			Version      uint64  `json:"version"`
			MaxGas       uint64  `json:"maxGas"`
			FeeCollector string  `json:"feeCollector"`
			NetworkID    *uint64 `json:"networkId"`
			RootGenesis  *data32 `json:"rootGenesisId"`
		}{Version: 1, MaxGas: 30_000_000, NetworkID: &n, RootGenesis: &r}, nil
	}
}

// The build and the import each carry the binding this node's own derivation produced: the build names the attributes digest, the import the
// block hash, and both name the parent, the origin, the configuration and the committed root input.
func TestAdapterSendsItsOwnPairBindingOnBuildAndImport(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	cfg := pairTestConfig(verifier.GenesisOrigin.BlockHash())
	engine.on("engine_sealConfigV1", pairSealConfigHandler(3, cfg.Pins.RootGenesisID))
	var buildRaw, importRaw json.RawMessage
	var captured SealBuildInput
	var attrs UnicityPayloadAttributes
	pid := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		require.NoError(t, json.Unmarshal(args[1], &attrs))
		buildRaw = args[2]
		require.NoError(t, json.Unmarshal(args[2], &captured))
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &pid}, nil
	})
	engine.on("engine_newPayloadWithSealV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		importRaw = args[3]
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash())}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	a.pair = cfg
	_, err := a.Build(context.Background(), params)
	require.NoError(t, err)

	var wire struct {
		PairBinding data `json:"pairBinding"`
	}
	require.NoError(t, json.Unmarshal(buildRaw, &wire))
	build, err := DecodePairBinding(wire.PairBinding)
	require.NoError(t, err)
	var recipient [20]byte = attrs.SuggestedFeeRecipient
	digest, err := AttributesDigest(uint64(attrs.Timestamp), attrs.PrevRandao, recipient, attrs.ParentBeaconBlockRoot)
	require.NoError(t, err)
	var conf [32]byte
	copy(conf[:], want.Input.Origin.ShardConfHash)
	empty, err := TransitionsHash(nil)
	require.NoError(t, err)
	require.Equal(t, PairBinding{NetworkID: 3, RootGenesisID: cfg.Pins.RootGenesisID, ExecutionGenesisHash: cfg.ExecutionGenesis,
		ParentHash: [32]byte(verifier.GenesisOrigin.BlockHash()), ParentNumber: 0, OriginRootEpoch: want.Input.Origin.RootEpoch,
		OriginRootRound: want.Input.Origin.RootRound, ConfigurationID: conf, ActivationID: build.ActivationID,
		RootInputHash: want.Commitment, TransitionsHash: empty, Kind: PairBuild, SubjectID: digest}, build)
	require.NotEqual(t, [32]byte{}, build.ActivationID, "no transition: a non-zero identity is still carried")

	// the import: a follower derives its own binding for the exact block it hands the client
	attrs2 := DeriveAttributesV2(want.Input, ParentHeader{}, a.feeCollector)
	payload := samplePayload()
	payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
	payload.BlockNumber = 1
	payload.Timestamp, payload.PrevRandao, payload.FeeRecipient = attrs2.Timestamp, attrs2.PrevRandao, attrs2.SuggestedFeeRecipient
	payload.ExtraData, payload.Withdrawals = want.Commitment[:], attrs2.Withdrawals
	witnesses, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.NoError(t, err)
	block, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: witnesses, Provenance: "build"})
	require.NoError(t, err)
	status, err := a.Verify(context.Background(), block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
	var iw struct {
		PairBinding data `json:"pairBinding"`
	}
	require.NoError(t, json.Unmarshal(importRaw, &iw))
	imported, err := DecodePairBinding(iw.PairBinding)
	require.NoError(t, err)
	expected := build
	expected.Kind, expected.SubjectID = PairImport, [32]byte(payload.BlockHash)
	require.Equal(t, expected, imported, "the import differs from the build only in its subject")
}

func TestAdapterWithoutPairConfigSendsNoBinding(t *testing.T) {
	verifier, params, _ := bootstrapAdapterFixture(t)
	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	var raw json.RawMessage
	pid := data{1, 2, 3, 4, 5, 6, 7, 8}
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(r json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(r, &args))
		raw = args[2]
		return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &pid}, nil
	})
	eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
		return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash())}, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	_, err := a.Build(context.Background(), params)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "pairBinding")
}

// A build with the binding enabled is refused, before any forkchoice call, when the client's reported pins are not this node's own.
func TestAdapterRefusesToBuildOnAnotherNetworkOrRootGenesis(t *testing.T) {
	for name, tc := range map[string]struct {
		network uint64
		root    [32]byte
	}{
		"network":      {4, [32]byte{0x51, 31: 0x51}},
		"root genesis": {3, [32]byte{0x50, 31: 0x51}},
	} {
		verifier, params, _ := bootstrapAdapterFixture(t)
		engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
		engine.on("engine_sealConfigV1", pairSealConfigHandler(tc.network, tc.root))
		calls := 0
		engine.on("engine_forkchoiceUpdatedWithSealV1", func(json.RawMessage) (any, *rpcError) { calls++; return nil, nil })
		eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
			return blockHeaderJSON{Number: 0, Hash: data32(verifier.GenesisOrigin.BlockHash())}, nil
		})
		a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
		a.pair = pairTestConfig(verifier.GenesisOrigin.BlockHash())
		_, err := a.Build(context.Background(), params)
		closeFn()
		require.ErrorIs(t, err, ErrPairPins, name)
		require.Zero(t, calls, name)
	}
}

// With a transition in the input, the binding names the acknowledged transition's commit id.
func TestPairBindingNamesTheAcknowledgedTransition(t *testing.T) {
	verifier, params, derived := bootstrapAdapterFixture(t)
	transition := handoff.EVMTransition{OldRootEpoch: 1, NewRootEpoch: 2, OldActiveConfHash: [32]byte{9}, NewActiveConfHash: [32]byte{9}, NextBodyID: [32]byte{1}, GenesisID: [32]byte{2},
		Ack: handoff.AckRecord{FrozenID: [32]byte{3}, CommitID: [32]byte{4}, FrozenParent: [32]byte{5}, SuccessorParent: [32]byte{5}, SuccessorTR: [32]byte{6}, EVMRound: params.Round}}
	encoded, err := transition.Encode()
	require.NoError(t, err)
	derived.Input.Transitions = [][]byte{encoded}
	derived.Encoded, derived.Commitment = derived.Input.Encode(), derived.Input.ExtraData()
	cfg := pairTestConfig(verifier.GenesisOrigin.BlockHash())
	cfg.ActivationID = func(uint64) ([32]byte, bool) { return [32]byte{0xEE}, true }
	b, err := cfg.newPairBinding(derived, pairParent{Hash: [32]byte{1}, Number: 7}, PairImport, [32]byte{2})
	require.NoError(t, err)
	require.Equal(t, [32]byte{4}, b.ActivationID, "the transition's commit id wins over the history hook")
	th, err := TransitionsHash([][]byte{encoded})
	require.NoError(t, err)
	require.Equal(t, th, b.TransitionsHash)

	derived.Input.Transitions = nil
	derived.Encoded, derived.Commitment = derived.Input.Encode(), derived.Input.ExtraData()
	b, err = cfg.newPairBinding(derived, pairParent{Hash: [32]byte{1}, Number: 7}, PairImport, [32]byte{2})
	require.NoError(t, err)
	require.Equal(t, [32]byte{0xEE}, b.ActivationID, "no transition: the verified activation of the origin epoch")

	// a zero subject or parent is refused rather than sent
	_, err = cfg.newPairBinding(derived, pairParent{Number: 7}, PairImport, [32]byte{2})
	require.ErrorIs(t, err, ErrPairBinding)
	_, err = cfg.newPairBinding(derived, pairParent{Hash: [32]byte{1}}, PairImport, [32]byte{})
	require.ErrorIs(t, err, ErrPairBinding)
}

// Recovery admission presents this node's own import binding of the head, after the pins check, and surfaces the client's refusal.
func TestAdapterPresentsItsOwnBindingForRecoveryAdmission(t *testing.T) {
	verifier, _, want := bootstrapAdapterFixture(t)
	cfg := pairTestConfig(verifier.GenesisOrigin.BlockHash())
	head := [32]byte{0x63, 31: 0x63}
	parent := [32]byte(verifier.GenesisOrigin.BlockHash())

	engine, eth := newMockReth(t, Secret{}), newMockReth(t, Secret{})
	engine.on("engine_sealConfigV1", pairSealConfigHandler(3, cfg.Pins.RootGenesisID))
	var presented json.RawMessage
	var refuse bool
	engine.on("engine_admitParentV1", func(raw json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(raw, &args))
		require.Len(t, args, 1)
		presented = args[0]
		if refuse {
			return nil, &rpcError{Code: -39002, Message: "recovery admission refused: presented binding refused at 1: pair binding refused: ParentHashMismatch"}
		}
		return nil, nil
	})
	a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
	defer closeFn()
	a.pair = cfg

	require.NoError(t, a.AdmitRecoveredHead(context.Background(), want, parent, 0, head))
	var hexed data
	require.NoError(t, json.Unmarshal(presented, &hexed))
	b, err := DecodePairBinding(hexed)
	require.NoError(t, err)
	require.Equal(t, PairImport, b.Kind)
	require.Equal(t, head, b.SubjectID)
	require.Equal(t, parent, b.ParentHash)
	require.Equal(t, [32]byte(want.Commitment), b.RootInputHash)

	refuse = true
	err = a.AdmitRecoveredHead(context.Background(), want, parent, 0, head)
	require.ErrorContains(t, err, "recovery admission refused")
	require.ErrorContains(t, err, "ParentHashMismatch", "the client's typed cause reaches the caller")

	// no binding configured: nothing is sent
	a.pair = nil
	presented = nil
	require.ErrorIs(t, a.AdmitRecoveredHead(context.Background(), want, parent, 0, head), ErrPairBinding)
	require.Nil(t, presented)
}

// The node's restart admission: the head's authorizing certificate retained with the companion is authenticated again, the root input is
// derived from it, and the client's retained root input must be that derivation. Only then is the binding presented.
func TestRestartAdmissionPresentsTheNodesOwnDerivationOfTheHead(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	cfg := pairTestConfig(verifier.GenesisOrigin.BlockHash())
	genesis := verifier.GenesisOrigin.BlockHash()
	head := hexw(word(0x11))
	witnesses, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.NoError(t, err)
	hexed := make([]string, len(witnesses))
	for i, w := range witnesses {
		hexed[i] = "0x" + hexString(w)
	}

	setup := func(mutate func(rootInput *[]byte, witnesses *[]string, number *string)) (*Adapter, func(), *json.RawMessage, *int) {
		eth, engine := newMockReth(t, Secret{}), newMockReth(t, Secret{})
		rootInput, ws, number := append([]byte(nil), want.Encoded...), append([]string(nil), hexed...), "0x1"
		if mutate != nil {
			mutate(&rootInput, &ws, &number)
		}
		eth.on("eth_getBlockByNumber", func(json.RawMessage) (any, *rpcError) {
			return map[string]any{"number": number, "hash": head, "parentHash": hexw([32]byte(genesis)), "stateRoot": hexw(word(0x55))}, nil
		})
		eth.on("eth_getBlockByHash", func(json.RawMessage) (any, *rpcError) {
			return map[string]any{"number": "0x0", "hash": hexw([32]byte(genesis)), "parentHash": hexw(word(0)), "stateRoot": hexw([32]byte(verifier.GenesisOrigin.StateRoot()))}, nil
		})
		eth.on("unicity_getSealCompanionV1", func(json.RawMessage) (any, *rpcError) {
			return map[string]any{"status": "found", "companion": map[string]any{"rootInput": "0x" + hexString(rootInput), "pairBinding": "0x00", "witnesses": ws, "provenance": "build"}}, nil
		})
		engine.on("engine_sealConfigV1", pairSealConfigHandler(3, cfg.Pins.RootGenesisID))
		var presented json.RawMessage
		calls := 0
		engine.on("engine_admitParentV1", func(r json.RawMessage) (any, *rpcError) {
			calls++
			var args []json.RawMessage
			require.NoError(t, json.Unmarshal(r, &args))
			presented = args[0]
			return nil, nil
		})
		a, closeFn := newTestAdapterWithVerifier(t, engine, eth, verifier)
		a.pair = cfg
		return a, closeFn, &presented, &calls
	}

	a, closeFn, presented, calls := setup(nil)
	defer closeFn()
	require.NoError(t, a.AdmitHead(context.Background()))
	require.Equal(t, 1, *calls)
	var raw data
	require.NoError(t, json.Unmarshal(*presented, &raw))
	b, err := DecodePairBinding(raw)
	require.NoError(t, err)
	require.Equal(t, PairImport, b.Kind)
	require.Equal(t, word(0x11), b.SubjectID, "the head block")
	require.Equal(t, [32]byte(genesis), b.ParentHash)
	require.EqualValues(t, 0, b.ParentNumber)
	require.Equal(t, [32]byte(want.Commitment), b.RootInputHash, "the node's own derivation, not a hash the client reported")

	refused := func(name string, cause error, mutate func(*[]byte, *[]string, *string)) {
		t.Helper()
		a, closeFn, _, calls := setup(mutate)
		defer closeFn()
		err := a.AdmitHead(context.Background())
		require.ErrorIs(t, err, cause, name)
		require.Zero(t, *calls, "%s: nothing is presented", name)
	}
	refused("a retained root input that is not the derivation", ErrAdmissionInput, func(ri *[]byte, _ *[]string, _ *string) { (*ri)[len(*ri)-1] ^= 1 })
	refused("witnesses that are not [certificate, technical record]", ErrCompanionWitnesses, func(_ *[]byte, ws *[]string, _ *string) { *ws = (*ws)[:1] })

	// a client with nothing beyond genesis has nothing to admit
	a, closeFn2, _, calls := setup(func(_ *[]byte, _ *[]string, number *string) { *number = "0x0" })
	defer closeFn2()
	require.NoError(t, a.AdmitHead(context.Background()))
	require.Zero(t, *calls)

	// the node has no pair binding configured, or no verifier: it re-derives nothing
	a.pair = nil
	require.ErrorIs(t, a.AdmitHead(context.Background()), ErrPairBinding)
	a.pair = cfg
	a.verifier = nil
	require.Error(t, a.AdmitHead(context.Background()))
}

func word(b byte) [32]byte { return [32]byte{0: b, 31: b} }

func hexw(b [32]byte) string { return "0x" + hexString(b[:]) }

func hexString(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return string(out)
}
