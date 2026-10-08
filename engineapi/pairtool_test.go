package engineapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-go-base/types"
)

func urlOf(t *testing.T, m *mockReth, auth bool) string {
	t.Helper()
	srv := m.server(auth)
	t.Cleanup(srv.Close)
	return srv.URL
}

// pairChain is the one block a pair retains: its header, its root input (with two transitions) and the binding its own Go side supplied.
type pairChain struct {
	header      map[string]any
	rootInput   []byte
	transitions [][]byte
	binding     PairBinding
}

func newPairChain(t *testing.T) pairChain {
	t.Helper()
	transitions := [][]byte{{0xa1, 0x01}, {0xb2}}
	rootInput, err := types.Cbor.Marshal(rootInputOf(transitions, true))
	require.NoError(t, err)
	th, err := TransitionsHash(transitions)
	require.NoError(t, err)
	block, parent := word(0x11), word(0x22)
	timestamp := uint64(100)
	var recipient [20]byte
	recipient[0] = 0x77
	digest, err := AttributesDigest(timestamp, word(0x33), recipient, word(0x44))
	require.NoError(t, err)
	return pairChain{
		header: map[string]any{"number": "0x5", "hash": hexw(block), "parentHash": hexw(parent), "stateRoot": hexw(word(0x55)), "mixHash": hexw(word(0x33)),
			"miner": "0x7700000000000000000000000000000000000000", "timestamp": "0x64", "extraData": hexw(word(0x66)), "parentBeaconBlockRoot": hexw(word(0x44)),
			"withdrawals": []any{}},
		rootInput: rootInput, transitions: transitions,
		binding: PairBinding{NetworkID: 3, RootGenesisID: word(0x01), ExecutionGenesisHash: word(0x02), ParentHash: parent, ParentNumber: 4, OriginRootEpoch: 1,
			OriginRootRound: 9, ConfigurationID: word(0x07), ActivationID: word(0x08), RootInputHash: sha256.Sum256(rootInput), TransitionsHash: th,
			Kind: PairBuild, SubjectID: digest},
	}
}

// the B1 update and the root-record import companion the retained block's build carried
var (
	pairB1Update = []byte{0xb1, 0x01}
	pairRecords  = []byte{0xec, 0x02, 0x03}
)

func (c pairChain) serve(t *testing.T, eth *mockReth) {
	t.Helper()
	enc, err := c.binding.Encode()
	require.NoError(t, err)
	eth.on("eth_getBlockByNumber", func(r json.RawMessage) (any, *rpcError) {
		var args []any
		_ = json.Unmarshal(r, &args)
		if len(args) > 0 && args[0] == "finalized" { // the block before the retained one is the finalized one: the retained block is an uncertified tip
			fin := map[string]any{}
			for k, v := range c.header {
				fin[k] = v
			}
			fin["number"] = "0x4"
			return fin, nil
		}
		return c.header, nil
	})
	eth.on("unicity_getSealCompanionV1", func(json.RawMessage) (any, *rpcError) {
		return map[string]any{"status": "found", "companion": map[string]any{"rootInput": "0x" + hexString(c.rootInput),
			"pairBinding": "0x" + hexString(enc), "witnesses": []any{}, "provenance": "build",
			"b1Update": "0x" + hexString(pairB1Update), "records": "0x" + hexString(pairRecords)}}, nil
	})
}

func TestExportReadsWhatThePairRetainedForABlock(t *testing.T) {
	c := newPairChain(t)
	eth := newMockReth(t, Secret{})
	c.serve(t, eth)
	got, err := ExportPairBlock(context.Background(), urlOf(t, eth, false), 0, true)
	require.NoError(t, err)
	require.EqualValues(t, 5, got.Number)
	require.Equal(t, word(0x11), got.Head)
	require.Equal(t, word(0x22), got.Parent)
	require.Equal(t, word(0x55), got.StateRoot)
	require.Equal(t, c.rootInput, got.RootInput)
	want, err := types.Cbor.Marshal([]any{c.transitions[0], c.transitions[1]})
	require.NoError(t, err)
	require.Equal(t, want, got.Transitions, "the canonical array the binding's transitions hash covers")
	require.Equal(t, c.binding.TransitionsHash, sha256.Sum256(got.Transitions))

	// no companion retained: a typed refusal, never an empty export
	eth.on("unicity_getSealCompanionV1", func(json.RawMessage) (any, *rpcError) {
		return map[string]any{"status": "unavailable", "horizon": 9}, nil
	})
	_, err = ExportPairBlock(context.Background(), urlOf(t, eth, false), 0, true)
	require.ErrorIs(t, err, ErrPairCompanion)
	eth.on("eth_getBlockByNumber", func(json.RawMessage) (any, *rpcError) { return nil, nil })
	_, err = ExportPairBlock(context.Background(), urlOf(t, eth, false), 9, false)
	require.Error(t, err)
}

func TestEachControlSubmitsTheRetainedBuildWithExactlyOneThingChanged(t *testing.T) {
	c := newPairChain(t)
	eth := newMockReth(t, Secret{})
	c.serve(t, eth)

	run := func(kind PairControl, accept bool) (ForkchoiceStateV1, UnicityPayloadAttributes, json.RawMessage, PairControlOutcome) {
		engine := newMockReth(t, Secret{})
		var state ForkchoiceStateV1
		var attrs UnicityPayloadAttributes
		var raw json.RawMessage
		pid := data{1, 2, 3, 4, 5, 6, 7, 8}
		engine.on("engine_forkchoiceUpdatedWithSealV1", func(r json.RawMessage) (any, *rpcError) {
			var args []json.RawMessage
			require.NoError(t, json.Unmarshal(r, &args))
			require.NoError(t, json.Unmarshal(args[0], &state))
			require.NoError(t, json.Unmarshal(args[1], &attrs))
			raw = args[2]
			// the execution client's schema (ureth#52 wire.rs): the binding field is required, and then each comparison has its own variant
			var wire struct {
				PairBinding *data `json:"pairBinding"`
				B1Update    data  `json:"b1Update"`
				Records     data  `json:"records"`
			}
			require.NoError(t, json.Unmarshal(args[2], &wire))
			// the rebuild carries what the retained build carried: the update and the root-record import its root input commits to
			require.Equal(t, data(pairB1Update), wire.B1Update)
			require.Equal(t, data(pairRecords), wire.Records)
			if wire.PairBinding == nil {
				return nil, &rpcError{Code: -32602, Message: "invalid params: missing field `pairBinding`"}
			}
			verdict := "Missing"
			if len(*wire.PairBinding) != 0 {
				got, err := DecodePairBinding(*wire.PairBinding)
				require.NoError(t, err)
				switch want := c.binding; {
				case got.ParentHash != want.ParentHash:
					verdict = "ParentHashMismatch"
				case got.SubjectID != want.SubjectID:
					verdict = "JobMismatch"
				case got.RootInputHash != want.RootInputHash:
					verdict = "RootInputMismatch"
				default:
					return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusValid}, PayloadID: &pid}, nil
				}
			}
			msg := "pair binding refused: " + verdict
			return ForkchoiceUpdatedResponse{PayloadStatus: PayloadStatusV1{Status: PayloadStatusInvalid, ValidationError: &msg}}, nil
		})
		out, err := RunPairControl(context.Background(), urlOf(t, engine, true), Secret{}, urlOf(t, eth, false), kind)
		require.NoError(t, err, kind)
		return state, attrs, raw, out
	}
	submitted := func(raw json.RawMessage) PairBinding {
		var w struct {
			PairBinding data `json:"pairBinding"`
		}
		require.NoError(t, json.Unmarshal(raw, &w))
		b, err := DecodePairBinding(w.PairBinding)
		require.NoError(t, err)
		return b
	}

	// the control: the build of this block on its parent, with its own binding
	state, attrs, raw, out := run(ControlAccept, true)
	require.True(t, out.Accepted)
	require.Equal(t, data32(word(0x22)), state.HeadBlockHash, "built on the block's parent")
	require.EqualValues(t, 100, uint64(attrs.Timestamp))
	require.Equal(t, data32(word(0x66)), attrs.Commitment)
	var sealInput struct {
		RootInput   data   `json:"rootInput"`
		Transitions []data `json:"transitions"`
	}
	require.NoError(t, json.Unmarshal(raw, &sealInput))
	require.Equal(t, c.rootInput, []byte(sealInput.RootInput))
	require.Len(t, sealInput.Transitions, 2)
	control := submitted(raw)
	require.Equal(t, c.binding, control, "the retained binding, unchanged")

	// each refusal differs from the control in exactly one field
	for kind, tc := range map[PairControl]struct {
		change  func(*PairBinding)
		variant string
	}{
		ControlWrongParent: {func(b *PairBinding) { b.ParentHash[0] ^= 0xff }, "ParentHashMismatch"},
		ControlWrongJob: {func(b *PairBinding) {
			b.SubjectID, _ = AttributesDigest(101, word(0x33), [20]byte{0: 0x77}, word(0x44))
		}, "JobMismatch"},
		ControlSubstitutedInput: {func(b *PairBinding) { b.RootInputHash[0] ^= 0xff }, "RootInputMismatch"},
	} {
		change := tc.change
		_, _, raw, out := run(kind, false)
		require.False(t, out.Accepted, kind)
		require.Contains(t, out.Detail, "pair binding refused: "+tc.variant, "%s is refused with its own typed variant", kind)
		want := control
		change(&want)
		require.Equal(t, want, submitted(raw), "%s changes only its own field", kind)
	}

	_, _, raw, out = run(ControlMissingEvidence, false)
	require.False(t, out.Accepted)
	require.Contains(t, out.Detail, "pair binding refused: Missing", "the client's own missing-evidence guard decided, not its parameter schema")
	require.Contains(t, string(raw), `"pairBinding":"0x"`, "no evidence is an explicit empty field inside the schema")

	_, err := RunPairControl(context.Background(), "http://127.0.0.1:1", Secret{}, urlOf(t, eth, false), PairControl("bogus"))
	require.Error(t, err)
}

func TestTheRestartAdmissionPresentsTheRetainedBindingAsAnImportOfTheHead(t *testing.T) {
	c := newPairChain(t)
	eth := newMockReth(t, Secret{})
	c.serve(t, eth)
	engine := newMockReth(t, Secret{})
	var presented json.RawMessage
	engine.on("engine_admitParentV1", func(r json.RawMessage) (any, *rpcError) {
		var args []json.RawMessage
		require.NoError(t, json.Unmarshal(r, &args))
		presented = args[0]
		return nil, nil
	})
	require.NoError(t, AdmitHeadFromRetained(context.Background(), urlOf(t, engine, true), Secret{}, urlOf(t, eth, false)))
	var hexed data
	require.NoError(t, json.Unmarshal(presented, &hexed))
	b, err := DecodePairBinding(bytes.Clone(hexed))
	require.NoError(t, err)
	want := c.binding
	want.Kind, want.SubjectID = PairImport, word(0x11)
	require.Equal(t, want, b, "the same context, the subject now the head block")

	engine.on("engine_admitParentV1", func(json.RawMessage) (any, *rpcError) {
		return nil, &rpcError{Code: -39002, Message: "recovery admission refused: presented binding refused at 5: pair binding refused: ParentHashMismatch"}
	})
	require.ErrorContains(t, AdmitHeadFromRetained(context.Background(), urlOf(t, engine, true), Secret{}, urlOf(t, eth, false)), "ParentHashMismatch")
}

// The execution client refuses a build below its finalized block after the pair gate accepted the job. For the control that changes nothing
// that answer is the gate's acceptance; for every other control the same answer means the gate did not refuse, so it is not an acceptance.
func TestATooDeepReorgIsTheGatesAcceptanceOnlyForTheUnchangedControl(t *testing.T) {
	c := newPairChain(t)
	eth := newMockReth(t, Secret{})
	c.serve(t, eth)
	engine := newMockReth(t, Secret{})
	engine.on("engine_forkchoiceUpdatedWithSealV1", func(json.RawMessage) (any, *rpcError) {
		return nil, &rpcError{Code: -38006, Message: "Too deep reorg"}
	})
	out, err := RunPairControl(context.Background(), urlOf(t, engine, true), Secret{}, urlOf(t, eth, false), ControlAccept)
	require.NoError(t, err)
	require.True(t, out.Accepted)
	require.True(t, out.GateOnly)
	require.Contains(t, out.Detail, "Too deep reorg")

	for _, kind := range []PairControl{ControlWrongParent, ControlWrongJob, ControlSubstitutedInput, ControlMissingEvidence} {
		out, err = RunPairControl(context.Background(), urlOf(t, engine, true), Secret{}, urlOf(t, eth, false), kind)
		require.NoError(t, err, kind)
		require.False(t, out.Accepted, "%s: a build the gate did not refuse is a failed control", kind)
		require.False(t, out.GateOnly, kind)
	}

	// any other engine error of the unchanged control stays a refusal
	other := newMockReth(t, Secret{})
	other.on("engine_forkchoiceUpdatedWithSealV1", func(json.RawMessage) (any, *rpcError) {
		return nil, &rpcError{Code: -32602, Message: "Invalid params"}
	})
	out, err = RunPairControl(context.Background(), urlOf(t, other, true), Secret{}, urlOf(t, eth, false), ControlAccept)
	require.NoError(t, err)
	require.False(t, out.Accepted)
}

// rootInputOf is a root input of the shape the transition list is read from: the transition array is the 11th field, followed (fresh B1) by the B1
// update hash and the root-records hash.
func rootInputOf(transitions [][]byte, fresh bool) []any {
	d := make([]any, len(transitions))
	for i, t := range transitions {
		d[i] = t
	}
	v := []any{uint64(2), uint64(3), uint64(8), []byte{0x80}, uint64(5), uint64(1), uint64(1), make([]byte, 32), []any{uint64(1)}, []any{uint64(5), uint64(1), "leader", []byte{1}, []byte{2}}, d}
	if fresh {
		v = append(v, make([]byte, 32), make([]byte, 32))
	}
	return v
}

func TestTheTransitionListIsTheEleventhFieldOfEveryTuple(t *testing.T) {
	transitions := [][]byte{{0xa1, 0x01}, {0xb2}}
	for name, fresh := range map[string]bool{"the legacy 11-field tuple": false, "the fresh B1 13-field tuple": true} {
		raw, err := types.Cbor.Marshal(rootInputOf(transitions, fresh))
		require.NoError(t, err, name)
		got, err := rootInputTransitionList(raw)
		require.NoError(t, err, name)
		require.Equal(t, []data{{0xa1, 0x01}, {0xb2}}, got, name)
	}
	short, _ := types.Cbor.Marshal([]any{uint64(2), uint64(5)})
	_, err := rootInputTransitionList(short)
	require.ErrorContains(t, err, "transition field")
	v := rootInputOf(transitions, true)
	v[rootInputTransitionsField] = []byte("not an array")
	notArray, _ := types.Cbor.Marshal(v)
	_, err = rootInputTransitionList(notArray)
	require.ErrorContains(t, err, "not an array")
	v = rootInputOf(transitions, true)
	v[rootInputTransitionsField] = []any{"text"}
	notBytes, _ := types.Cbor.Marshal(v)
	_, err = rootInputTransitionList(notBytes)
	require.ErrorContains(t, err, "not a byte string")
	// the canonical array the binding hashes comes from the same field
	fresh, _ := types.Cbor.Marshal(rootInputOf(transitions, true))
	legacy, _ := types.Cbor.Marshal(rootInputOf(transitions, false))
	a, err := rootInputTransitions(fresh)
	require.NoError(t, err)
	b, err := rootInputTransitions(legacy)
	require.NoError(t, err)
	require.Equal(t, a, b)
	th, err := TransitionsHash(transitions)
	require.NoError(t, err)
	require.NotZero(t, th)
}
