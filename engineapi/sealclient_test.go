package engineapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// stubEngine serves one scripted JSON-RPC result and records the raw request
// body, so a client test can assert the method name and the positional
// parameters that actually went out rather than inferring them.
func stubEngine(t *testing.T, result json.RawMessage) (*httptest.Server, *capturedRequest) {
	t.Helper()
	capture := &capturedRequest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capture.mu.Lock()
		capture.raw = body
		capture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"result":  result,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, capture
}

// errorStub serves one JSON-RPC error response.
func errorStub(t *testing.T, code int, message string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      1,
			"error":   map[string]any{"code": code, "message": message},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

type capturedRequest struct {
	mu  sync.Mutex
	raw []byte
}

func (c *capturedRequest) decode(t *testing.T) (string, []json.RawMessage) {
	t.Helper()
	c.mu.Lock()
	raw := append([]byte(nil), c.raw...)
	c.mu.Unlock()
	var req struct {
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	require.NoError(t, json.Unmarshal(raw, &req))
	return req.Method, req.Params
}

// sampleAttrs is a populated UnicityPayloadAttributes; the commitment is the
// field reth's UnicityPayloadAttributes requires and uses as the header
// extraData.
func sampleAttrs() *UnicityPayloadAttributes {
	return &UnicityPayloadAttributes{
		PayloadAttributesV3: PayloadAttributesV3{
			Timestamp:             quantity(1000),
			PrevRandao:            fixedHash(0x22),
			SuggestedFeeRecipient: data20{0x33},
			Withdrawals:           []WithdrawalV1{},
			ParentBeaconBlockRoot: fixedHash(0x44),
		},
		Commitment: fixedHash(0x55),
	}
}

func TestSealBuildInputVector(t *testing.T) {
	// The nil transitions slice is the dangerous case: Go marshals a nil slice
	// to null, and ureth's Vec<Bytes> will not decode null. It has to be [].
	nilTransitions, err := json.Marshal(SealBuildInput{RootInput: data{0x01, 0x02, 0x03}})
	require.NoError(t, err)
	require.Equal(t, `{"b1Update":"0x","records":"0x","rootInput":"0x010203","transitions":[]}`, string(nilTransitions))
	require.NotContains(t, string(nilTransitions), "null")

	// An explicit empty slice must encode identically.
	emptyTransitions, err := json.Marshal(SealBuildInput{
		RootInput:   data{0x01, 0x02, 0x03},
		Transitions: []data{},
	})
	require.NoError(t, err)
	require.Equal(t, string(nilTransitions), string(emptyTransitions))

	// A populated one pins the key order and the 0x-hex DATA convention, so a
	// later change that would break ureth's deny_unknown_fields decode fails
	// here rather than in a running deployment.
	populated, err := json.Marshal(SealBuildInput{
		RootInput:   data{0xde, 0xad},
		Transitions: []data{{0xaa}, {0xbb, 0xcc}},
	})
	require.NoError(t, err)
	require.Equal(t, `{"b1Update":"0x","records":"0x","rootInput":"0xdead","transitions":["0xaa","0xbbcc"]}`, string(populated))
}

func TestForkchoiceUpdatedWithSealV1SendsMethodAndThreeParams(t *testing.T) {
	srv, capture := stubEngine(t, json.RawMessage(`{"payloadStatus":{"status":"VALID"},"payloadId":null}`))
	c := NewClient(srv.URL, Secret{})

	state := ForkchoiceStateV1{
		HeadBlockHash:      fixedHash(0x11),
		SafeBlockHash:      fixedHash(0x11),
		FinalizedBlockHash: fixedHash(0x11),
	}
	attrs := sampleAttrs()
	input := SealBuildInput{RootInput: data{0x01, 0x02}, Transitions: []data{}}

	resp, err := c.ForkchoiceUpdatedWithSealV1(context.Background(), state, attrs, input)
	require.NoError(t, err)
	require.Equal(t, PayloadStatusValid, resp.PayloadStatus.Status)

	method, params := capture.decode(t)
	require.Equal(t, "engine_forkchoiceUpdatedWithSealV1", method)
	require.Len(t, params, 3, "the method takes forkchoice state, attributes and seal build input, in that order")

	var gotState ForkchoiceStateV1
	require.NoError(t, json.Unmarshal(params[0], &gotState))
	require.Equal(t, state, gotState)

	var gotAttrs UnicityPayloadAttributes
	require.NoError(t, json.Unmarshal(params[1], &gotAttrs))
	require.Equal(t, *attrs, gotAttrs)
	require.Contains(t, string(params[1]), `"commitment"`,
		"the commitment must be on the wire: reth's UnicityPayloadAttributes requires it")

	require.Equal(t, `{"b1Update":"0x","records":"0x","rootInput":"0x0102","transitions":[]}`, string(params[2]))
}

func TestForkchoiceUpdatedWithSealV1RefusesNilAttributesWithoutCallingTheFarSide(t *testing.T) {
	// Port 1 is unreachable; if the call reached the transport it would fail
	// with a connection error instead of the refusal this asserts.
	c := NewClient("http://127.0.0.1:1", Secret{})

	_, err := c.ForkchoiceUpdatedWithSealV1(context.Background(), ForkchoiceStateV1{}, nil, SealBuildInput{RootInput: data{0x01}})
	require.ErrorContains(t, err, "requires payload attributes")
}

func TestGetPayloadWithSealV1SendsMethodAndDecodesAllThreeFields(t *testing.T) {
	hash := func(nibble string) string { return "0x" + strings.Repeat(nibble, 32) }
	result := json.RawMessage(fmt.Sprintf(`{
		"executionPayload": {
			"parentHash": %q,
			"feeRecipient": "0x2222222222222222222222222222222222222222",
			"stateRoot": %q,
			"receiptsRoot": %q,
			"logsBloom": "0x",
			"prevRandao": %q,
			"blockNumber": "0x7",
			"gasLimit": "0x1c9c380",
			"gasUsed": "0x5208",
			"timestamp": "0x6553f100",
			"extraData": "0xdead",
			"baseFeePerGas": "0x3b9aca00",
			"blockHash": %q,
			"transactions": [],
			"withdrawals": [],
			"blobGasUsed": "0x0",
			"excessBlobGas": "0x0"
		},
		"blockValue": "0x1234",
		"sealCompanion": {"rootInput": "0x010203", "witnesses": [], "provenance": "build"}
	}`, hash("11"), hash("33"), hash("44"), hash("55"), hash("66")))

	srv, capture := stubEngine(t, result)
	c := NewClient(srv.URL, Secret{})
	payloadID := data{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xee, 0xee, 0xee}

	resp, err := c.GetPayloadWithSealV1(context.Background(), payloadID)
	require.NoError(t, err)

	method, params := capture.decode(t)
	require.Equal(t, "engine_getPayloadWithSealV1", method)
	require.Len(t, params, 1)
	var gotID data
	require.NoError(t, json.Unmarshal(params[0], &gotID))
	require.Equal(t, payloadID, gotID)

	// All three response fields, not just the payload.
	require.Equal(t, quantity(7), resp.ExecutionPayload.BlockNumber)
	require.Equal(t, fixedHash(0x66), resp.ExecutionPayload.BlockHash)
	require.Equal(t, data{0xde, 0xad}, resp.ExecutionPayload.ExtraData)
	require.Equal(t, quantity(0x1234), resp.BlockValue)
	require.Equal(t, data{0x01, 0x02, 0x03}, resp.SealCompanion.RootInput)
	require.Equal(t, "build", resp.SealCompanion.Provenance)
	require.Empty(t, resp.SealCompanion.Witnesses)
}

func TestNewPayloadWithSealV1SendsFourParamsAndNormalizesNilBlobHashes(t *testing.T) {
	srv, capture := stubEngine(t, json.RawMessage(`{"status":"VALID"}`))
	c := NewClient(srv.URL, Secret{})

	payload := ExecutionPayloadV3{
		ParentHash:   fixedHash(0x11),
		StateRoot:    fixedHash(0x33),
		BlockHash:    fixedHash(0x66),
		LogsBloom:    data{},
		ExtraData:    data{},
		Transactions: []data{{0xaa}},
		Withdrawals:  []WithdrawalV1{},
	}
	companion := SealCompanion{B1Update: data{}, RootRecords: data{}, RootInput: data{0x01, 0x02, 0x03}, Witnesses: []data{{0xaa}, {0xbb}}, Provenance: "newPayload"}

	resp, err := c.NewPayloadWithSealV1(context.Background(), payload, nil, fixedHash(0x44), companion)
	require.NoError(t, err)
	require.Equal(t, PayloadStatusValid, resp.Status)

	method, params := capture.decode(t)
	require.Equal(t, "engine_newPayloadWithSealV1", method)
	require.Len(t, params, 4, "payload, expectedBlobVersionedHashes, parentBeaconBlockRoot, sealCompanion")

	var gotPayload ExecutionPayloadV3
	require.NoError(t, json.Unmarshal(params[0], &gotPayload))
	require.Equal(t, payload, gotPayload)

	require.Equal(t, "[]", string(params[1]),
		"a nil expectedBlobVersionedHashes must be normalized to [] exactly as NewPayloadV3 does")

	var gotRoot data32
	require.NoError(t, json.Unmarshal(params[2], &gotRoot))
	require.Equal(t, fixedHash(0x44), gotRoot, "parentBeaconBlockRoot is a method parameter, not a payload field")

	var gotCompanion SealCompanion
	require.NoError(t, json.Unmarshal(params[3], &gotCompanion))
	require.Equal(t, companion, gotCompanion)
}

func TestNewPayloadWithSealV1SurfacesRPCErrorsAsErrors(t *testing.T) {
	srv := errorStub(t, -38001, "seal method unavailable")
	c := NewClient(srv.URL, Secret{})

	payload, err := c.NewPayloadWithSealV1(context.Background(), ExecutionPayloadV3{}, nil, fixedHash(0x44), SealCompanion{})
	require.ErrorContains(t, err, "seal method unavailable")
	require.Equal(t, PayloadStatusV1{}, payload, "an RPC error must not look like a decoded status")
}

func TestSealClientMethodsSurfaceRPCErrorsAsErrors(t *testing.T) {
	srv := errorStub(t, -38001, "seal method unavailable")
	c := NewClient(srv.URL, Secret{})
	ctx := context.Background()

	forkchoice, err := c.ForkchoiceUpdatedWithSealV1(ctx, ForkchoiceStateV1{}, sampleAttrs(), SealBuildInput{})
	require.ErrorContains(t, err, "seal method unavailable")
	require.Equal(t, ForkchoiceUpdatedResponse{}, forkchoice, "an RPC error must not look like a decoded response")

	payload, err := c.GetPayloadWithSealV1(ctx, data{})
	require.ErrorContains(t, err, "seal method unavailable")
	require.Equal(t, GetPayloadWithSealV1Response{}, payload)
}
