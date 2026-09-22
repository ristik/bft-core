package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Client speaks JSON-RPC 2.0 to one execution client's authenticated Engine
// API endpoint (conventionally :8551). One Client per shard-node process —
// there is exactly one executor per validator, so there is no connection
// pooling or multi-target routing to do here.
type Client struct {
	url    string
	secret Secret
	http   *http.Client
	// requireSeal adds the D2 seal siblings to the capability requirement. Off unless a
	// deployment selects the seal path; see RequireSealCapabilities.
	requireSeal bool
}

func NewClient(url string, secret Secret) *Client {
	return &Client{
		url:    url,
		secret: secret,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

/*
RequireSealCapabilities makes the three D2 `engine_*WithSealV1` siblings required, so the
startup check in adapter.go fails a client that does not offer them.

It is opt-in, and deliberately not the default. D2 §2 says the adapter's startup check "fails
the process if they are absent", which is right once a deployment drives the seal path. Making
it unconditional now would fail startup against every stock client while buying nothing: this
adapter does not yet call the seal methods. Routing build and import through them is activation,
which D2 §7 and #10 own.

So a deployment that has a seal-capable client and intends to use it turns this on, and the
negotiation is real and fatal for it. Everything else is unaffected.
*/
func (c *Client) RequireSealCapabilities() { c.requireSeal = true }

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *rpcError) Error() string {
	return fmt.Sprintf("engine API error %d: %s", e.Code, e.Message)
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *rpcError       `json:"error"`
}

// call is the one place every method below funnels through: build the
// envelope, sign a fresh token (see jwt.go — one per call, not reused),
// POST, and surface either a transport error, an RPC-level error, or the
// raw result for the caller to unmarshal into its specific response type.
func (c *Client) call(ctx context.Context, method string, params []any, out any) error {
	reqBody, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("engineapi: encoding request for %s: %w", method, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("engineapi: building request for %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")

	token, err := c.secret.Token(time.Now())
	if err != nil {
		return fmt.Errorf("engineapi: signing token for %s: %w", method, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("engineapi: calling %s: %w", method, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("engineapi: reading response for %s: %w", method, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("engineapi: %s returned HTTP %d: %s", method, resp.StatusCode, string(body))
	}

	var rpcResp rpcResponse
	if err := json.Unmarshal(body, &rpcResp); err != nil {
		return fmt.Errorf("engineapi: decoding response envelope for %s: %w", method, err)
	}
	if rpcResp.Error != nil {
		return fmt.Errorf("engineapi: %s: %w", method, rpcResp.Error)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(rpcResp.Result, out); err != nil {
		return fmt.Errorf("engineapi: decoding result for %s: %w", method, err)
	}
	return nil
}

// requiredCapabilities is the exact V3 method set this client speaks — see
// docs/adr/0001-executor-boundary.md decision 3. ExchangeCapabilities
// checks the server offers all of these; adapter.go's startup check is what
// makes that check fatal rather than advisory.
var requiredCapabilities = []string{
	"engine_forkchoiceUpdatedV3",
	"engine_getPayloadV3",
	"engine_newPayloadV3",
}

// sealCapabilities are the D2 §2 siblings. They are required only when a deployment has selected
// the seal path through RequireSealCapabilities, and they are required together: a client that
// offered a subset would be advertising a flow it cannot complete, so a partial answer is a
// missing-capability failure like any other.
var sealCapabilities = []string{
	"engine_forkchoiceUpdatedWithSealV1",
	"engine_getPayloadWithSealV1",
	"engine_newPayloadWithSealV1",
}

// required returns the capability set this client insists on.
func (c *Client) required() []string {
	if !c.requireSeal {
		return requiredCapabilities
	}
	out := make([]string, 0, len(requiredCapabilities)+len(sealCapabilities))
	out = append(out, requiredCapabilities...)
	return append(out, sealCapabilities...)
}

// ExchangeCapabilities calls engine_exchangeCapabilities and returns which
// of requiredCapabilities the server is missing (empty means fully capable).
func (c *Client) ExchangeCapabilities(ctx context.Context) (missing []string, err error) {
	required := c.required()
	var offered []string
	if err := c.call(ctx, "engine_exchangeCapabilities", []any{required}, &offered); err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(offered))
	for _, m := range offered {
		have[m] = true
	}
	for _, m := range required {
		if !have[m] {
			missing = append(missing, m)
		}
	}
	return missing, nil
}

func (c *Client) ForkchoiceUpdatedV3(ctx context.Context, state ForkchoiceStateV1, attrs *PayloadAttributesV3) (ForkchoiceUpdatedResponse, error) {
	var resp ForkchoiceUpdatedResponse
	err := c.call(ctx, "engine_forkchoiceUpdatedV3", []any{state, attrs}, &resp)
	return resp, err
}

func (c *Client) GetPayloadV3(ctx context.Context, payloadID data) (GetPayloadV3Response, error) {
	var resp GetPayloadV3Response
	err := c.call(ctx, "engine_getPayloadV3", []any{payloadID}, &resp)
	return resp, err
}

// ForkchoiceUpdatedWithSealV1 is engine_forkchoiceUpdatedWithSealV1, the
// build-path seal sibling of ForkchoiceUpdatedV3. Parameter order matches that
// method — forkchoice state, payload attributes, then the seal build input —
// because these are siblings of the same call, not a new style.
//
// payloadAttributes is required by D2: a seal build input without attributes
// describes nothing. The pointer is kept so callers handle this and
// ForkchoiceUpdatedV3 the same way, but nil is refused here rather than sent as
// JSON null and rejected with a far-side decoding error.
func (c *Client) ForkchoiceUpdatedWithSealV1(ctx context.Context, state ForkchoiceStateV1, attrs *UnicityPayloadAttributes, sealBuildInput SealBuildInput) (ForkchoiceUpdatedResponse, error) {
	if attrs == nil {
		return ForkchoiceUpdatedResponse{}, fmt.Errorf("engineapi: engine_forkchoiceUpdatedWithSealV1 requires payload attributes — a seal build input without attributes describes nothing (D2 §2)")
	}
	var resp ForkchoiceUpdatedResponse
	err := c.call(ctx, "engine_forkchoiceUpdatedWithSealV1", []any{state, attrs, sealBuildInput}, &resp)
	return resp, err
}

// GetPayloadWithSealV1 is engine_getPayloadWithSealV1, the build-path seal
// sibling of GetPayloadV3. It returns the built payload, its block value and the
// companion the leader disseminates alongside it.
func (c *Client) GetPayloadWithSealV1(ctx context.Context, payloadID data) (GetPayloadWithSealV1Response, error) {
	var resp GetPayloadWithSealV1Response
	err := c.call(ctx, "engine_getPayloadWithSealV1", []any{payloadID}, &resp)
	return resp, err
}

// NewPayloadV3 takes all three parameters the spec requires — see
// codec.go's ProposalEnvelope doc comment for why
// expectedBlobVersionedHashes is always empty here and why
// parentBeaconBlockRoot is computed by the caller rather than received over
// dissemination.
func (c *Client) NewPayloadV3(ctx context.Context, payload ExecutionPayloadV3, expectedBlobVersionedHashes []data32, parentBeaconBlockRoot data32) (PayloadStatusV1, error) {
	// A nil slice marshals to JSON null, not []; the spec wants an explicit
	// empty array when there are no blobs (§6 of the build plan), so a nil
	// caller value is normalized here rather than trusted.
	if expectedBlobVersionedHashes == nil {
		expectedBlobVersionedHashes = []data32{}
	}
	var resp PayloadStatusV1
	err := c.call(ctx, "engine_newPayloadV3", []any{payload, expectedBlobVersionedHashes, parentBeaconBlockRoot}, &resp)
	return resp, err
}

// NewPayloadWithSealV1 is engine_newPayloadWithSealV1, the import-path seal sibling of
// NewPayloadV3: the same three parameters in the same order, plus the seal companion the block
// travelled with. It reports the same PayloadStatusV1 the standard method does, because the seal
// sibling is a versioned sibling rather than a different contract.
//
// The caller must have authenticated the companion's witnesses before calling; this method does not
// and cannot. reth accepts that verdict over the JWT-authenticated channel (f3-engine-seal-delivery.md
// §4), which is why the authentication boundary is Adapter.Verify's and not this method's.
func (c *Client) NewPayloadWithSealV1(ctx context.Context, payload ExecutionPayloadV3, expectedBlobVersionedHashes []data32, parentBeaconBlockRoot data32, sealCompanion SealCompanion) (PayloadStatusV1, error) {
	// A nil slice marshals to JSON null, not []; the spec wants an explicit
	// empty array when there are no blobs (§6 of the build plan), so a nil
	// caller value is normalized here rather than trusted. Same rule and same
	// reason as NewPayloadV3.
	if expectedBlobVersionedHashes == nil {
		expectedBlobVersionedHashes = []data32{}
	}
	var resp PayloadStatusV1
	err := c.call(ctx, "engine_newPayloadWithSealV1", []any{payload, expectedBlobVersionedHashes, parentBeaconBlockRoot, sealCompanion}, &resp)
	return resp, err
}

// ChainID and GetBlockByNumber call the standard eth_* methods on the
// AUTHENTICATED Engine endpoint, not the plain RPC port.
//
// This is not a reth extension and needs no divergence from upstream. The
// Engine API specification's "underlying protocol" section
// (execution-apis/src/engine/common.md) requires an execution client to
// serve a named subset of the eth_* namespace on the same authenticated
// port as engine_*, and eth_chainId and eth_getBlockByNumber are both in
// that subset. The pinned client implements them: see EngineEthApi in
// crates/rpc/rpc-api/src/engine.rs, where `chainId` and `getBlockByNumber`
// sit alongside the engine_* methods.
//
// Why the adapter wants them: --engine-url and --eth-url are configured
// separately, so nothing structurally prevents an operator from pointing
// them at two DIFFERENT execution clients. Everything that decides what
// this node votes for goes over the Engine connection; everything the
// startup checks previously inspected went over the plain one. Reading the
// chain id and genesis over the Engine connection is what makes the
// startup checks describe the client that actually builds our blocks.
//
// What agreement between the two connections does and does not establish
// is documented on Adapter.CheckChainID.
func (c *Client) ChainID(ctx context.Context) (uint64, error) {
	var raw json.RawMessage
	if err := c.call(ctx, "eth_chainId", nil, &raw); err != nil {
		return 0, err
	}
	return decodeChainID(raw)
}

func (c *Client) GetBlockByNumber(ctx context.Context, tag string) (blockHeaderJSON, error) {
	var raw json.RawMessage
	if err := c.call(ctx, "eth_getBlockByNumber", []any{tag, false}, &raw); err != nil {
		return blockHeaderJSON{}, err
	}
	return decodeBlockHeader(raw)
}
