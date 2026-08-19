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
}

func NewClient(url string, secret Secret) *Client {
	return &Client{
		url:    url,
		secret: secret,
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

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

// ExchangeCapabilities calls engine_exchangeCapabilities and returns which
// of requiredCapabilities the server is missing (empty means fully capable).
func (c *Client) ExchangeCapabilities(ctx context.Context) (missing []string, err error) {
	var offered []string
	if err := c.call(ctx, "engine_exchangeCapabilities", []any{requiredCapabilities}, &offered); err != nil {
		return nil, err
	}
	have := make(map[string]bool, len(offered))
	for _, m := range offered {
		have[m] = true
	}
	for _, m := range requiredCapabilities {
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
