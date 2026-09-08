package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// EthClient speaks the standard eth_* JSON-RPC namespace — reth's regular
// HTTP RPC port (conventionally :8545), unauthenticated, separate from the
// JWT-protected engine_* namespace Client (client.go) speaks on :8551.
// Adapter needs both: engine_* to drive block production, eth_* to look up
// a parent block's header fields (its timestamp, specifically — see
// params.go's ParentHeader) that the Engine API itself doesn't expose a
// lookup for.
type EthClient struct {
	url  string
	http *http.Client
}

func NewEthClient(url string) *EthClient {
	return &EthClient{url: url, http: &http.Client{Timeout: 10 * time.Second}}
}

// blockHeaderJSON is the subset of eth_getBlockBy{Hash,Number}'s response
// this package reads. Only fields Adapter actually consumes are declared —
// the rest of a real response is ignored on decode, not an error.
type blockHeaderJSON struct {
	Number     quantity `json:"number"`
	Hash       data32   `json:"hash"`
	ParentHash data32   `json:"parentHash"`
	StateRoot  data32   `json:"stateRoot"`
	Timestamp  quantity `json:"timestamp"`
}

func (c *EthClient) call(ctx context.Context, method string, params []any, out any) error {
	reqBody, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("engineapi: encoding request for %s: %w", method, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("engineapi: building request for %s: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/json")

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

// errNoSuchBlock is what a JSON `null` result means for the block getters:
// the RPC succeeded and the client is telling us it does not have that
// block. Decoding `null` into blockHeaderJSON succeeds and yields a
// ZERO-VALUED header, so without this the caller would compare an
// all-zeroes hash as if it were a real answer — a startup check would
// report a genesis "mismatch" against 0x000…0 rather than saying the
// client has no genesis block. Both meanings are failures, but only one of
// them tells the operator what to fix.
var errNoSuchBlock = errors.New("no such block")

func decodeBlockHeader(raw json.RawMessage) (blockHeaderJSON, error) {
	if isJSONNull(raw) {
		return blockHeaderJSON{}, errNoSuchBlock
	}
	var h blockHeaderJSON
	if err := json.Unmarshal(raw, &h); err != nil {
		return blockHeaderJSON{}, fmt.Errorf("decoding block header: %w", err)
	}
	return h, nil
}

// decodeChainID exists for the same reason as decodeBlockHeader: reth types
// eth_chainId's result as Option<U64> (crates/rpc/rpc-api/src/engine.rs), so
// a null is a legal response meaning "no chain id configured" — which would
// otherwise decode to the perfectly plausible-looking chain id 0.
func decodeChainID(raw json.RawMessage) (uint64, error) {
	if isJSONNull(raw) {
		return 0, errors.New("client reports no chain id")
	}
	var q quantity
	if err := json.Unmarshal(raw, &q); err != nil {
		return 0, fmt.Errorf("decoding chain id: %w", err)
	}
	return uint64(q), nil
}

func isJSONNull(raw json.RawMessage) bool {
	return len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null"
}

// GetBlockByHash returns the subset of the block header this package needs.
// includeTxs is always false — headers, not bodies.
func (c *EthClient) GetBlockByHash(ctx context.Context, hash data32) (blockHeaderJSON, error) {
	var raw json.RawMessage
	if err := c.call(ctx, "eth_getBlockByHash", []any{hash, false}, &raw); err != nil {
		return blockHeaderJSON{}, err
	}
	return decodeBlockHeader(raw)
}

// GetBlockByNumber accepts either a QUANTITY-encoded number or a tag
// ("latest", "finalized", "safe") — reth accepts both forms for this
// parameter per the standard eth_getBlockByNumber spec.
func (c *EthClient) GetBlockByNumber(ctx context.Context, tag string) (blockHeaderJSON, error) {
	var raw json.RawMessage
	if err := c.call(ctx, "eth_getBlockByNumber", []any{tag, false}, &raw); err != nil {
		return blockHeaderJSON{}, err
	}
	return decodeBlockHeader(raw)
}

// ChainID calls eth_chainId on the plain endpoint. Adapter.CheckChainID
// pairs it with the same call on the authenticated Engine endpoint.
func (c *EthClient) ChainID(ctx context.Context) (uint64, error) {
	var raw json.RawMessage
	if err := c.call(ctx, "eth_chainId", nil, &raw); err != nil {
		return 0, err
	}
	return decodeChainID(raw)
}
