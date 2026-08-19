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
	Number    quantity `json:"number"`
	Hash      data32   `json:"hash"`
	ParentHash data32  `json:"parentHash"`
	StateRoot data32   `json:"stateRoot"`
	Timestamp quantity `json:"timestamp"`
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

// GetBlockByHash returns the subset of the block header this package needs.
// includeTxs is always false — headers, not bodies.
func (c *EthClient) GetBlockByHash(ctx context.Context, hash data32) (blockHeaderJSON, error) {
	var h blockHeaderJSON
	err := c.call(ctx, "eth_getBlockByHash", []any{hash, false}, &h)
	return h, err
}

// GetBlockByNumber accepts either a QUANTITY-encoded number or a tag
// ("latest", "finalized", "safe") — reth accepts both forms for this
// parameter per the standard eth_getBlockByNumber spec.
func (c *EthClient) GetBlockByNumber(ctx context.Context, tag string) (blockHeaderJSON, error) {
	var h blockHeaderJSON
	err := c.call(ctx, "eth_getBlockByNumber", []any{tag, false}, &h)
	return h, err
}

// ChainID calls eth_chainId — used by shard_node_doctor.go's "chain
// identity" check (docs/engine-api-adapter-plan.md §8), not by Adapter
// itself.
func (c *EthClient) ChainID(ctx context.Context) (uint64, error) {
	var q quantity
	err := c.call(ctx, "eth_chainId", nil, &q)
	return uint64(q), err
}
