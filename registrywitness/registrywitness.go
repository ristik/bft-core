/*
Package registrywitness acquires the SealRegistry evidence for an exact, already authenticated parent block
from an execution client, and captures it as witness(B) for the child of B
(docs/design/f4a-seal-registry-contract.md §8.2).

Acquisition names the block only by hash: debug_getRawHeader(B) and eth_getProof(a_sr, keys, {blockHash: B}).
Nothing is accepted until registryproof.Verify accepts it under the caller's context. The two ways this can
fail are kept apart:

  - ErrUnavailable: no evidence was obtained. The client does not know the block, its proof window has
    passed the block, the call failed or timed out. The caller reports "proof unavailable" and is not ready
    for the child; it never substitutes the head, a block number or a zero cursor.
  - ErrInvalid: a response arrived but is not acceptable evidence: malformed, oversized, for another block
    or account, or refused by registryproof.Verify.

Store holds captured witnesses in memory, bounded, and re-verifies a witness each time it is used (§7.5).
Durable retention and restart are #14; serving witnesses to other nodes and reacquisition after expiry
are #15. Nothing in production imports this package (inert_test.go).
*/
package registrywitness

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/unicitynetwork/bft-core/registryproof"
)

var (
	// ErrUnavailable wraps registryproof.ErrUnavailable, so either class check reaches it.
	ErrUnavailable = fmt.Errorf("registrywitness: %w", registryproof.ErrUnavailable)
	// ErrInvalid is a response that is not acceptable evidence. The registryproof refusal, when there is
	// one, is wrapped as well.
	ErrInvalid = errors.New("registrywitness: evidence invalid")
)

// RPCError is a JSON-RPC error object returned by the client.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("JSON-RPC error %d: %s", e.Code, e.Message) }

// Caller performs one JSON-RPC call and returns its result. It returns a *RPCError for a JSON-RPC error,
// ErrInvalid for a response that is not a JSON-RPC result, and any other error for transport failure.
type Caller interface {
	Call(ctx context.Context, method string, params []any) (json.RawMessage, error)
}

// MaxResponseBytes bounds one response body before it is decoded. registryproof's evidence bound is
// 256 KiB of binary nodes; hex encoding doubles it, and the envelope and keys add less than 8 KiB.
const MaxResponseBytes = 600 << 10

// HTTPCaller is a Caller for a JSON-RPC HTTP endpoint.
type HTTPCaller struct {
	url    string
	client *http.Client
}

// NewHTTPCaller returns a caller for url. timeout bounds each call, in addition to the caller's context.
func NewHTTPCaller(url string, timeout time.Duration) *HTTPCaller {
	return &HTTPCaller{url: url, client: &http.Client{Timeout: timeout}}
}

type rpcRequest struct {
	JSONRPC string `json:"jsonrpc"`
	ID      int    `json:"id"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *RPCError       `json:"error"`
}

func (h *HTTPCaller) Call(ctx context.Context, method string, params []any) (json.RawMessage, error) {
	body, err := json.Marshal(rpcRequest{JSONRPC: "2.0", ID: 1, Method: method, Params: params})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxResponseBytes {
		return nil, fmt.Errorf("%w: %s response exceeds %d bytes", ErrInvalid, method, MaxResponseBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s returned HTTP %d", method, resp.StatusCode)
	}
	var r rpcResponse
	if err := json.Unmarshal(raw, &r); err != nil || r.JSONRPC != "2.0" {
		return nil, fmt.Errorf("%w: %s response is not a JSON-RPC 2.0 object", ErrInvalid, method)
	}
	if r.Error != nil {
		return nil, r.Error
	}
	if r.Result == nil {
		return nil, fmt.Errorf("%w: %s response has neither result nor error", ErrInvalid, method)
	}
	return r.Result, nil
}

// reth's JSON-RPC errors for a block it cannot serve: an unknown block is -32001 "block not found", and a
// block behind the proof window is -32602 "distance to target block exceeds maximum proof window"
// (crates/rpc/rpc-eth-types/src/error/mod.rs at 189c0df3, and the measured responses in testdata).
const proofWindowMessage = "exceeds maximum proof window"

// classify maps a Caller error to the package's classes. A context error is returned as itself, wrapped
// in ErrUnavailable, so callers can tell cancellation from an unavailable client.
func classify(ctx context.Context, method string, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return fmt.Errorf("%w: %s: %w", ErrUnavailable, method, ctxErr)
	}
	if errors.Is(err, ErrInvalid) {
		return fmt.Errorf("%s: %w", method, err)
	}
	var rpcErr *RPCError
	if errors.As(err, &rpcErr) {
		switch {
		case strings.Contains(rpcErr.Message, proofWindowMessage):
			return fmt.Errorf("%w: %s: the block is behind the client's proof window: %w", ErrUnavailable, method, rpcErr)
		default:
			return fmt.Errorf("%w: %s: %w", ErrUnavailable, method, rpcErr)
		}
	}
	return fmt.Errorf("%w: %s: %w", ErrUnavailable, method, err)
}

/*
Acquire fetches and verifies the evidence for parent, which the caller has already authenticated as the
certified parent (§7.2). The request names parent by hash; a number or tag is not representable.

It returns a Witness only after registryproof.Verify accepts the evidence under c.
*/
func Acquire(ctx context.Context, rpc Caller, c registryproof.Context, parent common.Hash) (Witness, error) {
	if parent == (common.Hash{}) {
		return Witness{}, fmt.Errorf("%w: parent hash is zero", registryproof.ErrContext)
	}

	rawHeader, err := rpc.Call(ctx, "debug_getRawHeader", []any{parent})
	if err != nil {
		return Witness{}, classify(ctx, "debug_getRawHeader", err)
	}
	if isNull(rawHeader) {
		return Witness{}, fmt.Errorf("%w: debug_getRawHeader: the client does not have block %s", ErrUnavailable, parent)
	}
	var header hexutil.Bytes
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return Witness{}, fmt.Errorf("%w: debug_getRawHeader: result is not hex bytes: %v", ErrInvalid, err)
	}

	keys := make([]common.Hash, registryproof.FieldCount)
	for i := range keys {
		keys[i] = registryproof.SlotKey(i)
	}
	rawProof, err := rpc.Call(ctx, "eth_getProof", []any{registryproof.RegistryAddress, keys, map[string]any{"blockHash": parent}})
	if err != nil {
		return Witness{}, classify(ctx, "eth_getProof", err)
	}
	if isNull(rawProof) {
		return Witness{}, fmt.Errorf("%w: eth_getProof: null result for block %s", ErrUnavailable, parent)
	}
	var proof registryproof.GetProofResult
	if err := json.Unmarshal(rawProof, &proof); err != nil {
		return Witness{}, fmt.Errorf("%w: eth_getProof: result does not decode: %v", ErrInvalid, err)
	}
	ev, err := registryproof.EvidenceFromGetProof(header, proof)
	if err != nil {
		return Witness{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return newWitness(c, parent, ev)
}

func isNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

// Witness is witness(B): the header and proofs for B, accepted by registryproof.Verify. It is opaque; the
// evidence is held privately and only copies leave it.
type Witness struct {
	w *witness
}

type witness struct {
	parent   common.Hash
	evidence registryproof.Evidence
	snapshot registryproof.Snapshot
}

func newWitness(c registryproof.Context, parent common.Hash, ev registryproof.Evidence) (Witness, error) {
	ev = cloneEvidence(ev)
	s, err := registryproof.Verify(c, parent, ev)
	if err != nil {
		if errors.Is(err, registryproof.ErrUnavailable) {
			return Witness{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
		}
		return Witness{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return Witness{w: &witness{parent: parent, evidence: ev, snapshot: s}}, nil
}

// Valid reports whether w was produced by Acquire or a Store.
func (w Witness) Valid() bool { return w.w != nil }

// Parent is the block hash w proves.
func (w Witness) Parent() common.Hash {
	if w.w == nil {
		return common.Hash{}
	}
	return w.w.parent
}

// Snapshot is the verified registry snapshot at the parent.
func (w Witness) Snapshot() registryproof.Snapshot {
	if w.w == nil {
		return registryproof.Snapshot{}
	}
	return w.w.snapshot
}

// Evidence returns a copy of the retained header and proofs.
func (w Witness) Evidence() registryproof.Evidence {
	if w.w == nil {
		return registryproof.Evidence{}
	}
	return cloneEvidence(w.w.evidence)
}

func cloneEvidence(ev registryproof.Evidence) registryproof.Evidence {
	out := registryproof.Evidence{Header: bytes.Clone(ev.Header), AccountProof: cloneNodes(ev.AccountProof)}
	if ev.StorageProofs != nil {
		out.StorageProofs = make([][][]byte, len(ev.StorageProofs))
		for i, p := range ev.StorageProofs {
			out.StorageProofs[i] = cloneNodes(p)
		}
	}
	return out
}

func cloneNodes(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i, n := range in {
		out[i] = bytes.Clone(n)
	}
	return out
}

/*
Store holds witness(B) for the child of B, in memory and bounded.

Capture accepts a Witness (already verified) and keeps its evidence. ForChild returns the snapshot for a
parent only after verifying the retained evidence again under the store's context, so retained material is
never used as an unverified cached value (§7.5). When the store is full, the oldest captured witness is
dropped and becomes unavailable; how long witnesses must be retained, and across restarts, is #14.
*/
type Store struct {
	ctx      registryproof.Context
	capacity int

	mu      sync.Mutex
	entries map[common.Hash]registryproof.Evidence
	order   []common.Hash
}

// NewStore returns a store that retains at most capacity witnesses verified under ctx.
func NewStore(ctx registryproof.Context, capacity int) (*Store, error) {
	if capacity <= 0 {
		return nil, fmt.Errorf("registrywitness: store capacity must be positive, got %d", capacity)
	}
	return &Store{ctx: ctx, capacity: capacity, entries: map[common.Hash]registryproof.Evidence{}}, nil
}

// Capture retains w for its parent. It refuses a Witness not produced by Acquire, and re-verifies w's
// evidence under the store's context, so a witness verified under another context is not retained.
func (s *Store) Capture(w Witness) error {
	if !w.Valid() {
		return fmt.Errorf("%w: the witness was not produced by Acquire", ErrInvalid)
	}
	verified, err := newWitness(s.ctx, w.w.parent, w.w.evidence)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	parent := verified.w.parent
	// A re-captured parent becomes the newest entry, so eviction drops the least recently captured.
	if _, ok := s.entries[parent]; ok {
		for i, h := range s.order {
			if h == parent {
				s.order = append(s.order[:i], s.order[i+1:]...)
				break
			}
		}
	}
	s.order = append(s.order, parent)
	s.entries[parent] = verified.w.evidence
	for len(s.order) > s.capacity {
		delete(s.entries, s.order[0])
		s.order = s.order[1:]
	}
	return nil
}

// AcquireAndCapture acquires witness(parent) from rpc and retains it.
func (s *Store) AcquireAndCapture(ctx context.Context, rpc Caller, parent common.Hash) (Witness, error) {
	w, err := Acquire(ctx, rpc, s.ctx, parent)
	if err != nil {
		return Witness{}, err
	}
	if err := s.Capture(w); err != nil {
		return Witness{}, err
	}
	return w, nil
}

// ForChild returns the verified snapshot of parent for building, validating or signing its child. A parent
// with no retained witness is ErrUnavailable; there is no fallback.
func (s *Store) ForChild(parent common.Hash) (registryproof.Snapshot, error) {
	s.mu.Lock()
	ev, ok := s.entries[parent]
	if ok {
		ev = cloneEvidence(ev)
	}
	s.mu.Unlock()
	if !ok {
		return registryproof.Snapshot{}, fmt.Errorf("%w: no witness retained for %s", ErrUnavailable, parent)
	}
	w, err := newWitness(s.ctx, parent, ev)
	if err != nil {
		return registryproof.Snapshot{}, err
	}
	return w.Snapshot(), nil
}

// Len is the number of retained witnesses.
func (s *Store) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}
