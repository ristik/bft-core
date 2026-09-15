package registrywitness

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registrygenesis"
	"github.com/unicitynetwork/bft-core/registryproof"
	bfttypes "github.com/unicitynetwork/bft-go-base/types"
)

// genesisFor builds the registrygenesis vector deployment (#153 §5.4 configuration, merged registry) with
// the given header parameters. Different parameters give a different, equally valid block.
func genesisFor(t testing.TB, evm registrygenesis.EVMParams) *registrygenesis.Genesis {
	return genesisForNetwork(t, 3, evm)
}

// genesisForNetwork varies the network, which changes G, the registry storage and the state root.
func genesisForNetwork(t testing.TB, network bfttypes.NetworkID, evm registrygenesis.EVMParams) *registrygenesis.Genesis {
	art, err := registrygenesis.PinnedArtifact()
	require.NoError(t, err)
	cfg := &bfttypes.PartitionDescriptionRecord{
		Version: 1, NetworkID: network, PartitionID: 8, T2Timeout: 5 * time.Second,
		PartitionParams: map[string]string{registrygenesis.ChainIDParam: "1337"}, Epoch: 0,
		Validators: []*bfttypes.NodeInfo{{NodeID: "validator-1", SigKey: append([]byte{0x02}, make([]byte, 32)...), Stake: 1}},
	}
	pins := registrygenesis.Pins{RootEpoch: 1, RegistryCodeHash: art.CodeHash, SystemAddress: registrygenesis.SystemAddress, RegistryAddress: registryproof.RegistryAddress}
	g, err := registrygenesis.Generate(cfg, pins, art, evm)
	require.NoError(t, err)
	return g
}

// rethGenesis is what the pinned reth served for the vector genesis (registrygenesis/testdata).
type rethGenesis struct {
	Hash   common.Hash
	Header string
	Proof  json.RawMessage
}

func loadRethGenesis(t testing.TB) rethGenesis {
	raw, err := os.ReadFile("../registrygenesis/testdata/reth-genesis-vector.json")
	require.NoError(t, err)
	var v struct {
		RPCBlock0Hash common.Hash     `json:"rpcBlock0Hash"`
		Header        string          `json:"header"`
		Proof         json.RawMessage `json:"proof"`
	}
	require.NoError(t, json.Unmarshal(raw, &v))
	return rethGenesis{Hash: v.RPCBlock0Hash, Header: v.Header, Proof: v.Proof}
}

// getProofJSON renders evidence in eth_getProof form.
func getProofJSON(t testing.TB, ev registryproof.Evidence) json.RawMessage {
	r := map[string]any{"address": registryproof.RegistryAddress.Hex(), "accountProof": hexList(ev.AccountProof)}
	var storage []any
	for i, p := range ev.StorageProofs {
		storage = append(storage, map[string]any{"key": registryproof.SlotKey(i).Hex(), "value": "0x0", "proof": hexList(p)})
	}
	r["storageProof"] = storage
	b, err := json.Marshal(r)
	require.NoError(t, err)
	return b
}

func hexList(nodes [][]byte) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = hexutil.Encode(n)
	}
	return out
}

type request struct {
	Method string            `json:"method"`
	Params []json.RawMessage `json:"params"`
}

// server is a stand-in JSON-RPC endpoint. respond returns the raw response body for a request.
type server struct {
	*httptest.Server
	mu       sync.Mutex
	requests []request
}

func newServer(t *testing.T, respond func(r request) string) *server {
	s := &server{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, hr *http.Request) {
		body, _ := io.ReadAll(hr.Body)
		var r request
		_ = json.Unmarshal(body, &r)
		s.mu.Lock()
		s.requests = append(s.requests, r)
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, respond(r))
	}))
	t.Cleanup(s.Close)
	return s
}

func result(v any) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "result": v})
	return string(b)
}

func rawResult(raw json.RawMessage) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"result":%s}`, raw)
}

func rpcError(code int, message string) string {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "error": map[string]any{"code": code, "message": message}})
	return string(b)
}

// honest replays the pinned reth's genesis responses for the genesis hash, and reth's unknown-block error
// for any other hash.
func honest(v rethGenesis) func(r request) string {
	return func(r request) string {
		var hash common.Hash
		if len(r.Params) > 0 {
			_ = json.Unmarshal(r.Params[0], &hash)
		}
		switch r.Method {
		case "debug_getRawHeader":
			if hash != v.Hash {
				return rpcError(-32001, "block not found: hash "+hash.Hex())
			}
			return result(v.Header)
		case "eth_getProof":
			var id struct {
				BlockHash common.Hash `json:"blockHash"`
			}
			if len(r.Params) == 3 {
				_ = json.Unmarshal(r.Params[2], &id)
			}
			if id.BlockHash != v.Hash {
				return rpcError(-32001, "block not found: hash "+id.BlockHash.Hex())
			}
			return rawResult(v.Proof)
		}
		return rpcError(-32601, "method not found")
	}
}

func caller(s *server) *HTTPCaller { return NewHTTPCaller(s.URL, 5*time.Second) }

// ctxBlindCaller is a Caller that does not wrap context errors, as a non-HTTP transport might not.
type ctxBlindCaller struct{}

func (ctxBlindCaller) Call(context.Context, string, []any) (json.RawMessage, error) {
	return nil, errors.New("transport closed")
}

func TestAcquireVerifiesThePinnedRethGenesisResponses(t *testing.T) {
	g := genesisFor(t, registrygenesis.DefaultEVMParams)
	v := loadRethGenesis(t)
	require.Equal(t, g.EVMGenesisHash(), v.Hash, "premise: the retained reth vector is for this genesis")
	s := newServer(t, honest(v))

	w, err := Acquire(context.Background(), caller(s), g.ProofContext(), v.Hash)
	require.NoError(t, err)
	require.True(t, w.Valid())
	require.Equal(t, v.Hash, w.Parent())
	require.True(t, w.Snapshot().Genesis())
	require.Equal(t, uint64(0), w.Snapshot().LastAppliedRootRound())

	// Every request names the block by its hash; no request uses a number or a tag.
	require.Len(t, s.requests, 2)
	require.Equal(t, "debug_getRawHeader", s.requests[0].Method)
	require.JSONEq(t, `"`+v.Hash.Hex()+`"`, string(s.requests[0].Params[0]))
	require.Equal(t, "eth_getProof", s.requests[1].Method)
	require.Len(t, s.requests[1].Params, 3)
	require.JSONEq(t, `"`+registryproof.RegistryAddress.Hex()+`"`, string(s.requests[1].Params[0]))
	require.JSONEq(t, `{"blockHash":"`+v.Hash.Hex()+`"}`, string(s.requests[1].Params[2]))
	var keys []common.Hash
	require.NoError(t, json.Unmarshal(s.requests[1].Params[1], &keys))
	for i := range keys {
		require.Equal(t, registryproof.SlotKey(i), keys[i])
	}
	for _, r := range s.requests {
		for _, p := range r.Params {
			for _, tag := range []string{"latest", "pending", "safe", "finalized", "earliest"} {
				require.NotContains(t, string(p), tag)
			}
		}
	}
}

func TestUnavailableEvidence(t *testing.T) {
	g := genesisFor(t, registrygenesis.DefaultEVMParams)
	v := loadRethGenesis(t)
	override := func(method, response string) func(request) string {
		return func(r request) string {
			if r.Method == method {
				return response
			}
			return honest(v)(r)
		}
	}
	for name, respond := range map[string]func(request) string{
		"proof window passed (reth -32602)": override("eth_getProof", rpcError(-32602, "distance to target block exceeds maximum proof window")),
		"unknown block (reth -32001)":       override("debug_getRawHeader", rpcError(-32001, "block not found: hash "+v.Hash.Hex())),
		"null header":                       override("debug_getRawHeader", result(nil)),
		"null proof":                        override("eth_getProof", result(nil)),
		"internal error":                    override("eth_getProof", rpcError(-32603, "internal error")),
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, respond)
			_, err := Acquire(context.Background(), caller(s), g.ProofContext(), v.Hash)
			require.ErrorIs(t, err, ErrUnavailable)
			require.ErrorIs(t, err, registryproof.ErrUnavailable)
			require.NotErrorIs(t, err, ErrInvalid)
		})
	}

	t.Run("HTTP 500", func(t *testing.T) {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) }))
		defer s.Close()
		_, err := Acquire(context.Background(), NewHTTPCaller(s.URL, time.Second), g.ProofContext(), v.Hash)
		require.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("connection refused", func(t *testing.T) {
		s := httptest.NewServer(http.NotFoundHandler())
		url := s.URL
		s.Close()
		_, err := Acquire(context.Background(), NewHTTPCaller(url, time.Second), g.ProofContext(), v.Hash)
		require.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("cancelled context", func(t *testing.T) {
		s := newServer(t, honest(v))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Acquire(ctx, caller(s), g.ProofContext(), v.Hash)
		require.ErrorIs(t, err, ErrUnavailable)
		require.ErrorIs(t, err, context.Canceled)
	})
	t.Run("a caller that ignores cancellation still reports it", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := Acquire(ctx, ctxBlindCaller{}, g.ProofContext(), v.Hash)
		require.ErrorIs(t, err, ErrUnavailable)
		require.ErrorIs(t, err, context.Canceled, "the context error is reported even when the Caller does not wrap it")
	})
	t.Run("timeout", func(t *testing.T) {
		release := make(chan struct{})
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		defer s.Close()
		defer close(release)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := Acquire(ctx, NewHTTPCaller(s.URL, 5*time.Second), g.ProofContext(), v.Hash)
		require.ErrorIs(t, err, ErrUnavailable)
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func TestInvalidEvidence(t *testing.T) {
	g := genesisFor(t, registrygenesis.DefaultEVMParams)
	v := loadRethGenesis(t)
	// Another valid genesis with different registry storage and state: the client answers for a different
	// block than the one asked for, as a client that substituted its head would.
	other := genesisForNetwork(t, 4, registrygenesis.DefaultEVMParams)
	require.NotEqual(t, g.EVMGenesisHash(), other.EVMGenesisHash())
	require.NotEqual(t, g.StateRoot(), other.StateRoot(), "premise: the other block has a different state")
	otherHeader := hexutil.Encode(other.Header())
	otherProof := getProofJSON(t, other.Evidence())

	truncated := func() json.RawMessage {
		var m map[string]any
		require.NoError(t, json.Unmarshal(v.Proof, &m))
		m["accountProof"] = []string{}
		b, _ := json.Marshal(m)
		return b
	}()
	foreign := func() json.RawMessage {
		var m map[string]any
		require.NoError(t, json.Unmarshal(v.Proof, &m))
		m["address"] = "0xff00000000000000000000000000000000000003"
		b, _ := json.Marshal(m)
		return b
	}()
	missingKey := func() json.RawMessage {
		var m map[string]any
		require.NoError(t, json.Unmarshal(v.Proof, &m))
		m["storageProof"] = m["storageProof"].([]any)[1:]
		b, _ := json.Marshal(m)
		return b
	}()

	type tc struct {
		header, proof string
		also          error
		message       string // the refusal names this check, not a later one
	}
	for name, c := range map[string]tc{
		"header is not hex":                    {header: result("0xzz"), proof: rawResult(v.Proof), message: "not hex bytes"},
		"header and proof of another block":    {header: result(otherHeader), proof: rawResult(otherProof), also: registryproof.ErrHeaderHash},
		"right header, another block's proof":  {header: result(v.Header), proof: rawResult(otherProof), also: registryproof.ErrAccountProof},
		"account proof emptied":                {header: result(v.Header), proof: rawResult(truncated), also: registryproof.ErrAccountProof},
		"proof for another address":            {header: result(v.Header), proof: rawResult(foreign), also: registryproof.ErrAccountProof},
		"a storage proof missing":              {header: result(v.Header), proof: rawResult(missingKey), also: registryproof.ErrStorageProof},
		"proof result is a string":             {header: result(v.Header), proof: result("0x00")},
		"response is not JSON-RPC":             {header: `"0x00"`, proof: rawResult(v.Proof), message: "not a valid JSON-RPC 2.0 response"},
		"response without the jsonrpc version": {header: `{"id":1,"result":"0x00"}`, proof: rawResult(v.Proof), message: "not a valid JSON-RPC 2.0 response"},
		"response lacks result and error":      {header: `{"jsonrpc":"2.0","id":1}`, proof: rawResult(v.Proof)},
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, func(r request) string {
				if r.Method == "debug_getRawHeader" {
					return c.header
				}
				return c.proof
			})
			_, err := Acquire(context.Background(), caller(s), g.ProofContext(), v.Hash)
			require.ErrorIs(t, err, ErrInvalid)
			require.NotErrorIs(t, err, ErrUnavailable)
			if c.also != nil {
				require.ErrorIs(t, err, c.also)
			}
			if c.message != "" {
				require.ErrorContains(t, err, c.message)
			}
		})
	}

	t.Run("oversized response", func(t *testing.T) {
		huge := result(strings.Repeat("0", MaxResponseBytes))
		s := newServer(t, func(request) string { return huge })
		_, err := Acquire(context.Background(), caller(s), g.ProofContext(), v.Hash)
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "exceeds")
	})
	t.Run("an oversized body that never ends is cut at the bound, not read to the timeout", func(t *testing.T) {
		chunk := strings.Repeat("0", 64<<10)
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":1,"result":"`)
			for sent := 0; sent <= MaxResponseBytes; sent += len(chunk) {
				_, _ = io.WriteString(w, chunk)
			}
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		}))
		defer s.Close()
		_, err := Acquire(context.Background(), NewHTTPCaller(s.URL, 3*time.Second), g.ProofContext(), v.Hash)
		require.ErrorIs(t, err, ErrInvalid)
		require.ErrorContains(t, err, "exceeds")
	})
	t.Run("evidence verified under another deployment's context", func(t *testing.T) {
		s := newServer(t, honest(v))
		_, err := Acquire(context.Background(), caller(s), other.ProofContext(), v.Hash)
		require.ErrorIs(t, err, ErrInvalid)
	})
	t.Run("zero parent", func(t *testing.T) {
		s := newServer(t, honest(v))
		_, err := Acquire(context.Background(), caller(s), g.ProofContext(), common.Hash{})
		require.ErrorIs(t, err, registryproof.ErrContext)
		require.Empty(t, s.requests, "nothing is requested for a zero parent")
	})
}

func TestStore(t *testing.T) {
	g := genesisFor(t, registrygenesis.DefaultEVMParams)
	v := loadRethGenesis(t)
	s := newServer(t, honest(v))

	store, err := NewStore(g.ProofContext(), 2)
	require.NoError(t, err)

	t.Run("nothing retained is unavailable, never another block's snapshot", func(t *testing.T) {
		_, err := store.ForChild(v.Hash)
		require.ErrorIs(t, err, ErrUnavailable)
	})

	w, err := store.AcquireAndCapture(context.Background(), caller(s), v.Hash)
	require.NoError(t, err)
	require.Equal(t, 1, store.Len())
	snap, err := store.ForChild(v.Hash)
	require.NoError(t, err)
	require.True(t, snap.Genesis())
	require.Equal(t, w.Snapshot().Fields(), snap.Fields())

	t.Run("a held witness does not answer for another parent", func(t *testing.T) {
		_, err := store.ForChild(common.Hash{1})
		require.ErrorIs(t, err, ErrUnavailable)
	})
	t.Run("the zero witness is refused", func(t *testing.T) {
		require.ErrorIs(t, store.Capture(Witness{}), ErrInvalid)
	})
	t.Run("a failed acquisition stores nothing", func(t *testing.T) {
		bad := newServer(t, func(r request) string {
			return rpcError(-32602, "distance to target block exceeds maximum proof window")
		})
		before := store.Len()
		_, err := store.AcquireAndCapture(context.Background(), caller(bad), common.Hash{2})
		require.ErrorIs(t, err, ErrUnavailable)
		require.Equal(t, before, store.Len())
	})
	t.Run("a witness verified under another context is not retained", func(t *testing.T) {
		other := genesisForNetwork(t, 4, registrygenesis.DefaultEVMParams)
		otherStore, err := NewStore(other.ProofContext(), 2)
		require.NoError(t, err)
		require.ErrorIs(t, otherStore.Capture(w), ErrInvalid)
		require.Equal(t, 0, otherStore.Len())
	})
	t.Run("copies leaving a witness do not reach the store", func(t *testing.T) {
		ev := w.Evidence()
		ev.Header[0] ^= 0xff
		ev.AccountProof[0][0] ^= 0xff
		_, err := store.ForChild(v.Hash)
		require.NoError(t, err)
	})
	t.Run("retained evidence is re-verified on every use", func(t *testing.T) {
		store.mu.Lock()
		ev := store.entries[v.Hash]
		ev.AccountProof[0][0] ^= 0xff
		store.mu.Unlock()
		_, err := store.ForChild(v.Hash)
		require.ErrorIs(t, err, ErrInvalid)
		store.mu.Lock()
		ev.AccountProof[0][0] ^= 0xff
		store.mu.Unlock()
		_, err = store.ForChild(v.Hash)
		require.NoError(t, err)
	})
	t.Run("capacity drops the oldest witness", func(t *testing.T) {
		small, err := NewStore(g.ProofContext(), 1)
		require.NoError(t, err)
		require.NoError(t, small.Capture(w))
		small.mu.Lock()
		// A second parent, retained directly: only one genesis exists for this context, so the eviction
		// order is exercised on the store's bookkeeping.
		small.order = append(small.order, common.Hash{3})
		small.entries[common.Hash{3}] = cloneEvidence(w.w.evidence)
		small.mu.Unlock()
		require.NoError(t, small.Capture(w), "re-capturing an existing parent refreshes it without duplicating it")
		require.Equal(t, 1, small.Len())
		_, err = small.ForChild(common.Hash{3})
		require.ErrorIs(t, err, ErrUnavailable, "the oldest entry was dropped")
		_, err = small.ForChild(v.Hash)
		require.NoError(t, err, "the re-captured parent is kept")
	})
	t.Run("capacity must be positive", func(t *testing.T) {
		_, err := NewStore(g.ProofContext(), 0)
		require.Error(t, err)
	})
}

func TestStoreConcurrentUse(t *testing.T) {
	g := genesisFor(t, registrygenesis.DefaultEVMParams)
	v := loadRethGenesis(t)
	s := newServer(t, honest(v))
	store, err := NewStore(g.ProofContext(), 4)
	require.NoError(t, err)
	w, err := Acquire(context.Background(), caller(s), g.ProofContext(), v.Hash)
	require.NoError(t, err)

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs <- store.Capture(w)
		}()
		go func() {
			defer wg.Done()
			if _, err := store.ForChild(v.Hash); err != nil && !errors.Is(err, ErrUnavailable) {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	_, err = store.ForChild(v.Hash)
	require.NoError(t, err)
}
