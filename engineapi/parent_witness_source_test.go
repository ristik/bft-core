package engineapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/shardnode"
)

func sourceProof(ev registryproof.Evidence) registryproof.GetProofResult {
	p := registryproof.GetProofResult{Address: registryproof.RegistryAddress}
	for _, n := range ev.AccountProof {
		p.AccountProof = append(p.AccountProof, hexutil.Bytes(bytes.Clone(n)))
	}
	for i := range ev.StorageProofs {
		sp := registryproof.StorageProofResult{Key: registryproof.SlotKey(i).Hex()}
		for _, n := range ev.StorageProofs[i] {
			sp.Proof = append(sp.Proof, hexutil.Bytes(bytes.Clone(n)))
		}
		p.StorageProof = append(p.StorageProof, sp)
	}
	return p
}

func sourceFixture(t *testing.T) (*certifiedchain.Chain, ParentWitnessPins, shardnode.BlockRef) {
	t.Helper()
	c := certifiedchain.New(t, 3, 2)
	pins := ParentWitnessPins{NetworkID: 3, PartitionID: 8, FullShardConfHash: c.Genesis.FullShardConfHash(), Registry: c.Genesis.ProofContext()}
	b := c.Blocks[1]
	return c, pins, shardnode.BlockRef{Number: b.Number, Hash: b.Hash.Bytes(), StateRoot: b.StateRoot.Bytes()}
}

func sourceServer(t *testing.T, b common.Hash, ev registryproof.Evidence, alter func(string, any) any) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		var req struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
			return
		}
		var result any
		switch req.Method {
		case "debug_getRawHeader":
			if len(req.Params) != 1 || string(req.Params[0]) != `"`+b.Hex()+`"` {
				t.Errorf("wrong header target %s", req.Params)
			}
			result = hexutil.Bytes(ev.Header)
		case "eth_getProof":
			if len(req.Params) != 3 {
				t.Errorf("wrong proof params %s", req.Params)
				return
			}
			if string(req.Params[0]) != `"`+registryproof.RegistryAddress.Hex()+`"` {
				t.Errorf("wrong registry %s", req.Params[0])
			}
			var keys []string
			if err := json.Unmarshal(req.Params[1], &keys); err != nil {
				t.Error(err)
			}
			if len(keys) != registryproof.FieldCount {
				t.Errorf("wrong key count %d", len(keys))
			}
			for i, key := range keys {
				if key != registryproof.SlotKey(i).Hex() {
					t.Errorf("wrong key %d: %s", i, key)
				}
			}
			if string(req.Params[2]) != `{"blockHash":"`+b.Hex()+`"}` {
				t.Errorf("wrong proof target %s", req.Params[2])
			}
			result = sourceProof(ev)
		default:
			t.Errorf("unexpected RPC %s", req.Method)
		}
		if alter != nil {
			result = alter(req.Method, result)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	return s, &calls
}

func TestParentWitnessSourceExactCertifiedParent(t *testing.T) {
	c, pins, parent := sourceFixture(t)
	s, calls := sourceServer(t, c.Blocks[1].Hash, c.Blocks[1].Evidence, nil)
	defer s.Close()
	source, err := NewParentWitnessSource(context.Background(), pins, registrywitness.NewHTTPCaller(s.URL, time.Second), DefaultParentWitnessBudget())
	require.NoError(t, err)
	defer source.Close()
	snapshot, err := source.Acquire(context.Background(), parent)
	require.NoError(t, err)
	require.Equal(t, parent.Number, snapshot.Number())
	require.Equal(t, common.BytesToHash(parent.StateRoot), snapshot.StateRoot())
	require.EqualValues(t, 2, calls.Load())
	_, err = source.Acquire(context.Background(), shardnode.BlockRef{Number: 0, Hash: c.Blocks[0].Hash.Bytes(), StateRoot: c.Blocks[0].StateRoot.Bytes()})
	require.ErrorIs(t, err, ErrParentWitnessMismatch)
	require.EqualValues(t, 2, calls.Load(), "genesis must never cause proof RPC")
}

func TestParentWitnessSourceRefusesMismatchedAndInvalidEvidence(t *testing.T) {
	c, pins, parent := sourceFixture(t)
	for _, tc := range []struct {
		name  string
		alter func(string, any) any
		want  error
	}{
		{"wrong header", func(m string, v any) any {
			if m == "debug_getRawHeader" {
				return hexutil.Bytes(c.Blocks[0].Evidence.Header)
			}
			return v
		}, ErrParentWitnessInvalid},
		{"missing key", func(m string, v any) any {
			if m == "eth_getProof" {
				p := v.(registryproof.GetProofResult)
				p.StorageProof = p.StorageProof[:21]
				return p
			}
			return v
		}, ErrParentWitnessInvalid},
		{"duplicate key", func(m string, v any) any {
			if m == "eth_getProof" {
				p := v.(registryproof.GetProofResult)
				p.StorageProof[1].Key = p.StorageProof[0].Key
				return p
			}
			return v
		}, ErrParentWitnessInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := sourceServer(t, c.Blocks[1].Hash, c.Blocks[1].Evidence, tc.alter)
			defer s.Close()
			source, err := NewParentWitnessSource(context.Background(), pins, registrywitness.NewHTTPCaller(s.URL, time.Second), DefaultParentWitnessBudget())
			require.NoError(t, err)
			defer source.Close()
			_, err = source.Acquire(context.Background(), parent)
			require.ErrorIs(t, err, tc.want)
		})
	}
	parent.StateRoot = bytes.Repeat([]byte{0xaa}, 32)
	s, _ := sourceServer(t, c.Blocks[1].Hash, c.Blocks[1].Evidence, nil)
	defer s.Close()
	source, err := NewParentWitnessSource(context.Background(), pins, registrywitness.NewHTTPCaller(s.URL, time.Second), DefaultParentWitnessBudget())
	require.NoError(t, err)
	defer source.Close()
	_, err = source.Acquire(context.Background(), parent)
	require.ErrorIs(t, err, ErrParentWitnessMismatch)
	pins.Registry.RegistryCodeHash = common.HexToHash("0x01")
	wrong, err := NewParentWitnessSource(context.Background(), pins, registrywitness.NewHTTPCaller(s.URL, time.Second), DefaultParentWitnessBudget())
	require.NoError(t, err)
	defer wrong.Close()
	_, err = wrong.Acquire(context.Background(), shardnode.BlockRef{Number: 1, Hash: c.Blocks[1].Hash.Bytes(), StateRoot: c.Blocks[1].StateRoot.Bytes()})
	require.ErrorIs(t, err, ErrParentWitnessInvalid)
}

func TestParentWitnessSourceShutdownCancelsAcquisition(t *testing.T) {
	_, pins, parent := sourceFixture(t)
	started := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(started)
		<-r.Context().Done()
	}))
	defer s.Close()
	source, err := NewParentWitnessSource(context.Background(), pins, registrywitness.NewHTTPCaller(s.URL, time.Second), DefaultParentWitnessBudget())
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { _, e := source.Acquire(context.Background(), parent); done <- e }()
	<-started
	source.Close()
	select {
	case err := <-done:
		require.True(t, errors.Is(err, ErrParentWitnessStopped) || errors.Is(err, ErrParentWitnessBudget))
	case <-time.After(time.Second):
		t.Fatal("acquisition did not stop")
	}
}
