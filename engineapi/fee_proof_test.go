package engineapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/registrywitness"
	"github.com/unicitynetwork/bft-core/shardnode"
)

func TestVerifyRetriesUnavailableFeeProofAndRejectsInvalidProof(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine := newMockReth(t, Secret{})
	var imports atomic.Int32
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		imports.Add(1)
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	var rpcCalls atomic.Int32
	eth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		reply := map[string]any{"jsonrpc": "2.0", "id": request.ID}
		switch request.Method {
		case "eth_getBlockByHash":
			reply["result"] = blockHeaderJSON{Hash: data32(verifier.GenesisOrigin.BlockHash())}
		case "eth_getProof":
			switch rpcCalls.Add(1) {
			case 1:
				reply["error"] = &rpcError{Code: -32001, Message: "block not found"}
			case 2:
				reply["result"] = json.RawMessage(`{}`)
			default:
				reply["result"] = json.RawMessage(`[]`)
			}
		default:
			t.Errorf("unexpected request: %s", request.Method)
		}
		if err := json.NewEncoder(w).Encode(reply); err != nil {
			t.Error(err)
		}
	}))
	defer eth.Close()
	a, closeFn := newTestAdapterWithVerifier(t, engine, newMockReth(t, Secret{}), verifier)
	defer closeFn()
	a.eth = NewEthClient(eth.URL)
	a.feeCollector = [20]byte{19: 0xad}
	a.resolveCollector = func(ctx context.Context, client *EthClient, _ shardnode.BlockRef) ([20]byte, error) {
		var proof struct{}
		if err := client.CallContext(ctx, &proof, "eth_getProof"); err != nil {
			return [20]byte{}, err
		}
		return a.feeCollector, nil
	}
	attrs := DeriveAttributesV2(want.Input, ParentHeader{}, a.feeCollector)
	payload := samplePayload()
	payload.ParentHash = data32(verifier.GenesisOrigin.BlockHash())
	payload.BlockNumber = 1
	payload.Timestamp = attrs.Timestamp
	payload.PrevRandao = attrs.PrevRandao
	payload.FeeRecipient = attrs.SuggestedFeeRecipient
	payload.ExtraData = want.Commitment[:]
	payload.Withdrawals = attrs.Withdrawals
	witnesses, err := encodeSealCompanionWitnesses(params.AuthorizingCertificate, params.AuthorizingTechnicalRecord)
	require.NoError(t, err)
	block, err := EncodeBlockWithSealCompanion(payload, &SealCompanion{RootInput: want.Encoded, Witnesses: witnesses, Provenance: "build"})
	require.NoError(t, err)

	status, err := a.Verify(t.Context(), block, params)
	require.Equal(t, shardnode.StatusSyncing, status, "%v", err)
	require.ErrorIs(t, err, ErrFeeProofUnavailable)
	var transient interface{ TransientVerify() bool }
	require.ErrorAs(t, err, &transient)
	require.True(t, transient.TransientVerify())
	require.Zero(t, imports.Load())

	status, err = a.Verify(t.Context(), block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
	require.EqualValues(t, 1, imports.Load())

	status, err = a.Verify(t.Context(), block, params)
	require.Equal(t, shardnode.StatusInvalid, status, "%v", err)
	require.ErrorContains(t, err, "decoding result")
	require.False(t, errors.As(err, &transient))
	require.EqualValues(t, 1, imports.Load())
}

type feeProofTransport func(*http.Request) (*http.Response, error)

func (rt feeProofTransport) RoundTrip(req *http.Request) (*http.Response, error) { return rt(req) }

type feeProofCountReader struct {
	io.Reader
	bytes int
}

func (r *feeProofCountReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.bytes += n
	return n, err
}

func TestFeeProofResponseReadIsBoundedBeforeDecoding(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusServiceUnavailable} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			response := strings.Repeat(" ", registrywitness.MaxResponseBytes+8192)
			counter := &feeProofCountReader{Reader: strings.NewReader(response)}
			client := NewEthClient("http://local.test")
			client.http.Transport = feeProofTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, ContentLength: -1, Body: io.NopCloser(counter)}, nil
			})
			var proof any
			err := client.CallContext(t.Context(), &proof, "eth_getProof")
			require.ErrorIs(t, err, ErrFeeProofOversized)
			require.Equal(t, registrywitness.MaxResponseBytes+1, counter.bytes)
			require.False(t, isFeeProofUnavailable(err))
			require.Nil(t, proof)
		})
	}
}
