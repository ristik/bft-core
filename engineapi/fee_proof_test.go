package engineapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/shardnode"
)

func TestVerifyTreatsLocalFeeProofFailuresAsRetryable(t *testing.T) {
	verifier, params, want := bootstrapAdapterFixture(t)
	engine := newMockReth(t, Secret{})
	var imports atomic.Int32
	engine.on("engine_newPayloadWithSealV1", func(json.RawMessage) (any, *rpcError) {
		imports.Add(1)
		return PayloadStatusV1{Status: PayloadStatusValid}, nil
	})
	faults := []struct {
		status int
		body   string
		detail string
	}{
		{http.StatusUnauthorized, "", "HTTP 401"},
		{http.StatusRequestTimeout, "", "HTTP 408"},
		{http.StatusTooManyRequests, "", "HTTP 429"},
		{http.StatusInternalServerError, "", "HTTP 500"},
		{http.StatusBadGateway, "", "HTTP 502"},
		{http.StatusServiceUnavailable, "", "HTTP 503"},
		{http.StatusGatewayTimeout, "", "HTTP 504"},
		{http.StatusOK, `{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"block not found"}}`, "block not found"},
		{http.StatusOK, `{"jsonrpc":"2.0","id":1,"result":[]}`, "decoding result"},
		{http.StatusOK, strings.Repeat(" ", maxFeeProofResponseBytes+8192), "exceeds limit"},
	}
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
			attempt := int(rpcCalls.Add(1)) - 1
			if attempt < len(faults) {
				fault := faults[attempt]
				w.WriteHeader(fault.status)
				_, _ = io.WriteString(w, fault.body)
				return
			}
			reply["result"] = json.RawMessage(`{}`)
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

	for _, fault := range faults {
		status, err := a.Verify(t.Context(), block, params)
		require.Equal(t, shardnode.StatusSyncing, status, "%v", err)
		require.ErrorIs(t, err, ErrFeeProofUnavailable)
		require.ErrorContains(t, err, fault.detail)
		var transient interface{ TransientVerify() bool }
		require.ErrorAs(t, err, &transient)
		require.True(t, transient.TransientVerify())
		require.Zero(t, imports.Load())
	}
	status, err := a.Verify(t.Context(), block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusValid, status)
	require.EqualValues(t, 1, imports.Load())

	// A different collector from authenticated state still rejects the same candidate.
	a.resolveCollector = func(context.Context, *EthClient, shardnode.BlockRef) ([20]byte, error) {
		return [20]byte{19: 0x42}, nil
	}
	status, err = a.Verify(t.Context(), block, params)
	require.NoError(t, err)
	require.Equal(t, shardnode.StatusInvalid, status)
	require.ErrorContains(t, a.CheckBlockBinding(t.Context(), block, params), "wrong VR fee collector")
	require.EqualValues(t, 1, imports.Load())

	a.resolveCollector = func(context.Context, *EthClient, shardnode.BlockRef) ([20]byte, error) {
		return [20]byte{}, ErrFeeProofOversized
	}
	err = a.CheckBlockBinding(t.Context(), block, params)
	require.ErrorIs(t, err, shardnode.ErrBlockBindingUnavailable)
	require.ErrorIs(t, err, ErrFeeProofOversized)

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
			response := strings.Repeat(" ", maxFeeProofResponseBytes+8192)
			counter := &feeProofCountReader{Reader: strings.NewReader(response)}
			client := NewEthClient("http://local.test")
			client.http.Transport = feeProofTransport(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, ContentLength: -1, Body: io.NopCloser(counter)}, nil
			})
			var proof any
			err := client.CallContext(t.Context(), &proof, "eth_getProof")
			require.ErrorIs(t, err, ErrFeeProofOversized)
			require.Equal(t, maxFeeProofResponseBytes+1, counter.bytes)
			require.Nil(t, proof)
		})
	}
}
