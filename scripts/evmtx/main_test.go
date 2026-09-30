package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSendRawAlreadyKnownReturnsSubmittedTransactionHash(t *testing.T) {
	raw := []byte{0x02, 0x01, 0x02, 0x03}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"already known"}}`)
	}))
	defer server.Close()

	hash, err := sendRaw(server.URL, raw)
	require.NoError(t, err)
	require.Equal(t, "0x"+hex.EncodeToString(keccak(raw)), hash)
}

func TestSendRawDoesNotTreatOtherNodeErrorsAsAlreadyKnown(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"nonce too low"}}`)
	}))
	defer server.Close()

	_, err := sendRaw(server.URL, []byte{0x02, 0x01})
	require.EqualError(t, err, "eth_sendRawTransaction: nonce too low")
}
