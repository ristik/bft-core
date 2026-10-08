package cmd

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/unicitynetwork/bft-core/rootchain/consensus"
	rctypes "github.com/unicitynetwork/bft-core/rootchain/consensus/types"
)

type posControlStub struct {
	err     error
	calls   int
	control rctypes.PosControl
	witness []byte
}

func (s *posControlStub) SubmitPosControl(_ context.Context, c rctypes.PosControl, w []byte) error {
	s.calls++
	s.control, s.witness = c, w
	return s.err
}

func TestRootPosControlHTTPIsLocalBoundedAndMapsRefusals(t *testing.T) {
	control := rctypes.PosControl{Network: 5, Op: rctypes.OpRetirement, Retire: &rctypes.RetireContext{}, Data: make([]byte, 96)}
	item, err := control.MarshalCBOR()
	require.NoError(t, err)
	body := func(c, w []byte) string {
		b, err := json.Marshal(map[string]string{"control": "0x" + hex.EncodeToString(c), "witness": "0x" + hex.EncodeToString(w)})
		require.NoError(t, err)
		return string(b)
	}
	do := func(h http.HandlerFunc, addr, payload string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/pos/control", bytes.NewBufferString(payload))
		r.RemoteAddr = addr
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h(w, r)
		return w
	}
	stub := &posControlStub{}
	h := rootPosControlHandler(stub)

	require.Equal(t, http.StatusForbidden, do(h, "192.0.2.1:1", body(item, []byte("w"))).Code)
	require.Equal(t, http.StatusBadRequest, do(h, "127.0.0.1:1", `{`).Code)
	require.Equal(t, http.StatusBadRequest, do(h, "127.0.0.1:1", body(item, nil)).Code, "no witness")
	require.Equal(t, http.StatusBadRequest, do(h, "127.0.0.1:1", body(item[:len(item)-1], []byte("w"))).Code, "a malformed control item")
	require.Equal(t, http.StatusBadRequest, do(h, "127.0.0.1:1", body(item, bytes.Repeat([]byte{1}, maxPosControlRequest))).Code, "oversized")
	require.Zero(t, stub.calls, "nothing reaches the node before the request is local, bounded and well formed")

	ok := do(h, "127.0.0.1:1", body(item, []byte("w")))
	require.Equal(t, http.StatusNoContent, ok.Code)
	require.Equal(t, 1, stub.calls)
	require.Equal(t, control, stub.control)
	require.Equal(t, []byte("w"), stub.witness)

	stub.err = errors.Join(consensus.ErrPosSubmission, errors.New("stale"))
	require.Equal(t, http.StatusUnprocessableEntity, do(h, "127.0.0.1:1", body(item, []byte("w"))).Code)
	stub.err = errors.New("disk")
	require.Equal(t, http.StatusInternalServerError, do(h, "127.0.0.1:1", body(item, []byte("w"))).Code)
}
