package registrywitness

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/registrygenesis"
)

// TestReview158MalformedEnvelopesAreInvalid is the review's reproduction (#158), unchanged apart from
// formatting: each envelope defect, applied to every honest response, must be invalid evidence.
func TestReview158MalformedEnvelopesAreInvalid(t *testing.T) {
	g := genesisFor(t, registrygenesis.DefaultEVMParams)
	v := loadRethGenesis(t)
	for name, change := range map[string]func(string) string{
		"wrong response ID":   func(s string) string { return strings.Replace(s, `"id":1`, `"id":999`, 1) },
		"missing response ID": func(s string) string { return strings.Replace(s, `"id":1,`, ``, 1) },
		"result and error": func(s string) string {
			return strings.Replace(s, `"jsonrpc":"2.0"`, `"jsonrpc":"2.0","error":{"code":-32001,"message":"block not found"}`, 1)
		},
		"malformed error object": func(string) string { return `{"jsonrpc":"2.0","id":1,"error":{}}` },
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, func(r request) string { return change(honest(v)(r)) })
			w, err := Acquire(context.Background(), caller(s), g.ProofContext(), v.Hash)
			require.ErrorIs(t, err, ErrInvalid)
			require.NotErrorIs(t, err, ErrUnavailable)
			require.False(t, w.Valid())
		})
	}
}

// Every envelope rule on both the success and the error path. A malformed envelope is invalid even when
// its content would otherwise be a genuine proof or a genuine unavailability error.
func TestEnvelopeValidation(t *testing.T) {
	g := genesisFor(t, registrygenesis.DefaultEVMParams)
	v := loadRethGenesis(t)
	windowError := `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"distance to target block exceeds maximum proof window"}}`

	// onProof replaces the eth_getProof response; the header response stays honest.
	onProof := func(response string) func(request) string {
		return func(r request) string {
			if r.Method == "eth_getProof" {
				return response
			}
			return honest(v)(r)
		}
	}
	proofResult := func(envelope string) string { return strings.Replace(envelope, "RESULT", string(v.Proof), 1) }

	for name, tc := range map[string]struct {
		response string
		want     error
		message  string
	}{
		// Valid envelopes keep their documented classes.
		"valid result":                    {proofResult(`{"jsonrpc":"2.0","id":1,"result":RESULT}`), nil, ""},
		"valid result, members reordered": {proofResult(`{"result":RESULT,"id":1,"jsonrpc":"2.0"}`), nil, ""},
		"valid null result":               {`{"jsonrpc":"2.0","id":1,"result":null}`, ErrUnavailable, "null result"},
		"valid proof-window error":        {windowError, ErrUnavailable, "proof window"},
		"valid error with data":           {`{"jsonrpc":"2.0","id":1,"error":{"code":-32001,"message":"block not found","data":{"x":1}}}`, ErrUnavailable, ""},

		// Identity.
		"id as a string":           {proofResult(`{"jsonrpc":"2.0","id":"1","result":RESULT}`), ErrInvalid, `"id"`},
		"id null":                  {proofResult(`{"jsonrpc":"2.0","id":null,"result":RESULT}`), ErrInvalid, `"id"`},
		"id with a fraction":       {proofResult(`{"jsonrpc":"2.0","id":1.0,"result":RESULT}`), ErrInvalid, `"id"`},
		"id with an exponent":      {proofResult(`{"jsonrpc":"2.0","id":1e0,"result":RESULT}`), ErrInvalid, `"id"`},
		"error with another id":    {strings.Replace(windowError, `"id":1`, `"id":2`, 1), ErrInvalid, `"id"`},
		"error without an id":      {strings.Replace(windowError, `"id":1,`, ``, 1), ErrInvalid, `"id"`},
		"version missing":          {proofResult(`{"id":1,"result":RESULT}`), ErrInvalid, `"jsonrpc"`},
		"version 1.0":              {proofResult(`{"jsonrpc":"1.0","id":1,"result":RESULT}`), ErrInvalid, `"jsonrpc"`},
		"version as a number":      {proofResult(`{"jsonrpc":2.0,"id":1,"result":RESULT}`), ErrInvalid, `"jsonrpc"`},
		"not an object":            {`["jsonrpc","2.0"]`, ErrInvalid, "not a JSON object"},
		"JSON null":                {`null`, ErrInvalid, "not a JSON object"},
		"result with error null":   {proofResult(`{"jsonrpc":"2.0","id":1,"result":RESULT,"error":null}`), ErrInvalid, "both"},
		"neither result nor error": {`{"jsonrpc":"2.0","id":1}`, ErrInvalid, "neither"},

		// Error objects.
		"error is null":            {`{"jsonrpc":"2.0","id":1,"error":null}`, ErrInvalid, `"error" is not an object`},
		"error is a string":        {`{"jsonrpc":"2.0","id":1,"error":"unavailable"}`, ErrInvalid, `"error" is not an object`},
		"error without a code":     {`{"jsonrpc":"2.0","id":1,"error":{"message":"x"}}`, ErrInvalid, `"code"`},
		"error code as a string":   {`{"jsonrpc":"2.0","id":1,"error":{"code":"-32602","message":"x"}}`, ErrInvalid, `"error.code"`},
		"error code with fraction": {`{"jsonrpc":"2.0","id":1,"error":{"code":-32602.5,"message":"x"}}`, ErrInvalid, `"error.code"`},
		"error code null":          {`{"jsonrpc":"2.0","id":1,"error":{"code":null,"message":"x"}}`, ErrInvalid, `"error.code"`},
		"error without a message":  {`{"jsonrpc":"2.0","id":1,"error":{"code":-32602}}`, ErrInvalid, `"error.message"`},
		"error message a number":   {`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":5}}`, ErrInvalid, `"error.message"`},
		"error message null":       {`{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":null}}`, ErrInvalid, `"error.message"`},
	} {
		t.Run(name, func(t *testing.T) {
			s := newServer(t, onProof(tc.response))
			w, err := Acquire(context.Background(), caller(s), g.ProofContext(), v.Hash)
			if tc.want == nil {
				require.NoError(t, err)
				require.True(t, w.Valid())
				return
			}
			require.ErrorIs(t, err, tc.want)
			if tc.want == ErrInvalid {
				require.NotErrorIs(t, err, ErrUnavailable)
			} else {
				require.NotErrorIs(t, err, ErrInvalid)
			}
			if tc.message != "" {
				require.ErrorContains(t, err, tc.message)
			}
			require.False(t, w.Valid())
		})
	}
}
