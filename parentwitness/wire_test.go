package parentwitness

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/unicitynetwork/bft-core/internal/testutils/certifiedchain"
	"github.com/unicitynetwork/bft-core/registryproof"
	"github.com/unicitynetwork/bft-go-base/types"
)

func fixtureTarget(t *testing.T) (*certifiedchain.Chain, Target) {
	t.Helper()
	c := certifiedchain.New(t, 3, 1)
	pc := registryproof.Context{RegistryAddress: registryproof.RegistryAddress, RegistryCodeHash: c.Pins.RegistryCodeHash, GenesisCommitment: c.Genesis.GenesisCommitment(), FullShardConfHash: c.Genesis.FullShardConfHash(), ShardEpoch: 0, RootEpoch: 1, EVMGenesisHash: c.Blocks[0].Hash}
	target, err := NewTarget(TargetConfig{NetworkID: 3, PartitionID: 8, ShardID: types.ShardID{}, FullShardConfHash: pc.FullShardConfHash, Registry: pc, BlockHash: c.Blocks[1].Hash})
	require.NoError(t, err)
	return c, target
}

func TestVerifiedFoundAndOwnedBoundaries(t *testing.T) {
	c, target := fixtureTarget(t)
	r := Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: c.Blocks[1].Evidence}
	raw, err := EncodeResponse(r)
	require.NoError(t, err)
	r.Evidence.Header[0] ^= 1
	verified, err := VerifyResponse(target, raw)
	require.NoError(t, err)
	require.True(t, verified.Valid())
	require.True(t, verified.Found())
	require.Equal(t, OutcomeFound, verified.Outcome())
	require.Equal(t, c.Blocks[1].StateRoot, verified.Snapshot().StateRoot())
	e := verified.Evidence()
	e.Header[0] ^= 1
	require.NotEqual(t, e.Header, verified.Evidence().Header)
}

func TestExactEchoAndLocalVerification(t *testing.T) {
	c, target := fixtureTarget(t)
	for name, mutate := range map[string]func(*Response){
		"block":   func(r *Response) { r.Request.BlockHash[0] ^= 1 },
		"context": func(r *Response) { r.Request.Context.RootEpoch++ },
	} {
		t.Run(name, func(t *testing.T) {
			r := Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: c.Blocks[1].Evidence}
			mutate(&r)
			raw, err := EncodeResponse(r)
			require.NoError(t, err)
			_, err = VerifyResponse(target, raw)
			require.ErrorIs(t, err, ErrContext)
		})
	}
	r := Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: c.Blocks[1].Evidence}
	r.Evidence.Header = bytes.Clone(r.Evidence.Header)
	r.Evidence.Header[20] ^= 1
	raw, err := EncodeResponse(r)
	require.NoError(t, err)
	_, err = VerifyResponse(target, raw)
	require.ErrorIs(t, err, registryproof.ErrHeaderHash)
}

func TestHighBitsCannotAliasLocalContext(t *testing.T) {
	_, target := fixtureTarget(t)
	for name, mutate := range map[string]func(*contextWire){
		"network":   func(c *contextWire) { c.NetworkID += 1 << 16 },
		"partition": func(c *contextWire) { c.PartitionID += 1 << 32 },
	} {
		t.Run(name+" request", func(t *testing.T) {
			w := requestWire{Version: Version, Context: contextToWire(target.request.Context), BlockHash: target.request.BlockHash.Bytes()}
			mutate(&w.Context)
			raw, err := marshalCanonical(w)
			require.NoError(t, err)
			_, err = DecodeRequest(raw)
			require.ErrorIs(t, err, ErrWire)
		})
		t.Run(name+" response", func(t *testing.T) {
			w := responseWire{Version: Version, Context: contextToWire(target.request.Context), BlockHash: target.request.BlockHash.Bytes(), Outcome: uint64(OutcomeBusy)}
			mutate(&w.Context)
			raw, err := marshalCanonical(w)
			require.NoError(t, err)
			_, err = VerifyResponse(target, raw)
			require.ErrorIs(t, err, ErrWire)
		})
	}
}

func TestOutcomesEvidenceAndCanonicalRefusals(t *testing.T) {
	_, target := fixtureTarget(t)
	for outcome := OutcomeUnavailable; outcome <= OutcomeInvalidRequest; outcome++ {
		raw, err := EncodeResponse(Response{Request: target.Request(), Outcome: outcome, Detail: "bounded"})
		require.NoError(t, err)
		got, err := VerifyResponse(target, raw)
		require.NoError(t, err)
		require.True(t, got.Valid())
		require.False(t, got.Found())
		require.Equal(t, outcome, got.Outcome())
	}
	_, err := EncodeResponse(Response{Request: target.Request(), Outcome: OutcomeBusy, Evidence: registryproof.Evidence{Header: []byte{1}}})
	require.ErrorIs(t, err, ErrWire)
	raw, err := EncodeResponse(Response{Request: target.Request(), Outcome: OutcomeBusy})
	require.NoError(t, err)
	noncanonical := append([]byte{0x9f}, raw[1:]...)
	noncanonical = append(noncanonical, 0xff)
	_, err = VerifyResponse(target, noncanonical)
	require.ErrorIs(t, err, ErrWire)
}

func TestPredecodeCBORBounds(t *testing.T) {
	for name, raw := range map[string][]byte{
		"node bytes":  append([]byte{0x59, 0x04, 0x01}, make([]byte, 1025)...),
		"array count": {0x99, 0x08, 0x01},
		"indefinite":  {0x9f, 0xff},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateCBORBounds(raw)
			require.Error(t, err)
		})
	}
}

func TestFramingRejectsOversizeBeforeBodyRead(t *testing.T) {
	var prefix [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(prefix[:], MaxRequestBytes+1)
	tracked := &prefixGuardReader{prefix: bytes.Clone(prefix[:n])}
	_, err := ReadRequestFrame(tracked)
	require.ErrorIs(t, err, ErrBounds)
	require.Equal(t, n, tracked.read)
	require.False(t, tracked.overread, "oversize admission never asks the underlying reader for body bytes")
}

func TestVerifyResponseChecksFrameBoundBeforeDecode(t *testing.T) {
	_, target := fixtureTarget(t)
	raw := make([]byte, MaxResponseBytes+1)
	_, err := VerifyResponse(target, raw)
	require.ErrorIs(t, err, ErrBounds)
	owned, err := cloneBoundedResponse(raw)
	require.ErrorIs(t, err, ErrBounds)
	require.Nil(t, owned, "the bound helper returns no owned allocation for oversized input")
}

func TestFramingRejectsShortWrites(t *testing.T) {
	_, target := fixtureTarget(t)
	err := WriteRequestFrame(shortWriter{}, target.Request())
	require.ErrorIs(t, err, io.ErrShortWrite)
}

func TestTargetCopiesMutableInputs(t *testing.T) {
	_, target := fixtureTarget(t)
	r := target.Request()
	r.Context.ShardID, _ = shardFromBytes([]byte{0x40})
	require.Empty(t, target.Request().Context.ShardID)
	_, err := registryproof.Verify(target.registry, target.request.BlockHash, registryproof.Evidence{})
	require.ErrorIs(t, err, registryproof.ErrUnavailable)
}

type prefixGuardReader struct {
	prefix   []byte
	read     int
	overread bool
}

func (r *prefixGuardReader) Read(p []byte) (int, error) {
	remaining := len(r.prefix) - r.read
	if remaining == 0 {
		return 0, io.EOF
	}
	if len(p) > remaining {
		r.overread = true
		return 0, errors.New("reader was asked to cross from prefix into body")
	}
	n := copy(p, r.prefix[r.read:])
	r.read += n
	return n, nil
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

func TestWorstCaseResponseFitsFrozenCap(t *testing.T) {
	_, target := fixtureTarget(t)
	// This uneven distribution is larger on the wire than equal-size nodes because 970 nodes
	// cross CBOR's 256-byte threshold and gain a third length-prefix byte.
	nodes := make([][]byte, 23*65)
	for i := range nodes[:970] {
		nodes[i] = bytes.Repeat([]byte{byte(i)}, 256)
	}
	for i := 970; i < 970+524; i++ {
		nodes[i] = bytes.Repeat([]byte{byte(i)}, 24)
	}
	nodes[len(nodes)-1] = bytes.Repeat([]byte{1}, 224)
	var nodeBytes int
	for _, n := range nodes {
		nodeBytes += len(n)
	}
	require.Equal(t, MaxEvidenceBytes-1024, nodeBytes)
	ev := registryproof.Evidence{Header: bytes.Repeat([]byte{1}, 1024), AccountProof: nodes[:65], StorageProofs: make([][][]byte, registryproof.FieldCount)}
	for i := range ev.StorageProofs {
		ev.StorageProofs[i] = nodes[65+i*65 : 65+(i+1)*65]
	}
	raw, err := EncodeResponse(Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: ev})
	require.NoError(t, err)
	require.LessOrEqual(t, len(raw), MaxResponseBytes)
	require.Equal(t, 266357, len(raw), "freeze adversarial prefix distribution with fixture context")
	require.LessOrEqual(t, len(raw)+(35-2)+(202-1), MaxFoundResponseBytesUpperBound)
	require.Less(t, MaxFoundResponseBytesUpperBound, MaxResponseBytes)
}
