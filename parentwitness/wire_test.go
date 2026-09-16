package parentwitness

import (
	"bufio"
	"bytes"
	"encoding/binary"
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
	require.Equal(t, OutcomeFound, verified.Outcome)
	require.Equal(t, c.Blocks[1].StateRoot, verified.Snapshot.StateRoot())
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

func TestOutcomesEvidenceAndCanonicalRefusals(t *testing.T) {
	_, target := fixtureTarget(t)
	for outcome := OutcomeUnavailable; outcome <= OutcomeInvalidRequest; outcome++ {
		raw, err := EncodeResponse(Response{Request: target.Request(), Outcome: outcome, Detail: "bounded"})
		require.NoError(t, err)
		got, err := VerifyResponse(target, raw)
		require.NoError(t, err)
		require.Equal(t, outcome, got.Outcome)
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
	tracked := &oneByteReader{data: append(prefix[:n], 0xaa)}
	r := bufio.NewReaderSize(tracked, 16)
	_, err := ReadRequestFrame(r)
	require.ErrorIs(t, err, ErrBounds)
	require.Equal(t, n, tracked.read, "oversize admission consumes only the declared-length prefix")
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

type oneByteReader struct {
	data []byte
	read int
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if r.read == len(r.data) {
		return 0, io.EOF
	}
	p[0] = r.data[r.read]
	r.read++
	return 1, nil
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
	// 23 proof lists × 65 nodes is the maximum list overhead. Aggregate node bytes, including
	// the header, remain capped at 256 KiB, so distribute the remaining bytes across the nodes.
	nodes := make([][]byte, 23*65)
	remaining := MaxEvidenceBytes - 1024
	for i := range nodes {
		n := remaining / (len(nodes) - i)
		if n > 1024 {
			n = 1024
		}
		nodes[i] = bytes.Repeat([]byte{byte(i)}, n)
		remaining -= n
	}
	ev := registryproof.Evidence{Header: bytes.Repeat([]byte{1}, 1024), AccountProof: nodes[:65], StorageProofs: make([][][]byte, registryproof.FieldCount)}
	for i := range ev.StorageProofs {
		ev.StorageProofs[i] = nodes[65+i*65 : 65+(i+1)*65]
	}
	raw, err := EncodeResponse(Response{Request: target.Request(), Outcome: OutcomeFound, Evidence: ev})
	require.NoError(t, err)
	require.LessOrEqual(t, len(raw), MaxResponseBytes)
	require.Equal(t, 265387, len(raw), "freeze maximum evidence with the fixture context")
	require.Equal(t, MaxFoundResponseBytes, len(raw)+(35-2)+(202-1), "add maximum shard and diagnostic encodings")
	require.Less(t, MaxFoundResponseBytes, MaxResponseBytes)
}
