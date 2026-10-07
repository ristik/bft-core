// Package q3delivery serves and fetches the activation bundle of a V3 epoch between root nodes: the proof envelope that authenticates the
// activation from the pinned genesis, the old epoch's committed checkpoint and the candidate preimage (q3active.Bundle). It is the V3
// counterpart of handoffdelivery, with its own protocol identifier: a peer that does not speak it cannot fetch a V3 bundle, and a V2
// peer is never asked for one.
//
// A bundle fetched here is untrusted bytes. The caller hands it to its own q3active.Runtime, which verifies it against the verified
// history and installs it through the journal; nothing about the peer is trusted, and what a peer serves is only ever the evidence.
package q3delivery

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-core/q3active"
	"github.com/unicitynetwork/bft-go-base/types"
)

// Protocol is the stream protocol of V3 activation bundle delivery.
const Protocol = "/unicity/q3-activation-bundle/1.0.0"

// ErrBundle is returned for a request or response that is not exactly one bounded, canonical frame, or a bundle that is not the one asked for.
var ErrBundle = errors.New("q3delivery: invalid bundle exchange")

const (
	maxRequestBytes  = 256
	maxResponseBytes = 24 << 20
	requestDeadline  = 20 * time.Second
	maxConcurrent    = 8
)

type request struct {
	_     struct{} `cbor:",toarray"`
	Epoch uint64
}

type response struct {
	_      struct{} `cbor:",toarray"`
	Error  string
	Bundle []byte
}

// Provider reads the activation bundle of a successor epoch, or reports it unavailable (the old epoch has not committed it here).
type Provider interface {
	Q3Bundle(ctx context.Context, epoch uint64) (q3active.Bundle, error)
}

// Host is the part of a libp2p host the exchange needs.
type Host interface {
	RegisterProtocolHandler(string, libp2pnetwork.StreamHandler)
	CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error)
}

// Server answers bundle requests, a bounded number at a time.
type Server struct {
	provider Provider
	slots    chan struct{}
}

// NewServer serves bundles from provider.
func NewServer(provider Provider) (*Server, error) {
	if provider == nil {
		return nil, errors.New("q3delivery: missing provider")
	}
	return &Server{provider: provider, slots: make(chan struct{}, maxConcurrent)}, nil
}

// Register installs the stream handler on host.
func (s *Server) Register(host Host) { host.RegisterProtocolHandler(Protocol, s.handle) }

func (s *Server) handle(stream libp2pnetwork.Stream) {
	defer stream.Close()
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		_ = stream.Reset()
		return
	}
	_ = stream.SetDeadline(time.Now().Add(requestDeadline))
	ctx, cancel := context.WithTimeout(context.Background(), requestDeadline)
	defer cancel()
	if err := s.Serve(ctx, stream); err != nil {
		_ = stream.Reset()
		return
	}
	_ = stream.CloseWrite()
}

// Serve handles exactly one bounded request and response.
func (s *Server) Serve(ctx context.Context, rw io.ReadWriter) error {
	var req request
	if err := readFrame(rw, &req, maxRequestBytes); err != nil {
		return err
	}
	if req.Epoch < 2 {
		return writeFrame(rw, response{Error: "invalid successor epoch"}, maxResponseBytes)
	}
	bundle, err := s.provider.Q3Bundle(ctx, req.Epoch)
	if err != nil {
		return writeFrame(rw, response{Error: "activation unavailable"}, maxResponseBytes)
	}
	raw, err := q3active.EncodeBundle(bundle)
	if err != nil {
		return writeFrame(rw, response{Error: "activation unavailable"}, maxResponseBytes)
	}
	if epoch, err := bundleEpoch(raw); err != nil || epoch != req.Epoch {
		return writeFrame(rw, response{Error: "activation epoch mismatch"}, maxResponseBytes)
	}
	return writeFrame(rw, response{Bundle: raw}, maxResponseBytes)
}

// Request fetches the activation bundle of the successor epoch from one root. The result is evidence only: it is as untrusted as any
// peer's bytes until the caller's runtime has verified and installed it.
func Request(ctx context.Context, host Host, root peer.ID, epoch uint64) (q3active.Bundle, error) {
	if host == nil || epoch < 2 {
		return q3active.Bundle{}, ErrBundle
	}
	ctx, cancel := context.WithTimeout(ctx, requestDeadline)
	defer cancel()
	stream, err := host.CreateStream(ctx, root, Protocol)
	if err != nil {
		return q3active.Bundle{}, fmt.Errorf("q3delivery: root stream: %w", err)
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			return q3active.Bundle{}, err
		}
	}
	return exchange(stream, epoch)
}

func exchange(rw io.ReadWriter, epoch uint64) (q3active.Bundle, error) {
	if err := writeFrame(rw, request{Epoch: epoch}, maxRequestBytes); err != nil {
		return q3active.Bundle{}, err
	}
	var rsp response
	if err := readFrame(rw, &rsp, maxResponseBytes); err != nil {
		return q3active.Bundle{}, err
	}
	if rsp.Error != "" || len(rsp.Bundle) == 0 {
		return q3active.Bundle{}, fmt.Errorf("%w: %q", ErrBundle, rsp.Error)
	}
	if got, err := bundleEpoch(rsp.Bundle); err != nil || got != epoch {
		return q3active.Bundle{}, fmt.Errorf("%w: not the bundle of epoch %d", ErrBundle, epoch)
	}
	b, _, err := q3active.DecodeBundle(rsp.Bundle)
	return b, err
}

// bundleEpoch is the successor epoch a canonical bundle activates: its envelope's last link.
func bundleEpoch(raw []byte) (uint64, error) {
	_, env, err := q3active.DecodeBundle(raw)
	if err != nil {
		return 0, err
	}
	return env.Links[len(env.Links)-1].Body.Epoch, nil
}

func writeFrame(w io.Writer, value any, max int) error {
	raw, err := types.Cbor.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > max {
		return ErrBundle
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(raw)))
	if err := writeAll(w, prefix[:]); err != nil {
		return err
	}
	return writeAll(w, raw)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func readFrame(r io.Reader, target any, max int) error {
	reader := bufio.NewReader(r)
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint32(prefix[:]))
	if n == 0 || n > max {
		return ErrBundle
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return err
	}
	if err := types.Cbor.Unmarshal(raw, target); err != nil {
		return err
	}
	canonical, err := types.Cbor.Marshal(target)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrBundle
	}
	return nil
}
