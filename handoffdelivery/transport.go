package handoffdelivery

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
	"github.com/unicitynetwork/bft-go-base/types"
)

const Protocol = "/unicity/root-handoff-bundle/1.0.0"

const (
	maxRequestBytes  = 256
	maxResponseBytes = 64 << 20
	requestDeadline  = 10 * time.Second
)

type request struct {
	_     struct{} `cbor:",toarray"`
	Epoch uint64
}

type response struct {
	_      struct{} `cbor:",toarray"`
	Error  string
	Bundle *Bundle
}

// Provider reads a committed handoff bundle for the requested successor
// epoch. It may return unavailable while the root has not finalized H.
type Provider interface {
	HandoffBundle(context.Context, uint64) (*Bundle, error)
}

type Host interface {
	RegisterProtocolHandler(string, libp2pnetwork.StreamHandler)
	CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error)
}

type Server struct {
	provider Provider
	slots    chan struct{}
}

func NewServer(provider Provider) (*Server, error) {
	if provider == nil {
		return nil, errors.New("handoff delivery: missing provider")
	}
	return &Server{provider: provider, slots: make(chan struct{}, 8)}, nil
}

func (s *Server) Register(host Host) {
	host.RegisterProtocolHandler(Protocol, s.handle)
}

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

// Serve handles exactly one bounded request and response. The caller still
// verifies the returned bundle using its local old trust and shard identity.
func (s *Server) Serve(ctx context.Context, rw io.ReadWriter) error {
	var req request
	if err := readFrame(rw, &req, maxRequestBytes); err != nil {
		return err
	}
	if req.Epoch < 2 {
		return writeFrame(rw, response{Error: "invalid successor epoch"}, maxResponseBytes)
	}
	bundle, err := s.provider.HandoffBundle(ctx, req.Epoch)
	if err != nil || bundle == nil {
		return writeFrame(rw, response{Error: "handoff unavailable"}, maxResponseBytes)
	}
	if bundle.Body.Epoch != req.Epoch || bundle.Proof.Record.Epoch+1 != req.Epoch {
		return writeFrame(rw, response{Error: "handoff epoch mismatch"}, maxResponseBytes)
	}
	return writeFrame(rw, response{Bundle: bundle}, maxResponseBytes)
}

func Request(ctx context.Context, host Host, root peer.ID, epoch uint64) (Bundle, error) {
	if host == nil || epoch < 2 {
		return Bundle{}, ErrBundle
	}
	ctx, cancel := context.WithTimeout(ctx, requestDeadline)
	defer cancel()
	stream, err := host.CreateStream(ctx, root, Protocol)
	if err != nil {
		return Bundle{}, fmt.Errorf("handoff delivery: root stream: %w", err)
	}
	defer stream.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := stream.SetDeadline(deadline); err != nil {
			return Bundle{}, err
		}
	}
	var rsp response
	if err := writeFrame(stream, request{Epoch: epoch}, maxRequestBytes); err != nil {
		return Bundle{}, err
	}
	if err := readFrame(stream, &rsp, maxResponseBytes); err != nil {
		return Bundle{}, err
	}
	if rsp.Error != "" || rsp.Bundle == nil || rsp.Bundle.Body.Epoch != epoch || rsp.Bundle.Proof.Record.Epoch+1 != epoch {
		return Bundle{}, ErrBundle
	}
	return *rsp.Bundle, nil
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
