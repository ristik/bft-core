package gettrustbase

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	libp2pnet "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/network"
	"github.com/unicitynetwork/bft-core/utbstore"
)

// Source is the finalized entry history a server reads. *utbstore.Store implements it.
type Source interface {
	Tip() utbstore.Tip
	GenesisEpoch() uint64
	Entry(epoch uint64) (*types.RootTrustBaseV2, error)
	Range(from, to uint64, maxEntries, maxBytes int) (entries [][]byte, next uint64, more bool, err error)
}

// Config bounds the server. Zero values take the design defaults.
type Config struct {
	MaxEntries       int           // per page, default 64
	MaxResponseBytes int           // encoded response, default 1 MiB
	Timeout          time.Duration // per request, default 5 s
	MaxWorkers       int           // node-wide concurrent requests, default 32
	MaxPerPeer       int           // concurrent requests per peer, default 2
}

func (c Config) withDefaults() Config {
	if c.MaxEntries == 0 {
		c.MaxEntries = DefaultMaxEntries
	}
	if c.MaxResponseBytes == 0 {
		c.MaxResponseBytes = DefaultMaxResponse
	}
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	if c.MaxWorkers == 0 {
		c.MaxWorkers = 32
	}
	if c.MaxPerPeer == 0 {
		c.MaxPerPeer = 2
	}
	return c
}

// ErrConfig: the budgets cannot carry one maximum-size entry, so a page could never make progress.
var ErrConfig = errors.New("gettrustbase: invalid server configuration")

// Server answers requests from a Source. Respond is the pure protocol; Register wires it to a libp2p peer.
type Server struct {
	src     Source
	network types.NetworkID
	cfg     Config

	workers chan struct{}
	mu      sync.Mutex
	perPeer map[peer.ID]int
}

// NewServer checks that one maximum-size entry plus the envelope fits the response budget (otherwise startup is refused, design §7).
func NewServer(src Source, cfg Config) (*Server, error) {
	cfg = cfg.withDefaults()
	if cfg.MaxEntries < 1 || cfg.MaxWorkers < 1 || cfg.MaxPerPeer < 1 || cfg.MaxResponseBytes < MaxEntryBytes+envelopeBound {
		return nil, fmt.Errorf("%w: %d entries, %d response bytes (one entry needs %d)", ErrConfig, cfg.MaxEntries, cfg.MaxResponseBytes, MaxEntryBytes+envelopeBound)
	}
	g, err := src.Entry(src.GenesisEpoch())
	if err != nil {
		return nil, err
	}
	return &Server{src: src, network: g.NetworkID, cfg: cfg, workers: make(chan struct{}, cfg.MaxWorkers), perPeer: map[peer.ID]int{}}, nil
}

func (s *Server) reply(st Status) *Response {
	return &Response{Version: Version, Network: s.network, Status: st, Entries: []cbor.RawMessage{}}
}

// Respond answers one request from one snapshot of the finalized history.
func (s *Server) Respond(req *Request) *Response {
	if req.Version != Version || req.MaxEntries == 0 || req.MaxBytes == 0 {
		return s.reply(StatusInvalidRequest)
	}
	if req.Network != s.network {
		return s.reply(StatusWrongNetwork)
	}
	genesis := s.src.GenesisEpoch()
	if req.FromEpoch < genesis || (req.ToEpoch != nil && *req.ToEpoch < req.FromEpoch) ||
		(req.SnapshotEnd == nil) != (req.SnapshotEntryID == nil) ||
		(req.SnapshotEnd != nil && (len(req.SnapshotEntryID) != entryIDLen || req.FromEpoch > *req.SnapshotEnd ||
			(req.ToEpoch != nil && *req.ToEpoch < *req.SnapshotEnd))) {
		return s.reply(StatusInvalidRequest)
	}
	tip := s.src.Tip()

	end := tip.Epoch
	endID := tip.EntryID[:]
	if req.SnapshotEnd != nil {
		// the page continues a frozen snapshot: local history must reach it and agree on its end
		if tip.Epoch < *req.SnapshotEnd {
			r := s.reply(StatusNotYetAvailable)
			r.FromEpoch, r.EffectiveEnd, r.EndEntryID = req.FromEpoch, tip.Epoch, endID
			return r
		}
		e, err := s.src.Entry(*req.SnapshotEnd)
		if err != nil {
			return s.reply(StatusUnavailable)
		}
		id, err := e.EntryID()
		if err != nil {
			return s.reply(StatusUnavailable)
		}
		if !bytes.Equal(id[:], req.SnapshotEntryID) {
			return s.reply(StatusHistoryMismatch)
		}
		end, endID = *req.SnapshotEnd, id[:]
	} else if req.ToEpoch != nil && *req.ToEpoch < end {
		e, err := s.src.Entry(*req.ToEpoch)
		if err != nil {
			return s.reply(StatusUnavailable)
		}
		id, err := e.EntryID()
		if err != nil {
			return s.reply(StatusUnavailable)
		}
		end, endID = *req.ToEpoch, id[:]
	}
	if req.FromEpoch > end {
		// nothing at or after from yet (a requested end ahead of the tip is clamped, not an error)
		r := s.reply(StatusNotYetAvailable)
		r.FromEpoch, r.EffectiveEnd, r.EndEntryID = req.FromEpoch, tip.Epoch, tip.EntryID[:]
		return r
	}

	maxEntries := min(int(req.MaxEntries), s.cfg.MaxEntries)
	maxBytes := min(int(req.MaxBytes), s.cfg.MaxResponseBytes) - envelopeBound
	if maxBytes < 1 {
		return s.reply(StatusLimitTooSmall)
	}
	entries, next, more, err := s.src.Range(req.FromEpoch, end, maxEntries, maxBytes)
	switch {
	case errors.Is(err, utbstore.ErrBudget):
		return s.reply(StatusLimitTooSmall)
	case err != nil || len(entries) == 0:
		// finalized history must be contiguous: a hole is an internal fault, never an absent epoch
		return s.reply(StatusUnavailable)
	}
	r := s.reply(StatusOK)
	r.FromEpoch, r.EffectiveEnd, r.EndEntryID = req.FromEpoch, end, endID
	for _, e := range entries {
		r.Entries = append(r.Entries, e)
	}
	if more {
		r.NextEpoch = &next
	}
	return r
}

// Register serves ProtocolID on p.
func (s *Server) Register(p *network.Peer) { p.RegisterProtocolHandler(ProtocolID, s.handle) }

func (s *Server) acquire(id peer.ID) bool {
	select {
	case s.workers <- struct{}{}:
	default:
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perPeer[id] >= s.cfg.MaxPerPeer {
		<-s.workers
		return false
	}
	s.perPeer[id]++
	return true
}

func (s *Server) release(id peer.ID) {
	s.mu.Lock()
	if s.perPeer[id]--; s.perPeer[id] <= 0 {
		delete(s.perPeer, id)
	}
	s.mu.Unlock()
	<-s.workers
}

func (s *Server) handle(stream libp2pnet.Stream) {
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(s.cfg.Timeout))
	from := stream.Conn().RemotePeer()
	if !s.acquire(from) {
		_ = writeFrame(stream, s.encode(s.reply(StatusBusy)))
		return
	}
	defer s.release(from)
	raw, err := readFrame(bufio.NewReader(stream), MaxRequestBytes)
	var resp *Response
	if err != nil {
		resp = s.reply(StatusInvalidRequest)
	} else if req, derr := DecodeRequest(raw); derr != nil {
		resp = s.reply(StatusInvalidRequest)
	} else {
		resp = s.Respond(req)
	}
	_ = writeFrame(stream, s.encode(resp))
}

func (s *Server) encode(r *Response) []byte {
	b, err := r.Encode()
	if err != nil || len(b) > s.cfg.MaxResponseBytes {
		b, _ = s.reply(StatusUnavailable).Encode()
	}
	return b
}

var errFrameLength = errors.New("gettrustbase: frame length")

// writeFrame writes a uvarint length and the payload.
func writeFrame(w io.Writer, payload []byte) error {
	head := binary.AppendUvarint(nil, uint64(len(payload)))
	_, err := w.Write(append(head, payload...))
	return err
}

// readFrame reads one length-prefixed frame, refusing a declared length above max before allocating.
func readFrame(r *bufio.Reader, max int) ([]byte, error) {
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, err
	}
	if n == 0 || n > uint64(max) {
		return nil, fmt.Errorf("%w: %d outside 1..%d", errFrameLength, n, max)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// Client requests pages from peers over a libp2p peer.
type Client struct {
	Peer        *network.Peer
	Timeout     time.Duration // default 5 s
	MaxResponse int           // default DefaultMaxResponse
}

// Page sends one request and decodes the response with the page limits.
func (c *Client) Page(ctx context.Context, id peer.ID, req *Request) (*Response, [][]byte, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	maxResp := c.MaxResponse
	if maxResp == 0 {
		maxResp = DefaultMaxResponse
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stream, err := c.Peer.CreateStream(ctx, id, ProtocolID)
	if err != nil {
		return nil, nil, err
	}
	defer stream.Close()
	_ = stream.SetDeadline(time.Now().Add(timeout))
	payload, err := req.Encode()
	if err != nil {
		return nil, nil, err
	}
	if err := writeFrame(stream, payload); err != nil {
		return nil, nil, err
	}
	_ = stream.CloseWrite()
	raw, err := readFrame(bufio.NewReader(stream), maxResp)
	if err != nil {
		return nil, nil, err
	}
	resp, _, err := DecodeResponse(raw, Limits{MaxBytes: maxResp, MaxEntries: DefaultMaxEntries})
	if err != nil {
		return nil, nil, err
	}
	entries := make([][]byte, len(resp.Entries))
	for i, e := range resp.Entries {
		entries[i] = e
	}
	return resp, entries, nil
}
