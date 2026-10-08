package recordsfeed

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/rootrecords"
)

const (
	// ProtocolID is the libp2p protocol the root serves cuts and records on.
	ProtocolID = "/ab/p85-records/1.0.0"
	// ClientDeadline bounds one request to one root, ServerDeadline one served stream.
	ClientDeadline = 10 * time.Second
	ServerDeadline = 15 * time.Second
	// MaxPendingStreams bounds the streams served at once, MaxPendingPerPeer those of one peer.
	MaxPendingStreams = 32
	MaxPendingPerPeer = 4

	maxRequestBytes = 64
	kindCut         = 1
	kindRecords     = 2
)

// ServerSource is what the root serves from.
type ServerSource interface {
	// ControlCut is the cut of the committed block of the round; an error when the root no longer holds it.
	ControlCut(round uint64) (Cut, error)
	// Records returns up to max records from the index of the retained source log.
	Records(from uint64, max int) ([]rootrecords.Record, error)
}

type request struct {
	_    struct{} `cbor:",toarray"`
	Kind uint8
	// Round is the committed block of a cut request; From and Max the range of a records request.
	Round uint64
	From  uint64
	Max   uint32
}

type wireRecord struct {
	_           struct{} `cbor:",toarray"`
	Index       uint64
	ID          []byte
	Predecessor []byte
	Kind        uint8
	Progress    uint64
	UCTime      uint64
	Data        []byte
	ClosedEpoch uint64
}

func toWire(r rootrecords.Record) wireRecord {
	return wireRecord{Index: r.Index, ID: r.ID[:], Predecessor: r.Predecessor[:], Kind: uint8(r.Kind), Progress: r.Progress,
		UCTime: r.UCTime, Data: r.Data, ClosedEpoch: r.ClosedEpoch}
}

func fromWire(w wireRecord) (rootrecords.Record, error) {
	if len(w.ID) != 32 || len(w.Predecessor) != 32 {
		return rootrecords.Record{}, fmt.Errorf("%w: record identifier width", ErrWire)
	}
	r := rootrecords.Record{Index: w.Index, Kind: rootrecords.Kind(w.Kind), Progress: w.Progress, UCTime: w.UCTime, Data: w.Data, ClosedEpoch: w.ClosedEpoch}
	copy(r.ID[:], w.ID)
	copy(r.Predecessor[:], w.Predecessor)
	return r, nil
}

// Stream is the part of a libp2p stream the protocol uses.
type Stream interface {
	io.ReadWriter
	SetDeadline(time.Time) error
	CloseWrite() error
	Close() error
	Reset() error
}

// Opener opens a stream to a peer.
type Opener interface {
	CreateStream(ctx context.Context, to peer.ID, protocol string) (Stream, error)
}

// Libp2p adapts a host's stream opener.
type Libp2p interface {
	CreateStream(ctx context.Context, to peer.ID, protocol string) (libp2pnetwork.Stream, error)
}

type libp2pOpener struct{ host Libp2p }

// FromLibp2p is the Opener of a libp2p host.
func FromLibp2p(host Libp2p) Opener { return libp2pOpener{host} }

func (o libp2pOpener) CreateStream(ctx context.Context, to peer.ID, protocol string) (Stream, error) {
	return o.host.CreateStream(ctx, to, protocol)
}

// Server answers cut and record requests from the peers it allows (the validators of the shards this root serves).
type Server struct {
	source  ServerSource
	allowed func(peer.ID) bool

	mu      sync.Mutex
	pending int
	peers   map[peer.ID]int
}

// NewServer serves source to the peers allowed accepts; allowed is consulted per request.
func NewServer(source ServerSource, allowed func(peer.ID) bool) *Server {
	return &Server{source: source, allowed: allowed, peers: map[peer.ID]int{}}
}

// Handler is the libp2p stream handler.
func (s *Server) Handler(st libp2pnetwork.Stream) { s.Serve(st.Conn().RemotePeer(), st) }

// Serve answers one request on st; whatever it does not like resets the stream.
func (s *Server) Serve(from peer.ID, st Stream) {
	if !s.admit(from) {
		_ = st.Reset()
		return
	}
	defer s.release(from)
	if err := st.SetDeadline(time.Now().Add(ServerDeadline)); err != nil {
		_ = st.Reset()
		return
	}
	raw, err := readFrame(st, maxRequestBytes)
	if err != nil {
		_ = st.Reset()
		return
	}
	var req request
	if err := types.Cbor.Unmarshal(raw, &req); err != nil {
		_ = st.Reset()
		return
	}
	var body []byte
	switch req.Kind {
	case kindCut:
		cut, cerr := s.source.ControlCut(req.Round)
		if cerr == nil {
			body, err = types.Cbor.Marshal(cut)
		} else {
			err = cerr
		}
	case kindRecords:
		recs, rerr := s.source.Records(req.From, int(min(req.Max, MaxBatch)))
		if rerr != nil {
			err = rerr
			break
		}
		wire := make([]wireRecord, 0, len(recs))
		for _, r := range recs {
			wire = append(wire, toWire(r))
		}
		body, err = types.Cbor.Marshal(wire)
	default:
		err = ErrWire
	}
	if err != nil || len(body) == 0 {
		body = nil // "not held": a zero-length response
	}
	if err := writeFrame(st, body); err != nil {
		_ = st.Reset()
		return
	}
	_ = st.Close()
}

func (s *Server) admit(from peer.ID) bool {
	if from == "" || s.allowed == nil || !s.allowed(from) {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pending >= MaxPendingStreams || s.peers[from] >= MaxPendingPerPeer {
		return false
	}
	s.pending++
	s.peers[from]++
	return true
}

func (s *Server) release(from peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pending--
	if s.peers[from]--; s.peers[from] == 0 {
		delete(s.peers, from)
	}
}

func writeFrame(w io.Writer, body []byte) error {
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := w.Write(body)
	return err
}

func readFrame(r io.Reader, max int) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[:])
	if int64(n) > int64(max) {
		return nil, fmt.Errorf("%w: %d bytes exceed the bound %d", ErrWire, n, max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// P2PRemote is a Remote over streams to the roots, asked in order.
type P2PRemote struct {
	Opener Opener
	Roots  []peer.ID
}

func (p P2PRemote) call(ctx context.Context, req request, maxResp int) ([]byte, error) {
	raw, err := types.Cbor.Marshal(req)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, root := range p.Roots {
		if ctx.Err() != nil {
			break
		}
		body, err := p.callOne(ctx, root, raw, maxResp)
		if err == nil {
			return body, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", root, err))
	}
	return nil, errors.Join(append([]error{ErrUnavailable}, errs...)...)
}

func (p P2PRemote) callOne(ctx context.Context, root peer.ID, raw []byte, maxResp int) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, ClientDeadline)
	defer cancel()
	st, err := p.Opener.CreateStream(ctx, root, ProtocolID)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		if err := st.SetDeadline(dl); err != nil {
			_ = st.Reset()
			return nil, err
		}
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			_ = st.Reset()
		case <-stop:
		}
	}()
	if err := writeFrame(st, raw); err != nil {
		_ = st.Reset()
		return nil, err
	}
	_ = st.CloseWrite()
	body, err := readFrame(st, maxResp)
	if err != nil {
		_ = st.Reset()
		return nil, err
	}
	_ = st.Close()
	if len(body) == 0 {
		return nil, errors.New("the root does not hold it")
	}
	return body, nil
}

// Cut implements Remote.
func (p P2PRemote) Cut(ctx context.Context, round uint64) (Cut, error) {
	body, err := p.call(ctx, request{Kind: kindCut, Round: round}, MaxCutBytes)
	if err != nil {
		return Cut{}, err
	}
	var cut Cut
	if err := types.Cbor.Unmarshal(body, &cut); err != nil {
		return Cut{}, fmt.Errorf("%w: cut: %v", ErrWire, err)
	}
	return cut, nil
}

// Records implements Remote. A root that answers with no record for a range the caller knows exists (the log is longer, the cut said
// so) is a root that does not hold it: the next one is asked.
func (p P2PRemote) Records(ctx context.Context, from uint64, max int) ([]rootrecords.Record, error) {
	raw, err := types.Cbor.Marshal(request{Kind: kindRecords, From: from, Max: uint32(min(max, MaxBatch))})
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, root := range p.Roots {
		if ctx.Err() != nil {
			break
		}
		body, err := p.callOne(ctx, root, raw, MaxBatchBytes)
		if err == nil {
			var wire []wireRecord
			if err = types.Cbor.Unmarshal(body, &wire); err != nil {
				err = fmt.Errorf("%w: records: %v", ErrWire, err)
			} else if len(wire) == 0 {
				err = errors.New("the root has no record in that range")
			} else {
				out := make([]rootrecords.Record, 0, len(wire))
				for _, w := range wire {
					r, ferr := fromWire(w)
					if ferr != nil {
						err = ferr
						break
					}
					out = append(out, r)
				}
				if err == nil {
					return out, nil
				}
			}
		}
		errs = append(errs, fmt.Errorf("%s: %w", root, err))
	}
	return nil, errors.Join(append([]error{ErrUnavailable}, errs...)...)
}

var _ Remote = P2PRemote{}
