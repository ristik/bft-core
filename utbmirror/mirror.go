// Package utbmirror lets shard nodes mirror the finalized UTB entries they hold to non-active followers, so that a follower extends its
// trust-base chain without asking a root. A served entry is untrusted bytes: the follower appends it to its own utbstore, which accepts it
// only as the authenticated successor of the tip it already validated forward from its provisioned pin.
package utbmirror

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	libp2pnetwork "github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
	"github.com/unicitynetwork/bft-go-base/types"

	"github.com/unicitynetwork/bft-core/utbstore"
)

// Protocol is the stream protocol of UTB entry mirroring.
const Protocol = "/unicity/utb-entries/1.0.0"

const (
	maxRequestBytes  = 64
	maxResponseBytes = 4 << 20
	maxEntries       = 64
	deadline         = 10 * time.Second
	maxConcurrent    = 8
	maxPerPeer       = 2
)

// ErrMirror is returned for an exchange that is not one bounded, canonical frame each way.
var ErrMirror = errors.New("utbmirror: invalid exchange")

type request struct {
	_    struct{} `cbor:",toarray"`
	From uint64
}

type response struct {
	_       struct{} `cbor:",toarray"`
	Entries [][]byte
}

// Store is what a mirror serves from and a follower appends to.
type Store interface {
	Range(from, to uint64, maxEntries, maxBytes int) ([][]byte, uint64, bool, error)
	Append([]byte) (bool, error)
	Tip() utbstore.Tip
}

// Host is the part of a libp2p host the exchange needs.
type Host interface {
	RegisterProtocolHandler(string, libp2pnetwork.StreamHandler)
	CreateStream(context.Context, peer.ID, string) (libp2pnetwork.Stream, error)
}

// Server serves entries from a store, bounded in total and per peer.
type Server struct {
	store Store
	mu    sync.Mutex
	total int
	peers map[peer.ID]int
}

func NewServer(store Store) *Server { return &Server{store: store, peers: map[peer.ID]int{}} }

func (s *Server) reserve(id peer.ID) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.total >= maxConcurrent || s.peers[id] >= maxPerPeer {
		return false
	}
	s.total++
	s.peers[id]++
	return true
}

func (s *Server) release(id peer.ID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.total--
	if s.peers[id]--; s.peers[id] <= 0 {
		delete(s.peers, id)
	}
}

// Handler is the libp2p stream handler.
func (s *Server) Handler(st libp2pnetwork.Stream) {
	defer st.Close()
	id := st.Conn().RemotePeer()
	if !s.reserve(id) {
		_ = st.Reset()
		return
	}
	defer s.release(id)
	_ = st.SetDeadline(time.Now().Add(deadline))
	if err := s.Serve(st); err != nil {
		_ = st.Reset()
		return
	}
	_ = st.CloseWrite()
}

// Serve answers one request: the stored entries from its epoch on, within the page budget (none when the store has none).
func (s *Server) Serve(rw io.ReadWriter) error {
	var req request
	if err := readFrame(rw, &req, maxRequestBytes); err != nil {
		return err
	}
	entries, _, _, err := s.store.Range(req.From, ^uint64(0), maxEntries, maxResponseBytes-1024)
	if err != nil {
		entries = nil
	}
	return writeFrame(rw, response{Entries: entries})
}

// Fetch asks one mirror for the entries from an epoch on.
func Fetch(ctx context.Context, host Host, id peer.ID, from uint64) ([][]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	st, err := host.CreateStream(ctx, id, Protocol)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
	}
	if err := writeFrame(st, request{From: from}); err != nil {
		_ = st.Reset()
		return nil, err
	}
	_ = st.CloseWrite()
	var resp response
	if err := readFrame(st, &resp, maxResponseBytes); err != nil {
		_ = st.Reset()
		return nil, err
	}
	if len(resp.Entries) > maxEntries {
		return nil, fmt.Errorf("%w: %d entries", ErrMirror, len(resp.Entries))
	}
	return resp.Entries, nil
}

// Follower extends a store from mirrors: the entries after its tip, appended in order. Append authenticates each from its predecessor;
// the first entry a mirror serves that does not authenticate ends that mirror's turn.
type Follower struct {
	Store   Store
	Host    Host
	Mirrors func() []peer.ID
	// Interval is the pause between rounds; zero is two seconds.
	Interval time.Duration
	Log      *slog.Logger
}

// Sync asks each mirror in turn for entries after the tip and appends what authenticates. It reports how many entries were appended.
func (f *Follower) Sync(ctx context.Context) int {
	added := 0
	for _, id := range f.Mirrors() {
		for {
			entries, err := Fetch(ctx, f.Host, id, f.Store.Tip().Epoch+1)
			if err != nil || len(entries) == 0 {
				break
			}
			progressed := false
			for _, raw := range entries {
				ok, err := f.Store.Append(raw)
				if err != nil {
					if f.Log != nil {
						f.Log.WarnContext(ctx, "mirrored trust-base entry refused", "mirror", id.String(), "error", err)
					}
					break
				}
				if ok {
					added++
					progressed = true
				}
			}
			if !progressed {
				break
			}
		}
	}
	return added
}

// Run syncs until ctx ends; it returns nil on cancellation.
func (f *Follower) Run(ctx context.Context) error {
	interval := f.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	for {
		f.Sync(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

func writeFrame(w io.Writer, v any) error {
	body, err := types.Cbor.Marshal(v)
	if err != nil {
		return err
	}
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(body)))
	if _, err := w.Write(n[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func readFrame(r io.Reader, v any, max int) error {
	var n [4]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return err
	}
	size := int(binary.BigEndian.Uint32(n[:]))
	if size == 0 || size > max {
		return fmt.Errorf("%w: frame of %d bytes", ErrMirror, size)
	}
	body := make([]byte, size)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	if err := types.Cbor.Unmarshal(body, v); err != nil {
		return fmt.Errorf("%w: %v", ErrMirror, err)
	}
	if again, err := types.Cbor.Marshal(v); err != nil || len(again) != size {
		return fmt.Errorf("%w: not canonical", ErrMirror)
	}
	return nil
}
